"""WebSocket and SSE channel implementations.

WebSocketChannel wraps a FastAPI WebSocket connection with PIN authentication.
SSEWriter manages a Server-Sent Events stream for a single client, fed from
the event bus.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from sentinel.api.auth import PinVerifier
from sentinel.channels.base import Channel, IncomingMessage, OutgoingMessage
from sentinel.core.bus import EventBus

logger = logging.getLogger("sentinel.audit")


class WebSocketChannel(Channel):
    """Wraps a FastAPI WebSocket connection with PIN-based authentication."""
    channel_type = "websocket"
    _MAX_MESSAGE_LENGTH = 10_000  # matches MCP input limit
    _IDLE_TIMEOUT = 600.0  # BH3-017: 10 min idle timeout (raised for Opus planner latency)

    def __init__(self, websocket, pin_verifier_getter, failure_tracker):
        self._ws = websocket
        self._pin_verifier_getter = pin_verifier_getter
        self._failure_tracker = failure_tracker
        self._remote = "unknown"
        if websocket.client:
            self._remote = websocket.client.host

    async def start(self) -> None:
        pass  # WebSocket is already accepted before this is called

    async def stop(self) -> None:
        try:
            await self._ws.close()
        except Exception:
            pass

    async def authenticate(self) -> bool:
        """First-message PIN auth. Returns True if authenticated.

        Expects: {"type": "auth", "pin": "1234"}
        Responds: {"type": "auth_ok"} or closes with 4001
        """
        verifier = self._pin_verifier_getter()

        # No PIN configured — auto-authenticate
        if verifier is None:
            await self._ws.send_json({"type": "auth_ok"})
            return True

        # Check lockout
        if self._failure_tracker.is_locked_out(self._remote):
            logger.warning(
                "WebSocket auth locked out",
                extra={"event": "ws_auth_lockout", "remote": self._remote},
            )
            await self._ws.close(code=4001, reason="Too many failed attempts")
            return False

        try:
            raw = await asyncio.wait_for(self._ws.receive_text(), timeout=10.0)
            msg = json.loads(raw)
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
            await self._ws.close(code=4001, reason="Authentication timeout or invalid message")
            return False

        if msg.get("type") != "auth" or not isinstance(msg.get("pin"), str):
            await self._ws.close(code=4001, reason="Expected auth message")
            return False

        if not verifier.verify(msg["pin"]):
            self._failure_tracker.record_failure(self._remote)
            logger.warning(
                "WebSocket PIN auth failed",
                extra={"event": "ws_auth_failed", "remote": self._remote},
            )
            try:
                await self._ws.send_json({"type": "auth_error", "reason": "Invalid PIN"})
            except Exception:
                pass
            await self._ws.close(code=4001, reason="Invalid PIN")
            return False

        # Success
        self._failure_tracker.clear(self._remote)
        await self._ws.send_json({"type": "auth_ok"})
        logger.debug(
            "WebSocket authenticated",
            extra={"event": "ws_auth_success", "remote": self._remote},
        )
        return True

    async def send(self, message: OutgoingMessage) -> None:
        """Send a JSON message to the WebSocket client."""
        payload = {
            "type": message.event_type,
            "data": message.data,
            "timestamp": message.timestamp.isoformat(),
        }
        await self._ws.send_json(payload)

    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages from the WebSocket."""
        while True:
            try:
                # BH3-017: Idle timeout prevents abandoned connections holding resources
                raw = await asyncio.wait_for(
                    self._ws.receive_text(), timeout=self._IDLE_TIMEOUT,
                )
            except asyncio.TimeoutError:
                # Idle timeout — close the connection gracefully
                logger.info(
                    "WebSocket idle timeout — closing",
                    extra={"event": "ws_idle_timeout", "remote": self._remote},
                )
                try:
                    await self._ws.close(code=1000, reason="Idle timeout")
                except Exception:
                    pass
                break
            except Exception:
                break  # disconnected

            # Length validation
            if len(raw) > self._MAX_MESSAGE_LENGTH:
                try:
                    await self._ws.send_json({
                        "type": "error",
                        "reason": f"Message too long (max {self._MAX_MESSAGE_LENGTH} chars)",
                    })
                except Exception:
                    break
                continue

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                # Send error and continue listening
                try:
                    await self._ws.send_json({
                        "type": "error",
                        "reason": "Invalid JSON",
                    })
                except Exception:
                    break
                continue

            # Content validation — must have non-empty text
            content = msg.get("request", msg.get("content", ""))
            if not isinstance(content, str) or not content.strip():
                try:
                    await self._ws.send_json({
                        "type": "error",
                        "reason": "Empty or missing message content",
                    })
                except Exception:
                    break
                continue

            yield IncomingMessage(
                channel_id=f"ws-{self._remote}",
                source="websocket",
                content=content,
                metadata=msg,
            )


class SSEWriter:
    """Manages a Server-Sent Events stream for a single client.

    Subscribes to event bus topics and queues events for streaming
    via sse-starlette's EventSourceResponse.
    """

    def __init__(self, event_bus: EventBus):
        self._bus = event_bus
        self._queue: asyncio.Queue[dict] = asyncio.Queue()
        self._subscriptions: list[tuple[str, object]] = []
        self._done = False

    async def subscribe(self, task_id: str) -> None:
        """Subscribe to all events for a specific task."""
        pattern = f"task.{task_id}.*"

        async def _handler(topic: str, data):
            event_type = topic.split(".")[-1]  # e.g. "started", "completed"
            await self._queue.put({
                "event": event_type,
                "data": json.dumps(data if isinstance(data, dict) else {"payload": data}),
            })
            # Signal completion when task is done
            if event_type == "completed":
                self._done = True

        self._bus.subscribe(pattern, _handler)
        self._subscriptions.append((pattern, _handler))

    def cleanup(self) -> None:
        """Unsubscribe from all bus topics."""
        for pattern, handler in self._subscriptions:
            self._bus.unsubscribe(pattern, handler)
        self._subscriptions.clear()

    async def event_generator(self) -> AsyncIterator[dict]:
        """Yield SSE events from the queue. Used by sse-starlette."""
        try:
            while True:
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=30.0)
                    is_final = event.get("event") == "completed"
                    yield event
                    if is_final:
                        break
                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent connection timeout
                    yield {"comment": "keepalive"}
        finally:
            self.cleanup()
