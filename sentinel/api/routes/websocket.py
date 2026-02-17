"""WebSocket route handler.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  WS /ws — WebSocket endpoint with PIN auth, channel routing, bidirectional messaging

The WebSocket has its own PIN authentication flow (via WebSocketChannel),
separate from the HTTP PinAuthMiddleware.  A _FailureTracker instance is
created here to rate-limit brute-force attempts on the WS PIN.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from starlette.websockets import WebSocket, WebSocketDisconnect

from sentinel.api.auth import _FailureTracker
from sentinel.channels.base import ChannelRouter
from sentinel.channels.web import WebSocketChannel

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()

# ── Module globals (init pattern) ──────────────────────────────────

_orchestrator: Any = None
_event_bus: Any = None
_message_router: Any = None
_pin_verifier: Any = None
_audit: Any = None
_ws_failure_tracker = _FailureTracker()


def init(
    *,
    orchestrator: Any = None,
    event_bus: Any = None,
    message_router: Any = None,
    pin_verifier: Any = None,
    audit: Any = None,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _orchestrator, _event_bus, _message_router, _pin_verifier, _audit
    _orchestrator = orchestrator
    _event_bus = event_bus
    _message_router = message_router
    _pin_verifier = pin_verifier
    _audit = audit


# ── WebSocket endpoint ────────────────────────────────────────────


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint with PIN auth and real-time task execution."""
    from sentinel.core.context import current_user_id

    await websocket.accept()

    channel = WebSocketChannel(
        websocket=websocket,
        pin_verifier_getter=lambda: _pin_verifier,
        failure_tracker=_ws_failure_tracker,
    )

    if not await channel.authenticate():
        return  # Connection closed with 4001

    if _orchestrator is None or _event_bus is None:
        try:
            await websocket.send_json({
                "type": "error",
                "reason": "Orchestrator not initialized",
            })
        except Exception:
            pass
        await channel.stop()
        return

    router_inst = ChannelRouter(_orchestrator, _event_bus, _audit, message_router=_message_router)

    # Subscribe to routine events and forward to this WS client
    async def _forward_routine_event(topic: str, data: dict) -> None:
        try:
            await websocket.send_json({
                "type": "routine_event",
                "event": topic,
                "data": data,
            })
        except Exception:
            pass  # Client disconnected — cleanup handled below

    _event_bus.subscribe("routine.*", _forward_routine_event)

    try:
        async for message in channel.receive():
            msg_type = message.metadata.get("type", "")

            if msg_type == "task":
                # Set RLS user context — hardcoded to 1 (single-user).
                # Multi-user: resolve user_id from WebSocket auth token.
                # Same pattern as Signal and Telegram channel handlers.
                ctx_token = current_user_id.set(1)
                # Add source_key for session binding
                client_ip = websocket.client.host if websocket.client else "unknown"
                message.metadata["source_key"] = f"websocket:{client_ip}"
                task_id = None
                try:
                    task_id = await router_inst.handle_message(channel, message)
                except Exception as exc:
                    # BH3-020: Include task_id in error so the UI can match the response
                    error_payload = {"type": "error", "reason": str(exc)}
                    if task_id:
                        error_payload["task_id"] = task_id
                    await websocket.send_json(error_payload)
                finally:
                    current_user_id.reset(ctx_token)

            elif msg_type == "approval":
                ctx_token = current_user_id.set(1)
                try:
                    result = await router_inst.handle_approval(
                        channel,
                        approval_id=message.metadata.get("approval_id", ""),
                        granted=message.metadata.get("granted", False),
                        reason=message.metadata.get("reason", ""),
                    )
                    await websocket.send_json({
                        "type": "approval_result",
                        "data": result,
                    })
                except Exception as exc:
                    await websocket.send_json({
                        "type": "error",
                        "reason": str(exc),
                    })
                finally:
                    current_user_id.reset(ctx_token)

            else:
                await websocket.send_json({
                    "type": "error",
                    "reason": f"Unknown message type: {msg_type}",
                })

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        # Unsubscribe routine event forwarder on disconnect
        try:
            _event_bus.unsubscribe("routine.*", _forward_routine_event)
        except Exception:
            pass
