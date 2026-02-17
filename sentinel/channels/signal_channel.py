"""Signal messaging channel via signal-cli subprocess.

Manages a signal-cli instance in JSON-RPC mode, with crash recovery via
exponential backoff. All tests use mocked subprocess — no signal-cli binary needed.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from sentinel.channels.base import Channel, IncomingMessage, OutgoingMessage
from sentinel.core.bus import EventBus

logger = logging.getLogger("sentinel.audit")


@dataclass
class SignalConfig:
    """Configuration for the Signal channel."""
    signal_cli_path: str = "/usr/bin/signal-cli"
    account: str = ""             # phone number, e.g. "+1234567890"
    trust_all_known: bool = False


class ExponentialBackoff:
    """Backoff helper: 1s, 2s, 4s, ... up to max_delay."""

    def __init__(self, base: float = 1.0, max_delay: float = 300.0):
        self._base = base
        self._max_delay = max_delay
        self._attempt = 0

    @property
    def delay(self) -> float:
        """Current delay value without incrementing."""
        d = self._base * (2 ** self._attempt)
        return min(d, self._max_delay)

    def next_delay(self) -> float:
        """Calculate the next delay and increment the attempt counter."""
        d = self.delay
        self._attempt += 1
        return d

    def reset(self) -> None:
        """Reset after a successful operation."""
        self._attempt = 0

    @property
    def attempt(self) -> int:
        return self._attempt


class SignalChannel(Channel):
    """Signal messaging channel using signal-cli in JSON-RPC mode.

    Manages the subprocess lifecycle including crash recovery with exponential
    backoff. Messages are sent/received via JSON-RPC over stdin/stdout.
    """
    channel_type = "signal"

    def __init__(self, config: SignalConfig, event_bus: EventBus | None = None):
        self._config = config
        self._bus = event_bus
        self._process: asyncio.subprocess.Process | None = None
        self._backoff = ExponentialBackoff(base=1.0, max_delay=300.0)
        self._running = False
        self._message_queue: asyncio.Queue[IncomingMessage] = asyncio.Queue()
        self._rpc_id = 0

    async def start(self) -> None:
        """Start signal-cli subprocess in JSON-RPC mode."""
        self._running = True
        await self._start_process()
        # Start background tasks for reading and health monitoring
        asyncio.create_task(self._read_loop())
        asyncio.create_task(self._health_monitor())

    async def _start_process(self) -> None:
        """Launch the signal-cli subprocess."""
        args = [
            self._config.signal_cli_path,
            "--output=json",
        ]
        if self._config.account:
            args.extend(["-a", self._config.account])
        args.append("jsonRpc")

        try:
            self._process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._backoff.reset()
            logger.info(
                "signal-cli started",
                extra={
                    "event": "signal_started",
                    "pid": self._process.pid,
                    "account": self._config.account,
                },
            )
        except Exception as exc:
            logger.error(
                "Failed to start signal-cli",
                extra={"event": "signal_start_failed", "error": str(exc)},
            )
            self._process = None

    async def stop(self) -> None:
        """Gracefully terminate the subprocess."""
        self._running = False
        if self._process is not None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
            finally:
                self._process = None
            logger.info("signal-cli stopped", extra={"event": "signal_stopped"})

    async def send(self, message: OutgoingMessage) -> None:
        """Send a message via signal-cli JSON-RPC."""
        if self._process is None or self._process.stdin is None:
            logger.warning(
                "Cannot send — signal-cli not running",
                extra={"event": "signal_send_failed"},
            )
            return

        self._rpc_id += 1
        rpc_request = {
            "jsonrpc": "2.0",
            "method": "send",
            "id": self._rpc_id,
            "params": {
                "message": json.dumps(message.data),
                "recipient": message.channel_id,
            },
        }

        line = json.dumps(rpc_request) + "\n"
        self._process.stdin.write(line.encode())
        await self._process.stdin.drain()

    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages queued by the read loop."""
        while self._running:
            try:
                msg = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def _read_loop(self) -> None:
        """Read JSON-RPC responses/notifications from stdout."""
        while self._running:
            if self._process is None or self._process.stdout is None:
                await asyncio.sleep(0.5)
                continue

            try:
                line = await self._process.stdout.readline()
                if not line:
                    # EOF — process has exited
                    break

                try:
                    data = json.loads(line.decode())
                except json.JSONDecodeError:
                    logger.warning(
                        "Malformed JSON from signal-cli",
                        extra={
                            "event": "signal_malformed_json",
                            "raw": line.decode()[:200],
                        },
                    )
                    continue

                # Handle incoming messages (JSON-RPC notifications)
                if "method" in data and data["method"] == "receive":
                    params = data.get("params", {})
                    envelope = params.get("envelope", {})
                    data_msg = envelope.get("dataMessage", {})
                    source = envelope.get("source", "")
                    content = data_msg.get("message", "")

                    if content:
                        msg = IncomingMessage(
                            channel_id=source,
                            source="signal",
                            content=content,
                            metadata={
                                "timestamp": envelope.get("timestamp", 0),
                                "type": "task",
                            },
                        )
                        await self._message_queue.put(msg)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    "signal-cli read error",
                    extra={"event": "signal_read_error", "error": str(exc)},
                )
                break

    async def _health_monitor(self) -> None:
        """Restart subprocess on crash with exponential backoff."""
        while self._running:
            await asyncio.sleep(1.0)

            if self._process is None:
                continue

            # Check if process has exited
            if self._process.returncode is not None:
                if not self._running:
                    break  # Intentional shutdown

                delay = self._backoff.next_delay()
                logger.warning(
                    "signal-cli crashed — restarting",
                    extra={
                        "event": "signal_crash_restart",
                        "return_code": self._process.returncode,
                        "backoff_delay": delay,
                        "attempt": self._backoff.attempt,
                    },
                )
                await asyncio.sleep(delay)
                if self._running:
                    await self._start_process()
