"""Signal messaging channel via signal-cli daemon + Unix socket.

Spawns signal-cli in daemon mode and communicates via a Unix socket at
a configurable path. Crash recovery via exponential backoff, plus periodic
socket ping to detect hung processes. Includes sender allowlist, per-sender
rate limiting, markdown stripping, response formatting, and message splitting
for Signal's character limits. All tests use mocked I/O — no signal-cli needed.
"""

import asyncio
import json
import logging
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from sentinel.channels.base import Channel, IncomingMessage, OutgoingMessage
from sentinel.core.bus import EventBus

logger = logging.getLogger("sentinel.audit")


@dataclass
class SignalConfig:
    """Configuration for the Signal channel."""
    signal_cli_path: str = "/usr/local/bin/signal-cli"
    signal_cli_config: str = "/app/signal-data"   # data directory (keys + trust store)
    socket_path: str = "/tmp/signal.sock"          # Unix socket for daemon mode
    account: str = ""             # phone number, e.g. "+1234567890"
    trust_all_known: bool = False
    allowed_senders: set[str] = field(default_factory=set)
    rate_limit: int = 10          # messages per minute per sender
    max_message_length: int = 2000


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
    """Signal messaging channel using signal-cli in daemon mode.

    Spawns signal-cli as a subprocess and communicates via Unix socket.
    The daemon creates the socket at the configured path after startup.
    Health monitoring includes process exit detection and periodic socket
    ping to detect hung processes (the 100% CPU bug).
    """
    channel_type = "signal"

    # Socket connection constants
    _SOCKET_CONNECT_INTERVAL = 0.5  # seconds between connect retries
    _SOCKET_CONNECT_TIMEOUT = 10.0  # max wait for socket after daemon start
    _PING_INTERVAL = 60.0           # seconds between health pings
    _PING_TIMEOUT = 10.0            # max wait for ping response

    def __init__(self, config: SignalConfig, event_bus: EventBus | None = None):
        self._config = config
        self._bus = event_bus
        self._process: asyncio.subprocess.Process | None = None
        self._backoff = ExponentialBackoff(base=1.0, max_delay=300.0)
        self._running = False
        self._message_queue: asyncio.Queue[IncomingMessage] = asyncio.Queue()
        self._rpc_id = 0
        # Socket I/O streams (connected after daemon starts)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        # Per-sender sliding window rate limiting (sender -> list of timestamps)
        self._rate_limits: dict[str, list[float]] = {}

    async def start(self) -> None:
        """Start signal-cli daemon and connect to its Unix socket."""
        self._running = True
        await self._start_process()
        if self._process is not None:
            await self._connect_socket()
        # Start background tasks for reading and health monitoring
        asyncio.create_task(self._read_loop())
        asyncio.create_task(self._health_monitor())

    async def _start_process(self) -> None:
        """Launch signal-cli in daemon mode with Unix socket."""
        args = [
            self._config.signal_cli_path,
            "--config", self._config.signal_cli_config,
        ]
        if self._config.account:
            args.extend(["-u", self._config.account])
        args.extend(["daemon", "--socket", self._config.socket_path])

        try:
            self._process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._backoff.reset()
            logger.info(
                "signal-cli daemon started",
                extra={
                    "event": "signal_started",
                    "pid": self._process.pid,
                    "account": self._config.account,
                    "socket": self._config.socket_path,
                },
            )
        except Exception as exc:
            logger.error(
                "Failed to start signal-cli",
                extra={"event": "signal_start_failed", "error": str(exc)},
            )
            self._process = None

    async def _connect_socket(self) -> None:
        """Connect to the daemon's Unix socket with retry loop.

        The daemon takes a moment after launch to create the socket file.
        Retries every _SOCKET_CONNECT_INTERVAL for up to _SOCKET_CONNECT_TIMEOUT.
        """
        deadline = time.monotonic() + self._SOCKET_CONNECT_TIMEOUT
        while time.monotonic() < deadline and self._running:
            try:
                self._reader, self._writer = await asyncio.open_unix_connection(
                    self._config.socket_path,
                )
                logger.info(
                    "Connected to signal-cli socket",
                    extra={
                        "event": "signal_socket_connected",
                        "socket": self._config.socket_path,
                    },
                )
                return
            except (FileNotFoundError, ConnectionRefusedError):
                await asyncio.sleep(self._SOCKET_CONNECT_INTERVAL)
            except Exception as exc:
                logger.error(
                    "Unexpected error connecting to signal-cli socket",
                    extra={"event": "signal_socket_error", "error": str(exc)},
                )
                await asyncio.sleep(self._SOCKET_CONNECT_INTERVAL)

        logger.error(
            "Failed to connect to signal-cli socket within timeout",
            extra={
                "event": "signal_socket_timeout",
                "socket": self._config.socket_path,
                "timeout": self._SOCKET_CONNECT_TIMEOUT,
            },
        )
        self._reader = None
        self._writer = None

    async def _close_socket(self) -> None:
        """Close the socket connection."""
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            finally:
                self._writer = None
                self._reader = None

    async def stop(self) -> None:
        """Close socket connection, then terminate the subprocess."""
        self._running = False
        await self._close_socket()
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
        """Format and send a response via JSON-RPC over Unix socket.

        Extracts readable text from the event payload, strips markdown,
        splits into chunks that fit Signal's message length limit, and
        sends each chunk as a separate JSON-RPC call.
        """
        if self._writer is None:
            logger.warning(
                "Cannot send — signal-cli socket not connected",
                extra={"event": "signal_send_failed"},
            )
            return

        text = _format_response(message.data)
        text = _strip_markdown(text)
        parts = _split_response(text, self._config.max_message_length)

        for part in parts:
            self._rpc_id += 1
            rpc_request = {
                "jsonrpc": "2.0",
                "method": "send",
                "id": self._rpc_id,
                "params": {
                    "message": part,
                    "recipient": message.channel_id,
                },
            }
            line = json.dumps(rpc_request) + "\n"
            try:
                self._writer.write(line.encode())
                await self._writer.drain()
            except Exception as exc:
                logger.error(
                    "Failed to write to signal-cli socket",
                    extra={"event": "signal_send_error", "error": str(exc)},
                )
                break

    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages queued by the read loop."""
        while self._running:
            try:
                msg = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    def _is_rate_limited(self, sender: str) -> bool:
        """Check if sender exceeds the rate limit (sliding 60s window)."""
        now = time.monotonic()
        window = 60.0

        timestamps = self._rate_limits.get(sender, [])
        # Prune timestamps outside the window
        timestamps = [t for t in timestamps if now - t < window]
        self._rate_limits[sender] = timestamps

        if len(timestamps) >= self._config.rate_limit:
            return True

        timestamps.append(now)
        return False

    async def _read_loop(self) -> None:
        """Read JSON-RPC notifications from the Unix socket."""
        while self._running:
            if self._reader is None:
                await asyncio.sleep(0.5)
                continue

            try:
                line = await self._reader.readline()
                if not line:
                    # EOF — daemon closed the socket
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

                    if not content:
                        continue

                    # Sender allowlist check — runs BEFORE rate limiting so
                    # unknown senders don't pollute rate limit state
                    if self._config.allowed_senders and source not in self._config.allowed_senders:
                        logger.info(
                            "Signal message from unknown sender dropped",
                            extra={
                                "event": "signal_unknown_sender",
                                "sender": source,
                            },
                        )
                        continue

                    # Rate limiting — per-sender sliding window
                    if self._is_rate_limited(source):
                        logger.warning(
                            "Signal sender rate limited",
                            extra={
                                "event": "signal_rate_limited",
                                "sender": source,
                                "limit": self._config.rate_limit,
                            },
                        )
                        continue

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
                # L-001: Continue on transient errors instead of breaking the read
                # loop. A break here leaves the process running but unmonitored —
                # the health monitor only detects process exit, not a stopped loop.
                logger.error(
                    "signal-cli read error",
                    extra={"event": "signal_read_error", "error": str(exc)},
                )
                await asyncio.sleep(0.5)
                continue

    async def _ping_socket(self) -> bool:
        """Send a JSON-RPC ping to verify the socket is responsive.

        Uses listAccounts as a lightweight RPC method. We only verify
        the write succeeds — the read loop consumes the response.
        """
        if self._writer is None:
            return False

        self._rpc_id += 1
        rpc_request = {
            "jsonrpc": "2.0",
            "method": "listAccounts",
            "id": self._rpc_id,
        }
        try:
            line = json.dumps(rpc_request) + "\n"
            self._writer.write(line.encode())
            await self._writer.drain()
            return True
        except Exception:
            return False

    async def _health_monitor(self) -> None:
        """Monitor process health and socket responsiveness.

        Two checks run in the background:
        1. Process exit detection — if returncode is set, restart with backoff
        2. Periodic socket ping — every ~60s, send a lightweight RPC to verify
           the daemon is responsive. If the write fails, kill and restart.
           This closes the gap where signal-cli is alive but hung (100% CPU bug).
        """
        ping_timer = 0.0
        while self._running:
            await asyncio.sleep(1.0)
            ping_timer += 1.0

            if self._process is None:
                continue

            # Check 1: Process has exited
            if self._process.returncode is not None:
                if not self._running:
                    break  # Intentional shutdown

                await self._close_socket()
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
                    if self._process is not None:
                        await self._connect_socket()
                    ping_timer = 0.0
                continue

            # Check 2: Periodic socket ping (detects hung process)
            if ping_timer >= self._PING_INTERVAL:
                ping_timer = 0.0
                if not await self._ping_socket():
                    logger.warning(
                        "signal-cli socket ping failed — restarting",
                        extra={
                            "event": "signal_ping_failed",
                            "pid": self._process.pid,
                        },
                    )
                    await self._close_socket()
                    try:
                        self._process.kill()
                        await asyncio.wait_for(self._process.wait(), timeout=5.0)
                    except (asyncio.TimeoutError, ProcessLookupError):
                        pass
                    self._process = None

                    delay = self._backoff.next_delay()
                    await asyncio.sleep(delay)
                    if self._running:
                        await self._start_process()
                        if self._process is not None:
                            await self._connect_socket()
                        ping_timer = 0.0


# ── Module-level formatting helpers ──────────────────────────────────

# Regex patterns for markdown stripping (compiled once at module load)
_MD_FENCED_BLOCK = re.compile(r"```[\s\S]*?```")
_MD_INLINE_CODE = re.compile(r"`([^`]+)`")
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]+\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_MD_BOLD_ASTERISK = re.compile(r"\*\*(.+?)\*\*")
_MD_BOLD_UNDERSCORE = re.compile(r"__(.+?)__")
_MD_ITALIC_ASTERISK = re.compile(r"\*(.+?)\*")
_MD_ITALIC_UNDERSCORE = re.compile(r"_(.+?)_")
_MD_HEADER = re.compile(r"^#{1,6}\s+", re.MULTILINE)
_MD_HR = re.compile(r"^-{3,}$", re.MULTILINE)
_MD_STRIKETHROUGH = re.compile(r"~~(.+?)~~")


def _strip_markdown(text: str) -> str:
    """Convert markdown-formatted text to clean plain text.

    Handles fenced code blocks, inline code, images, links, bold,
    italic, headers, horizontal rules, and strikethrough.
    """
    # Fenced code blocks → just the code content
    text = _MD_FENCED_BLOCK.sub(lambda m: m.group(0).split("\n", 1)[-1].rsplit("```", 1)[0], text)
    # Images → alt text
    text = _MD_IMAGE.sub(r"\1", text)
    # Links → link text
    text = _MD_LINK.sub(r"\1", text)
    # Inline code → just the content
    text = _MD_INLINE_CODE.sub(r"\1", text)
    # Bold
    text = _MD_BOLD_ASTERISK.sub(r"\1", text)
    text = _MD_BOLD_UNDERSCORE.sub(r"\1", text)
    # Strikethrough
    text = _MD_STRIKETHROUGH.sub(r"\1", text)
    # Italic
    text = _MD_ITALIC_ASTERISK.sub(r"\1", text)
    text = _MD_ITALIC_UNDERSCORE.sub(r"\1", text)
    # Headers → remove leading #s
    text = _MD_HEADER.sub("", text)
    # Horizontal rules
    text = _MD_HR.sub("", text)

    return text.strip()


def _format_response(data: dict) -> str:
    """Extract human-readable text from an OutgoingMessage data dict.

    Handles common orchestrator event payload patterns:
    - data["response"] — main response text
    - data["reason"] — blocking/error reasons
    - data["status"] — status-only messages
    - Fallback to compact JSON for unrecognised shapes.
    """
    if not data:
        return ""

    # Primary: response field (most task completions)
    if "response" in data and data["response"]:
        return str(data["response"])

    # Error/blocking: reason field
    if "reason" in data and data["reason"]:
        status = data.get("status", "")
        prefix = f"[{status}] " if status else ""
        return f"{prefix}{data['reason']}"

    # Status-only messages
    if "status" in data and len(data) == 1:
        return str(data["status"])

    # Payload wrapper (from ChannelRouter)
    if "payload" in data:
        return str(data["payload"])

    # Fallback: compact JSON
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _split_response(text: str, max_length: int) -> list[str]:
    """Split text into chunks that each fit within max_length.

    Splitting strategy (in priority order):
    1. Paragraph boundaries (double newline)
    2. Sentence boundaries (. ! ? followed by space or end)
    3. Hard break at max_length as last resort

    Returns at least one chunk (empty string if input is empty).
    """
    if not text:
        return [""]
    if len(text) <= max_length:
        return [text]

    chunks: list[str] = []
    remaining = text

    while remaining:
        if len(remaining) <= max_length:
            chunks.append(remaining)
            break

        # Try to split at a paragraph boundary within the limit
        segment = remaining[:max_length]
        split_pos = segment.rfind("\n\n")
        if split_pos > 0:
            chunks.append(remaining[:split_pos].rstrip())
            remaining = remaining[split_pos:].lstrip("\n")
            continue

        # Try to split at a sentence boundary
        # Look for '. ', '! ', '? ' or end-of-sentence at end of segment
        best_sentence = -1
        for match in re.finditer(r"[.!?](?:\s|$)", segment):
            pos = match.end()
            if pos <= max_length:
                best_sentence = pos
        if best_sentence > 0:
            chunks.append(remaining[:best_sentence].rstrip())
            remaining = remaining[best_sentence:].lstrip()
            continue

        # Hard break — last resort
        chunks.append(remaining[:max_length])
        remaining = remaining[max_length:]

    return chunks
