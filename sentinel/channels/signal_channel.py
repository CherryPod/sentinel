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
import os
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.core.config import Settings

from sentinel.channels.base import (
    Channel,
    ChannelDescriptor,
    IncomingMessage,
    OutgoingMessage,
)
from sentinel.core.bus import EventBus
from sentinel.core.config import settings
from sentinel.core.context import PrincipalRequiredError
from sentinel.core.socket_auth import _assert_peer_uid
from sentinel.media.models import is_mime_allowed

logger = logging.getLogger(__name__)

# Q13.fix.f — once-per-process marker so the SO_PEERCRED-unavailable fallback
# warning does not spam per-reconnect. Same pattern as sidecar.py.
_peercred_unavailable_logged = False

_RATE_WINDOW_SECONDS = 60.0


def _redact_phone(number: str) -> str:
    """Redact phone number to last 4 digits for logging.

    Phone numbers are PII — only the last 4 digits are logged so that log
    records can still be correlated without exposing the full identifier.
    """
    if len(number) >= 4:
        return f"***{number[-4:]}"
    return "***"


@dataclass
class SignalConfig:
    """Configuration for the Signal channel."""

    signal_cli_path: str = "/usr/local/bin/signal-cli"
    signal_cli_config: str = "/app/signal-data"  # data directory (keys + trust store)
    # Q13.fix.f — default re-rooted under settings.runtime_dir (/run/sentinel/)
    # per design cluster 2 Decision 1. Direct SignalConfig() constructors used
    # in unit tests don't exercise the orchestrator-init runtime_dir validator.
    socket_path: str = "/run/sentinel/signal.sock"  # Unix socket for daemon mode
    account: str = ""  # phone number, e.g. "+1234567890"
    trust_all_known: bool = False
    allowed_senders: set[str] = field(default_factory=set)
    rate_limit: int = 10  # messages per minute per sender
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
        d = self._base * (2**self._attempt)
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

    descriptor = ChannelDescriptor(
        name="signal",
        tool_name="signal_send",
        tool_description="Send a message via Signal. Write op — REQUIRES APPROVAL.",
        domain="messaging",
        config_prefix="signal_",
        keywords=("send on signal", "signal message", "message on signal"),
        preview_label="Signal",
        needs_recipient=True,
    )

    # Q11-U1 (cleanup-C49): socket-connect retry policy + ping cadence +
    # process-wait grace are operator-tunable via Settings (see
    # sentinel/core/config.py:signal_socket_connect_*, signal_ping_interval_s,
    # signal_process_wait_timeout). _PING_TIMEOUT was dead code since
    # Q11.fix.c — the live ping deadline is settings.signal_ping_timeout.

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
        # Q13.fix.f Cx-2 (2026-04-24) — single-owner reconnect lock. Both
        # _read_loop (EOF reconnect at :672-689) and _health_monitor (the
        # new writer-reconnect branch) can issue _connect_socket; without
        # the lock they race, leading to two concurrent sockets where the
        # later overwrites the earlier and orphans the writer. The race is
        # a real timing hazard because _read_loop's EOF path sleeps
        # (`await asyncio.sleep(delay)`) BEFORE calling _connect_socket,
        # opening a scheduling window for _health_monitor to see _writer
        # is None and fire its own reconnect concurrently. The lock is
        # asyncio-native (single-threaded cooperative); serialise BOTH
        # sites via _reconnect_under_lock().
        self._reconnect_lock = asyncio.Lock()
        # BH3-016: Track background tasks for graceful shutdown
        self._background_tasks: set[asyncio.Task] = set()
        # Per-sender sliding window rate limiting (sender -> list of timestamps)
        self._rate_limits: dict[str, list[float]] = {}
        # Attachment ingester — set by lifecycle.py after startup
        self._ingester = None

    async def start(self) -> None:
        """Start signal-cli daemon and connect to its Unix socket."""
        self._running = True
        await self._start_process()
        if self._process is not None:
            await self._connect_socket()
        # Infrastructure: no user context needed — read loop and health monitor
        # are channel-level background tasks not scoped to any particular user.
        # (BH3-016: tracked for shutdown)
        for coro in (self._read_loop(), self._health_monitor()):
            task = asyncio.create_task(coro)
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def _start_process(self) -> None:
        """Launch signal-cli in daemon mode with Unix socket."""
        args = [
            self._config.signal_cli_path,
            "--config",
            self._config.signal_cli_config,
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
                    "event": "signal.started",
                    "pid": self._process.pid,
                    "account": self._config.account,
                    "socket": self._config.socket_path,
                },
            )
        except Exception as exc:
            logger.error(
                "Failed to start signal-cli",
                extra={"event": "signal.start_failed", "error": str(exc)},
                exc_info=True,
            )
            self._process = None

    async def _connect_socket(self) -> None:
        """Connect to the daemon's Unix socket with retry loop.

        The daemon takes a moment after launch to create the socket file.
        Retries every ``settings.signal_socket_connect_interval_s`` for up to
        ``settings.signal_socket_connect_timeout``.
        """
        deadline = time.monotonic() + settings.signal_socket_connect_timeout
        while time.monotonic() < deadline and self._running:
            try:
                # PH-Q11.c-b1 (Q11.fix.b MC-review 2026-04-22): bound the
                # individual open_unix_connection call. The outer monotonic
                # deadline only re-checks after each await returns, so a hung
                # peer (socket file exists, accept() never completes) could
                # block one call beyond the total signal_socket_connect_timeout.
                # The per-call timeout uses the same setting as the upper
                # bound; TimeoutError flows to the catch-all below and the
                # loop retries after signal_socket_connect_interval_s.
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(self._config.socket_path),
                    timeout=settings.signal_socket_connect_timeout,
                )
                # Q13.fix.f — peer-UID check on every new connect. See
                # sentinel/core/socket_auth.py and design cluster 2 Decision 2.
                # On mismatch: PermissionError closes the writer inside the
                # helper; the local except branch resets state and returns
                # so the outer loop can back off. On non-Linux kernel /
                # missing SO_PEERCRED: one-shot warning + fall back to
                # ACL-only (the 0700 runtime_dir still pins the path).
                global _peercred_unavailable_logged
                try:
                    await _assert_peer_uid(
                        self._writer,
                        self._config.socket_path,
                        module_event_prefix="signal.peer_uid",
                    )
                except PermissionError:
                    # Helper already closed the writer. Reset local state so
                    # the outer reconnect logic treats this like a failed
                    # connect; do NOT sleep here — the caller drives backoff.
                    logger.warning(
                        "Signal socket peer auth failed; connection refused",
                        extra={
                            "event": "signal.peer_auth_failed",
                            "socket": self._config.socket_path,
                        },
                        exc_info=True,
                    )
                    self._reader = None
                    self._writer = None
                    return
                except OSError as exc:
                    # SO_PEERCRED unavailable — non-Linux host or kernel quirk.
                    # ACL-only posture is still meaningful (0700 runtime_dir).
                    if not _peercred_unavailable_logged:
                        _peercred_unavailable_logged = True
                        logger.warning(
                            "SO_PEERCRED unavailable on signal socket; "
                            "ACL-only fallback",
                            extra={
                                "event": "signal.peercred_unavailable",
                                "socket": self._config.socket_path,
                                "error": str(exc),
                            },
                            exc_info=True,
                        )
                logger.info(
                    "Connected to signal-cli socket",
                    extra={
                        "event": "signal.socket_connected",
                        "socket": self._config.socket_path,
                    },
                )
                return
            except (FileNotFoundError, ConnectionRefusedError):
                logger.debug(
                    "_connect_socket: FileNotFoundError | ConnectionRefusedError",
                    extra={"event": "signal_channel.socket_connect_retry"},
                )
                await asyncio.sleep(settings.signal_socket_connect_interval_s)
            except Exception as exc:  # catch-all: socket connect unexpected error
                logger.warning(
                    "Unexpected error connecting to signal-cli socket",
                    extra={"event": "signal.socket_error", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(settings.signal_socket_connect_interval_s)

        logger.error(
            "Failed to connect to signal-cli socket within timeout",
            extra={
                "event": "signal.socket_timeout",
                "socket": self._config.socket_path,
                "timeout": settings.signal_socket_connect_timeout,
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
            except Exception:  # catch-all: socket close best-effort
                logger.debug(
                    "_close_socket: Exception suppressed",
                    extra={"event": "signal_channel._close_socket.suppressed"},
                    exc_info=True,
                )
            finally:
                self._writer = None
                self._reader = None

    async def _reconnect_under_lock(self) -> None:
        """Q13.fix.f Cx-2 — serialise reconnect attempts across _read_loop
        (EOF) and _health_monitor (writer-reconnect). The lock guarantees at
        most one `_connect_socket()` in flight; the second caller arrives
        after the first finishes and re-checks `_writer is None` before
        firing another connect. Without this, both loops can concurrently
        call `open_unix_connection`, leaving one socket orphaned and racing
        `_reader/_writer` assignments.
        """
        async with self._reconnect_lock:
            # Second caller arrives after the first completed — if the first
            # already reconnected successfully, skip; the writer is live.
            if self._writer is not None:
                return
            if not self._running:
                return
            await self._connect_socket()

    async def stop(self) -> None:
        """Cancel background tasks, close socket, then terminate the subprocess."""
        self._running = False
        # BH3-016: Cancel tracked background tasks
        for task in list(self._background_tasks):
            task.cancel()
        # Wait briefly for tasks to finish cancellation
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()
        await self._close_socket()
        if self._process is not None:
            try:
                self._process.terminate()
                await asyncio.wait_for(
                    self._process.wait(),
                    timeout=settings.signal_process_wait_timeout,
                )
            except (TimeoutError, ProcessLookupError):
                logger.debug(
                    "stop: TimeoutError | ProcessLookupError",
                    extra={"event": "signal_channel.stop_timeout"},
                )
                try:
                    self._process.kill()
                except ProcessLookupError:
                    logger.debug(
                        "stop: ProcessLookupError suppressed",
                        extra={"event": "signal_channel.stop.suppressed"},
                        exc_info=True,
                    )
            finally:
                self._process = None
            logger.info("signal-cli stopped", extra={"event": "signal.stopped"})

    async def send(self, message: OutgoingMessage) -> None:
        """Format and send a response via JSON-RPC over Unix socket.

        Extracts readable text from the event payload, strips markdown,
        splits into chunks that fit Signal's message length limit, and
        sends each chunk as a separate JSON-RPC call.
        """
        if self._writer is None:
            logger.warning(
                "Cannot send — signal-cli socket not connected",
                extra={"event": "signal.send_failed"},
            )
            return

        text = _format_response(message.data)
        text = _strip_markdown(text)
        parts = _split_response(text, self._config.max_message_length)

        for i, part in enumerate(parts):
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
                logger.debug("send: file_io", extra={"event": "signal_channel.send.io"})
                self._writer.write(line.encode())
                await asyncio.wait_for(
                    self._writer.drain(),
                    timeout=settings.channel_send_timeout,
                )
            except TimeoutError:
                logger.warning(
                    "Signal send timed out",
                    extra={"event": "signal.send_timeout"},
                    exc_info=True,
                )
                break
            except (ConnectionError, BrokenPipeError) as exc:
                # Socket dead — no point retrying
                logger.warning(
                    "Signal socket broken, aborting send",
                    extra={
                        "event": "signal.send_error",
                        "error": str(exc),
                        "chunks_sent": i,
                        "chunks_total": len(parts),
                    },
                    exc_info=True,
                )
                break
            except Exception as exc:  # catch-all: send retry on transient error
                # Transient error — retry once with short delay
                logger.warning(
                    "Signal send error, retrying once",
                    extra={"event": "signal.send_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(1)
                try:
                    logger.debug(
                        "send: file_io", extra={"event": "signal_channel.send.io"}
                    )
                    self._writer.write(line.encode())
                    await asyncio.wait_for(
                        self._writer.drain(),
                        timeout=settings.channel_send_timeout,
                    )
                except Exception as retry_exc:  # catch-all: send retry failed
                    logger.warning(
                        "Signal send failed after retry",
                        extra={
                            "event": "signal.send_failed",
                            "error": str(retry_exc),
                            "chunks_sent": i,
                            "chunks_total": len(parts),
                        },
                        exc_info=True,
                    )
                    break

    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages queued by the read loop."""
        while self._running:
            try:
                # Q11-U1 documented exception: receive-loop poll cadence;
                # same pattern as matrix_channel _RECEIVE_POLL_SECONDS — a
                # yields-control-back-to-event-loop idiom, not an external-
                # service deadline. Not operator-tunable.
                msg = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                yield msg
            except TimeoutError:
                continue

    # -- Registry extensions ---------------------------------------------------

    @classmethod
    def from_settings(cls, settings: "Settings") -> "SignalChannel | None":
        """Build from flat Settings fields. Returns None if disabled."""
        if not settings.signal_enabled:
            return None
        allowed = {
            s.strip() for s in settings.signal_allowed_senders.split(",") if s.strip()
        }
        config = SignalConfig(
            signal_cli_path=settings.signal_cli_path,
            signal_cli_config=settings.signal_cli_config,
            socket_path=settings.signal_socket_path,
            account=settings.signal_account,
            allowed_senders=allowed,
            rate_limit=settings.signal_rate_limit,
            max_message_length=settings.signal_max_message_length,
        )
        return cls(config)

    async def send_message(self, text: str, recipient: str | None = None) -> dict:
        """High-level send for tool dispatch."""
        out = OutgoingMessage(
            channel_id=recipient or "",
            event_type="tool.signal_send",
            data={"response": text},
        )
        await self.send(out)
        return {"status": "sent", "channel": "signal"}

    @property
    def is_running(self) -> bool:
        return self._running

    def _is_rate_limited(self, sender: str) -> bool:
        """Check if sender exceeds the rate limit (sliding 60s window)."""
        logger.debug(
            "_is_rate_limited called",
            extra={"event": "signal_channel.rate_limit_check", "sender": sender},
        )
        now = time.monotonic()

        timestamps = self._rate_limits.get(sender, [])
        # Prune timestamps outside the window
        timestamps = [t for t in timestamps if now - t < _RATE_WINDOW_SECONDS]
        self._rate_limits[sender] = timestamps

        if len(timestamps) >= self._config.rate_limit:
            return True

        timestamps.append(now)
        return False

    async def _process_attachments(
        self,
        raw_attachments: list[dict],
        sender: str,
    ) -> list[dict]:
        """Process raw signal-cli attachment dicts through the ingester.

        For each attachment: resolve the on-disk path from signal-cli's
        data directory, validate MIME type, and ingest via AttachmentIngester.
        Failures (missing file, blocked MIME, I/O error) are logged and
        skipped — they never crash the read loop.

        Returns a list of dicts suitable for IncomingMessage.attachments.
        """
        if not raw_attachments or self._ingester is None:
            return []

        attachment_metas: list[dict] = []

        for att in raw_attachments:
            att_id = att.get("id", "")
            att_mime = att.get("contentType", "application/octet-stream")
            # signal-cli sends "filename": null for some media (e.g. video
            # notes). Build a timestamped fallback so files are identifiable.
            att_filename = att.get("filename")
            if not att_filename:
                ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
                ext = att_mime.split("/")[-1].split(";")[
                    0
                ]  # e.g. "mp4" from "video/mp4"
                att_filename = f"signal-{ts}.{ext}"
            att_size = att.get("size", 0)

            # Check MIME allowlist before touching disk
            if not is_mime_allowed(att_mime):
                logger.info(
                    "Signal attachment skipped: MIME type not allowed",
                    extra={
                        "event": "signal.attachment_mime_blocked",
                        "attachment_id": att_id,
                        "mime_type": att_mime,
                        "sender": _redact_phone(sender),
                    },
                )
                continue

            # Build source path from signal-cli's data directory
            source_path = os.path.join(
                self._config.signal_cli_config,
                "attachments",
                att_id,
            )
            if not os.path.isfile(source_path):
                logger.warning(
                    "Signal attachment file not found on disk",
                    extra={
                        "event": "signal.attachment_missing",
                        "attachment_id": att_id,
                        "source_path": source_path,
                        "sender": _redact_phone(sender),
                    },
                )
                continue

            try:
                meta = await self._ingester.ingest_from_path(
                    source_path=source_path,
                    mime_type=att_mime,
                    original_filename=att_filename,
                    source_channel="signal",
                    channel_file_id=att_id,
                )
                attachment_metas.append(
                    {
                        "attachment_id": meta.attachment_id,
                        "mime_type": meta.mime_type,
                        "original_filename": meta.original_filename,
                        "safe_filename": meta.safe_filename,
                        "file_size": att_size,
                        "workspace_path": meta.workspace_path,
                    }
                )
            except PrincipalRequiredError:
                # Q4.fix.c: zero-principal is a fail-closed signal from the
                # store (MediaStore.save). Signal's read loop runs as channel
                # infrastructure (no current_user_id set — see start()), so
                # this indicates the upstream binding is missing (Q4.fix.d
                # scope). Re-raise before the broad ValueError catch so the
                # failure propagates loudly instead of being mis-logged as
                # signal.attachment_ingest_error.
                raise
            except (ValueError, OSError) as exc:
                logger.warning(
                    "Signal attachment ingestion failed",
                    extra={
                        "event": "signal.attachment_ingest_error",
                        "attachment_id": att_id,
                        "error_detail": str(exc),
                        "sender": _redact_phone(sender),
                    },
                    exc_info=True,
                )
                continue

        return attachment_metas

    async def _read_loop(self) -> None:
        """Read JSON-RPC notifications from the Unix socket.

        On EOF (daemon restart, socket closed), reconnects with exponential
        backoff (1s, 2s, 4s, ... max 30s) instead of exiting permanently.
        """
        eof_backoff = ExponentialBackoff(base=1.0, max_delay=30.0)
        while self._running:
            if self._reader is None:
                await asyncio.sleep(0.5)
                continue

            try:
                logger.debug(
                    "_read_loop: file_io",
                    extra={"event": "signal_channel._read_loop.io"},
                )
                # Q11-F6a (Option A, 2026-04-24): per-readline deadline using
                # `settings.signal_read_timeout` (300s). Subsumes the Q13-F2
                # partial-frame envelope: a peer writing partial bytes below the
                # 64 KiB StreamReader limit without newline-terminating would
                # otherwise stall this read coroutine indefinitely — the health
                # monitor pings the writer, not the reader, so such a stall
                # would be invisible. On timeout the outer ``except TimeoutError``
                # handler nulls the socket; recovery is then implicit via
                # ``_health_monitor`` Check 1 (writer-never-connected branch,
                # Q13.fix.f), which fires on the next 1s loop iteration and
                # routes through ``_reconnect_under_lock`` with exponential
                # backoff. No longer gated on ``signal_ping_interval_s`` —
                # ping-fail recovery is the fallback path for hung-but-alive
                # daemons, not for socket-cleared-by-timeout cases. The
                # reader-None guard at the top of this loop is an idle
                # parking branch, not a reconnect path. (Recovery asymmetry
                # vs the EOF path is logged as Q13-FL fix-later — the EOF
                # path reconnects in-line via _connect_socket under
                # exponential backoff.)
                #
                # Q13-F11: framing-overflow catch is scoped tight to the readline
                # call. StreamReader.readline() repackages internal
                # LimitOverrunError as plain ValueError (asyncio/streams.py:577),
                # so ValueError is the production shape; LimitOverrunError is
                # included as defence-in-depth for a future readuntil() switch
                # or asyncio implementation change. Keeping this catch off the
                # outer try avoids mislabelling other ValueError subclasses
                # (notably UnicodeDecodeError from line.decode() below) as
                # framing overflow.
                try:
                    line = await asyncio.wait_for(
                        self._reader.readline(),
                        timeout=settings.signal_read_timeout,
                    )
                except (ValueError, asyncio.LimitOverrunError) as exc:
                    raw_length = getattr(exc, "consumed", None)
                    logger.warning(
                        "signal-cli framing overflow",
                        extra={
                            "event": "signal.framing_overflow",
                            "raw_length": (
                                raw_length if raw_length is not None else str(exc)
                            ),
                        },
                        exc_info=True,
                    )
                    await asyncio.sleep(0.5)
                    continue
                if not line:
                    # EOF — daemon closed the socket; reconnect with backoff
                    if not self._running:
                        break
                    delay = eof_backoff.next_delay()
                    logger.warning(
                        "signal-cli socket EOF — reconnecting",
                        extra={
                            "event": "signal.socket_eof",
                            "backoff_delay": delay,
                            "attempt": eof_backoff.attempt,
                        },
                    )
                    await self._close_socket()
                    await asyncio.sleep(delay)
                    if self._running:
                        # Q13.fix.f Cx-2 — route through the shared reconnect
                        # lock so _health_monitor's writer-reconnect branch
                        # can't race this path and produce two concurrent
                        # open_unix_connection calls.
                        await self._reconnect_under_lock()
                        if self._reader is not None:
                            eof_backoff.reset()
                    continue

                try:
                    data = json.loads(line.decode())
                except json.JSONDecodeError:
                    logger.warning(
                        "Malformed JSON from signal-cli",
                        extra={
                            "event": "signal.malformed_json",
                            "raw_length": len(line),
                        },
                        exc_info=True,
                    )
                    continue

                # Handle incoming messages (JSON-RPC notifications)
                if "method" in data and data["method"] == "receive":
                    params = data.get("params", {})
                    envelope = params.get("envelope", {})
                    data_msg = envelope.get("dataMessage", {})
                    source = envelope.get("source", "")
                    content = data_msg.get("message", "")

                    # Sender allowlist check — runs BEFORE attachment ingestion
                    # so unknown senders cannot write files to disk or DB.
                    if source not in self._config.allowed_senders:
                        logger.info(
                            "Signal message from unknown sender dropped",
                            extra={
                                "event": "signal.unknown_sender",
                                "sender": _redact_phone(source),  # was: source
                            },
                        )
                        continue

                    # Rate limiting — per-sender sliding window
                    if self._is_rate_limited(source):
                        logger.warning(
                            "Signal sender rate limited",
                            extra={
                                "event": "signal.rate_limited",
                                "sender": _redact_phone(source),  # was: source
                                "rate_limit_count": self._config.rate_limit,
                            },
                        )
                        continue

                    # Extract and ingest attachments from the envelope
                    # (after allowlist + rate limit so unknown/abusive senders
                    # cannot write files to disk or DB).
                    raw_attachments = data_msg.get("attachments", [])
                    attachment_metas = await self._process_attachments(
                        raw_attachments,
                        source,
                    )

                    # Skip if there is neither text content nor valid attachments
                    if not content and not attachment_metas:
                        continue

                    msg = IncomingMessage(
                        channel_id=source,
                        source="signal",
                        content=content,
                        metadata={
                            "timestamp": envelope.get("timestamp", 0),
                            "type": "task",
                        },
                        attachments=attachment_metas,
                    )
                    await self._message_queue.put(msg)

            except asyncio.CancelledError:
                # Q11-F6c: propagate cancellation so the parent's `await task`
                # observes `cancelled() is True`. A prior `break` exited the
                # loop normally and the parent saw a completed task, erasing
                # the "cancelled during shutdown" signal.
                raise
            except TimeoutError:
                # Q11-F6a (Option A, 2026-04-24): the readline wait_for now uses
                # `signal_read_timeout` (300s) rather than `signal_framing_timeout_s`
                # (600s). The tighter Q11 deadline subsumes the Q13-F2 partial-frame
                # envelope — 300s catches both daemon-hang and partial-frame stalls.
                # `signal_framing_timeout_s` is retained as a deprecated setting
                # pending Q16-class cleanup. Event name `signal.framing_timeout`
                # kept for audit-log continuity (semantic is still "framing deadline
                # exceeded"; only the timeout value changed).
                #
                # Q13-F2 original context: framing deadline exceeded — peer wrote
                # no newline within the bound. Close the socket. The reader-None
                # guard at the top of _read_loop then parks the loop;
                # ``_health_monitor`` 's Check 1 (writer-never-connected,
                # Q13.fix.f) fires on the next 1s loop iteration and routes
                # through ``_reconnect_under_lock`` with exponential backoff —
                # no longer gated on ``signal_ping_interval_s``. EOF path
                # reconnects in-line via _connect_socket under exponential
                # backoff — see Q13-FL.
                logger.warning(
                    "signal-cli framing timeout — reconnecting",
                    extra={
                        "event": "signal.framing_timeout",
                        "socket_path": self._config.socket_path,
                        "timeout_s": settings.signal_read_timeout,
                    },
                    exc_info=True,  # auto:exc
                )
                await self._close_socket()
                continue
            except Exception as exc:  # catch-all: message processing isolation
                # L-001: Continue on transient errors instead of breaking the read
                # loop. A break here leaves the process running but unmonitored —
                # the health monitor only detects process exit, not a stopped loop.
                logger.warning(
                    "signal-cli read error",
                    extra={"event": "signal.read_error", "error": str(exc)},
                    exc_info=True,
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
            logger.debug(
                "_ping_socket: file_io",
                extra={"event": "signal_channel._ping_socket.io"},
            )
            self._writer.write(line.encode())
            # Q11-F6b: bound the drain() write to prevent a hung signal-cli from
            # stalling the health monitor. Mirrors the send paths at :315/:352
            # which wrap drain() in settings.channel_send_timeout; ping drain is
            # lighter weight (~100 bytes), so signal_ping_timeout (10s) is tighter.
            # TimeoutError (which asyncio.wait_for raises on deadline) subclasses
            # Exception, so it flows to the best-effort handler below and the
            # method returns False — the health monitor's ping-failed branch then
            # kills and restarts the daemon.
            await asyncio.wait_for(
                self._writer.drain(),
                timeout=settings.signal_ping_timeout,
            )
            return True
        except Exception:  # catch-all: ping socket best-effort
            logger.debug(
                "_ping_socket: Exception", extra={"event": "signal_channel.ping_error"}
            )
            return False

    async def _health_monitor(self) -> None:
        """Monitor process health and socket responsiveness.

        Three checks run in the background:
        1. Writer-never-connected (Q13.fix.f) — if the daemon is alive but
           the socket writer is None (e.g. initial connect hit
           SO_PEERCRED mismatch, or first-boot PermissionError), retry
           _connect_socket() with backoff. Without this, a boot-time
           peer-auth failure leaves the channel dead indefinitely —
           _read_loop would spin-sleep on None reader and the existing
           ping + returncode checks never fire. See design doc
           §"Signal-side reconnect — implementation-time verify".
        2. Process exit detection — if returncode is set, restart with backoff
        3. Periodic socket ping — every ~60s, send a lightweight RPC to verify
           the daemon is responsive. If the write fails, kill and restart.
           This closes the gap where signal-cli is alive but hung (100% CPU bug).
        """
        ping_timer = 0.0
        while self._running:
            await asyncio.sleep(1.0)
            ping_timer += 1.0

            if self._process is None:
                continue

            # Check 1 (Q13.fix.f): Writer never connected. Daemon is alive
            # (_process is not None, returncode will gate to Check 2 if exited),
            # but the socket isn't connected. Most likely cause: initial
            # _connect_socket() hit SO_PEERCRED mismatch or PermissionError
            # and returned with _writer=None. Retry _connect_socket() here
            # with backoff so the channel can recover without needing the
            # daemon to crash first. Q13.fix.f Cx-2: serialise with
            # _read_loop's EOF reconnect via the shared _reconnect_under_lock
            # helper so both sites can never call open_unix_connection
            # concurrently.
            if self._writer is None and self._process.returncode is None:
                delay = self._backoff.next_delay()
                logger.debug(
                    "Signal writer is None; retrying _connect_socket",
                    extra={
                        "event": "signal.writer_reconnect",
                        "backoff_delay": delay,
                        "attempt": self._backoff.attempt,
                    },
                )
                await asyncio.sleep(delay)
                if self._running and self._writer is None:
                    await self._reconnect_under_lock()
                    if self._writer is not None:
                        # Successful reconnect — reset backoff for future
                        # failures.
                        self._backoff.reset()
                ping_timer = 0.0
                continue

            # Check 2: Process has exited
            if self._process.returncode is not None:
                if not self._running:
                    break  # Intentional shutdown

                await self._close_socket()
                delay = self._backoff.next_delay()
                logger.warning(
                    "signal-cli crashed — restarting",
                    extra={
                        "event": "signal.crash_restart",
                        "return_code": self._process.returncode,
                        "backoff_delay": delay,
                        "attempt": self._backoff.attempt,
                    },
                )
                await asyncio.sleep(delay)
                if self._running:
                    await self._start_process()
                    if self._process is not None:
                        # Q13.fix.f Cx-4 — route through the shared reconnect
                        # lock. A daemon crash wakes _read_loop (EOF from the
                        # dying socket) and _health_monitor (returncode !=
                        # None) simultaneously; without the lock, both tasks
                        # call _connect_socket concurrently and the later
                        # writer-assignment orphans the earlier one. Cx-2
                        # originally claimed this site "cannot race the other
                        # sites" — that claim is retracted (see commit msg).
                        await self._reconnect_under_lock()
                    ping_timer = 0.0
                continue

            # Check 3: Periodic socket ping (detects hung process)
            if ping_timer >= settings.signal_ping_interval_s:
                ping_timer = 0.0
                if not await self._ping_socket():
                    logger.warning(
                        "signal-cli socket ping failed — restarting",
                        extra={
                            "event": "signal.ping_failed",
                            "pid": self._process.pid,
                        },
                    )
                    await self._close_socket()
                    try:
                        self._process.kill()
                        await asyncio.wait_for(
                            self._process.wait(),
                            timeout=settings.signal_process_wait_timeout,
                        )
                    except (TimeoutError, ProcessLookupError):
                        logger.debug(
                            "_health_monitor: TimeoutError | ProcessLookupError suppressed",
                            extra={
                                "event": "signal_channel._health_monitor.suppressed"
                            },
                            exc_info=True,
                        )
                    self._process = None

                    delay = self._backoff.next_delay()
                    await asyncio.sleep(delay)
                    if self._running:
                        await self._start_process()
                        if self._process is not None:
                            # Q13.fix.f Cx-4 — same race class as Check 2:
                            # closing the hung socket above unblocks
                            # _read_loop's readuntil() with EOF, which
                            # routes through _reconnect_under_lock.
                            # Without the lock here, this task's reconnect
                            # races that one. Route through the helper.
                            await self._reconnect_under_lock()
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
_SENTENCE_END = re.compile(r"[.!?](?:\s|$)")


def _strip_markdown(text: str) -> str:
    """Convert markdown-formatted text to clean plain text.

    Handles fenced code blocks, inline code, images, links, bold,
    italic, headers, horizontal rules, and strikethrough.
    """
    # Fenced code blocks → just the code content
    logger.debug(
        "_strip_markdown called",
        extra={
            "event": "signal_channel.strip_markdown",
            "text_len": len(text) if text else 0,
        },
    )
    text = _MD_FENCED_BLOCK.sub(
        lambda m: m.group(0).split("\n", 1)[-1].rsplit("```", 1)[0], text
    )
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
    logger.debug(
        "_format_response called",
        extra={
            "event": "signal_channel.format_response",
            "data_len": len(data) if data else 0,
        },
    )
    if not data:
        return ""

    # Primary: response field (most task completions)
    if data.get("response"):
        logger.debug(
            "format_response: response field",
            extra={
                "event": "signal_channel.format_response.match",
                "field": "response",
            },
        )
        return str(data["response"])

    # Error/blocking: reason field
    if data.get("reason"):
        status = data.get("status", "")
        prefix = f"[{status}] " if status else ""
        return f"{prefix}{data['reason']}"

    # Status-only messages
    if "status" in data and len(data) == 1:
        return str(data["status"])

    # Payload wrapper (from ChannelRouter)
    if "payload" in data:
        return str(data["payload"])

    # Confirmation gate preview
    if "preview" in data and "confirmation_id" in data:
        return f"{data['preview']}\n\nReply 'go' to confirm."

    # Plan approval request
    if "approval_id" in data and "plan_summary" in data:
        summary = data["plan_summary"]
        steps = data.get("steps", [])
        step_lines = "\n".join(
            f"  - {s.get('description', s.get('type', ''))}" for s in steps
        )
        return f"Plan: {summary}\n{step_lines}\n\nReply 'go' to approve."

    # Fallback: compact JSON
    logger.debug(
        "format_response: fallback to JSON",
        extra={
            "event": "signal_channel.format_response.fallback",
            "keys": list(data.keys())[:5],
        },
    )
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _split_response(text: str, max_length: int) -> list[str]:
    """Split text into chunks that each fit within max_length.

    Splitting strategy (in priority order):
    1. Paragraph boundaries (double newline)
    2. Sentence boundaries (. ! ? followed by space or end)
    3. Hard break at max_length as last resort

    Returns at least one chunk (empty string if input is empty).
    """
    logger.debug(
        "_split_response called",
        extra={
            "event": "signal_channel.split_response",
            "text_len": len(text) if text else 0,
            "max_length": max_length,
        },
    )
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
        for match in _SENTENCE_END.finditer(segment):
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
