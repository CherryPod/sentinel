"""SidecarClient — async Unix socket client for the Rust WASM sidecar.

Handles connection management, crash recovery, and request/response
serialization. The sidecar is auto-started on first use if the socket
doesn't exist and a binary path is configured.
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import uuid
from dataclasses import dataclass

from sentinel.core.socket_auth import _assert_peer_uid

logger = logging.getLogger(__name__)

# Q13.fix.f — once-per-process marker so the SO_PEERCRED-unavailable fallback
# warning does not spam per-request. The fallback only fires on non-Linux or
# missing-SO_PEERCRED kernels; in the controller container (Ubuntu 24.04) it
# should never fire. Surface loudly at first occurrence for operator visibility.
_peercred_unavailable_logged = False


class SidecarResponseTooLargeError(Exception):
    """Receiver-side response cap exceeded.

    Raised by ``_send_request`` when ``reader.readline()`` exceeds the
    ``StreamReader.limit`` set to ``_MAX_RESPONSE_BYTES`` (4 MiB). The
    sidecar process is healthy when this fires; ``execute()`` returns
    ``success=False`` without restarting the subprocess. Defence-in-depth
    against operator config drift, future Rust tool additions bypassing
    the host_call IO_BUFFER discipline, or sidecar protocol-line bugs.
    """


class SidecarProtocolError(Exception):
    """Sidecar returned a response line that is not valid JSON.

    Raised by ``_send_request`` when ``json.loads(response_line)`` fails.
    The sidecar process is healthy when this fires (the line was received);
    ``execute()`` returns ``success=False`` without restarting the subprocess.
    Keeps ``json.JSONDecodeError`` from escaping past the executor boundary
    and violating the Q14-F2 structured-error contract.
    """


@dataclass
class SidecarResponse:
    """Response from the sidecar after tool execution."""

    success: bool
    result: str
    data: dict | None = None
    leaked: bool = False
    fuel_consumed: int | None = None


class SidecarClient:
    """Async client for communicating with the Rust WASM sidecar over Unix socket.

    Features:
    - Auto-start: spawns the sidecar binary if socket doesn't exist
    - Crash recovery: on connection error, restarts sidecar and retries once
    - Timeout handling: per-request asyncio.wait_for
    """

    def __init__(
        self,
        # Q13.fix.f — default re-rooted under /run/sentinel (see settings.runtime_dir).
        # In production, callers pass settings.sidecar_socket explicitly; this default
        # is only used by direct-instantiation unit tests that don't exercise the
        # runtime_dir validator (orchestrator init path does).
        socket_path: str = "/run/sentinel/sentinel-sidecar.sock",
        # Q11-U1 documented exception: +5s envelope buffer over the sidecar's
        # inner 30s execution timeout — same envelope-margin pattern as
        # sandbox.py:_create_client. Production callers pass
        # settings.sidecar_timeout via orchestrator.py:236; this default
        # applies only to direct-instantiation tests.
        timeout: int = 35,
        sidecar_binary_path: str = "",
        tool_dir: str = "",
    ):
        self._socket_path = socket_path
        self._timeout = timeout
        self._binary_path = sidecar_binary_path
        self._tool_dir = tool_dir
        self._process: subprocess.Popen | None = None
        self._stderr_task: asyncio.Task | None = None

    async def execute(
        self,
        tool_name: str,
        args: dict,
        capabilities: list[str] | None = None,
        credentials: dict[str, str] | None = None,
        timeout: int | None = None,
        http_allowlist: list[str] | None = None,
    ) -> SidecarResponse:
        """Execute a tool via the sidecar.

        On connection failure, attempts to restart the sidecar and retry once.
        """
        request = {
            "request_id": _generate_request_id(),
            "tool_name": tool_name,
            "args": args,
            "capabilities": capabilities or [],
            "credentials": credentials or {},
        }
        if timeout is not None:
            request["timeout_ms"] = timeout * 1000
        if http_allowlist is not None:
            request["http_allowlist"] = http_allowlist

        effective_timeout = timeout or self._timeout

        try:
            return await asyncio.wait_for(
                self._send_request(request),
                timeout=effective_timeout,
            )
        except TimeoutError:
            logger.warning(
                "execute: TimeoutError",
                extra={"event": "sidecar.execute_timeout"},
                exc_info=True,
            )
            return SidecarResponse(
                success=False,
                result=f"sidecar timeout after {effective_timeout}s",
            )
        except PermissionError:
            # Q13.fix.f — SO_PEERCRED mismatch on the sidecar socket. Fail closed:
            # do NOT call start_sidecar() + retry, because a mismatched peer UID
            # means the socket is bound by a process we did not expect. Retrying
            # would re-connect to the same wrong peer (the Rust sidecar spawn
            # races with a squatter). PermissionError is an OSError subclass, so
            # this except branch MUST precede the (ConnectionError, BrokenPipeError,
            # OSError) tuple below — Python matches the first branch whose types
            # include the raised class.
            logger.warning(
                "Sidecar peer auth failed; not retrying",
                extra={"event": "sidecar.peer_auth_failed"},
                exc_info=True,
            )
            return SidecarResponse(
                success=False,
                result="sidecar peer auth failed",
            )
        except SidecarResponseTooLargeError:
            # C66 / PH-Q14→Q10-F1 — receiver-side _MAX_RESPONSE_BYTES cap fired.
            # The sidecar process is healthy; do NOT call start_sidecar(). The
            # cap is defence-in-depth against operator config drift, future
            # Rust tools bypassing host_call IO_BUFFER discipline, or sidecar
            # protocol-line bugs. SidecarResponseTooLargeError inherits from
            # Exception (not OSError), so this branch's placement before the
            # (ConnectionError, BrokenPipeError, OSError) tuple is a
            # readability convention, not a class-hierarchy requirement.
            logger.warning(
                "Sidecar response exceeded receiver cap; not restarting",
                extra={
                    "event": "sidecar.response_too_large",
                    "cap_bytes": self._MAX_RESPONSE_BYTES,
                },
                exc_info=True,
            )
            return SidecarResponse(
                success=False,
                result=f"sidecar response too large (>{self._MAX_RESPONSE_BYTES} bytes)",
            )
        except SidecarProtocolError:
            # CRIT-13 — sidecar sent a line that is not valid JSON. The sidecar
            # process is healthy (the line was received); do NOT restart.
            # Converts raw json.JSONDecodeError into a structured SidecarResponse
            # so it cannot escape past the ToolExecutor boundary (Q14-F2 contract).
            logger.warning(
                "Sidecar response is not valid JSON; not restarting",
                extra={"event": "sidecar.protocol_error"},
                exc_info=True,
            )
            return SidecarResponse(
                success=False,
                result="sidecar protocol error: malformed JSON response",
            )
        except (ConnectionError, BrokenPipeError, OSError) as exc:
            logger.warning(
                "Sidecar connection failed, attempting restart",
                extra={"event": "sidecar.reconnect", "error": str(exc)},
                exc_info=True,
            )
            # Q14-F2: include start_sidecar() inside the retry try so a
            # RuntimeError from startup ("no sidecar binary path configured" /
            # "sidecar exited during startup" / "sidecar did not signal
            # readiness") becomes a structured SidecarResponse instead of
            # propagating past the ToolExecutor boundary.
            try:
                await self.start_sidecar()
                return await asyncio.wait_for(
                    self._send_request(request),
                    timeout=effective_timeout,
                )
            except Exception as retry_exc:
                logger.error(
                    "Sidecar restart-or-retry failed",
                    extra={
                        "event": "sidecar.restart_or_retry_failed",
                        "error": str(retry_exc),
                    },
                    exc_info=True,
                )
                return SidecarResponse(
                    success=False,
                    result=f"sidecar unavailable: {retry_exc}",
                )

    # BH3-036: Maximum response size enforced at the StreamReader level.
    # readline() reads the entire line into memory before returning, so a
    # post-read size check is too late — a compromised sidecar could send
    # a multi-GB line and OOM the process. Setting the StreamReader limit
    # causes readline() to raise ValueError if a single line exceeds this.
    _MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MiB

    async def _send_request(self, request: dict) -> SidecarResponse:
        """Connect to the Unix socket, send a JSON request, read the response."""
        reader, writer = await asyncio.open_unix_connection(
            self._socket_path,
            limit=self._MAX_RESPONSE_BYTES,
        )

        # Q13.fix.f — verify the peer's UID matches this process's UID on every
        # new connect. See sentinel/core/socket_auth.py and the design doc at
        # docs/hardening/2026-04-20-hardening-Q13-protocol-auth-findings.md
        # §Design Cluster 2 Decision 2 for threat model and same-UID caveat.
        # PermissionError from mismatch propagates up; execute() catches it
        # BEFORE the (ConnectionError, BrokenPipeError, OSError) branch.
        # OSError from getsockopt (non-Linux kernel) is caught one-shot here
        # and demoted to ACL-only (the 0700 runtime_dir still pins the path).
        global _peercred_unavailable_logged
        try:
            await _assert_peer_uid(
                writer,
                self._socket_path,
                module_event_prefix="sidecar.peer_uid",
            )
        except OSError as exc:
            if isinstance(exc, PermissionError):
                # Let PermissionError propagate — fail-closed semantics in execute().
                raise
            if not _peercred_unavailable_logged:
                _peercred_unavailable_logged = True
                logger.warning(
                    "SO_PEERCRED unavailable on sidecar socket; ACL-only fallback",
                    extra={
                        "event": "sidecar.peercred_unavailable",
                        "socket": self._socket_path,
                        "error": str(exc),
                    },
                    exc_info=True,
                )

        try:
            # Send newline-delimited JSON
            line = json.dumps(request) + "\n"
            writer.write(line.encode())
            await writer.drain()

            # Read response line — StreamReader.limit enforces the 4 MiB cap
            # at the read level, preventing OOM from oversized responses.
            try:
                response_line = await reader.readline()
            except ValueError:
                raise SidecarResponseTooLargeError(
                    f"sidecar response exceeded receiver cap ({self._MAX_RESPONSE_BYTES} bytes)"
                ) from None
            if not response_line:
                raise ConnectionError("sidecar closed connection")
            if not response_line.endswith(b"\n"):
                # Sidecar crashed mid-write: partial bytes without a newline
                # terminator indicate a truncated response, not a malformed one.
                # Route to ConnectionError so execute() triggers restart-retry
                # instead of the no-restart SidecarProtocolError path.
                raise ConnectionError("sidecar closed connection with partial response")
            if not response_line.strip():
                # Bare newline (e.g. b"\n" or b"\r\n"): sidecar flushed a
                # line terminator but no payload — treat as a crash artifact,
                # not a protocol violation, so restart-retry fires.
                raise ConnectionError("sidecar sent empty response line")

            try:
                data = json.loads(response_line)
            except (json.JSONDecodeError, ValueError) as exc:
                # ValueError covers UnicodeDecodeError (subclass) for invalid
                # UTF-8 bytes that json.loads() rejects before JSON parsing.
                raise SidecarProtocolError(
                    "sidecar response is not valid JSON"
                ) from exc
            if not isinstance(data, dict):
                raise SidecarProtocolError(
                    f"sidecar response is not a JSON object (got {type(data).__name__})"
                )
            return SidecarResponse(
                success=data.get("success", False),
                result=data.get("result", ""),
                data=data.get("data"),
                leaked=data.get("leaked", False),
                fuel_consumed=data.get("fuel_consumed"),
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # catch-all: writer close best-effort
                logger.debug(
                    "Writer close failed",
                    extra={"event": "sidecar.writer_close_failed"},
                )

    async def start_sidecar(self) -> None:
        """Start the sidecar binary as a subprocess.

        Waits up to 5 seconds for the sidecar to signal readiness via
        stderr ("READY"). This guarantees the accept loop is live before
        any requests are sent, eliminating the startup race condition.
        """
        if not self._binary_path:
            raise RuntimeError("no sidecar binary path configured")

        # Stop existing process if any
        await self.stop_sidecar()

        env = os.environ.copy()
        env["SENTINEL_SIDECAR_SOCKET"] = self._socket_path
        if self._tool_dir:
            env["SENTINEL_SIDECAR_TOOL_DIR"] = self._tool_dir

        logger.info(
            "Starting sidecar",
            extra={
                "event": "sidecar.start",
                "binary": self._binary_path,
                "socket": self._socket_path,
            },
        )

        # BH3-037: Pipe stderr to Python logger instead of DEVNULL so
        # Rust sidecar logging (tracing/env_logger) is visible for debugging.
        self._process = subprocess.Popen(
            [self._binary_path],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # Q14-F2: any post-Popen failure (READY timeout, exit-during-startup,
        # cancellation) must terminate the spawned subprocess before
        # propagating the error — otherwise the child leaks as an orphan on
        # every restart-failure cycle. BaseException covers asyncio
        # CancelledError too (cleanup-and-re-raise pattern).
        try:
            # Wait for the sidecar's READY signal on stderr. The Rust binary
            # prints "READY" after all initialisation is complete and the
            # accept loop is live, eliminating the race between socket-file
            # creation and actual readiness to process requests.
            loop = asyncio.get_event_loop()
            ready = False
            # Q11-U1 documented exception: sidecar READY-signal poll is a
            # lifecycle deadline. The "50 * 200ms = 10s" form is intentionally
            # explicit so operators reading the code see the wall-clock bound
            # at-a-glance; replacing with a single setting (`sidecar_ready_timeout`)
            # would obscure the boot-diagnostic readability that "count + per-
            # iteration delay" provides at boot-trace time. Not a hot-path
            # external-service deadline.
            for _ in range(50):  # 50 * 200ms = 10s max
                if self._process.poll() is not None:
                    raise RuntimeError(
                        f"sidecar exited during startup (code={self._process.returncode})"
                    )
                try:
                    line = await asyncio.wait_for(
                        loop.run_in_executor(None, self._process.stderr.readline),
                        timeout=0.2,
                    )
                except TimeoutError:
                    continue
                if line:
                    text = line.decode("utf-8", errors="replace").rstrip()
                    if text:
                        logger.debug(
                            "sidecar: %s",
                            text,
                            extra={"event": "sidecar.stderr"},
                        )
                    if text == "READY":
                        ready = True
                        break
            if not ready:
                raise RuntimeError("sidecar did not signal readiness within 10s")
        except BaseException:
            logger.warning(
                "Sidecar startup failed, cleaning up spawned process",
                extra={"event": "sidecar.startup_failed_cleaning_up"},
                exc_info=True,
            )
            # Q14-F2 round-2 (Codex Q14d-C-1): asyncio.shield prevents the
            # cleanup itself from being interrupted by a second cancellation.
            # stop_sidecar() does SIGTERM + asyncio.to_thread(wait, timeout=5);
            # without shield, a cancellation arriving during that wait skips
            # the kill/reap path and leaks the spawned process — exactly the
            # orphan-cleanup contract the BaseException catch was meant to
            # guarantee. Shield runs the cleanup task to completion in the
            # background even if the outer task is being cancelled. The await
            # may still raise CancelledError (which propagates correctly past
            # the original startup exception via __context__ chaining) but the
            # shielded cleanup task continues independently.
            try:
                await asyncio.shield(self.stop_sidecar())
            except Exception:  # cleanup best-effort (non-cancellation failures)
                logger.debug(
                    "stop_sidecar during startup-failure cleanup raised",
                    extra={"event": "sidecar.startup_cleanup_failed"},
                    exc_info=True,
                )
            raise

        logger.info("Sidecar started", extra={"event": "sidecar.ready"})

        # Infrastructure: no user context needed — stderr drain is a process-
        # level monitoring task that is not scoped to any particular user.
        self._stderr_task = asyncio.create_task(self._drain_stderr(self._process))

    @staticmethod
    async def _drain_stderr(proc: subprocess.Popen) -> None:
        """Read sidecar stderr in a background task and forward to logger."""
        if proc.stderr is None:
            return
        loop = asyncio.get_event_loop()
        try:
            while True:
                line = await loop.run_in_executor(None, proc.stderr.readline)
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    logger.debug(
                        "sidecar: %s",
                        text,
                        extra={"event": "sidecar.stderr"},
                    )
        except Exception:  # catch-all: stderr drain end
            logger.debug(
                "Stderr drain ended", extra={"event": "sidecar.stderr_drain_ended"}
            )

    async def stop_sidecar(self) -> None:
        """Stop the sidecar subprocess gracefully (SIGTERM, then SIGKILL)."""
        if self._process is None:
            return

        logger.info("Stopping sidecar", extra={"event": "sidecar.stop"})

        try:
            # Q11-U1 documented exception: subprocess lifecycle grace
            # deadlines (SIGTERM=5s graceful + SIGKILL=2s post-kill grace).
            # Two-phase shutdown sequence; not an external-service SLA.
            # Lifecycle literals carved out by the umbrella scope brief.
            self._process.send_signal(signal.SIGTERM)
            try:
                await asyncio.to_thread(self._process.wait, timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "stop_sidecar: subprocess.TimeoutExpired",
                    extra={"event": "sidecar.stop_timeout"},
                    exc_info=True,
                )
                self._process.kill()
                await asyncio.to_thread(self._process.wait, timeout=2)
        except (ProcessLookupError, OSError):
            logger.debug(
                "Process already exited",
                extra={"event": "sidecar.process_already_exited"},
            )
        finally:
            self._process = None
            # Cancel the stderr drain task if running
            if self._stderr_task is not None:
                self._stderr_task.cancel()
                self._stderr_task = None

        # Clean up socket file
        if os.path.exists(self._socket_path):
            try:
                os.unlink(self._socket_path)
            except OSError:
                logger.debug(
                    "Socket cleanup failed",
                    extra={"event": "sidecar.socket_cleanup_failed"},
                )

    @property
    def is_running(self) -> bool:
        """Check if the sidecar process is still running."""
        if self._process is None:
            return False
        return self._process.poll() is None


def _generate_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())
