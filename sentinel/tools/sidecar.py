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
from dataclasses import dataclass, field

logger = logging.getLogger("sentinel.audit")


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
        socket_path: str = "/tmp/sentinel-sidecar.sock",
        timeout: int = 30,
        sidecar_binary_path: str = "",
        tool_dir: str = "",
    ):
        self._socket_path = socket_path
        self._timeout = timeout
        self._binary_path = sidecar_binary_path
        self._tool_dir = tool_dir
        self._process: subprocess.Popen | None = None

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
        except (asyncio.TimeoutError, TimeoutError):
            return SidecarResponse(
                success=False,
                result=f"sidecar timeout after {effective_timeout}s",
            )
        except (ConnectionError, BrokenPipeError, OSError) as exc:
            logger.warning(
                "Sidecar connection failed, attempting restart",
                extra={"event": "sidecar_reconnect", "error": str(exc)},
            )
            # Restart and retry once
            await self.start_sidecar()
            try:
                return await asyncio.wait_for(
                    self._send_request(request),
                    timeout=effective_timeout,
                )
            except Exception as retry_exc:
                logger.error(
                    "Sidecar retry failed",
                    extra={"event": "sidecar_retry_failed", "error": str(retry_exc)},
                )
                return SidecarResponse(
                    success=False,
                    result=f"sidecar unavailable: {retry_exc}",
                )

    async def _send_request(self, request: dict) -> SidecarResponse:
        """Connect to the Unix socket, send a JSON request, read the response."""
        reader, writer = await asyncio.open_unix_connection(self._socket_path)

        try:
            # Send newline-delimited JSON
            line = json.dumps(request) + "\n"
            writer.write(line.encode())
            await writer.drain()

            # Read response line
            response_line = await reader.readline()
            if not response_line:
                raise ConnectionError("sidecar closed connection")

            data = json.loads(response_line)
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
            except Exception:
                pass

    async def start_sidecar(self) -> None:
        """Start the sidecar binary as a subprocess.

        Waits up to 5 seconds for the socket to appear.
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
                "event": "sidecar_start",
                "binary": self._binary_path,
                "socket": self._socket_path,
            },
        )

        self._process = subprocess.Popen(
            [self._binary_path],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # Wait for socket to appear
        for _ in range(50):  # 50 * 100ms = 5s
            if os.path.exists(self._socket_path):
                logger.info("Sidecar started", extra={"event": "sidecar_ready"})
                return
            await asyncio.sleep(0.1)

        raise RuntimeError(
            f"sidecar failed to create socket at {self._socket_path} within 5s"
        )

    async def stop_sidecar(self) -> None:
        """Stop the sidecar subprocess gracefully (SIGTERM, then SIGKILL)."""
        if self._process is None:
            return

        logger.info("Stopping sidecar", extra={"event": "sidecar_stop"})

        try:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
        except (ProcessLookupError, OSError):
            pass
        finally:
            self._process = None

        # Clean up socket file
        if os.path.exists(self._socket_path):
            try:
                os.unlink(self._socket_path)
            except OSError:
                pass

    @property
    def is_running(self) -> bool:
        """Check if the sidecar process is still running."""
        if self._process is None:
            return False
        return self._process.poll() is None


def _generate_request_id() -> str:
    """Generate a unique request ID."""
    import uuid
    return str(uuid.uuid4())
