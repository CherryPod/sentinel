"""Podman socket API proxy — allowlisted access to the host Podman socket.

Security layer between the sentinel container and the real Podman socket.
Only permits operations needed by the E5 sandbox (disposable containers
for shell commands). Everything else returns 403 Forbidden.

Started from entrypoint.sh before uvicorn. Listens on a Unix socket
(default /tmp/podman-proxy.sock) and forwards allowed requests to the
real Podman socket (default /run/podman/podman-host.sock).

Usage:
    python3 -m sentinel.tools.podman_proxy
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import sys

logger = logging.getLogger("sentinel.podman_proxy")

# ── Configuration ────────────────────────────────────────────────

UPSTREAM_SOCKET = os.environ.get(
    "SENTINEL_PODMAN_PROXY_UPSTREAM", "/run/podman/podman-host.sock"
)
LISTEN_SOCKET = os.environ.get(
    "SENTINEL_PODMAN_PROXY_LISTEN", "/tmp/podman-proxy.sock"
)
SANDBOX_NAME_PREFIX = "sentinel-sandbox-"
SANDBOX_IMAGE = os.environ.get("SENTINEL_SANDBOX_IMAGE", "python:3.12-slim")

# SYS-6/U4: Cap tracked container IDs to prevent unbounded growth.
# Stale IDs are harmless — they only allow DELETE requests through.
MAX_TRACKED_IDS = 1000

# Timeouts for proxy operations (seconds)
PROXY_HEADER_READ_TIMEOUT = 30  # Max time to read request headers
PROXY_FORWARD_TIMEOUT = 300     # Max time for upstream forwarding (matches podman_build)

# ── Allowlist ────────────────────────────────────────────────────

# Version prefix: /vN.N.N/ — matches any Podman API version
_VER = r"/v\d+\.\d+\.\d+"

# Container ID or name placeholder
_CID = r"[a-zA-Z0-9_-]+"

# Routes that are always allowed (no body validation needed)
_STATIC_ROUTES: list[tuple[str, re.Pattern]] = [
    ("GET", re.compile(rf"^{_VER}/info$")),
    ("GET", re.compile(rf"^{_VER}/images/json")),
]

# Routes allowed for tracked container IDs only
_CONTAINER_ID_ROUTES: list[tuple[str, re.Pattern]] = [
    ("POST", re.compile(rf"^{_VER}/containers/({_CID})/start$")),
    ("POST", re.compile(rf"^{_VER}/containers/({_CID})/wait$")),
    ("POST", re.compile(rf"^{_VER}/containers/({_CID})/kill$")),
    ("GET", re.compile(rf"^{_VER}/containers/({_CID})/logs")),
    ("GET", re.compile(rf"^{_VER}/containers/({_CID})/json$")),
    ("DELETE", re.compile(rf"^{_VER}/containers/({_CID})$")),
]

# Container list — inject name filter for sandbox prefix
_CONTAINER_LIST_RE = re.compile(rf"^{_VER}/containers/json")

# Container create — needs body validation
_CONTAINER_CREATE_RE = re.compile(rf"^{_VER}/containers/create")


class PodmanProxy:
    """Async Unix socket proxy with Podman API allowlist."""

    def __init__(
        self,
        upstream: str = UPSTREAM_SOCKET,
        listen: str = LISTEN_SOCKET,
    ):
        self._upstream = upstream
        self._listen = listen
        self._tracked_ids: set[str] = set()
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        # Clean up stale socket
        if os.path.exists(self._listen):
            os.unlink(self._listen)

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self._listen
        )
        # Make socket accessible within container
        os.chmod(self._listen, 0o660)
        logger.info("Podman proxy listening on %s → %s", self._listen, self._upstream)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if os.path.exists(self._listen):
            os.unlink(self._listen)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._proxy_request(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:
            logger.exception("Proxy handler error")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _proxy_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Read HTTP request line + headers + body with timeout to prevent
        # slow-loris style hangs (BH3-100)
        try:
            request_line, method, path, path_no_query, headers_raw, body = (
                await asyncio.wait_for(
                    self._read_request(reader, writer),
                    timeout=PROXY_HEADER_READ_TIMEOUT,
                )
            )
        except asyncio.TimeoutError:
            logger.warning("Client request read timed out")
            self._send_error(writer, 408, "Request timeout")
            return
        if request_line is None:
            return  # Already handled (empty or forbidden)

        # ── Allowlist check ──────────────────────────────────────

        allowed, reason = self._check_allowed(method, path_no_query, body)
        if not allowed:
            logger.warning(
                "Blocked: %s %s — %s", method, path_no_query, reason
            )
            self._send_forbidden(writer, reason)
            return

        # ── Forward to upstream ──────────────────────────────────

        try:
            up_reader, up_writer = await asyncio.open_unix_connection(
                self._upstream
            )
        except (ConnectionError, FileNotFoundError) as exc:
            self._send_error(writer, 502, f"Upstream unavailable: {exc}")
            return

        # Forward request line + headers + body.
        # Inject Connection: close so upstream closes after response —
        # without this, HTTP/1.1 keep-alive means upstream never sends
        # EOF, and our read loop hangs indefinitely.
        up_writer.write(request_line)
        conn_header_seen = False
        for h in headers_raw:
            h_lower = h.decode("latin-1").strip().lower()
            if h_lower.startswith("connection:"):
                up_writer.write(b"Connection: close\r\n")
                conn_header_seen = True
            else:
                up_writer.write(h)
        if not conn_header_seen:
            up_writer.write(b"Connection: close\r\n")
        up_writer.write(b"\r\n")
        if body:
            up_writer.write(body)
        await up_writer.drain()

        # Read and forward response with timeout to prevent indefinite hangs
        # if upstream stops responding (BH3-040).
        is_create = method == "POST" and _CONTAINER_CREATE_RE.match(path_no_query)
        response_data = bytearray() if is_create else None
        try:
            await asyncio.wait_for(
                self._forward_response(up_reader, writer, response_data),
                timeout=PROXY_FORWARD_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning("Upstream forwarding timed out: %s %s", method, path_no_query)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            up_writer.close()

        # Track container IDs from create responses
        if response_data is not None:
            self._track_created_container(response_data)

        # Untrack deleted containers
        if method == "DELETE":
            for _, pattern in _CONTAINER_ID_ROUTES:
                m = pattern.match(path_no_query)
                if m:
                    cid = m.group(1)
                    self._tracked_ids.discard(cid)
                    break

    async def _read_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[bytes | None, str, str, str, list[bytes], bytes]:
        """Read and parse an HTTP request (line + headers + body).

        Returns (request_line, method, path, path_no_query, headers_raw, body).
        If request_line is None, the request was empty or already rejected.
        """
        request_line = await reader.readline()
        if not request_line:
            return None, "", "", "", [], b""
        request_str = request_line.decode("latin-1").strip()
        parts = request_str.split(" ", 2)
        if len(parts) < 2:
            self._send_forbidden(writer, "Malformed request")
            return None, "", "", "", [], b""

        method = parts[0].upper()
        path = parts[1]
        path_no_query = path.split("?", 1)[0]

        headers_raw: list[bytes] = []
        content_length = 0
        while True:
            line = await reader.readline()
            if not line or line == b"\r\n" or line == b"\n":
                break
            headers_raw.append(line)
            header_str = line.decode("latin-1").strip().lower()
            if header_str.startswith("content-length:"):
                try:
                    content_length = int(header_str.split(":", 1)[1].strip())
                except ValueError:
                    self._send_forbidden(writer, "Invalid Content-Length header")
                    return None, "", "", "", [], b""
                if content_length < 0 or content_length > 100_000_000:
                    self._send_forbidden(writer, "Content-Length out of range")
                    return None, "", "", "", [], b""

        body = b""
        if content_length > 0:
            body = await reader.readexactly(content_length)

        return request_line, method, path, path_no_query, headers_raw, body

    @staticmethod
    async def _forward_response(
        up_reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        response_data: bytearray | None,
    ) -> None:
        """Read upstream response and forward to client."""
        while True:
            chunk = await up_reader.read(65536)
            if not chunk:
                break
            if response_data is not None:
                response_data.extend(chunk)
            writer.write(chunk)
            await writer.drain()

    def _check_allowed(
        self, method: str, path: str, body: bytes
    ) -> tuple[bool, str]:
        """Check if a request is allowed. Returns (allowed, reason)."""
        # Static routes (health, image list)
        for allowed_method, pattern in _STATIC_ROUTES:
            if method == allowed_method and pattern.match(path):
                return True, ""

        # Container list — allowed but we note it (filter enforced upstream)
        if method == "GET" and _CONTAINER_LIST_RE.match(path):
            return True, ""

        # Container create — validate body
        if method == "POST" and _CONTAINER_CREATE_RE.match(path):
            return self._validate_create(body)

        # Container ID routes — must be tracked
        for allowed_method, pattern in _CONTAINER_ID_ROUTES:
            if method == allowed_method:
                m = pattern.match(path)
                if m:
                    cid = m.group(1)
                    if cid in self._tracked_ids:
                        return True, ""
                    return False, f"Container {cid[:12]} not in tracked set"

        return False, f"Path not in allowlist: {method} {path}"

    def _validate_create(self, body: bytes) -> tuple[bool, str]:
        """Validate container create request body."""
        if not body:
            return False, "Empty create body"
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return False, "Invalid JSON in create body"

        # Accept both snake_case and PascalCase field names — the Docker
        # compat API requires PascalCase, but we check both for robustness.
        name = data.get("Name", data.get("name", ""))
        if not name.startswith(SANDBOX_NAME_PREFIX):
            return False, f"Container name must start with {SANDBOX_NAME_PREFIX!r}"

        image = data.get("Image", data.get("image", ""))
        if image != SANDBOX_IMAGE:
            return False, f"Image must be {SANDBOX_IMAGE!r}, got {image!r}"

        return True, ""

    def _track_created_container(self, response_data: bytearray) -> None:
        """Extract container ID from create response and add to tracked set."""
        try:
            # Find the JSON body in the HTTP response
            body_start = response_data.find(b"\r\n\r\n")
            if body_start < 0:
                return
            body = response_data[body_start + 4 :]
            data = json.loads(body)
            cid = data.get("Id", "")
            if cid:
                # SYS-6/U4: Cap tracked IDs — clear stale set if at limit
                if len(self._tracked_ids) >= MAX_TRACKED_IDS:
                    logger.warning(
                        "Tracked container IDs at capacity (%d) — clearing stale entries",
                        len(self._tracked_ids),
                    )
                    self._tracked_ids.clear()
                self._tracked_ids.add(cid)
                # Also track short ID (first 12 chars) since either may be used
                self._tracked_ids.add(cid[:12])
                logger.info("Tracking sandbox container: %s", cid[:12])
        except (json.JSONDecodeError, ValueError):
            pass

    @staticmethod
    def _send_forbidden(writer: asyncio.StreamWriter, reason: str) -> None:
        body = json.dumps({"message": f"Forbidden: {reason}"}).encode()
        writer.write(
            f"HTTP/1.1 403 Forbidden\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n".encode()
        )
        writer.write(body)

    @staticmethod
    def _send_error(
        writer: asyncio.StreamWriter, status: int, reason: str
    ) -> None:
        body = json.dumps({"message": reason}).encode()
        writer.write(
            f"HTTP/1.1 {status} Error\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n".encode()
        )
        writer.write(body)


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [podman-proxy] %(message)s",
    )
    proxy = PodmanProxy()
    await proxy.start()
    logger.info("Podman proxy ready")

    # Run until signal
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()

    await proxy.stop()
    logger.info("Podman proxy stopped")


if __name__ == "__main__":
    asyncio.run(main())
