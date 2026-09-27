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
import shlex
import signal
import urllib.parse

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────

UPSTREAM_SOCKET = os.environ.get(
    "SENTINEL_PODMAN_PROXY_UPSTREAM", "/run/podman/podman-host.sock"
)
LISTEN_SOCKET = os.environ.get("SENTINEL_PODMAN_PROXY_LISTEN", "/tmp/podman-proxy.sock")
SANDBOX_NAME_PREFIX = "sentinel-sandbox-"
SANDBOX_IMAGE = os.environ.get("SENTINEL_SANDBOX_IMAGE", "python:3.12-slim")
SANDBOX_WORKSPACE_VOLUME = os.environ.get("SENTINEL_SANDBOX_WORKSPACE_VOLUME", "")

# Required container security settings — Podman API uses PascalCase.
# NetworkMode "none" enforces the air gap; "no-new-privileges" prevents
# privilege escalation inside the sandbox.
REQUIRED_NETWORK_MODE = "none"
REQUIRED_SECURITY_OPT = "no-new-privileges"

# SYS-6/U4: Cap tracked container IDs to prevent unbounded growth.
# Stale IDs are harmless — they only allow DELETE requests through.
MAX_TRACKED_IDS = 1000

# CRIT-01: Positive allowlist for container create body keys.
# Only PascalCase accepted — the Podman Docker-compat API requires it.
_ALLOWED_TOP_LEVEL_KEYS = frozenset({
    "Image", "Cmd", "Name", "NetworkDisabled", "WorkingDir", "HostConfig",
})
_ALLOWED_HOST_CONFIG_KEYS = frozenset({
    "NetworkMode", "ReadonlyRootfs", "NoNewPrivileges", "Memory",
    "CpuQuota", "CapDrop", "CapAdd", "SecurityOpt", "Binds", "Tmpfs",
})
_ALLOWED_CAP_ADD = frozenset({"CAP_SETUID", "CAP_SETGID"})
_CMD_PREFIX = (
    "chmod 1777 /workspace 2>/dev/null; "
    "exec setpriv --reuid=65534 --regid=65534 --clear-groups sh -c "
)
_UNSAFE_TMPFS_OPTS = frozenset({"exec", "suid", "dev"})

# Timeouts for proxy operations (seconds).
# Q11-U1 (cleanup-C49): operator-tunable via env vars. The proxy runs as a
# standalone pre-uvicorn process and cannot import pydantic-settings, so it
# uses os.environ.get(...) following the existing UPSTREAM_SOCKET pattern.
# Cross-coupling: SENTINEL_PODMAN_PROXY_FORWARD_TIMEOUT must be >=
# settings.sandbox_podman_build_timeout (in-app) so the proxy outer-bound
# always outlasts the inner build operation. Defaults match by construction
# at 300 — operators raising one must raise the other.
PROXY_HEADER_READ_TIMEOUT = int(
    os.environ.get("SENTINEL_PODMAN_PROXY_HEADER_READ_TIMEOUT", "30")
)
PROXY_FORWARD_TIMEOUT = int(
    os.environ.get("SENTINEL_PODMAN_PROXY_FORWARD_TIMEOUT", "300")
)
PROXY_UPSTREAM_CONNECT_TIMEOUT = int(
    os.environ.get("SENTINEL_PODMAN_PROXY_UPSTREAM_CONNECT_TIMEOUT", "5")
)
_MAX_CONTENT_LENGTH = 100_000_000  # 100 MB

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
        # ASYNCIO SAFETY: dict[str, None] used as an insertion-ordered set.
        # dict.__setitem__ / dict.__contains__ / dict.pop are atomic under the
        # GIL. Ordered insertion (Python 3.7+) enables FIFO eviction of the
        # oldest entry at MAX_TRACKED_IDS capacity. Check-then-act sequences
        # are safe because the single-threaded event loop prevents interleaving
        # between a check and its following mutation within the same coroutine.
        self._tracked_ids: dict[str, None] = {}
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        # Clean up stale socket
        if os.path.exists(self._listen):
            os.unlink(self._listen)

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self._listen
        )  # nosec B103 — Unix socket, owner+group only (no world access)
        # Make socket accessible within container
        os.chmod(self._listen, 0o660)  # nosec B103 — Unix socket, owner+group only (no world access)
        logger.info("Podman proxy listening on %s → %s", self._listen, self._upstream)
        if not SANDBOX_WORKSPACE_VOLUME:
            logger.warning(
                "SENTINEL_SANDBOX_WORKSPACE_VOLUME not set -- "
                "all container creates will be rejected",
                extra={"event": "podman_proxy.workspace_volume_missing"},
            )

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
            logger.debug(
                "Client disconnected", extra={"event": "podman_proxy.client_disconnect"}
            )
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
            (
                request_line,
                method,
                path,
                path_no_query,
                headers_raw,
                body,
            ) = await asyncio.wait_for(
                self._read_request(reader, writer),
                timeout=PROXY_HEADER_READ_TIMEOUT,
            )
        except TimeoutError:
            logger.warning("Client request read timed out", exc_info=True)
            self._send_error(writer, 408, "Request timeout")
            return
        if request_line is None:
            return  # Already handled (empty or forbidden)

        # ── Allowlist check ──────────────────────────────────────

        allowed, reason = self._check_allowed(method, path_no_query, body)
        if not allowed:
            logger.warning("Blocked: %s %s — %s", method, path_no_query, reason)
            self._send_forbidden(writer, reason)
            return

        # Inject sandbox name filter for container list so untracked
        # (non-sentinel-sandbox-*) containers are never returned.
        if method == "GET" and _CONTAINER_LIST_RE.match(path_no_query):
            req_parts = request_line.decode("latin-1").split(" ", 2)
            http_ver = req_parts[2] if len(req_parts) > 2 else "HTTP/1.1\r\n"
            original_query = path.split("?", 1)[1] if "?" in path else ""
            filtered = self._build_container_list_path(path_no_query, original_query)
            request_line = f"{method} {filtered} {http_ver}".encode("latin-1")
            logger.debug(
                "check_allowed: container list rewritten with sandbox filter",
                extra={"event": "podman_proxy.container_list_filter"},
            )

        # ── Forward to upstream ──────────────────────────────────

        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self._upstream),
                timeout=PROXY_UPSTREAM_CONNECT_TIMEOUT,
            )
        except TimeoutError:
            logger.warning(
                "Upstream connect timed out",
                extra={"event": "podman_proxy.upstream_connect_timeout"},
                exc_info=True,
            )
            self._send_error(writer, 504, "Upstream connect timeout")
            return
        except (ConnectionError, FileNotFoundError) as exc:
            logger.debug(
                "_proxy_request: ConnectionError | FileNotFoundError",
                extra={"event": "podman_proxy._proxy_request_error", "error": str(exc)},
                exc_info=True,
            )
            self._send_error(writer, 502, f"Upstream unavailable: {exc}")
            return

        # Forward request line + headers + body.
        # Inject Connection: close so upstream closes after response —
        # without this, HTTP/1.1 keep-alive means upstream never sends
        # EOF, and our read loop hangs indefinitely.
        logger.debug(
            "_proxy_request: file_io", extra={"event": "podman_proxy._proxy_request.io"}
        )
        up_writer.write(request_line)
        conn_header_seen = False
        for h in headers_raw:
            h_lower = h.decode("latin-1").strip().lower()
            if h_lower.startswith("connection:"):
                logger.debug(
                    "_proxy_request: file_io",
                    extra={"event": "podman_proxy._proxy_request.io"},
                )
                up_writer.write(b"Connection: close\r\n")
                conn_header_seen = True
            else:
                logger.debug(
                    "_proxy_request: clean",
                    extra={"event": "podman_proxy._proxy_request.io.clean"},
                )
                up_writer.write(h)
        if not conn_header_seen:
            logger.debug(
                "_proxy_request: not_conn_header_seen",
                extra={
                    "event": "podman_proxy._proxy_request.match",
                    "reason": "not_conn_header_seen",
                },
            )  # auto:neg
            up_writer.write(b"Connection: close\r\n")
        logger.debug(
            "_proxy_request: file_io", extra={"event": "podman_proxy._proxy_request.io"}
        )
        up_writer.write(b"\r\n")
        if body:
            logger.debug(
                "_proxy_request: body",
                extra={"event": "podman_proxy._proxy_request.match", "reason": "body"},
            )  # auto:neg
            up_writer.write(body)
        await up_writer.drain()

        # Read and forward response with timeout to prevent indefinite hangs
        # if upstream stops responding (BH3-040).
        # Container list GETs are buffered (not streamed) so the response can
        # be filtered to tracked IDs before forwarding to the client.
        is_create = method == "POST" and _CONTAINER_CREATE_RE.match(path_no_query)
        is_list = method == "GET" and _CONTAINER_LIST_RE.match(path_no_query)
        response_data = bytearray() if is_create else None
        # list_buffer is mutually exclusive with the streaming path (response_data).
        list_buffer: bytearray | None = bytearray() if is_list else None
        list_buffered_ok = False
        try:
            if list_buffer is not None:
                await asyncio.wait_for(
                    self._buffer_response(up_reader, list_buffer),
                    timeout=PROXY_FORWARD_TIMEOUT,
                )
                list_buffered_ok = True
            else:
                await asyncio.wait_for(
                    self._forward_response(up_reader, writer, response_data),
                    timeout=PROXY_FORWARD_TIMEOUT,
                )
        except TimeoutError:
            logger.warning(
                "Upstream forwarding timed out: %s %s",
                method,
                path_no_query,
                exc_info=True,
            )
            if list_buffer is not None:
                self._send_error(writer, 504, "Container list upstream timeout")
        except (ConnectionError, asyncio.IncompleteReadError):
            logger.debug(
                "Upstream disconnected during forwarding",
                extra={"event": "podman_proxy.upstream_disconnect"},
            )
            if list_buffer is not None:
                self._send_error(writer, 502, "Container list upstream disconnected")
        finally:
            up_writer.close()

        # Send tracked-ID filtered container list to client.
        # Guard: only forward if buffering completed without error (list_buffered_ok).
        if list_buffer is not None and list_buffered_ok:
            filtered_response = self._filter_container_list_response(list_buffer)
            writer.write(filtered_response)
            await writer.drain()

        # Track container IDs from create responses
        if response_data is not None:
            self._track_created_container(response_data)

        # Untrack deleted containers
        if method == "DELETE":
            logger.debug(
                "_proxy_request: method_eq_DELETE",
                extra={
                    "event": "podman_proxy._proxy_request.match",
                    "reason": "method_eq_DELETE",
                },
            )  # auto:neg
            for _, pattern in _CONTAINER_ID_ROUTES:
                m = pattern.match(path_no_query)
                if m:
                    cid = m.group(1)
                    self._tracked_ids.pop(cid, None)
                    self._tracked_ids.pop(cid[:12], None)
                    break

    async def _read_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[bytes | None, str, str, str, list[bytes], bytes]:
        """Read and parse an HTTP request (line + headers + body).

        Returns (request_line, method, path, path_no_query, headers_raw, body).
        If request_line is None, the request was empty or already rejected.
        """
        logger.debug(
            "_read_request called", extra={"event": "podman_proxy._read_request"}
        )
        request_line = await reader.readline()
        if not request_line:
            return None, "", "", "", [], b""
        request_str = request_line.decode("latin-1").strip()
        parts = request_str.split(" ", 2)
        if len(parts) < 2:
            self._send_forbidden(writer, "Malformed request")
            logger.debug(
                "read_request: malformed request line",
                extra={
                    "event": "podman_proxy.read_request.malformed",
                    "reason": "malformed_request",
                },
            )
            return None, "", "", "", [], b""

        method = parts[0].upper()
        path = parts[1]
        path_no_query = path.split("?", 1)[0]

        headers_raw: list[bytes] = []
        content_length = 0
        while True:
            logger.debug(
                "_read_request: file_io",
                extra={"event": "podman_proxy._read_request.io"},
            )
            line = await reader.readline()
            if not line or line == b"\r\n" or line == b"\n":
                break
            headers_raw.append(line)
            header_str = line.decode("latin-1").strip().lower()
            if header_str.startswith("content-length:"):
                try:
                    content_length = int(header_str.split(":", 1)[1].strip())
                except ValueError:
                    logger.warning(
                        "_read_request: ValueError",
                        extra={"event": "podman_proxy.read_request_error"},
                        exc_info=True,
                    )
                    self._send_forbidden(writer, "Invalid Content-Length header")
                    return None, "", "", "", [], b""
                if content_length < 0 or content_length > _MAX_CONTENT_LENGTH:
                    self._send_forbidden(writer, "Content-Length out of range")
                    logger.debug(
                        "read_request: content-length out of range",
                        extra={
                            "event": "podman_proxy.read_request.content_length_invalid",
                            "reason": "content_length_out_of_range",
                        },
                    )
                    return None, "", "", "", [], b""

        body = b""
        if content_length > 0:
            body = await reader.readexactly(content_length)

        logger.debug(
            "read_request: header-only request (no body)",
            extra={
                "event": "podman_proxy.read_request.header_only",
                "reason": "no_body",
            },
        )
        return request_line, method, path, path_no_query, headers_raw, body

    @staticmethod
    async def _forward_response(
        up_reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        response_data: bytearray | None,
    ) -> None:
        """Read upstream response and forward to client."""
        while True:
            logger.debug(
                "_forward_response: file_io",
                extra={"event": "podman_proxy._forward_response.io"},
            )
            chunk = await up_reader.read(65536)
            if not chunk:
                break
            if response_data is not None:
                response_data.extend(chunk)
            logger.debug(
                "_forward_response: file_io",
                extra={"event": "podman_proxy._forward_response.io"},
            )
            writer.write(chunk)
            await writer.drain()

    @staticmethod
    async def _buffer_response(
        up_reader: asyncio.StreamReader,
        response_data: bytearray,
    ) -> None:
        """Read upstream response into buffer without forwarding to client."""
        logger.debug(
            "_buffer_response called", extra={"event": "podman_proxy._buffer_response"}
        )
        while True:
            chunk = await up_reader.read(65536)
            if not chunk:
                break
            response_data.extend(chunk)

    @staticmethod
    def _build_container_list_path(path_no_query: str, original_query: str = "") -> str:
        """Return a container-list path with a sandbox name filter injected.

        Client-supplied `filters` are always overridden (prevents broadening).
        `all` is preserved so callers like cleanup_stale see stopped containers.
        """
        existing = urllib.parse.parse_qs(original_query)
        params: dict[str, str] = {}
        if "all" in existing:
            params["all"] = existing["all"][0]
        # Prefix-anchor the name filter; Podman treats it as a regex.
        params["filters"] = json.dumps({"name": [f"^{SANDBOX_NAME_PREFIX}"]})
        return f"{path_no_query}?{urllib.parse.urlencode(params)}"

    def _filter_container_list_response(self, raw_response: bytearray) -> bytes:
        """Return a container-list HTTP response filtered to tracked IDs only.

        Fails open: on any parse error the unmodified response is returned so
        the upstream name-prefix filter still applies as a defence layer.
        """
        sep = raw_response.find(b"\r\n\r\n")
        if sep < 0:
            return bytes(raw_response)
        raw_headers = raw_response[:sep]
        body: bytes = bytes(raw_response[sep + 4:])

        # Decode chunked transfer encoding before JSON parsing.
        # Podman may use chunked for list responses; parsing chunk-framed bytes
        # as JSON would always fail and the filter would silently fall back to
        # the name-prefix-only layer.
        is_chunked = any(
            line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower()
            for line in raw_headers.split(b"\r\n")
        )
        if is_chunked:
            try:
                body = self._decode_chunked(body)
            except Exception:
                logger.warning(
                    "Container list chunk decode failed — "
                    "ID-filter bypassed; only name-prefix filter active; "
                    "foreign sentinel-sandbox-* containers may be visible",
                    extra={"event": "podman_proxy.container_list_filter_parse_failed"},
                )
                return bytes(raw_response)

        try:
            containers = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "Container list response not JSON — "
                "ID-filter bypassed; only name-prefix filter active; "
                "foreign sentinel-sandbox-* containers may be visible",
                extra={"event": "podman_proxy.container_list_filter_parse_failed"},
            )
            return bytes(raw_response)
        if not isinstance(containers, list):
            return bytes(raw_response)
        filtered = [
            c for c in containers
            if isinstance(c, dict) and c.get("Id", "") in self._tracked_ids
        ]
        logger.debug(
            "Container list filtered: %d → %d entries",
            len(containers),
            len(filtered),
            extra={"event": "podman_proxy.container_list_filtered"},
        )
        new_body = json.dumps(filtered).encode()
        # Rebuild headers: drop Content-Length and Transfer-Encoding, inject
        # the new Content-Length so the client gets a well-formed response.
        header_lines = raw_headers.split(b"\r\n")
        rebuilt: list[bytes] = []
        for line in header_lines:
            lower = line.lower()
            if lower.startswith(b"content-length:") or lower.startswith(b"transfer-encoding:"):
                continue
            rebuilt.append(line)
        rebuilt.append(f"Content-Length: {len(new_body)}".encode())
        return b"\r\n".join(rebuilt) + b"\r\n\r\n" + new_body

    @staticmethod
    def _decode_chunked(data: bytes) -> bytes:
        """Decode HTTP chunked transfer-encoding into a plain byte string."""
        out = bytearray()
        pos = 0
        while pos < len(data):
            end = data.index(b"\r\n", pos)
            # Strip chunk extensions (e.g. "a; ext=foo") — only the size matters.
            size = int(data[pos:end].split(b";", 1)[0].strip(), 16)
            if size == 0:
                break
            pos = end + 2
            out.extend(data[pos:pos + size])
            pos += size + 2  # skip trailing CRLF after chunk data
        return bytes(out)

    def _check_allowed(self, method: str, path: str, body: bytes) -> tuple[bool, str]:
        """Check if a request is allowed. Returns (allowed, reason)."""
        # Static routes (health, image list)
        logger.debug(
            "_check_allowed called",
            extra={
                "event": "podman_proxy._check_allowed",
                "method": method,
                "path": path,
                "body_len": len(body) if body else 0,
            },
        )
        for allowed_method, pattern in _STATIC_ROUTES:
            if method == allowed_method and pattern.match(path):
                return True, ""

        # Container list — allowed; sandbox name filter injected in _proxy_request
        if method == "GET" and _CONTAINER_LIST_RE.match(path):
            logger.debug(
                "check_allowed: container list GET allowed",
                extra={
                    "event": "podman_proxy.check_allowed.container_list",
                    "reason": "container_list_allowed",
                },
            )
            return True, ""
        logger.debug(
            "_check_allowed: method_eq_GET_passed",
            extra={
                "event": "podman_proxy.check_allowed.container_list.passed",
                "reason": "method_eq_GET_passed",
            },
        )  # auto:neg

        # Container create — validate body
        if method == "POST" and _CONTAINER_CREATE_RE.match(path):
            logger.debug(
                "check_allowed: container create POST allowed",
                extra={
                    "event": "podman_proxy.check_allowed.container_create",
                    "reason": "container_create_allowed",
                },
            )
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

        logger.debug(
            "_check_allowed: early return",
            extra={"event": "podman_proxy._check_allowed.early_return"},
        )
        return False, f"Path not in allowlist: {method} {path}"

    def _validate_create(self, body: bytes) -> tuple[bool, str]:
        """Validate container create body against positive allowlist."""
        if not body:
            return False, "Empty create body"
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return False, "Invalid JSON in create body"
        if not isinstance(data, dict):
            return False, "Create body must be a JSON object"

        # -- Top-level key allowlist --
        unknown_top = set(data.keys()) - _ALLOWED_TOP_LEVEL_KEYS
        if unknown_top:
            logger.warning(
                "Sandbox create rejected: unknown top-level keys %s",
                sorted(unknown_top),
                extra={"event": "podman_proxy.unknown_top_keys"},
            )
            return False, f"Unknown top-level keys: {sorted(unknown_top)}"

        # -- Name --
        name = data.get("Name", "")
        if not isinstance(name, str) or not name.startswith(SANDBOX_NAME_PREFIX):
            return False, f"Container name must start with {SANDBOX_NAME_PREFIX!r}"

        # -- Image --
        image = data.get("Image", "")
        if image != SANDBOX_IMAGE:
            return False, f"Image must be {SANDBOX_IMAGE!r}, got {image!r}"

        # -- NetworkDisabled --
        if data.get("NetworkDisabled") is not True:
            return False, "NetworkDisabled must be true"

        # -- WorkingDir --
        if data.get("WorkingDir") != "/workspace":
            return (
                False,
                f"WorkingDir must be '/workspace', got {data.get('WorkingDir')!r}",
            )

        # -- Cmd (structural prefix + shlex-quoted suffix) --
        cmd = data.get("Cmd")
        if not isinstance(cmd, list) or len(cmd) != 3:
            return False, "Cmd must be a 3-element list"
        if cmd[0] != "sh" or cmd[1] != "-c":
            return False, "Cmd must start with ['sh', '-c', ...]"
        if not isinstance(cmd[2], str) or not cmd[2].startswith(_CMD_PREFIX):
            return False, "Cmd wrapper must use the setpriv privilege-drop prefix"
        cmd_suffix = cmd[2][len(_CMD_PREFIX):]
        try:
            tokens = shlex.split(cmd_suffix)
        except ValueError:
            return False, "Cmd suffix has malformed shell quoting"
        if len(tokens) != 1:
            return False, "Cmd suffix must be exactly one shell-quoted token"
        if cmd_suffix != shlex.quote(tokens[0]):
            return False, "Cmd suffix is not canonical shlex-quoted form"

        # -- HostConfig --
        host_config = data.get("HostConfig")
        if not isinstance(host_config, dict):
            return False, "HostConfig must be present and a dict"

        unknown_hc = set(host_config.keys()) - _ALLOWED_HOST_CONFIG_KEYS
        if unknown_hc:
            logger.warning(
                "Sandbox create rejected: unknown HostConfig keys %s",
                sorted(unknown_hc),
                extra={"event": "podman_proxy.unknown_hc_keys"},
            )
            return False, f"Unknown HostConfig keys: {sorted(unknown_hc)}"

        # NetworkMode
        if host_config.get("NetworkMode") != REQUIRED_NETWORK_MODE:
            return (
                False,
                f"NetworkMode must be {REQUIRED_NETWORK_MODE!r}, "
                f"got {host_config.get('NetworkMode')!r}",
            )

        # ReadonlyRootfs
        if host_config.get("ReadonlyRootfs") is not True:
            return False, "ReadonlyRootfs must be true"

        # NoNewPrivileges
        if host_config.get("NoNewPrivileges") is not True:
            return False, "NoNewPrivileges must be true"

        # Memory (type() excludes bool, which is a subclass of int)
        memory = host_config.get("Memory")
        if type(memory) is not int or memory <= 0:
            return False, f"Memory must be a positive integer, got {memory!r}"

        # CpuQuota
        cpu_quota = host_config.get("CpuQuota")
        if type(cpu_quota) is not int or cpu_quota <= 0:
            return False, f"CpuQuota must be a positive integer, got {cpu_quota!r}"

        # CapDrop
        cap_drop = host_config.get("CapDrop")
        if not isinstance(cap_drop, list) or cap_drop != ["ALL"]:
            return False, f"CapDrop must be ['ALL'], got {cap_drop!r}"

        # CapAdd
        cap_add = host_config.get("CapAdd")
        if (
            not isinstance(cap_add, list)
            or not all(isinstance(c, str) for c in cap_add)
            or not set(cap_add).issubset(_ALLOWED_CAP_ADD)
        ):
            return (
                False,
                f"CapAdd must be subset of {sorted(_ALLOWED_CAP_ADD)}, "
                f"got {cap_add!r}",
            )

        # SecurityOpt (exact equality — rejects extra opts like seccomp=unconfined)
        security_opts = host_config.get("SecurityOpt")
        if security_opts != [REQUIRED_SECURITY_OPT]:
            return (
                False,
                f"SecurityOpt must be exactly [{REQUIRED_SECURITY_OPT!r}], "
                f"got {security_opts!r}",
            )

        # Binds
        if not SANDBOX_WORKSPACE_VOLUME:
            return False, "SENTINEL_SANDBOX_WORKSPACE_VOLUME not configured"
        expected_bind = f"{SANDBOX_WORKSPACE_VOLUME}:/workspace:rw"
        binds = host_config.get("Binds")
        if not isinstance(binds, list) or binds != [expected_bind]:
            return (
                False,
                f"Binds must be exactly [{expected_bind!r}], got {binds!r}",
            )

        # Tmpfs (comma-split token check to avoid substring false positives)
        tmpfs = host_config.get("Tmpfs")
        if not isinstance(tmpfs, dict) or set(tmpfs.keys()) != {"/tmp"}:
            return False, "Tmpfs must contain exactly one key: /tmp"
        tmpfs_opts = tmpfs.get("/tmp")
        if not isinstance(tmpfs_opts, str):
            return False, "Tmpfs /tmp option value must be a string"
        tmpfs_tokens = [t.strip() for t in tmpfs_opts.split(",") if t.strip()]
        if "noexec" not in tmpfs_tokens:
            return (
                False,
                f"Tmpfs /tmp options must include 'noexec', got {tmpfs_opts!r}",
            )
        unsafe = _UNSAFE_TMPFS_OPTS & set(tmpfs_tokens)
        if unsafe:
            return (
                False,
                f"Tmpfs /tmp options include unsafe flags: {sorted(unsafe)}",
            )

        logger.info(
            "Sandbox create validated (positive allowlist)",
            extra={"event": "podman_proxy.create_validated", "record_name": name},
        )
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
                # SYS-6/U4: Cap tracked IDs — evict one oldest entry before each
                # insert (full ID + short ID) to keep len <= MAX_TRACKED_IDS.
                # FIFO via insertion-ordered dict; each eviction is targeted, not
                # a full wipe, so in-flight tracked containers remain authorised.
                for new_id in (cid, cid[:12]):
                    if len(self._tracked_ids) >= MAX_TRACKED_IDS:
                        oldest = next(iter(self._tracked_ids))
                        del self._tracked_ids[oldest]
                        logger.warning(
                            "Tracked container IDs at capacity — evicted oldest entry",
                            extra={"event": "podman_proxy.tracked_ids_evict"},
                        )
                    self._tracked_ids[new_id] = None
                logger.info("Tracking sandbox container: %s", cid[:12])
        except (json.JSONDecodeError, ValueError):
            logger.debug(
                "Container tracking parse failed",
                extra={"event": "podman_proxy.track_parse_failed"},
            )

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
    def _send_error(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
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
