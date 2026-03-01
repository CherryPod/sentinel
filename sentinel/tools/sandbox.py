"""PodmanSandbox — disposable container execution for shell commands.

Creates a fresh Podman container per command via the Podman REST API
(Unix socket). No network, dropped capabilities, read-only root FS.
Workspace volume is the only writable mount.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import struct
import uuid
from dataclasses import dataclass

import httpx

logger = logging.getLogger("sentinel.audit")


def _demux_stream(raw: bytes) -> str:
    """Strip Docker/Podman multiplexed stream headers from log output.

    The container logs API returns frames with an 8-byte header:
      byte 0: stream type (1=stdout, 2=stderr)
      bytes 1-3: padding (zeros)
      bytes 4-7: frame payload length (big-endian uint32)
    Followed by `length` bytes of payload.

    If the data doesn't look like multiplexed output (no valid header),
    return it as-is (plain text fallback).
    """
    if len(raw) < 8:
        return raw.decode("utf-8", errors="replace")

    # Heuristic: check if first byte is a valid stream type (0, 1, or 2)
    # and bytes 1-3 are zero padding
    if raw[0] not in (0, 1, 2) or raw[1:4] != b"\x00\x00\x00":
        return raw.decode("utf-8", errors="replace")

    # Demultiplex: walk frame headers and extract payloads
    chunks: list[bytes] = []
    pos = 0
    while pos + 8 <= len(raw):
        # stream_type = raw[pos]  # not needed — we already filtered by endpoint
        frame_len = struct.unpack(">I", raw[pos + 4 : pos + 8])[0]
        pos += 8
        end = min(pos + frame_len, len(raw))
        chunks.append(raw[pos:end])
        pos = end

    return b"".join(chunks).decode("utf-8", errors="replace")


@dataclass
class SandboxResult:
    """Result from a sandboxed shell command execution."""
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    oom_killed: bool
    container_id: str


class PodmanSandbox:
    """Disposable Podman container executor for shell commands.

    Each command gets a fresh container with:
    - No network access
    - All capabilities dropped
    - Read-only root filesystem
    - Only /workspace mounted read-write
    - tmpfs on /tmp (noexec)
    """

    _CONTAINER_PREFIX = "sentinel-sandbox-"

    def __init__(
        self,
        socket_path: str,
        image: str,
        default_timeout: int,
        max_timeout: int,
        memory_limit: int,
        cpu_quota: int,
        workspace_volume: str,
        output_limit: int,
    ):
        self._socket_path = socket_path
        self._image = image
        self._default_timeout = default_timeout
        self._max_timeout = max_timeout
        self._memory_limit = memory_limit
        self._cpu_quota = cpu_quota
        self._workspace_volume = workspace_volume
        self._output_limit = output_limit
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create the httpx client with Unix socket transport."""
        if self._client is None:
            transport = httpx.AsyncHTTPTransport(uds=self._socket_path)
            self._client = httpx.AsyncClient(
                transport=transport,
                base_url="http://podman",  # hostname is ignored for UDS
                timeout=httpx.Timeout(self._max_timeout + 10),
            )
        return self._client

    async def _verify_hardening(self, container_id: str) -> None:
        """Inspect container and verify security settings were applied.

        Called after create, before start. Catches Podman silently
        ignoring fields (Fix V / Fix W class regressions).
        Raises ToolError and deletes the container if any check fails.
        """
        from sentinel.tools.executor import ToolError

        client = self._get_client()
        resp = await client.get(f"/v5.0.0/containers/{container_id}/json")
        if resp.status_code != 200:
            raise ToolError(
                f"sandbox hardening check failed: cannot inspect container "
                f"(HTTP {resp.status_code})"
            )

        data = resp.json()
        hc = data.get("HostConfig", {})
        failures = []

        if hc.get("NetworkMode") != "none":
            failures.append(f"NetworkMode={hc.get('NetworkMode')!r}, expected 'none'")

        if not hc.get("ReadonlyRootfs"):
            failures.append("ReadonlyRootfs is not set")

        security_opt = hc.get("SecurityOpt") or []
        if "no-new-privileges" not in security_opt:
            failures.append(f"SecurityOpt={security_opt!r}, missing 'no-new-privileges'")

        if not hc.get("Memory") or hc["Memory"] <= 0:
            failures.append(f"Memory={hc.get('Memory')!r}, expected > 0")

        binds = hc.get("Binds") or []
        if not any("/workspace" in b for b in binds):
            failures.append(f"Binds={binds!r}, missing /workspace mount")

        if failures:
            # Delete the unsafe container before raising
            try:
                await client.delete(
                    f"/v5.0.0/containers/{container_id}",
                    params={"force": "true"},
                )
            except Exception:
                pass
            detail = "; ".join(failures)
            logger.error(
                "Sandbox hardening verification FAILED — refusing to start",
                extra={
                    "event": "sandbox_hardening_failed",
                    "container_id": container_id[:12],
                    "failures": failures,
                },
            )
            raise ToolError(
                f"sandbox container failed hardening check: {detail}"
            )

        logger.info(
            "Sandbox hardening verified",
            extra={
                "event": "sandbox_hardening_ok",
                "container_id": container_id[:12],
            },
        )

    async def health_check(self) -> bool:
        """Check if Podman socket is reachable and sandbox image is available."""
        try:
            client = self._get_client()
            # Check Podman API is responding
            resp = await client.get("/v5.0.0/info")
            if resp.status_code != 200:
                logger.warning(
                    "Podman API health check failed",
                    extra={"event": "sandbox_health_failed", "status": resp.status_code},
                )
                return False

            # Check sandbox image is available
            resp = await client.get(
                "/v5.0.0/images/json",
                params={"filters": f'{{"reference":["{self._image}"]}}'},
            )
            if resp.status_code != 200:
                logger.warning(
                    "Podman image list failed",
                    extra={"event": "sandbox_image_check_failed", "status": resp.status_code},
                )
                return False

            images = resp.json()
            if not images:
                logger.warning(
                    "Sandbox image not found",
                    extra={"event": "sandbox_image_missing", "image": self._image},
                )
                return False

            logger.info(
                "Sandbox health check passed",
                extra={"event": "sandbox_health_ok", "image": self._image},
            )
            return True

        except (httpx.ConnectError, httpx.TransportError, OSError) as exc:
            logger.warning(
                "Sandbox health check failed: %s",
                exc,
                extra={"event": "sandbox_health_error", "error": str(exc)},
            )
            return False

    async def cleanup_stale(self) -> int:
        """Remove any leftover sentinel-sandbox-* containers from previous runs."""
        try:
            client = self._get_client()
            resp = await client.get(
                "/v5.0.0/containers/json",
                params={"all": "true", "filters": f'{{"name":["{self._CONTAINER_PREFIX}"]}}'},
            )
            if resp.status_code != 200:
                logger.warning(
                    "Failed to list stale sandbox containers",
                    extra={"event": "sandbox_cleanup_list_failed", "status": resp.status_code},
                )
                return 0

            containers = resp.json()
            removed = 0
            for c in containers:
                cid = c.get("Id", "")
                resp = await client.delete(f"/v5.0.0/containers/{cid}", params={"force": "true"})
                if resp.status_code == 200:
                    removed += 1
                    logger.info(
                        "Removed stale sandbox container",
                        extra={"event": "sandbox_cleanup_removed", "container_id": cid[:12]},
                    )
                else:
                    logger.warning(
                        "Failed to remove stale container",
                        extra={"event": "sandbox_cleanup_failed", "container_id": cid[:12], "status": resp.status_code},
                    )

            if removed:
                logger.info(
                    "Sandbox stale cleanup complete",
                    extra={"event": "sandbox_cleanup_done", "removed": removed},
                )
            return removed

        except (httpx.ConnectError, httpx.TransportError, OSError) as exc:
            logger.warning(
                "Sandbox cleanup failed: %s",
                exc,
                extra={"event": "sandbox_cleanup_error", "error": str(exc)},
            )
            return 0

    async def run(self, command: str, timeout: int | None = None) -> SandboxResult:
        """Run a command in a disposable Podman container.

        Creates a fresh container, runs the command, captures output,
        and destroys the container. Container is always cleaned up,
        even on errors.
        """
        from sentinel.tools.executor import ToolError

        effective_timeout = min(
            timeout if timeout is not None else self._default_timeout,
            self._max_timeout,
        )
        container_name = f"{self._CONTAINER_PREFIX}{uuid.uuid4().hex[:12]}"
        client = self._get_client()
        container_id = None

        try:
            # 1. Create container
            # Field names MUST use Docker API PascalCase — Podman's compat
            # API silently ignores snake_case fields (e.g. host_config → no
            # volume mounts, no security settings).
            # Privilege-drop wrapper: container starts as root (needed to
            # chmod the workspace volume), then drops to nobody (65534)
            # before executing the user command.  setpriv is a pure
            # syscall wrapper (no PAM/shadow) — works on read-only rootfs
            # and with NoNewPrivileges (privilege DROP is always allowed).
            # Result: /etc/shadow is unreadable, user code can't escalate,
            # but /workspace stays writable for build artefacts.
            wrapped_cmd = (
                "chmod 1777 /workspace 2>/dev/null; "
                "exec setpriv --reuid=65534 --regid=65534 --clear-groups "
                f"sh -c {shlex.quote(command)}"
            )
            create_body = {
                "Image": self._image,
                "Cmd": ["sh", "-c", wrapped_cmd],
                "Name": container_name,
                "NetworkDisabled": True,
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "NoNewPrivileges": True,
                    "Memory": self._memory_limit,
                    "CpuQuota": self._cpu_quota,
                    "CapDrop": ["ALL"],
                    # CAP_SETUID/SETGID needed for setpriv privilege drop.
                    # Cleared by kernel when UID changes 0 → 65534 (non-root
                    # processes lose all caps). User command runs with zero caps.
                    "CapAdd": ["CAP_SETUID", "CAP_SETGID"],
                    "SecurityOpt": ["no-new-privileges"],
                    "Binds": [
                        f"{self._workspace_volume}:/workspace:rw",
                    ],
                    "Tmpfs": {"/tmp": "size=100M,noexec"},
                },
                "WorkingDir": "/workspace",
            }

            resp = await client.post("/v5.0.0/containers/create", json=create_body)
            if resp.status_code not in (200, 201):
                raise ToolError(f"sandbox container create failed: {resp.status_code} {resp.text}")

            container_id = resp.json().get("Id", "")
            logger.info(
                "Sandbox container created",
                extra={
                    "event": "sandbox_created",
                    "container_id": container_id[:12],
                    "command": command[:200],
                },
            )

            # 1b. Verify hardening was applied (catches silent API field ignores)
            await self._verify_hardening(container_id)

            # 2. Start container
            resp = await client.post(f"/v5.0.0/containers/{container_id}/start")
            if resp.status_code not in (200, 204):
                raise ToolError(f"sandbox container start failed: {resp.status_code} {resp.text}")

            # 3. Wait for container to finish (with timeout)
            timed_out = False
            try:
                resp = await asyncio.wait_for(
                    client.post(
                        f"/v5.0.0/containers/{container_id}/wait",
                        params={"condition": "not-running"},
                    ),
                    timeout=effective_timeout,
                )
                exit_code = resp.json().get("StatusCode", -1)
            except asyncio.TimeoutError:
                timed_out = True
                exit_code = -1
                # Kill the container
                await client.post(f"/v5.0.0/containers/{container_id}/kill")
                logger.warning(
                    "Sandbox command timed out, container killed",
                    extra={
                        "event": "sandbox_timeout",
                        "container_id": container_id[:12],
                        "timeout": effective_timeout,
                    },
                )

            # 4. Get logs (stdout and stderr separately)
            # The Podman logs API returns Docker-style multiplexed stream
            # frames (8-byte header per frame). Read raw bytes and demux.
            stdout_resp = await client.get(
                f"/v5.0.0/containers/{container_id}/logs",
                params={"stdout": "true", "stderr": "false"},
            )
            stderr_resp = await client.get(
                f"/v5.0.0/containers/{container_id}/logs",
                params={"stdout": "false", "stderr": "true"},
            )

            stdout = _demux_stream(stdout_resp.content)[:self._output_limit] if stdout_resp.status_code == 200 else ""
            stderr = _demux_stream(stderr_resp.content)[:self._output_limit] if stderr_resp.status_code == 200 else ""

            # 5. Check OOM kill
            oom_killed = False
            inspect_resp = await client.get(f"/v5.0.0/containers/{container_id}/json")
            if inspect_resp.status_code == 200:
                state = inspect_resp.json().get("State", {})
                oom_killed = state.get("OOMKilled", False)

            result = SandboxResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=timed_out,
                oom_killed=oom_killed,
                container_id=container_id,
            )

            logger.info(
                "Sandbox command complete",
                extra={
                    "event": "sandbox_complete",
                    "container_id": container_id[:12],
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "oom_killed": oom_killed,
                    "stdout_len": len(stdout),
                    "stderr_len": len(stderr),
                },
            )
            return result

        finally:
            # 6. Always delete the container
            if container_id:
                try:
                    await client.delete(
                        f"/v5.0.0/containers/{container_id}",
                        params={"force": "true"},
                    )
                    logger.info(
                        "Sandbox container removed",
                        extra={"event": "sandbox_removed", "container_id": container_id[:12]},
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to remove sandbox container: %s",
                        exc,
                        extra={
                            "event": "sandbox_remove_failed",
                            "container_id": container_id[:12],
                            "error": str(exc),
                        },
                    )
