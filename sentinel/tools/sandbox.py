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

    # Finding #1: Secondary validation — check that the declared frame length
    # is plausible (doesn't exceed remaining data). This catches binary output
    # that happens to start with \x01\x00\x00\x00 followed by a huge length.
    first_frame_len = struct.unpack(">I", raw[4:8])[0]
    if first_frame_len > len(raw) - 8:
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
        api_timeout: int = 30,
    ):
        self._socket_path = socket_path
        self._image = image
        self._default_timeout = default_timeout
        self._max_timeout = max_timeout
        self._memory_limit = memory_limit
        self._cpu_quota = cpu_quota
        self._workspace_volume = workspace_volume
        self._output_limit = output_limit
        self._api_timeout = api_timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def default_timeout(self) -> int:
        return self._default_timeout

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create the httpx client with Unix socket transport.

        Finding #2: The client-level timeout is max_timeout + 10s buffer,
        meaning the client will wait up to 310s (300s max + 10s) for execution
        responses. The per-call api_timeout (30s) handles non-execution calls.
        """
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _create_client(self) -> httpx.AsyncClient:
        """Create a fresh httpx client for the Podman socket."""
        transport = httpx.AsyncHTTPTransport(uds=self._socket_path)
        return httpx.AsyncClient(
            transport=transport,
            base_url="http://podman",  # hostname is ignored for UDS
            timeout=httpx.Timeout(self._max_timeout + 10),
        )

    async def _reset_client(self) -> None:
        """Finding #3: Recreate the httpx client after a connection failure.

        If the Podman socket becomes unavailable (e.g. Podman restarts),
        the cached client holds a dead transport. This recreates it.
        """
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    async def close(self) -> None:
        """Close the httpx client and release the underlying connection pool.

        Called during application shutdown to avoid resource leaks (BH3-099).
        """
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _verify_hardening(self, container_id: str) -> None:
        """Inspect container and verify security settings were applied.

        Called after create, before start. Catches Podman silently
        ignoring fields (Fix V / Fix W class regressions).
        Raises ToolError and deletes the container if any check fails.
        """
        from sentinel.tools.executor import ToolError

        client = self._get_client()
        resp = await client.get(
            f"/v5.0.0/containers/{container_id}/json",
            timeout=self._api_timeout,
        )
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

        # Finding #4: Parse bind strings ("host:container[:options]") and validate
        # the container target is exactly /workspace, not just a substring match.
        binds = hc.get("Binds") or []
        has_workspace = any(
            b.split(":")[1] == "/workspace" for b in binds if ":" in b
        )
        if not has_workspace:
            failures.append(f"Binds={binds!r}, missing /workspace mount")

        # BH3-006: Verify capabilities were applied.
        # Podman's Docker-compat API may silently ignore CapDrop/CapAdd in
        # the create payload (PascalCase required, but even then some Podman
        # versions skip capability fields). We inspect the effective caps to
        # catch this. Expected: CapDrop=["ALL"] with CapAdd for setpriv only.
        #
        # GOTCHA (Podman 4.9.3): We send CapDrop=["ALL"] in the create body,
        # but `podman inspect` expands "ALL" into individual cap names.
        # SECOND GOTCHA: the Docker-compat API (/v5.0.0/containers/{id}/json)
        # returns caps WITHOUT the "CAP_" prefix (e.g. "CHOWN"), while the
        # native `podman inspect` CLI returns WITH the prefix ("CAP_CHOWN").
        # We normalise by stripping the "CAP_" prefix before comparison.
        # We accept EITHER the literal "ALL" (future Podman / Docker compat)
        # OR the full set of default container capabilities being present.
        # These 9 caps are the OCI default set granted to unprivileged
        # containers. If Podman adds more defaults in future, this set may
        # need updating — but a superset in the drop list is fine (issubset).
        _DEFAULT_CAPS_BARE = {
            "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID",
            "KILL", "NET_BIND_SERVICE", "SETFCAP", "SETPCAP",
            "SYS_CHROOT",
        }
        cap_drop = hc.get("CapDrop") or []
        # Strip "CAP_" prefix if present, uppercase for comparison
        cap_drop_normalised = {
            c.upper().removeprefix("CAP_") for c in cap_drop
        }
        if "ALL" not in cap_drop_normalised and not _DEFAULT_CAPS_BARE.issubset(cap_drop_normalised):
            failures.append(
                f"CapDrop={cap_drop!r} — expected 'ALL' or all default caps dropped"
            )

        if failures:
            # Delete the unsafe container before raising
            try:
                await client.delete(
                    f"/v5.0.0/containers/{container_id}",
                    params={"force": "true"},
                    timeout=self._api_timeout,
                )
            except Exception as del_exc:
                logger.warning(
                    "Failed to delete unhardened container: %s",
                    del_exc,
                    extra={
                        "event": "hardening_delete_failed",
                        "container_id": container_id[:12],
                        "error": str(del_exc),
                    },
                )
            detail = "; ".join(failures)
            # Finding #6: Log the HostConfig subset for post-incident investigation
            logger.debug(
                "Hardening failure — HostConfig details",
                extra={
                    "event": "sandbox_hardening_failed_detail",
                    "container_id": container_id[:12],
                    "host_config": {
                        k: hc.get(k) for k in (
                            "NetworkMode", "ReadonlyRootfs", "SecurityOpt",
                            "Memory", "Binds", "CapDrop", "CapAdd", "Tmpfs",
                        )
                    },
                },
            )
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
            resp = await client.get("/v5.0.0/info", timeout=self._api_timeout)
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
                timeout=self._api_timeout,
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
                timeout=self._api_timeout,
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
                resp = await client.delete(
                    f"/v5.0.0/containers/{cid}",
                    params={"force": "true"},
                    timeout=self._api_timeout,
                )
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
        # Finding #3: Get client, resetting if stale from a prior connection failure
        try:
            client = self._get_client()
        except Exception:
            await self._reset_client()
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
            # Finding #7: chmod 1777 runs as root on every invocation (by design).
            # The sticky bit prevents users from deleting each other's files.
            # This runs before hardening-verified user command; the root window
            # between container start and setpriv is minimal and mitigated by
            # CapDrop=ALL + ReadonlyRootfs + no-new-privileges.
            wrapped_cmd = (
                "chmod 1777 /workspace 2>/dev/null; "
                "exec setpriv --reuid=65534 --regid=65534 --clear-groups "
                f"sh -c {shlex.quote(command)}"
            )
            create_body = {
                "Image": self._image,
                "Cmd": ["sh", "-c", wrapped_cmd],
                "Name": container_name,
                # BH3-152: NetworkDisabled is belt-and-suspenders with
                # NetworkMode:"none" below. Podman's compat API silently
                # ignores NetworkDisabled, but we keep it for Docker compat
                # and defence-in-depth if the API behaviour changes.
                "NetworkDisabled": True,
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    # BH3-152: NoNewPrivileges is belt-and-suspenders with
                    # SecurityOpt:["no-new-privileges"] below. Podman's compat
                    # API ignores NoNewPrivileges, but SecurityOpt works.
                    # Both are kept for defence-in-depth.
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

            resp = await client.post(
                "/v5.0.0/containers/create",
                json=create_body,
                timeout=self._api_timeout,
            )
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
            # Finding #11: Log the full wrapped command (including chmod +
            # setpriv wrapper) at debug level for audit trail.
            logger.debug(
                "Sandbox wrapped command",
                extra={
                    "event": "sandbox_wrapped_cmd",
                    "container_id": container_id[:12],
                    "wrapped_cmd": wrapped_cmd,
                },
            )

            # 1b. Verify hardening was applied (catches silent API field ignores)
            await self._verify_hardening(container_id)

            # 2. Start container
            resp = await client.post(
                f"/v5.0.0/containers/{container_id}/start",
                timeout=self._api_timeout,
            )
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
                # Finding #8: Kill the container and check response status
                try:
                    kill_resp = await client.post(
                        f"/v5.0.0/containers/{container_id}/kill",
                        timeout=self._api_timeout,
                    )
                    if kill_resp.status_code not in (200, 204):
                        logger.warning(
                            "Kill-on-timeout returned unexpected status",
                            extra={
                                "event": "sandbox_kill_failed",
                                "container_id": container_id[:12],
                                "status_code": kill_resp.status_code,
                            },
                        )
                except Exception as kill_exc:
                    logger.warning(
                        "Failed to kill timed-out container: %s", kill_exc,
                        extra={
                            "event": "sandbox_kill_error",
                            "container_id": container_id[:12],
                            "error": str(kill_exc),
                        },
                    )
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
            # Finding #9: After a timeout kill, Podman's log buffer may not be
            # fully flushed — output could be incomplete. This is a Podman
            # implementation detail, not actionable from our side.
            stdout_resp = await client.get(
                f"/v5.0.0/containers/{container_id}/logs",
                params={"stdout": "true", "stderr": "false"},
                timeout=self._api_timeout,
            )
            stderr_resp = await client.get(
                f"/v5.0.0/containers/{container_id}/logs",
                params={"stdout": "false", "stderr": "true"},
                timeout=self._api_timeout,
            )

            stdout = _demux_stream(stdout_resp.content)[:self._output_limit] if stdout_resp.status_code == 200 else ""
            stderr = _demux_stream(stderr_resp.content)[:self._output_limit] if stderr_resp.status_code == 200 else ""

            # 5. Check OOM kill
            oom_killed = False
            inspect_resp = await client.get(
                f"/v5.0.0/containers/{container_id}/json",
                timeout=self._api_timeout,
            )
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
                        timeout=self._api_timeout,
                    )
                    logger.info(
                        "Sandbox container removed",
                        extra={"event": "sandbox_removed", "container_id": container_id[:12]},
                    )
                except httpx.HTTPStatusError as exc:
                    # Finding #10: 404 means already deleted (e.g. hardening
                    # failure path) — downgrade to debug, not a real failure.
                    level = logging.DEBUG if exc.response.status_code == 404 else logging.WARNING
                    logger.log(
                        level,
                        "Failed to remove sandbox container: %s",
                        exc,
                        extra={
                            "event": "sandbox_remove_failed",
                            "container_id": container_id[:12],
                            "error": str(exc),
                        },
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
