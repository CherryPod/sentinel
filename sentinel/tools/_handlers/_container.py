"""Container handler mixin — Podman build, run, stop.

Extracted from executor.py during Phase 1 structural refactor.
The mixin expects these attributes on self (provided by ToolExecutor):
  - _engine: PolicyEngine instance
"""

import asyncio
import logging
import shlex

from sentinel.core.config import settings
from sentinel.core.models import DataSource, PolicyResult, TaggedData, TrustLevel
from sentinel.crypto.blind_index import log_hash
from sentinel.planner._command_shape import _cmd_shape
from sentinel.security.provenance import create_tagged_data
from sentinel.tools._handlers._registry import tool_handler
from sentinel.tools._handlers._types import ToolBlockedError, ToolError

logger = logging.getLogger(__name__)

# Q11-U1 (cleanup-C49): Podman lifecycle timeouts moved to Settings
# (sandbox_podman_{build,run,stop}_timeout); see sentinel/core/config.py.
# BH3-096 originally extracted to module-scope; that step is now superseded
# by pydantic-settings backing for operator-tunability.

# Podman flags that must never be passed, even if the tool interface is extended
_DANGEROUS_PODMAN_FLAG_NAMES = frozenset(
    {
        "-v",
        "--volume",
        "-p",
        "--publish",
        "--privileged",
        "--cap-add",
        "--security-opt",
        "--device",
        "--mount",
        "--sysctl",
    }
)
_DANGEROUS_PODMAN_FLAG_VALUES = frozenset(
    {
        "--pid=host",
        "--network=host",
        "--userns=host",
        "--ipc=host",
        "--cgroupns=host",
        "--uts=host",
    }
)


class ContainerHandlerMixin:
    """Container tool handlers (podman_build, podman_run, podman_stop)."""

    # -- Flag validation -------------------------------------------------------

    def _check_podman_flags(self, cmd: list[str]) -> None:
        """Reject dangerous podman flags before policy check."""
        for arg in cmd:
            # Check exact flag names (e.g. -v, --volume)
            flag_name = arg.split("=", 1)[0] if "=" in arg else arg
            if flag_name in _DANGEROUS_PODMAN_FLAG_NAMES:
                # D47 (FL-D38-a1): redact user-controlled `=value` portion of
                # arg via shape/hash/len. flag_name is policy literal (frozenset
                # member) — leak-free.
                joined_cmd = shlex.join(cmd)
                logger.warning(
                    "Dangerous podman flag blocked",
                    extra={
                        "event": "podman.flag_blocked",
                        "flag_shape": f"denied:flag_name:{flag_name}",
                        "flag_hash": log_hash(arg),
                        "flag_len": len(arg),
                        "cmd_shape": _cmd_shape(joined_cmd),
                        "cmd_hash": log_hash(joined_cmd),
                        "cmd_len": len(joined_cmd),
                    },
                )
                # Q14-FL1 / cleanup-C70: fixed-template user-facing reason;
                # derived flag + cmd retained in server-side log extras above.
                raise ToolBlockedError("Dangerous podman flag blocked")
            # Check full flag=value entries (e.g. --network=host)
            if arg in _DANGEROUS_PODMAN_FLAG_VALUES:
                # D47 (FL-D38-a1): full arg is policy literal here (frozenset
                # member) — emit verbatim. cmd may contain workspace paths —
                # redact via D38 _cmd_shape primitive.
                joined_cmd = shlex.join(cmd)
                logger.warning(
                    "Dangerous podman flag blocked",
                    extra={
                        "event": "podman.flag_blocked",
                        "flag_shape": f"denied:flag_value:{arg}",
                        "flag_hash": log_hash(arg),
                        "flag_len": len(arg),
                        "cmd_shape": _cmd_shape(joined_cmd),
                        "cmd_hash": log_hash(joined_cmd),
                        "cmd_len": len(joined_cmd),
                    },
                )
                # Q14-FL1 / cleanup-C70: fixed-template user-facing reason;
                # derived flag + cmd retained in server-side log extras above.
                raise ToolBlockedError("Dangerous podman flag blocked")

    # -- Handlers --------------------------------------------------------------

    @tool_handler(
        "podman_build",
        description="Build a container image from a context directory",
        args={"context_path": "string", "tag": "string"},
        group="container",
        order=50,
    )
    async def _podman_build(self, args: dict) -> tuple[TaggedData, dict | None]:
        context_path = args.get("context_path", "")
        tag = args.get("tag", "")
        logger.debug(
            "podman_build called",
            extra={
                "event": "container.build.entry",
                "tag": tag,
                "context_path": context_path,
            },
        )

        cmd = ["podman", "build", context_path, "-t", tag]
        self._check_podman_flags(cmd)
        result = self._engine.check_command(shlex.join(cmd))
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "podman_build blocked by policy",
                extra={
                    "event": "podman.build_blocked",
                    "tag": tag,
                    "reason": result.reason,
                },
            )
            raise ToolBlockedError(f"podman_build blocked: {result.reason}")

        logger.info(
            "podman_build policy passed",
            extra={
                "event": "podman.build_allowed",
                "tag": tag,
                "context_path": context_path,
            },
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=settings.sandbox_podman_build_timeout,
                )
            except TimeoutError as exc:
                proc.kill()
                await proc.wait()
                logger.warning(
                    "podman_build timed out",
                    extra={"event": "podman.build_timeout", "tag": tag},
                    exc_info=True,
                )
                raise ToolError("podman build timed out") from exc
            stdout = stdout_bytes.decode(errors="replace")
            stderr = stderr_bytes.decode(errors="replace")
            output = stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{stderr}"
                logger.warning(
                    "podman_build non-zero exit",
                    extra={
                        "event": "podman.build_nonzero",
                        "tag": tag,
                        "exit_code": proc.returncode,
                    },
                )
        except OSError as exc:
            logger.warning(
                "podman_build OS error",
                extra={"event": "podman.build_error", "tag": tag, "error": str(exc)},
                exc_info=True,
            )
            raise ToolError("podman_build failed:") from exc

        return await create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"podman_build:{tag}",
        ), None

    @tool_handler(
        "podman_run",
        description="Run a container from an image",
        args={"image": "string", "name": "string"},
        group="container",
        order=50,
    )
    async def _podman_run(self, args: dict) -> tuple[TaggedData, dict | None]:
        image = args.get("image", "")
        name = args.get("name", "")
        logger.debug(
            "podman_run called",
            extra={
                "event": "container.run.entry",
                "image": image,
                "container_name": name,
            },
        )

        cmd = ["podman", "run", "--name", name, "-d", image]
        self._check_podman_flags(cmd)
        result = self._engine.check_command(shlex.join(cmd))
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "podman_run blocked by policy",
                extra={
                    "event": "podman.run_blocked",
                    "image": image,
                    "container_name": name,
                    "reason": result.reason,
                },
            )
            raise ToolBlockedError(f"podman_run blocked: {result.reason}")

        logger.info(
            "podman_run policy passed",
            extra={
                "event": "podman.run_allowed",
                "image": image,
                "container_name": name,
            },
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=settings.sandbox_podman_run_timeout,
                )
            except TimeoutError as exc:
                proc.kill()
                await proc.wait()
                logger.warning(
                    "podman_run timed out",
                    extra={"event": "podman.run_timeout", "container_name": name},
                    exc_info=True,
                )
                raise ToolError("podman run timed out") from exc
            stdout = stdout_bytes.decode(errors="replace")
            stderr = stderr_bytes.decode(errors="replace")
            output = stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{stderr}"
                logger.warning(
                    "podman_run non-zero exit",
                    extra={
                        "event": "podman.run_nonzero",
                        "container_name": name,
                        "exit_code": proc.returncode,
                    },
                )
        except OSError as exc:
            logger.warning(
                "podman_run OS error",
                extra={
                    "event": "podman.run_error",
                    "container_name": name,
                    "error": str(exc),
                },
                exc_info=True,
            )
            raise ToolError("podman_run failed:") from exc

        return await create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"podman_run:{image}",
        ), None

    @tool_handler(
        "podman_stop",
        description="Stop a running container",
        args={"container_name": "string"},
        group="container",
        order=50,
    )
    async def _podman_stop(self, args: dict) -> tuple[TaggedData, dict | None]:
        container_name = args.get("container_name", "")
        logger.debug(
            "podman_stop called",
            extra={"event": "container.stop.entry", "container_name": container_name},
        )

        cmd = ["podman", "stop", container_name]
        self._check_podman_flags(cmd)
        result = self._engine.check_command(shlex.join(cmd))
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "podman_stop blocked by policy",
                extra={
                    "event": "podman.stop_blocked",
                    "container": container_name,
                    "reason": result.reason,
                },
            )
            raise ToolBlockedError(f"podman_stop blocked: {result.reason}")

        logger.info(
            "podman_stop policy passed",
            extra={"event": "podman.stop_allowed", "container": container_name},
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=settings.sandbox_podman_stop_timeout,
                )
            except TimeoutError as exc:
                proc.kill()
                await proc.wait()
                logger.warning(
                    "podman_stop timed out",
                    extra={"event": "podman.stop_timeout", "container": container_name},
                    exc_info=True,
                )
                raise ToolError("podman stop timed out") from exc
            stdout = stdout_bytes.decode(errors="replace")
            stderr = stderr_bytes.decode(errors="replace")
            output = stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{stderr}"
                logger.warning(
                    "podman_stop non-zero exit",
                    extra={
                        "event": "podman.stop_nonzero",
                        "container": container_name,
                        "exit_code": proc.returncode,
                    },
                )
        except OSError as exc:
            logger.warning(
                "podman_stop OS error",
                extra={
                    "event": "podman.stop_error",
                    "container": container_name,
                    "error": str(exc),
                },
                exc_info=True,
            )
            raise ToolError("podman_stop failed:") from exc

        return await create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"podman_stop:{container_name}",
        ), None
