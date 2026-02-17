import json
import logging
import os
import shlex
import subprocess
import time

from sentinel.core.models import DataSource, PolicyResult, TaggedData, TrustLevel
from sentinel.security.policy_engine import PolicyEngine
from sentinel.security.provenance import create_tagged_data, get_file_writer, get_tagged_data, record_file_write

from sentinel.tools.sidecar import SidecarClient, SidecarResponse

logger = logging.getLogger("sentinel.audit")

# Tools that can be dispatched to the WASM sidecar when enabled
WASM_TOOLS = frozenset({"file_read", "file_write", "shell_exec", "http_fetch"})

# Capability mapping: tool name → required sidecar capabilities
_WASM_TOOL_CAPABILITIES = {
    "file_read": ["read_file"],
    "file_write": ["write_file"],
    "shell_exec": ["shell_exec"],
    "http_fetch": ["http_request"],
}

# Podman flags that must never be passed, even if the tool interface is extended
_DANGEROUS_PODMAN_FLAG_NAMES = frozenset({
    "-v", "--volume", "-p", "--publish", "--privileged",
    "--cap-add", "--security-opt", "--device",
})
_DANGEROUS_PODMAN_FLAG_VALUES = frozenset({
    "--pid=host", "--network=host", "--userns=host", "--ipc=host",
})


class ToolError(Exception):
    """Error during tool execution."""


class ToolBlockedError(ToolError):
    """Tool execution blocked by policy."""


class ToolExecutor:
    """Executes tool actions with policy validation before every operation.

    When a SidecarClient is provided and a tool is in WASM_TOOLS, the tool
    is dispatched to the Rust WASM sidecar for sandboxed execution. Non-WASM
    tools (podman_*, mkdir) always use the Python handlers.
    """

    def __init__(self, policy_engine: PolicyEngine, sidecar: SidecarClient | None = None):
        self._engine = policy_engine
        self._sidecar = sidecar

    def get_tool_descriptions(self) -> list[dict]:
        return [
            {
                "name": "file_write",
                "description": "Write content to a file at the given path",
                "args": {"path": "string", "content": "string"},
            },
            {
                "name": "file_read",
                "description": "Read the contents of a file",
                "args": {"path": "string"},
            },
            {
                "name": "mkdir",
                "description": "Create a directory (and parents)",
                "args": {"path": "string"},
            },
            {
                "name": "shell",
                "description": "Run a shell command and return its output",
                "args": {"command": "string"},
            },
            {
                "name": "podman_build",
                "description": "Build a container image from a context directory",
                "args": {"context_path": "string", "tag": "string"},
            },
            {
                "name": "podman_run",
                "description": "Run a container from an image",
                "args": {"image": "string", "name": "string"},
            },
            {
                "name": "podman_stop",
                "description": "Stop a running container",
                "args": {"container_name": "string"},
            },
        ]

    def _check_podman_flags(self, cmd: list[str]) -> None:
        """Reject dangerous podman flags before policy check."""
        for arg in cmd:
            # Check exact flag names (e.g. -v, --volume)
            flag_name = arg.split("=", 1)[0] if "=" in arg else arg
            if flag_name in _DANGEROUS_PODMAN_FLAG_NAMES:
                logger.warning(
                    "Dangerous podman flag blocked",
                    extra={"event": "podman_flag_blocked", "flag": arg, "cmd": shlex.join(cmd)},
                )
                raise ToolBlockedError(f"Dangerous podman flag blocked: {arg}")
            # Check full flag=value entries (e.g. --network=host)
            if arg in _DANGEROUS_PODMAN_FLAG_VALUES:
                logger.warning(
                    "Dangerous podman flag blocked",
                    extra={"event": "podman_flag_blocked", "flag": arg, "cmd": shlex.join(cmd)},
                )
                raise ToolBlockedError(f"Dangerous podman flag blocked: {arg}")

    async def execute(self, tool_name: str, args: dict) -> TaggedData:
        """Execute a tool by name with policy checks.

        WASM-capable tools are dispatched to the sidecar when available.
        """
        logger.info(
            "Tool execution requested",
            extra={
                "event": "tool_execute",
                "tool": tool_name,
                "args_keys": list(args.keys()),
            },
        )

        # Dispatch to sidecar for WASM-capable tools
        if self._sidecar is not None and tool_name in WASM_TOOLS:
            return await self._execute_via_sidecar(tool_name, args)

        handler = {
            "file_write": self._file_write,
            "file_read": self._file_read,
            "mkdir": self._mkdir,
            "shell": self._shell,
            "podman_build": self._podman_build,
            "podman_run": self._podman_run,
            "podman_stop": self._podman_stop,
        }.get(tool_name)

        if handler is None:
            logger.warning(
                "Unknown tool requested",
                extra={"event": "tool_unknown", "tool": tool_name},
            )
            raise ToolError(f"Unknown tool: {tool_name}")

        t0 = time.monotonic()
        result = await handler(args)
        elapsed = time.monotonic() - t0
        logger.info(
            "Tool execution complete",
            extra={
                "event": "tool_complete",
                "tool": tool_name,
                "data_id": result.id,
                "elapsed_s": round(elapsed, 3),
            },
        )
        return result

    async def _execute_via_sidecar(self, tool_name: str, args: dict) -> TaggedData:
        """Dispatch a tool to the WASM sidecar for sandboxed execution."""
        capabilities = _WASM_TOOL_CAPABILITIES.get(tool_name, [])

        t0 = time.monotonic()
        response = await self._sidecar.execute(
            tool_name=tool_name,
            args=args,
            capabilities=capabilities,
        )
        elapsed = time.monotonic() - t0

        if not response.success:
            logger.warning(
                "Sidecar tool execution failed",
                extra={
                    "event": "sidecar_tool_failed",
                    "tool": tool_name,
                    "error": response.result,
                    "elapsed_s": round(elapsed, 3),
                },
            )
            raise ToolError(f"sidecar: {response.result}")

        if response.leaked:
            logger.warning(
                "Sidecar detected credential leak in output",
                extra={
                    "event": "sidecar_leak_detected",
                    "tool": tool_name,
                },
            )

        # Convert SidecarResponse to TaggedData
        content = response.result
        if response.data is not None:
            content = json.dumps(response.data)

        tagged = create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"sidecar:{tool_name}",
        )

        logger.info(
            "Sidecar tool execution complete",
            extra={
                "event": "sidecar_tool_complete",
                "tool": tool_name,
                "data_id": tagged.id,
                "elapsed_s": round(elapsed, 3),
                "fuel_consumed": response.fuel_consumed,
                "leaked": response.leaked,
            },
        )
        return tagged

    async def _file_write(self, args: dict) -> TaggedData:
        path = args.get("path", "")
        content = args.get("content", "")

        result = self._engine.check_file_write(path)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "file_write blocked by policy",
                extra={"event": "file_write_blocked", "path": path, "reason": result.reason},
            )
            raise ToolBlockedError(f"file_write blocked: {result.reason}")

        logger.debug(
            "file_write policy passed",
            extra={"event": "file_write_allowed", "path": path},
        )

        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
        except OSError as exc:
            logger.error(
                "file_write OS error",
                extra={"event": "file_write_error", "path": path, "error": str(exc)},
            )
            raise ToolError(f"file_write failed: {exc}") from exc

        logger.info(
            "File written",
            extra={"event": "file_written", "path": path, "size": len(content)},
        )
        tagged = create_tagged_data(
            content=f"File written: {path}",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"file_write:{path}",
        )
        # Record file provenance so file_read can inherit trust from the writer
        record_file_write(path, tagged.id)
        return tagged

    async def _file_read(self, args: dict) -> TaggedData:
        path = args.get("path", "")

        result = self._engine.check_file_read(path)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "file_read blocked by policy",
                extra={"event": "file_read_blocked", "path": path, "reason": result.reason},
            )
            raise ToolBlockedError(f"file_read blocked: {result.reason}")

        logger.debug(
            "file_read policy passed",
            extra={"event": "file_read_allowed", "path": path},
        )

        try:
            with open(path) as f:
                content = f.read()
        except OSError as exc:
            logger.error(
                "file_read OS error",
                extra={"event": "file_read_error", "path": path, "error": str(exc)},
            )
            raise ToolError(f"file_read failed: {exc}") from exc

        # Determine trust level: if this file was written by the pipeline,
        # inherit trust from the writer's provenance chain to prevent trust laundering.
        # Files not tracked (e.g. pre-existing workspace files) default to TRUSTED.
        trust_level = TrustLevel.TRUSTED
        parent_ids = []
        writer_id = get_file_writer(path)
        if writer_id is not None:
            parent_ids = [writer_id]
            writer_data = get_tagged_data(writer_id)
            if writer_data and writer_data.trust_level == TrustLevel.UNTRUSTED:
                trust_level = TrustLevel.UNTRUSTED

        logger.info(
            "File read",
            extra={
                "event": "file_read_success",
                "path": path,
                "size": len(content),
                "trust_level": trust_level.value,
                "inherited_from": writer_id,
            },
        )
        return create_tagged_data(
            content=content,
            source=DataSource.FILE,
            trust_level=trust_level,
            originated_from=f"file_read:{path}",
            parent_ids=parent_ids,
        )

    async def _mkdir(self, args: dict) -> TaggedData:
        path = args.get("path", "")

        result = self._engine.check_file_write(path)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "mkdir blocked by policy",
                extra={"event": "mkdir_blocked", "path": path, "reason": result.reason},
            )
            raise ToolBlockedError(f"mkdir blocked: {result.reason}")

        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            logger.error(
                "mkdir OS error",
                extra={"event": "mkdir_error", "path": path, "error": str(exc)},
            )
            raise ToolError(f"mkdir failed: {exc}") from exc

        logger.info(
            "Directory created",
            extra={"event": "mkdir_success", "path": path},
        )

        return create_tagged_data(
            content=f"Directory created: {path}",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"mkdir:{path}",
        )

    async def _shell(self, args: dict) -> TaggedData:
        command = args.get("command", "")

        result = self._engine.check_command(command)
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "Shell command blocked by policy",
                extra={"event": "shell_blocked", "command": command, "reason": result.reason},
            )
            raise ToolBlockedError(f"shell blocked: {result.reason}")

        logger.info(
            "Shell command policy passed",
            extra={"event": "shell_allowed", "command": command},
        )

        try:
            proc = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )
            output = proc.stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{proc.stderr}"
                logger.warning(
                    "Shell command non-zero exit",
                    extra={"event": "shell_nonzero", "command": command, "exit_code": proc.returncode},
                )
        except subprocess.TimeoutExpired:
            logger.error(
                "Shell command timed out",
                extra={"event": "shell_timeout", "command": command},
            )
            raise ToolError(f"shell command timed out: {command}")
        except OSError as exc:
            logger.error(
                "Shell command OS error",
                extra={"event": "shell_error", "command": command, "error": str(exc)},
            )
            raise ToolError(f"shell failed: {exc}") from exc

        return create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"shell:{command}",
        )

    async def _podman_build(self, args: dict) -> TaggedData:
        context_path = args.get("context_path", "")
        tag = args.get("tag", "")

        cmd = ["podman", "build", context_path, "-t", tag]
        self._check_podman_flags(cmd)
        result = self._engine.check_command(shlex.join(cmd))
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "podman_build blocked by policy",
                extra={"event": "podman_build_blocked", "tag": tag, "reason": result.reason},
            )
            raise ToolBlockedError(f"podman_build blocked: {result.reason}")

        logger.info(
            "podman_build policy passed",
            extra={"event": "podman_build_allowed", "tag": tag, "context_path": context_path},
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False,
            )
            output = proc.stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{proc.stderr}"
                logger.warning(
                    "podman_build non-zero exit",
                    extra={"event": "podman_build_nonzero", "tag": tag, "exit_code": proc.returncode},
                )
        except subprocess.TimeoutExpired:
            logger.error("podman_build timed out", extra={"event": "podman_build_timeout", "tag": tag})
            raise ToolError("podman build timed out")
        except OSError as exc:
            logger.error("podman_build OS error", extra={"event": "podman_build_error", "tag": tag, "error": str(exc)})
            raise ToolError(f"podman_build failed: {exc}") from exc

        return create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"podman_build:{tag}",
        )

    async def _podman_run(self, args: dict) -> TaggedData:
        image = args.get("image", "")
        name = args.get("name", "")

        cmd = ["podman", "run", "--name", name, "-d", image]
        self._check_podman_flags(cmd)
        result = self._engine.check_command(shlex.join(cmd))
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "podman_run blocked by policy",
                extra={"event": "podman_run_blocked", "image": image, "name": name, "reason": result.reason},
            )
            raise ToolBlockedError(f"podman_run blocked: {result.reason}")

        logger.info(
            "podman_run policy passed",
            extra={"event": "podman_run_allowed", "image": image, "name": name},
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
            )
            output = proc.stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{proc.stderr}"
                logger.warning(
                    "podman_run non-zero exit",
                    extra={"event": "podman_run_nonzero", "name": name, "exit_code": proc.returncode},
                )
        except subprocess.TimeoutExpired:
            logger.error("podman_run timed out", extra={"event": "podman_run_timeout", "name": name})
            raise ToolError("podman run timed out")
        except OSError as exc:
            logger.error("podman_run OS error", extra={"event": "podman_run_error", "name": name, "error": str(exc)})
            raise ToolError(f"podman_run failed: {exc}") from exc

        return create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"podman_run:{image}",
        )

    async def _podman_stop(self, args: dict) -> TaggedData:
        container_name = args.get("container_name", "")

        cmd = ["podman", "stop", container_name]
        self._check_podman_flags(cmd)
        result = self._engine.check_command(shlex.join(cmd))
        if result.status != PolicyResult.ALLOWED:
            logger.warning(
                "podman_stop blocked by policy",
                extra={"event": "podman_stop_blocked", "container": container_name, "reason": result.reason},
            )
            raise ToolBlockedError(f"podman_stop blocked: {result.reason}")

        logger.info(
            "podman_stop policy passed",
            extra={"event": "podman_stop_allowed", "container": container_name},
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )
            output = proc.stdout
            if proc.returncode != 0:
                output += f"\n[exit code: {proc.returncode}]\n{proc.stderr}"
                logger.warning(
                    "podman_stop non-zero exit",
                    extra={"event": "podman_stop_nonzero", "container": container_name, "exit_code": proc.returncode},
                )
        except subprocess.TimeoutExpired:
            logger.error("podman_stop timed out", extra={"event": "podman_stop_timeout", "container": container_name})
            raise ToolError("podman stop timed out")
        except OSError as exc:
            logger.error("podman_stop OS error", extra={"event": "podman_stop_error", "container": container_name, "error": str(exc)})
            raise ToolError(f"podman_stop failed: {exc}") from exc

        return create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"podman_stop:{container_name}",
        )
