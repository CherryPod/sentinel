import logging
import os
import shlex
import subprocess

from .models import DataSource, PolicyResult, TaggedData, TrustLevel
from .policy_engine import PolicyEngine
from .provenance import create_tagged_data

logger = logging.getLogger("sentinel.audit")

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
    """Executes tool actions with policy validation before every operation."""

    def __init__(self, policy_engine: PolicyEngine):
        self._engine = policy_engine

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
                raise ToolBlockedError(f"Dangerous podman flag blocked: {arg}")
            # Check full flag=value entries (e.g. --network=host)
            if arg in _DANGEROUS_PODMAN_FLAG_VALUES:
                raise ToolBlockedError(f"Dangerous podman flag blocked: {arg}")

    async def execute(self, tool_name: str, args: dict) -> TaggedData:
        """Execute a tool by name with policy checks."""
        logger.info(
            "Tool execution requested",
            extra={
                "event": "tool_execute",
                "tool": tool_name,
                "args_keys": list(args.keys()),
            },
        )

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
            raise ToolError(f"Unknown tool: {tool_name}")

        return await handler(args)

    async def _file_write(self, args: dict) -> TaggedData:
        path = args.get("path", "")
        content = args.get("content", "")

        result = self._engine.check_file_write(path)
        if result.status != PolicyResult.ALLOWED:
            raise ToolBlockedError(f"file_write blocked: {result.reason}")

        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
        except OSError as exc:
            raise ToolError(f"file_write failed: {exc}") from exc

        logger.info(
            "File written",
            extra={"event": "file_written", "path": path, "size": len(content)},
        )
        return create_tagged_data(
            content=f"File written: {path}",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"file_write:{path}",
        )

    async def _file_read(self, args: dict) -> TaggedData:
        path = args.get("path", "")

        result = self._engine.check_file_read(path)
        if result.status != PolicyResult.ALLOWED:
            raise ToolBlockedError(f"file_read blocked: {result.reason}")

        try:
            with open(path) as f:
                content = f.read()
        except OSError as exc:
            raise ToolError(f"file_read failed: {exc}") from exc

        return create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"file_read:{path}",
        )

    async def _mkdir(self, args: dict) -> TaggedData:
        path = args.get("path", "")

        result = self._engine.check_file_write(path)
        if result.status != PolicyResult.ALLOWED:
            raise ToolBlockedError(f"mkdir blocked: {result.reason}")

        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            raise ToolError(f"mkdir failed: {exc}") from exc

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
            raise ToolBlockedError(f"shell blocked: {result.reason}")

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
        except subprocess.TimeoutExpired:
            raise ToolError(f"shell command timed out: {command}")
        except OSError as exc:
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
            raise ToolBlockedError(f"podman_build blocked: {result.reason}")

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
        except subprocess.TimeoutExpired:
            raise ToolError("podman build timed out")
        except OSError as exc:
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
            raise ToolBlockedError(f"podman_run blocked: {result.reason}")

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
        except subprocess.TimeoutExpired:
            raise ToolError("podman run timed out")
        except OSError as exc:
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
            raise ToolBlockedError(f"podman_stop blocked: {result.reason}")

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
        except subprocess.TimeoutExpired:
            raise ToolError("podman stop timed out")
        except OSError as exc:
            raise ToolError(f"podman_stop failed: {exc}") from exc

        return create_tagged_data(
            content=output,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from=f"podman_stop:{container_name}",
        )
