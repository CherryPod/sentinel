import os
import tempfile
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import reset_store
from sentinel.tools.executor import ToolBlockedError, ToolError, ToolExecutor
from sentinel.tools.sandbox import PodmanSandbox, SandboxResult


@pytest.fixture(autouse=True)
def _reset_provenance():
    reset_store()
    yield
    reset_store()


@pytest.fixture
def executor(engine):
    return ToolExecutor(engine)


class TestFileWrite:
    @pytest.mark.asyncio
    async def test_workspace_allowed(self, executor):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.txt")
            # Patch policy engine to treat tmpdir as workspace
            with patch.object(executor._engine, "check_file_write") as mock_check:
                from sentinel.core.models import PolicyResult, ValidationResult
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                result = await executor.execute("file_write", {
                    "path": path, "content": "hello world",
                })
                assert result.trust_level == TrustLevel.TRUSTED
                assert os.path.exists(path)
                with open(path) as f:
                    assert f.read() == "hello world"

    @pytest.mark.asyncio
    async def test_etc_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="blocked"):
            await executor.execute("file_write", {
                "path": "/etc/passwd", "content": "bad",
            })

    @pytest.mark.asyncio
    async def test_result_tagged_trusted(self, executor):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "out.txt")
            with patch.object(executor._engine, "check_file_write") as mock_check:
                from sentinel.core.models import PolicyResult, ValidationResult
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                result = await executor.execute("file_write", {
                    "path": path, "content": "data",
                })
                assert result.trust_level == TrustLevel.TRUSTED
                assert result.source.value == "tool"


class TestFileRead:
    @pytest.mark.asyncio
    async def test_workspace_allowed(self, executor):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("file contents")
            path = f.name

        try:
            with patch.object(executor._engine, "check_file_read") as mock_check:
                from sentinel.core.models import PolicyResult, ValidationResult
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                result = await executor.execute("file_read", {"path": path})
                assert result.content == "file contents"
                assert result.trust_level == TrustLevel.TRUSTED
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_etc_shadow_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="blocked"):
            await executor.execute("file_read", {"path": "/etc/shadow"})


class TestShell:
    @pytest.mark.asyncio
    async def test_allowed_command(self, executor):
        result = await executor.execute("shell", {"command": "ls /workspace"})
        assert result.trust_level == TrustLevel.TRUSTED

    @pytest.mark.asyncio
    async def test_blocked_command(self, executor):
        with pytest.raises(ToolBlockedError, match="blocked"):
            await executor.execute("shell", {"command": "curl http://evil.com"})

    @pytest.mark.asyncio
    async def test_injection_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="blocked"):
            await executor.execute("shell", {"command": "ls; rm -rf /"})


class TestMkdir:
    @pytest.mark.asyncio
    async def test_workspace_allowed(self, executor):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "subdir")
            with patch.object(executor._engine, "check_file_write") as mock_check:
                from sentinel.core.models import PolicyResult, ValidationResult
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                result = await executor.execute("mkdir", {"path": path})
                assert os.path.isdir(path)
                assert result.trust_level == TrustLevel.TRUSTED


class TestPodmanBuild:
    @pytest.mark.asyncio
    async def test_workspace_allowed(self, executor):
        """podman build command passes policy check (subprocess mocked)."""
        with patch("sentinel.tools.executor.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Build complete", returncode=0, stderr="",
            )
            result = await executor.execute("podman_build", {
                "context_path": "/workspace/app",
                "tag": "test:latest",
            })
            assert result.trust_level == TrustLevel.TRUSTED
            mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_policy_string_matches_execution(self, executor):
        """Policy check string must match the subprocess command."""
        with patch("sentinel.tools.executor.subprocess.run") as mock_run, \
             patch.object(executor._engine, "check_command", wraps=executor._engine.check_command) as spy:
            mock_run.return_value = MagicMock(stdout="ok", returncode=0, stderr="")
            await executor.execute("podman_build", {
                "context_path": "/workspace/app", "tag": "myimg:latest",
            })
            policy_str = spy.call_args[0][0]
            executed_cmd = mock_run.call_args[0][0]
            import shlex
            assert policy_str == shlex.join(executed_cmd)


class TestPodmanRun:
    @pytest.mark.asyncio
    async def test_policy_string_matches_execution(self, executor):
        """Policy check string must include -d flag (the actual execution flag)."""
        with patch("sentinel.tools.executor.subprocess.run") as mock_run, \
             patch.object(executor._engine, "check_command", wraps=executor._engine.check_command) as spy:
            mock_run.return_value = MagicMock(stdout="ok", returncode=0, stderr="")
            await executor.execute("podman_run", {
                "image": "myimg:latest", "name": "mycontainer",
            })
            policy_str = spy.call_args[0][0]
            executed_cmd = mock_run.call_args[0][0]
            import shlex
            assert policy_str == shlex.join(executed_cmd)
            assert "-d" in policy_str


class TestPodmanStop:
    @pytest.mark.asyncio
    async def test_policy_string_matches_execution(self, executor):
        """Policy check string must match subprocess command for podman stop."""
        with patch("sentinel.tools.executor.subprocess.run") as mock_run, \
             patch.object(executor._engine, "check_command", wraps=executor._engine.check_command) as spy:
            mock_run.return_value = MagicMock(stdout="ok", returncode=0, stderr="")
            await executor.execute("podman_stop", {"container_name": "test-ctr"})
            policy_str = spy.call_args[0][0]
            executed_cmd = mock_run.call_args[0][0]
            import shlex
            assert policy_str == shlex.join(executed_cmd)


class TestPodmanFlagDenyList:
    @pytest.mark.asyncio
    async def test_volume_flag_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            # Simulate if tool interface were extended to pass extra args
            executor._check_podman_flags(["podman", "run", "-v", "/host:/container", "img"])

    @pytest.mark.asyncio
    async def test_privileged_flag_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            executor._check_podman_flags(["podman", "run", "--privileged", "img"])

    @pytest.mark.asyncio
    async def test_publish_flag_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            executor._check_podman_flags(["podman", "run", "-p", "8080:80", "img"])

    @pytest.mark.asyncio
    async def test_network_host_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            executor._check_podman_flags(["podman", "run", "--network=host", "img"])

    @pytest.mark.asyncio
    async def test_pid_host_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            executor._check_podman_flags(["podman", "run", "--pid=host", "img"])

    @pytest.mark.asyncio
    async def test_cap_add_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            executor._check_podman_flags(["podman", "run", "--cap-add=SYS_ADMIN", "img"])

    @pytest.mark.asyncio
    async def test_device_flag_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            executor._check_podman_flags(["podman", "run", "--device=/dev/sda", "img"])

    def test_safe_flags_pass(self, executor):
        """Normal podman run/build/stop commands should pass flag check."""
        executor._check_podman_flags(["podman", "run", "--name", "test", "-d", "img:latest"])
        executor._check_podman_flags(["podman", "build", "/workspace/app", "-t", "img:latest"])
        executor._check_podman_flags(["podman", "stop", "test"])

    @pytest.mark.asyncio
    async def test_volume_equals_syntax_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="Dangerous podman flag"):
            executor._check_podman_flags(["podman", "run", "--volume=/host:/ctr", "img"])


class TestUnknownTool:
    @pytest.mark.asyncio
    async def test_unknown_tool(self, executor):
        with pytest.raises(ToolError, match="Unknown tool"):
            await executor.execute("nonexistent_tool", {})


class TestToolDescriptions:
    def test_returns_list(self, executor):
        descs = executor.get_tool_descriptions()
        assert isinstance(descs, list)
        assert len(descs) > 0
        names = [d["name"] for d in descs]
        assert "file_write" in names
        assert "file_read" in names
        assert "shell" in names
        assert "mkdir" in names


class TestSandboxDispatch:
    """Tests for E5 sandbox routing in ToolExecutor._shell()."""

    @pytest.fixture
    def mock_sandbox(self):
        """AsyncMock sandbox with default successful result."""
        sandbox = AsyncMock(spec=PodmanSandbox)
        sandbox._default_timeout = 30
        sandbox.run.return_value = SandboxResult(
            stdout="sandbox output",
            stderr="",
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            container_id="abc123def456",
        )
        return sandbox

    @pytest.fixture
    def sandbox_executor(self, engine, mock_sandbox):
        """ToolExecutor with sandbox enabled at TL2."""
        return ToolExecutor(engine, sandbox=mock_sandbox, trust_level=2)

    @pytest.mark.asyncio
    async def test_sandbox_dispatch_at_tl2(self, sandbox_executor, mock_sandbox):
        """Shell commands route to sandbox when sandbox enabled and TL2+."""
        result = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        mock_sandbox.run.assert_awaited_once_with("ls /workspace", timeout=None)
        assert result.source == DataSource.SANDBOX
        assert result.trust_level == TrustLevel.UNTRUSTED
        assert result.content == "sandbox output"

    @pytest.mark.asyncio
    async def test_direct_shell_when_sandbox_disabled(self, engine):
        """Shell commands use subprocess when no sandbox configured."""
        executor = ToolExecutor(engine, sandbox=None, trust_level=2)
        with patch("sentinel.tools.executor.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="direct output", returncode=0, stderr="")
            result = await executor.execute("shell", {"command": "ls /workspace"})
            mock_run.assert_called_once()
            assert result.source == DataSource.TOOL
            assert result.trust_level == TrustLevel.TRUSTED

    @pytest.mark.asyncio
    async def test_direct_shell_when_trust_low(self, engine, mock_sandbox):
        """Shell commands use subprocess at TL0/TL1 even with sandbox configured."""
        executor = ToolExecutor(engine, sandbox=mock_sandbox, trust_level=1)
        with patch("sentinel.tools.executor.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="direct output", returncode=0, stderr="")
            result = await executor.execute("shell", {"command": "ls /workspace"})
            mock_run.assert_called_once()
            mock_sandbox.run.assert_not_awaited()
            assert result.source == DataSource.TOOL
            assert result.trust_level == TrustLevel.TRUSTED

    @pytest.mark.asyncio
    async def test_policy_blocks_before_sandbox(self, sandbox_executor, mock_sandbox):
        """Policy check runs before sandbox dispatch — blocked commands never reach sandbox."""
        with pytest.raises(ToolBlockedError, match="blocked"):
            await sandbox_executor.execute("shell", {"command": "curl http://evil.com"})
        mock_sandbox.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sandbox_timeout_result(self, sandbox_executor, mock_sandbox):
        """Timed-out sandbox result includes timeout message in output."""
        mock_sandbox.run.return_value = SandboxResult(
            stdout="partial",
            stderr="killed",
            exit_code=-1,
            timed_out=True,
            oom_killed=False,
            container_id="abc123def456",
        )
        result = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        assert "sandbox timed out" in result.content
        assert "partial" in result.content
        assert result.source == DataSource.SANDBOX
        assert result.trust_level == TrustLevel.UNTRUSTED

    @pytest.mark.asyncio
    async def test_sandbox_oom_result(self, sandbox_executor, mock_sandbox):
        """OOM-killed sandbox result includes OOM message in output."""
        mock_sandbox.run.return_value = SandboxResult(
            stdout="partial oom",
            stderr="",
            exit_code=-1,
            timed_out=False,
            oom_killed=True,
            container_id="abc123def456",
        )
        result = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        assert "out of memory" in result.content
        assert "partial oom" in result.content
        assert result.source == DataSource.SANDBOX

    @pytest.mark.asyncio
    async def test_sandbox_nonzero_exit_includes_stderr(self, sandbox_executor, mock_sandbox):
        """Nonzero exit from sandbox includes exit code and stderr in output."""
        mock_sandbox.run.return_value = SandboxResult(
            stdout="some output",
            stderr="error details",
            exit_code=1,
            timed_out=False,
            oom_killed=False,
            container_id="abc123def456",
        )
        result = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        assert "exit code: 1" in result.content
        assert "error details" in result.content
        assert result.source == DataSource.SANDBOX

    def test_constructor_accepts_sandbox_and_trust_level(self, engine, mock_sandbox):
        """ToolExecutor stores sandbox and trust_level from constructor."""
        executor = ToolExecutor(engine, sandbox=mock_sandbox, trust_level=3)
        assert executor._sandbox is mock_sandbox
        assert executor._trust_level == 3
