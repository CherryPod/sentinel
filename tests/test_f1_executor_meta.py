"""Tests for exec_meta returned from ToolExecutor.execute()."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.tools.executor import ToolExecutor
from sentinel.tools.sandbox import SandboxResult


def _make_executor():
    """Create a ToolExecutor with a permissive mock policy engine."""
    engine = MagicMock()
    engine.check_command.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_read.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_write.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    return ToolExecutor(policy_engine=engine)


class TestLastExecMetaInit:
    def test_no_exec_meta_attribute(self):
        executor = _make_executor()
        assert not hasattr(executor, "_last_exec_meta")


class TestShellExecMeta:
    @pytest.mark.asyncio
    async def test_shell_sets_exec_meta_on_success(self):
        executor = _make_executor()
        _, meta = await executor.execute("shell", {"command": "echo hello"})
        assert meta is not None
        assert meta["exit_code"] == 0
        assert meta["stderr"] == ""

    @pytest.mark.asyncio
    async def test_shell_sets_exec_meta_on_nonzero_exit(self):
        executor = _make_executor()
        _, meta = await executor.execute("shell", {"command": "false"})
        assert meta is not None
        assert meta["exit_code"] != 0

    @pytest.mark.asyncio
    async def test_exec_meta_independent_between_calls(self):
        executor = _make_executor()
        _, meta1 = await executor.execute("shell", {"command": "echo first"})
        assert meta1 is not None
        _, meta2 = await executor.execute("shell", {"command": "echo second"})
        # Each call returns its own meta, not accumulated
        assert meta2["exit_code"] == 0


class TestFileWriteExecMeta:
    @pytest.mark.asyncio
    async def test_file_write_captures_sizes(self, tmp_path):
        executor = _make_executor()
        target = str(tmp_path / "test.txt")
        _, meta = await executor.execute("file_write", {"path": target, "content": "hello world"})
        assert meta is not None
        assert meta["file_size_before"] is None  # new file
        assert meta["file_size_after"] == 11
        assert meta["file_content_before"] is None

    @pytest.mark.asyncio
    async def test_file_write_captures_before_content(self, tmp_path):
        target = str(tmp_path / "existing.txt")
        with open(target, "w") as f:
            f.write("original content")

        executor = _make_executor()
        _, meta = await executor.execute("file_write", {"path": target, "content": "new content"})
        assert meta["file_size_before"] == 16  # len("original content")
        assert meta["file_size_after"] == 11  # len("new content")
        assert meta["file_content_before"] == "original content"


class TestSandboxExecMeta:
    def _make_sandbox_executor(self, sandbox_result):
        """Create executor with mock sandbox at trust level 4 (routes to sandbox)."""
        executor = _make_executor()
        executor._trust_level = 4
        mock_sandbox = AsyncMock()
        mock_sandbox.run.return_value = sandbox_result
        executor._sandbox = mock_sandbox
        return executor

    @pytest.mark.asyncio
    async def test_sandbox_sets_exec_meta_on_success(self):
        executor = self._make_sandbox_executor(SandboxResult(
            stdout="hello", stderr="", exit_code=0,
            timed_out=False, oom_killed=False, container_id="abc123",
        ))
        _, meta = await executor.execute("shell", {"command": "echo hello"})
        assert meta is not None
        assert meta["exit_code"] == 0
        assert meta["stderr"] == ""

    @pytest.mark.asyncio
    async def test_sandbox_sets_exec_meta_on_nonzero_exit(self):
        executor = self._make_sandbox_executor(SandboxResult(
            stdout="", stderr="command not found", exit_code=127,
            timed_out=False, oom_killed=False, container_id="abc123",
        ))
        _, meta = await executor.execute("shell", {"command": "badcmd"})
        assert meta is not None
        assert meta["exit_code"] == 127
        assert meta["stderr"] == "command not found"


class TestFileReadExecMeta:
    @pytest.mark.asyncio
    async def test_file_read_captures_size(self, tmp_path):
        target = str(tmp_path / "read_me.txt")
        with open(target, "w") as f:
            f.write("file contents here")

        executor = _make_executor()
        _, meta = await executor.execute("file_read", {"path": target})
        assert meta is not None
        assert meta["file_size"] == 18
