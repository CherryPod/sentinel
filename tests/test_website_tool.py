"""Tests for the website tool (create/remove/list)."""
import os
import pytest
from unittest.mock import MagicMock

from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.tools.executor import ToolExecutor, ToolBlockedError, ToolError


def _make_executor(workspace_path):
    """Create a ToolExecutor with permissive policy engine."""
    engine = MagicMock()
    engine.check_command.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_read.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_write.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine._workspace_path = workspace_path
    return ToolExecutor(policy_engine=engine)


class TestWebsiteList:
    @pytest.mark.asyncio
    async def test_list_empty_no_sites_dir(self, tmp_path):
        """list returns 'no active sites' when sites dir doesn't exist."""
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("website", {"action": "list"})
        assert "no active sites" in result.content.lower()

    @pytest.mark.asyncio
    async def test_list_empty_sites_dir_exists(self, tmp_path):
        """list returns 'no active sites' when sites dir exists but is empty."""
        (tmp_path / "sites").mkdir()
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("website", {"action": "list"})
        assert "no active sites" in result.content.lower()

    @pytest.mark.asyncio
    async def test_list_shows_existing_sites(self, tmp_path):
        """list returns directory names from /workspace/sites/."""
        sites_dir = tmp_path / "sites"
        sites_dir.mkdir()
        (sites_dir / "dashboard").mkdir()
        (sites_dir / "weather").mkdir()
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("website", {"action": "list"})
        assert "dashboard" in result.content
        assert "weather" in result.content

    @pytest.mark.asyncio
    async def test_list_ignores_files(self, tmp_path):
        """list only returns directories, not stray files."""
        sites_dir = tmp_path / "sites"
        sites_dir.mkdir()
        (sites_dir / "real-site").mkdir()
        (sites_dir / "stray-file.txt").write_text("not a site")
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("website", {"action": "list"})
        assert "real-site" in result.content
        assert "stray-file" not in result.content

    @pytest.mark.asyncio
    async def test_unknown_action_raises(self, tmp_path):
        """Unknown action raises ToolError."""
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="unknown action"):
            await executor.execute("website", {"action": "invalid"})


class TestWebsiteCreate:
    @pytest.mark.asyncio
    async def test_create_writes_files(self, tmp_path):
        """create writes all files to /workspace/sites/{site_id}/."""
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("website", {
            "action": "create",
            "site_id": "my-site",
            "files": {
                "index.html": "<html><body>Hello</body></html>",
                "style.css": "body { margin: 0; }",
            },
        })
        site_dir = tmp_path / "sites" / "my-site"
        assert site_dir.is_dir()
        # Code fixer may normalise content (e.g. trailing newline, DOCTYPE)
        assert "<html><body>Hello</body></html>" in (site_dir / "index.html").read_text()
        assert "body { margin: 0; }" in (site_dir / "style.css").read_text()
        assert "my-site" in result.content
        assert "/sites/my-site/" in result.content

    @pytest.mark.asyncio
    async def test_create_returns_url_and_meta(self, tmp_path):
        """create returns URL in content and metadata."""
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("website", {
            "action": "create",
            "site_id": "test-dash",
            "title": "Test Dashboard",
            "files": {"index.html": "<html>test</html>"},
        })
        assert "Test Dashboard" in result.content
        assert "https://localhost:3001/sites/test-dash/" in result.content
        assert meta["site_id"] == "test-dash"
        assert meta["file_count"] == 1
        assert meta["url"] == "https://localhost:3001/sites/test-dash/"

    @pytest.mark.asyncio
    async def test_create_rejects_invalid_site_id(self, tmp_path):
        """create rejects site_id with special characters."""
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="Invalid site_id"):
            await executor.execute("website", {
                "action": "create",
                "site_id": "../etc/passwd",
                "files": {"index.html": "hack"},
            })

    @pytest.mark.asyncio
    async def test_create_rejects_uppercase_site_id(self, tmp_path):
        """create rejects uppercase site_id."""
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="Invalid site_id"):
            await executor.execute("website", {
                "action": "create",
                "site_id": "MyDashboard",
                "files": {"index.html": "<html>test</html>"},
            })

    @pytest.mark.asyncio
    async def test_create_rejects_invalid_filename(self, tmp_path):
        """create rejects filenames with path traversal."""
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="Invalid filename"):
            await executor.execute("website", {
                "action": "create",
                "site_id": "legit-site",
                "files": {"../../../etc/passwd": "hack"},
            })

    @pytest.mark.asyncio
    async def test_create_requires_files(self, tmp_path):
        """create raises error if files map is empty."""
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="files"):
            await executor.execute("website", {
                "action": "create",
                "site_id": "empty-site",
                "files": {},
            })

    @pytest.mark.asyncio
    async def test_create_policy_blocked(self, tmp_path):
        """create respects policy engine blocks."""
        executor = _make_executor(str(tmp_path))
        executor._engine.check_file_write.return_value = ValidationResult(
            status=PolicyResult.BLOCKED, reason="blocked by policy"
        )
        with pytest.raises(ToolBlockedError):
            await executor.execute("website", {
                "action": "create",
                "site_id": "blocked-site",
                "files": {"index.html": "<html>test</html>"},
            })


class TestWebsiteRemove:
    @pytest.mark.asyncio
    async def test_remove_deletes_site(self, tmp_path):
        """remove deletes the site directory."""
        sites_dir = tmp_path / "sites"
        site_dir = sites_dir / "old-site"
        site_dir.mkdir(parents=True)
        (site_dir / "index.html").write_text("<html>old</html>")

        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("website", {
            "action": "remove",
            "site_id": "old-site",
        })
        assert not site_dir.exists()
        assert "old-site" in result.content
        assert meta["site_id"] == "old-site"

    @pytest.mark.asyncio
    async def test_remove_nonexistent_site(self, tmp_path):
        """remove raises error for a site that doesn't exist."""
        (tmp_path / "sites").mkdir()
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="does not exist"):
            await executor.execute("website", {
                "action": "remove",
                "site_id": "ghost-site",
            })

    @pytest.mark.asyncio
    async def test_remove_rejects_invalid_site_id(self, tmp_path):
        """remove validates site_id."""
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="Invalid site_id"):
            await executor.execute("website", {
                "action": "remove",
                "site_id": "../../etc",
            })

    @pytest.mark.asyncio
    async def test_remove_policy_blocked(self, tmp_path):
        """remove respects policy engine blocks."""
        sites_dir = tmp_path / "sites"
        (sites_dir / "blocked-site").mkdir(parents=True)

        executor = _make_executor(str(tmp_path))
        executor._engine.check_file_write.return_value = ValidationResult(
            status=PolicyResult.BLOCKED, reason="blocked"
        )
        with pytest.raises(ToolBlockedError):
            await executor.execute("website", {
                "action": "remove",
                "site_id": "blocked-site",
            })
