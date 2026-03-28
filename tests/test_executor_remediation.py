"""Tests for executor audit remediation (2026-03-25).

Source: docs/assessments/audit_executor_20260323.md
"""
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.context import current_user_id
from sentinel.core.models import DataSource, PolicyResult, TrustLevel, ValidationResult
from sentinel.security.provenance import reset_store
from sentinel.tools.executor import ToolBlockedError, ToolError, ToolExecutor
from sentinel.tools.sandbox import PodmanSandbox, SandboxResult


@pytest.fixture(autouse=True)
def _reset_provenance():
    reset_store()
    yield
    reset_store()


@pytest.fixture(autouse=True)
def _set_user_context():
    """Set user context for get_user_workspace() calls."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


def _make_executor(trust_level=0, sandbox=None):
    """Create a ToolExecutor with permissive mock policy engine."""
    engine = MagicMock()
    engine.check_command.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_read.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_write.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine._workspace_path = "/workspace"
    return ToolExecutor(
        policy_engine=engine, sandbox=sandbox, trust_level=trust_level,
    )


class TestShellSandboxGate:
    """Finding #3: Shell must always use sandbox when available, regardless of TL."""

    @pytest.mark.asyncio
    async def test_sandbox_used_at_tl0(self):
        """Sandbox is used even at TL0 when available."""
        sandbox = AsyncMock(spec=PodmanSandbox)
        sandbox.run.return_value = SandboxResult(
            stdout="ok", stderr="", exit_code=0,
            timed_out=False, oom_killed=False, container_id="abc123def456",
        )
        executor = _make_executor(trust_level=0, sandbox=sandbox)
        tagged, meta = await executor.execute("shell", {"command": "echo hello"})
        sandbox.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_sandbox_used_at_tl1(self):
        """Sandbox is used even at TL1 when available."""
        sandbox = AsyncMock(spec=PodmanSandbox)
        sandbox.run.return_value = SandboxResult(
            stdout="ok", stderr="", exit_code=0,
            timed_out=False, oom_killed=False, container_id="abc123def456",
        )
        executor = _make_executor(trust_level=1, sandbox=sandbox)
        tagged, meta = await executor.execute("shell", {"command": "echo hello"})
        sandbox.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_direct_shell_output_untrusted(self):
        """When sandbox is unavailable, direct shell output must be UNTRUSTED."""
        executor = _make_executor(trust_level=0, sandbox=None)
        tagged, meta = await executor.execute("shell", {"command": "echo hello"})
        assert tagged.trust_level == TrustLevel.UNTRUSTED


class TestWebsiteSemgrepScan:
    """Finding #1: Website tool must run Semgrep pre-write scan like _file_write."""

    @pytest.mark.asyncio
    async def test_website_create_runs_semgrep(self):
        """Semgrep scan is called for each file in website create."""
        executor = _make_executor(trust_level=3)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sentinel.tools.executor.get_user_workspace", return_value=Path(tmpdir)), \
                 patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                mock_sg.is_loaded.return_value = True
                mock_result = MagicMock()
                mock_result.found = False
                mock_result.matches = []
                mock_sg.scan_blocks = AsyncMock(return_value=mock_result)
                await executor.execute("website", {
                    "action": "create", "site_id": "test-site",
                    "files": {"index.html": "<html><body>Hello</body></html>"},
                })
                mock_sg.scan_blocks.assert_called_once()

    @pytest.mark.asyncio
    async def test_website_create_blocked_by_semgrep(self):
        """Website create is blocked when Semgrep finds issues."""
        executor = _make_executor(trust_level=3)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sentinel.tools.executor.get_user_workspace", return_value=Path(tmpdir)), \
                 patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                mock_sg.is_loaded.return_value = True
                mock_match = MagicMock()
                mock_match.pattern_name = "dangerous-pattern"
                mock_result = MagicMock()
                mock_result.found = True
                mock_result.matches = [mock_match]
                mock_sg.scan_blocks = AsyncMock(return_value=mock_result)
                with pytest.raises(ToolBlockedError, match="Semgrep"):
                    await executor.execute("website", {
                        "action": "create", "site_id": "test-site",
                        "files": {"app.js": "eval(user_input)"},
                    })
            site_dir = os.path.join(tmpdir, "sites", "test-site")
            assert not os.path.exists(site_dir)

    @pytest.mark.asyncio
    async def test_website_semgrep_fail_closed(self):
        """Semgrep crash blocks the write (fail-closed)."""
        executor = _make_executor(trust_level=3)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sentinel.tools.executor.get_user_workspace", return_value=Path(tmpdir)), \
                 patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                mock_sg.is_loaded.return_value = True
                mock_sg.scan_blocks = AsyncMock(side_effect=RuntimeError("semgrep crashed"))
                with pytest.raises(ToolBlockedError, match="fail-closed"):
                    await executor.execute("website", {
                        "action": "create", "site_id": "test-site",
                        "files": {"index.html": "<html>test</html>"},
                    })

    @pytest.mark.asyncio
    async def test_website_semgrep_skipped_below_tl3(self):
        """Semgrep scan is skipped below TL3."""
        executor = _make_executor(trust_level=2)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sentinel.tools.executor.get_user_workspace", return_value=Path(tmpdir)), \
                 patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                mock_sg.is_loaded.return_value = True
                await executor.execute("website", {
                    "action": "create", "site_id": "test-site",
                    "files": {"index.html": "<html>Hello</html>"},
                })
                mock_sg.scan_blocks.assert_not_called()


class TestPublicPropertyAccess:
    """Findings #29, #30: Executor must use public properties, not private attrs."""

    def test_policy_engine_exposes_workspace_path(self):
        """PolicyEngine has a public workspace_path property."""
        from pathlib import Path
        from sentinel.security.policy_engine import PolicyEngine

        project_root = Path(__file__).resolve().parent.parent
        policy_path = project_root / "policies" / "sentinel-policy.yaml"
        if not policy_path.exists():
            policy_path = Path("/policies/sentinel-policy.yaml")
        engine = PolicyEngine(str(policy_path), workspace_path="/workspace")
        assert engine.workspace_path == "/workspace"

    def test_sandbox_exposes_default_timeout(self):
        """PodmanSandbox has a public default_timeout property."""
        sandbox = PodmanSandbox(
            socket_path="/run/podman/podman.sock",
            image="sentinel-sandbox:latest",
            default_timeout=60,
            max_timeout=300,
            memory_limit=512,
            cpu_quota=100000,
            workspace_volume="/workspace",
            output_limit=1_000_000,
        )
        assert sandbox.default_timeout == 60


class TestQuickWins:
    """Findings #31, #34, #39: Module constants, dead imports, dispatch caching."""

    def test_file_read_max_bytes_is_module_constant(self):
        """FILE_READ_MAX_BYTES is a module-level constant."""
        from sentinel.tools import executor
        assert hasattr(executor, "FILE_READ_MAX_BYTES")
        assert executor.FILE_READ_MAX_BYTES == 1_048_576

    def test_dispatch_dict_built_once(self):
        """Handler dispatch dict is built in __init__."""
        executor = _make_executor()
        assert hasattr(executor, "_handlers")
        assert "file_write" in executor._handlers
        assert "shell" in executor._handlers


class TestSessionReset:
    """Finding #14: Session state can be reset between tasks."""

    def test_reset_clears_file_reads(self):
        executor = _make_executor()
        executor._session_file_reads.add("/workspace/foo.py")
        assert len(executor._session_file_reads) == 1
        executor.reset_session_state()
        assert len(executor._session_file_reads) == 0


class TestCredentialOverlay:
    """Finding #28: Single _CredentialOverlay replaces two inner classes."""

    def test_overlay_returns_cred_values(self):
        from sentinel.tools.executor import _CredentialOverlay
        base = MagicMock()
        creds = {"username": "user@test.com", "password": "secret"}
        field_map = {"imap_username": "username", "imap_password": "password"}
        overlay = _CredentialOverlay(creds, base, field_map)
        assert overlay.imap_username == "user@test.com"
        assert overlay.imap_password == "secret"

    def test_overlay_falls_through_to_base(self):
        from sentinel.tools.executor import _CredentialOverlay
        base = MagicMock()
        base.imap_host = "mail.example.com"
        creds = {"username": "user"}
        field_map = {"imap_username": "username"}
        overlay = _CredentialOverlay(creds, base, field_map)
        assert overlay.imap_host == "mail.example.com"


class TestWorkspacePathRewrite:
    """Multi-user path rewriting: /workspace/X -> /workspace/{user_id}/X."""

    def test_file_write_path_rewritten(self):
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "file_write", {"path": "/workspace/sites/dashboard/index.html", "content": "x"},
        )
        assert result["path"] == "/workspace/1/sites/dashboard/index.html"

    def test_file_read_path_rewritten(self):
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "file_read", {"path": "/workspace/scripts/app.py"},
        )
        assert result["path"] == "/workspace/1/scripts/app.py"

    def test_file_patch_path_rewritten(self):
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "file_patch", {"path": "/workspace/sites/dash/app.js", "operation": "replace"},
        )
        assert result["path"] == "/workspace/1/sites/dash/app.js"

    def test_shell_command_rewritten(self):
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "shell", {"command": "ls -la /workspace/sites/"},
        )
        assert result["command"] == "ls -la /workspace/1/sites/"

    def test_shell_multiple_workspace_refs(self):
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "shell", {"command": "cp /workspace/a.py /workspace/b.py"},
        )
        assert result["command"] == "cp /workspace/1/a.py /workspace/1/b.py"

    def test_already_scoped_path_not_double_rewritten(self):
        """Paths that already contain a user ID segment are left alone."""
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "file_write", {"path": "/workspace/1/sites/dashboard/index.html", "content": "x"},
        )
        assert result["path"] == "/workspace/1/sites/dashboard/index.html"

    def test_already_scoped_shell_not_double_rewritten(self):
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "shell", {"command": "ls /workspace/1/sites/"},
        )
        assert result["command"] == "ls /workspace/1/sites/"

    def test_different_user_id(self):
        """Rewrites use the current user context, not hardcoded user 1."""
        token = current_user_id.set(42)
        try:
            executor = _make_executor()
            result = executor._rewrite_workspace_paths(
                "file_read", {"path": "/workspace/data.csv"},
            )
            assert result["path"] == "/workspace/42/data.csv"
        finally:
            current_user_id.reset(token)

    def test_no_user_context_passes_through(self):
        """Infrastructure tasks (user_id=0) get no rewrite."""
        token = current_user_id.set(0)
        try:
            executor = _make_executor()
            result = executor._rewrite_workspace_paths(
                "file_write", {"path": "/workspace/sites/x/index.html", "content": "x"},
            )
            assert result["path"] == "/workspace/sites/x/index.html"
        finally:
            current_user_id.reset(token)

    def test_non_workspace_path_untouched(self):
        """Paths outside /workspace/ are not rewritten."""
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "file_read", {"path": "/etc/passwd"},
        )
        assert result["path"] == "/etc/passwd"

    def test_non_file_tool_untouched(self):
        """Tools like web_search don't get path rewriting."""
        executor = _make_executor()
        args = {"query": "test /workspace/sites/"}
        result = executor._rewrite_workspace_paths("web_search", args)
        assert result is args  # Same object, not copied

    def test_mkdir_path_rewritten(self):
        executor = _make_executor()
        result = executor._rewrite_workspace_paths(
            "mkdir", {"path": "/workspace/new-dir"},
        )
        assert result["path"] == "/workspace/1/new-dir"
