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
                tagged, exec_meta = await executor.execute("file_write", {
                    "path": path, "content": "hello world",
                })
                assert tagged.trust_level == TrustLevel.TRUSTED
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
                tagged, exec_meta = await executor.execute("file_write", {
                    "path": path, "content": "data",
                })
                assert tagged.trust_level == TrustLevel.TRUSTED
                assert tagged.source.value == "tool"


class TestFileWriteFileTagStrip:
    """Defence-in-depth: strip <FILE path="..."> tags from code file writes.

    When Qwen outputs multi-file content using <FILE> tags and the planner
    stores the entire output in one variable, each file_write step gets the
    full blob. The executor must extract just the matching file's content.
    """

    async def _write_code_file(self, executor, path, content):
        """Helper: execute file_write with policy mocked to allow."""
        with patch.object(executor._engine, "check_file_write") as mock_check:
            from sentinel.core.models import PolicyResult, ValidationResult
            mock_check.return_value = ValidationResult(
                status=PolicyResult.ALLOWED, path=path,
            )
            return await executor.execute("file_write", {
                "path": path, "content": content,
            })

    @pytest.mark.asyncio
    async def test_extracts_matching_file_by_exact_path(self, executor):
        """When content has multiple <FILE> blocks, extract the one matching the target path."""
        multi_file_content = (
            '<FILE path="/workspace/cli.py">\nimport argparse\n</FILE>\n'
            '<FILE path="/workspace/main.py">\nfrom cli import main\nmain()\n</FILE>'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "main.py")
            # Rewrite to use tmpdir paths in the FILE tags
            content = (
                f'<FILE path="{os.path.join(tmpdir, "cli.py")}">\nimport argparse\n</FILE>\n'
                f'<FILE path="{path}">\nfrom cli import main\nmain()\n</FILE>'
            )
            await self._write_code_file(executor, path, content)
            with open(path) as f:
                written = f.read()
            assert written == "from cli import main\nmain()\n"
            assert "<FILE" not in written

    @pytest.mark.asyncio
    async def test_extracts_matching_file_by_basename(self, executor):
        """When exact path doesn't match, fall back to basename matching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "app.py")
            # FILE tags use a different base path than the actual write target
            content = (
                '<FILE path="/workspace/app.py">\nprint("hello")\n</FILE>\n'
                '<FILE path="/workspace/utils.py">\ndef helper(): pass\n</FILE>'
            )
            await self._write_code_file(executor, path, content)
            with open(path) as f:
                written = f.read()
            assert written == 'print("hello")\n'
            assert "<FILE" not in written

    @pytest.mark.asyncio
    async def test_single_block_fallback(self, executor):
        """When there's only one <FILE> block and path doesn't match, use it anyway."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "script.py")
            content = '<FILE path="/workspace/other.py">\nx = 42\n</FILE>'
            await self._write_code_file(executor, path, content)
            with open(path) as f:
                written = f.read()
            assert written == "x = 42\n"

    @pytest.mark.asyncio
    async def test_no_strip_on_non_code_files(self, executor):
        """<FILE> tags in non-code files (e.g. .txt, .json) are left as-is."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "data.txt")
            content = '<FILE path="/workspace/data.txt">\nhello\n</FILE>'
            await self._write_code_file(executor, path, content)
            with open(path) as f:
                written = f.read()
            # Non-code file — tags should be preserved
            assert "<FILE" in written

    @pytest.mark.asyncio
    async def test_no_strip_when_no_file_tags(self, executor):
        """Normal code content without <FILE> tags is written unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "clean.py")
            content = "import os\nprint(os.getcwd())\n"
            await self._write_code_file(executor, path, content)
            with open(path) as f:
                written = f.read()
            assert written == content

    @pytest.mark.asyncio
    async def test_no_match_multiple_blocks_passes_through(self, executor):
        """When multiple blocks exist but none match, content passes through unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "unrelated.py")
            content = (
                '<FILE path="/workspace/a.py">\ncode_a\n</FILE>\n'
                '<FILE path="/workspace/b.py">\ncode_b\n</FILE>'
            )
            await self._write_code_file(executor, path, content)
            with open(path) as f:
                written = f.read()
            # No match and multiple blocks — passes through unchanged
            assert "<FILE" in written


class TestFileWriteTrailingNewline:
    """Code fixer: trailing newline and normalisation on code file writes."""

    async def _write_code_file(self, executor, path, content):
        """Helper: execute file_write with policy mocked to allow."""
        with patch.object(executor._engine, "check_file_write") as mock_check:
            from sentinel.core.models import PolicyResult, ValidationResult
            mock_check.return_value = ValidationResult(
                status=PolicyResult.ALLOWED, path=path,
            )
            return await executor.execute("file_write", {
                "path": path, "content": content,
            })

    @pytest.mark.asyncio
    async def test_adds_trailing_newline(self, executor):
        """Code file without trailing newline gets one added."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "app.py")
            await self._write_code_file(executor, path, "x = 1")
            with open(path) as f:
                assert f.read() == "x = 1\n"

    @pytest.mark.asyncio
    async def test_preserves_existing_newline(self, executor):
        """Code file that already has trailing newline is unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "app.py")
            await self._write_code_file(executor, path, "x = 1\n")
            with open(path) as f:
                assert f.read() == "x = 1\n"

    @pytest.mark.asyncio
    async def test_no_newline_for_non_code(self, executor):
        """Non-code files (.txt) don't get trailing newline added."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "data.txt")
            with patch.object(executor._engine, "check_file_write") as mock_check:
                from sentinel.core.models import PolicyResult, ValidationResult
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                await executor.execute("file_write", {
                    "path": path, "content": "no newline",
                })
            with open(path) as f:
                assert f.read() == "no newline"

    @pytest.mark.asyncio
    async def test_yaml_gets_stripping(self, executor):
        """YAML files (now in _CODE_EXTENSIONS) get fence stripping."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            content = "```yaml\nkey: value\n```"
            await self._write_code_file(executor, path, content)
            with open(path) as f:
                written = f.read()
            assert "```" not in written
            assert "key: value" in written


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
                tagged, exec_meta = await executor.execute("file_read", {"path": path})
                assert tagged.content == "file contents"
                # Files without provenance default to UNTRUSTED (trust laundering fix)
                assert tagged.trust_level == TrustLevel.UNTRUSTED
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_etc_shadow_blocked(self, executor):
        with pytest.raises(ToolBlockedError, match="blocked"):
            await executor.execute("file_read", {"path": "/etc/shadow"})


class TestShell:
    @pytest.mark.asyncio
    async def test_allowed_command(self, executor):
        tagged, exec_meta = await executor.execute("shell", {"command": "ls /workspace"})
        # Direct shell (no sandbox) is UNTRUSTED — it has network + full FS
        assert tagged.trust_level == TrustLevel.UNTRUSTED

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
                tagged, exec_meta = await executor.execute("mkdir", {"path": path})
                assert os.path.isdir(path)
                assert tagged.trust_level == TrustLevel.TRUSTED


class TestPodmanBuild:
    @pytest.mark.asyncio
    async def test_workspace_allowed(self, executor):
        """podman build command passes policy check (subprocess mocked)."""
        with patch("sentinel.tools.executor.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"Build complete", b"")
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc
            tagged, exec_meta = await executor.execute("podman_build", {
                "context_path": "/workspace/app",
                "tag": "test:latest",
            })
            assert tagged.trust_level == TrustLevel.TRUSTED
            mock_exec.assert_called_once()

    @pytest.mark.asyncio
    async def test_policy_string_matches_execution(self, executor):
        """Policy check string must match the subprocess command."""
        with patch("sentinel.tools.executor.asyncio.create_subprocess_exec") as mock_exec, \
             patch.object(executor._engine, "check_command", wraps=executor._engine.check_command) as spy:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"ok", b"")
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc
            await executor.execute("podman_build", {
                "context_path": "/workspace/app", "tag": "myimg:latest",
            })
            policy_str = spy.call_args[0][0]
            executed_cmd = list(mock_exec.call_args[0])
            import shlex
            assert policy_str == shlex.join(executed_cmd)


class TestPodmanRun:
    @pytest.mark.asyncio
    async def test_policy_string_matches_execution(self, executor):
        """Policy check string must include -d flag (the actual execution flag)."""
        with patch("sentinel.tools.executor.asyncio.create_subprocess_exec") as mock_exec, \
             patch.object(executor._engine, "check_command", wraps=executor._engine.check_command) as spy:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"ok", b"")
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc
            await executor.execute("podman_run", {
                "image": "myimg:latest", "name": "mycontainer",
            })
            policy_str = spy.call_args[0][0]
            executed_cmd = list(mock_exec.call_args[0])
            import shlex
            assert policy_str == shlex.join(executed_cmd)
            assert "-d" in policy_str


class TestPodmanStop:
    @pytest.mark.asyncio
    async def test_policy_string_matches_execution(self, executor):
        """Policy check string must match subprocess command for podman stop."""
        with patch("sentinel.tools.executor.asyncio.create_subprocess_exec") as mock_exec, \
             patch.object(executor._engine, "check_command", wraps=executor._engine.check_command) as spy:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"ok", b"")
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc
            await executor.execute("podman_stop", {"container_name": "test-ctr"})
            policy_str = spy.call_args[0][0]
            executed_cmd = list(mock_exec.call_args[0])
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


class TestSignalSend:
    """Tests for signal_send tool."""

    @pytest.fixture
    def signal_executor(self, engine):
        """Executor with a mock Signal channel wired in."""
        ex = ToolExecutor(engine)
        mock_channel = AsyncMock()
        ex.set_channels(signal_channel=mock_channel)
        return ex

    @pytest.mark.asyncio
    async def test_basic_send(self, signal_executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = True
            tagged, exec_meta = await signal_executor.execute(
                "signal_send", {"message": "hello", "recipient": "+441234567890"},
            )
            assert tagged.trust_level == TrustLevel.TRUSTED
            assert "Signal message sent" in tagged.content
            signal_executor._signal_channel.send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_disabled(self, executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = False
            with pytest.raises(ToolError, match="disabled"):
                await executor.execute("signal_send", {"message": "hello", "recipient": "x"})

    @pytest.mark.asyncio
    async def test_no_channel(self, executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = True
            with pytest.raises(ToolError, match="not available"):
                await executor.execute("signal_send", {"message": "hello", "recipient": "x"})

    @pytest.mark.asyncio
    async def test_missing_recipient(self, signal_executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = True
            with pytest.raises(ToolError, match="No recipient"):
                await signal_executor.execute(
                    "signal_send", {"message": "hello"},
                )

    @pytest.mark.asyncio
    async def test_empty_message(self, signal_executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = True
            with pytest.raises(ToolError, match="'message' is required"):
                await signal_executor.execute(
                    "signal_send", {"message": "", "recipient": "+441234567890"},
                )


class TestTelegramSend:
    """Tests for telegram_send tool."""

    @pytest.fixture
    def telegram_executor(self, engine):
        """Executor with a mock Telegram channel wired in."""
        ex = ToolExecutor(engine)
        mock_channel = AsyncMock()
        ex.set_channels(telegram_channel=mock_channel)
        return ex

    @pytest.mark.asyncio
    async def test_basic_send(self, telegram_executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.telegram_enabled = True
            tagged, exec_meta = await telegram_executor.execute(
                "telegram_send", {"message": "hello", "recipient": "0000000000"},
            )
            assert tagged.trust_level == TrustLevel.TRUSTED
            assert "Telegram message sent" in tagged.content
            telegram_executor._telegram_channel.send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_disabled(self, executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.telegram_enabled = False
            with pytest.raises(ToolError, match="disabled"):
                await executor.execute("telegram_send", {"message": "hello", "recipient": "x"})

    @pytest.mark.asyncio
    async def test_no_channel(self, executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.telegram_enabled = True
            with pytest.raises(ToolError, match="not available"):
                await executor.execute("telegram_send", {"message": "hello", "recipient": "x"})

    @pytest.mark.asyncio
    async def test_missing_recipient(self, telegram_executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.telegram_enabled = True
            with pytest.raises(ToolError, match="No recipient"):
                await telegram_executor.execute(
                    "telegram_send", {"message": "hello"},
                )

    @pytest.mark.asyncio
    async def test_empty_message(self, telegram_executor):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.telegram_enabled = True
            with pytest.raises(ToolError, match="'message' is required"):
                await telegram_executor.execute(
                    "telegram_send", {"message": "", "recipient": "0000000000"},
                )


class TestMessagingToolDescriptions:
    """Verify signal_send / telegram_send appear conditionally in tool descriptions."""

    def test_signal_included_when_enabled(self, engine):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = True
            mock_settings.telegram_enabled = False
            mock_settings.email_backend = "imap"
            mock_settings.calendar_backend = "caldav"
            ex = ToolExecutor(engine)
            names = [d["name"] for d in ex.get_tool_descriptions()]
            assert "signal_send" in names
            assert "telegram_send" not in names

    def test_telegram_included_when_enabled(self, engine):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = False
            mock_settings.telegram_enabled = True
            mock_settings.email_backend = "imap"
            mock_settings.calendar_backend = "caldav"
            ex = ToolExecutor(engine)
            names = [d["name"] for d in ex.get_tool_descriptions()]
            assert "telegram_send" in names
            assert "signal_send" not in names

    def test_neither_when_disabled(self, engine):
        with patch("sentinel.core.config.settings") as mock_settings:
            mock_settings.signal_enabled = False
            mock_settings.telegram_enabled = False
            mock_settings.email_backend = "imap"
            mock_settings.calendar_backend = "caldav"
            ex = ToolExecutor(engine)
            names = [d["name"] for d in ex.get_tool_descriptions()]
            assert "signal_send" not in names
            assert "telegram_send" not in names


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
        tagged, exec_meta = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        mock_sandbox.run.assert_awaited_once_with("ls /workspace", timeout=None)
        assert tagged.source == DataSource.SANDBOX
        assert tagged.trust_level == TrustLevel.UNTRUSTED
        assert tagged.content == "sandbox output"

    @pytest.mark.asyncio
    async def test_direct_shell_when_sandbox_disabled(self, engine):
        """Shell commands use async subprocess when no sandbox configured."""
        executor = ToolExecutor(engine, sandbox=None, trust_level=2)
        with patch("sentinel.tools.executor.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"direct output", b"")
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc
            tagged, exec_meta = await executor.execute("shell", {"command": "ls /workspace"})
            mock_exec.assert_called_once()
            assert tagged.source == DataSource.TOOL
            # Direct shell (no sandbox) is UNTRUSTED — it has network + full FS
            assert tagged.trust_level == TrustLevel.UNTRUSTED

    @pytest.mark.asyncio
    async def test_sandbox_used_at_low_trust(self, engine, mock_sandbox):
        """Shell commands use sandbox even at TL1 when sandbox is available."""
        executor = ToolExecutor(engine, sandbox=mock_sandbox, trust_level=1)
        tagged, exec_meta = await executor.execute("shell", {"command": "ls /workspace"})
        mock_sandbox.run.assert_awaited_once()
        assert tagged.source == DataSource.SANDBOX

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
        tagged, exec_meta = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        assert "sandbox timed out" in tagged.content
        assert "partial" in tagged.content
        assert tagged.source == DataSource.SANDBOX
        assert tagged.trust_level == TrustLevel.UNTRUSTED

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
        tagged, exec_meta = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        assert "out of memory" in tagged.content
        assert "partial oom" in tagged.content
        assert tagged.source == DataSource.SANDBOX

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
        tagged, exec_meta = await sandbox_executor.execute("shell", {"command": "ls /workspace"})
        assert "exit code: 1" in tagged.content
        assert "error details" in tagged.content
        assert tagged.source == DataSource.SANDBOX

    def test_constructor_accepts_sandbox_and_trust_level(self, engine, mock_sandbox):
        """ToolExecutor stores sandbox and trust_level from constructor."""
        executor = ToolExecutor(engine, sandbox=mock_sandbox, trust_level=3)
        assert executor._sandbox is mock_sandbox
        assert executor._trust_level == 3


class TestShellSandboxContext:
    """_shell() passes sandbox_context=True when sandbox is active."""

    @pytest.mark.asyncio
    async def test_sandbox_active_passes_context(self, engine):
        """When sandbox is configured and TL >= 2, check_command gets sandbox_context=True."""
        mock_sandbox = AsyncMock()
        mock_sandbox.run.return_value = MagicMock(
            stdout="ok", stderr="", exit_code=0, timed_out=False, oom_killed=False,
        )
        executor = ToolExecutor(engine, sandbox=mock_sandbox, trust_level=2)

        with patch.object(
            executor._engine, "check_command", wraps=executor._engine.check_command,
        ) as spy:
            await executor.execute("shell_exec", {"command": "ls /workspace"})
            spy.assert_called_once_with("ls /workspace", sandbox_context=True)

    @pytest.mark.asyncio
    async def test_no_sandbox_passes_false(self, engine):
        """When sandbox is None, check_command gets sandbox_context=False."""
        executor = ToolExecutor(engine, sandbox=None, trust_level=2)

        with patch.object(
            executor._engine, "check_command", wraps=executor._engine.check_command,
        ) as spy, patch("sentinel.tools.executor.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (b"ok", b"")
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            await executor.execute("shell_exec", {"command": "ls /workspace"})
            spy.assert_called_once_with("ls /workspace", sandbox_context=False)

    @pytest.mark.asyncio
    async def test_low_trust_sandbox_context_true(self, engine):
        """At TL1 with sandbox configured, sandbox_context is True (sandbox always used when available)."""
        mock_sandbox = AsyncMock()
        mock_sandbox.run.return_value = MagicMock(
            stdout="ok", stderr="", exit_code=0, timed_out=False, oom_killed=False,
        )
        executor = ToolExecutor(engine, sandbox=mock_sandbox, trust_level=1)

        with patch.object(
            executor._engine, "check_command", wraps=executor._engine.check_command,
        ) as spy:
            await executor.execute("shell_exec", {"command": "ls /workspace"})
            spy.assert_called_once_with("ls /workspace", sandbox_context=True)
