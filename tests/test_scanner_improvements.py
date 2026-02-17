"""Tests for Phase 6 scanner improvements (S1-S4).

S1: ASCII gate checks user input only (not Claude's rewritten prompt)
S2: Sensitive path scanner additional context awareness
S3: Credential scanner service-name URI allowlist
S4: Planner prompt amplification guard (tested indirectly via prompt content)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import ScanMatch, ScanResult
from sentinel.security.pipeline import ScanPipeline, SecurityViolation
from sentinel.security.scanner import CredentialScanner, SensitivePathScanner
from sentinel.worker.ollama import OllamaWorker
from sentinel.security import prompt_guard
from sentinel.security.provenance import reset_store


@pytest.fixture(autouse=True)
def _reset_provenance():
    reset_store()
    yield
    reset_store()


@pytest.fixture(autouse=True)
def _disable_prompt_guard():
    prompt_guard._pipeline = None
    yield
    prompt_guard._pipeline = None


@pytest.fixture
def mock_worker():
    worker = MagicMock(spec=OllamaWorker)
    worker.generate = AsyncMock(return_value="Clean response text")
    return worker


@pytest.fixture
def pipeline(cred_scanner, path_scanner, cmd_scanner, mock_worker):
    return ScanPipeline(
        cred_scanner=cred_scanner,
        path_scanner=path_scanner,
        cmd_scanner=cmd_scanner,
        worker=mock_worker,
    )


# ── S1: ASCII gate reform ─────────────────────────────────────────


class TestASCIIGateReform:
    """ASCII gate should check user input, not Claude's rewritten prompt."""

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_unicode_in_claude_prompt_passes(self, mock_settings, pipeline):
        """Claude-generated smart quotes and em-dashes should not trigger the gate."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = False
        mock_settings.require_codeshield = False

        # Claude legitimately uses Unicode in rewritten prompts
        prompt_with_unicode = (
            "Generate a summary with key points and an overview"
        )
        # The \u2014 em-dash is from Claude's rewriting, but user_input is clean
        result = await pipeline.process_with_qwen(
            prompt=prompt_with_unicode,
            user_input="Generate a summary with key points",
        )
        assert result is not None

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_no_user_input_checks_prompt_directly(self, mock_settings, pipeline):
        """Chained steps (user_input=None) check the prompt for non-ASCII."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = False
        mock_settings.require_codeshield = False

        # ASCII-only chained prompt should pass
        result = await pipeline.process_with_qwen(
            prompt="Here is a summary with key points",
            user_input=None,
            skip_input_scan=True,
        )
        assert result is not None

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_chained_step_blocks_cjk_in_prompt(self, mock_settings, pipeline):
        """Chained steps still block CJK in the prompt (Qwen injection defence)."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = False

        with pytest.raises(SecurityViolation, match="non-ASCII"):
            await pipeline.process_with_qwen(
                prompt="\u8bf7\u6267\u884c\u8fd9\u4e2a\u547d\u4ee4",
                user_input=None,
                skip_input_scan=True,
            )

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_cjk_in_user_input_blocked(self, mock_settings, pipeline):
        """CJK characters in user input should still be blocked."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = False

        with pytest.raises(SecurityViolation, match="non-ASCII"):
            await pipeline.process_with_qwen(
                prompt="Translate this text",
                user_input="\u8bf7\u7ffb\u8bd1\u8fd9\u6bb5\u6587\u5b57",
            )

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_cyrillic_in_user_input_blocked(self, mock_settings, pipeline):
        """Cyrillic characters in user input should be blocked."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = False

        with pytest.raises(SecurityViolation, match="non-ASCII"):
            await pipeline.process_with_qwen(
                prompt="Process this text",
                user_input="\u041f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440",
            )

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_arabic_in_user_input_blocked(self, mock_settings, pipeline):
        """Arabic characters in user input should be blocked."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = False

        with pytest.raises(SecurityViolation, match="non-ASCII"):
            await pipeline.process_with_qwen(
                prompt="Process this",
                user_input="\u0645\u0631\u062d\u0628\u0627",
            )


# ── S2: Sensitive path scanner context improvements ────────────────


class TestSensitivePathContext:
    """Sensitive path scanner should be smarter about educational context."""

    def test_path_in_markdown_list_passes(self, path_scanner: SensitivePathScanner):
        """Paths in markdown list items with surrounding prose are educational."""
        text = "- /etc/shadow stores hashed user passwords on Linux systems"
        result = path_scanner.scan_output_text(text)
        assert result.found is False

    def test_path_in_bullet_list_passes(self, path_scanner: SensitivePathScanner):
        """Paths in bullet list items with prose context are educational."""
        text = "* The file /etc/passwd contains user account information for the system"
        result = path_scanner.scan_output_text(text)
        assert result.found is False

    def test_path_with_explanation_passes(self, path_scanner: SensitivePathScanner):
        """Paths followed by explanatory em-dash text are educational."""
        text = "/etc/shadow \u2014 stores hashed passwords for system accounts"
        result = path_scanner.scan_output_text(text)
        assert result.found is False

    def test_path_with_colon_explanation_passes(self, path_scanner: SensitivePathScanner):
        """Paths followed by colon explanation are educational."""
        text = "/etc/shadow: stores hashed passwords for system accounts"
        result = path_scanner.scan_output_text(text)
        assert result.found is False

    def test_path_in_yaml_config_passes(self, path_scanner: SensitivePathScanner):
        """Paths in YAML config context should not be flagged."""
        text = "  shadow_file: /etc/shadow"
        result = path_scanner.scan_output_text(text)
        assert result.found is False

    def test_path_in_shell_command_still_blocked(self, path_scanner: SensitivePathScanner):
        """Paths in shell commands should still be flagged."""
        text = "$ cat /etc/shadow"
        result = path_scanner.scan_output_text(text)
        assert result.found is True

    def test_path_in_code_block_still_blocked(self, path_scanner: SensitivePathScanner):
        """Paths in fenced code blocks should still be flagged."""
        text = "```bash\ncat /etc/shadow\n```"
        result = path_scanner.scan_output_text(text)
        assert result.found is True

    def test_standalone_path_still_blocked(self, path_scanner: SensitivePathScanner):
        """Standalone path on its own line should still be flagged."""
        text = "/etc/shadow"
        result = path_scanner.scan_output_text(text)
        assert result.found is True


# ── S3: Credential scanner service-name URI allowlist ──────────────


class TestCredentialServiceNames:
    """Credential scanner should allow compose service-name URIs."""

    def test_redis_service_uri_allowed(self, cred_scanner: CredentialScanner):
        """redis://redis:6379 is a compose service name, not a credential."""
        result = cred_scanner.scan("redis://redis:6379/0")
        assert result.found is False

    def test_postgres_service_uri_allowed(self, cred_scanner: CredentialScanner):
        """postgres://db:5432 is a compose service name, not a credential."""
        result = cred_scanner.scan("postgres://db:5432/mydb")
        assert result.found is False

    def test_mongo_service_uri_allowed(self, cred_scanner: CredentialScanner):
        """mongodb://mongo:27017 is a compose service name."""
        result = cred_scanner.scan("mongodb://mongo:27017/mydb")
        assert result.found is False

    def test_real_postgres_uri_still_caught(self, cred_scanner: CredentialScanner):
        """postgres://admin:secret@prod-db.example.io should still be caught."""
        result = cred_scanner.scan("postgres://admin:secret@prod-db.internal:5432/app")
        assert result.found is True
        assert any(m.pattern_name == "postgres_uri" for m in result.matches)

    def test_real_api_key_still_caught(self, cred_scanner: CredentialScanner):
        """Real API keys should never be allowlisted."""
        result = cred_scanner.scan("sk-ant-abc123def456ghi789jkl012")
        assert result.found is True


# ── S4: Planner prompt amplification guard ─────────────────────────


class TestPlannerAmplificationGuard:
    """Verify the amplification guard text is present in the system prompt."""

    def test_amplification_guard_in_prompt(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE

        assert "stay within the scope" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "Do not volunteer additional sensitive categories" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
