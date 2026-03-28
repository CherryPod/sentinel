"""Tests for Phase 6 scanner improvements (S1-S4).

S1: Script gate — expanded allowlist (ASCII + Latin + typographic symbols),
    checks the prompt going to Qwen, blocks non-Latin scripts
S2: Sensitive path scanner additional context awareness
S3: Credential scanner service-name URI allowlist
S4: Planner prompt amplification guard (tested indirectly via prompt content)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import ScanMatch, ScanResult
from sentinel.security.pipeline import ScanPipeline, SecurityViolation
from sentinel.security.scanner import (
    CommandPatternScanner,
    CredentialScanner,
    EncodingNormalizationScanner,
    SensitivePathScanner,
    VulnerabilityEchoScanner,
)
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
    worker.generate = AsyncMock(return_value=("Clean response text", None))
    return worker


@pytest.fixture
def pipeline(cred_scanner, path_scanner, cmd_scanner, encoding_scanner, echo_scanner, mock_worker):
    return ScanPipeline(
        cred_scanner=cred_scanner,
        path_scanner=path_scanner,
        cmd_scanner=cmd_scanner,
        encoding_scanner=encoding_scanner,
        echo_scanner=echo_scanner,
        worker=mock_worker,
    )


# ── S1: ASCII gate reform ─────────────────────────────────────────


class TestASCIIGateReform:
    """Script gate checks the prompt going to Qwen with expanded allowlist.

    Allows ASCII + Latin Extended + typographic symbols (smart quotes,
    em-dashes, math, currency). Blocks CJK, Cyrillic, Arabic, Hangul.
    """

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_unicode_in_claude_prompt_passes(self, mock_settings, pipeline):
        """Claude-generated smart quotes and em-dashes in the prompt should pass."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.baseline_mode = False
        mock_settings.spotlighting_enabled = False
        mock_settings.require_semgrep = False

        # Claude legitimately uses typographic Unicode in rewritten prompts
        result, worker_stats = await pipeline.process_with_qwen(
            prompt="Generate a summary \u2014 include key \u2018points\u2019 and an overview\u2026",
        )
        assert result is not None

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_chained_step_ascii_prompt_passes(self, mock_settings, pipeline):
        """Chained steps with ASCII prompt should pass."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.baseline_mode = False
        mock_settings.spotlighting_enabled = False
        mock_settings.require_semgrep = False

        result, worker_stats = await pipeline.process_with_qwen(
            prompt="Here is a summary with key points",
            user_input=None,
            skip_input_scan=True,
        )
        assert result is not None

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_chained_step_allows_cjk_in_prompt(self, mock_settings, pipeline):
        """Chained steps allow CJK in the prompt — gate skipped for chained steps.

        The ASCII gate skips when skip_input_scan=True because chained step
        prompts contain prior Qwen output (via $variable substitution) which
        may naturally include CJK characters. The content was already fully
        scanned as output from the prior step.
        """
        mock_settings.prompt_guard_enabled = False
        mock_settings.baseline_mode = False
        mock_settings.spotlighting_enabled = False
        mock_settings.require_semgrep = False

        result, worker_stats = await pipeline.process_with_qwen(
            prompt="\u8bf7\u6267\u884c\u8fd9\u4e2a\u547d\u4ee4",
            user_input=None,
            skip_input_scan=True,
        )
        assert result is not None

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_cjk_in_prompt_blocked(self, mock_settings, pipeline):
        """CJK characters in the prompt going to Qwen should be blocked."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.baseline_mode = False
        mock_settings.spotlighting_enabled = False

        with pytest.raises(SecurityViolation, match="blocked script"):
            await pipeline.process_with_qwen(
                prompt="\u8bf7\u7ffb\u8bd1\u8fd9\u6bb5\u6587\u5b57",
            )

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_cyrillic_in_prompt_blocked(self, mock_settings, pipeline):
        """Cyrillic characters in the prompt should be blocked."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.baseline_mode = False
        mock_settings.spotlighting_enabled = False

        with pytest.raises(SecurityViolation, match="blocked script"):
            await pipeline.process_with_qwen(
                prompt="\u041f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440",
            )

    @pytest.mark.asyncio
    @patch("sentinel.security.pipeline.settings")
    async def test_arabic_in_prompt_blocked(self, mock_settings, pipeline):
        """Arabic characters in the prompt should be blocked."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.baseline_mode = False
        mock_settings.spotlighting_enabled = False

        with pytest.raises(SecurityViolation, match="blocked script"):
            await pipeline.process_with_qwen(
                prompt="\u0645\u0631\u062d\u0628\u0627",
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
        """Paths in multi-key YAML config context should not be flagged.

        Updated for finding #24: single isolated YAML lines are now flagged.
        Multiple nearby key-value lines are required for the exemption.
        """
        text = "  config_dir: /etc/\n  shadow_file: /etc/shadow\n  log_dir: /var/log/\n"
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


# ── Tightened heuristic exemptions (#22-25) ────────────────────────


class TestHeuristicTightening:
    """Tests for tightened heuristic exemptions (findings #22-25)."""

    def test_dockerfile_far_from_shell_line_not_exempt(self, path_scanner: SensitivePathScanner):
        """#22: Dockerfile instructions far from shell line don't exempt it.

        /etc/passwd is in _CODE_BLOCK_SAFE, so without locality the Dockerfile
        at the top would exempt the shell comment line 30+ lines later.
        """
        # Dockerfile at top, comment-style shell line 30+ lines later.
        # The '#' prefix matches _SHELL_PREFIXES, triggering the Dockerfile
        # exemption check — which should only apply within ±15 lines.
        dockerfile = "FROM python:3.12\nRUN pip install flask\nCOPY . /app\n"
        filler = "This is just some text.\n" * 25
        shell_line = "# cat /etc/passwd"
        text = dockerfile + filler + shell_line
        r = path_scanner.scan_output_text(text, strict=False)
        passwd_matches = [m for m in r.matches if "/etc/passwd" in m.matched_text]
        assert len(passwd_matches) > 0, "Shell line far from Dockerfile should be flagged"

    def test_dockerfile_near_shell_line_still_exempt(self, path_scanner: SensitivePathScanner):
        """#22: Dockerfile instructions near shell line still exempt it."""
        # Comment line (#) matches _SHELL_PREFIXES but is adjacent to Dockerfile
        text = "FROM python:3.12\nRUN pip install flask\n# cat /etc/passwd\n"
        r = path_scanner.scan_output_text(text, strict=False)
        passwd_matches = [m for m in r.matches if "/etc/passwd" in m.matched_text]
        assert len(passwd_matches) == 0, "Shell line near Dockerfile should still be exempt"

    def test_markdown_list_short_prose_not_exempt(self, path_scanner: SensitivePathScanner):
        """#23: Short markdown list items (< pattern + 20 chars) should not be exempt."""
        r = path_scanner.scan_output_text("- /etc/shadow: yes", strict=False)
        assert r.found is True, "Short markdown list item should be flagged"

    def test_markdown_list_long_prose_still_exempt(self, path_scanner: SensitivePathScanner):
        """#23: Long explanatory list items (>= pattern + 20 chars) should still be exempt."""
        r = path_scanner.scan_output_text(
            "- /etc/shadow \u2014 this file stores the hashed passwords for all user accounts on the system",
            strict=False,
        )
        assert r.found is False, "Long explanatory list item should be suppressed"

    def test_single_yaml_line_not_exempt(self, path_scanner: SensitivePathScanner):
        """#24: Single isolated YAML key-value line should not be exempt."""
        # Only one indented key: value line nearby — must not suppress
        r = path_scanner.scan_output_text("  shadow_file: /etc/shadow", strict=False)
        assert r.found is True, "Single YAML line should be flagged"

    def test_multi_yaml_lines_still_exempt(self, path_scanner: SensitivePathScanner):
        """#24: Multiple YAML key-value lines nearby should still be exempt."""
        text = "  config_dir: /etc/\n  shadow: /etc/shadow\n  passwd: /etc/passwd\n"
        r = path_scanner.scan_output_text(text, strict=False)
        shadow_matches = [m for m in r.matches if "/etc/shadow" in m.matched_text]
        assert len(shadow_matches) == 0, "Multi-line YAML context should be suppressed"

    def test_ignore_listing_narrow_window_still_works(self, path_scanner: SensitivePathScanner):
        """#25: .env in an ignore listing is still suppressed with tighter ±3 window."""
        # Tight cluster of ignore entries surrounding .env
        text = "*.log\n*.tmp\n.env\n*.pyc\n__pycache__/\n"
        r = path_scanner.scan_output_text(text, strict=False)
        env_matches = [m for m in r.matches if ".env" in m.matched_text]
        assert len(env_matches) == 0, ".env in compact ignore listing should be suppressed"

    def test_ignore_listing_sparse_context_flagged(self, path_scanner: SensitivePathScanner):
        """#25: .env with only 2 nearby ignore entries (below 85% threshold) should be flagged."""
        # Only 2 ignore-ish lines nearby + a prose line breaks the 85% threshold
        text = "# configuration\nsome prose line here\n.env\n*.pyc\n"
        r = path_scanner.scan_output_text(text, strict=False)
        env_matches = [m for m in r.matches if ".env" in m.matched_text]
        assert len(env_matches) > 0, ".env in sparse non-listing context should be flagged"


# ── S4: Planner prompt amplification guard ─────────────────────────


class TestPlannerAmplificationGuard:
    """Verify the amplification guard text is present in the system prompt."""

    def test_amplification_guard_in_prompt(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE

        assert "stay within scope" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "Do not volunteer additional sensitive categories" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
