"""Tests for DoS input validation — Pydantic field validators + pipeline prompt gate."""

import unicodedata
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from sentinel.api.app import (
    ApprovalDecision,
    ProcessRequest,
    ScanRequest,
    TaskRequest,
    MAX_TEXT_LENGTH,
    MIN_TASK_REQUEST_LENGTH,
    MAX_REASON_LENGTH,
)
from sentinel.security.pipeline import ScanPipeline, SecurityViolation
from sentinel.security.scanner import CommandPatternScanner, CredentialScanner, SensitivePathScanner
from sentinel.worker.ollama import OllamaWorker
from sentinel.security.provenance import reset_store
from sentinel.security import prompt_guard


# ── Fixtures ──────────────────────────────────────────────────────


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
    worker.generate = AsyncMock(return_value="Generated response text")
    return worker


@pytest.fixture
def pipeline(engine, mock_worker):
    cred = CredentialScanner(engine.policy.get("credential_patterns", []))
    path = SensitivePathScanner(engine.policy.get("sensitive_path_patterns", []))
    cmd = CommandPatternScanner()
    return ScanPipeline(
        cred_scanner=cred,
        path_scanner=path,
        cmd_scanner=cmd,
        worker=mock_worker,
    )


# ── TaskRequest validation ────────────────────────────────────────


class TestTaskRequestValidation:
    """TaskRequest.request: strip, NFC, newline collapse, min 3, max 50K."""

    def test_empty_string_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            TaskRequest(request="")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            TaskRequest(request="   \t\n  ")

    def test_below_minimum_rejected(self):
        with pytest.raises(ValidationError, match="too short"):
            TaskRequest(request="ab")

    def test_single_char_rejected(self):
        with pytest.raises(ValidationError, match="too short"):
            TaskRequest(request="?")

    def test_above_maximum_rejected(self):
        with pytest.raises(ValidationError, match="too long"):
            TaskRequest(request="a" * (MAX_TEXT_LENGTH + 1))

    def test_valid_request_passes(self):
        req = TaskRequest(request="Summarize this document")
        assert req.request == "Summarize this document"

    def test_minimum_length_passes(self):
        req = TaskRequest(request="abc")
        assert req.request == "abc"

    def test_strips_whitespace(self):
        req = TaskRequest(request="  hello world  ")
        assert req.request == "hello world"

    def test_strip_then_length_check(self):
        """Whitespace padding around a 2-char string should fail min length after strip."""
        with pytest.raises(ValidationError, match="too short"):
            TaskRequest(request="   ab   ")

    def test_newline_collapse(self):
        """Runs of 3+ newlines collapse to 2, preventing newline bombs."""
        req = TaskRequest(request="hello\n\n\n\n\nworld")
        assert req.request == "hello\n\nworld"

    def test_double_newline_preserved(self):
        """Exactly 2 newlines are left alone (normal paragraph break)."""
        req = TaskRequest(request="hello\n\nworld")
        assert req.request == "hello\n\nworld"

    def test_unicode_nfc_normalized(self):
        """Combining characters are normalized to precomposed form."""
        # e + combining acute accent → é (precomposed)
        decomposed = "caf\u0065\u0301"  # NFD form
        req = TaskRequest(request=decomposed)
        assert req.request == unicodedata.normalize("NFC", decomposed)

    def test_massive_newline_bomb(self):
        """100 consecutive newlines should collapse, not create oversized output."""
        req = TaskRequest(request="start" + "\n" * 100 + "end")
        assert "\n\n\n" not in req.request
        assert req.request == "start\n\nend"


# ── ScanRequest validation ────────────────────────────────────────


class TestScanRequestValidation:
    """ScanRequest.text: strip, NFC, min 1, max 50K."""

    def test_empty_string_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            ScanRequest(text="")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            ScanRequest(text="   ")

    def test_above_maximum_rejected(self):
        with pytest.raises(ValidationError, match="too long"):
            ScanRequest(text="x" * (MAX_TEXT_LENGTH + 1))

    def test_single_char_passes(self):
        """ScanRequest has min 1, unlike TaskRequest's min 3."""
        req = ScanRequest(text="x")
        assert req.text == "x"

    def test_valid_text_passes(self):
        req = ScanRequest(text="check this output")
        assert req.text == "check this output"


# ── ProcessRequest validation ─────────────────────────────────────


class TestProcessRequestValidation:
    """ProcessRequest.text + untrusted_data validation."""

    def test_empty_text_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            ProcessRequest(text="")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            ProcessRequest(text="\t\n  ")

    def test_above_maximum_rejected(self):
        with pytest.raises(ValidationError, match="too long"):
            ProcessRequest(text="a" * (MAX_TEXT_LENGTH + 1))

    def test_valid_text_passes(self):
        req = ProcessRequest(text="process this")
        assert req.text == "process this"

    def test_untrusted_data_none_passes(self):
        req = ProcessRequest(text="process this", untrusted_data=None)
        assert req.untrusted_data is None

    def test_untrusted_data_above_max_rejected(self):
        with pytest.raises(ValidationError, match="too long"):
            ProcessRequest(text="ok", untrusted_data="x" * (MAX_TEXT_LENGTH + 1))

    def test_untrusted_data_valid_passes(self):
        req = ProcessRequest(text="ok", untrusted_data="some user data")
        assert req.untrusted_data == "some user data"


# ── ApprovalDecision validation ───────────────────────────────────


class TestApprovalDecisionValidation:
    """ApprovalDecision.reason: max 1,000 chars."""

    def test_empty_reason_passes(self):
        """Empty string is the default — should be allowed."""
        d = ApprovalDecision(granted=True, reason="")
        assert d.reason == ""

    def test_valid_reason_passes(self):
        d = ApprovalDecision(granted=False, reason="Looks suspicious")
        assert d.reason == "Looks suspicious"

    def test_above_maximum_rejected(self):
        with pytest.raises(ValidationError, match="too long"):
            ApprovalDecision(granted=True, reason="x" * (MAX_REASON_LENGTH + 1))

    def test_at_maximum_passes(self):
        d = ApprovalDecision(granted=True, reason="x" * MAX_REASON_LENGTH)
        assert len(d.reason) == MAX_REASON_LENGTH


# ── Pipeline prompt length gate ───────────────────────────────────


class TestPipelinePromptLengthGate:
    """process_with_qwen() rejects oversized resolved prompts (>100K combined)."""

    @pytest.mark.asyncio
    async def test_oversized_prompt_only(self, pipeline):
        """Prompt alone exceeding 100K triggers SecurityViolation."""
        big_prompt = "x" * 100_001
        with pytest.raises(SecurityViolation, match="Prompt too long"):
            await pipeline.process_with_qwen(
                prompt=big_prompt,
                skip_input_scan=True,
            )

    @pytest.mark.asyncio
    async def test_oversized_combined(self, pipeline):
        """Prompt + untrusted_data exceeding 100K triggers SecurityViolation."""
        prompt = "a" * 60_000
        data = "b" * 50_000
        with pytest.raises(SecurityViolation, match="Prompt too long"):
            await pipeline.process_with_qwen(
                prompt=prompt,
                untrusted_data=data,
                skip_input_scan=True,
            )

    @patch("sentinel.security.pipeline.settings")
    @pytest.mark.asyncio
    async def test_within_limit_passes(self, mock_settings, pipeline):
        """Combined length under 100K should not be blocked by the length gate."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = True
        mock_settings.ollama_model = "qwen3:14b"

        result = await pipeline.process_with_qwen(
            prompt="Summarize the following text",
            untrusted_data="Some data to summarize",
            skip_input_scan=True,
        )
        assert result.content == "Generated response text"

    @patch("sentinel.security.pipeline.settings")
    @pytest.mark.asyncio
    async def test_exactly_at_limit_passes(self, mock_settings, pipeline):
        """Exactly 100,000 chars combined should pass (limit is >100K, not >=)."""
        mock_settings.prompt_guard_enabled = False
        mock_settings.spotlighting_enabled = False
        mock_settings.ollama_model = "qwen3:14b"

        prompt = "a" * 50_000
        data = "b" * 50_000
        result = await pipeline.process_with_qwen(
            prompt=prompt,
            untrusted_data=data,
            skip_input_scan=True,
        )
        assert result.content == "Generated response text"
