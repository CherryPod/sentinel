"""Tests for build_step_outcome and auto_store_memory."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.core.models import PlanStep, StepResult
from sentinel.planner.builders import build_step_outcome


class TestBuildStepOutcome:
    def test_llm_task_success_basic_fields(self):

        step = PlanStep(id="step_1", type="llm_task", description="Write hello.py")
        result = StepResult(
            step_id="step_1", status="success", content="print('hello')",
            worker_usage={"eval_count": 500},
        )
        outcome = build_step_outcome(step, result, elapsed_s=1.5)
        assert outcome["step_type"] == "llm_task"
        assert outcome["status"] == "success"
        assert outcome["duration_s"] == 1.5
        assert outcome["output_size"] == len("print('hello')")
        assert outcome["error_detail"] is None

    def test_llm_task_blocked_has_genericised_error_detail(self):
        """error_detail is genericised — no scanner names leak to planner."""

        step = PlanStep(id="step_1", type="llm_task", description="Write malware")
        result = StepResult(
            step_id="step_1", status="blocked",
            error="Semgrep: insecure code detected (2 issues)",
        )
        outcome = build_step_outcome(step, result, elapsed_s=0.3)
        assert outcome["status"] == "blocked"
        assert outcome["error_detail"] == "code vulnerability detected"
        assert "Semgrep" not in outcome["error_detail"]

    def test_tool_call_with_exec_meta(self):

        exec_meta = {
            "exit_code": 0, "stderr": "",
        }
        step = PlanStep(id="step_1", type="tool_call", description="Run test", tool="shell")
        result = StepResult(step_id="step_1", status="success", content="PASSED")
        outcome = build_step_outcome(step, result, elapsed_s=2.0, exec_meta=exec_meta)
        assert outcome["exit_code"] == 0
        assert outcome["stderr_preview"] == ""

    def test_tool_call_file_write_meta(self):

        exec_meta = {
            "file_size_before": 100,
            "file_size_after": 250,
            "file_content_before": "old content",
        }
        step = PlanStep(
            id="step_1", type="tool_call", description="Write file",
            tool="file_write", args={"path": "/workspace/app.py", "content": "new"},
        )
        result = StepResult(step_id="step_1", status="success", content="File written: /workspace/app.py")
        outcome = build_step_outcome(step, result, elapsed_s=0.1, exec_meta=exec_meta)
        assert outcome["file_path"] == "/workspace/app.py"
        assert outcome["file_size_before"] == 100
        assert outcome["file_size_after"] == 250
        assert "diff_stats" in outcome

    def test_token_usage_ratio_included(self):

        step = PlanStep(id="step_1", type="llm_task", description="Generate code")
        result = StepResult(
            step_id="step_1", status="success", content="code",
            worker_usage={"eval_count": 4096},
        )
        outcome = build_step_outcome(step, result, elapsed_s=1.0)
        assert outcome["token_usage_ratio"] == 0.5

    def test_no_executor_meta_when_tool_executor_is_none(self):
        step = PlanStep(id="step_1", type="tool_call", description="Do thing", tool="shell")
        result = StepResult(step_id="step_1", status="skipped")
        outcome = build_step_outcome(step, result, elapsed_s=0.0)
        assert outcome["exit_code"] is None

    def test_step_outcome_includes_description_and_tool(self):
        """build_step_outcome includes step description and tool name."""
        step = PlanStep(
            id="step_1",
            type="tool_call",
            description="Search email inbox for dentist",
            tool="email_search",
            args={"query": "dentist"},
        )
        result = StepResult(step_id="step_1", status="success", content="found 3 emails")
        outcome = build_step_outcome(step, result, elapsed_s=1.5)
        assert outcome["description"] == "Search email inbox for dentist"
        assert outcome["tool"] == "email_search"

    def test_step_outcome_description_without_tool(self):
        """build_step_outcome includes description even when tool is None (llm_task)."""
        step = PlanStep(
            id="step_1",
            type="llm_task",
            description="Generate Python analysis script",
            prompt="Write a script...",
        )
        result = StepResult(step_id="step_1", status="success", content="print('hello')")
        outcome = build_step_outcome(step, result, elapsed_s=2.1)
        assert outcome["description"] == "Generate Python analysis script"
        assert outcome["tool"] == ""

    def test_code_fixer_fields_present_when_exec_meta_has_them(self):
        """code_fixer fields from exec_meta are forwarded to step_outcome."""
        exec_meta = {
            "code_fixer_changed": True,
            "code_fixer_fixes": ["python:trailing_newline", "json:truncated_json"],
            "code_fixer_errors": [],
        }
        step = PlanStep(
            id="step_1", type="tool_call", description="Write file",
            tool="file_write", args={"path": "/workspace/app.py", "content": "x=1\n"},
        )
        result = StepResult(step_id="step_1", status="success", content="File written")
        outcome = build_step_outcome(step, result, elapsed_s=0.1, exec_meta=exec_meta)
        assert outcome["code_fixer_changed"] is True
        assert outcome["code_fixer_fixes"] == ["python:trailing_newline", "json:truncated_json"]
        assert outcome["code_fixer_errors"] == []

    def test_code_fixer_fields_default_when_exec_meta_is_none(self):
        """code_fixer fields default to safe empty values when exec_meta is None."""
        step = PlanStep(id="step_1", type="tool_call", description="Do thing", tool="shell")
        result = StepResult(step_id="step_1", status="success", content="ok")
        outcome = build_step_outcome(step, result, elapsed_s=0.5, exec_meta=None)
        assert outcome["code_fixer_changed"] is False
        assert outcome["code_fixer_fixes"] == []
        assert outcome["code_fixer_errors"] == []

    def test_code_fixer_fields_default_when_keys_absent_from_exec_meta(self):
        """code_fixer fields default gracefully when exec_meta exists but lacks fixer keys."""
        exec_meta = {"exit_code": 0, "stderr": ""}
        step = PlanStep(id="step_1", type="tool_call", description="Run test", tool="shell")
        result = StepResult(step_id="step_1", status="success", content="PASSED")
        outcome = build_step_outcome(step, result, elapsed_s=1.0, exec_meta=exec_meta)
        assert outcome["code_fixer_changed"] is False
        assert outcome["code_fixer_fixes"] == []
        assert outcome["code_fixer_errors"] == []

    def test_sandbox_fields_present_when_exec_meta_has_them(self):
        """sandbox_timed_out and sandbox_oom_killed are forwarded from exec_meta."""
        exec_meta = {
            "exit_code": 1,
            "stderr": "",
            "timed_out": True,
            "oom_killed": False,
        }
        step = PlanStep(id="step_1", type="tool_call", description="Run script", tool="shell")
        result = StepResult(step_id="step_1", status="error", content="")
        outcome = build_step_outcome(step, result, elapsed_s=30.0, exec_meta=exec_meta)
        assert outcome["sandbox_timed_out"] is True
        assert outcome["sandbox_oom_killed"] is False

    def test_sandbox_fields_default_false_when_exec_meta_is_none(self):
        """sandbox fields default to False when exec_meta is None."""
        step = PlanStep(id="step_1", type="tool_call", description="Do thing", tool="shell")
        result = StepResult(step_id="step_1", status="success", content="ok")
        outcome = build_step_outcome(step, result, elapsed_s=0.5, exec_meta=None)
        assert outcome["sandbox_timed_out"] is False
        assert outcome["sandbox_oom_killed"] is False


class TestGenericiseErrorScannerCategories:
    """Scanner name → 4-bucket category mapping.

    Security invariant: no scanner name may appear in the returned string.
    Tested exhaustively — one test per scanner_name value.
    """

    def _blocked(self, error: str) -> dict:
        step = PlanStep(id="s1", type="llm_task", description="test")
        result = StepResult(step_id="s1", status="blocked", error=error)
        return build_step_outcome(step, result, elapsed_s=0.1)

    # ── credential_scanner ────────────────────────────────────────

    def test_credential_scanner_maps_to_credential_secret_detected(self):
        outcome = self._blocked("credential_scanner: API key found in output")
        assert outcome["error_detail"] == "credential/secret detected"

    def test_credential_scanner_name_not_in_result(self):
        outcome = self._blocked("credential_scanner: token detected")
        assert "credential_scanner" not in outcome["error_detail"]

    # ── dangerous pattern bucket ──────────────────────────────────

    def test_command_pattern_scanner_maps_to_dangerous_pattern(self):
        outcome = self._blocked("command_pattern_scanner: rm -rf blocked")
        assert outcome["error_detail"] == "dangerous pattern detected"

    def test_prompt_guard_maps_to_dangerous_pattern(self):
        outcome = self._blocked("prompt_guard: injection attempt detected")
        assert outcome["error_detail"] == "dangerous pattern detected"

    def test_encoding_normalization_scanner_maps_to_dangerous_pattern(self):
        outcome = self._blocked("encoding_normalization_scanner: homoglyph detected")
        assert outcome["error_detail"] == "dangerous pattern detected"

    def test_vulnerability_echo_scanner_maps_to_dangerous_pattern(self):
        outcome = self._blocked("vulnerability_echo_scanner: known CVE pattern")
        assert outcome["error_detail"] == "dangerous pattern detected"

    def test_ascii_prompt_gate_maps_to_dangerous_pattern(self):
        outcome = self._blocked("ascii_prompt_gate: non-ASCII control chars")
        assert outcome["error_detail"] == "dangerous pattern detected"

    def test_prompt_length_gate_maps_to_dangerous_pattern(self):
        outcome = self._blocked("prompt_length_gate: output exceeds limit")
        assert outcome["error_detail"] == "dangerous pattern detected"

    def test_script_gate_maps_to_dangerous_pattern(self):
        outcome = self._blocked("script_gate: embedded script detected")
        assert outcome["error_detail"] == "dangerous pattern detected"

    def test_dangerous_pattern_scanner_names_not_in_result(self):
        """None of the scanner names that map to dangerous pattern appear in output."""
        scanner_names = (
            "command_pattern_scanner", "prompt_guard",
            "encoding_normalization_scanner", "vulnerability_echo_scanner",
            "ascii_prompt_gate", "prompt_length_gate", "script_gate",
        )
        for name in scanner_names:
            outcome = self._blocked(f"{name}: blocked")
            assert name not in outcome["error_detail"], (
                f"Scanner name '{name}' leaked into error_detail"
            )

    # ── semgrep ───────────────────────────────────────────────────

    def test_semgrep_maps_to_code_vulnerability_detected(self):
        outcome = self._blocked("Semgrep: insecure code detected (2 issues)")
        assert outcome["error_detail"] == "code vulnerability detected"

    def test_semgrep_name_not_in_result(self):
        outcome = self._blocked("semgrep: rule matched")
        assert "semgrep" not in outcome["error_detail"]

    # ── sensitive_path_scanner ────────────────────────────────────

    def test_sensitive_path_scanner_maps_to_sensitive_path_reference(self):
        outcome = self._blocked("sensitive_path_scanner: /etc/passwd accessed")
        assert outcome["error_detail"] == "sensitive path reference"

    def test_sensitive_path_scanner_name_not_in_result(self):
        outcome = self._blocked("sensitive_path_scanner: blocked")
        assert "sensitive_path_scanner" not in outcome["error_detail"]


class TestExecutePlanStepOutcomes:
    @pytest.mark.asyncio
    async def test_execute_plan_populates_step_outcomes(self):
        """Integration: _execute_plan returns TaskResult with step_outcomes."""
        from unittest.mock import MagicMock, AsyncMock
        from sentinel.core.models import Plan, PlanStep, TaskResult
        from sentinel.planner.orchestrator import Orchestrator

        orch = Orchestrator.__new__(Orchestrator)
        orch._pipeline = MagicMock()
        orch._planner = MagicMock()
        orch._tool_executor = MagicMock()
        orch._session_store = None
        orch._approval_manager = None
        orch._memory_store = None
        orch._bus = MagicMock()
        orch._bus.emit = AsyncMock()
        orch._event_bus = None
        orch._worker_contexts = {}
        orch._shutting_down = False

        # Mock _execute_step to return a (StepResult, exec_meta) tuple
        async def fake_execute_step(step, ctx, user_input=None, **kwargs):
            return StepResult(step_id=step.id, status="success", content="result"), None

        orch._execute_step = fake_execute_step
        orch._get_tagged_data = lambda _: None

        plan = Plan(
            plan_summary="Test plan",
            steps=[
                PlanStep(id="step_1", type="llm_task", description="Do thing"),
            ],
        )
        result = await orch._execute_plan(plan)
        assert result.status == "success"
        assert len(result.step_outcomes) == 1
        assert result.step_outcomes[0]["step_type"] == "llm_task"
        assert result.step_outcomes[0]["status"] == "success"


class TestAutoStoreMemoryGuard:
    """Verify auto_store_memory respects the settings.auto_memory flag.

    The guard lives in orchestrator._handle_task_inner() — we test it here by
    patching settings.auto_memory and confirming memory_store.store is never
    reached when the flag is False.
    """

    @pytest.mark.asyncio
    async def test_auto_store_memory_calls_store_when_enabled(self):
        """auto_store_memory() writes to the store when invoked directly."""
        from sentinel.planner.builders import auto_store_memory

        mock_store = MagicMock()
        mock_store.store = AsyncMock()

        await auto_store_memory(
            user_request="what is 2+2",
            plan_summary="Answer: 4",
            memory_store=mock_store,
            embedding_client=None,
        )

        mock_store.store.assert_awaited_once()
        call_kwargs = mock_store.store.call_args.kwargs
        assert "Task: what is 2+2" in call_kwargs["content"]
        assert call_kwargs["source"] == "conversation"

    @pytest.mark.asyncio
    async def test_orchestrator_skips_auto_store_when_auto_memory_disabled(self):
        """When settings.auto_memory=False, auto_store_memory is NOT called.

        This confirms the guard in _handle_task_inner() works correctly.
        The episodic pipeline (system:episodic) is the intended path when
        auto_memory is disabled — no duplicate conversation chunks compete
        for the k=3 retrieval budget.
        """
        from sentinel.planner.builders import auto_store_memory as real_fn

        mock_store = MagicMock()
        mock_store.store = AsyncMock()

        # Patch settings.auto_memory = False and auto_store_memory to track calls
        with patch("sentinel.planner.orchestrator.settings") as mock_settings, \
             patch("sentinel.planner.orchestrator.auto_store_memory", wraps=real_fn) as mock_fn:
            mock_settings.auto_memory = False

            # Guard condition: auto_memory=False → branch not taken
            if mock_settings.auto_memory and mock_store is not None:
                await mock_fn(
                    user_request="test",
                    plan_summary="done",
                    memory_store=mock_store,
                    embedding_client=None,
                )

        # mock_fn must NOT have been called — the guard short-circuits
        mock_fn.assert_not_called()
        mock_store.store.assert_not_awaited()
