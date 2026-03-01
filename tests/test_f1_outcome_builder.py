"""Tests for _build_step_outcome on Orchestrator."""

import pytest
from unittest.mock import MagicMock, AsyncMock

from sentinel.core.models import PlanStep, StepResult


def _make_orchestrator():
    """Minimal Orchestrator with mocked deps."""
    from sentinel.planner.orchestrator import Orchestrator
    orch = Orchestrator.__new__(Orchestrator)
    orch._pipeline = MagicMock()
    orch._planner = MagicMock()
    orch._tool_executor = MagicMock()
    orch._tool_executor._last_exec_meta = None
    orch._session_store = None
    orch._approval_manager = None
    orch._memory_store = None
    orch._bus = MagicMock()
    orch._bus.emit = AsyncMock()
    orch._event_bus = None
    orch._worker_contexts = {}
    orch._current_session_id = None
    return orch


class TestBuildStepOutcome:
    def test_llm_task_success_basic_fields(self):
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Write hello.py")
        result = StepResult(
            step_id="step_1", status="success", content="print('hello')",
            worker_usage={"eval_count": 500},
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=1.5)
        assert outcome["step_type"] == "llm_task"
        assert outcome["status"] == "success"
        assert outcome["duration_s"] == 1.5
        assert outcome["output_size"] == len("print('hello')")
        assert outcome["error_detail"] is None

    def test_llm_task_blocked_has_genericised_error_detail(self):
        """error_detail is genericised — no scanner names leak to planner."""
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Write malware")
        result = StepResult(
            step_id="step_1", status="blocked",
            error="Semgrep: insecure code detected (2 issues)",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.3)
        assert outcome["status"] == "blocked"
        assert outcome["error_detail"] == "scan blocked"
        assert "Semgrep" not in outcome["error_detail"]

    def test_tool_call_with_exec_meta(self):
        orch = _make_orchestrator()
        orch._tool_executor._last_exec_meta = {
            "exit_code": 0, "stderr": "",
        }
        step = PlanStep(id="step_1", type="tool_call", description="Run test", tool="shell")
        result = StepResult(step_id="step_1", status="success", content="PASSED")
        outcome = orch._build_step_outcome(step, result, elapsed_s=2.0)
        assert outcome["exit_code"] == 0
        assert outcome["stderr_preview"] == ""

    def test_tool_call_file_write_meta(self):
        orch = _make_orchestrator()
        orch._tool_executor._last_exec_meta = {
            "file_size_before": 100,
            "file_size_after": 250,
            "file_content_before": "old content",
        }
        step = PlanStep(
            id="step_1", type="tool_call", description="Write file",
            tool="file_write", args={"path": "/workspace/app.py", "content": "new"},
        )
        result = StepResult(step_id="step_1", status="success", content="File written: /workspace/app.py")
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.1)
        assert outcome["file_path"] == "/workspace/app.py"
        assert outcome["file_size_before"] == 100
        assert outcome["file_size_after"] == 250
        assert "diff_stats" in outcome

    def test_token_usage_ratio_included(self):
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Generate code")
        result = StepResult(
            step_id="step_1", status="success", content="code",
            worker_usage={"eval_count": 4096},
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=1.0)
        assert outcome["token_usage_ratio"] == 0.5

    def test_no_executor_meta_when_tool_executor_is_none(self):
        orch = _make_orchestrator()
        orch._tool_executor = None
        step = PlanStep(id="step_1", type="tool_call", description="Do thing", tool="shell")
        result = StepResult(step_id="step_1", status="skipped")
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.0)
        assert outcome["exit_code"] is None


class TestExecutePlanStepOutcomes:
    @pytest.mark.asyncio
    async def test_execute_plan_populates_step_outcomes(self):
        """Integration: _execute_plan returns TaskResult with step_outcomes."""
        from sentinel.core.models import Plan, PlanStep, TaskResult
        from sentinel.planner.orchestrator import Orchestrator

        orch = _make_orchestrator()

        # Mock _execute_step to return a simple success
        async def fake_execute_step(step, ctx, user_input=None, **kwargs):
            return StepResult(step_id=step.id, status="success", content="result")

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
