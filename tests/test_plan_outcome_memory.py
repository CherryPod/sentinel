"""Plan-outcome memory: plan_json storage and retrieval."""

import json
import pytest

from sentinel.core.context import current_user_id
from sentinel.memory.episodic import EpisodicRecord, EpisodicStore


@pytest.fixture(autouse=True)
def _set_user_id():
    """All in-memory episodic tests run as user 1."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


SAMPLE_PLAN_JSON = {
    "phases": [
        {
            "phase": "initial",
            "trigger": None,
            "trigger_step": None,
            "plan": {
                "summary": "Read page, generate widget, patch",
                "steps": [
                    {"id": "step_1", "type": "tool_call", "tool": "file_read",
                     "args": {"path": "/workspace/index.html"}, "output_var": "$page"},
                    {"id": "step_2", "type": "llm_task", "description": "Generate widget",
                     "prompt": "Generate a clock widget using textContent",
                     "output_var": "$widget"},
                ],
            },
            "step_outcomes_summary": {
                "step_1": {"status": "success", "output_size": 2341},
                "step_2": {"status": "success", "output_size": 180},
            },
            "replan_context_summary": None,
        },
    ],
    "user_request_full": "Build a dashboard with a live clock",
}


class TestPlanJsonStorage:
    """plan_json round-trips through create/get on in-memory store."""

    def _make_store(self):
        return EpisodicStore(pool=None)

    async def test_create_with_plan_json(self):
        store = self._make_store()
        record_id = await store.create(
            session_id="s1",
            user_request="Build dashboard",
            task_status="success",
            plan_json=SAMPLE_PLAN_JSON,
        )
        record = await store.get(record_id)
        assert record is not None
        assert record.plan_json == SAMPLE_PLAN_JSON

    async def test_create_without_plan_json(self):
        """Backwards compat: plan_json defaults to None."""
        store = self._make_store()
        record_id = await store.create(
            session_id="s1",
            user_request="Old task",
            task_status="success",
        )
        record = await store.get(record_id)
        assert record is not None
        assert record.plan_json is None


from sentinel.planner.orchestrator import _categorise_error, _failure_fingerprint
from sentinel.core.models import PlanStep


class TestErrorCategorisation:
    """_categorise_error maps specific errors to generic categories."""

    def test_scanner_block(self):
        assert _categorise_error("blocked", scanner_result="blocked") == "scanner_block"

    def test_exit_nonzero(self):
        assert _categorise_error("exit 1: ImportError", exit_code=1) == "exit_nonzero"

    def test_timeout(self):
        assert _categorise_error("", sandbox_timed_out=True) == "timeout"

    def test_oom(self):
        assert _categorise_error("", sandbox_oom_killed=True) == "oom"

    def test_constraint_violation(self):
        assert _categorise_error("", constraint_result="violation") == "constraint_violation"

    def test_unknown_fallback(self):
        assert _categorise_error("some weird error") == "unknown"

    def test_scanner_takes_priority(self):
        """Scanner block is checked before exit code."""
        assert _categorise_error("exit 1", scanner_result="blocked", exit_code=1) == "scanner_block"


class TestFailureFingerprint:
    """_failure_fingerprint produces deterministic hashes for identical failures."""

    def test_same_inputs_same_hash(self):
        step = PlanStep(id="s1", type="tool_call", tool="file_patch",
                        args={"path": "/a.html", "anchor": "css:#main"})
        fp1 = _failure_fingerprint(step, "scanner_block")
        fp2 = _failure_fingerprint(step, "scanner_block")
        assert fp1 == fp2

    def test_different_error_different_hash(self):
        step = PlanStep(id="s1", type="tool_call", tool="file_patch",
                        args={"path": "/a.html", "anchor": "css:#main"})
        fp1 = _failure_fingerprint(step, "scanner_block")
        fp2 = _failure_fingerprint(step, "exit_nonzero")
        assert fp1 != fp2

    def test_different_tool_different_hash(self):
        step_a = PlanStep(id="s1", type="tool_call", tool="file_patch", args={"path": "/a"})
        step_b = PlanStep(id="s1", type="tool_call", tool="file_write", args={"path": "/a"})
        assert _failure_fingerprint(step_a, "scanner_block") != _failure_fingerprint(step_b, "scanner_block")

    def test_hash_is_12_chars(self):
        step = PlanStep(id="s1", type="tool_call", tool="shell", args={"cmd": "ls"})
        fp = _failure_fingerprint(step, "exit_nonzero")
        assert len(fp) == 12

    def test_llm_task_uses_type(self):
        """llm_task steps have no tool — fingerprint uses step type."""
        step = PlanStep(id="s1", type="llm_task", prompt="generate code")
        fp = _failure_fingerprint(step, "exit_nonzero")
        assert len(fp) == 12  # doesn't crash on tool=None


from sentinel.planner.orchestrator import _truncate_plan_prompts


class TestTruncatePlanPrompts:
    """_truncate_plan_prompts caps worker prompts in serialised plan dicts."""

    def test_truncates_long_prompt(self):
        plan_dict = {"steps": [{"id": "s1", "prompt": "x" * 500}]}
        result = _truncate_plan_prompts(plan_dict)
        assert len(result["steps"][0]["prompt"]) == 203  # 200 + "..."
        assert result["steps"][0]["prompt"].endswith("...")

    def test_leaves_short_prompt(self):
        plan_dict = {"steps": [{"id": "s1", "prompt": "short"}]}
        result = _truncate_plan_prompts(plan_dict)
        assert result["steps"][0]["prompt"] == "short"

    def test_handles_no_prompt(self):
        plan_dict = {"steps": [{"id": "s1", "type": "tool_call"}]}
        result = _truncate_plan_prompts(plan_dict)
        assert "prompt" not in result["steps"][0]

    def test_handles_empty_steps(self):
        plan_dict = {"steps": []}
        result = _truncate_plan_prompts(plan_dict)
        assert result["steps"] == []


from sentinel.planner.orchestrator import _build_replan_summary


class TestBuildReplanSummary:
    """_build_replan_summary builds condensed context from structured data."""

    def test_builds_from_structured_data(self):
        executed_steps = [
            PlanStep(id="step_1", type="tool_call", tool="file_read",
                     args={"path": "/workspace/index.html"}, output_var="$page"),
            PlanStep(id="step_2", type="llm_task", description="Generate widget",
                     output_var="$widget"),
        ]
        step_outcomes = [
            {"status": "success", "output_size": 2341, "file_path": "/workspace/index.html"},
            {"status": "success", "output_size": 180},
        ]
        result = _build_replan_summary(
            executed_steps=executed_steps,
            step_outcomes=step_outcomes,
        )
        assert "step_1" in result
        assert "success" in result
        assert "step_2" in result
        assert len(result) < 500

    def test_includes_error_diagnostic(self):
        executed_steps = [
            PlanStep(id="step_1", type="tool_call", tool="shell",
                     args={"cmd": "python script.py"}),
        ]
        step_outcomes = [
            {"status": "soft_failed", "exit_code": 1,
             "stderr_preview": "SyntaxError: unexpected token",
             "error_detail": "exit 1: SyntaxError: unexpected token"},
        ]
        result = _build_replan_summary(
            executed_steps=executed_steps,
            step_outcomes=step_outcomes,
            failure_trigger=True,
        )
        assert "SyntaxError" in result
        assert "step_1" in result

    def test_empty_inputs(self):
        assert _build_replan_summary([], []) == ""

    def test_truncates_with_many_steps(self):
        """Result should stay under 500 chars even with many steps."""
        steps = [
            PlanStep(id=f"step_{i}", type="tool_call", tool="file_read",
                     args={"path": f"/workspace/file_{i}.txt"}, output_var=f"$v{i}")
            for i in range(20)
        ]
        outcomes = [
            {"status": "success", "output_size": 100}
            for _ in range(20)
        ]
        result = _build_replan_summary(steps, outcomes)
        assert len(result) <= 500


from unittest.mock import AsyncMock, MagicMock, patch
from sentinel.core.models import Plan, StepResult
from sentinel.planner.orchestrator import Orchestrator


def _make_mock_orchestrator():
    """Create a minimal Orchestrator with mocked dependencies for plan capture testing."""
    orch = object.__new__(Orchestrator)
    orch._worker = AsyncMock()
    orch._planner = AsyncMock()
    orch._executor = AsyncMock()
    orch._scanner = AsyncMock()
    orch._episodic_store = None
    orch._memory_store = None
    orch._strategy_store = None
    orch._embedding_client = None
    orch._event_bus = None
    orch._worker_contexts = {}
    orch._worker_context_accessed = {}
    orch._shutting_down = False
    return orch


class TestPlanPhaseCapture:
    """_execute_plan accumulates plan_phases during execution."""

    async def test_simple_plan_captures_initial_phase(self):
        """A plan with no replans should produce one phase."""
        orch = _make_mock_orchestrator()

        plan = Plan(
            plan_summary="Test plan",
            steps=[
                PlanStep(id="step_1", type="tool_call", tool="file_read",
                         args={"path": "/workspace/test.txt"}),
            ],
        )

        # Mock _execute_step to return success
        mock_result = StepResult(
            step_id="step_1",
            status="success",
            content="file contents",
        )
        exec_meta = {"file_path": "/workspace/test.txt"}
        orch._execute_step = AsyncMock(return_value=(mock_result, exec_meta))
        orch._emit = AsyncMock()

        result = await orch._execute_plan(plan, user_input="read the file")

        assert result.status == "success"
        # plan_phases should be available on the result
        assert hasattr(result, "plan_phases")
        assert len(result.plan_phases) == 1
        assert result.plan_phases[0]["phase"] == "initial"
        assert "step_1" in result.plan_phases[0]["step_outcomes_summary"]
        assert result.plan_phases[0]["step_outcomes_summary"]["step_1"]["status"] == "success"


class TestPlanJsonStoragePipeline:
    """_store_episodic_record passes plan_phases through to episodic record."""

    async def test_plan_json_stored_in_record(self):
        store = EpisodicStore(pool=None)
        plan_phases = SAMPLE_PLAN_JSON["phases"]

        record_id = await store.create(
            session_id="s1",
            user_request="Build dashboard with live clock",
            task_status="success",
            step_count=2,
            success_count=2,
            plan_json={
                "phases": plan_phases,
                "user_request_full": "Build dashboard with live clock",
            },
        )
        record = await store.get(record_id)
        assert record is not None
        assert record.plan_json is not None
        assert record.plan_json["phases"][0]["phase"] == "initial"
        assert record.plan_json["user_request_full"] == "Build dashboard with live clock"

    async def test_user_request_2000_char_limit(self):
        """user_request should accept up to 2000 chars."""
        store = EpisodicStore(pool=None)
        long_request = "x" * 2000
        record_id = await store.create(
            session_id="s1",
            user_request=long_request,
            task_status="success",
        )
        record = await store.get(record_id)
        assert record is not None
        assert len(record.user_request) == 2000
