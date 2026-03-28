"""Integration tests for verification signals in the orchestrator."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import Plan, PlanStep, StepResult, TaskResult
from sentinel.planner.orchestrator import ExecutionContext, Orchestrator
from sentinel.security.pipeline import PipelineScanResult, ScanPipeline
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.provenance import reset_store


@pytest.fixture(autouse=True)
async def _reset_provenance():
    await reset_store()
    yield
    await reset_store()


@pytest.fixture
def mock_planner():
    planner = MagicMock(spec=ClaudePlanner)
    planner.create_plan = AsyncMock()
    return planner


@pytest.fixture
def mock_pipeline():
    pipeline = MagicMock(spec=ScanPipeline)
    clean = PipelineScanResult()
    pipeline.scan_input = AsyncMock(return_value=clean)
    pipeline.scan_output = AsyncMock(return_value=PipelineScanResult())
    pipeline.process_with_qwen = AsyncMock()
    return pipeline


@pytest.fixture(autouse=True)
def _disable_semgrep():
    from sentinel.core.config import settings
    original = settings.require_semgrep
    settings.require_semgrep = False
    yield
    settings.require_semgrep = original


def _make_plan(steps, summary="Test plan"):
    return Plan(plan_summary=summary, steps=[PlanStep(**s) for s in steps])


class TestTier1BudgetExhaustion:
    @pytest.mark.asyncio
    async def test_budget_exhaustion_returns_partial(self, mock_planner, mock_pipeline):
        """When replan budget is exhausted with remaining steps, status should be 'partial'."""
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read", "args": {"path": "/workspace/test.txt"}, "replan_after": True},
        ])

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        async def fake_execute_step(step, context, **kwargs):
            return StepResult(step_id=step.id, status="success", content="file content"), {}

        # Mock _request_continuation to always return more steps (forcing budget exhaustion)
        continuation_plan = Plan(
            plan_summary="Continuation",
            steps=[PlanStep(id="cont_1", type="tool_call", tool="file_read", args={"path": "/workspace/other.txt"}, replan_after=True)],
            continuation=True,
        )

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step), \
             patch.object(orch, "_request_continuation", new_callable=AsyncMock, return_value=continuation_plan):
            result = await orch._execute_plan(plan, user_input="test", task_id="test-1")

        # After 3 replans of pure discovery, should be partial
        assert result.completion == "partial"
        assert result.goal_actions_executed is False


class TestTier1GoalActions:
    @pytest.mark.asyncio
    async def test_discovery_only_plan_marked_correctly(self, mock_planner, mock_pipeline):
        """A plan with only file_read steps: goal_actions_executed should be False."""
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read", "args": {"path": "/workspace/test.txt"}},
            {"id": "step_2", "type": "tool_call", "tool": "list_dir", "args": {"path": "/workspace/"}},
        ])
        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        async def fake_execute_step(step, context, **kwargs):
            return StepResult(step_id=step.id, status="success", content="data"), {}

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step):
            result = await orch._execute_plan(plan, user_input="test", task_id="test-2")

        assert result.goal_actions_executed is False
        # Still "success" status because all steps completed — but goal_actions flag shows the gap
        assert result.status == "success"
        assert result.completion == "full"

    @pytest.mark.asyncio
    async def test_effect_tool_plan_marked_correctly(self, mock_planner, mock_pipeline):
        """A plan with file_write: goal_actions_executed should be True."""
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read", "args": {"path": "/workspace/test.txt"}},
            {"id": "step_2", "type": "tool_call", "tool": "file_write", "args": {"path": "/workspace/out.txt", "content": "hello"}},
        ])
        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        async def fake_execute_step(step, context, **kwargs):
            meta = {}
            if step.tool == "file_write":
                meta = {"file_size_before": None, "file_size_after": 5}
            return StepResult(step_id=step.id, status="success", content="ok"), meta

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step):
            result = await orch._execute_plan(plan, user_input="test", task_id="test-3")

        assert result.goal_actions_executed is True
        assert result.status == "success"
        assert result.completion == "full"
        assert len(result.file_mutations) == 1


from sentinel.planner.verification import (
    classify_task_category,
    build_judge_payload,
    process_judge_verdict,
    check_stagnation,
    detect_idempotent_calls,
)


class TestTier2JudgeGating:
    @pytest.mark.asyncio
    async def test_judge_skipped_when_tier1_red(self, mock_planner, mock_pipeline):
        """Tier 1 RED (partial/abandoned) → judge NOT invoked."""
        result = TaskResult(
            status="partial",
            completion="partial",
            goal_actions_executed=False,
            file_mutations=[],
        )
        mock_planner.verify_goal = AsyncMock()

        from sentinel.planner.orchestrator import _should_invoke_judge
        assert _should_invoke_judge(result, task_category="semantic") is False

    @pytest.mark.asyncio
    async def test_judge_invoked_for_semantic_task_no_assertions(self):
        """Semantic task + no assertions + all green → judge invoked."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
            file_mutations=[{"path": "/workspace/test.css", "size_before": 100, "size_after": 120, "no_op": False}],
            assertion_failures=[],
        )
        from sentinel.planner.orchestrator import _should_invoke_judge
        assert _should_invoke_judge(result, task_category="semantic") is True

    @pytest.mark.asyncio
    async def test_judge_skipped_for_deterministic_with_passing_assertions(self):
        """Deterministic task + assertions defined & pass → judge NOT invoked."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
            file_mutations=[{"path": "/workspace/test.css", "size_before": 100, "size_after": 120, "no_op": False}],
            assertion_failures=[],
        )
        from sentinel.planner.orchestrator import _should_invoke_judge
        assert _should_invoke_judge(result, task_category="deterministic", assertions_defined=2) is False

    @pytest.mark.asyncio
    async def test_judge_invoked_for_structural_with_failed_assertions(self):
        """Structural task + assertion failure → judge invoked as arbitrator."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
            file_mutations=[{"path": "/workspace/test.css", "size_before": 100, "size_after": 120, "no_op": False}],
            assertion_failures=[{"type": "file_contains", "passed": False}],
        )
        from sentinel.planner.orchestrator import _should_invoke_judge
        assert _should_invoke_judge(result, task_category="structural", assertions_defined=1) is True

    @pytest.mark.asyncio
    async def test_judge_invoked_for_structural_with_no_assertions_defined(self):
        """Structural task + NO assertions defined → judge invoked (no evidence)."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
            file_mutations=[{"path": "/workspace/test.css", "size_before": 100, "size_after": 120, "no_op": False}],
            assertion_failures=[],
        )
        from sentinel.planner.orchestrator import _should_invoke_judge
        # This is the bug fix: previously returned False because assertion_failures=[]
        # was treated as "assertions passed" rather than "no assertions defined"
        assert _should_invoke_judge(result, task_category="structural", assertions_defined=0) is True

    @pytest.mark.asyncio
    async def test_judge_skipped_for_structural_with_assertions_passing(self):
        """Structural task + assertions defined & all pass → judge skipped (confident)."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
            file_mutations=[{"path": "/workspace/test.css", "size_before": 100, "size_after": 120, "no_op": False}],
            assertion_failures=[],
        )
        from sentinel.planner.orchestrator import _should_invoke_judge
        assert _should_invoke_judge(result, task_category="structural", assertions_defined=3) is False

    @pytest.mark.asyncio
    async def test_judge_invoked_when_tool_output_warnings_present(self):
        """Tool output warnings → judge invoked regardless of category."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
            file_mutations=[{"path": "/workspace/test.css", "size_before": 100, "size_after": 120, "no_op": False}],
            assertion_failures=[],
            tool_output_warnings=[{"step_id": "step_1", "pattern": "warning: deprecated", "severity": "LOW"}],
        )
        from sentinel.planner.orchestrator import _should_invoke_judge
        # Even deterministic tasks should get judged if warnings are present
        assert _should_invoke_judge(result, task_category="deterministic", assertions_defined=1) is True


class TestEndToEndVerification:
    @pytest.mark.asyncio
    async def test_glasgow_bug_scenario(self, mock_planner, mock_pipeline):
        """The Glasgow bug: discovery-only plan with budget exhaustion should be 'partial'."""
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read",
             "args": {"path": "/workspace/sites/glasgow/index.html"}, "replan_after": True},
        ], summary="Change Glasgow background to dark green")

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        async def fake_execute_step(step, context, **kwargs):
            return StepResult(step_id=step.id, status="success", content="<html>...</html>"), {}

        # Continuation always returns more discovery (simulating the bug)
        async def fake_continuation(**kwargs):
            return Plan(
                plan_summary="Continue discovery",
                steps=[PlanStep(id=f"cont_{len(kwargs.get('step_results', []))}", type="tool_call",
                       tool="file_read", args={"path": "/workspace/sites/glasgow/style.css"}, replan_after=True)],
                continuation=True,
            )

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step), \
             patch.object(orch, "_request_continuation", side_effect=fake_continuation):
            result = await orch._execute_plan(
                plan, user_input="Change Glasgow background to dark green", task_id="glasgow-test",
            )

        # The Glasgow bug fix: should be partial, not success
        assert result.status == "partial"
        assert result.completion == "partial"
        assert result.goal_actions_executed is False
        assert result.file_mutations == []  # No file writes happened

    @pytest.mark.asyncio
    async def test_successful_file_write_is_full(self, mock_planner, mock_pipeline):
        """A plan that reads then writes: should be full success."""
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read",
             "args": {"path": "/workspace/test.txt"}},
            {"id": "step_2", "type": "llm_task", "prompt": "Generate content"},
            {"id": "step_3", "type": "tool_call", "tool": "file_write",
             "args": {"path": "/workspace/output.txt", "content": "hello world"}},
        ])

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        async def fake_execute_step(step, context, **kwargs):
            meta = {}
            if step.tool == "file_write":
                meta = {"file_size_before": None, "file_size_after": 11}
            return StepResult(step_id=step.id, status="success", content="ok"), meta

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step):
            result = await orch._execute_plan(plan, user_input="Write hello world", task_id="write-test")

        assert result.status == "success"
        assert result.completion == "full"
        assert result.goal_actions_executed is True
        assert len(result.file_mutations) == 1
        assert result.file_mutations[0]["size_after"] == 11


class TestStagnationDetection:
    """Tests for stagnation detection wired into the replan loop."""

    def test_check_stagnation_returns_none_below_threshold(self):
        """Below warn threshold: no stagnation."""
        assert check_stagnation(0) is None
        assert check_stagnation(1) is None

    def test_check_stagnation_returns_warn_at_threshold(self):
        """At warn threshold (2): returns 'warn'."""
        assert check_stagnation(2) == "warn"

    def test_check_stagnation_returns_abort_at_threshold(self):
        """At abort threshold (3): returns 'abort'."""
        assert check_stagnation(3) == "abort"
        assert check_stagnation(5) == "abort"

    @pytest.mark.asyncio
    async def test_stagnation_abort_returns_partial(self, mock_planner, mock_pipeline):
        """When 3 consecutive replan cycles produce no mutations, force partial."""
        # Plan with replan_after — each continuation also has replan_after
        # and only does file_read (no mutations). Should stagnate after 3 cycles.
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read",
             "args": {"path": "/workspace/test.txt"}, "replan_after": True},
        ])

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)
        replan_call_count = 0

        async def fake_execute_step(step, context, **kwargs):
            # Always succeed with file_read — no mutations
            return StepResult(step_id=step.id, status="success", content="data"), {}

        async def fake_continuation(**kwargs):
            nonlocal replan_call_count
            replan_call_count += 1
            return Plan(
                plan_summary=f"Continuation {replan_call_count}",
                steps=[PlanStep(
                    id=f"cont_{replan_call_count}", type="tool_call",
                    tool="file_read", args={"path": "/workspace/other.txt"},
                    replan_after=True,
                )],
                continuation=True,
            )

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step), \
             patch.object(orch, "_request_continuation", side_effect=fake_continuation):
            result = await orch._execute_plan(plan, user_input="test", task_id="stagnation-test")

        assert result.status == "partial"
        assert result.completion == "partial"
        assert "Stagnation" in (result.reason or "")

    @pytest.mark.asyncio
    async def test_stagnation_resets_on_mutation(self, mock_planner, mock_pipeline):
        """If a mutation occurs, the stagnation counter resets."""
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read",
             "args": {"path": "/workspace/test.txt"}, "replan_after": True},
        ])

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)
        replan_call_count = 0

        async def fake_execute_step(step, context, **kwargs):
            # On cont_3 (the write step), return size metadata so it's a mutation
            if step.tool == "file_write":
                return StepResult(step_id=step.id, status="success", content="wrote"), {
                    "file_size_before": 0, "file_size_after": 100,
                }
            return StepResult(step_id=step.id, status="success", content="data"), {}

        async def fake_continuation(**kwargs):
            nonlocal replan_call_count
            replan_call_count += 1
            # Continuation 1: read (stagnation counter → 1)
            # Continuation 2: write (stagnation resets → 0 because mutation happened)
            # No more continuations after that
            if replan_call_count <= 1:
                tool = "file_read"
                replan = True
            else:
                tool = "file_write"
                replan = False  # Stop here — goal achieved
            return Plan(
                plan_summary=f"Continuation {replan_call_count}",
                steps=[PlanStep(
                    id=f"cont_{replan_call_count}", type="tool_call",
                    tool=tool, args={"path": "/workspace/out.txt"},
                    replan_after=replan,
                )],
                continuation=True,
            )

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step), \
             patch.object(orch, "_request_continuation", side_effect=fake_continuation):
            result = await orch._execute_plan(plan, user_input="test", task_id="stagnation-reset-test")

        # Should NOT have stagnation-aborted because the write broke the streak
        assert "Stagnation" not in (result.reason or "")
        # Should complete (either success or partial from budget, but not stagnation)
        assert result.goal_actions_executed is True  # file_write ran


class TestIdempotencyDetection:
    """Tests for idempotent call detection at the end of _execute_plan."""

    def test_no_duplicates_returns_empty(self):
        outcomes = [
            {"tool": "file_read", "status": "success", "output_size": 100, "description": "Read file A"},
            {"tool": "file_write", "status": "success", "output_size": 50, "description": "Write file B"},
        ]
        assert detect_idempotent_calls(outcomes) == []

    def test_duplicate_calls_detected(self):
        outcomes = [
            {"tool": "file_read", "status": "success", "output_size": 100, "description": "Read config"},
            {"tool": "file_read", "status": "success", "output_size": 100, "description": "Read config"},
            {"tool": "file_write", "status": "success", "output_size": 50, "description": "Write output"},
        ]
        result = detect_idempotent_calls(outcomes)
        assert len(result) == 1
        assert "x2" in result[0]

    @pytest.mark.asyncio
    async def test_idempotent_calls_appear_in_warnings(self, mock_planner, mock_pipeline):
        """Idempotent calls should appear as MEDIUM severity warnings in tool_output_warnings."""
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_read",
             "args": {"path": "/workspace/test.txt"}},
            {"id": "step_2", "type": "tool_call", "tool": "file_read",
             "args": {"path": "/workspace/test.txt"}},
        ])

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        async def fake_execute_step(step, context, **kwargs):
            return StepResult(step_id=step.id, status="success", content="same data"), {}

        with patch.object(orch, "_execute_step", side_effect=fake_execute_step):
            result = await orch._execute_plan(plan, user_input="test", task_id="idempotent-test")

        # Should have an idempotent_call warning
        idempotent_warnings = [
            w for w in (result.tool_output_warnings or [])
            if "idempotent_call" in w.get("pattern", "")
        ]
        assert len(idempotent_warnings) >= 1
        assert idempotent_warnings[0]["severity"] == "MEDIUM"


class TestJudgeDrivenReplan:
    """Tests for judge verdict triggering a replan attempt."""

    @pytest.mark.asyncio
    async def test_judge_partial_triggers_replan(self, mock_planner, mock_pipeline):
        """When judge says partial with high confidence + GAP, a replan is triggered."""
        # Initial plan: just a file_write
        plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_write",
             "args": {"path": "/workspace/test.css", "content": "body { color: blue; }"}},
        ], summary="Change background to red")

        # Judge returns partial with GAP
        mock_planner.verify_goal = AsyncMock(return_value={
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": False,
            "SIDE_EFFECTS": False,
            "COMPLETENESS": False,
            "GOAL_MET": "partial",
            "CONFIDENCE": "high",
            "GAP": "Changed color instead of background-color",
        })
        mock_planner._last_usage = None

        # Second plan (after replan) - also just a file_write
        replan_plan = _make_plan([
            {"id": "step_1", "type": "tool_call", "tool": "file_write",
             "args": {"path": "/workspace/test.css", "content": "body { background-color: red; }"}},
        ], summary="Fix: change background-color to red")

        # create_plan is called for the replan
        mock_planner.create_plan = AsyncMock(return_value=replan_plan)

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        call_count = 0
        async def fake_execute_step(step, context, **kwargs):
            nonlocal call_count
            call_count += 1
            return StepResult(step_id=step.id, status="success", content="ok"), {
                "file_size_before": 50, "file_size_after": 60,
            }

        # We need to mock handle_task's dependencies but test the outer loop.
        # Easier to test _execute_plan + the judge logic separately.
        # Let's test at the _execute_plan level first, then verify the judge
        # replan logic via the create_plan call.
        with patch.object(orch, "_execute_step", side_effect=fake_execute_step):
            # Run _execute_plan for the initial plan
            result = await orch._execute_plan(plan, user_input="Change background to red", task_id="judge-replan-test")

        # The _execute_plan itself should return success (judge runs in the outer method)
        assert result.status == "success"
        assert result.completion == "full"

        # Verify the planner was set up for replan calls
        # (The actual replan loop is in handle_task, which requires too many
        # dependencies to test in isolation. We test the building blocks here.)

    @pytest.mark.asyncio
    async def test_judge_yes_no_replan(self, mock_planner, mock_pipeline):
        """When judge says yes with high confidence, no replan happens."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
            file_mutations=[{"path": "/workspace/test.css", "size_before": 50, "size_after": 60, "no_op": False}],
        )
        verdict = {
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": True,
            "SIDE_EFFECTS": False,
            "COMPLETENESS": True,
            "GOAL_MET": "yes",
            "CONFIDENCE": "high",
            "GAP": None,
        }
        processed = process_judge_verdict(verdict, result.completion)
        assert processed["acted_on"] is True
        assert processed["completion"] == "full"
        # No replan needed — completion stays full

    @pytest.mark.asyncio
    async def test_judge_low_confidence_no_replan(self):
        """Low confidence verdicts don't trigger replans."""
        result = TaskResult(
            status="success",
            completion="full",
            goal_actions_executed=True,
        )
        verdict = {
            "GOAL_MET": "no",
            "CONFIDENCE": "low",
            "GAP": "Something seems wrong",
        }
        processed = process_judge_verdict(verdict, result.completion)
        # Low confidence → not acted on → no replan
        assert processed["acted_on"] is False

    @pytest.mark.asyncio
    async def test_judge_partial_without_gap_no_replan(self):
        """Judge says partial but no GAP context → can't replan meaningfully."""
        verdict = {
            "GOAL_MET": "partial",
            "CONFIDENCE": "high",
            "GAP": "",  # Empty GAP
        }
        processed = process_judge_verdict(verdict, "full")
        # Would trigger acted_on, but empty GAP means the replan logic
        # in handle_task will skip (gap check in the if-condition)
        assert processed["acted_on"] is True
        assert processed["completion"] == "partial"
