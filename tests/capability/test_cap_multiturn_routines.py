"""C3 capability tests — Multi-Turn Routine Execution.

Verifies the 7 deployment-gate behaviours: iteration to completion,
max_iterations enforcement, per-iteration timeout, context carry-forward,
approval per iteration, error stops chain, and cumulative risk escalation.

All tests mock the orchestrator (no real Claude/Qwen calls) and use
in-memory SQLite.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from sentinel.core.bus import EventBus
from sentinel.core.db import init_db
from sentinel.core.models import TaskResult
from sentinel.routines.engine import RoutineEngine, _now_iso
from sentinel.routines.store import RoutineStore

pytestmark = pytest.mark.capability


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def store(db):
    return RoutineStore(db=db)


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def mock_orchestrator():
    orch = AsyncMock()
    orch.handle_task = AsyncMock(return_value=TaskResult(
        status="success",
        plan_summary="Iteration completed",
        task_id="test-task-id",
    ))
    return orch


@pytest.fixture
def engine(store, mock_orchestrator, bus, db):
    return RoutineEngine(
        store=store,
        orchestrator=mock_orchestrator,
        event_bus=bus,
        db=db,
        tick_interval=1,
        max_concurrent=3,
        execution_timeout=10,
    )


# ── Tests ────────────────────────────────────────────────────────


class TestMultiturnIteratesToCompletion:
    """multiturn_iterates_to_completion — routine iterates until [DONE] signal."""

    async def test_done_signal_stops_iteration(self, engine, store, mock_orchestrator, db):
        iteration_count = 0

        async def _iterate(**kwargs):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 3:
                return TaskResult(
                    status="success",
                    plan_summary="All work finished. [DONE]",
                    task_id=f"task-{iteration_count}",
                )
            return TaskResult(
                status="success",
                plan_summary=f"Iteration {iteration_count} result",
                task_id=f"task-{iteration_count}",
            )

        mock_orchestrator.handle_task = AsyncMock(side_effect=_iterate)

        store.create(
            name="Multi-turn test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Analyze data iteratively",
                "max_iterations": 5,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.5)

        # Should have called 3 times (done on 3rd), not 5
        assert mock_orchestrator.handle_task.call_count == 3

        # Verify execution recorded as complete
        rows = db.execute(
            "SELECT status, result_summary FROM routine_executions"
        ).fetchall()
        assert len(rows) >= 1
        assert rows[0][0] == "complete"
        assert "[DONE]" in rows[0][1]


class TestMultiturnRespectsMaxIterations:
    """multiturn_respects_max_iterations — stops at max even without done signal."""

    async def test_stops_at_max_iterations(self, engine, store, mock_orchestrator, db):
        mock_orchestrator.handle_task = AsyncMock(return_value=TaskResult(
            status="success",
            plan_summary="Still working...",
            task_id="ongoing",
        ))

        store.create(
            name="Max iterations test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Process data",
                "max_iterations": 3,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.5)

        assert mock_orchestrator.handle_task.call_count == 3

        # Verify execution recorded with final result status
        rows = db.execute(
            "SELECT status FROM routine_executions"
        ).fetchall()
        assert len(rows) >= 1
        assert rows[0][0] == "success"


class TestMultiturnPerIterationTimeout:
    """multiturn_per_iteration_timeout — timeout on individual iteration."""

    async def test_per_iteration_timeout(self, store, bus, db):
        call_count = 0

        async def _slow(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                await asyncio.sleep(9999)  # hang on second iteration
            return TaskResult(status="success", plan_summary="fast", task_id="x")

        orch = AsyncMock()
        orch.handle_task = AsyncMock(side_effect=_slow)

        eng = RoutineEngine(
            store=store, orchestrator=orch, event_bus=bus,
            db=db, tick_interval=1, max_concurrent=3, execution_timeout=30,
        )

        store.create(
            name="Timeout test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Process slowly",
                "max_iterations": 5,
                "per_iteration_timeout": 1,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(2.5)

        # First iteration succeeds, second times out — stops chain
        assert orch.handle_task.call_count == 2

        rows = db.execute(
            "SELECT status, error FROM routine_executions"
        ).fetchall()
        assert len(rows) >= 1
        assert rows[0][0] == "timeout"
        assert "Iteration 2" in rows[0][1]


class TestMultiturnContextCarriesForward:
    """multiturn_context_carries_forward — previous result appears in next prompt."""

    async def test_context_in_subsequent_prompts(self, engine, store, mock_orchestrator):
        iteration_count = 0

        async def _track_context(**kwargs):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 3:
                return TaskResult(
                    status="success",
                    plan_summary="Final result [DONE]",
                    task_id="done",
                )
            return TaskResult(
                status="success",
                plan_summary=f"Result from iteration {iteration_count}",
                task_id=f"task-{iteration_count}",
            )

        mock_orchestrator.handle_task = AsyncMock(side_effect=_track_context)

        store.create(
            name="Context test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Analyze step by step",
                "max_iterations": 5,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.5)

        # Check that iteration 2's prompt contains iteration 1's result
        calls = mock_orchestrator.handle_task.call_args_list
        assert len(calls) == 3

        # First call: just the base prompt
        first_prompt = calls[0].kwargs.get("user_request", calls[0][1].get("user_request", ""))
        assert "Analyze step by step" in first_prompt
        assert "Previous iteration" not in first_prompt

        # Second call: base prompt + iteration 1 result
        second_prompt = calls[1].kwargs.get("user_request", calls[1][1].get("user_request", ""))
        assert "Analyze step by step" in second_prompt
        assert "Result from iteration 1" in second_prompt

        # Third call: base prompt + iteration 2 result
        third_prompt = calls[2].kwargs.get("user_request", calls[2][1].get("user_request", ""))
        assert "Result from iteration 2" in third_prompt


class TestMultiturnApprovalPerIteration:
    """multiturn_approval_per_iteration — approval_mode passed to each iteration."""

    async def test_approval_mode_passed_each_iteration(self, engine, store, mock_orchestrator):
        iteration_count = 0

        async def _with_approval(**kwargs):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 2:
                return TaskResult(
                    status="success",
                    plan_summary="Done [DONE]",
                    task_id="final",
                )
            return TaskResult(
                status="success",
                plan_summary="Continuing",
                task_id=f"task-{iteration_count}",
            )

        mock_orchestrator.handle_task = AsyncMock(side_effect=_with_approval)

        store.create(
            name="Approval test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Do something requiring approval",
                "approval_mode": "full",
                "max_iterations": 3,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.5)

        # Verify approval_mode was passed to every call
        for c in mock_orchestrator.handle_task.call_args_list:
            assert c.kwargs.get("approval_mode") == "full"


class TestMultiturnErrorStopsChain:
    """multiturn_error_stops_chain — error on any iteration stops the chain."""

    async def test_error_breaks_iteration(self, store, bus, db):
        call_count = 0

        async def _fail_on_second(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("iteration 2 exploded")
            return TaskResult(
                status="success",
                plan_summary=f"Iteration {call_count}",
                task_id=f"task-{call_count}",
            )

        orch = AsyncMock()
        orch.handle_task = AsyncMock(side_effect=_fail_on_second)

        eng = RoutineEngine(
            store=store, orchestrator=orch, event_bus=bus,
            db=db, tick_interval=1, max_concurrent=3, execution_timeout=10,
        )

        store.create(
            name="Error chain test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Multi-step work",
                "max_iterations": 5,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.5)

        # Should stop after iteration 2 error
        assert orch.handle_task.call_count == 2

        rows = db.execute(
            "SELECT status, error FROM routine_executions"
        ).fetchall()
        assert len(rows) >= 1
        assert rows[0][0] == "error"
        assert "iteration 2" in rows[0][1].lower()

    async def test_blocked_status_stops_chain(self, store, bus, db):
        """A 'blocked' result also terminates the iteration loop."""
        call_count = 0

        async def _block_on_second(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return TaskResult(
                    status="blocked",
                    plan_summary="Security violation detected",
                    task_id=f"task-{call_count}",
                )
            return TaskResult(
                status="success",
                plan_summary=f"Iteration {call_count}",
                task_id=f"task-{call_count}",
            )

        orch = AsyncMock()
        orch.handle_task = AsyncMock(side_effect=_block_on_second)

        eng = RoutineEngine(
            store=store, orchestrator=orch, event_bus=bus,
            db=db, tick_interval=1, max_concurrent=3, execution_timeout=10,
        )

        store.create(
            name="Blocked chain test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Multi-step work",
                "max_iterations": 5,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.5)

        assert orch.handle_task.call_count == 2

        rows = db.execute(
            "SELECT status FROM routine_executions"
        ).fetchall()
        assert rows[0][0] == "blocked"


class TestMultiturnCumulativeRiskEscalation:
    """multiturn_cumulative_risk_escalation — risk carries across iterations via source_key."""

    async def test_source_key_consistent_across_iterations(self, engine, store, mock_orchestrator):
        iteration_count = 0

        async def _iterate(**kwargs):
            nonlocal iteration_count
            iteration_count += 1
            if iteration_count >= 3:
                return TaskResult(
                    status="success",
                    plan_summary="All done [DONE]",
                    task_id="final",
                )
            return TaskResult(
                status="success",
                plan_summary=f"Step {iteration_count}",
                task_id=f"task-{iteration_count}",
            )

        mock_orchestrator.handle_task = AsyncMock(side_effect=_iterate)

        r = store.create(
            name="Risk test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={
                "prompt": "Do risky stuff",
                "max_iterations": 5,
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.5)

        # All iterations should use the same source_key (for session binding)
        calls = mock_orchestrator.handle_task.call_args_list
        source_keys = [c.kwargs.get("source_key") for c in calls]

        # All source_keys should be identical
        assert len(set(source_keys)) == 1
        assert source_keys[0] == f"routine:{r.user_id}"


class TestMultiturnBackwardCompatibility:
    """Single-iteration routines (no max_iterations) work exactly as before."""

    async def test_single_iteration_unchanged(self, engine, store, mock_orchestrator, db):
        """A routine with no max_iterations follows the single-iteration fast path."""
        mock_orchestrator.handle_task = AsyncMock(return_value=TaskResult(
            status="success",
            plan_summary="Done in one shot",
            task_id="single",
        ))

        store.create(
            name="Single turn",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "Simple task"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.3)

        assert mock_orchestrator.handle_task.call_count == 1

        rows = db.execute(
            "SELECT status FROM routine_executions"
        ).fetchall()
        assert rows[0][0] == "success"
