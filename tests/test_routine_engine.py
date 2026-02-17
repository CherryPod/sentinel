"""Tests for RoutineEngine — scheduler loop, triggers, execution.

Verifies:
- Scheduler loop finds and executes due routines
- Cron trigger calculates next_run correctly
- Event trigger fires on matching bus topics
- Manual trigger via API
- Cooldown prevents re-execution within window
- Max concurrent limit respected
- Execution timeout kills hung routines
- Execution history recorded in routine_executions
- Event bus emits routine.triggered and routine.executed
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.bus import EventBus
from sentinel.core.db import init_db
from sentinel.core.models import Plan, PlanStep, TaskResult
from sentinel.routines.engine import RoutineEngine, _now_iso
from sentinel.routines.store import RoutineStore


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
        plan_summary="Test completed",
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
        tick_interval=1,  # fast ticks for tests
        max_concurrent=3,
        execution_timeout=5,
    )


# ── Scheduler loop ────────────────────────────────────────────────


class TestSchedulerLoop:
    async def test_check_due_routines_executes(self, engine, store, mock_orchestrator):
        """Due routines get executed by the scheduler."""
        store.create(
            name="Due routine",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Run health check"},
            next_run_at="2020-01-01T00:00:00.000Z",  # long past
        )

        await engine._check_due_routines()

        # Give the spawned task time to run
        await asyncio.sleep(0.1)

        mock_orchestrator.handle_task.assert_called_once()
        call_kwargs = mock_orchestrator.handle_task.call_args
        assert "Run health check" in str(call_kwargs)

    async def test_skips_not_due(self, engine, store, mock_orchestrator):
        """Routines with future next_run_at are skipped."""
        store.create(
            name="Future routine",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Not yet"},
            next_run_at="2099-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.05)

        mock_orchestrator.handle_task.assert_not_called()


# ── Event trigger ─────────────────────────────────────────────────


class TestEventTrigger:
    async def test_event_trigger_fires_on_match(self, engine, store, bus, mock_orchestrator):
        """Event-triggered routine fires when a matching event is published."""
        store.create(
            name="On task complete",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "Task completed, analyze results"},
        )

        await engine.start()
        try:
            await bus.publish("task.abc123.completed", {"status": "success"})
            await asyncio.sleep(0.2)

            mock_orchestrator.handle_task.assert_called_once()
        finally:
            await engine.stop()

    async def test_event_trigger_no_match(self, engine, store, bus, mock_orchestrator):
        """Non-matching events don't trigger routines."""
        store.create(
            name="On task complete only",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "test"},
        )

        await engine.start()
        try:
            await bus.publish("memory.stored", {"chunk_id": "abc"})
            await asyncio.sleep(0.1)

            mock_orchestrator.handle_task.assert_not_called()
        finally:
            await engine.stop()

    async def test_event_ignores_routine_events(self, engine, store, bus, mock_orchestrator):
        """Routine events (routine.*) don't trigger routines to prevent loops."""
        store.create(
            name="Self-trigger test",
            trigger_type="event",
            trigger_config={"event": "routine.*"},
            action_config={"prompt": "this should not fire"},
        )

        await engine.start()
        try:
            await bus.publish("routine.triggered", {"routine_id": "x"})
            await asyncio.sleep(0.1)

            mock_orchestrator.handle_task.assert_not_called()
        finally:
            await engine.stop()


# ── Manual trigger ────────────────────────────────────────────────


class TestManualTrigger:
    async def test_manual_trigger(self, engine, store, mock_orchestrator):
        r = store.create(
            name="Manual test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Manual execution"},
        )

        execution_id = await engine.trigger_manual(r.routine_id)
        assert execution_id is not None

        await asyncio.sleep(0.1)
        mock_orchestrator.handle_task.assert_called_once()

    async def test_manual_trigger_not_found(self, engine):
        result = await engine.trigger_manual("nonexistent")
        assert result is None


# ── Cooldown ──────────────────────────────────────────────────────


class TestCooldown:
    async def test_cooldown_prevents_reexecution(self, engine, store, mock_orchestrator):
        """Routine with cooldown is skipped if recently executed."""
        r = store.create(
            name="Cooldown test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            cooldown_s=3600,
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        # Set last_run_at to now (within cooldown window)
        store.update_run_state(r.routine_id, last_run_at=_now_iso(), next_run_at="2020-01-01T00:00:00.000Z")

        await engine._check_due_routines()
        await asyncio.sleep(0.05)

        mock_orchestrator.handle_task.assert_not_called()

    async def test_no_cooldown_allows_execution(self, engine, store, mock_orchestrator):
        """Routine without cooldown executes immediately."""
        store.create(
            name="No cooldown",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            cooldown_s=0,
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.1)

        mock_orchestrator.handle_task.assert_called_once()


# ── Max concurrent ────────────────────────────────────────────────


class TestMaxConcurrent:
    async def test_max_concurrent_respected(self, store, bus, db):
        """Only max_concurrent routines execute at once."""
        # Use an event to hold executions open
        hold = asyncio.Event()

        async def slow_task(**kwargs):
            await hold.wait()
            return TaskResult(status="success", plan_summary="done", task_id="x")

        slow_orchestrator = AsyncMock()
        slow_orchestrator.handle_task = AsyncMock(side_effect=slow_task)

        eng = RoutineEngine(
            store=store,
            orchestrator=slow_orchestrator,
            event_bus=bus,
            db=db,
            tick_interval=1,
            max_concurrent=2,
            execution_timeout=30,
        )

        # Create 4 due routines
        for i in range(4):
            store.create(
                name=f"Routine {i}",
                trigger_type="cron",
                trigger_config={"cron": "0 9 * * *"},
                action_config={"prompt": f"test {i}"},
                next_run_at="2020-01-01T00:00:00.000Z",
            )

        await eng._check_due_routines()
        await asyncio.sleep(0.05)

        # Should only have spawned 2 (the max)
        assert len(eng._running) == 2

        # Release held tasks and cleanup
        hold.set()
        await asyncio.sleep(0.1)
        await eng.stop()


# ── Execution timeout ─────────────────────────────────────────────


class TestExecutionTimeout:
    async def test_timeout_kills_hung_routine(self, store, bus, db):
        """Hung executions are terminated after timeout."""
        # Make orchestrator hang forever
        async def hang(**kwargs):
            await asyncio.sleep(9999)

        hang_orchestrator = AsyncMock()
        hang_orchestrator.handle_task = AsyncMock(side_effect=hang)

        eng = RoutineEngine(
            store=store,
            orchestrator=hang_orchestrator,
            event_bus=bus,
            db=db,
            tick_interval=1,
            max_concurrent=3,
            execution_timeout=1,  # 1-second timeout
        )

        r = store.create(
            name="Timeout test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "will hang"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(2)  # Wait for timeout + cleanup

        # Check execution was recorded as timeout
        rows = db.execute(
            "SELECT status, error FROM routine_executions WHERE routine_id = ?",
            (r.routine_id,),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "timeout"
        assert "timed out" in rows[0][1]


# ── Execution history ─────────────────────────────────────────────


class TestExecutionHistory:
    async def test_execution_recorded(self, engine, store, db, mock_orchestrator):
        """Successful execution is recorded in routine_executions."""
        r = store.create(
            name="History test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.2)

        history = engine.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "success"
        assert history[0]["triggered_by"] == "scheduler"

    async def test_manual_trigger_in_history(self, engine, store, db, mock_orchestrator):
        """Manual triggers are recorded with triggered_by='manual'."""
        r = store.create(
            name="Manual history",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "manual test"},
        )

        await engine.trigger_manual(r.routine_id)
        await asyncio.sleep(0.2)

        history = engine.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["triggered_by"] == "manual"


# ── Bus emissions ─────────────────────────────────────────────────


class TestBusEmissions:
    async def test_emits_triggered_and_executed(self, engine, store, bus, mock_orchestrator):
        """Engine emits routine.triggered and routine.executed events."""
        events = []

        async def capture(topic, data):
            events.append(topic)

        bus.subscribe("routine.*", capture)

        r = store.create(
            name="Bus test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.3)

        assert "routine.triggered" in events
        assert "routine.executed" in events


# ── Next run calculation ──────────────────────────────────────────


class TestNextRunCalculation:
    def test_cron_next_run(self, engine):
        from sentinel.routines.store import Routine
        r = Routine(
            routine_id="test", user_id="default", name="test",
            description="", trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            enabled=True, last_run_at=None, next_run_at=None,
            cooldown_s=0, created_at="", updated_at="",
        )
        result = engine._calculate_next_run(r)
        assert result is not None
        assert "T09:00" in result

    def test_interval_next_run(self, engine):
        from sentinel.routines.store import Routine
        r = Routine(
            routine_id="test", user_id="default", name="test",
            description="", trigger_type="interval",
            trigger_config={"seconds": 3600},
            action_config={"prompt": "test"},
            enabled=True, last_run_at=None, next_run_at=None,
            cooldown_s=0, created_at="", updated_at="",
        )
        result = engine._calculate_next_run(r)
        assert result is not None

    def test_event_next_run_is_none(self, engine):
        from sentinel.routines.store import Routine
        r = Routine(
            routine_id="test", user_id="default", name="test",
            description="", trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "test"},
            enabled=True, last_run_at=None, next_run_at=None,
            cooldown_s=0, created_at="", updated_at="",
        )
        result = engine._calculate_next_run(r)
        assert result is None


# ── Start/stop lifecycle ──────────────────────────────────────────


class TestLifecycle:
    async def test_start_and_stop(self, engine):
        await engine.start()
        assert engine._scheduler_task is not None
        assert not engine._scheduler_task.done()

        await engine.stop()
        assert engine._stopped is True

    async def test_stop_cancels_running_tasks(self, store, bus, db):
        """Stop cancels any running execution tasks."""
        hold = asyncio.Event()

        async def slow_task(**kwargs):
            await hold.wait()
            return TaskResult(status="success", plan_summary="done", task_id="x")

        slow_orch = AsyncMock()
        slow_orch.handle_task = AsyncMock(side_effect=slow_task)

        eng = RoutineEngine(
            store=store, orchestrator=slow_orch, event_bus=bus,
            db=db, tick_interval=1, max_concurrent=3, execution_timeout=30,
        )

        store.create(
            name="Running routine",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.05)
        assert len(eng._running) == 1

        await eng.stop()
        assert len(eng._running) == 0


# ── Error handling ────────────────────────────────────────────────


class TestErrorHandling:
    async def test_orchestrator_error_recorded(self, store, bus, db):
        """Orchestrator exceptions are caught and recorded."""
        error_orch = AsyncMock()
        error_orch.handle_task = AsyncMock(side_effect=RuntimeError("boom"))

        eng = RoutineEngine(
            store=store, orchestrator=error_orch, event_bus=bus,
            db=db, tick_interval=1, max_concurrent=3, execution_timeout=5,
        )

        r = store.create(
            name="Error test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "will fail"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.2)

        history = eng.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "error"
        assert "boom" in history[0]["error"]

    async def test_empty_prompt_recorded_as_error(self, engine, store, db, mock_orchestrator):
        """Routine with no prompt in action_config records an error."""
        r = store.create(
            name="No prompt",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={},  # missing prompt
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.2)

        history = engine.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "error"
        assert "prompt" in history[0]["error"].lower()
