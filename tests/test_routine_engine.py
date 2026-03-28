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
from sentinel.core.models import Plan, PlanStep, TaskResult
from sentinel.router.classifier import ClassificationResult, Route
from sentinel.routines.engine import RoutineEngine, _now_iso
from sentinel.routines.store import Routine, RoutineStore


@pytest.fixture
def store():
    return RoutineStore()


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
def engine(store, mock_orchestrator, bus):
    return RoutineEngine(
        store=store,
        orchestrator=mock_orchestrator,
        event_bus=bus,
        pool=None,
        tick_interval=1,  # fast ticks for tests
        max_concurrent=3,
        execution_timeout=5,
    )


@pytest.fixture
def mock_classifier():
    """Mock classifier that returns PLANNER by default."""
    from sentinel.router.classifier import ClassificationResult, Route
    clf = AsyncMock()
    clf.classify = AsyncMock(return_value=ClassificationResult(
        route=Route.PLANNER, reason="default mock",
    ))
    return clf


@pytest.fixture
def mock_fast_path():
    """Mock fast-path executor."""
    fp = AsyncMock()
    fp.execute = AsyncMock(return_value={
        "status": "success",
        "response": "fast-path result",
        "reason": "",
        "template": "test_template",
    })
    return fp


@pytest.fixture
def engine_with_router(store, mock_orchestrator, bus, mock_classifier, mock_fast_path):
    """Engine with classifier and fast-path wired in."""
    return RoutineEngine(
        store=store,
        orchestrator=mock_orchestrator,
        event_bus=bus,
        pool=None,
        tick_interval=1,
        max_concurrent=3,
        execution_timeout=5,
        classifier=mock_classifier,
        fast_path=mock_fast_path,
    )


def _make_routine(store, prompt="check my calendar", **overrides):
    """Helper to create a routine with sensible defaults."""
    import uuid
    defaults = dict(
        routine_id=str(uuid.uuid4()),
        user_id=1,
        name="test-routine",
        description="test",
        trigger_type="cron",
        trigger_config={"cron": "0 9 * * *"},
        action_config={"prompt": prompt, "approval_mode": "auto"},
        enabled=True,
        cooldown_s=0,
        last_run_at=None,
        next_run_at=None,
        created_at="",
        updated_at="",
    )
    defaults.update(overrides)
    r = Routine(**defaults)
    store._mem[r.routine_id] = r
    return r


@pytest.mark.asyncio
async def test_engine_accepts_classifier_and_fast_path(engine_with_router, mock_classifier, mock_fast_path):
    """RoutineEngine stores classifier and fast_path references."""
    assert engine_with_router._classifier is mock_classifier
    assert engine_with_router._fast_path is mock_fast_path


@pytest.mark.asyncio
async def test_engine_without_router_has_none(engine):
    """Default engine (no classifier/fast_path args) has None for both."""
    assert engine._classifier is None
    assert engine._fast_path is None


# ── Scheduler loop ────────────────────────────────────────────────


class TestSchedulerLoop:
    async def test_check_due_routines_executes(self, engine, store, mock_orchestrator):
        """Due routines get executed by the scheduler."""
        await store.create(
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
        await store.create(
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
        await store.create(
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
        await store.create(
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
        await store.create(
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
        r = await store.create(
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
        r = await store.create(
            name="Cooldown test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            cooldown_s=3600,
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        # Set last_run_at to now (within cooldown window)
        await store.update_run_state(r.routine_id, last_run_at=_now_iso(), next_run_at="2020-01-01T00:00:00.000Z")

        await engine._check_due_routines()
        await asyncio.sleep(0.05)

        mock_orchestrator.handle_task.assert_not_called()

    async def test_no_cooldown_allows_execution(self, engine, store, mock_orchestrator):
        """Routine without cooldown executes immediately."""
        await store.create(
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
    async def test_max_concurrent_respected(self, store, bus):
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
            pool=None,
            tick_interval=1,
            max_concurrent=2,
            execution_timeout=30,
        )

        # Create 4 due routines
        for i in range(4):
            await store.create(
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
    async def test_timeout_kills_hung_routine(self, store, bus):
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
            pool=None,
            tick_interval=1,
            max_concurrent=3,
            execution_timeout=1,  # 1-second timeout
        )

        r = await store.create(
            name="Timeout test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "will hang"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(2)  # Wait for timeout + cleanup

        # Check execution was recorded as timeout via in-memory store
        history = await eng.get_execution_history(r.routine_id)
        assert len(history) == 1
        assert history[0]["status"] == "timeout"
        assert "timed out" in history[0]["error"]


# ── Execution history ─────────────────────────────────────────────


class TestExecutionHistory:
    async def test_execution_recorded(self, engine, store, mock_orchestrator):
        """Successful execution is recorded in routine_executions."""
        r = await store.create(
            name="History test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.2)

        history = await engine.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "success"
        assert history[0]["triggered_by"] == "scheduler"

    async def test_manual_trigger_in_history(self, engine, store, mock_orchestrator):
        """Manual triggers are recorded with triggered_by='manual'."""
        r = await store.create(
            name="Manual history",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "manual test"},
        )

        await engine.trigger_manual(r.routine_id)
        await asyncio.sleep(0.2)

        history = await engine.get_execution_history(r.routine_id)
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

        r = await store.create(
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
        r = Routine(
            routine_id="test", user_id=1, name="test",
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
        r = Routine(
            routine_id="test", user_id=1, name="test",
            description="", trigger_type="interval",
            trigger_config={"seconds": 3600},
            action_config={"prompt": "test"},
            enabled=True, last_run_at=None, next_run_at=None,
            cooldown_s=0, created_at="", updated_at="",
        )
        result = engine._calculate_next_run(r)
        assert result is not None

    def test_event_next_run_is_none(self, engine):
        r = Routine(
            routine_id="test", user_id=1, name="test",
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

    async def test_stop_cancels_running_tasks(self, store, bus):
        """Stop cancels any running execution tasks."""
        hold = asyncio.Event()

        async def slow_task(**kwargs):
            await hold.wait()
            return TaskResult(status="success", plan_summary="done", task_id="x")

        slow_orch = AsyncMock()
        slow_orch.handle_task = AsyncMock(side_effect=slow_task)

        eng = RoutineEngine(
            store=store, orchestrator=slow_orch, event_bus=bus,
            pool=None, tick_interval=1, max_concurrent=3, execution_timeout=30,
        )

        await store.create(
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
    async def test_orchestrator_error_recorded(self, store, bus):
        """Orchestrator exceptions are caught and recorded."""
        error_orch = AsyncMock()
        error_orch.handle_task = AsyncMock(side_effect=RuntimeError("boom"))

        eng = RoutineEngine(
            store=store, orchestrator=error_orch, event_bus=bus,
            pool=None, tick_interval=1, max_concurrent=3, execution_timeout=5,
        )

        r = await store.create(
            name="Error test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "will fail"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.2)

        history = await eng.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "error"
        assert "boom" in history[0]["error"]

    async def test_empty_prompt_recorded_as_error(self, engine, store, mock_orchestrator):
        """Routine with no prompt in action_config records an error."""
        r = await store.create(
            name="No prompt",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={},  # missing prompt
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.2)

        history = await engine.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "error"
        assert "prompt" in history[0]["error"].lower()


# ── Fast-path routing ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_try_fast_path_returns_result_on_fast_classification(
    engine_with_router, store, mock_classifier, mock_fast_path,
):
    """When classifier returns FAST, _try_fast_path returns a TaskResult."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.FAST, template_name="calendar_read", params={"time_min": "today"},
    )
    routine = _make_routine(store, prompt="check my calendar")
    result = await engine_with_router._try_fast_path(
        prompt="check my calendar",
        routine=routine,
        execution_id="exec-1",
    )
    assert result is not None
    assert result.status == "success"
    assert result.response == "fast-path result"
    mock_fast_path.execute.assert_called_once()


@pytest.mark.asyncio
async def test_try_fast_path_returns_none_on_planner_classification(
    engine_with_router, store, mock_classifier, mock_fast_path,
):
    """When classifier returns PLANNER, _try_fast_path returns None (fall back)."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.PLANNER, reason="too complex",
    )
    routine = _make_routine(store, prompt="complex multi-step task")
    result = await engine_with_router._try_fast_path(
        prompt="complex multi-step task",
        routine=routine,
        execution_id="exec-2",
    )
    assert result is None
    mock_fast_path.execute.assert_not_called()


@pytest.mark.asyncio
async def test_try_fast_path_returns_none_on_classifier_error(
    engine_with_router, store, mock_classifier, mock_fast_path,
):
    """If classifier raises, _try_fast_path returns None (fall back to planner)."""
    mock_classifier.classify.side_effect = Exception("Qwen is down")
    routine = _make_routine(store, prompt="check my calendar")
    result = await engine_with_router._try_fast_path(
        prompt="check my calendar",
        routine=routine,
        execution_id="exec-3",
    )
    assert result is None
    mock_fast_path.execute.assert_not_called()


@pytest.mark.asyncio
async def test_try_fast_path_returns_none_on_fast_path_execution_error(
    engine_with_router, store, mock_classifier, mock_fast_path,
):
    """If fast-path execute raises, _try_fast_path returns None (fall back)."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.FAST, template_name="calendar_read", params={},
    )
    mock_fast_path.execute.side_effect = Exception("Tool executor crashed")
    routine = _make_routine(store, prompt="check my calendar")
    result = await engine_with_router._try_fast_path(
        prompt="check my calendar",
        routine=routine,
        execution_id="exec-4",
    )
    assert result is None


@pytest.mark.asyncio
async def test_try_fast_path_returns_none_on_fast_path_error_status(
    engine_with_router, store, mock_classifier, mock_fast_path,
):
    """If fast-path returns error status, _try_fast_path returns None (fall back)."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.FAST, template_name="calendar_read", params={},
    )
    mock_fast_path.execute.return_value = {
        "status": "error",
        "response": None,
        "reason": "Tool not found",
        "template": "calendar_read",
    }
    routine = _make_routine(store, prompt="check my calendar")
    result = await engine_with_router._try_fast_path(
        prompt="check my calendar",
        routine=routine,
        execution_id="exec-5",
    )
    assert result is None


# ── Fast-path integration (wired into _execute_routine) ──────────


@pytest.mark.asyncio
async def test_single_iteration_uses_fast_path_when_classified_fast(
    engine_with_router, store, mock_orchestrator, mock_classifier, mock_fast_path,
):
    """Single-iteration routine uses fast-path, skips orchestrator."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.FAST, template_name="calendar_read", params={},
    )
    routine = _make_routine(store, prompt="check my calendar")
    await engine_with_router.start()
    try:
        exec_id = await engine_with_router.trigger_manual(routine.routine_id)
        await asyncio.sleep(0.3)
    finally:
        await engine_with_router.stop()

    mock_fast_path.execute.assert_called_once()
    mock_orchestrator.handle_task.assert_not_called()


@pytest.mark.asyncio
async def test_single_iteration_falls_back_to_planner_when_classified_planner(
    engine_with_router, store, mock_orchestrator, mock_classifier, mock_fast_path,
):
    """Single-iteration routine falls back to orchestrator when classified as planner."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.PLANNER, reason="complex",
    )
    routine = _make_routine(store, prompt="do something complex")
    await engine_with_router.start()
    try:
        exec_id = await engine_with_router.trigger_manual(routine.routine_id)
        await asyncio.sleep(0.3)
    finally:
        await engine_with_router.stop()

    mock_fast_path.execute.assert_not_called()
    mock_orchestrator.handle_task.assert_called_once()


@pytest.mark.asyncio
async def test_multi_iteration_skips_classifier_entirely(
    engine_with_router, store, mock_orchestrator, mock_classifier, mock_fast_path,
):
    """Multi-iteration routines always use planner, classifier is never called."""
    routine = _make_routine(
        store, prompt="iterative task",
        action_config={"prompt": "iterative task", "max_iterations": 3, "approval_mode": "auto"},
    )
    await engine_with_router.start()
    try:
        exec_id = await engine_with_router.trigger_manual(routine.routine_id)
        await asyncio.sleep(0.5)
    finally:
        await engine_with_router.stop()

    mock_classifier.classify.assert_not_called()
    mock_orchestrator.handle_task.assert_called()


@pytest.mark.asyncio
async def test_fast_path_failure_falls_back_to_planner(
    engine_with_router, store, mock_orchestrator, mock_classifier, mock_fast_path,
):
    """If fast-path execution fails, routine falls back to planner."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.FAST, template_name="calendar_read", params={},
    )
    mock_fast_path.execute.side_effect = Exception("boom")
    routine = _make_routine(store, prompt="check my calendar")
    await engine_with_router.start()
    try:
        exec_id = await engine_with_router.trigger_manual(routine.routine_id)
        await asyncio.sleep(0.3)
    finally:
        await engine_with_router.stop()

    mock_fast_path.execute.assert_called_once()
    mock_orchestrator.handle_task.assert_called_once()


@pytest.mark.asyncio
async def test_engine_without_router_uses_planner_as_before(
    engine, store, mock_orchestrator,
):
    """Engine without classifier/fast_path uses planner for everything."""
    routine = _make_routine(store, prompt="check my calendar")
    await engine.start()
    try:
        exec_id = await engine.trigger_manual(routine.routine_id)
        await asyncio.sleep(0.3)
    finally:
        await engine.stop()

    mock_orchestrator.handle_task.assert_called_once()


@pytest.mark.asyncio
async def test_try_fast_path_passes_skip_confirmation(
    engine_with_router, store, mock_classifier, mock_fast_path,
):
    """_try_fast_path passes skip_confirmation=True to fast-path executor."""
    mock_classifier.classify.return_value = ClassificationResult(
        route=Route.FAST, template_name="telegram_send",
        params={"message": "reminder"},
    )
    routine = _make_routine(store, prompt="send reminder via telegram")
    await engine_with_router._try_fast_path(
        prompt="send reminder via telegram",
        routine=routine,
        execution_id="exec-skip",
    )
    _, kwargs = mock_fast_path.execute.call_args
    assert kwargs.get("skip_confirmation") is True


# ── Audit finding tests ──────────────────────────────────────────


class TestApprovalModeDefault:
    """Finding #1: User-created routines default to approval_mode='full'."""

    async def test_default_approval_mode_is_full(self, engine, store, mock_orchestrator):
        """A routine with no explicit approval_mode uses 'full'."""
        r = await store.create(
            name="User routine",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test prompt"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.1)

        mock_orchestrator.handle_task.assert_called_once()
        call_kwargs = mock_orchestrator.handle_task.call_args.kwargs
        assert call_kwargs["approval_mode"] == "full"

    async def test_explicit_auto_approval_preserved(self, engine, store, mock_orchestrator):
        """A routine with explicit approval_mode='auto' keeps it."""
        r = await store.create(
            name="System routine",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test", "approval_mode": "auto"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.1)

        mock_orchestrator.handle_task.assert_called_once()
        call_kwargs = mock_orchestrator.handle_task.call_args.kwargs
        assert call_kwargs["approval_mode"] == "auto"


class TestStarvationAlerting:
    """Finding #8: Starvation counter tracks consecutive max_concurrent hits."""

    async def test_starvation_counter_increments(self, store, bus):
        hold = asyncio.Event()

        async def slow_task(**kwargs):
            await hold.wait()
            return TaskResult(status="success", plan_summary="done", task_id="x")

        slow_orch = AsyncMock()
        slow_orch.handle_task = AsyncMock(side_effect=slow_task)

        eng = RoutineEngine(
            store=store, orchestrator=slow_orch, event_bus=bus,
            tick_interval=1, max_concurrent=1, execution_timeout=30,
        )

        # Create 2 due routines — one runs, one skipped
        for i in range(2):
            await store.create(
                name=f"Starve {i}", trigger_type="cron",
                trigger_config={"cron": "0 9 * * *"},
                action_config={"prompt": f"test {i}"},
                next_run_at="2020-01-01T00:00:00.000Z",
            )

        await eng._check_due_routines()
        assert eng._starvation_ticks == 1

        await eng._check_due_routines()
        assert eng._starvation_ticks == 2

        hold.set()
        await asyncio.sleep(0.1)
        await eng.stop()

    async def test_starvation_resets_when_slots_free(self, engine, store, mock_orchestrator):
        """Starvation counter resets when all due routines are processed."""
        # No routines — should reset counter
        engine._starvation_ticks = 5
        await engine._check_due_routines()
        assert engine._starvation_ticks == 0


class TestSeedDefaultsRequiresUserId:
    """Finding #13: seed_defaults requires explicit user_id."""

    async def test_seed_defaults_no_default(self, engine):
        import inspect
        sig = inspect.signature(engine.seed_defaults)
        param = sig.parameters["user_id"]
        assert param.default is inspect.Parameter.empty, \
            "seed_defaults should require explicit user_id"


class TestCleanupStaleMultiUser:
    """Finding #11: cleanup_stale handles all users' executions."""

    async def test_cleanup_stale_handles_multi_user(self, engine):
        await engine.record_start("exec-1", "r1", 1, "scheduler")
        await engine.record_start("exec-2", "r2", 42, "scheduler")

        count = await engine.cleanup_stale()
        assert count == 2

        for eid in ("exec-1", "exec-2"):
            rec = engine._mem_executions[eid]
            assert rec["status"] == "interrupted"
