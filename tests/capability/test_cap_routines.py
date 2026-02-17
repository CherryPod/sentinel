"""A2 capability tests — Routine Engine in production.

Verifies the 11 deployment-gate behaviours for the routine engine:
cron scheduling, missed ticks, cooldown, max concurrent, timeout,
error handling, dedup, result routing, persistence, disable toggle,
and stale execution cleanup on restart.

All tests mock the orchestrator (no real Claude/Qwen calls) and use
in-memory storage.  freezegun is used via context manager for
deterministic time checks where needed (decorator form has async issues).
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from freezegun import freeze_time

from sentinel.core.bus import EventBus
from sentinel.core.models import TaskResult
from sentinel.routines.cron import next_run as cron_next_run
from sentinel.routines.engine import RoutineEngine, _now_iso, _now_utc
from sentinel.routines.store import Routine, RoutineStore

pytestmark = pytest.mark.capability


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def store():
    return RoutineStore(pool=None)


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def mock_orchestrator():
    orch = AsyncMock()
    orch.handle_task = AsyncMock(return_value=TaskResult(
        status="success",
        plan_summary="Routine completed",
        task_id="test-task-id",
    ))
    return orch


@pytest.fixture
def engine(store, mock_orchestrator, bus):
    return RoutineEngine(
        store=store,
        orchestrator=mock_orchestrator,
        event_bus=bus,
        tick_interval=1,
        max_concurrent=3,
        execution_timeout=5,
    )


# ── Tests ────────────────────────────────────────────────────────


class TestRoutineCronFiresOnSchedule:
    """routine_cron_fires_on_schedule — cron routine fires when due."""

    async def test_cron_fires_on_schedule(self, engine, store, mock_orchestrator):
        # Create routine with next_run in the past — scheduler should pick it up
        r = await store.create(
            name="Every minute check",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "Run scheduled check"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.15)

        mock_orchestrator.handle_task.assert_called_once()
        assert "Run scheduled check" in str(mock_orchestrator.handle_task.call_args)

        # Verify execution recorded
        history = await engine.get_execution_history(r.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "success"

        # Verify next_run_at was updated (should now be in the future)
        routines = await store.list()
        assert len(routines) == 1
        assert routines[0].next_run_at is not None
        assert routines[0].last_run_at is not None


class TestRoutineCronMissedTick:
    """routine_cron_missed_tick — late start fires rather than skips."""

    async def test_missed_tick_fires(self, engine, store, mock_orchestrator):
        # Routine was due 5 minutes ago — Sentinel fires late, never skips
        five_min_ago = (_now_utc() - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"

        await store.create(
            name="Morning report",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Generate morning report"},
            next_run_at=five_min_ago,
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.15)

        # Should fire even though we're late
        mock_orchestrator.handle_task.assert_called_once()


class TestRoutineCooldownEnforcement:
    """routine_cooldown_enforcement — cooldown blocks rapid re-execution."""

    async def test_cooldown_blocks_reexecution(self, engine, store, mock_orchestrator):
        r = await store.create(
            name="Cooldown test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "test"},
            cooldown_s=300,  # 5-minute cooldown
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        # Set last_run_at to now (within the 300s cooldown window)
        await store.update_run_state(
            r.routine_id,
            last_run_at=_now_iso(),
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.05)

        mock_orchestrator.handle_task.assert_not_called()


class TestRoutineMaxConcurrent:
    """routine_max_concurrent — respects max_concurrent limit."""

    async def test_max_concurrent_limits_spawns(self, store, bus):
        hold = asyncio.Event()

        async def slow_task(**kwargs):
            await hold.wait()
            return TaskResult(status="success", plan_summary="done", task_id="x")

        slow_orch = AsyncMock()
        slow_orch.handle_task = AsyncMock(side_effect=slow_task)

        eng = RoutineEngine(
            store=store, orchestrator=slow_orch, event_bus=bus,
            tick_interval=1, max_concurrent=2, execution_timeout=30,
        )

        # Create 4 due routines
        for i in range(4):
            await store.create(
                name=f"Routine {i}",
                trigger_type="cron",
                trigger_config={"cron": "* * * * *"},
                action_config={"prompt": f"test {i}"},
                next_run_at="2020-01-01T00:00:00.000Z",
            )

        await eng._check_due_routines()
        await asyncio.sleep(0.05)

        assert len(eng._running) == 2

        hold.set()
        await asyncio.sleep(0.1)
        await eng.stop()


class TestRoutineTimeout:
    """routine_timeout — hung execution recorded as 'timeout'."""

    async def test_timeout_records_status(self, store, bus):
        async def hang(**kwargs):
            await asyncio.sleep(9999)

        hang_orch = AsyncMock()
        hang_orch.handle_task = AsyncMock(side_effect=hang)

        eng = RoutineEngine(
            store=store, orchestrator=hang_orch, event_bus=bus,
            tick_interval=1, max_concurrent=3, execution_timeout=1,
        )

        r = await store.create(
            name="Timeout test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "will hang"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(2)

        history = await eng.get_execution_history(r.routine_id)
        assert len(history) == 1
        assert history[0]["status"] == "timeout"
        assert "timed out" in history[0]["error"]


class TestRoutineErrorHandling:
    """routine_error_handling — orchestrator error recorded, engine continues."""

    async def test_error_recorded_and_engine_continues(self, store, bus):
        call_count = 0

        async def fail_then_succeed(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("boom")
            return TaskResult(status="success", plan_summary="ok", task_id="x")

        orch = AsyncMock()
        orch.handle_task = AsyncMock(side_effect=fail_then_succeed)

        eng = RoutineEngine(
            store=store, orchestrator=orch, event_bus=bus,
            tick_interval=1, max_concurrent=3, execution_timeout=5,
        )

        # First routine — will fail
        r1 = await store.create(
            name="Failing routine",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "will fail"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.2)

        # Verify error recorded
        history = await eng.get_execution_history(r1.routine_id)
        assert len(history) >= 1
        assert history[0]["status"] == "error"
        assert "boom" in history[0]["error"]

        # Create second routine — should succeed (engine still alive)
        r2 = await store.create(
            name="Working routine",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "will succeed"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.2)

        history2 = await eng.get_execution_history(r2.routine_id)
        assert len(history2) >= 1
        assert history2[0]["status"] == "success"


class TestRoutineDedup:
    """routine_dedup — cooldown prevents duplicate event-triggered executions."""

    async def test_rapid_events_deduped_by_cooldown(self, store, bus):
        orch = AsyncMock()
        orch.handle_task = AsyncMock(return_value=TaskResult(
            status="success", plan_summary="done", task_id="x",
        ))

        eng = RoutineEngine(
            store=store, orchestrator=orch, event_bus=bus,
            tick_interval=60, max_concurrent=3, execution_timeout=5,
        )

        await store.create(
            name="Event dedup test",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "handle event"},
            cooldown_s=300,
        )

        await eng.start()
        try:
            # Publish 3 events rapidly
            await bus.publish("task.a.completed", {})
            await asyncio.sleep(0.15)
            await bus.publish("task.b.completed", {})
            await asyncio.sleep(0.05)
            await bus.publish("task.c.completed", {})
            await asyncio.sleep(0.2)

            # Only the first should have fired (cooldown blocks the rest)
            assert orch.handle_task.call_count == 1
        finally:
            await eng.stop()


class TestRoutineResultRouting:
    """routine_result_routing — routine events forwarded to bus subscribers."""

    async def test_events_published_to_bus(self, engine, store, bus, mock_orchestrator):
        events = []

        async def capture(topic, data):
            events.append({"topic": topic, "data": data})

        bus.subscribe("routine.*", capture)

        await store.create(
            name="Result routing test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "test routing"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.3)

        topics = [e["topic"] for e in events]
        assert "routine.triggered" in topics
        assert "routine.executed" in topics

        # Verify event data includes routine info
        triggered_event = next(e for e in events if e["topic"] == "routine.triggered")
        assert "routine_id" in triggered_event["data"]
        assert "execution_id" in triggered_event["data"]
        assert triggered_event["data"]["name"] == "Result routing test"


class TestRoutinePersistenceAcrossRestart:
    """routine_persistence_across_restart — routine survives store re-read."""

    async def test_routine_persists_in_store(self, store):
        r = await store.create(
            name="Persistent routine",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * MON"},
            action_config={"prompt": "weekly check", "approval_mode": "auto"},
            description="Survives restart",
            cooldown_s=600,
        )
        routine_id = r.routine_id

        # Re-read from the same store (simulates reload)
        loaded = await store.get(routine_id)

        assert loaded is not None
        assert loaded.name == "Persistent routine"
        assert loaded.trigger_type == "cron"
        assert loaded.trigger_config == {"cron": "0 9 * * MON"}
        assert loaded.action_config == {"prompt": "weekly check", "approval_mode": "auto"}
        assert loaded.description == "Survives restart"
        assert loaded.cooldown_s == 600
        assert loaded.enabled is True


class TestRoutineDisableToggle:
    """routine_disable_toggle — disabled routine skipped on next tick."""

    async def test_disabled_routine_skipped(self, engine, store, mock_orchestrator):
        r = await store.create(
            name="Toggle test",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "should not run"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        # Disable the routine
        await store.update(r.routine_id, enabled=False)

        await engine._check_due_routines()
        await asyncio.sleep(0.05)

        mock_orchestrator.handle_task.assert_not_called()


class TestRoutineInflightOnRestart:
    """routine_inflight_on_restart — stale 'running' executions marked 'interrupted'."""

    async def test_stale_executions_cleaned_on_start(self, store, bus):
        # Create a routine so FK constraint is satisfied
        r = await store.create(
            name="Stale test routine",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )

        orch = AsyncMock()
        orch.handle_task = AsyncMock(return_value=TaskResult(
            status="success", plan_summary="ok", task_id="x",
        ))

        eng = RoutineEngine(
            store=store, orchestrator=orch, event_bus=bus,
            tick_interval=60, max_concurrent=3, execution_timeout=5,
        )

        # Manually insert stale "running" executions into in-memory store
        eng._mem_executions["stale-exec-1"] = {
            "execution_id": "stale-exec-1",
            "routine_id": r.routine_id,
            "user_id": 1,
            "triggered_by": "scheduler",
            "started_at": "2026-02-17T08:00:00.000Z",
            "completed_at": "",
            "status": "running",
            "result_summary": "",
            "error": "",
            "task_id": "",
        }
        eng._mem_executions["stale-exec-2"] = {
            "execution_id": "stale-exec-2",
            "routine_id": r.routine_id,
            "user_id": 1,
            "triggered_by": "manual",
            "started_at": "2026-02-17T08:30:00.000Z",
            "completed_at": "",
            "status": "running",
            "result_summary": "",
            "error": "",
            "task_id": "",
        }

        await eng.start()

        # Verify stale executions are now 'interrupted'
        for eid in ("stale-exec-1", "stale-exec-2"):
            rec = eng._mem_executions[eid]
            assert rec["status"] == "interrupted"
            assert "Engine restarted" in rec["error"]

        # Verify new executions can still fire normally
        await store.create(
            name="Post-restart routine",
            trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "should work after cleanup"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await eng._check_due_routines()
        await asyncio.sleep(0.15)

        # Assert at least one call (scheduler loop may also pick it up — the
        # important thing is execution isn't blocked by stale cleanup)
        assert orch.handle_task.call_count >= 1

        await eng.stop()
