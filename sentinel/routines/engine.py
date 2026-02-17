"""Routine engine — scheduler loop, event triggers, and execution management.

Runs as a background asyncio task during the app lifespan.  Checks for due
routines on a configurable interval, subscribes to the event bus for
event-triggered routines, and manages concurrent executions with timeouts.
"""

import asyncio
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch

from sentinel.core.bus import EventBus
from sentinel.planner.orchestrator import Orchestrator
from sentinel.routines.cron import next_run as cron_next_run
from sentinel.routines.store import Routine, RoutineStore

logger = logging.getLogger("sentinel.audit")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(s: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a UTC datetime."""
    # Handle both '...Z' and '...+00:00' suffixes
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


class RoutineEngine:
    """Background scheduler and event-trigger dispatcher for routines."""

    def __init__(
        self,
        store: RoutineStore,
        orchestrator: Orchestrator,
        event_bus: EventBus,
        db: sqlite3.Connection | None = None,
        tick_interval: int = 15,
        max_concurrent: int = 3,
        execution_timeout: int = 300,
    ):
        self._store = store
        self._orchestrator = orchestrator
        self._event_bus = event_bus
        self._db = db
        self._tick_interval = tick_interval
        self._max_concurrent = max_concurrent
        self._execution_timeout = execution_timeout

        self._scheduler_task: asyncio.Task | None = None
        self._running: dict[str, asyncio.Task] = {}  # execution_id → Task
        self._stopped = False

    # -- lifecycle --

    async def start(self) -> None:
        """Start the scheduler loop and subscribe to event bus."""
        self._stopped = False
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        self._event_bus.subscribe("*", self._on_event)
        logger.info(
            "Routine engine started",
            extra={
                "event": "routine_engine_start",
                "tick_interval": self._tick_interval,
                "max_concurrent": self._max_concurrent,
            },
        )

    async def stop(self) -> None:
        """Stop the scheduler and cancel all running executions."""
        self._stopped = True

        if self._scheduler_task is not None:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
            self._scheduler_task = None

        # Cancel all running executions
        for execution_id, task in list(self._running.items()):
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._running.clear()

        try:
            self._event_bus.unsubscribe("*", self._on_event)
        except Exception:
            pass

        logger.info("Routine engine stopped", extra={"event": "routine_engine_stop"})

    # -- scheduler loop --

    async def _scheduler_loop(self) -> None:
        """Periodic check for due routines."""
        while not self._stopped:
            try:
                await self._check_due_routines()
            except Exception as exc:
                logger.error(
                    "Scheduler tick error",
                    extra={"event": "routine_scheduler_error", "error": str(exc)},
                )
            await asyncio.sleep(self._tick_interval)

    async def _check_due_routines(self) -> None:
        """Find routines whose next_run_at has passed and execute them."""
        now = _now_iso()
        due = self._store.list_due(now)

        for routine in due:
            if self._in_cooldown(routine):
                continue
            if len(self._running) >= self._max_concurrent:
                logger.warning(
                    "Max concurrent routines reached, skipping",
                    extra={
                        "event": "routine_max_concurrent",
                        "running": len(self._running),
                        "skipped_routine": routine.routine_id,
                    },
                )
                break
            await self._spawn_execution(routine, triggered_by="scheduler")

    # -- event trigger --

    async def _on_event(self, topic: str, data: dict) -> None:
        """Check if any event-triggered routine matches this topic."""
        if self._stopped:
            return

        # Avoid triggering on our own emissions
        if topic.startswith("routine."):
            return

        # Find enabled event-triggered routines
        # TODO: add user_id filter for multi-user — currently all users' event
        # routines fire on matching topics. Single-user v1 limitation.
        if self._db is not None:
            rows = self._db.execute(
                "SELECT * FROM routines WHERE enabled = 1 AND trigger_type = 'event'"
            ).fetchall()
            routines = [self._store._row_to_routine(r) for r in rows]
        else:
            routines = [
                r for r in self._store._mem.values()
                if r.enabled and r.trigger_type == "event"
            ]

        for routine in routines:
            event_pattern = routine.trigger_config.get("event", "")
            if not event_pattern:
                continue
            if fnmatch(topic, event_pattern):
                if self._in_cooldown(routine):
                    continue
                if len(self._running) >= self._max_concurrent:
                    break
                await self._spawn_execution(
                    routine, triggered_by=f"event:{topic}",
                )

    # -- execution management --

    async def _spawn_execution(self, routine: Routine, triggered_by: str) -> str:
        """Create an execution record and spawn the async task."""
        execution_id = str(uuid.uuid4())
        now = _now_iso()

        # Record execution start
        if self._db is not None:
            self._db.execute(
                """INSERT INTO routine_executions
                   (execution_id, routine_id, user_id, triggered_by, started_at, status)
                   VALUES (?, ?, ?, ?, ?, 'running')""",
                (execution_id, routine.routine_id, routine.user_id, triggered_by, now),
            )
            self._db.commit()

        # Emit event
        try:
            await self._event_bus.publish("routine.triggered", {
                "routine_id": routine.routine_id,
                "execution_id": execution_id,
                "triggered_by": triggered_by,
                "name": routine.name,
            })
        except Exception:
            pass

        logger.info(
            "Routine triggered",
            extra={
                "event": "routine_triggered",
                "routine_id": routine.routine_id,
                "execution_id": execution_id,
                "triggered_by": triggered_by,
                "name": routine.name,
            },
        )

        task = asyncio.create_task(
            self._execute_routine(routine, execution_id, triggered_by)
        )
        self._running[execution_id] = task

        # Clean up when done
        def _cleanup(t: asyncio.Task) -> None:
            self._running.pop(execution_id, None)

        task.add_done_callback(_cleanup)

        return execution_id

    async def _execute_routine(
        self,
        routine: Routine,
        execution_id: str,
        triggered_by: str,
    ) -> None:
        """Run a routine through the orchestrator with timeout."""
        prompt = routine.action_config.get("prompt", "")
        if not prompt:
            self._record_execution_result(
                execution_id, "error", error="No prompt in action_config",
            )
            return

        approval_mode = routine.action_config.get("approval_mode", "auto")
        now = _now_iso()

        try:
            result = await asyncio.wait_for(
                self._orchestrator.handle_task(
                    user_request=prompt,
                    source=f"routine:{routine.routine_id}",
                    approval_mode=approval_mode,
                    source_key=f"routine:{routine.user_id}",
                    task_id=execution_id,
                ),
                timeout=self._execution_timeout,
            )

            self._record_execution_result(
                execution_id,
                status=result.status,
                result_summary=result.plan_summary,
                task_id=result.task_id,
            )

        except asyncio.TimeoutError:
            self._record_execution_result(
                execution_id, "timeout",
                error=f"Execution timed out after {self._execution_timeout}s",
            )
        except asyncio.CancelledError:
            self._record_execution_result(
                execution_id, "cancelled", error="Execution cancelled",
            )
            raise
        except Exception as exc:
            self._record_execution_result(
                execution_id, "error", error=str(exc),
            )

        # Update routine run state
        next_at = self._calculate_next_run(routine)
        self._store.update_run_state(
            routine.routine_id,
            last_run_at=now,
            next_run_at=next_at,
        )

        # Emit completion event
        try:
            await self._event_bus.publish("routine.executed", {
                "routine_id": routine.routine_id,
                "execution_id": execution_id,
                "triggered_by": triggered_by,
                "name": routine.name,
            })
        except Exception:
            pass

    def _record_execution_result(
        self,
        execution_id: str,
        status: str,
        result_summary: str = "",
        error: str = "",
        task_id: str = "",
    ) -> None:
        """Update the execution record with the result."""
        if self._db is not None:
            self._db.execute(
                """UPDATE routine_executions
                   SET status = ?, completed_at = ?, result_summary = ?,
                       error = ?, task_id = ?
                   WHERE execution_id = ?""",
                (status, _now_iso(), result_summary, error, task_id, execution_id),
            )
            self._db.commit()

        logger.info(
            "Routine execution completed",
            extra={
                "event": "routine_execution_complete",
                "execution_id": execution_id,
                "status": status,
                "error": error[:200] if error else "",
            },
        )

    # -- helpers --

    def _calculate_next_run(self, routine: Routine) -> str | None:
        """Calculate the next run time based on trigger type."""
        if routine.trigger_type == "cron":
            cron_expr = routine.trigger_config.get("cron", "")
            if cron_expr:
                try:
                    dt = cron_next_run(cron_expr)
                    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                except ValueError:
                    return None
            return None

        elif routine.trigger_type == "interval":
            seconds = routine.trigger_config.get("seconds", 0)
            if seconds > 0:
                dt = _now_utc() + timedelta(seconds=seconds)
                return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            return None

        # Event-triggered routines don't have a next_run_at
        return None

    def _in_cooldown(self, routine: Routine) -> bool:
        """Check if the routine is still within its cooldown window."""
        if routine.cooldown_s <= 0 or routine.last_run_at is None:
            return False
        try:
            last = _parse_iso(routine.last_run_at)
            cooldown_end = last + timedelta(seconds=routine.cooldown_s)
            return _now_utc() < cooldown_end
        except (ValueError, TypeError):
            return False

    # -- public API --

    async def trigger_manual(self, routine_id: str) -> str | None:
        """Manually trigger a routine. Returns execution_id or None if not found."""
        routine = self._store.get(routine_id)
        if routine is None:
            return None
        return await self._spawn_execution(routine, triggered_by="manual")

    def get_execution_history(
        self,
        routine_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        """Get execution history for a routine."""
        if self._db is None:
            return []
        rows = self._db.execute(
            """SELECT execution_id, routine_id, user_id, triggered_by,
                      started_at, completed_at, status, result_summary, error, task_id
               FROM routine_executions
               WHERE routine_id = ?
               ORDER BY started_at DESC
               LIMIT ? OFFSET ?""",
            (routine_id, limit, offset),
        ).fetchall()
        return [
            {
                "execution_id": r[0],
                "routine_id": r[1],
                "user_id": r[2],
                "triggered_by": r[3],
                "started_at": r[4],
                "completed_at": r[5],
                "status": r[6],
                "result_summary": r[7],
                "error": r[8],
                "task_id": r[9],
            }
            for r in rows
        ]
