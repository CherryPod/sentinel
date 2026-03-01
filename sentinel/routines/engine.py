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
        """Start the scheduler loop and subscribe to event bus.

        On startup, marks any executions left in 'running' state as
        'interrupted' — these are stale from a previous engine crash/restart
        and would otherwise block max_concurrent slots forever.
        """
        self._stopped = False

        # Clean up stale executions from previous engine instance
        if self._db is not None:
            stale_count = self._db.execute(
                "SELECT COUNT(*) FROM routine_executions WHERE status = 'running'"
            ).fetchone()[0]
            if stale_count > 0:
                self._db.execute(
                    """UPDATE routine_executions
                       SET status = 'interrupted',
                           error = 'Engine restarted while execution was in progress',
                           completed_at = ?
                       WHERE status = 'running'""",
                    (_now_iso(),),
                )
                self._db.commit()
                logger.warning(
                    "Marked stale executions as interrupted",
                    extra={
                        "event": "routine_stale_cleanup",
                        "count": stale_count,
                    },
                )

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
        # M-003: Accesses private store attributes (_row_to_routine, _mem) to
        # avoid adding a public query method for this single-caller pattern.
        # Refactor if RoutineStore grows a public list_by_trigger_type() method.
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
                "routine_name": routine.name,
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
        """Run a routine through the orchestrator with timeout.

        Supports multi-turn execution when ``max_iterations`` > 1 in
        ``action_config``.  Each iteration feeds the previous result back
        as context, and a ``[DONE]`` signal in the plan summary terminates
        early.  Single-iteration routines (the default) follow the original
        fast path.
        """
        prompt = routine.action_config.get("prompt", "")
        if not prompt:
            self._record_execution_result(
                execution_id, "error", error="No prompt in action_config",
            )
            return

        approval_mode = routine.action_config.get("approval_mode", "auto")
        max_iterations = routine.action_config.get("max_iterations", 1)
        per_iteration_timeout = routine.action_config.get(
            "per_iteration_timeout", self._execution_timeout,
        )
        now = _now_iso()

        if max_iterations <= 1:
            # ── Single-iteration fast path (backward compatible) ──
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
        else:
            # ── Multi-turn iteration loop ──
            context = ""
            final_result = None
            for iteration in range(1, max_iterations + 1):
                iter_prompt = prompt
                if context:
                    iter_prompt += (
                        f"\n\n--- Previous iteration ({iteration - 1}) result ---\n"
                        f"{context}"
                    )

                try:
                    result = await asyncio.wait_for(
                        self._orchestrator.handle_task(
                            user_request=iter_prompt,
                            source=f"routine:{routine.routine_id}",
                            approval_mode=approval_mode,
                            source_key=f"routine:{routine.user_id}",
                            task_id=execution_id,
                        ),
                        timeout=per_iteration_timeout,
                    )

                    self._record_iteration(
                        execution_id, iteration, result.status,
                        result.plan_summary,
                    )
                    final_result = result

                    # Check for done signal or error/blocked status
                    if self._is_done_signal(result):
                        self._record_execution_result(
                            execution_id, "complete",
                            result_summary=result.plan_summary,
                            task_id=result.task_id,
                        )
                        break

                    if result.status in ("blocked", "error"):
                        self._record_execution_result(
                            execution_id, result.status,
                            result_summary=result.plan_summary,
                            task_id=result.task_id,
                        )
                        break

                    # Carry forward context for next iteration
                    context = result.plan_summary or ""

                except asyncio.TimeoutError:
                    self._record_execution_result(
                        execution_id, "timeout",
                        error=(
                            f"Iteration {iteration} timed out after "
                            f"{per_iteration_timeout}s"
                        ),
                    )
                    break
                except asyncio.CancelledError:
                    self._record_execution_result(
                        execution_id, "cancelled",
                        error=f"Cancelled during iteration {iteration}",
                    )
                    raise
                except Exception as exc:
                    self._record_execution_result(
                        execution_id, "error",
                        error=f"Iteration {iteration}: {exc}",
                    )
                    break
            else:
                # Exhausted max_iterations without done signal
                if final_result is not None:
                    self._record_execution_result(
                        execution_id, final_result.status,
                        result_summary=final_result.plan_summary,
                        task_id=final_result.task_id,
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

    def _is_done_signal(self, result) -> bool:
        """Check if an orchestrator result indicates the routine is complete.

        A done signal is detected when the plan summary contains the
        literal marker ``[DONE]`` (case-insensitive).

        M-002: Substring match is intentional — plan_summary is generated by
        Claude (trusted planner), not raw user input. False positives from
        natural language mentioning "[DONE]" are acceptable since they only
        cause early routine termination, not a security bypass.
        """
        summary = (result.plan_summary or "").lower()
        return "[done]" in summary

    def _record_iteration(
        self,
        execution_id: str,
        iteration: int,
        status: str,
        result_summary: str = "",
    ) -> None:
        """Log a multi-turn iteration for auditing."""
        logger.info(
            "Routine iteration completed",
            extra={
                "event": "routine_iteration",
                "execution_id": execution_id,
                "iteration": iteration,
                "status": status,
                "summary_preview": (result_summary or "")[:200],
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

    def seed_defaults(self, user_id: str = "default") -> list[str]:
        """Create starter routine templates if the user has no routines.

        Returns a list of created routine IDs (empty if user already has routines).
        """
        if self._store.count_for_user(user_id) > 0:
            return []

        created = []

        # Daily summary — runs at 09:00 UTC every day
        r1 = self._store.create(
            name="Daily Summary",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={
                "prompt": (
                    "Summarize the key activities and conversations from the "
                    "past 24 hours. Include any important task results, security "
                    "events, and memory updates."
                ),
                "approval_mode": "auto",
            },
            user_id=user_id,
            description="Automated daily summary of recent activity.",
            cooldown_s=3600,
        )
        created.append(r1.routine_id)

        # Memory cleanup — runs at 03:00 UTC every Sunday
        r2 = self._store.create(
            name="Memory Cleanup",
            trigger_type="cron",
            trigger_config={"cron": "0 3 * * SUN"},
            action_config={
                "prompt": (
                    "Review stored memories for outdated, redundant, or low-value "
                    "entries. List candidates for cleanup with reasoning."
                ),
                "approval_mode": "auto",
            },
            user_id=user_id,
            description="Weekly review of memory store for housekeeping.",
            cooldown_s=3600,
        )
        created.append(r2.routine_id)

        logger.info(
            "Seeded default routines",
            extra={
                "event": "routine_seed_defaults",
                "user_id": user_id,
                "count": len(created),
            },
        )
        return created

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
