"""Routine engine — scheduler loop, event triggers, and execution management.

Runs as a background asyncio task during the app lifespan.  Checks for due
routines on a configurable interval, subscribes to the event bus for
event-triggered routines, and manages concurrent executions with timeouts.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any, cast

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


def _dt_to_iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class RoutineEngine:
    """Background scheduler and event-trigger dispatcher for routines."""

    def __init__(
        self,
        store: RoutineStore,
        orchestrator: Orchestrator,
        event_bus: EventBus,
        pool: Any | None = None,
        admin_pool: Any | None = None,
        tick_interval: int = 15,
        max_concurrent: int = 3,
        execution_timeout: int = 300,
        classifier: Any | None = None,
        fast_path: Any | None = None,
    ):
        self._store = store
        self._orchestrator = orchestrator
        self._event_bus = event_bus
        self._pool = pool
        self._admin_pool = admin_pool
        self._in_memory = pool is None
        self._tick_interval = tick_interval
        self._max_concurrent = max_concurrent
        self._execution_timeout = execution_timeout
        self._classifier = classifier
        self._fast_path = fast_path

        # In-memory execution storage for tests (pool=None)
        self._mem_executions: dict[str, dict] = {}

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
        stale_count = await self.cleanup_stale()
        if stale_count > 0:
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

    _STOP_TIMEOUT = 10  # seconds to wait for cancelled routines

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

        # Cancel all running executions and wait with a timeout (SYS-5b)
        if self._running:
            tasks = list(self._running.values())
            execution_ids = list(self._running.keys())
            for task in tasks:
                task.cancel()
            done, pending = await asyncio.wait(tasks, timeout=self._STOP_TIMEOUT)
            if pending:
                stale_ids = [
                    eid for eid, t in zip(execution_ids, tasks) if t in pending
                ]
                logger.warning(
                    "Routine engine: %d tasks did not stop within %ds timeout",
                    len(pending), self._STOP_TIMEOUT,
                    extra={
                        "event": "routine_stop_timeout",
                        "pending_count": len(pending),
                        "pending_ids": stale_ids,
                    },
                )
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
        """Find routines whose next_run_at has passed and execute them.

        Uses admin pool to discover routines across ALL users (bypasses RLS).
        Each routine's execution sets ContextVar to routine.user_id (line ~316).
        """
        now = _now_iso()
        due = await self._store.list_due_all_users(now, admin_pool=self._admin_pool)

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

        # Discover event-triggered routines across ALL users via admin pool
        routines = await self._store.list_event_triggered_all_users(
            enabled_only=True, admin_pool=self._admin_pool,
        )

        for routine in routines:
            event_pattern = routine.trigger_config.get("event", "")
            if not event_pattern:
                continue
            if fnmatch(topic, event_pattern):
                if self._in_cooldown(routine):
                    continue
                if len(self._running) >= self._max_concurrent:
                    break
                # BH3-053: Catch spawn failures so remaining routines still fire
                try:
                    await self._spawn_execution(
                        routine, triggered_by=f"event:{topic}",
                    )
                except Exception as exc:
                    logger.error(
                        "Failed to spawn event-triggered routine %s: %s",
                        routine.routine_id, exc,
                        extra={
                            "event": "routine_event_spawn_error",
                            "routine_id": routine.routine_id,
                            "topic": topic,
                            "error": str(exc),
                        },
                    )

    # -- execution management --

    async def _spawn_execution(self, routine: Routine, triggered_by: str) -> str:
        """Create an execution record and spawn the async task."""
        execution_id = str(uuid.uuid4())

        # Record execution start
        await self.record_start(
            execution_id, routine.routine_id, routine.user_id, triggered_by,
        )

        # Emit event
        try:
            await self._event_bus.publish("routine.triggered", {
                "routine_id": routine.routine_id,
                "execution_id": execution_id,
                "triggered_by": triggered_by,
                "name": routine.name,
            })
        except Exception as pub_exc:
            logger.debug(
                "Failed to publish routine.triggered event: %s",
                pub_exc,
                extra={
                    "event": "event_bus_publish_failed",
                    "topic": "routine.triggered",
                    "error": str(pub_exc),
                },
            )

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

        Sets the current_user_id contextvar from the routine's user_id so
        that RLS-scoped queries return the correct data for this user.
        """
        from sentinel.core.context import current_user_id
        ctx_token = current_user_id.set(routine.user_id)
        try:
            await self._execute_routine_inner(routine, execution_id, triggered_by)
        finally:
            current_user_id.reset(ctx_token)

    async def _execute_routine_inner(
        self,
        routine: Routine,
        execution_id: str,
        triggered_by: str,
    ) -> None:
        """Inner execution logic, called with user context already set."""
        prompt = routine.action_config.get("prompt", "")
        if not prompt:
            await self._record_execution_result(
                execution_id, "error", error="No prompt in action_config",
            )
            return

        approval_mode = routine.action_config.get("approval_mode", "auto")
        max_iterations = min(routine.action_config.get("max_iterations", 1), 50)
        per_iteration_timeout = routine.action_config.get(
            "per_iteration_timeout", self._execution_timeout,
        )
        now = _now_iso()

        if max_iterations <= 1:
            # -- Single-iteration: try fast-path, fall back to planner --
            # BH3-011: Timeout prevents a hanging tool from permanently
            # consuming a _max_concurrent slot.
            try:
                result = await asyncio.wait_for(
                    self._try_fast_path(prompt, routine, execution_id),
                    timeout=self._execution_timeout,
                )
            except asyncio.TimeoutError:
                await self._record_execution_result(
                    execution_id, "timeout",
                    error=f"Fast-path timed out after {self._execution_timeout}s",
                )
                result = ...  # sentinel to skip both branches below
            except asyncio.CancelledError:
                await self._record_execution_result(
                    execution_id, "cancelled", error="Fast-path cancelled",
                )
                raise

            if result is ...:
                pass  # already recorded above
            elif result is not None:
                # Fast-path succeeded
                await self._record_execution_result(
                    execution_id,
                    status=result.status,
                    result_summary=result.plan_summary,
                    task_id=result.task_id,
                )
            else:
                # Planner path (original behaviour)
                try:
                    result = await asyncio.wait_for(
                        self._orchestrator.handle_task(
                            user_request=prompt,
                            source=f"routine:{routine.routine_id}",
                            approval_mode=approval_mode,
                            source_key=f"routine:{routine.routine_id}",
                            task_id=execution_id,
                        ),
                        timeout=self._execution_timeout,
                    )

                    await self._record_execution_result(
                        execution_id,
                        status=result.status,
                        result_summary=result.plan_summary,
                        task_id=result.task_id,
                    )

                except asyncio.TimeoutError:
                    await self._record_execution_result(
                        execution_id, "timeout",
                        error=f"Execution timed out after {self._execution_timeout}s",
                    )
                except asyncio.CancelledError:
                    await self._record_execution_result(
                        execution_id, "cancelled", error="Execution cancelled",
                    )
                    raise
                except Exception as exc:
                    await self._record_execution_result(
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
                            source_key=f"routine:{routine.routine_id}",
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
                        await self._record_execution_result(
                            execution_id, "complete",
                            result_summary=result.plan_summary,
                            task_id=result.task_id,
                        )
                        break

                    if result.status in ("blocked", "error"):
                        await self._record_execution_result(
                            execution_id, result.status,
                            result_summary=result.plan_summary,
                            task_id=result.task_id,
                        )
                        break

                    # Carry forward context for next iteration
                    context = result.plan_summary or ""

                except asyncio.TimeoutError:
                    await self._record_execution_result(
                        execution_id, "timeout",
                        error=(
                            f"Iteration {iteration} timed out after "
                            f"{per_iteration_timeout}s"
                        ),
                    )
                    break
                except asyncio.CancelledError:
                    await self._record_execution_result(
                        execution_id, "cancelled",
                        error=f"Cancelled during iteration {iteration}",
                    )
                    raise
                except Exception as exc:
                    await self._record_execution_result(
                        execution_id, "error",
                        error=f"Iteration {iteration}: {exc}",
                    )
                    break
            else:
                # Exhausted max_iterations without done signal
                if final_result is not None:
                    await self._record_execution_result(
                        execution_id, final_result.status,
                        result_summary=final_result.plan_summary,
                        task_id=final_result.task_id,
                    )

        # Update routine run state
        next_at = self._calculate_next_run(routine)
        await self._store.update_run_state(
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
        except Exception as pub_exc:
            logger.debug(
                "Failed to publish routine.executed event: %s",
                pub_exc,
                extra={
                    "event": "event_bus_publish_failed",
                    "topic": "routine.executed",
                    "error": str(pub_exc),
                },
            )

    async def _record_execution_result(
        self,
        execution_id: str,
        status: str,
        result_summary: str = "",
        error: str = "",
        task_id: str = "",
    ) -> None:
        """Update the execution record with the result."""
        await self.record_completion(
            execution_id, status, result_summary, error, task_id,
        )

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

    # -- fast-path routing --

    async def _try_fast_path(
        self,
        prompt: str,
        routine: Routine,
        execution_id: str,
    ) -> TaskResult | None:
        """Attempt fast-path execution for a single-iteration routine.

        Returns a TaskResult on success, or None to signal the caller
        should fall back to the planner path. Never raises.
        """
        from sentinel.core.models import TaskResult

        if self._classifier is None or self._fast_path is None:
            return None

        try:
            classification = await self._classifier.classify(prompt)
        except Exception:
            logger.warning(
                "Routine fast-path classification failed, falling back to planner",
                extra={
                    "event": "routine_fastpath_classify_error",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                },
            )
            return None

        if classification.is_planner:
            logger.debug(
                "Routine classified as planner: %s",
                classification.reason,
                extra={
                    "event": "routine_fastpath_planner",
                    "routine_id": routine.routine_id,
                },
            )
            return None

        # Fast-path classification — execute via template
        try:
            fp_result = await self._fast_path.execute(
                template_name=classification.template_name,
                params=classification.params,
                session=None,
                task_id=execution_id,
                user_id=routine.user_id,
                skip_confirmation=True,
            )
        except Exception:
            logger.warning(
                "Routine fast-path execution failed, falling back to planner",
                extra={
                    "event": "routine_fastpath_exec_error",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                    "template": classification.template_name,
                },
            )
            return None

        # Error status from fast-path — fall back to planner for a better attempt
        if fp_result.get("status") not in ("success", "blocked"):
            logger.info(
                "Routine fast-path returned %s, falling back to planner",
                fp_result.get("status"),
                extra={
                    "event": "routine_fastpath_fallback",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                    "template": classification.template_name,
                    "reason": fp_result.get("reason", ""),
                },
            )
            return None

        return TaskResult(
            task_id=execution_id,
            status=fp_result["status"],
            plan_summary=f"Fast-path: {classification.template_name}",
            response=fp_result.get("response", ""),
        )

    # -- DB operations (PostgreSQL with in-memory fallback) --

    async def record_start(
        self,
        execution_id: str,
        routine_id: str,
        user_id: int,
        triggered_by: str,
    ) -> None:
        if self._in_memory:
            self._mem_executions[execution_id] = {
                "execution_id": execution_id,
                "routine_id": routine_id,
                "user_id": user_id,
                "triggered_by": triggered_by,
                "started_at": _now_iso(),
                "completed_at": "",
                "status": "running",
                "result_summary": "",
                "error": "",
                "task_id": "",
            }
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO routine_executions "
                "(execution_id, routine_id, user_id, triggered_by, started_at, status) "
                "VALUES ($1, $2, $3, $4, NOW(), 'running')",
                execution_id, routine_id, user_id, triggered_by,
            )

    async def record_completion(
        self,
        execution_id: str,
        status: str,
        result_summary: str = "",
        error: str = "",
        task_id: str = "",
    ) -> None:
        if self._in_memory:
            if execution_id in self._mem_executions:
                rec = self._mem_executions[execution_id]
                rec["status"] = status
                rec["completed_at"] = _now_iso()
                rec["result_summary"] = result_summary
                rec["error"] = error
                rec["task_id"] = task_id
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE routine_executions "
                "SET status = $1, completed_at = NOW(), result_summary = $2, "
                "error = $3, task_id = $4 "
                "WHERE execution_id = $5",
                status, result_summary, error, task_id, execution_id,
            )

    async def cleanup_stale(self) -> int:
        """Mark stale 'running' executions as 'interrupted'. Returns count."""
        if self._in_memory:
            count = 0
            for rec in self._mem_executions.values():
                if rec["status"] == "running":
                    rec["status"] = "interrupted"
                    rec["error"] = "Engine restarted while execution was in progress"
                    rec["completed_at"] = _now_iso()
                    count += 1
            return count
        # BH3-055: Set ContextVar so RLS allows the UPDATE. Without this,
        # default=0 at startup → zero rows updated.
        from sentinel.core.context import current_user_id
        ctx_token = current_user_id.set(1)
        try:
            return await self._cleanup_stale_pg()
        finally:
            current_user_id.reset(ctx_token)

    async def _cleanup_stale_pg(self) -> int:
        """PG implementation of cleanup_stale (called with ContextVar set).

        BH3-054: Logs individual interrupted executions so the operator knows
        exactly which routines were lost on restart.
        """
        async with self._pool.acquire() as conn:
            # Fetch details before updating so we can log them
            stale_rows = await conn.fetch(
                "SELECT execution_id, routine_id, started_at "
                "FROM routine_executions WHERE status = 'running'",
            )
            if not stale_rows:
                return 0
            for row in stale_rows:
                logger.warning(
                    "Interrupted stale routine execution on restart",
                    extra={
                        "event": "routine_execution_interrupted",
                        "execution_id": row["execution_id"],
                        "routine_id": row["routine_id"],
                        "started_at": str(row["started_at"]),
                    },
                )
            result = await conn.execute(
                "UPDATE routine_executions "
                "SET status = 'interrupted', "
                "error = 'Engine restarted while execution was in progress', "
                "completed_at = NOW() "
                "WHERE status = 'running'",
            )
            # asyncpg returns "UPDATE N"
            return int(result.split()[-1]) if result else 0

    async def get_execution_history(
        self,
        routine_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        if self._in_memory:
            matching = [
                dict(rec)
                for rec in self._mem_executions.values()
                if rec["routine_id"] == routine_id
            ]
            matching.sort(key=lambda r: r["started_at"], reverse=True)
            return matching[offset : offset + limit]
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT execution_id, routine_id, user_id, triggered_by, "
                "started_at, completed_at, status, result_summary, error, task_id "
                "FROM routine_executions "
                "WHERE routine_id = $1 "
                "ORDER BY started_at DESC "
                "LIMIT $2 OFFSET $3",
                routine_id, limit, offset,
            )
            return [
                {
                    "execution_id": r["execution_id"],
                    "routine_id": r["routine_id"],
                    "user_id": r["user_id"],
                    "triggered_by": r["triggered_by"],
                    "started_at": _dt_to_iso(r["started_at"]),
                    "completed_at": _dt_to_iso(r["completed_at"]),
                    "status": r["status"],
                    "result_summary": r["result_summary"],
                    "error": r["error"],
                    "task_id": r["task_id"],
                }
                for r in rows
            ]

    async def get_execution_stats(self, cutoff: str | None = None) -> dict:
        if self._in_memory:
            recs = list(self._mem_executions.values())
            if cutoff is not None:
                recs = [r for r in recs if r["started_at"] >= cutoff]
            counts: dict[str, int] = {}
            for r in recs:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            total = sum(counts.values())
            durations: list[float] = []
            for r in recs:
                if r["completed_at"] and r["started_at"]:
                    try:
                        s = _parse_iso(r["started_at"])
                        e = _parse_iso(r["completed_at"])
                        d = (e - s).total_seconds()
                        if d >= 0:
                            durations.append(d)
                    except (ValueError, TypeError):
                        pass
            avg_duration = round(sum(durations) / len(durations), 1) if durations else 0.0
            return {
                "total": total,
                "success": counts.get("success", 0),
                "error": counts.get("error", 0),
                "timeout": counts.get("timeout", 0),
                "avg_duration_s": avg_duration,
            }

        async with self._pool.acquire() as conn:
            if cutoff is not None:
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM routine_executions "
                    "WHERE started_at >= $1::timestamptz GROUP BY status",
                    cutoff,
                )
            else:
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM routine_executions "
                    "GROUP BY status",
                )
            counts_db = {r["status"]: r["cnt"] for r in rows}

            total = sum(counts_db.values())
            success = counts_db.get("success", 0)
            error = counts_db.get("error", 0)
            timeout = counts_db.get("timeout", 0)

            # Average duration from completed executions
            if cutoff is not None:
                dur_rows = await conn.fetch(
                    "SELECT EXTRACT(EPOCH FROM (completed_at - started_at)) AS dur "
                    "FROM routine_executions "
                    "WHERE started_at >= $1::timestamptz AND completed_at IS NOT NULL",
                    cutoff,
                )
            else:
                dur_rows = await conn.fetch(
                    "SELECT EXTRACT(EPOCH FROM (completed_at - started_at)) AS dur "
                    "FROM routine_executions WHERE completed_at IS NOT NULL",
                )
            durations_db = [r["dur"] for r in dur_rows if r["dur"] is not None and r["dur"] >= 0]
            avg_duration = round(sum(durations_db) / len(durations_db), 1) if durations_db else 0.0

            return {
                "total": total,
                "success": success,
                "error": error,
                "timeout": timeout,
                "avg_duration_s": avg_duration,
            }

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
        routine = await self._store.get(routine_id)
        if routine is None:
            return None
        return await self._spawn_execution(routine, triggered_by="manual")

    async def seed_defaults(self, user_id: int = 1) -> list[str]:
        """Create starter routine templates if the user has no routines.

        Returns a list of created routine IDs (empty if user already has routines).
        """
        if await self._store.count_for_user(user_id) > 0:
            return []

        created = []

        # Daily summary — runs at 09:00 UTC every day
        r1 = await self._store.create(
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
        r2 = await self._store.create(
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


if TYPE_CHECKING:
    from sentinel.core.store_protocols import RoutineEngineProtocol

    _: RoutineEngineProtocol = cast(RoutineEngineProtocol, RoutineEngine.__new__(RoutineEngine))
