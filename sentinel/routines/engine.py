"""Routine engine — scheduler loop, event triggers, and execution management.

Runs as a background asyncio task during the app lifespan.  Checks for due
routines on a configurable interval, subscribes to the event bus for
event-triggered routines, and manages concurrent executions with timeouts.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import uuid
from datetime import timedelta
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any, cast

from sentinel.core.context import PrincipalRequiredError, current_user_id, spawn_task
from sentinel.core.exceptions import ToolBlockedError
from sentinel.core.models import DataSource, TrustLevel
from sentinel.routines.cron import next_run as cron_next_run
from sentinel.routines.stats import (
    _LOG_PREVIEW_LIMIT,
    RoutineStats,
    _now_iso,
    _now_utc,
    _parse_iso,
)
from sentinel.security.provenance import create_tagged_data

if TYPE_CHECKING:
    from sentinel.core.bus import EventBus
    from sentinel.core.models import TaskResult
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.routines.store import Routine, RoutineStore

logger = logging.getLogger(__name__)

_STARVATION_THRESHOLD = 3  # consecutive ticks at max concurrency before ERROR alert
_MAX_ITERATIONS_CAP = 50  # hard ceiling on routine iteration count
_CLEANUP_BACKOFF_SECONDS = 300  # 5 min backoff after update_run_state failure


def compute_next_run_at(
    trigger_type: str,
    trigger_config: dict,
    enabled: bool,
) -> str | None:
    """Compute the initial or recomputed next_run_at for a routine.

    Returns an ISO-8601 UTC string, or None if the routine should not be
    scheduled (disabled, event-triggered, or invalid config).
    """
    if not enabled:
        return None
    if trigger_type == "cron":
        cron_expr = trigger_config.get("cron", "")
        if not cron_expr:
            return None
        try:
            dt = cron_next_run(cron_expr)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except (ValueError, KeyError):
            return None
    if trigger_type == "interval":
        seconds = trigger_config.get("seconds", 0)
        if not isinstance(seconds, (int, float)) or seconds <= 0:
            return None
        dt = _now_utc() + timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    # Event triggers and unknown types have no scheduled next_run_at
    return None


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
        self._admin_pool = admin_pool
        self._tick_interval = tick_interval
        self._max_concurrent = max_concurrent
        self._execution_timeout = execution_timeout
        self._classifier = classifier
        self._fast_path = fast_path

        # Execution record storage (DB or in-memory)
        self._stats = RoutineStats(pool=pool, admin_pool=admin_pool)

        self._scheduler_task: asyncio.Task | None = None
        # Q5.fix.e D3a: value is (task, routine_id) tuple so routine-scoped
        # cancel can find in-flight executions without parsing task names.
        self._running: dict[str, tuple[asyncio.Task, str]] = {}
        # CRIT-10 G1: claimed routine_ids — synchronously populated in
        # _spawn_execution before any await to close the TOCTOU dedup gap
        # between the dedup check and the _running write.
        self._claiming: set[str] = set()
        self._stopped = False
        self._starvation_ticks = 0  # Finding #8: consecutive ticks at max concurrency

    # -- lifecycle --

    async def start(self) -> None:
        """Start the scheduler loop and subscribe to event bus.

        On startup, marks any executions left in 'running' state as
        'interrupted' — these are stale from a previous engine crash/restart
        and would otherwise block max_concurrent slots forever.
        """
        self._stopped = False

        # Clean up stale executions from previous engine instance
        stale_count = await self._stats.cleanup_stale()
        if stale_count > 0:
            logger.warning(
                "Marked stale executions as interrupted",
                extra={
                    "event": "routine.stale_cleanup",
                    "count": stale_count,
                },
            )

        await self._backfill_null_next_run_at()

        # Scheduler is infrastructure: empty Context isolates from bootstrap user-1
        # (lifecycle.py:391). _spawn_execution re-pins per-routine inside its body
        # per Q6-FL1 (C36.fix). FL-C36-a1 cure: D32 helper centralises empty-Context
        # invariant for both create_task and add_done_callback.
        self._scheduler_task = self._create_scheduler_task()
        self._event_bus.subscribe("*", self._on_event)
        logger.info(
            "Routine engine started",
            extra={
                "event": "routine.engine_start",
                "tick_interval": self._tick_interval,
                "max_concurrent": self._max_concurrent,
            },
        )

    _STOP_TIMEOUT = 10  # seconds to wait for cancelled routines
    # Q5.fix.e D3a: bounded wait for cancel_routine_executions — matches the
    # 5s budget in §Design D3d, smaller than engine-wide _STOP_TIMEOUT because
    # it's per-routine, not shutdown.
    _CANCEL_WAIT_TIMEOUT = 5

    async def stop(self) -> None:
        """Stop the scheduler and cancel all running executions."""
        self._stopped = True

        if self._scheduler_task is not None:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                logger.debug(
                    "stop: scheduler CancelledError suppressed",
                    extra={"event": "engine.stop.scheduler_cancelled"},
                    exc_info=True,
                )
            self._scheduler_task = None

        # Cancel all running executions and wait with a timeout (SYS-5b)
        if self._running:
            # Q5.fix.e D3a: _running values are (task, routine_id) tuples.
            tasks = [task for (task, _routine_id) in self._running.values()]
            execution_ids = list(self._running.keys())
            for task in tasks:
                task.cancel()
            done, pending = await asyncio.wait(tasks, timeout=self._STOP_TIMEOUT)
            if pending:
                stale_ids = [
                    eid
                    for eid, t in zip(execution_ids, tasks, strict=True)
                    if t in pending
                ]
                logger.warning(
                    "Routine engine: %d tasks did not stop within %ds timeout",
                    len(pending),
                    self._STOP_TIMEOUT,
                    extra={
                        "event": "routine.stop_timeout",
                        "pending_count": len(pending),
                        "pending_ids": stale_ids,
                    },
                )
        self._running.clear()

        try:
            self._event_bus.unsubscribe("*", self._on_event)
        except Exception:  # catch-all: cleanup best-effort
            logger.debug(
                "stop: unsubscribe failed",
                extra={"event": "engine.stop.unsubscribe_failed"},
                exc_info=True,
            )

        logger.info("Routine engine stopped", extra={"event": "routine.engine_stop"})

    def _on_scheduler_done(self, task: asyncio.Task) -> None:
        """Finding #4: Restart the scheduler if it exited unexpectedly."""
        if self._stopped:
            return  # Normal shutdown — don't restart
        exc = task.exception() if not task.cancelled() else None
        if exc is not None:
            logger.error(
                "Scheduler loop died unexpectedly, restarting",
                extra={"event": "routine.scheduler_crash", "error": str(exc)},
            )
        elif task.cancelled():
            logger.warning(
                "Scheduler loop was cancelled unexpectedly, restarting",
                extra={"event": "routine.scheduler_cancelled"},
            )
        else:
            logger.warning(
                "Scheduler loop exited without stop(), restarting",
                extra={"event": "routine.scheduler_unexpected_exit"},
            )
        # Infrastructure: scheduler restart — empty Context for both task and
        # callback isolates from this callback's registration-time captured
        # context (which would otherwise be the bootstrap-scope user-1).
        self._scheduler_task = self._create_scheduler_task()

    def _create_scheduler_task(self) -> asyncio.Task:
        """Create the scheduler task with an explicit empty contextvars.Context.

        The scheduler is infrastructure (manages routines across all users); it
        must run with current_user_id at its default (0), NOT inheriting the
        bootstrap-scope user_id=1 set at lifecycle.py:391 to satisfy routines-
        table RLS INSERT. The done-callback is registered with its own fresh
        empty Context so the restart path doesn't inherit registration-time
        ambient context. See D32 design doc for the full rationale; this is the
        FL-C36-a1 cure (companion to C36.fix's _spawn_execution-side pin).
        """
        task = asyncio.create_task(
            self._scheduler_loop(),
            name="routine-scheduler",
            context=contextvars.Context(),
        )
        task.add_done_callback(
            self._on_scheduler_done,
            context=contextvars.Context(),
        )
        return task

    # -- scheduler loop --

    async def _scheduler_loop(self) -> None:
        """Periodic check for due routines."""
        while not self._stopped:
            try:
                await self._check_due_routines()
            except Exception as exc:  # catch-all: scheduler loop isolation
                logger.warning(
                    "Scheduler tick error",
                    extra={"event": "routine.scheduler_error", "error": str(exc)},
                    exc_info=True,
                )
            await asyncio.sleep(self._tick_interval)

    async def _check_due_routines(self) -> None:
        """Find routines whose next_run_at has passed and execute them.

        Finding #6: Admin pool bypasses Row-Level Security to discover routines
        across all users. Each routine's execution runs under the routine
        owner's user_id via current_user_id contextvar — pinned at _spawn_execution
        entry per Q6-FL1 (with _execute_routine retaining a defensive inner pin).
        If admin_pool is None, falls back to the regular pool (single-user mode).
        """
        now = _now_iso()
        due = await self._store.list_due_all_users(now, admin_pool=self._admin_pool)

        # Build in-flight set once; includes _claiming to close the TOCTOU gap
        # between dedup check and _running write (process-local, single-engine).
        running_routine_ids = {rid for (_, rid) in self._running.values()} | self._claiming
        for routine in due:
            if self._in_cooldown(routine):
                continue
            if routine.routine_id in running_routine_ids:
                logger.info(
                    "Skipping in-flight routine",
                    extra={
                        "event": "routine.dedup_skip",
                        "routine_id": routine.routine_id,
                    },
                )
                continue
            if len(self._running) >= self._max_concurrent:
                # Finding #8: Track consecutive starvation ticks
                self._starvation_ticks += 1
                logger.warning(
                    "Max concurrent routines reached, skipping remaining due routines",
                    extra={
                        "event": "routine.max_concurrent",
                        "running": len(self._running),
                        "skipped_routine": routine.routine_id,
                        "consecutive_starvation_ticks": self._starvation_ticks,
                    },
                )
                if self._starvation_ticks >= _STARVATION_THRESHOLD:
                    logger.error(
                        "Routine starvation: %d consecutive ticks at max concurrency — "
                        "routines may be starved indefinitely",
                        self._starvation_ticks,
                        extra={
                            "event": "routine.starvation_alert",
                            "consecutive_ticks": self._starvation_ticks,
                        },
                    )
                break
            await self._spawn_execution(routine, triggered_by="scheduler")
        else:
            # All due routines were processed — reset starvation counter
            self._starvation_ticks = 0

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
            enabled_only=True,
            admin_pool=self._admin_pool,
        )

        running_routine_ids = {rid for (_, rid) in self._running.values()} | self._claiming
        for routine in routines:
            event_pattern = routine.trigger_config.get("event", "")
            if not event_pattern:
                continue
            if fnmatch(topic, event_pattern):
                if self._in_cooldown(routine):
                    continue
                if routine.routine_id in running_routine_ids:
                    continue
                if len(self._running) >= self._max_concurrent:
                    break
                # BH3-053: Catch spawn failures so remaining routines still fire
                try:
                    await self._spawn_execution(
                        routine,
                        triggered_by=f"event:{topic}",
                    )
                except Exception as exc:  # catch-all: routine spawn isolation
                    logger.warning(
                        "Failed to spawn event-triggered routine %s: %s",
                        routine.routine_id,
                        exc,
                        extra={
                            "event": "routine.event_spawn_error",
                            "routine_id": routine.routine_id,
                            "topic": topic,
                            "error": str(exc),
                        },
                        exc_info=True,
                    )

    # -- execution management --

    async def _spawn_execution(self, routine: Routine, triggered_by: str) -> str:
        """Create an execution record and spawn the async task.

        Q6-FL1: pins ``current_user_id`` to ``routine.user_id`` before any
        user-scoped side effect (``record_start`` RLS INSERT,
        ``routine.triggered`` publish, log emit) and across the ``spawn_task``
        boundary so the child task inherits the routine-owner principal.
        ``_execute_routine`` retains its own set/reset as a defensive
        execution-boundary pin for any future direct callers.
        """
        # Claim the routine_id synchronously before any await (CRIT-10 G1): closes
        # the TOCTOU gap where concurrent _on_event or _check_due_routines calls
        # could both see the routine as not-in-flight and double-spawn.
        self._claiming.add(routine.routine_id)
        ctx_token = current_user_id.set(routine.user_id)
        try:
            execution_id = str(uuid.uuid4())

            # Record execution start
            await self._stats.record_start(
                execution_id,
                routine.routine_id,
                routine.user_id,
                triggered_by,
            )

            # Emit event
            try:
                await self._event_bus.publish(
                    "routine.triggered",
                    {
                        "routine_id": routine.routine_id,
                        "execution_id": execution_id,
                        "triggered_by": triggered_by,
                        "name": routine.name,
                        "user_id": routine.user_id,
                    },
                )
            except Exception as pub_exc:  # catch-all: event publish best-effort
                logger.debug(
                    "Failed to publish routine.triggered event: %s",
                    pub_exc,
                    extra={
                        "event": "engine.bus_publish_failed",
                        "topic": "routine.triggered",
                        "error": str(pub_exc),
                    },
                )

            logger.info(
                "Routine triggered",
                extra={
                    "event": "routine.triggered",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                    "triggered_by": triggered_by,
                    "routine_name": routine.name,
                },
            )

            task = spawn_task(
                self._execute_routine(routine, execution_id, triggered_by)
            )
            # Q5.fix.e D3a: store (task, routine_id) so cancel_routine_executions
            # can filter by routine without parsing task names.
            self._running[execution_id] = (task, routine.routine_id)

            # Clean up when done
            def _cleanup(t: asyncio.Task) -> None:
                self._running.pop(execution_id, None)

            task.add_done_callback(_cleanup)

            return execution_id
        finally:
            # Release claim on all exit paths — including CancelledError (a
            # BaseException subclass since Python 3.8, not caught by except Exception).
            # Leaving a stale claim permanently suppresses the routine on next tick.
            self._claiming.discard(routine.routine_id)
            current_user_id.reset(ctx_token)

    async def cancel_routine_executions(self, routine_id: str) -> int:
        """Cancel all in-flight executions for a routine, bounded wait for teardown.

        Iterates ``self._running`` for entries whose routine_id matches, calls
        ``task.cancel()`` on each, then awaits up to ``_CANCEL_WAIT_TIMEOUT``
        seconds for them to observe CancelledError and terminate. Returns the
        number of tasks that were asked to cancel (not the number that
        completed within the wait budget — a straggler is logged but still
        counted). Safe to call concurrently with normal completion: the
        ``add_done_callback`` cleanup removes entries when the task exits.

        Used by the routine DELETE handler between the pre-cancel cascade
        (approvals + confirmations) and the post-wait TX cascade
        (approvals + confirmations + sessions + routines). See
        ``docs/hardening/2026-04-20-hardening-Q5-ttl-coupling-findings.md``
        §Design D3.

        **Scheduler-visible residual** (Q5.fix.e merge-gate Codex thread
        ``019dc075-92d2-7352-b203-1c4590f77fe4``, Option B 2026-04-24): this
        method only cancels tasks present in ``_running`` at snapshot time.
        Between the snapshot and the caller's final ``DELETE FROM routines``,
        the scheduler tick (``_check_due_routines``), event-trigger path
        (``_on_event``), or manual trigger (``trigger_manual``) can spawn a
        fresh execution for the same routine_id. That new task is NOT
        cancelled here; its approval INSERTs on
        ``routine:{id}:{new_exec_id}`` become orphans once the routine row
        is gone. User-accepted residual, backstopped by
        ``ApprovalManager.purge_old(days=7)`` via the F7 scheduler. See
        ``RoutineStore.delete`` docstring for the full residual analysis.
        """
        to_cancel: list[asyncio.Task] = [
            task for (task, owner) in self._running.values() if owner == routine_id
        ]
        if not to_cancel:
            logger.debug(
                "cancel_routine_executions: match",
                extra={
                    "event": "engine.cancel_routine_executions.match",
                    "reason": "no_in_flight_executions",
                    "routine_id": routine_id,
                },
            )  # auto:neg
            return 0
        for task in to_cancel:
            task.cancel()
        logger.info(
            "Cancelling routine executions for delete",
            extra={
                "event": "engine.cancel_routine_executions",
                "routine_id": routine_id,
                "cancelled_count": len(to_cancel),
            },
        )
        _done, pending = await asyncio.wait(
            to_cancel, timeout=self._CANCEL_WAIT_TIMEOUT
        )
        if pending:
            logger.warning(
                "cancel_routine_executions: %d tasks did not terminate within %ds",
                len(pending),
                self._CANCEL_WAIT_TIMEOUT,
                extra={
                    "event": "engine.cancel_routine_executions.timeout",
                    "routine_id": routine_id,
                    "pending_count": len(pending),
                },
            )
        return len(to_cancel)

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
            logger.debug(
                "_execute_routine_inner: not_prompt",
                extra={
                    "event": "engine._execute_routine_inner.match",
                    "reason": "not_prompt",
                },
            )  # auto:neg
            await self._record_execution_result(
                execution_id,
                "error",
                error="No prompt in action_config",
            )
            return

        # Finding #1: Default to "full" for user-created routines — require human
        # approval for plan execution. "auto" is only set explicitly by seed_defaults()
        # for system routines.
        approval_mode = routine.action_config.get("approval_mode", "full")
        max_iterations = min(
            routine.action_config.get("max_iterations", 1), _MAX_ITERATIONS_CAP
        )
        now = _now_iso()

        if max_iterations <= 1:
            logger.debug(
                "_execute_routine_inner: max_iterations_lte_1",
                extra={
                    "event": "engine._execute_routine_inner.match",
                    "reason": "max_iterations_lte_1",
                },
            )  # auto:neg
            await self._run_single_iteration(
                prompt, routine, execution_id, approval_mode
            )
        else:
            logger.debug(
                "_execute_routine_inner: max_iterations_lte_1",
                extra={
                    "event": "engine._execute_routine_inner.clean",
                    "reason": "max_iterations_lte_1",
                },
            )  # auto:neg
            per_iteration_timeout = routine.action_config.get(
                "per_iteration_timeout",
                self._execution_timeout,
            )
            await self._run_multi_turn_loop(
                prompt,
                routine,
                execution_id,
                approval_mode,
                max_iterations,
                per_iteration_timeout,
            )

        # Update routine run state; if it fails, log and apply a backoff so the
        # routine doesn't re-spawn at tick speed (D6).
        # PrincipalRequiredError is re-raised: swallowing it defeats the fail-closed invariant.
        try:
            next_at = self._calculate_next_run(routine)
            await self._store.update_run_state(
                routine.routine_id,
                last_run_at=now,
                next_run_at=next_at,
            )
        except PrincipalRequiredError:
            raise
        except Exception:
            logger.warning(
                "Post-execution state update failed, applying backoff",
                extra={
                    "event": "routine.update_run_state_failed",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                },
                exc_info=True,
            )
            # Backoff: only scheduled routines benefit from a future next_run_at;
            # event-triggered routines must stay at next_run_at=None or the scheduler
            # would pick them up on the next tick (F1).
            backoff_next_at: str | None
            if routine.trigger_type in ("cron", "interval"):
                backoff_dt = _now_utc() + timedelta(seconds=_CLEANUP_BACKOFF_SECONDS)
                backoff_next_at = backoff_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            else:
                backoff_next_at = None
            try:
                await self._store.update_run_state(
                    routine.routine_id,
                    last_run_at=now,
                    next_run_at=backoff_next_at,
                )
            except PrincipalRequiredError:
                raise
            except Exception:
                logger.error(
                    "Backoff state update also failed",
                    extra={
                        "event": "routine.update_run_state_backoff_failed",
                        "routine_id": routine.routine_id,
                    },
                    exc_info=True,
                )

        # Emit completion event
        try:
            await self._event_bus.publish(
                "routine.executed",
                {
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                    "triggered_by": triggered_by,
                    "name": routine.name,
                    "user_id": routine.user_id,
                },
            )
        except Exception as pub_exc:  # catch-all: event publish best-effort
            logger.debug(
                "Failed to publish routine.executed event: %s",
                pub_exc,
                extra={
                    "event": "engine.bus_publish_failed",
                    "topic": "routine.executed",
                    "error": str(pub_exc),
                },
            )

    async def _run_single_iteration(
        self,
        prompt: str,
        routine: Routine,
        execution_id: str,
        approval_mode: str,
    ) -> None:
        """Single-iteration execution: try fast-path, fall back to planner.

        BH3-011: Timeout prevents a hanging tool from permanently consuming
        a _max_concurrent slot.
        """
        try:
            result = await asyncio.wait_for(
                self._try_fast_path(prompt, routine, execution_id),
                timeout=self._execution_timeout,
            )
        except TimeoutError:
            logger.warning(
                "Fast-path timed out after %ds",
                self._execution_timeout,
                extra={
                    "event": "engine.fastpath_timeout",
                    "execution_id": execution_id,
                    "routine_id": routine.routine_id,
                },
                exc_info=True,
            )
            await self._record_execution_result(
                execution_id,
                "timeout",
                error=f"Fast-path timed out after {self._execution_timeout}s",
            )
            result = ...  # sentinel to skip both branches below
        except asyncio.CancelledError:
            logger.debug(
                "Fast-path cancelled",
                extra={
                    "event": "engine.fastpath_cancelled",
                    "execution_id": execution_id,
                },
            )
            await self._record_execution_result(
                execution_id,
                "cancelled",
                error="Fast-path cancelled",
            )
            raise

        if result is ...:
            pass  # already recorded above
        elif result is not None:
            # Fast-path succeeded
            logger.debug(
                "Fast-path succeeded",
                extra={
                    "event": "engine.fastpath_success",
                    "execution_id": execution_id,
                    "status": result.status,
                },
            )
            await self._record_execution_result(
                execution_id,
                status=result.status,
                result_summary=result.plan_summary,
                task_id=result.task_id,
            )
        else:
            # Planner path (original behaviour) — fast-path returned None
            logger.debug(
                "Fast-path not applicable, falling back to planner",
                extra={
                    "event": "engine.planner_fallback",
                    "execution_id": execution_id,
                    "routine_id": routine.routine_id,
                },
            )
            # Q8.fix.c — replay-time UNTRUSTED wrap. The stored routine prompt
            # has no provenance at rest (create-time tag deferred to Q2-U1 per
            # fix-design §D3); mint the ingress tag here so S3 provenance
            # enforcement downstream treats routine-replay user_request as
            # UNTRUSTED. Fail-closed: routine replay never accepts a caller
            # trust assertion (stored prompt is plain str by definition).
            #
            # The mint is inside the try block so a provenance-store failure
            # (e.g. PG persistence error at `create_tagged_data`) is caught
            # by the existing routine-execution-isolation handlers below
            # rather than escaping the spawned background task and leaving
            # the execution row in `running` state forever.
            source_key = f"routine:{routine.routine_id}:{execution_id}"
            try:
                replay_tagged = await create_tagged_data(
                    content=prompt,
                    source=DataSource.USER,
                    trust_level=TrustLevel.UNTRUSTED,
                    originated_from=f"ingress:routine:replay:{source_key}",
                )
                user_request_data_id = replay_tagged.id
                logger.info(
                    "Routine replay tagged UNTRUSTED",
                    extra={
                        "event": "engine.replay_tagged",
                        "execution_id": execution_id,
                        "routine_id": routine.routine_id,
                        "data_id": user_request_data_id,
                        "request_len": len(prompt),
                    },
                )
                result = await asyncio.wait_for(
                    self._orchestrator.handle_task(
                        user_request=prompt,
                        source=f"routine:{routine.routine_id}",
                        approval_mode=approval_mode,
                        source_key=source_key,
                        task_id=execution_id,
                        user_request_data_id=user_request_data_id,
                    ),
                    timeout=self._execution_timeout,
                )

                await self._record_execution_result(
                    execution_id,
                    status=result.status,
                    result_summary=result.plan_summary,
                    task_id=result.task_id,
                )

            except TimeoutError:
                logger.warning(
                    "Planner execution timed out after %ds",
                    self._execution_timeout,
                    extra={
                        "event": "engine.planner_timeout",
                        "execution_id": execution_id,
                        "routine_id": routine.routine_id,
                    },
                    exc_info=True,
                )
                await self._record_execution_result(
                    execution_id,
                    "timeout",
                    error=f"Execution timed out after {self._execution_timeout}s",
                )
            except asyncio.CancelledError:
                logger.debug(
                    "Planner execution cancelled",
                    extra={
                        "event": "engine.planner_cancelled",
                        "execution_id": execution_id,
                    },
                )
                await self._record_execution_result(
                    execution_id,
                    "cancelled",
                    error="Execution cancelled",
                )
                raise
            except PrincipalRequiredError:
                # Q4.fix.f Coord follow-up: zero-principal must propagate past
                # the planner-path execution-isolation swallow so the
                # fail-closed invariant is preserved. Without this narrow, a
                # routine with routine.user_id=0 would silently record
                # "error" status via the broad swallow below instead of
                # hard-failing at the producer boundary.
                raise
            except Exception as exc:  # catch-all: routine execution isolation
                logger.warning(
                    "_run_single_iteration: planner exception",
                    extra={"event": "engine.single_iteration_error"},
                    exc_info=True,
                )
                await self._record_execution_result(
                    execution_id,
                    "error",
                    error=str(exc),
                )

    async def _run_multi_turn_loop(
        self,
        prompt: str,
        routine: Routine,
        execution_id: str,
        approval_mode: str,
        max_iterations: int,
        per_iteration_timeout: int,
    ) -> None:
        """Multi-turn iteration loop with context carry-forward."""
        context = ""
        final_result = None
        source_key = f"routine:{routine.routine_id}:{execution_id}"
        for iteration in range(1, max_iterations + 1):
            iter_prompt = prompt
            if context:
                iter_prompt += (
                    f"\n\n--- Previous iteration ({iteration - 1}) result ---\n"
                    f"{context}"
                )

            # Q8.fix.c — replay-time UNTRUSTED wrap per iteration. Wraps the
            # combined `iter_prompt` (stored prompt + prior-iteration context
            # prepend). Per fix-design §D1 row #7, the prior-iteration context
            # is Orchestrator-origin but once it re-enters handle_task the
            # combined string is treated as UNTRUSTED for this turn.
            #
            # The mint is inside the try block so a provenance-store failure
            # at `create_tagged_data` is caught by the existing per-iteration
            # execution-isolation handlers below rather than escaping the
            # spawned background task mid-loop.
            try:
                iter_tagged = await create_tagged_data(
                    content=iter_prompt,
                    source=DataSource.USER,
                    trust_level=TrustLevel.UNTRUSTED,
                    originated_from=f"ingress:routine:replay:{source_key}",
                )
                user_request_data_id = iter_tagged.id
                logger.info(
                    "Routine multi-turn iteration tagged UNTRUSTED",
                    extra={
                        "event": "engine.multi_turn_iteration_tagged",
                        "execution_id": execution_id,
                        "routine_id": routine.routine_id,
                        "iteration": iteration,
                        "data_id": user_request_data_id,
                        "request_len": len(iter_prompt),
                    },
                )
                result = await asyncio.wait_for(
                    self._orchestrator.handle_task(
                        user_request=iter_prompt,
                        source=f"routine:{routine.routine_id}",
                        approval_mode=approval_mode,
                        source_key=source_key,
                        task_id=execution_id,
                        user_request_data_id=user_request_data_id,
                    ),
                    timeout=per_iteration_timeout,
                )

                self._record_iteration(
                    execution_id,
                    iteration,
                    result.status,
                    result.plan_summary,
                )
                final_result = result

                # Check for done signal or error/blocked status
                if self._is_done_signal(result):
                    await self._record_execution_result(
                        execution_id,
                        "complete",
                        result_summary=result.plan_summary,
                        task_id=result.task_id,
                    )
                    break

                if result.status in ("blocked", "error"):
                    await self._record_execution_result(
                        execution_id,
                        result.status,
                        result_summary=result.plan_summary,
                        task_id=result.task_id,
                    )
                    break

                # Carry forward context for next iteration
                context = result.plan_summary or ""

            except TimeoutError:
                logger.warning(
                    "Iteration %d timed out after %ds",
                    iteration,
                    per_iteration_timeout,
                    extra={
                        "event": "engine.iteration_timeout",
                        "execution_id": execution_id,
                        "iteration": iteration,
                    },
                    exc_info=True,
                )
                await self._record_execution_result(
                    execution_id,
                    "timeout",
                    error=(
                        f"Iteration {iteration} timed out after "
                        f"{per_iteration_timeout}s"
                    ),
                )
                break
            except asyncio.CancelledError:
                logger.debug(
                    "Cancelled during iteration %d",
                    iteration,
                    extra={
                        "event": "engine.iteration_cancelled",
                        "execution_id": execution_id,
                        "iteration": iteration,
                    },
                )
                await self._record_execution_result(
                    execution_id,
                    "cancelled",
                    error=f"Cancelled during iteration {iteration}",
                )
                raise
            except Exception as exc:  # catch-all: routine iteration isolation
                logger.warning(
                    "_run_multi_turn_loop: iteration exception",
                    extra={
                        "event": "engine.multi_turn_error",
                        "iteration": iteration,
                    },
                    exc_info=True,
                )
                await self._record_execution_result(
                    execution_id,
                    "error",
                    error=f"Iteration {iteration}: {exc}",
                )
                break
        else:
            # Exhausted max_iterations without done signal
            if final_result is not None:
                await self._record_execution_result(
                    execution_id,
                    final_result.status,
                    result_summary=final_result.plan_summary,
                    task_id=final_result.task_id,
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
        await self._stats.record_completion(
            execution_id,
            status,
            result_summary,
            error,
            task_id,
        )

        logger.info(
            "Routine execution completed",
            extra={
                "event": "routine.execution_complete",
                "execution_id": execution_id,
                "status": status,
                "error": error[:_LOG_PREVIEW_LIMIT] if error else "",
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
                "event": "routine.iteration",
                "execution_id": execution_id,
                "iteration": iteration,
                "status": status,
                "summary_preview": (result_summary or "")[:_LOG_PREVIEW_LIMIT],
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
        from sentinel.core.models import TaskResult  # runtime import for instantiation

        if self._classifier is None or self._fast_path is None:
            return None

        try:
            classification = await self._classifier.classify(prompt)
        except Exception:  # catch-all: classification fallback to planner
            logger.warning(
                "Routine fast-path classification failed, falling back to planner",
                extra={
                    "event": "routine.fastpath_classify_error",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                },
                exc_info=True,
            )
            return None

        if classification.is_planner:
            logger.debug(
                "Routine classified as planner: %s",
                classification.reason,
                extra={
                    "event": "routine.fastpath_planner",
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
        except PrincipalRequiredError:
            # Q4.fix.f Coord follow-up: zero-principal must propagate past
            # the fast-path fallback swallow so the fail-closed invariant
            # at router/fast_path.py:71 is preserved. Without this, a routine
            # with user_id=0 would silently fall back to the planner path
            # (which also now raises) instead of hard-failing at the producer.
            raise
        except ToolBlockedError as exc:
            # Q9-F3 Merge Coord follow-up: FastPathExecutor narrow-raises
            # ToolBlockedError past the broad swallow so D5 BLOCKED semantics
            # stay distinguishable from generic tool errors. Without this
            # absorption the broad `except Exception` below catches the block,
            # logs a generic fastpath_exec_error, returns None, and silently
            # re-tries via planner — defeating F3's operational goal for the
            # routine plane. Audit HIGH was already emitted by ToolExecutor.
            logger.warning(
                "Routine fast-path blocked by policy",
                extra={
                    "event": "routine.fastpath_blocked",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                    "template": classification.template_name,
                    "reason": str(exc),
                },
                exc_info=True,
            )
            return TaskResult(
                task_id=execution_id,
                status="blocked",
                plan_summary=f"Fast-path: {classification.template_name}",
                response=f"Tool blocked by policy: {exc}",
            )
        except Exception:  # catch-all: fast-path fallback to planner
            logger.warning(
                "Routine fast-path execution failed, falling back to planner",
                extra={
                    "event": "routine.fastpath_exec_error",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                    "template": classification.template_name,
                },
                exc_info=True,
            )
            return None

        # Error status from fast-path — fall back to planner for a better attempt
        if fp_result.get("status") not in ("success", "blocked"):
            logger.info(
                "Routine fast-path returned %s, falling back to planner",
                fp_result.get("status"),
                extra={
                    "event": "routine.fastpath_fallback",
                    "routine_id": routine.routine_id,
                    "execution_id": execution_id,
                    "template": classification.template_name,
                    "reason": fp_result.get("reason", ""),
                },
            )
            return None
        logger.debug(
            "_try_fast_path: condition_passed",
            extra={
                "event": "routine.fastpath_fallback.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        return TaskResult(
            task_id=execution_id,
            status=fp_result["status"],
            plan_summary=f"Fast-path: {classification.template_name}",
            response=fp_result.get("response", ""),
        )

    # -- delegation to RoutineStats (preserves RoutineEngineProtocol + test compat) --

    @property
    def _mem_executions(self) -> dict[str, dict]:
        """Backward-compat: tests access in-memory execution storage directly."""
        return self._stats._mem_executions

    async def record_start(
        self,
        execution_id: str,
        routine_id: str,
        user_id: int,
        triggered_by: str,
    ) -> None:
        await self._stats.record_start(execution_id, routine_id, user_id, triggered_by)

    async def record_completion(
        self,
        execution_id: str,
        status: str,
        result_summary: str = "",
        error: str = "",
        task_id: str = "",
    ) -> None:
        await self._stats.record_completion(
            execution_id, status, result_summary, error, task_id
        )

    async def cleanup_stale(self) -> int:
        return await self._stats.cleanup_stale()

    async def get_execution_history(
        self,
        routine_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        return await self._stats.get_execution_history(routine_id, limit, offset)

    async def get_execution_stats(self, cutoff: str | None = None) -> dict:
        return await self._stats.get_execution_stats(cutoff)

    # -- helpers --

    async def _backfill_null_next_run_at(self) -> int:
        """One-shot repair: seed next_run_at for enabled cron/interval routines
        created before CRIT-10 without a seed value.

        Uses admin_pool when available (bypasses RLS) to cover all users.
        Falls back to self._store._pool for single-user mode. Returns 0 if no
        pool is available (in-memory mode).
        """
        pool = self._admin_pool or self._store._pool
        if pool is None:
            return 0
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT routine_id, trigger_type, trigger_config "
                "FROM routines "
                "WHERE enabled = TRUE "
                "AND next_run_at IS NULL "
                "AND trigger_type IN ('cron', 'interval')"
            )
        repaired = 0
        for row in rows:
            try:
                trigger_config = row["trigger_config"]
                if isinstance(trigger_config, str):
                    trigger_config = json.loads(trigger_config)
                if not isinstance(trigger_config, dict):
                    trigger_config = {}
                next_at = compute_next_run_at(
                    row["trigger_type"], trigger_config, enabled=True
                )
                if next_at is not None:
                    async with pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE routines SET next_run_at = $1, updated_at = NOW() "
                            "WHERE routine_id = $2 AND next_run_at IS NULL",
                            _parse_iso(next_at),
                            row["routine_id"],
                        )
                    repaired += 1
            except Exception:
                logger.warning(
                    "Backfill skipped bad row",
                    extra={
                        "event": "routine.backfill_row_error",
                        "routine_id": row["routine_id"],
                    },
                    exc_info=True,
                )
        if repaired > 0:
            logger.info(
                "Backfilled next_run_at for legacy routines",
                extra={
                    "event": "routine.backfill_next_run_at",
                    "repaired_count": repaired,
                },
            )
        return repaired

    def _calculate_next_run(self, routine: Routine) -> str | None:
        """Calculate the next run time based on trigger type.

        Returns None for disabled routines, event triggers, and invalid configs.
        Exception handling mirrors compute_next_run_at (KeyError + ValueError).
        """
        if not routine.enabled:
            return None
        if routine.trigger_type == "cron":
            cron_expr = routine.trigger_config.get("cron", "")
            if cron_expr:
                try:
                    dt = cron_next_run(cron_expr)
                    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                except (ValueError, KeyError):
                    logger.debug("routines.next_run_calc_error", exc_info=True)
                    return None
            return None
        logger.debug(
            "_calculate_next_run: trigger_type_eq_cron_passed",
            extra={
                "event": "engine._calculate_next_run.trigger_type_eq_cron_passed",
                "reason": "trigger_type_eq_cron_passed",
            },
        )  # auto:neg

        if routine.trigger_type == "interval":
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
            logger.debug(
                "Cooldown parse failed, treating as not in cooldown",
                extra={
                    "event": "engine.cooldown_parse_error",
                    "routine_id": routine.routine_id,
                },
                exc_info=True,
            )
            return False

    # -- public API --

    async def trigger_manual(self, routine_id: str) -> str | None:
        """Manually trigger a routine. Returns execution_id or None if not found."""
        routine = await self._store.get(routine_id)
        if routine is None:
            return None
        return await self._spawn_execution(routine, triggered_by="manual")

    async def seed_defaults(self, user_id: int) -> list[str]:
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
            next_run_at=compute_next_run_at("cron", {"cron": "0 9 * * *"}, enabled=True),
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
            next_run_at=compute_next_run_at("cron", {"cron": "0 3 * * SUN"}, enabled=True),
        )
        created.append(r2.routine_id)

        logger.info(
            "Seeded default routines",
            extra={
                "event": "routine.seed_defaults",
                "user_id": user_id,
                "count": len(created),
            },
        )
        return created


if TYPE_CHECKING:
    from sentinel.core.store_protocols import RoutineEngineProtocol

    _: RoutineEngineProtocol = cast(
        "RoutineEngineProtocol", RoutineEngine.__new__(RoutineEngine)
    )
