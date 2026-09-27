"""Loop controller — persistent goal-pursuit wrapper over the orchestrator.

Calls orchestrator.handle_task() repeatedly with gap-driven enriched
requests until the goal is met or budget (iterations / wall-clock) is
exhausted. The orchestrator is treated as a black box.

Security: gap summaries and enriched requests never leak scanner names,
rule IDs, or security mechanism details. See _loop_gaps._sanitise_error().
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinel.core.models import TaskResult
from sentinel.crypto.blind_index import log_hash
from sentinel.planner._loop_gaps import (
    _REDACTED_ERROR,
    _sanitise_error,
    _scrub_critical_terms,
    build_enriched_request,
    synthesise_gap,
)

if TYPE_CHECKING:
    from sentinel.core.bus import EventBus
    from sentinel.planner.loop_store import LoopStore

logger = logging.getLogger(__name__)

# Event bus publish timeout — prevents a misbehaving subscriber handler
# from blocking the loop controller indefinitely.
_EVENT_PUBLISH_TIMEOUT = 5.0

# Statuses that should never be retried (approval denied, content refused,
# fast-path responses, security blocks, resource locks)
_NO_RETRY_STATUSES = frozenset({"success", "denied", "refused", "locked", "blocked"})

# Backward-compat re-exports — tests import these from loop_controller
__all__ = [
    "_REDACTED_ERROR",
    "LoopController",
    "LoopResult",
    "_sanitise_error",
    "_scrub_critical_terms",
    "build_enriched_request",
    "synthesise_gap",
]


@dataclass
class LoopResult:
    """Return value from run_loop — mirrors LoopState but always populated."""

    loop_id: str
    status: str
    iteration_count: int
    cancelled_at_iteration: int | None = None
    iterations: list[dict] = field(default_factory=list)


class LoopController:
    """Persistent goal-pursuit loop wrapping orchestrator.handle_task()."""

    def __init__(
        self,
        orchestrator,
        loop_store: LoopStore,
        event_bus: EventBus | None,
    ) -> None:
        self.orchestrator = orchestrator
        self.loop_store = loop_store
        self.event_bus = event_bus

    # ── Public entry point ─────────────────────────────────────

    async def run_loop(
        self,
        loop_id: str,
        user_id: int,
        request: str,
        max_iterations: int = 5,
        timeout_seconds: int = 3600,
        source: str = "api",
        source_key: str | None = None,
        execute_fn=None,
        user_request_data_id: str | None = None,
    ) -> LoopResult:
        """Drive gap-driven retry iterations until goal met or budget exhausted.

        Args:
            execute_fn: Optional async callable(user_request, source) -> TaskResult.
                        If provided, used instead of orchestrator.handle_task().
                        This allows routing through the message_router (fast path
                        + input scanning) while still getting loop retry.
            user_request_data_id: Q8.fix.b ingress-time TaggedData id. Threaded
                        through to orchestrator.handle_task() on the else-branch
                        (`/api/loop` direct route; `/api/task` supplies its own
                        `execute_fn` closure that carries its own data_id). The
                        SAME data_id is reused across every iteration — the
                        per-iteration enriched request is an internal transform
                        per fix-design §Internal transformations.

        This method is designed to be called via spawn_task() so the user's
        context (user_id, request_id) is propagated.
        """
        logger.debug(
            "run_loop: entry",
            extra={
                "event": "run.loop_entry",
                "loop_id": loop_id,
                "user_id": user_id,
                "request_len": len(request),
                "max_iterations": max_iterations,
                "timeout_seconds": timeout_seconds,
                "source_val": source,
                "has_execute_fn": execute_fn is not None,
                "user_request_data_id": user_request_data_id,
            },
        )
        await self._init_loop(
            loop_id,
            user_id,
            request,
            max_iterations,
            timeout_seconds,
        )

        start_time = time.monotonic()
        enriched_request = request
        iteration_history: list[dict] = []
        iteration_count = 0
        final_status = "failed"
        cancelled_at_iteration: int | None = None

        for iteration in range(1, max_iterations + 1):
            guard = await self._check_loop_guards(
                loop_id,
                iteration,
                start_time,
                timeout_seconds,
            )
            if guard is not None:
                final_status, cancelled_at_iteration = guard
                break

            logger.info(
                "loop: %s iteration %d/%d starting",
                loop_id,
                iteration,
                max_iterations,
                extra={
                    "event": "loop.iteration_start",
                    "loop_id": loop_id,
                    "iteration": iteration,
                },
            )

            iter_start = time.monotonic()
            result = await self._execute_iteration(
                execute_fn,
                enriched_request,
                source,
                loop_id,
                iteration,
                source_key=source_key,
                user_request_data_id=user_request_data_id,
            )
            iter_duration = time.monotonic() - iter_start
            iteration_count = iteration

            self._log_iteration_result(loop_id, iteration, result, iter_duration)
            is_success, is_terminal, judge_retry_mode = self._classify_iteration(
                loop_id, iteration, result
            )

            gap, iter_record = self._build_iteration_record(
                loop_id,
                iteration,
                enriched_request,
                result,
                is_success,
                judge_retry_mode,
                iter_duration,
            )
            iteration_history.append(iter_record)
            await self.loop_store.append_iteration(
                loop_id=loop_id,
                user_id=user_id,
                iteration=iter_record,
            )

            if is_success:
                final_status = "succeeded"
                logger.info(
                    "loop: %s iteration %d succeeded (%.1fs) — "
                    "STOPPING loop. status=%s, completion=%s",
                    loop_id,
                    iteration,
                    iter_duration,
                    result.status,
                    result.completion,
                    extra={
                        "event": "loop.iteration_success",
                        "loop_id": loop_id,
                        "iteration": iteration,
                        "result_status": result.status,
                        "result_completion": result.completion,
                        "duration_s": round(iter_duration, 1),
                    },
                )
                await self._publish(
                    loop_id,
                    "finished",
                    self._finished_event_data(
                        loop_id,
                        user_id,
                        "succeeded",
                        iteration,
                        max_iterations,
                        start_time,
                    ),
                )
                break

            if is_terminal:
                final_status = result.status
                logger.info(
                    "loop: %s iteration %d terminal status %s — "
                    "STOPPING loop (non-retryable). completion=%s",
                    loop_id,
                    iteration,
                    result.status,
                    result.completion,
                    extra={
                        "event": "loop.terminal",
                        "loop_id": loop_id,
                        "iteration": iteration,
                        "status": result.status,
                        "completion": result.completion,
                    },
                )
                break

            enriched_request = await self._prepare_retry(
                loop_id,
                user_id,
                iteration,
                result,
                gap,
                judge_retry_mode,
                request,
                iteration_history,
                max_iterations,
                start_time,
            )
        else:
            # for/else: loop exhausted without break — budget spent
            self._log_budget_exhausted(
                loop_id,
                max_iterations,
                start_time,
                iteration_history,
            )

        logger.debug(
            "run_loop: exit — delegating to _finalize_loop",
            extra={
                "event": "run.loop_exit",
                "loop_id": loop_id,
                "final_status": final_status,
                "iteration_count": iteration_count,
                "cancelled_at_iteration": cancelled_at_iteration,
            },
        )
        return await self._finalize_loop(
            loop_id,
            user_id,
            final_status,
            cancelled_at_iteration,
            iteration_count,
            iteration_history,
            max_iterations,
            start_time,
        )

    # ── Helpers: loop lifecycle ────────────────────────────────

    async def _init_loop(
        self,
        loop_id: str,
        user_id: int,
        request: str,
        max_iterations: int,
        timeout_seconds: int,
    ) -> None:
        """Create store record, publish started event, log entry."""
        await self.loop_store.create(
            loop_id=loop_id,
            user_id=user_id,
            original_request=request,
            max_iterations=max_iterations,
            timeout_seconds=timeout_seconds,
        )
        await self._publish(
            loop_id,
            "started",
            {
                "loop_id": loop_id,
                "user_id": user_id,
                "type": "started",
                "original_request": request[:200],
                "max_iterations": max_iterations,
                "timeout_seconds": timeout_seconds,
            },
        )
        logger.info(
            "loop: started %s (%d max, %ds timeout)",
            loop_id,
            max_iterations,
            timeout_seconds,
            extra={"event": "loop.started", "loop_id": loop_id, "user_id": user_id},
        )

    async def _check_loop_guards(
        self,
        loop_id: str,
        iteration: int,
        start_time: float,
        timeout_seconds: int,
    ) -> tuple[str, int | None] | None:
        """Check cancellation and wall-clock timeout before each iteration.

        Returns (final_status, cancelled_at_iteration) if the loop should
        stop, or None to continue.
        """
        logger.debug(
            "_check_loop_guards: entry",
            extra={
                "event": "check.loop_guards_entry",
                "loop_id": loop_id,
                "iteration": iteration,
                "elapsed_s": round(time.monotonic() - start_time, 1),
                "timeout_seconds": timeout_seconds,
            },
        )
        if await self.loop_store.is_cancelled(loop_id):
            logger.info(
                "loop: %s cancelled at iteration %d",
                loop_id,
                iteration,
                extra={"event": "loop.cancelled", "loop_id": loop_id},
            )
            return ("cancelled", iteration - 1)
        logger.debug(
            "_check_loop_guards: condition_passed",
            extra={"event": "loop.cancelled.passed", "reason": "condition_passed"},
        )  # auto:neg

        elapsed = time.monotonic() - start_time
        if elapsed >= timeout_seconds:
            logger.warning(
                "loop: %s timed out at iteration %d (%.1fs)",
                loop_id,
                iteration,
                elapsed,
                extra={"event": "loop.timeout", "loop_id": loop_id},
            )
            return ("timed_out", None)

        logger.debug(
            "_check_loop_guards: all checks passed",
            extra={
                "event": "check.loop_guards_passed",
                "loop_id": loop_id,
                "iteration": iteration,
            },
        )
        return None

    async def _finalize_loop(
        self,
        loop_id: str,
        user_id: int,
        final_status: str,
        cancelled_at_iteration: int | None,
        iteration_count: int,
        iteration_history: list[dict],
        max_iterations: int,
        start_time: float,
    ) -> LoopResult:
        """Set terminal status in store, publish finished event, return result."""
        await self.loop_store.set_status(
            loop_id=loop_id,
            user_id=user_id,
            status=final_status,
            cancelled_at_iteration=cancelled_at_iteration,
        )

        if final_status != "succeeded":
            await self._publish(
                loop_id,
                "finished",
                {
                    **self._finished_event_data(
                        loop_id,
                        user_id,
                        final_status,
                        iteration_count,
                        max_iterations,
                        start_time,
                    ),
                    "last_gap": iteration_history[-1]["gap_summary"]
                    if iteration_history
                    else None,
                },
            )

        logger.debug(
            "loop: %s finalized — status=%s, iterations=%d",
            loop_id,
            final_status,
            iteration_count,
            extra={
                "event": "loop.finalized",
                "loop_id": loop_id,
                "final_status": final_status,
                "iteration_count": iteration_count,
            },
        )

        return LoopResult(
            loop_id=loop_id,
            status=final_status,
            iteration_count=iteration_count,
            cancelled_at_iteration=cancelled_at_iteration,
            iterations=iteration_history,
        )

    # ── Helpers: iteration execution ───────────────────────────

    async def _execute_iteration(
        self,
        execute_fn,
        enriched_request: str,
        source: str,
        loop_id: str,
        iteration: int,
        *,
        source_key: str | None = None,
        user_request_data_id: str | None = None,
    ) -> TaskResult:
        """Call the execution function (orchestrator or custom), handle errors.

        Wraps the orchestrator call in a try/except so the loop always gets
        a TaskResult — exceptions become status="error" results.

        Q3-F8: source_key is threaded through to the orchestrator branch so
        full-approval loops still satisfy the plan-approval fail-closed check.
        Q8.fix.b: user_request_data_id is threaded to the orchestrator branch
        only (execute_fn owns its own data_id threading via closure).
        """
        logger.debug(
            "_execute_iteration: entry",
            extra={
                "event": "execute.iteration_entry",
                "loop_id": loop_id,
                "iter_num": iteration,
                "has_execute_fn": execute_fn is not None,
                "request_len": len(enriched_request),
                "source_val": source,
                "user_request_data_id": user_request_data_id,
            },
        )
        try:
            if execute_fn is not None:
                logger.debug(
                    "_execute_iteration: using execute_fn branch",
                    extra={
                        "event": "execute.iteration_branch",
                        "loop_id": loop_id,
                        "iter_num": iteration,
                        "branch": "execute_fn",
                    },
                )
                result = await execute_fn(enriched_request, source)
            else:
                logger.debug(
                    "_execute_iteration: using orchestrator branch",
                    extra={
                        "event": "execute.iteration_branch",
                        "loop_id": loop_id,
                        "iter_num": iteration,
                        "branch": "orchestrator",
                    },
                )
                result = await self.orchestrator.handle_task(
                    user_request=enriched_request,
                    source=source,
                    source_key=source_key,
                    user_request_data_id=user_request_data_id,
                )
            logger.debug(
                "_execute_iteration: exit success",
                extra={
                    "event": "execute.iteration_exit",
                    "loop_id": loop_id,
                    "iter_num": iteration,
                    "result_status": result.status,
                },
            )
            return result
        except Exception as exc:
            logger.error(
                "loop: %s iteration %d orchestrator error: %s",
                loop_id,
                iteration,
                exc,
                exc_info=True,
                extra={"event": "loop.orchestrator_error", "loop_id": loop_id},
            )
            return TaskResult(status="error", reason=str(exc))

    def _log_iteration_result(
        self,
        loop_id: str,
        iteration: int,
        result: TaskResult,
        iter_duration: float,
    ) -> None:
        """Log the complete result state from the orchestrator.

        Logged before any decision logic runs — this is the raw input to
        the retry/stop decision tree.
        """
        step_statuses = (
            [
                {"step_id": sr.step_id, "status": sr.status, "tool": sr.tool}
                for sr in result.step_results
            ]
            if result.step_results
            else []
        )
        assertion_failures = result.assertion_failures or []
        _iter_muts = result.file_mutations or []
        logger.debug(
            "loop: %s iteration %d orchestrator returned — "
            "status=%s, completion=%s, "
            "goal_actions=%s, file_mutations_count=%d, "
            "step_count=%d, step_statuses=%s, "
            "assertion_failures=%d, "
            "judge_verdict=%s, "
            "has_response=%s, has_step_results=%s, "
            "plan_summary_len=%d, duration=%.1fs",
            loop_id,
            iteration,
            result.status,
            result.completion,
            result.goal_actions_executed,
            len(_iter_muts),
            len(result.step_results) if result.step_results else 0,
            step_statuses,
            len(assertion_failures),
            result.judge_verdict or "none",
            bool(result.response),
            bool(result.step_results),
            (len(result.plan_summary) if result.plan_summary else 0),
            iter_duration,
            extra={
                "event": "loop.iteration_orchestrator_result",
                "loop_id": loop_id,
                "iteration": iteration,
                "result_status": result.status,
                "result_completion": result.completion,
                "goal_actions_executed": result.goal_actions_executed,
                "file_mutations_count": len(_iter_muts),
                "file_mutation_path_lens": [
                    len(m.get("path") or m.get("file_path") or "") for m in _iter_muts
                ],
                "file_mutation_path_hashes": [
                    log_hash(m.get("path") or m.get("file_path") or None)
                    for m in _iter_muts
                ],
                "step_count": len(result.step_results) if result.step_results else 0,
                "step_statuses": step_statuses,
                "assertion_failure_count": len(assertion_failures),
                "assertion_failure_types": [
                    f.get("type", "unknown") if isinstance(f, dict) else "unknown"
                    for f in assertion_failures
                ],
                "assertion_failure_message_lens": [
                    len(f.get("message", "")) if isinstance(f, dict) else 0
                    for f in assertion_failures
                ],
                "has_judge_verdict": bool(result.judge_verdict),
                "judge_goal_met": result.judge_verdict.get("GOAL_MET")
                if result.judge_verdict
                else None,
                "has_response": bool(result.response),
                "has_step_results": bool(result.step_results),
                "plan_summary_len": (
                    len(result.plan_summary) if result.plan_summary else 0
                ),
                "duration_s": round(iter_duration, 1),
            },
        )

    # ── Helpers: iteration classification ──────────────────────

    def _classify_iteration(
        self,
        loop_id: str,
        iteration: int,
        result: TaskResult,
    ) -> tuple[bool, bool, str | None]:
        """Classify an iteration result into (is_success, is_terminal, judge_retry_mode).

        Applies three classification layers in order:
        1. Terminal status check (denied, refused, blocked, locked, success)
        2. Fast-path override (response without step_results → treat as success)
        3. Judge verdict override (GOAL_MET=partial → continuation, =no → fresh replan)
        """
        is_success = result.status == "success"
        is_terminal = result.status in _NO_RETRY_STATUSES

        # Fast-path responses have a response field but may not be "success"
        if result.response and not result.step_results:
            logger.debug(
                "loop: %s iteration %d fast-path override — "
                "result has response but no step_results, "
                "treating as success+terminal (was: is_success=%s, "
                "is_terminal=%s, status=%s)",
                loop_id,
                iteration,
                is_success,
                is_terminal,
                result.status,
                extra={
                    "event": "loop.fast_path_override",
                    "loop_id": loop_id,
                    "iteration": iteration,
                    "original_status": result.status,
                    "original_is_success": is_success,
                    "original_is_terminal": is_terminal,
                },
            )
            is_success = True
            is_terminal = True

        logger.debug(
            "loop: %s iteration %d terminal check — "
            "is_success=%s, is_terminal=%s, status=%s, "
            "status_in_no_retry_set=%s",
            loop_id,
            iteration,
            is_success,
            is_terminal,
            result.status,
            result.status in _NO_RETRY_STATUSES,
            extra={
                "event": "loop.iteration_terminal_check",
                "loop_id": loop_id,
                "iteration": iteration,
                "is_success": is_success,
                "is_terminal": is_terminal,
                "result_status": result.status,
            },
        )

        # Judge verdict override — if the judge says goal was NOT met,
        # override success and choose retry strategy:
        # - "partial" → continuation (keep context, approach is right)
        # - "no" → fresh replan (discard context, approach was wrong)
        judge_retry_mode = None
        if is_success and result.judge_verdict:
            goal_met = result.judge_verdict.get("GOAL_MET", "yes")
            if goal_met in ("partial", "no"):
                is_success = False
                is_terminal = False
                judge_retry_mode = (
                    "continuation" if goal_met == "partial" else "fresh_replan"
                )
                logger.info(
                    "loop: %s judge says GOAL_MET=%s, retry_mode=%s",
                    loop_id,
                    goal_met,
                    judge_retry_mode,
                    extra={
                        "event": "loop.judge_override",
                        "loop_id": loop_id,
                        "goal_met": goal_met,
                        "retry_mode": judge_retry_mode,
                        "gap": _scrub_critical_terms(
                            result.judge_verdict.get("GAP", "")
                        ),
                    },
                )

        return is_success, is_terminal, judge_retry_mode

    # ── Helpers: iteration recording ───────────────────────────

    def _build_iteration_record(
        self,
        loop_id: str,
        iteration: int,
        enriched_request: str,
        result: TaskResult,
        is_success: bool,
        judge_retry_mode: str | None,
        iter_duration: float,
    ) -> tuple[str | None, dict]:
        """Synthesise gap (if needed) and build the iteration record dict.

        Returns (gap, iter_record) where gap is None on success.
        """
        logger.debug(
            "loop: %s iteration %d gap synthesis — "
            "is_success=%s, will_call_synthesise_gap=%s",
            loop_id,
            iteration,
            is_success,
            not is_success,
            extra={
                "event": "loop.iteration_gap_decision",
                "loop_id": loop_id,
                "iteration": iteration,
                "is_success": is_success,
                "will_synthesise": not is_success,
                "result_status": result.status,
                "result_completion": result.completion,
                "judge_retry_mode": judge_retry_mode,
            },
        )

        gap = None if is_success else synthesise_gap(result)
        if gap is not None:
            logger.debug(
                "loop: %s iteration %d gap synthesised — '%s'",
                loop_id,
                iteration,
                gap,
                extra={
                    "event": "loop.iteration_gap_result",
                    "loop_id": loop_id,
                    "iteration": iteration,
                    "gap": gap,
                    "result_status": result.status,
                    "result_completion": result.completion,
                },
            )

        iter_record = {
            "iteration": iteration,
            "enriched_request": enriched_request[:500],
            "task_status": result.status,
            "plan_summary": result.plan_summary[:200],
            "gap_summary": gap,
            "duration_seconds": round(iter_duration, 1),
        }
        return gap, iter_record

    # ── Helpers: retry path ────────────────────────────────────

    async def _prepare_retry(
        self,
        loop_id: str,
        user_id: int,
        iteration: int,
        result: TaskResult,
        gap: str | None,
        judge_retry_mode: str | None,
        original_request: str,
        iteration_history: list[dict],
        max_iterations: int,
        start_time: float,
    ) -> str:
        """Log retry decision, publish iteration_complete, build enriched request.

        Returns the enriched request string for the next iteration.
        """
        logger.info(
            "loop: %s iteration %d -> RETRYING: status=%s, "
            "completion=%s, gap='%s', judge_retry_mode=%s, "
            "iterations_remaining=%d",
            loop_id,
            iteration,
            result.status,
            result.completion,
            gap,
            judge_retry_mode,
            max_iterations - iteration,
            extra={
                "event": "loop.iteration_retry",
                "loop_id": loop_id,
                "iteration": iteration,
                "result_status": result.status,
                "result_completion": result.completion,
                "gap": gap,
                "judge_retry_mode": judge_retry_mode,
                "iterations_remaining": max_iterations - iteration,
            },
        )

        await self._publish(
            loop_id,
            "iteration_complete",
            {
                "loop_id": loop_id,
                "user_id": user_id,
                "type": "iteration_complete",
                "iteration": iteration,
                "max_iterations": max_iterations,
                "status": result.status,
                "gap_summary": gap,
                "elapsed_seconds": round(time.monotonic() - start_time, 1),
            },
        )

        # fresh_replan: don't include prior step outcomes — they'd anchor
        # the planner to the failed approach. Only include the GAP.
        # continuation: include full history so planner knows what worked.
        if judge_retry_mode == "fresh_replan":
            logger.debug(
                "_prepare_retry: judge_retry_mode_eq_fresh_replan",
                extra={
                    "event": "loop_controller._prepare_retry.match",
                    "reason": "judge_retry_mode_eq_fresh_replan",
                },
            )  # auto:neg
            history: list[dict] = []
        else:
            logger.debug(
                "_prepare_retry: judge_retry_mode_eq_fresh_replan",
                extra={
                    "event": "loop_controller._prepare_retry.clean",
                    "reason": "judge_retry_mode_eq_fresh_replan",
                },
            )  # auto:neg
            history = iteration_history[:-1]

        mode = judge_retry_mode or "continuation"
        enriched = build_enriched_request(
            original=original_request,
            gap=gap,
            history=history,
        )
        logger.debug(
            "loop: %s iteration %d enriched request built (%s) — "
            "length=%d, history_count=%d, preview='%s'",
            loop_id,
            iteration,
            mode,
            len(enriched),
            len(history),
            enriched[:200],
            extra={
                "event": "loop.enriched_request_built",
                "loop_id": loop_id,
                "iteration": iteration,
                "mode": mode,
                "request_length": len(enriched),
                "history_count": len(history),
            },
        )
        return enriched

    # ── Helpers: logging + events ──────────────────────────────

    def _log_budget_exhausted(
        self,
        loop_id: str,
        max_iterations: int,
        start_time: float,
        iteration_history: list[dict],
    ) -> None:
        """Log warning when for-loop exhausts all iterations without success."""
        logger.warning(
            "loop: %s BUDGET EXHAUSTED — failed after %d iterations "
            "(%.1fs total). Last gap='%s', last status=%s",
            loop_id,
            max_iterations,
            time.monotonic() - start_time,
            iteration_history[-1]["gap_summary"] if iteration_history else "none",
            iteration_history[-1]["task_status"] if iteration_history else "none",
            extra={
                "event": "loop.budget_exhausted",
                "loop_id": loop_id,
                "max_iterations": max_iterations,
                "elapsed_s": round(time.monotonic() - start_time, 1),
                "last_gap": iteration_history[-1]["gap_summary"]
                if iteration_history
                else None,
                "last_status": iteration_history[-1]["task_status"]
                if iteration_history
                else None,
                "iteration_statuses": [h["task_status"] for h in iteration_history],
                "iteration_gaps": [h["gap_summary"] for h in iteration_history],
            },
        )

    @staticmethod
    def _finished_event_data(
        loop_id: str,
        user_id: int,
        status: str,
        iteration: int,
        max_iterations: int,
        start_time: float,
    ) -> dict:
        """Build the standard finished event payload."""
        logger.debug(
            "_finished_event_data called",
            extra={
                "event": "finished.event_data",
                "loop_id": loop_id,
                "user_id": user_id,
                "status": status,
            },
        )
        return {
            "loop_id": loop_id,
            "user_id": user_id,
            "type": "finished",
            "status": status,
            "iteration": iteration,
            "max_iterations": max_iterations,
            "elapsed_seconds": round(time.monotonic() - start_time, 1),
        }

    async def _publish(self, loop_id: str, event: str, data: dict) -> None:
        """Fire-and-forget event publish. No-op if event bus not configured."""
        if self.event_bus is not None:
            try:
                await asyncio.wait_for(
                    self.event_bus.publish(f"loop.{loop_id}.{event}", data),
                    timeout=_EVENT_PUBLISH_TIMEOUT,
                )
            except TimeoutError:
                logger.warning(
                    "loop: event publish timed out for %s.%s",
                    loop_id,
                    event,
                    exc_info=True,
                    extra={
                        "event": "loop.publish.timeout",
                        "loop_id": loop_id,
                        "topic": event,
                        "timeout_s": _EVENT_PUBLISH_TIMEOUT,
                    },
                )
            except Exception:  # catch-all: event publish best-effort
                logger.debug(
                    "loop: event publish failed for %s.%s",
                    loop_id,
                    event,
                    exc_info=True,
                )
