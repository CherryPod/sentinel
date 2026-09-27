"""PostProcessingMixin — post-execution and cleanup logic from Orchestrator.

Handles episodic record storage, session turn recording after plan
execution completes, and task-in-progress flag cleanup.
"""

from __future__ import annotations

import logging

from sentinel.session.store import ConversationTurn

from ._execution import _extract_prior_error
from ._task_context import TaskContext

logger = logging.getLogger(__name__)

# Statuses whose turn records must be durably persisted; add_turn failures for
# these propagate rather than being swallowed so violation history is not lost.
_PERSIST_REQUIRED_STATUSES = frozenset({"blocked", "denied", "refused", "locked"})


class PostProcessingMixin:
    """Post-execution methods: episodic storage, turn recording, cleanup.

    Mixed into Orchestrator — methods access self._session_store,
    self._store_episodic_record, etc. via the class hierarchy.
    """

    async def _post_process_task(self, ctx: TaskContext) -> None:
        """Post-processing: episodic record + session turn recording.

        Called after the execution loop completes (Stage E finished).
        """
        result = ctx.result
        session = ctx.session

        # F4: Store episodic record (best-effort, alongside auto-memory)
        # For fix-cycle turns (session has prior turns), include the
        # original scenario request so the episodic record is searchable
        # by scenario content rather than the generic retry prompt.
        original_request: str | None = None
        prior_error_summary: str | None = None
        if session is not None and session.turns:
            first_turn = session.turns[0]
            if first_turn.request_text != ctx.user_request:
                original_request = first_turn.request_text
            # Extract error context from the most recent failed turn
            for prev_turn in reversed(session.turns):
                if (
                    prev_turn.result_status not in ("success", "completed")
                    and prev_turn.step_outcomes
                ):
                    prior_error_summary = _extract_prior_error(prev_turn.step_outcomes)
                    break

        logger.debug(
            "Post-execution: storing episodic record — status=%s, "
            "completion=%s, fix_cycle=%s",
            result.status,
            result.completion,
            original_request is not None,
            extra={
                "event": "orchestrator.post_exec_episodic_store",
                "task_id": ctx.task_id,
                "status": result.status,
                "completion": result.completion,
                "has_original_request": original_request is not None,
                "has_prior_error": prior_error_summary is not None,
                "judge_verdict": result.judge_verdict is not None,
            },
        )

        await self._store_episodic_record(
            session_id=session.session_id if session else "",
            task_id=ctx.task_id,
            user_request=ctx.user_request,
            task_status=result.status,
            plan_summary=ctx.plan.plan_summary,
            step_outcomes=result.step_outcomes or [],
            original_request=original_request,
            prior_error_summary=prior_error_summary,
            plan_phases=result.plan_phases,
            completion=result.completion,
            goal_actions_executed=result.goal_actions_executed,
            file_mutations=result.file_mutations,
            assertion_failures=result.assertion_failures,
            tool_output_warnings=result.tool_output_warnings,
            judge_verdict=result.judge_verdict,
        )

        # Record turn with plan summary for conversation history
        if session is not None:
            turn = ConversationTurn(
                request_text=ctx.user_request,
                result_status=result.status,
                risk_score=ctx.conv_info.risk_score if ctx.conv_info else 0.0,
                plan_summary=ctx.plan.plan_summary,
                auto_approved=ctx.auto_approved,
                elapsed_s=round(ctx.task_elapsed, 2),
                step_outcomes=result.step_outcomes or None,
                mtm_turn_score=ctx.conv_info.mtm_turn_score if ctx.conv_info else 0.0,
                mtm_signal_categories=ctx.conv_info.mtm_turn_categories if ctx.conv_info else [],
            )
            session.add_turn(turn)
            _turn_store_ok = True
            if self._session_store is not None:
                try:
                    await self._session_store.add_turn(
                        session.session_id, turn, session=session
                    )
                except Exception as exc:  # best-effort except security-relevant statuses
                    if result.status in _PERSIST_REQUIRED_STATUSES:
                        # Violation history must be durably persisted; surface the failure.
                        raise
                    _turn_store_ok = False
                    logger.warning(
                        "Post-execution: session turn recording failed (best-effort) — "
                        "task result status unchanged. error=%s",
                        exc,
                        exc_info=True,
                        extra={
                            "event": "orchestrator.post_exec_turn_record_failed",
                            "task_id": ctx.task_id,
                            "status": result.status,
                        },
                    )
            logger.debug(
                "Post-execution: in-memory turn appended, store_write=%s — "
                "turn_count=%d, status=%s",
                _turn_store_ok,
                len(session.turns),
                result.status,
                extra={
                    "event": "orchestrator.post_exec_turn_recorded",
                    "task_id": ctx.task_id,
                    "turn_count": len(session.turns),
                    "store_write_ok": _turn_store_ok,
                },
            )

        logger.debug(
            "Post-execution: complete — returning result (status=%s, completion=%s)",
            result.status,
            result.completion,
            extra={
                "event": "orchestrator.post_exec_complete",
                "task_id": ctx.task_id,
                "status": result.status,
                "completion": result.completion,
            },
        )

    async def _cleanup_task(self, ctx: TaskContext) -> None:
        """Finally block: clear task-in-progress flag on session.

        Must be called in a finally block so the flag is cleared even on
        exceptions.

        C48 gate: only clears when ``ctx.task_in_progress_set`` is True —
        i.e. when intake successfully registered the new task. When intake
        blocks before flag-set (input scan rejects, contact resolution
        rejects, conversation analysis blocks) the stale crash flag is
        preserved so the next entry-boundary touch can run reconciliation
        and emit ``system.session_crash_reconciliation``. Without this
        gate, a blocked first-touch on a crashed session would clear the
        stale flag with no audit row.
        """
        if ctx.session is None:
            return
        if not ctx.task_in_progress_set:
            logger.debug(
                "Task cleanup: skipped — task_in_progress not registered",
                extra={
                    "event": "orchestrator.task_cleanup_skipped",
                    "task_id": ctx.task_id,
                    "session_id": ctx.session_id,
                },
            )
            return
        ctx.session.set_task_in_progress(False)
        if self._session_store is not None:
            try:
                await self._session_store.set_task_in_progress(
                    ctx.session.session_id, False
                )
            except Exception as exc:  # best-effort: CancelledError/KeyboardInterrupt propagate
                logger.warning(
                    "Task cleanup: set_task_in_progress store call failed (best-effort) — "
                    "in-memory flag cleared, DB may be stale. error=%s",
                    exc,
                    exc_info=True,
                    extra={
                        "event": "orchestrator.task_cleanup_store_failed",
                        "task_id": ctx.task_id,
                        "session_id": ctx.session_id,
                    },
                )
        logger.debug(
            "Task cleanup: task_in_progress cleared",
            extra={
                "event": "orchestrator.task_cleanup",
                "task_id": ctx.task_id,
                "session_id": ctx.session_id,
            },
        )
