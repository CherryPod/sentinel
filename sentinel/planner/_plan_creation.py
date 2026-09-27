"""PlanCreationMixin — Stage B/C planner context and plan creation.

Stage B: assembles tool descriptions, conversation history, cross-session
context, and session files context for the planner.

Stage C: invokes the planner to create a plan, handling timeout, refusal,
and error cases.
"""

from __future__ import annotations

import asyncio
import logging

from sentinel.core.config import settings
from sentinel.core.models import TaskResult
from sentinel.session.store import ConversationTurn

from ._task_context import TaskContext
from .builders import (
    build_cross_session_context,
    build_session_files_context,
    flush_pruned_turns,
)
from .planner import ClaudePlanner, PlannerError, PlannerRefusalError

logger = logging.getLogger(__name__)


class PlanCreationMixin:
    """Stage B + C methods: planner context assembly and plan invocation.

    Mixed into Orchestrator — methods access self._planner,
    self._safe_tool_handlers, self._tool_executor, etc. via the class hierarchy.
    """

    async def _prepare_planner_context(self, ctx: TaskContext) -> None:
        """Stage B: Prepare planner context — tools, history, memory.

        Populates ctx.available_tools, ctx.conversation_history,
        ctx.cross_session_context, and ctx.session_files_context.
        No early returns — this stage always succeeds.
        """
        logger.debug(
            "Stage B: preparing planner context",
            extra={
                "event": "orchestrator.stage_b_start",
                "task_id": ctx.task_id,
                "has_session": ctx.session is not None,
            },
        )

        # Tool descriptions — SAFE internal tools + system/external tools
        ctx.available_tools = self._safe_tool_handlers.get_descriptions()
        if self._tool_executor is not None:
            ctx.available_tools.extend(self._tool_executor.get_tool_descriptions())

        # Conversation history for multi-turn context
        if ctx.session is not None and len(ctx.session.turns) > 0:
            ctx.conversation_history = []
            for i, turn in enumerate(ctx.session.turns, 1):
                ctx.conversation_history.append(
                    {
                        "turn": i,
                        "request": turn.request_text[:1000],
                        "outcome": turn.result_status or "unknown",
                        "summary": turn.plan_summary,
                        "step_outcomes": turn.step_outcomes,
                    }
                )

        # F2: Pre-pruning memory flush — persist pruned turns before they
        # leave planner view.  After flushing, replace conversation_history
        # with the kept portion so the planner doesn't re-prune redundantly.
        if (
            ctx.conversation_history
            and len(ctx.conversation_history) > settings.session_max_history_turns
        ):
            kept_turns, pruned_turns = ClaudePlanner.prune_history(
                ctx.conversation_history,
                max_turns=settings.session_max_history_turns,
            )
            if pruned_turns:
                await flush_pruned_turns(
                    session_id=ctx.session.session_id,
                    pruned_turns=pruned_turns,
                    memory_store=self._memory_store,
                )
            ctx.conversation_history = kept_turns

        # F2: Cross-session context injection
        if ctx.session is not None:
            ctx.cross_session_context = await build_cross_session_context(
                user_request=ctx.user_request,
                memory_store=self._memory_store,
                embedding_client=self._embedding_client,
                cross_session_token_budget=settings.cross_session_token_budget,
                domain_summary_store=self._domain_summary_store,
                reranker=self._reranker,
                episodic_store=self._episodic_store,
                insight_store=self._insight_store,
            )

        # F3: Session workspace tracking — planner sees which files
        # this session modified
        if ctx.session is not None and len(ctx.session.turns) > 0:
            ctx.session_files_context = build_session_files_context(ctx.session.turns)

        logger.debug(
            "Stage B: planner context ready",
            extra={
                "event": "orchestrator.stage_b_complete",
                "task_id": ctx.task_id,
                "tool_count": len(ctx.available_tools),
                "history_turns": len(ctx.conversation_history)
                if ctx.conversation_history
                else 0,
                "has_cross_session": bool(ctx.cross_session_context),
                "has_session_files": bool(ctx.session_files_context),
            },
        )

        # Extension point: context enrichers would run here

    async def _create_plan(self, ctx: TaskContext) -> TaskResult | None:
        """Stage C: Create plan via planner.

        Returns a TaskResult on planner timeout/refusal/error (early return),
        or None on success (plan stored in ctx.plan).
        """
        logger.debug(
            "Stage C: creating plan",
            extra={
                "event": "orchestrator.stage_c_start",
                "task_id": ctx.task_id,
                "tool_count": len(ctx.available_tools),
            },
        )

        try:
            ctx.plan = await asyncio.wait_for(
                self._planner.create_plan(
                    user_request=ctx.user_request,
                    available_tools=ctx.available_tools,
                    conversation_history=ctx.conversation_history,
                    cross_session_context=ctx.cross_session_context,
                    interrupted_context=ctx.interrupted_context,
                    max_history_turns=settings.session_max_history_turns,
                    session_files_context=ctx.session_files_context,
                ),
                timeout=settings.planner_timeout,
            )
        except TimeoutError:
            logger.error(
                "Planner timed out",
                extra={
                    "event": "orchestrator.planner_timeout",
                    "timeout_s": settings.planner_timeout,
                    "error_category": "upstream_api",
                    "error_class": "transient",
                },
                exc_info=True,
            )
            return TaskResult(
                status="error",
                reason=f"Planning timed out after {settings.planner_timeout}s",
                conversation=ctx.conv_info,
            )
        except PlannerRefusalError as exc:
            logger.info(
                "Planner refused request",
                extra={
                    "event": "orchestrator.planner_refusal",
                    "reason": str(exc),
                    "error_category": exc.category,
                    "error_class": "transient" if exc.retryable else "permanent",
                },
                exc_info=True,
            )
            if ctx.session is not None:
                turn = ConversationTurn(
                    request_text=ctx.user_request,
                    result_status="refused",
                    blocked_by=["planner"],
                    risk_score=ctx.conv_info.risk_score if ctx.conv_info else 0.0,
                    mtm_turn_score=ctx.conv_info.mtm_turn_score if ctx.conv_info else 0.0,
                    mtm_signal_categories=ctx.conv_info.mtm_turn_categories if ctx.conv_info else [],
                )
                ctx.session.add_turn(turn)
                if self._session_store is not None:
                    await self._session_store.add_turn(
                        ctx.session.session_id, turn, session=ctx.session
                    )
            return TaskResult(
                status="refused",
                reason=str(exc),
                conversation=ctx.conv_info,
            )
        except PlannerError as exc:
            logger.error(
                "Planning failed",
                extra={
                    "event": "orchestrator.planner_error",
                    "error": str(exc),
                    "error_category": exc.category,
                    "error_class": "transient" if exc.retryable else "permanent",
                },
                exc_info=True,
            )
            return TaskResult(
                status="error",
                reason="Request processing failed",
                conversation=ctx.conv_info,
            )

        # Capture planner token usage for the task result
        ctx.planner_usage = getattr(self._planner, "_last_usage", None)

        # Event: plan created
        await self._emit(
            ctx.task_id,
            "planned",
            {
                "plan_summary": ctx.plan.plan_summary,
                "steps": [
                    {"id": s.id, "type": s.type, "description": s.description}
                    for s in ctx.plan.steps
                ],
            },
        )

        logger.debug(
            "Stage C: plan created — %d steps, summary_len: %d",
            len(ctx.plan.steps),
            len(ctx.plan.plan_summary) if ctx.plan.plan_summary else 0,
            extra={
                "event": "orchestrator.stage_c_complete",
                "task_id": ctx.task_id,
                "plan_step_count": len(ctx.plan.steps),
                "plan_summary_len": (
                    len(ctx.plan.plan_summary) if ctx.plan.plan_summary else 0
                ),
            },
        )

        # Extension point: plan enrichers/validators would run here

        return None
