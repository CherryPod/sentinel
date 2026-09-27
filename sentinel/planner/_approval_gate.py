"""ApprovalGateMixin — Stage D approval logic extracted from Orchestrator.

Handles auto-approval for safe plans at sufficient trust levels and
human approval requests for plans requiring oversight.  Also provides
the validation logic for executing previously approved plans.
"""

from __future__ import annotations

import logging

from sentinel.core.models import Plan, TaskResult

from ._task_context import TaskContext
from .builders import is_auto_approvable

logger = logging.getLogger(__name__)


class ApprovalGateMixin:
    """Stage D methods: approval checking and validation.

    Mixed into Orchestrator — methods access self._approval_manager
    and self._emit via the class hierarchy.
    """

    async def _check_approval(self, ctx: TaskContext) -> TaskResult | None:
        """Stage D: Approval gate.

        Returns a TaskResult if the plan needs human approval (awaiting),
        or None if execution can proceed (auto-approved or no approval needed).
        """
        logger.debug(
            "Stage D: checking approval",
            extra={
                "event": "orchestrator.stage_d_start",
                "task_id": ctx.task_id,
                "approval_mode": ctx.approval_mode,
                "effective_tl": ctx.effective_tl,
                "step_count": len(ctx.plan.steps) if ctx.plan else 0,
            },
        )
        if ctx.approval_mode != "full" or self._approval_manager is None:
            logger.debug(
                "Stage D: approval skipped (mode=%s, manager=%s)",
                ctx.approval_mode,
                "present" if self._approval_manager else "absent",
                extra={
                    "event": "orchestrator.stage_d_skip",
                    "task_id": ctx.task_id,
                    "approval_mode": ctx.approval_mode,
                },
            )
            return None
        logger.debug(
            "_check_approval: approval_mode_noteq_full_passed",
            extra={
                "event": "orchestrator.stage_d_skip.passed",
                "reason": "approval_mode_noteq_full_passed",
            },
        )  # auto:neg

        # D2/D3: Auto-approve safe plans at TL1+ (trust-level-aware)
        if ctx.effective_tl >= 1 and is_auto_approvable(ctx.plan, ctx.effective_tl):
            logger.info(
                "Plan auto-approved (all steps SAFE at TL%d)",
                ctx.effective_tl,
                extra={
                    "event": "orchestrator.plan_auto_approved",
                    "task_id": ctx.task_id,
                    "trust_level": ctx.effective_tl,
                    "plan_summary_len": (
                        len(ctx.plan.plan_summary) if ctx.plan.plan_summary else 0
                    ),
                    "plan_step_count": len(ctx.plan.steps),
                },
            )
            await self._emit(
                ctx.task_id,
                "auto_approved",
                {
                    "plan_summary": ctx.plan.plan_summary,
                    "trust_level": ctx.effective_tl,
                },
            )
            ctx.auto_approved = True
            return None

        # Request human approval
        # Q3-F8: fail closed instead of falling back to "". An empty key collapses
        # concurrent same-user plan approvals into one namespace; typing "go" then
        # grants the oldest pending approval — silent wrong-plan approval. Every
        # producer that reaches full-approval mode must thread a source_key through.
        if not ctx.source_key:
            raise RuntimeError(
                "source_key is required for plan approval "
                "(full approval mode cannot key approvals anonymously)"
            )
        approval_id = await self._approval_manager.request_plan_approval(
            ctx.plan,
            source_key=ctx.source_key,
            user_request=ctx.user_request,
            mtm_turn_score=ctx.conv_info.mtm_turn_score if ctx.conv_info else 0.0,
            mtm_signal_categories=list(ctx.conv_info.mtm_turn_categories) if ctx.conv_info else [],
        )
        logger.debug(
            "Stage D: approval requested",
            extra={
                "event": "orchestrator.stage_d_approval_requested",
                "task_id": ctx.task_id,
                "approval_id": approval_id,
            },
        )
        await self._emit(
            ctx.task_id,
            "approval_requested",
            {
                "approval_id": approval_id,
                "plan_summary": ctx.plan.plan_summary,
                "steps": [
                    {
                        "id": s.id,
                        "type": s.type,
                        "description": s.description,
                        "prompt": s.prompt,
                        "tool": s.tool,
                        "args": s.args or None,
                        "expects_code": s.expects_code,
                    }
                    for s in ctx.plan.steps
                ],
            },
        )
        # Extension point: approval enrichers would run here

        return TaskResult(
            task_id=ctx.task_id,
            status="awaiting_approval",
            plan_summary=ctx.plan.plan_summary,
            approval_id=approval_id,
            conversation=ctx.conv_info,
        )

    async def _validate_approval(
        self, approval_id: str
    ) -> tuple[dict, Plan] | TaskResult:
        """Validate an approval request and retrieve the approved plan.

        Returns (pending_data, plan) on success, or a TaskResult on failure.
        Handles: missing manager, not found, denied, plan missing.
        """
        if self._approval_manager is None:
            logger.debug(
                "Approved plan rejected: no approval manager",
                extra={
                    "event": "orchestrator.approvedplan",
                    "reason": "no_manager",
                    "approval_id": approval_id,
                },
            )
            return TaskResult(status="error", reason="Approval manager not configured")

        is_approved = await self._approval_manager.is_approved(approval_id)
        if is_approved is None:
            logger.debug(
                "Approved plan rejected: not found or pending",
                extra={
                    "event": "orchestrator.approvedplan",
                    "reason": "not_found",
                    "approval_id": approval_id,
                },
            )
            return TaskResult(
                status="error", reason="Approval not found or still pending"
            )
        if not is_approved:
            logger.debug(
                "Approved plan rejected: denied",
                extra={
                    "event": "orchestrator.approvedplan",
                    "reason": "denied",
                    "approval_id": approval_id,
                },
            )
            return TaskResult(status="denied", reason="Plan was denied")
        logger.debug(
            "_validate_approval: not_is_approved_passed",
            extra={
                "event": "orchestrator.approvedplan.passed",
                "reason": "not_is_approved_passed",
            },
        )  # auto:neg

        pending = await self._approval_manager.get_pending(approval_id)
        if pending is None or pending.get("plan") is None:
            logger.debug(
                "Approved plan rejected: plan not found",
                extra={
                    "event": "orchestrator.approvedplan",
                    "reason": "plan_missing",
                    "approval_id": approval_id,
                },
            )
            return TaskResult(status="error", reason="Plan not found for approval")
        logger.debug(
            "_validate_approval: pending_is_None_passed",
            extra={
                "event": "orchestrator.approvedplan.passed",
                "reason": "pending_is_None_passed",
            },
        )  # auto:neg

        return pending, pending["plan"]
