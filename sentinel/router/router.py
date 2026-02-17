"""MessageRouter — scan-first, classify, dispatch.

Central routing component that sits between inbound channels and the
execution layer. Every request is scanned before classification, then
dispatched to either the fast path (template executor) or the full
planner (Claude orchestrator).

When disabled (feature flag), all requests pass straight through to
the orchestrator with zero new behaviour.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sentinel.core.models import TaskResult
from sentinel.planner.intake import resolve_contacts
from sentinel.router.classifier import Route
from sentinel.session.store import ConversationTurn

if TYPE_CHECKING:
    from sentinel.contacts.store import ContactStore
    from sentinel.core.bus import EventBus
    from sentinel.core.confirmation import ConfirmationEntry
    from sentinel.router.classifier import Classifier
    from sentinel.router.fast_path import FastPathExecutor
    from sentinel.security.pipeline import ScanPipeline
    from sentinel.session.store import Session, SessionStore

logger = logging.getLogger(__name__)


class MessageRouter:
    """Routes user messages through scan -> classify -> dispatch.

    The routing flow:
    1. Feature flag check — if disabled, bypass to orchestrator directly.
    2. Session binding — look up or create the session.
    3. Session lock check — reject if the session is locked.
    4. Input scanning — block if the security pipeline flags the input.
    5. Classification — Qwen classifies as FAST or PLANNER.
    6. Dispatch — fast path executor or orchestrator.
    """

    def __init__(
        self,
        classifier: Classifier,
        fast_path: FastPathExecutor,
        orchestrator,
        pipeline: ScanPipeline,
        session_store: SessionStore | None,
        event_bus: EventBus,
        enabled: bool = True,
        contact_store: "ContactStore | None" = None,
        confirmation_gate=None,
    ) -> None:
        self._classifier = classifier
        self._fast_path = fast_path
        self._orchestrator = orchestrator
        self._pipeline = pipeline
        self._session_store = session_store
        self._bus = event_bus
        self._enabled = enabled
        self._contact_store = contact_store
        self._confirmation_gate = confirmation_gate

    async def route(
        self,
        user_request: str,
        source: str,
        source_key: str | None = None,
        task_id: str | None = None,
        approval_mode: str = "auto",
    ) -> TaskResult:
        """Route a user request through scan -> classify -> dispatch.

        Returns a TaskResult regardless of which path is taken.
        """
        # 1. Feature flag — full bypass when disabled
        if not self._enabled:
            return await self._orchestrator.handle_task(
                user_request,
                source=source,
                approval_mode=approval_mode,
                source_key=source_key,
                task_id=task_id,
            )

        # 2. Session binding
        session: Session | None = None
        if self._session_store is not None and source_key is not None:
            session = await self._session_store.get_or_create(source_key, source=source)

        # 3. Session lock check
        if session is not None and session.is_locked:
            return TaskResult(
                status="blocked",
                reason="Session locked — too many security violations",
            )

        # 4. Input scanning
        try:
            scan_result = await self._pipeline.scan_input(user_request)
        except Exception:
            logger.exception("Input scan failed")
            return TaskResult(
                status="error",
                reason="Request processing failed",
            )

        if not scan_result.is_clean:
            blockers = list(scan_result.violations.keys())
            reason = f"Input blocked by: {', '.join(blockers)}"
            logger.warning("Input scan blocked request: %s", blockers)

            # Record the blocked turn on the session
            if session is not None:
                turn = ConversationTurn(
                    request_text=user_request,
                    result_status="blocked",
                    blocked_by=blockers,
                )
                session.add_turn(turn)
                if self._session_store is not None:
                    await self._session_store.add_turn(session.session_id, turn, session=session)

            return TaskResult(status="blocked", reason=reason)

        # 4b. Contact resolution — resolve sender, rewrite names to opaque IDs
        contact_result = await resolve_contacts(
            self._contact_store, source_key, user_request,
        )
        if contact_result.rejected:
            return TaskResult(
                status="rejected",
                reason=contact_result.error or "Unknown sender",
            )
        user_request = contact_result.rewritten_text
        user_id = contact_result.user_id
        if contact_result.audit_log:
            logger.info(
                "Contact resolution applied",
                extra={
                    "event": "contact_resolution",
                    "user_id": contact_result.user_id,
                    "rewrites": len(contact_result.audit_log),
                },
            )

        # 4c. Pending confirmation check
        if self._confirmation_gate is not None and source_key is not None:
            pending = await self._confirmation_gate.get_pending(source_key)
            if pending is not None:
                return await self._handle_confirmation_reply(
                    user_request, pending, source, source_key, task_id,
                    user_id=user_id,
                )

        # 4d. Plan approval check — "go" with no fast-path confirmation triggers
        # pending plan approval if one exists for this source_key
        if (
            source_key is not None
            and user_request.strip().lower() == "go"
            and self._orchestrator.approval_manager is not None
        ):
            pending_approval = await self._orchestrator.approval_manager.get_pending_by_source_key(
                source_key,
            )
            if pending_approval is not None:
                accepted = await self._orchestrator.submit_approval(
                    approval_id=pending_approval["approval_id"],
                    granted=True,
                    reason="confirmed via channel",
                )
                if not accepted:
                    return TaskResult(
                        status="expired",
                        reason="Plan approval expired. Send your request again.",
                    )
                result = await self._orchestrator.execute_approved_plan(
                    pending_approval["approval_id"],
                )
                return result

        # 5. Classify
        classification = await self._classifier.classify(user_request)

        # 6. Dispatch
        if classification.route == Route.FAST:
            return await self._dispatch_fast(
                classification.template_name,
                classification.params,
                session,
                task_id,
                user_id,
            )

        return await self._dispatch_planner(
            user_request, source, approval_mode, source_key, task_id, session,
        )

    async def _handle_confirmation_reply(
        self,
        user_request: str,
        pending: "ConfirmationEntry",
        source: str,
        source_key: str | None,
        task_id: str | None,
        user_id: int = 1,
    ) -> TaskResult:
        """Handle a message when a confirmation is pending.

        "go" (exact, trimmed, case-insensitive) confirms and executes.
        Anything else cancels and routes the new message normally.
        """
        if user_request.strip().lower() == "go":
            entry = await self._confirmation_gate.confirm(pending.confirmation_id)
            if entry is None:
                # Expired or already handled between check and confirm
                return TaskResult(
                    status="expired",
                    reason="Pending action expired. Send your request again.",
                )
            # Execute the stored tool call
            result_dict = await self._fast_path.execute_confirmed(
                entry.tool_name, entry.tool_params, entry.task_id,
            )
            return TaskResult(
                status=result_dict.get("status", "error"),
                reason=result_dict.get("reason") or "",
                response=result_dict.get("response") or "",
            )

        # Not "go" — cancel and route the new message normally
        await self._confirmation_gate.cancel(pending.confirmation_id)
        logger.info(
            "Confirmation cancelled by new message",
            extra={
                "event": "confirmation_cancelled_by_message",
                "confirmation_id": pending.confirmation_id,
                "source_key": source_key,
            },
        )
        # Continue with normal routing — classify and dispatch
        classification = await self._classifier.classify(user_request)

        if classification.route == Route.FAST:
            return await self._dispatch_fast(
                classification.template_name,
                classification.params,
                None,
                task_id,
                user_id,
            )

        return await self._dispatch_planner(
            user_request, source, "auto", source_key, task_id, None,
        )

    async def _dispatch_fast(
        self,
        template_name: str,
        params: dict,
        session: Session | None,
        task_id: str | None,
        user_id: int,
    ) -> TaskResult:
        """Execute via the fast path and convert the result dict to TaskResult."""
        result_dict = await self._fast_path.execute(
            template_name, params, session, task_id, user_id,
        )
        return TaskResult(
            status=result_dict.get("status", "error"),
            reason=result_dict.get("reason") or "",
            response=result_dict.get("response") or "",
        )

    async def _dispatch_planner(
        self,
        user_request: str,
        source: str,
        approval_mode: str,
        source_key: str | None,
        task_id: str | None,
        session: Session | None,
    ) -> TaskResult:
        """Dispatch to the orchestrator via plan_and_execute (pre-scanned)."""
        return await self._orchestrator.plan_and_execute(
            user_request=user_request,
            source=source,
            approval_mode=approval_mode,
            source_key=source_key,
            task_id=task_id,
            session=session,
        )
