"""IntakeProcessingMixin — Stage A intake logic extracted from Orchestrator.

Handles trust resolution, session binding, conversation analysis,
input scanning, and contact resolution.  All rejection gates that
determine whether a request can proceed live here.
"""

from __future__ import annotations

import logging
import time

from sentinel.core.config import settings
from sentinel.core.context import current_user_id, resolve_trust_level
from sentinel.core.models import TaskResult
from sentinel.session._session_audit import (
    _maybe_emit_session_crash_reconciliation,
)
from sentinel.worker.context import WorkerContext

from ._task_context import TaskContext
from .builders import build_interrupted_task_warning
from .intake import (
    analyze_conversation,
    bind_session,
    resolve_contacts,
    scan_input,
)

logger = logging.getLogger(__name__)


class IntakeProcessingMixin:
    """Stage A methods: trust, session, scan, contacts.

    Mixed into Orchestrator — methods access self._contact_store,
    self._session_store, self._pipeline, etc. via the class hierarchy.
    """

    async def _preprocess_task(self, ctx: TaskContext) -> TaskResult | None:
        """Stage A: Pre-processing — trust, session, scan, contacts.

        Returns a TaskResult if the task should be blocked/rejected (early
        return), or None if processing should continue to Stage B.
        """
        logger.debug(
            "Stage A: pre-processing started",
            extra={
                "event": "orchestrator.stage_a_start",
                "task_id": ctx.task_id,
                "source": ctx.source,
                "input_pre_scanned": ctx.input_pre_scanned,
            },
        )

        # A1: Trust resolution, session binding, conversation analysis,
        # interrupted task detection, input scanning — all rejection gates
        blocked = await self._bind_and_validate_session(ctx)
        if blocked:
            return blocked

        # A2: Contact resolution — resolve sender, rewrite names to opaque IDs.
        # Runs AFTER S1 scan (scanner sees raw text). Rewritten text goes to planner.
        ctx.contact_result = await resolve_contacts(
            self._contact_store,
            ctx.source_key,
            ctx.user_request,
        )
        if ctx.contact_result.rejected:
            logger.debug(
                "Stage A: rejected by contact resolution",
                extra={
                    "event": "orchestrator.stage_a_rejected_contact",
                    "task_id": ctx.task_id,
                    "error": ctx.contact_result.error,
                },
            )
            return TaskResult(
                status="rejected",
                reason=ctx.contact_result.error or "Unknown sender",
            )
        ctx.user_request = ctx.contact_result.rewritten_text
        if ctx.contact_result.audit_log:
            logger.info(
                "Contact resolution applied",
                extra={
                    "event": "orchestrator.contact_resolution",
                    "user_id": ctx.contact_result.user_id,
                    "rewrites": len(ctx.contact_result.audit_log),
                },
            )

        # Event: task started (input scan passed)
        await self._emit(
            ctx.task_id,
            "started",
            {
                "source": ctx.source,
                "request_len": len(ctx.user_request),
            },
        )

        logger.debug(
            "Stage A: pre-processing complete",
            extra={
                "event": "orchestrator.stage_a_complete",
                "task_id": ctx.task_id,
                "effective_tl": ctx.effective_tl,
                "has_session": ctx.session is not None,
                "has_contact": ctx.contact_result is not None,
            },
        )

        # Extension point: input enrichers would run here

        return None

    async def _bind_and_validate_session(self, ctx: TaskContext) -> TaskResult | None:
        """Stage A1: Trust, session binding, conversation analysis, input scan.

        Handles all the "reject or proceed" gates that determine whether
        this request can continue.  Returns a TaskResult to block/reject,
        or None to continue to contact resolution.
        """
        # Trust level resolution
        user_tl = None
        if self._contact_store is not None:
            user_tl = await self._contact_store.get_user_trust_level(
                current_user_id.get()
            )
        ctx.effective_tl = resolve_trust_level(user_tl, settings.trust_level)
        logger.debug(
            "Trust level resolved: user_tl=%s, effective_tl=%d",
            user_tl,
            ctx.effective_tl,
            extra={
                "event": "orchestrator.trust_level_resolved",
                "task_id": ctx.task_id,
                "user_tl": user_tl,
                "effective_tl": ctx.effective_tl,
            },
        )

        # Session binding — acquire session and reject if locked.
        # D42 (FL-C79-a2): bind_session now always reloads from the store
        # inside the per-session lock; the previous ``pre_scanned_session``
        # mutable carrier is gone. The router's pre-lock load is no longer
        # threaded as a Session — it survives only as the boolean
        # ``ctx.input_pre_scanned`` signal that S1 input scan can be
        # skipped.  ``_use_sessions`` enables session binding when the
        # router pre-scanned (so the orchestrator must still reload the
        # post-lock snapshot) OR when conversation features are enabled.
        _use_sessions = ctx.input_pre_scanned or (
            settings.conversation_enabled
            and self._session_store is not None
            and self._conversation_analyzer is not None
        )
        ctx.intake = await bind_session(
            ctx.source_key,
            ctx.source,
            self._session_store if _use_sessions else None,
            input_pre_scanned=ctx.input_pre_scanned,
        )
        if ctx.intake.blocked:
            logger.debug(
                "Stage A: blocked by session binding",
                extra={
                    "event": "orchestrator.stage_a_blocked_session",
                    "task_id": ctx.task_id,
                },
            )
            return ctx.intake.task_result

        ctx.session = ctx.intake.session
        ctx.conv_info = ctx.intake.conv_info

        # Conversation analysis (multi-turn attack detection)
        if ctx.session is not None:
            conv_result = await analyze_conversation(
                ctx.user_request,
                ctx.session,
                self._conversation_analyzer,
                self._session_store,
                audit_emitter=getattr(self._pipeline, "_audit_emitter", None),
                multi_turn_monitor=self._multi_turn_monitor,
            )
            if conv_result.blocked:
                logger.debug(
                    "Stage A: blocked by conversation analysis",
                    extra={
                        "event": "orchestrator.stage_a_blocked_conversation",
                        "task_id": ctx.task_id,
                    },
                )
                return conv_result.task_result
            ctx.conv_info = conv_result.conv_info

        # Interrupted task detection — read the stale-True flag while it's
        # still authoritative (before any C48 reconciliation or new-task
        # set_task_in_progress overwrites it).  The boolean snapshot lets the
        # warning seam fire from observed-crash state without depending on
        # ordering with the helper or flag-set below.
        was_crashed = bool(ctx.session is not None and ctx.session.task_in_progress)
        if was_crashed:
            ctx.interrupted_context = build_interrupted_task_warning(ctx.session)

        # Input scanning (skipped when router already scanned).
        # ``intake.input_pre_scanned`` carries the scalar signal the router
        # threaded in via ``ctx.input_pre_scanned`` (D42: replaces the
        # previous Session-object carrier).
        if not ctx.intake.input_pre_scanned:
            input_scan_result = await scan_input(
                ctx.user_request,
                self._pipeline,
                ctx.session,
                self._session_store,
                ctx.conv_info,
            )
            if input_scan_result.blocked:
                logger.debug(
                    "Stage A: blocked by input scan",
                    extra={
                        "event": "orchestrator.stage_a_blocked_input_scan",
                        "task_id": ctx.task_id,
                    },
                )
                return input_scan_result.task_result

        # All Stage-A rejection gates have now passed (session-bind, conv
        # analysis, and — for non-pre-scanned paths — input scan).  C48
        # crash-reconciliation audit runs here so a blocked first-touch
        # never produces an audit row, and `_cleanup_task` (gated on
        # `ctx.task_in_progress_set`) leaves the stale flag in place for
        # the next entry-boundary touch to reconcile.
        # SYS-4: session_id as local on ctx — never stored on self, eliminates
        # race where a second concurrent request overwrites the instance field.
        if ctx.session is not None:
            ctx.session_id = ctx.session.session_id
            # In-memory short-circuit avoids a DB roundtrip on the
            # clean-session common case; only sessions whose flag is still
            # True (router didn't already clear, OR this is a non-pre-scanned
            # path that bypassed router) are candidates.
            if was_crashed and self._session_store is not None and ctx.session.user_id:
                await _maybe_emit_session_crash_reconciliation(
                    self._session_store,
                    getattr(self._pipeline, "_audit_emitter", None),
                    session_id=ctx.session.session_id,
                    user_id=ctx.session.user_id,
                )
            ctx.session.set_task_in_progress(True)
            if self._session_store is not None:
                await self._session_store.set_task_in_progress(
                    ctx.session.session_id, True
                )
            ctx.task_in_progress_set = True

            # F3: Get or create worker turn buffer for this session
            if ctx.session_id not in self._worker_contexts:
                self._worker_contexts[ctx.session_id] = WorkerContext(
                    session_id=ctx.session_id,
                )
            self._worker_context_accessed[ctx.session_id] = time.monotonic()

        return None
