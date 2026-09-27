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
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sentinel.core.context import require_user_id
from sentinel.core.exceptions import ToolBlockedError
from sentinel.core.models import TaskResult
from sentinel.crypto.blind_index import log_hash
from sentinel.planner.intake import resolve_contacts
from sentinel.router.classifier import Route
from sentinel.session._session_audit import (
    _maybe_emit_session_crash_reconciliation,
)
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


@dataclass
class _PreparedRequest:
    """Result of scan-and-prepare phase — carries validated state forward.

    D42 (FL-C79-a2): the prior ``session: Session | None`` field carried
    the router's pre-acquire snapshot all the way through to dispatch.
    Downstream writes (FastPath._record_turn / orchestrator add_turn for
    refusal/blocked turns) then washed concurrent intra-lock counter
    bumps.  The session is no longer threaded across the lock boundary;
    each dispatch path reloads inside its own per-session lock.
    """

    user_request: str
    user_id: int


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
        contact_store: ContactStore | None = None,
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
        user_request_data_id: str | None = None,
    ) -> TaskResult:
        """Route a user request through scan -> classify -> dispatch.

        Returns a TaskResult regardless of which path is taken.

        ``user_request_data_id`` is the Q8.fix.a ingress-time TaggedData id
        passed through from the channel/API adapter; threaded to downstream
        dispatch paths (bypass, planner) so S3 provenance lookups resolve.
        """
        logger.debug(
            "route called",
            extra={
                "event": "router.route",
                "source": source,
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
                "task_id": task_id,
                "enabled": self._enabled,
                "user_request_data_id": user_request_data_id,
            },
        )
        # 1. Feature flag — full bypass when disabled
        if not self._enabled:
            return await self._orchestrator.handle_task(
                user_request,
                source=source,
                approval_mode=approval_mode,
                source_key=source_key,
                task_id=task_id,
                user_request_data_id=user_request_data_id,
            )

        # 2-4b. Session binding, input scanning, contact resolution
        prepared = await self._scan_and_prepare(user_request, source, source_key)
        if isinstance(prepared, TaskResult):
            return prepared

        # 4c-4d. Pending confirmation / plan approval intercepts
        pending_result = await self._check_pending_actions(
            prepared.user_request,
            prepared.user_id,
            source,
            source_key,
            task_id,
            user_request_data_id=user_request_data_id,
        )
        if pending_result is not None:
            return pending_result

        # 5. Classify
        classification = await self._classifier.classify(prepared.user_request)

        # 6. Dispatch
        if classification.route == Route.FAST:
            return await self._dispatch_fast(
                classification.template_name,
                classification.params,
                source,
                source_key,
                task_id,
                prepared.user_id,
            )

        return await self._dispatch_planner(
            prepared.user_request,
            source,
            approval_mode,
            source_key,
            task_id,
            user_request_data_id=user_request_data_id,
        )

    async def _scan_and_prepare(
        self,
        user_request: str,
        source: str,
        source_key: str | None,
    ) -> TaskResult | _PreparedRequest:
        """Scan input, resolve contacts.

        Returns a TaskResult on early exit (blocked/error/rejected), or
        a _PreparedRequest with validated state for downstream steps.

        D42 (FL-C79-a2): does NOT pre-load the session.  Codex
        adversarial review (thread `019de412`) flagged that the
        previous advisory ``get_or_create`` itself mutated persisted
        state — it updates ``last_active`` (store.py:413), runs
        ``apply_decay`` (store.py:894-901) which can persist new
        ``cumulative_risk`` / ``violation_count`` / ``is_locked``,
        and on auto-unlock DELETEs ``conversation_turns``.  Calling
        it outside the per-session lock would still allow a stale
        session to reach an ``add_turn`` write across the lock
        boundary (the very TOCTOU class this fix exists to close).

        The dispatch paths (``_dispatch_fast`` and the orchestrator's
        ``plan_and_execute`` → ``bind_session``) each load fresh under
        their own held lock and re-verify ``is_locked``.  The
        input-scan-blocked path loads inside the lock via
        ``_record_input_blocked_locked``.  C48 reconciliation also
        moved into the dispatch paths.  The router itself no longer
        touches the session.
        """
        # Input scanning (no pre-lock session load — see docstring)
        try:
            scan_result = await self._pipeline.scan_input(user_request)
        except Exception:  # catch-all: input scan crash — fail closed
            logger.warning(
                "Input scan failed",
                extra={"event": "router.input_scan_failed"},
                exc_info=True,
            )
            return TaskResult(
                status="error",
                reason="Request processing failed",
            )

        if not scan_result.is_clean:
            blockers = list(scan_result.violated_scanners())
            reason = f"Input blocked by: {', '.join(blockers)}"
            logger.warning(
                "Input scan blocked request: %s",
                blockers,
                extra={"event": "router.input_blocked", "blockers": blockers},
            )
            # D42: record the blocked turn under the per-session lock so
            # the persisted counter bump cannot wash concurrent writes.
            if source_key is not None and self._session_store is not None:
                await self._record_input_blocked_locked(
                    source_key=source_key,
                    source=source,
                    user_request=user_request,
                    blockers=blockers,
                )
            return TaskResult(status="blocked", reason=reason)

        # Contact resolution — resolve sender, rewrite names to opaque IDs
        contact_result = await resolve_contacts(
            self._contact_store,
            source_key,
            user_request,
        )
        if contact_result.rejected:
            return TaskResult(
                status="rejected",
                reason=contact_result.error or "Unknown sender",
            )
        if contact_result.audit_log:
            logger.info(
                "Contact resolution applied",
                extra={
                    "event": "contact.resolution",
                    "user_id": contact_result.user_id,
                    "rewrites": len(contact_result.audit_log),
                },
            )

        return _PreparedRequest(
            user_request=contact_result.rewritten_text,
            user_id=contact_result.user_id,
        )

    async def _record_input_blocked_locked(
        self,
        source_key: str,
        source: str,
        user_request: str,
        blockers: list[str],
    ) -> None:
        """D42 (FL-C79-a2): write the input-blocked turn under the lock.

        Acquires the per-session lock, reloads the session inside the
        lock, appends the blocked turn, and persists.  Without the lock,
        a stale snapshot's ``violation_count`` / ``cumulative_risk``
        could pass a concurrent intra-lock writer (e.g. another
        channel's turn record), and the SQL UPDATE inside
        ``SessionStore.add_turn`` (store.py:651-659) would wash the
        concurrent bump.

        Lock release is gated by ``lock_held`` per the Q14a-r2 round-2
        discipline: the acquire moves inside the ``try`` and
        ``release()`` only fires when the acquire actually completed,
        so a raised ``acquire()`` (e.g. ``CancelledError``) cannot
        invoke ``release()`` on an unacquired lock.

        Best-effort: a failure to load or persist the blocked-turn
        record is logged but does not propagate; the request itself
        is still rejected by the caller.
        """
        if self._session_store is None:
            return

        session_lock = self._session_store.get_lock(source_key)
        lock_held = False
        try:
            await session_lock.acquire()
            lock_held = True
            session = await self._session_store.get_or_create(source_key, source=source)
            if session is None:
                return
            turn = ConversationTurn(
                request_text=user_request,
                result_status="blocked",
                blocked_by=blockers,
            )
            session.add_turn(turn)
            await self._session_store.add_turn(
                session.session_id, turn, session=session
            )
        except Exception:  # catch-all: blocked-turn record best-effort
            logger.warning(
                "Failed to record input-blocked turn",
                extra={
                    "event": "router.blocked_turn_record_failed",
                    "source_channel": source_key.split(":", 1)[0]
                    if ":" in source_key
                    else None,
                    "source_key_hash": log_hash(source_key),
                },
                exc_info=True,
            )
        finally:
            if lock_held:
                session_lock.release()

    async def _check_pending_actions(
        self,
        user_request: str,
        user_id: int,
        source: str,
        source_key: str | None,
        task_id: str | None,
        user_request_data_id: str | None = None,
    ) -> TaskResult | None:
        """Check for pending confirmations or plan approvals.

        Returns a TaskResult if a pending action was handled (confirmation
        reply or plan approval), or None to continue with normal routing.

        D42 (FL-C79-a2): no longer accepts a router-loaded ``session``.
        The cancel-and-reroute branch in ``_handle_confirmation_reply``
        dispatches to ``_dispatch_fast`` / ``_dispatch_planner`` which
        each load fresh inside their own per-session lock.
        """
        # Pending confirmation check
        if self._confirmation_gate is not None and source_key is not None:
            pending = await self._confirmation_gate.get_pending(source_key)
            if pending is not None:
                return await self._handle_confirmation_reply(
                    user_request,
                    pending,
                    source,
                    source_key,
                    task_id,
                    user_id=user_id,
                    user_request_data_id=user_request_data_id,
                )

        # Plan approval check — "go" with no fast-path confirmation triggers
        # pending plan approval if one exists for this source_key
        if (
            source_key is not None
            and user_request.strip().lower() == "go"
            and self._orchestrator.approval_manager is not None
        ):
            pending_approval = (
                await self._orchestrator.approval_manager.get_pending_by_source_key(
                    source_key,
                )
            )
            if pending_approval is not None:
                accepted = await self._orchestrator.submit_approval(
                    approval_id=pending_approval["approval_id"],
                    granted=True,
                    reason="confirmed via channel",
                    source_key=source_key,
                )
                if not accepted:
                    return TaskResult(
                        status="expired",
                        reason="Plan approval expired. Send your request again.",
                    )
                return await self._orchestrator.execute_approved_plan(
                    pending_approval["approval_id"],
                )

        return None

    async def _handle_confirmation_reply(
        self,
        user_request: str,
        pending: ConfirmationEntry,
        source: str,
        source_key: str | None,
        task_id: str | None,
        user_id: int | None = None,
        user_request_data_id: str | None = None,
    ) -> TaskResult:
        """Handle a message when a confirmation is pending.

        "go" (exact, trimmed, case-insensitive) confirms and executes.
        Anything else cancels and routes the new message normally.

        D42 (FL-C79-a2): no longer accepts a router-loaded ``session``.
        The cancel-and-reroute branch dispatches to ``_dispatch_fast`` /
        ``_dispatch_planner`` which each load fresh inside their own
        per-session lock.  (The previous Q3-F6 fix that threaded the
        session was needed for the fast-path NameSpaced "unknown"
        fallback; that fallback is gone now that ``_dispatch_fast``
        owns its own session reload.)
        """
        user_id = require_user_id(user_id, "MessageRouter._handle_confirmation_reply")
        if user_request.strip().lower() == "go":
            # Q10-F3: pass transport source_key so ConfirmationGate.confirm()
            # enforces reconnect-invalidation binding (parallel to Q3-F4 for
            # approvals).
            entry = await self._confirmation_gate.confirm(
                pending.confirmation_id,
                source_key=source_key,
            )
            if entry is None:
                # Expired or already handled between check and confirm
                return TaskResult(
                    status="expired",
                    reason="Pending action expired. Send your request again.",
                )
            # D42 (FL-C79-a2) fix-now (Codex adversarial 019de412 finding 2):
            # the confirmation "go" branch never reaches _dispatch_fast or
            # _dispatch_planner, so C48 crash-reconciliation would be
            # silently skipped here without an explicit emission.  Acquire
            # the per-session lock, reload the session inside it, run C48
            # against the in-lock snapshot, then execute the confirmed
            # tool call.  Lock release is gated by lock_held per the
            # Q14a-r2 round-2 discipline.
            session_lock = None
            lock_held = False
            if source_key is not None and self._session_store is not None:
                session_lock = self._session_store.get_lock(source_key)

            try:
                if session_lock is not None:
                    await session_lock.acquire()
                    lock_held = True

                if (
                    source_key is not None
                    and self._session_store is not None
                ):
                    session = await self._session_store.get_or_create(
                        source_key, source=source
                    )
                    if (
                        session is not None
                        and session.task_in_progress
                    ):
                        await _maybe_emit_session_crash_reconciliation(
                            self._session_store,
                            getattr(self._pipeline, "_audit_emitter", None),
                            session_id=session.session_id,
                            user_id=user_id,
                        )

                # Execute the stored tool call
                try:
                    result_dict = await self._fast_path.execute_confirmed(
                        entry.tool_name,
                        entry.tool_params,
                        entry.task_id,
                    )
                except ToolBlockedError as exc:
                    # Q9-F3: FastPathExecutor narrow-raises ToolBlockedError past
                    # the broad swallow so D5 BLOCKED semantics stay distinguishable.
                    # Caller absorbs here to produce a structured TaskResult instead
                    # of bubbling up to an uncaught HTTP 500. The audit event (HIGH)
                    # was already emitted by ToolExecutor (executor.py:416-430).
                    logger.exception(
                        "_handle_confirmation_reply: ToolBlockedError",
                        extra={
                            "event": "router.router._handle_confirmation_reply_toolblockederror"
                        },
                    )  # auto:except
                    return TaskResult(
                        status="blocked",
                        reason=f"Tool blocked by policy: {exc}",
                    )
                return TaskResult(
                    status=result_dict.get("status", "error"),
                    reason=result_dict.get("reason") or "",
                    response=result_dict.get("response") or "",
                )
            finally:
                if lock_held:
                    session_lock.release()

        # Not "go" — cancel and route the new message normally
        await self._confirmation_gate.cancel(pending.confirmation_id)
        logger.info(
            "Confirmation cancelled by new message",
            extra={
                "event": "confirmation.cancelled_by_message",
                "confirmation_id": pending.confirmation_id,
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
            },
        )
        # Continue with normal routing — classify and dispatch
        classification = await self._classifier.classify(user_request)

        if classification.route == Route.FAST:
            return await self._dispatch_fast(
                classification.template_name,
                classification.params,
                source,
                source_key,
                task_id,
                user_id,
            )

        return await self._dispatch_planner(
            user_request,
            source,
            "auto",
            source_key,
            task_id,
            user_request_data_id=user_request_data_id,
        )

    async def _dispatch_fast(
        self,
        template_name: str,
        params: dict,
        source: str,
        source_key: str | None,
        task_id: str | None,
        user_id: int,
    ) -> TaskResult:
        """Execute via the fast path and convert the result dict to TaskResult.

        Qwen-extracted params are UNTRUSTED — scan each string value through
        the input pipeline before forwarding to tool execution.

        D42 (FL-C79-a2): owns the per-session lock for the fast-path
        execution.  Acquires the lock first, reloads the session inside
        the lock via ``get_or_create``, runs C48 reconciliation (if the
        in-lock snapshot still shows ``task_in_progress=True`` after a
        prior crash), and passes the fresh session into
        ``FastPathExecutor.execute``.  ``FastPathExecutor._record_turn``
        writes its turn under the same held lock, so the persisted
        ``violation_count`` / ``cumulative_risk`` UPDATE cannot wash
        a concurrent intra-lock writer.  Lock release is gated by
        ``lock_held`` per the Q14a-r2 round-2 discipline so an
        ``acquire()`` that raises does not leak.
        """
        # BH3-DEF1: Scan Qwen-extracted param values through input pipeline.
        # Runs BEFORE the per-session lock acquire so a Qwen-rejection
        # short-circuits without contending on the lock.  The user's raw
        # message was already scanned, but Qwen could hallucinate or
        # inject different param values.
        param_text = " ".join(str(v) for v in params.values() if v is not None)
        if param_text:
            try:
                param_scan = await self._pipeline.scan_input(param_text)
            except Exception:  # catch-all: param scan crash — fail closed
                logger.warning(
                    "Param input scan failed for %s",
                    template_name,
                    extra={
                        "event": "router.param_scan_failed",
                        "template": template_name,
                    },
                    exc_info=True,
                )
                return TaskResult(
                    status="error",
                    reason="Request processing failed",
                )
            if not param_scan.is_clean:
                blockers = list(param_scan.violated_scanners())
                logger.warning(
                    "Qwen-extracted params blocked by %s for %s",
                    blockers,
                    template_name,
                    extra={
                        "event": "router.param_blocked",
                        "template": template_name,
                        "blockers": blockers,
                    },
                )
                return TaskResult(
                    status="blocked",
                    reason=f"Fast-path params blocked by: {', '.join(blockers)}",
                )

        # D42 (FL-C79-a2): per-session lock owns the fast-path session
        # reload + execution.  ``lock_held`` gates release per Q14a-r2
        # round-2 discipline so an ``acquire()`` that raises does not
        # leak.
        session_lock = None
        lock_held = False
        if source_key is not None and self._session_store is not None:
            session_lock = self._session_store.get_lock(source_key)

        try:
            if session_lock is not None:
                await session_lock.acquire()
                lock_held = True

            session: Session | None = None
            if source_key is not None and self._session_store is not None:
                session = await self._session_store.get_or_create(
                    source_key, source=source
                )
                # Re-verify is_locked under the lock — the advisory
                # check in _scan_and_prepare may have been stale.
                if session is not None and session.is_locked:
                    return TaskResult(
                        status="blocked",
                        reason="Session locked — too many security violations",
                    )

            # C48: Crash-reconciliation audit (Property-D-honest).
            # Runs against the in-lock-loaded snapshot so the
            # ``WHERE task_in_progress = TRUE`` predicate sees the
            # state that any concurrent path also sees inside its lock.
            if (
                session is not None
                and session.task_in_progress
                and self._session_store is not None
            ):
                await _maybe_emit_session_crash_reconciliation(
                    self._session_store,
                    getattr(self._pipeline, "_audit_emitter", None),
                    session_id=session.session_id,
                    user_id=user_id,
                )

            try:
                result_dict = await self._fast_path.execute(
                    template_name,
                    params,
                    session,
                    task_id,
                    user_id,
                )
            except ToolBlockedError as exc:
                # Q9-F3 caller absorption (see _handle_confirmation_reply).
                logger.exception(
                    "_dispatch_fast: ToolBlockedError",
                    extra={"event": "router.router._dispatch_fast_toolblockederror"},
                )  # auto:except
                return TaskResult(
                    status="blocked",
                    reason=f"Tool blocked by policy: {exc}",
                )
            return TaskResult(
                status=result_dict.get("status", "error"),
                reason=result_dict.get("reason") or "",
                response=result_dict.get("response") or "",
            )
        finally:
            if lock_held:
                session_lock.release()

    async def _dispatch_planner(
        self,
        user_request: str,
        source: str,
        approval_mode: str,
        source_key: str | None,
        task_id: str | None,
        user_request_data_id: str | None = None,
    ) -> TaskResult:
        """Dispatch to the orchestrator via plan_and_execute.

        D42 (FL-C79-a2): no longer threads the router's pre-acquire
        ``session`` snapshot into the orchestrator.  ``plan_and_execute``
        reloads the session from the store inside its per-session lock,
        so router-side stale reads can no longer wash concurrent writes.
        Only the boolean ``input_pre_scanned=True`` signal crosses the
        boundary, telling the orchestrator the router already ran S1.

        ``user_request_data_id`` — Q8.fix.a ingress-time TaggedData id
        threaded from ``route`` → ``plan_and_execute`` so downstream S3
        resolves to the ingress record.
        """
        return await self._orchestrator.plan_and_execute(
            user_request=user_request,
            source=source,
            approval_mode=approval_mode,
            source_key=source_key,
            task_id=task_id,
            input_pre_scanned=True,
            user_request_data_id=user_request_data_id,
        )
