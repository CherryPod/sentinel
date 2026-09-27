"""Audit-emit helper for ``system.session_crash_reconciliation``.

Co-located with :mod:`sentinel.session.store` (the producer of
:class:`~sentinel.session.store.ReconciliationResult`) rather than under
``sentinel/audit/``.  ``sentinel/audit/`` is on the cleanup-pass blast-radius
list — placing the helper here keeps the C48.fix gate at ``--hardening``.

Wire shape pinned in
``docs/design/2026-04-22-Q17-audit-wire-fix-design.md`` §D6 (re-adjudicated
2026-04-30, see cleanup-C48 design §3 for Property-D-honest field renames).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.audit.emitter import AuditEmitter
    from sentinel.session.store import ReconciliationResult, SessionStore

logger = logging.getLogger(__name__)


async def _emit_session_crash_reconciliation(
    audit_emitter: AuditEmitter | None,
    *,
    result: ReconciliationResult,
    reconciliation_reason: str = "crash_recovery",
) -> None:
    """Emit ``system.session_crash_reconciliation`` audit event.

    Best-effort fire-and-forget. ``asyncio.shield`` reduces the loss window
    between the reconciliation transaction commit and the audit emit when the
    caller's request is cancelled mid-await; it does NOT close the
    process-crash gap (a same-TX outbox would, and is out of scope for C48
    per the user's 2026-04-30 adjudication of Property-D-honest).

    Cancellation policy (D33.design lifecycle-surface ownership): shield IS
    preserved. Cancellation source is request-lifecycle (client disconnect,
    watchdog reap) — orthogonal to system shutdown and audit-DB health.
    CancelledError is still logged (``session.reconcile_audit_cancelled``)
    and re-raised; non-cancellation failures are swallowed and debug-logged.

    ``reconciliation_reason="crash_recovery"`` is currently the only wired
    value.  ``"eviction"`` and ``"shutdown"`` are reserved per the wire spec
    but have no producers today; if they ever land they may deserve separate
    event names if their semantics diverge enough.
    """
    if audit_emitter is None:
        return
    try:
        from sentinel.audit.events import SecurityAuditEvent

        details = {
            "session_id": result.session_id,
            "user_id": result.user_id,
            "task_in_progress_before": True,
            "cleared_at": result.cleared_at,
            "pending_approvals_observed_at_clear": (
                result.pending_approvals_observed_at_clear
            ),
            "pending_confirmations_observed_at_clear": (
                result.pending_confirmations_observed_at_clear
            ),
            "reconciliation_reason": reconciliation_reason,
            "session_age_s": result.session_age_s,
        }
        event = SecurityAuditEvent(
            event_type="system.session_crash_reconciliation",
            source_component="session.store",
            outcome="SUCCESS",
            severity="INFO",
            details=details,
        )
        await asyncio.shield(audit_emitter.emit(event))
    except asyncio.CancelledError:
        logger.debug(
            "Session reconcile audit emit cancelled — request cancelled",
            extra={"event": "session.reconcile_audit_cancelled"},
        )
        raise
    except Exception:
        logger.debug(
            "Crash reconciliation audit emission failed — continuing",
            exc_info=True,
            extra={"event": "session.reconcile_audit_failed"},
        )


async def _maybe_emit_session_crash_reconciliation(
    session_store: SessionStore,
    audit_emitter: AuditEmitter | None,
    *,
    session_id: str,
    user_id: int,
) -> None:
    """Run reconciliation transaction; emit audit on first successful clear.

    Single helper used at all three entry-boundary call sites (router /
    intake / approved-plan execution).  Idempotent across overlapping
    boundaries — the UPDATE-WHERE predicate ensures only one caller sees a
    non-None result for any given crashed session.

    Reconciliation DB failure must not propagate to the caller; the request
    continues without an audit row in that case (existing 7-day ``purge_old``
    sweep is the eventual backstop).  The catch is intentionally narrow:
    only DB-flavoured I/O errors are swallowed — programmer errors
    (``AttributeError`` from a missing collaborator, ``TypeError`` from a
    contract change) propagate so they fail loudly rather than silently
    losing the audit.
    """
    try:
        result = await session_store.reconcile_crashed_session(session_id, user_id)
    except (OSError, asyncio.TimeoutError) as exc:
        logger.warning(
            "Crash reconciliation transaction failed — continuing",
            exc_info=True,
            extra={
                "event": "session.reconcile_failed",
                "error_category": exc.__class__.__name__,
            },
        )
        return
    except Exception as exc:  # asyncpg.PostgresError + similar driver classes
        if exc.__class__.__module__.startswith(("asyncpg", "psycopg")):
            logger.warning(
                "Crash reconciliation transaction failed — continuing",
                exc_info=True,
                extra={
                    "event": "session.reconcile_failed",
                    "error_category": exc.__class__.__name__,
                },
            )
            return
        raise
    if result is None:
        return
    await _emit_session_crash_reconciliation(audit_emitter, result=result)
