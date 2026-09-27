"""PostgreSQL database maintenance functions.

Periodic purge helpers for audit logs, routine executions, provenance,
approvals, and confirmations. No VACUUM needed — PostgreSQL autovacuum
handles it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def purge_old_audit_log(pool: Any, days: int = 90) -> int:
    """Delete audit_log entries older than N days."""
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '1 day' * $1",
            days,
        )
        # asyncpg returns "DELETE N"
        deleted = int(result.split()[-1]) if result else 0

    if deleted > 0:
        logger.info(
            "Audit log purged",
            extra={"event": "audit.log_purge", "deleted": deleted, "days": days},
        )
    return deleted


async def purge_old_security_audit(
    pool: Any,
    category_retention: dict[str, int],
) -> int:
    """Delete security_audit_log entries older than category-specific retention.

    Uses the admin pool (sentinel_owner), which is exempt from the
    immutability trigger. Each category has its own retention period.
    """
    total = 0
    for category, days in category_retention.items():
        async with pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM security_audit_log "
                "WHERE event_category = $1 AND created_at < NOW() - INTERVAL '1 day' * $2",
                category,
                days,
            )
        count = int(result.split()[-1]) if result else 0
        total += count
    if total > 0:
        logger.info(
            "Security audit log purged",
            extra={"event": "audit.security_purge", "deleted": total},
        )
    return total


async def purge_old_routine_executions(pool: Any, days: int = 30) -> int:
    """Delete routine_executions older than N days."""
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM routine_executions "
            "WHERE started_at < NOW() - INTERVAL '1 day' * $1",
            days,
        )
        deleted = int(result.split()[-1]) if result else 0

    if deleted > 0:
        logger.info(
            "Routine executions purged",
            extra={"event": "routine.exec_purge", "deleted": deleted, "days": days},
        )
    return deleted


async def purge_old_webhook_replays(pool: Any, seconds: int = 600) -> int:
    """Delete webhook_replay_fingerprints older than N seconds.

    Q13.fix.e (F3). Replay fingerprints provide O(log n) deduplication of
    signed inbound webhook bodies. Retention target is bounded by sweep
    cadence (db_maintenance_interval_s, default 3600s), not this helper's
    window — any value < cadence is operationally equivalent because
    eviction happens only on sweep. Operates on the admin pool (same
    pattern as the other purge_* helpers in this module) because the
    table is NOT under RLS.
    """
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM webhook_replay_fingerprints "
            "WHERE received_at < NOW() - INTERVAL '1 second' * $1",
            seconds,
        )
        deleted = int(result.split()[-1]) if result else 0

    if deleted > 0:
        logger.info(
            "Webhook replay fingerprints purged",
            extra={
                "event": "webhook.replay_purge",
                "deleted": deleted,
                "seconds": seconds,
            },
        )
    return deleted


async def _emit_maintenance_audit(
    audit_emitter,
    *,
    results: dict[str, int],
    errors: dict[str, str],
) -> None:
    """Emit system.maintenance audit event after DB maintenance completes.

    Fire-and-forget: swallows non-cancellation exceptions so maintenance is
    never blocked by audit infrastructure failures.

    Cancellation policy (D33.design lifecycle-surface ownership): NOT shielded.
    Covers both the startup-time one-shot (init/database.py) and the periodic
    background-drain (_periodic_db_maintenance). Both are operator-withdrawing
    surfaces. CancelledError is logged and re-raised.
    """
    if audit_emitter is None:
        return
    try:
        from sentinel.audit.events import SecurityAuditEvent

        has_errors = bool(errors)
        event = SecurityAuditEvent(
            event_type="system.maintenance",
            source_component="db",
            outcome="DEGRADED" if has_errors else "SUCCESS",
            severity="MEDIUM" if has_errors else "INFO",
            details={
                "actor_type": "system",
                "purge_results": results,
                "total_purged": sum(results.values()),
                **({"errors": errors} if errors else {}),
            },
        )
        await audit_emitter.emit(event)
    except asyncio.CancelledError:
        logger.debug(
            "Maintenance audit emit cancelled — shutdown in progress",
            extra={"event": "db.maintenance_audit_cancelled"},
        )
        raise
    except Exception:
        logger.debug(
            "Maintenance audit event emission failed — continuing",
            exc_info=True,
            extra={"event": "db.maintenance_audit_failed"},
        )


async def run_db_maintenance(
    pool: Any,
    *,
    audit_emitter=None,
    event_bus: Any = None,
) -> dict[str, int]:
    """Run all periodic DB cleanup tasks.

    Takes the admin pool (sentinel_owner) for cross-user access — maintenance
    operations need to purge/read across all users, not just the current one.
    Must NOT be called with the RLS-wrapped application pool.

    Q5-F6: ``event_bus`` threads through to ``ApprovalManager.cleanup_and_notify``
    so ``approval.expired`` topics + audit events fire on auto-expiry. The
    function signature keeps ``event_bus`` keyword-optional for callers that
    genuinely want a pub/sub-less maintenance pass (tests, one-off scripts),
    but the production caller in ``init_database`` always passes a live bus.
    """
    from sentinel.core.approval import ApprovalManager
    from sentinel.core.confirmation import ConfirmationGate
    from sentinel.security.provenance import ProvenanceStore

    # Count wrapper: cleanup_and_notify returns list[dict]; task runners here
    # must return an int (row count) for the ``results`` dict.
    async def _approvals_notify() -> int:
        mgr = ApprovalManager(pool, event_bus=event_bus, audit_emitter=audit_emitter)
        expired = await mgr.cleanup_and_notify()
        return len(expired)

    results: dict[str, int] = {}
    errors: dict[str, str] = {}

    from sentinel.audit.events import CATEGORY_DEFAULTS

    retention = {cat: cfg.retention_days for cat, cfg in CATEGORY_DEFAULTS.items()}

    # Q5-F1: ConfirmationGate lacked any periodic purge. The ``confirmations``
    # table grows unbounded because every row transition is an UPDATE (pending →
    # confirmed / cancelled / expired) — no DELETE. We register both the
    # ``cleanup_expired`` sweep (pending→expired transition) AND ``purge_old``
    # (delete terminal-state rows older than retention) alongside the existing
    # approval purge.
    # Q5-F6: ``approvals_expired`` runs ``cleanup_and_notify`` (not the dead
    # ``_cleanup_expired``) so the auto-expired transition emits both the
    # ``approval.expired`` bus topic and the corresponding audit event. The
    # existing ``approvals`` task keeps ``purge_old`` (terminal-row delete).
    # Each maintenance task is isolated — one failure must not abort the rest.
    tasks = [
        ("audit_log", lambda: purge_old_audit_log(pool, days=90)),
        ("routine_executions", lambda: purge_old_routine_executions(pool, days=30)),
        ("provenance", lambda: ProvenanceStore(pool).cleanup_old(days=7)),
        # Q5-F6: expire pending → fire bus + audit events (cleanup_and_notify
        # path, replacing the previously-dead code path).
        ("approvals_expired", _approvals_notify),
        ("approvals", lambda: ApprovalManager(pool).purge_old(days=7)),
        # Q5-F1: confirmation periodic hygiene — expire pending past TTL, then
        # delete terminal-state rows older than 7d.
        ("confirmations_expired", lambda: ConfirmationGate(pool).cleanup_expired()),
        ("confirmations", lambda: ConfirmationGate(pool).purge_old(days=7)),
        ("security_audit_log", lambda: purge_old_security_audit(pool, retention)),
        # Q13.fix.e — webhook replay fingerprints: retention 600s (10min),
        # bounded by sweep cadence not this window.
        (
            "webhook_replay_fingerprints",
            lambda: purge_old_webhook_replays(pool, seconds=600),
        ),
    ]
    for name, task_fn in tasks:
        try:
            results[name] = await task_fn()
        except Exception:
            results[name] = 0
            logger.exception(
                "DB maintenance task failed",
                extra={"event": "db.maintenance_error", "task": name},
            )
            errors[name] = "failed"

    log_extra: dict[str, Any] = {"event": "db.maintenance", **results}
    if errors:
        log_extra["errors"] = errors
        logger.warning(
            "DB maintenance completed with errors",
            extra=log_extra,
        )
    else:
        logger.info(
            "DB maintenance complete",
            extra=log_extra,
        )

    # Emit structured audit event
    await _emit_maintenance_audit(audit_emitter, results=results, errors=errors)

    return results
