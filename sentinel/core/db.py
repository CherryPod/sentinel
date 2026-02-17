"""PostgreSQL database maintenance functions.

Periodic purge helpers for audit logs, routine executions, provenance, and approvals.
No VACUUM needed — PostgreSQL autovacuum handles it.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("sentinel.audit")


async def purge_old_audit_log(pool: Any, days: int = 7) -> int:
    """Delete audit_log entries older than N days."""
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM audit_log "
            "WHERE created_at < NOW() - INTERVAL '1 day' * $1",
            days,
        )
        # asyncpg returns "DELETE N"
        deleted = int(result.split()[-1]) if result else 0

    if deleted > 0:
        logger.info(
            "Audit log purged",
            extra={"event": "audit_log_purge", "deleted": deleted, "days": days},
        )
    return deleted


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
            extra={"event": "routine_exec_purge", "deleted": deleted, "days": days},
        )
    return deleted


async def run_db_maintenance(pool: Any) -> dict[str, int]:
    """Run all periodic DB cleanup tasks.

    Takes the admin pool (sentinel_owner) for cross-user access — maintenance
    operations need to purge/read across all users, not just the current one.
    Must NOT be called with the RLS-wrapped application pool.
    """
    from sentinel.core.approval import ApprovalManager
    from sentinel.security.provenance import ProvenanceStore

    results: dict[str, int] = {}
    errors: dict[str, str] = {}

    # Each maintenance task is isolated — one failure must not abort the rest
    tasks = [
        ("audit_log", lambda: purge_old_audit_log(pool, days=7)),
        ("routine_executions", lambda: purge_old_routine_executions(pool, days=30)),
        ("provenance", lambda: ProvenanceStore(pool).cleanup_old(days=7)),
        ("approvals", lambda: ApprovalManager(pool).purge_old(days=7)),
    ]
    for name, task_fn in tasks:
        try:
            results[name] = await task_fn()
        except Exception:
            results[name] = 0
            logger.exception(
                "DB maintenance task failed",
                extra={"event": "db_maintenance_error", "task": name},
            )
            errors[name] = "failed"

    log_extra: dict[str, Any] = {"event": "db_maintenance", **results}
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
    return results
