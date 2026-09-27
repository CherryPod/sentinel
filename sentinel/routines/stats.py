"""Routine execution statistics and record management.

Handles persistence (PostgreSQL with in-memory fallback) for routine
execution records: start/completion recording, stale cleanup, history
queries, and aggregate stats.

Also hosts shared timestamp helpers used by the engine module.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

_LOG_PREVIEW_LIMIT = 200  # max chars for error/summary in log extras


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _parse_iso(s: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a UTC datetime."""
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def _dt_to_iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class RoutineStats:
    """Execution record storage and statistics for the routine engine."""

    def __init__(
        self,
        pool: Any | None = None,
        admin_pool: Any | None = None,
    ):
        self._pool = pool
        self._admin_pool = admin_pool
        self._in_memory = pool is None

        # In-memory execution storage for tests (pool=None)
        self._mem_executions: dict[str, dict] = {}

    async def record_start(
        self,
        execution_id: str,
        routine_id: str,
        user_id: int,
        triggered_by: str,
    ) -> None:
        logger.debug(
            "stats.record_start",
            extra={
                "event": "stats.record_start",
                "execution_id": execution_id,
                "routine_id": routine_id,
                "triggered_by": triggered_by,
            },
        )
        if self._in_memory:
            self._mem_executions[execution_id] = {
                "execution_id": execution_id,
                "routine_id": routine_id,
                "user_id": user_id,
                "triggered_by": triggered_by,
                "started_at": _now_iso(),
                "completed_at": "",
                "status": "running",
                "result_summary": "",
                "error": "",
                "task_id": "",
            }
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO routine_executions "
                "(execution_id, routine_id, user_id, triggered_by, started_at, status) "
                "VALUES ($1, $2, $3, $4, NOW(), 'running')",
                execution_id,
                routine_id,
                user_id,
                triggered_by,
            )

    async def record_completion(
        self,
        execution_id: str,
        status: str,
        result_summary: str = "",
        error: str = "",
        task_id: str = "",
    ) -> None:
        logger.debug(
            "stats.record_completion",
            extra={
                "event": "stats.record_completion",
                "execution_id": execution_id,
                "status": status,
            },
        )
        if self._in_memory:
            if execution_id in self._mem_executions:
                rec = self._mem_executions[execution_id]
                rec["status"] = status
                rec["completed_at"] = _now_iso()
                rec["result_summary"] = result_summary
                rec["error"] = error
                rec["task_id"] = task_id
            return
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE routine_executions "
                "SET status = $1, completed_at = NOW(), result_summary = $2, "
                "error = $3, task_id = $4 "
                "WHERE execution_id = $5",
                status,
                result_summary,
                error,
                task_id,
                execution_id,
            )
        # Q5.fix.e D3e: FK cascade on routines.routine_id silently removes
        # matching routine_executions rows when the parent routine is deleted.
        # A subsequent record_completion UPDATE then hits zero rows with no
        # signal, losing the completion record. Log at WARNING so the race
        # between a running execution and a concurrent routine delete is
        # observable. Per Q5.fix.design Codex adjudication #7 (thread
        # 019db531).
        rows = 0
        if result:
            parts = result.split()
            if parts:
                try:
                    rows = int(parts[-1])
                except ValueError as exc:
                    # Unexpected asyncpg result shape — fall through to zero-row
                    # WARNING below (same observable behaviour as a literal
                    # UPDATE 0) after logging the parse failure for diagnosis.
                    logger.debug(
                        "record_completion: result-parse ValueError",
                        extra={
                            "event": "routines.stats.record_completion_parse_error",
                            "error": str(exc),
                            "update_result": result,
                        },
                    )
                    rows = 0
        if rows == 0:
            logger.warning(
                "record_completion hit zero rows — routine_executions row absent "
                "(likely raced with routine delete / FK cascade)",
                extra={
                    "event": "routines.stats.record_completion_missing",
                    "execution_id": execution_id,
                    "status": status,
                    "update_result": result,
                },
            )

    async def cleanup_stale(self) -> int:
        """Mark stale 'running' executions as 'interrupted'. Returns count.

        Finding #11: Uses admin pool (bypasses RLS) since stale executions
        may belong to any user. Removed hardcoded current_user_id.set(1).
        """
        if self._in_memory:
            count = 0
            for rec in self._mem_executions.values():
                if rec["status"] == "running":
                    rec["status"] = "interrupted"
                    rec["error"] = "Engine restarted while execution was in progress"
                    rec["completed_at"] = _now_iso()
                    count += 1
            return count
        # Use admin pool to bypass RLS — stale executions span all users
        pool = self._admin_pool or self._pool
        async with pool.acquire() as conn:
            # BH3-054: Log individual interrupted executions
            stale_rows = await conn.fetch(
                "SELECT execution_id, routine_id, started_at "
                "FROM routine_executions WHERE status = 'running'",
            )
            if not stale_rows:
                return 0
            for row in stale_rows:
                logger.warning(
                    "Interrupted stale routine execution on restart",
                    extra={
                        "event": "routine.execution_interrupted",
                        "execution_id": row["execution_id"],
                        "routine_id": row["routine_id"],
                        "started_at": str(row["started_at"]),
                    },
                )
            result = await conn.execute(
                "UPDATE routine_executions "
                "SET status = 'interrupted', "
                "error = 'Engine restarted while execution was in progress', "
                "completed_at = NOW() "
                "WHERE status = 'running'",
            )
            # asyncpg returns "UPDATE N"
            return int(result.split()[-1]) if result else 0

    async def get_execution_history(
        self,
        routine_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        logger.debug(
            "stats.get_execution_history",
            extra={
                "event": "stats.get_execution_history",
                "routine_id": routine_id,
                "limit": limit,
                "offset": offset,
            },
        )
        if self._in_memory:
            matching = [
                dict(rec)
                for rec in self._mem_executions.values()
                if rec["routine_id"] == routine_id
            ]
            matching.sort(key=lambda r: r["started_at"], reverse=True)
            return matching[offset : offset + limit]
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT execution_id, routine_id, user_id, triggered_by, "
                "started_at, completed_at, status, result_summary, error, task_id "
                "FROM routine_executions "
                "WHERE routine_id = $1 "
                "ORDER BY started_at DESC "
                "LIMIT $2 OFFSET $3",
                routine_id,
                limit,
                offset,
            )
            return [
                {
                    "execution_id": r["execution_id"],
                    "routine_id": r["routine_id"],
                    "user_id": r["user_id"],
                    "triggered_by": r["triggered_by"],
                    "started_at": _dt_to_iso(r["started_at"]),
                    "completed_at": _dt_to_iso(r["completed_at"]),
                    "status": r["status"],
                    "result_summary": r["result_summary"],
                    "error": r["error"],
                    "task_id": r["task_id"],
                }
                for r in rows
            ]

    async def get_execution_stats(self, cutoff: str | None = None) -> dict:
        logger.debug(
            "stats.get_execution_stats",
            extra={"event": "stats.get_execution_stats", "cutoff": cutoff},
        )
        if self._in_memory:
            recs = list(self._mem_executions.values())
            if cutoff is not None:
                recs = [r for r in recs if r["started_at"] >= cutoff]
            counts: dict[str, int] = {}
            for r in recs:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            total = sum(counts.values())
            durations: list[float] = []
            for r in recs:
                if r["completed_at"] and r["started_at"]:
                    try:
                        s = _parse_iso(r["started_at"])
                        e = _parse_iso(r["completed_at"])
                        d = (e - s).total_seconds()
                        if d >= 0:
                            durations.append(d)
                    except (ValueError, TypeError):
                        logger.debug(
                            "get_execution_stats: ValueError | TypeError suppressed",
                            extra={"event": "stats.get_execution_stats.suppressed"},
                            exc_info=True,
                        )
            avg_duration = (
                round(sum(durations) / len(durations), 1) if durations else 0.0
            )
            return {
                "total": total,
                "success": counts.get("success", 0),
                "error": counts.get("error", 0),
                "timeout": counts.get("timeout", 0),
                "avg_duration_s": avg_duration,
            }
        logger.debug(
            "get_execution_stats: in_memory_passed",
            extra={
                "event": "stats.get_execution_stats.suppressed.passed",
                "reason": "in_memory_passed",
            },
        )  # auto:neg

        async with self._pool.acquire() as conn:
            # asyncpg requires datetime for TIMESTAMPTZ params, not strings
            cutoff_dt = _parse_iso(cutoff) if cutoff is not None else None
            if cutoff_dt is not None:
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM routine_executions "
                    "WHERE started_at >= $1::timestamptz GROUP BY status",
                    cutoff_dt,
                )
            else:
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM routine_executions "
                    "GROUP BY status",
                )
            counts_db = {r["status"]: r["cnt"] for r in rows}

            total = sum(counts_db.values())
            success = counts_db.get("success", 0)
            error = counts_db.get("error", 0)
            timeout = counts_db.get("timeout", 0)

            # Average duration from completed executions
            if cutoff_dt is not None:
                dur_rows = await conn.fetch(
                    "SELECT EXTRACT(EPOCH FROM (completed_at - started_at)) AS dur "
                    "FROM routine_executions "
                    "WHERE started_at >= $1::timestamptz AND completed_at IS NOT NULL",
                    cutoff_dt,
                )
            else:
                dur_rows = await conn.fetch(
                    "SELECT EXTRACT(EPOCH FROM (completed_at - started_at)) AS dur "
                    "FROM routine_executions WHERE completed_at IS NOT NULL",
                )
            durations_db = [
                r["dur"] for r in dur_rows if r["dur"] is not None and r["dur"] >= 0
            ]
            avg_duration = (
                round(sum(durations_db) / len(durations_db), 1) if durations_db else 0.0
            )

            return {
                "total": total,
                "success": success,
                "error": error,
                "timeout": timeout,
                "avg_duration_s": avg_duration,
            }
