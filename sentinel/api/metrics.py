"""Metrics aggregation for the dashboard.

Queries the SQLite database to produce operational metrics for a given
time window. All aggregation is server-side — the API returns pre-computed
numbers ready for rendering.
"""

import json
import sqlite3
from statistics import median

_WINDOW_MODIFIERS = {
    "24h": "-1 day",
    "7d": "-7 days",
    "30d": "-30 days",
    "all": None,
}


def get_metrics(db: sqlite3.Connection, window: str = "24h") -> dict:
    """Aggregate all dashboard metrics for a time window.

    Args:
        db: Open SQLite connection.
        window: One of "24h", "7d", "30d", "all".

    Returns:
        Dict with approval_funnel, task_outcomes, scanner_blocks,
        routine_health, session_health, and response_times sections.
    """
    modifier = _WINDOW_MODIFIERS.get(window)
    cutoff = _cutoff_sql(modifier)

    return {
        "approval_funnel": _approval_funnel(db, cutoff),
        "task_outcomes": _task_outcomes(db, cutoff),
        "scanner_blocks": _scanner_blocks(db, cutoff),
        "routine_health": _routine_health(db, cutoff),
        "session_health": _session_health(db),
        "response_times": _response_times(db, cutoff),
    }


def _cutoff_sql(modifier: str | None) -> str | None:
    """Return a SQL expression for the cutoff timestamp, or None for 'all'."""
    if modifier is None:
        return None
    return f"strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '{modifier}')"


def _where_created(cutoff: str | None, table_prefix: str = "") -> str:
    """Build a WHERE clause filtering by created_at >= cutoff."""
    if cutoff is None:
        return ""
    col = f"{table_prefix}created_at" if table_prefix else "created_at"
    return f" WHERE {col} >= {cutoff}"


def _and_created(cutoff: str | None, table_prefix: str = "") -> str:
    """Build an AND clause filtering by created_at >= cutoff."""
    if cutoff is None:
        return ""
    col = f"{table_prefix}created_at" if table_prefix else "created_at"
    return f" AND {col} >= {cutoff}"


def _approval_funnel(db: sqlite3.Connection, cutoff: str | None) -> dict:
    """Count approvals by status + auto-approved from conversation_turns."""
    where = _where_created(cutoff)
    rows = db.execute(
        f"SELECT status, COUNT(*) FROM approvals{where} GROUP BY status"
    ).fetchall()
    counts = {row[0]: row[1] for row in rows}

    # Auto-approved count from conversation_turns
    ct_where = _where_created(cutoff)
    auto_row = db.execute(
        f"SELECT COUNT(*) FROM conversation_turns{ct_where}"
        + (" AND" if ct_where else " WHERE")
        + " auto_approved = 1"
    ).fetchone()

    return {
        "auto_approved": auto_row[0] if auto_row else 0,
        "manually_approved": counts.get("approved", 0),
        "denied": counts.get("denied", 0),
        "expired": counts.get("expired", 0),
        "pending": counts.get("pending", 0),
    }


def _task_outcomes(db: sqlite3.Connection, cutoff: str | None) -> dict:
    """Group conversation_turns by result_status."""
    where = _where_created(cutoff)
    rows = db.execute(
        f"SELECT result_status, COUNT(*) FROM conversation_turns{where} GROUP BY result_status"
    ).fetchall()
    counts = {row[0]: row[1] for row in rows}

    return {
        "success": counts.get("success", 0),
        "blocked": counts.get("blocked", 0),
        "error": counts.get("error", 0),
        "refused": counts.get("refused", 0),
        "denied": counts.get("denied", 0),
        "awaiting_approval": counts.get("awaiting_approval", 0),
    }


def _scanner_blocks(db: sqlite3.Connection, cutoff: str | None) -> list[dict]:
    """Parse blocked_by JSON arrays and count scanner occurrences."""
    where = _where_created(cutoff)
    condition = (
        f"{where} AND result_status = 'blocked'"
        if where
        else " WHERE result_status = 'blocked'"
    )
    rows = db.execute(
        f"SELECT blocked_by FROM conversation_turns{condition}"
    ).fetchall()

    scanner_counts: dict[str, int] = {}
    for (blocked_by_json,) in rows:
        try:
            scanners = json.loads(blocked_by_json) if blocked_by_json else []
        except (json.JSONDecodeError, TypeError):
            continue
        for scanner in scanners:
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

    # Sort by count descending
    return [
        {"scanner": name, "count": count}
        for name, count in sorted(scanner_counts.items(), key=lambda x: -x[1])
    ]


def _routine_health(db: sqlite3.Connection, cutoff: str | None) -> dict:
    """Aggregate routine execution stats."""
    # Use started_at for routine_executions (not created_at)
    if cutoff is not None:
        where = f" WHERE started_at >= {cutoff}"
    else:
        where = ""

    rows = db.execute(
        f"SELECT status, COUNT(*) FROM routine_executions{where} GROUP BY status"
    ).fetchall()
    counts = {row[0]: row[1] for row in rows}

    total = sum(counts.values())
    success = counts.get("success", 0)
    error = counts.get("error", 0)
    timeout = counts.get("timeout", 0)

    # Average duration from completed executions
    dur_rows = db.execute(
        "SELECT (julianday(completed_at) - julianday(started_at)) * 86400.0 "
        f"FROM routine_executions{where}"
        + (" AND" if where else " WHERE")
        + " completed_at IS NOT NULL"
    ).fetchall()
    durations = [r[0] for r in dur_rows if r[0] is not None and r[0] >= 0]
    avg_duration = round(sum(durations) / len(durations), 1) if durations else 0.0

    return {
        "total": total,
        "success": success,
        "error": error,
        "timeout": timeout,
        "avg_duration_s": avg_duration,
    }


def _session_health(db: sqlite3.Connection) -> dict:
    """Aggregate current session stats (not time-windowed — reflects live state)."""
    row = db.execute(
        "SELECT COUNT(*), "
        "SUM(CASE WHEN is_locked = 1 THEN 1 ELSE 0 END), "
        "AVG(cumulative_risk), "
        "SUM(violation_count) "
        "FROM sessions"
    ).fetchone()

    return {
        "active": row[0] or 0,
        "locked": row[1] or 0,
        "avg_risk": round(row[2] or 0.0, 3),
        "total_violations": row[3] or 0,
    }


def _response_times(db: sqlite3.Connection, cutoff: str | None) -> dict:
    """Compute avg/p50/p95 response times from elapsed_s column.

    Percentiles are computed in Python because SQLite lacks
    percentile aggregate functions.
    """
    where = _where_created(cutoff)
    condition = (
        f"{where} AND elapsed_s IS NOT NULL"
        if where
        else " WHERE elapsed_s IS NOT NULL"
    )
    rows = db.execute(
        f"SELECT elapsed_s FROM conversation_turns{condition} ORDER BY elapsed_s"
    ).fetchall()

    values = [r[0] for r in rows]
    count = len(values)

    if count == 0:
        return {"avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0}

    avg = round(sum(values) / count, 1)
    p50 = round(median(values), 1)
    # P95: index = ceil(0.95 * n) - 1
    p95_idx = min(int(0.95 * count + 0.5), count - 1)
    p95 = round(values[p95_idx], 1)

    return {"avg_s": avg, "p50_s": p50, "p95_s": p95, "count": count}
