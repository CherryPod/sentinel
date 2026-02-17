"""Metrics aggregation for the dashboard.

Queries store interfaces to produce operational metrics for a given
time window. All aggregation is server-side — the API returns pre-computed
numbers ready for rendering.

Cutoff timestamps are ISO 8601 strings. PG stores cast with ::timestamptz.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

_EMPTY_ROUTINE_HEALTH = {"total": 0, "success": 0, "error": 0, "timeout": 0, "avg_duration_s": 0.0}

_EMPTY_METRICS = {
    "approval_funnel": {
        "auto_approved": 0, "manually_approved": 0,
        "denied": 0, "expired": 0, "pending": 0,
    },
    "task_outcomes": {
        "success": 0, "blocked": 0, "error": 0,
        "refused": 0, "denied": 0, "awaiting_approval": 0,
    },
    "scanner_blocks": [],
    "routine_health": _EMPTY_ROUTINE_HEALTH,
    "session_health": {"active": 0, "locked": 0, "avg_risk": 0.0, "total_violations": 0},
    "response_times": {"avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0},
}

_WINDOW_DELTAS = {
    "24h": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "all": None,
}


async def get_metrics(
    session_store: Any,
    approval_manager: Any,
    routine_engine: Any | None,
    window: str = "24h",
) -> dict:
    """Aggregate all dashboard metrics for a time window.

    When session_store is None (no backend), returns zeroed metrics.
    """
    if session_store is None:
        return dict(_EMPTY_METRICS)

    delta = _WINDOW_DELTAS.get(window)
    cutoff = _cutoff_iso(delta)

    approval_funnel = await _approval_funnel(approval_manager, session_store, cutoff)
    task_outcomes = await _task_outcomes(session_store, cutoff)
    scanner_blocks = await session_store.get_blocked_by_counts(cutoff)
    routine_health = (
        await routine_engine.get_execution_stats(cutoff) if routine_engine else _EMPTY_ROUTINE_HEALTH
    )
    session_health = await session_store.get_session_health()
    response_times = await session_store.get_response_time_stats(cutoff)

    return {
        "approval_funnel": approval_funnel,
        "task_outcomes": task_outcomes,
        "scanner_blocks": scanner_blocks,
        "routine_health": routine_health,
        "session_health": session_health,
        "response_times": response_times,
    }


def _cutoff_iso(delta: timedelta | None) -> str | None:
    """Return an ISO 8601 timestamp for the cutoff, or None for 'all'."""
    if delta is None:
        return None
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def _approval_funnel(
    approval_manager: Any,
    session_store: Any,
    cutoff: str | None,
) -> dict:
    """Count approvals by status + auto-approved from conversation_turns."""
    counts = await approval_manager.get_status_counts(cutoff)
    auto_approved = await session_store.get_auto_approved_count(cutoff)

    return {
        "auto_approved": auto_approved,
        "manually_approved": counts.get("approved", 0),
        "denied": counts.get("denied", 0),
        "expired": counts.get("expired", 0),
        "pending": counts.get("pending", 0),
    }


async def _task_outcomes(session_store: Any, cutoff: str | None) -> dict:
    """Group conversation_turns by result_status."""
    counts = await session_store.get_turn_outcome_counts(cutoff)

    return {
        "success": counts.get("success", 0),
        "blocked": counts.get("blocked", 0),
        "error": counts.get("error", 0),
        "refused": counts.get("refused", 0),
        "denied": counts.get("denied", 0),
        "awaiting_approval": counts.get("awaiting_approval", 0),
    }
