"""Tests for sentinel.api.metrics — aggregation logic with mocked stores."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.api.metrics import get_metrics, _cutoff_iso


class TestCutoffIso:
    def test_returns_none_for_all(self):
        assert _cutoff_iso(None) is None

    def test_returns_iso_string(self):
        from datetime import timedelta
        result = _cutoff_iso(timedelta(days=1))
        assert result is not None
        assert "T" in result
        assert result.endswith("Z")


def _mock_stores(*, auto_approved=0, turn_outcomes=None, blocked_by=None,
                 session_health=None, response_times=None, approval_counts=None,
                 routine_stats=None):
    """Create mocked stores with configurable return values."""
    session_store = AsyncMock()
    session_store.get_auto_approved_count.return_value = auto_approved
    session_store.get_turn_outcome_counts.return_value = turn_outcomes or {}
    session_store.get_blocked_by_counts.return_value = blocked_by or []
    session_store.get_session_health.return_value = session_health or {
        "active": 0, "locked": 0, "avg_risk": 0.0, "total_violations": 0,
    }
    session_store.get_response_time_stats.return_value = response_times or {
        "avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0,
    }

    approval_manager = AsyncMock()
    approval_manager.get_status_counts.return_value = approval_counts or {}

    routine_engine = None
    if routine_stats is not None:
        routine_engine = AsyncMock()
        routine_engine.get_execution_stats.return_value = routine_stats

    return session_store, approval_manager, routine_engine


class TestEmptyDatabase:
    async def test_empty_database_returns_zeros(self):
        session_store, approval_manager, routine_engine = _mock_stores()
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        assert result["approval_funnel"]["auto_approved"] == 0
        assert result["approval_funnel"]["manually_approved"] == 0
        assert result["task_outcomes"]["success"] == 0
        assert result["scanner_blocks"] == []
        assert result["routine_health"]["total"] == 0
        assert result["session_health"]["active"] == 0
        assert result["response_times"]["count"] == 0
        assert result["response_times"]["avg_s"] == 0.0

    async def test_none_stores_return_empty(self):
        result = await get_metrics(None, None, None, "24h")
        assert result["approval_funnel"]["auto_approved"] == 0
        assert result["task_outcomes"]["success"] == 0
        assert result["routine_health"]["total"] == 0


class TestApprovalFunnel:
    async def test_approval_funnel_counts(self):
        session_store, approval_manager, routine_engine = _mock_stores(
            approval_counts={"approved": 2, "denied": 1, "expired": 1, "pending": 1},
            auto_approved=3,
        )
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        funnel = result["approval_funnel"]
        assert funnel["manually_approved"] == 2
        assert funnel["denied"] == 1
        assert funnel["expired"] == 1
        assert funnel["pending"] == 1
        assert funnel["auto_approved"] == 3

    async def test_auto_approved_count(self):
        session_store, approval_manager, routine_engine = _mock_stores(auto_approved=2)
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        assert result["approval_funnel"]["auto_approved"] == 2


class TestTaskOutcomes:
    async def test_task_outcomes_grouping(self):
        session_store, approval_manager, routine_engine = _mock_stores(
            turn_outcomes={"success": 2, "blocked": 1, "error": 1, "refused": 1},
        )
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        outcomes = result["task_outcomes"]
        assert outcomes["success"] == 2
        assert outcomes["blocked"] == 1
        assert outcomes["error"] == 1
        assert outcomes["refused"] == 1


class TestScannerBlocks:
    async def test_scanner_blocks_returned(self):
        blocks = [
            {"scanner": "credential_scanner", "count": 2},
            {"scanner": "sensitive_path_scanner", "count": 1},
        ]
        session_store, approval_manager, routine_engine = _mock_stores(blocked_by=blocks)
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        assert len(result["scanner_blocks"]) == 2
        assert result["scanner_blocks"][0]["scanner"] == "credential_scanner"
        assert result["scanner_blocks"][0]["count"] == 2


class TestRoutineHealth:
    async def test_routine_health_aggregation(self):
        session_store, approval_manager, routine_engine = _mock_stores(
            routine_stats={"total": 4, "success": 2, "error": 1, "timeout": 1, "avg_duration_s": 15.0},
        )
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        health = result["routine_health"]
        assert health["total"] == 4
        assert health["success"] == 2
        assert health["error"] == 1
        assert health["timeout"] == 1

    async def test_no_routine_engine_returns_empty(self):
        session_store, approval_manager, _ = _mock_stores()
        result = await get_metrics(session_store, approval_manager, None, "24h")
        assert result["routine_health"]["total"] == 0


class TestSessionHealth:
    async def test_session_health(self):
        session_store, approval_manager, routine_engine = _mock_stores(
            session_health={"active": 2, "locked": 1, "avg_risk": 0.4, "total_violations": 3},
        )
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        health = result["session_health"]
        assert health["active"] == 2
        assert health["locked"] == 1
        assert health["avg_risk"] == 0.4
        assert health["total_violations"] == 3


class TestResponseTimes:
    async def test_response_times(self):
        session_store, approval_manager, routine_engine = _mock_stores(
            response_times={"avg_s": 5.5, "p50_s": 5.5, "p95_s": 10.0, "count": 10},
        )
        result = await get_metrics(session_store, approval_manager, routine_engine, "24h")
        times = result["response_times"]
        assert times["count"] == 10
        assert times["avg_s"] == 5.5
        assert times["p50_s"] == 5.5
        assert times["p95_s"] == 10.0


class TestWindows:
    async def test_all_window_passes_none_cutoff(self):
        session_store, approval_manager, routine_engine = _mock_stores()
        await get_metrics(session_store, approval_manager, routine_engine, "all")
        session_store.get_auto_approved_count.assert_called_with(None)

    async def test_window_7d_produces_correct_cutoff(self):
        from datetime import timedelta
        result = _cutoff_iso(timedelta(days=7))
        assert result is not None
        from datetime import datetime, timezone
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - parsed
        assert abs(delta.total_seconds() - 7 * 86400) < 5

    async def test_invalid_window_treated_as_all(self):
        session_store, approval_manager, routine_engine = _mock_stores()
        result = await get_metrics(session_store, approval_manager, routine_engine, "invalid")
        session_store.get_auto_approved_count.assert_called_with(None)
        assert "approval_funnel" in result
