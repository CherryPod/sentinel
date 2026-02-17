"""Tests for metrics_pg — PostgreSQL-aware metrics aggregation.

Verifies that the async PG version produces the same structure as the SQLite
version, using ISO 8601 cutoffs instead of SQLite strftime() expressions.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.api.metrics import get_metrics, _cutoff_iso


# ── _cutoff_iso ──────────────────────────────────────────────


class TestCutoffIso:
    def test_returns_none_for_all(self):
        assert _cutoff_iso(None) is None

    def test_returns_iso_string(self):
        from datetime import timedelta
        result = _cutoff_iso(timedelta(days=1))
        assert result is not None
        assert "T" in result
        assert result.endswith("Z")


# ── get_metrics ──────────────────────────────────────────────


class TestGetMetrics:
    @pytest.mark.asyncio
    async def test_returns_all_sections(self):
        session_store = AsyncMock()
        session_store.get_auto_approved_count.return_value = 5
        session_store.get_turn_outcome_counts.return_value = {"success": 10, "blocked": 2}
        session_store.get_blocked_by_counts.return_value = [
            {"scanner": "PromptGuard", "count": 2},
        ]
        session_store.get_session_health.return_value = {
            "active": 3, "locked": 0, "avg_risk": 0.1, "total_violations": 0,
        }
        session_store.get_response_time_stats.return_value = {
            "avg_s": 2.0, "p50_s": 1.5, "p95_s": 5.0, "count": 10,
        }

        approval_manager = AsyncMock()
        approval_manager.get_status_counts.return_value = {
            "approved": 3, "pending": 1,
        }

        routine_engine = AsyncMock()
        routine_engine.get_execution_stats.return_value = {
            "total": 5, "success": 4, "error": 1, "timeout": 0, "avg_duration_s": 3.0,
        }

        result = await get_metrics(
            session_store, approval_manager, routine_engine, window="24h",
        )

        assert "approval_funnel" in result
        assert "task_outcomes" in result
        assert "scanner_blocks" in result
        assert "routine_health" in result
        assert "session_health" in result
        assert "response_times" in result

        # Verify approval funnel includes auto_approved
        assert result["approval_funnel"]["auto_approved"] == 5
        assert result["approval_funnel"]["manually_approved"] == 3

    @pytest.mark.asyncio
    async def test_handles_no_routine_engine(self):
        session_store = AsyncMock()
        session_store.get_auto_approved_count.return_value = 0
        session_store.get_turn_outcome_counts.return_value = {}
        session_store.get_blocked_by_counts.return_value = []
        session_store.get_session_health.return_value = {
            "active": 0, "locked": 0, "avg_risk": 0.0, "total_violations": 0,
        }
        session_store.get_response_time_stats.return_value = {
            "avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0,
        }

        approval_manager = AsyncMock()
        approval_manager.get_status_counts.return_value = {}

        result = await get_metrics(
            session_store, approval_manager, routine_engine=None, window="all",
        )

        assert result["routine_health"]["total"] == 0

    @pytest.mark.asyncio
    async def test_window_all_passes_none_cutoff(self):
        session_store = AsyncMock()
        session_store.get_auto_approved_count.return_value = 0
        session_store.get_turn_outcome_counts.return_value = {}
        session_store.get_blocked_by_counts.return_value = []
        session_store.get_session_health.return_value = {
            "active": 0, "locked": 0, "avg_risk": 0.0, "total_violations": 0,
        }
        session_store.get_response_time_stats.return_value = {
            "avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0,
        }

        approval_manager = AsyncMock()
        approval_manager.get_status_counts.return_value = {}

        await get_metrics(
            session_store, approval_manager, routine_engine=None, window="all",
        )

        # Verify cutoff was None (no timestamptz arg)
        session_store.get_auto_approved_count.assert_called_with(None)

    @pytest.mark.asyncio
    async def test_window_7d_produces_correct_cutoff(self):
        from datetime import timedelta
        result = _cutoff_iso(timedelta(days=7))
        assert result is not None
        # Parse it back to verify it's ~7 days ago
        from datetime import datetime, timezone
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - parsed
        # Should be roughly 7 days (allow 5s tolerance)
        assert abs(delta.total_seconds() - 7 * 86400) < 5

    @pytest.mark.asyncio
    async def test_window_30d_produces_correct_cutoff(self):
        from datetime import timedelta
        result = _cutoff_iso(timedelta(days=30))
        assert result is not None
        from datetime import datetime, timezone
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - parsed
        assert abs(delta.total_seconds() - 30 * 86400) < 5

    @pytest.mark.asyncio
    async def test_invalid_window_treated_as_all(self):
        """Unknown window value gets None from _WINDOW_DELTAS, treated as 'all'."""
        session_store = AsyncMock()
        session_store.get_auto_approved_count.return_value = 0
        session_store.get_turn_outcome_counts.return_value = {}
        session_store.get_blocked_by_counts.return_value = []
        session_store.get_session_health.return_value = {
            "active": 0, "locked": 0, "avg_risk": 0.0, "total_violations": 0,
        }
        session_store.get_response_time_stats.return_value = {
            "avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0,
        }

        approval_manager = AsyncMock()
        approval_manager.get_status_counts.return_value = {}

        result = await get_metrics(
            session_store, approval_manager, routine_engine=None, window="invalid",
        )

        # Should not crash and cutoff should be None (same as "all")
        session_store.get_auto_approved_count.assert_called_with(None)
        assert "approval_funnel" in result
