"""Tests for RoutineEngine — PostgreSQL backend for routine executions.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.routines.engine import RoutineEngine


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    conn = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = cm
    return pool, conn


@pytest.fixture
def store(mock_pool):
    pool, _ = mock_pool
    mock_routine_store = MagicMock()
    mock_orchestrator = AsyncMock()
    mock_bus = MagicMock()
    return RoutineEngine(
        store=mock_routine_store,
        orchestrator=mock_orchestrator,
        event_bus=mock_bus,
        pool=pool,
    )


def _make_execution_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "execution_id": "ex-123",
        "routine_id": "r-123",
        "user_id": 1,
        "triggered_by": "scheduler",
        "started_at": now,
        "completed_at": now,
        "status": "success",
        "result_summary": "Done",
        "error": "",
        "task_id": "task-1",
    }
    defaults.update(overrides)
    return defaults


# ── get_execution_history ─────────────────────────────────────


class TestGetExecutionHistory:
    @pytest.mark.asyncio
    async def test_returns_history(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_execution_row()]

        result = await store.get_execution_history("r-123")

        assert len(result) == 1
        assert result[0]["execution_id"] == "ex-123"
        assert result[0]["status"] == "success"

    @pytest.mark.asyncio
    async def test_passes_limit_offset(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        await store.get_execution_history("r-123", limit=10, offset=5)

        args = conn.fetch.call_args[0]
        assert "LIMIT $2 OFFSET $3" in args[0]
        assert args[2] == 10
        assert args[3] == 5

    @pytest.mark.asyncio
    async def test_empty_history(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        result = await store.get_execution_history("r-123")

        assert result == []

    @pytest.mark.asyncio
    async def test_timestamps_converted_to_iso(self, store, mock_pool):
        _, conn = mock_pool
        now = datetime(2026, 3, 5, 12, 0, 0, tzinfo=timezone.utc)
        conn.fetch.return_value = [_make_execution_row(started_at=now, completed_at=now)]

        result = await store.get_execution_history("r-123")

        assert "2026-03-05T12:00:00" in result[0]["started_at"]


# ── get_execution_stats ───────────────────────────────────────


class TestGetExecutionStats:
    @pytest.mark.asyncio
    async def test_returns_stats(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.side_effect = [
            # First call: status counts
            [
                {"status": "success", "cnt": 10},
                {"status": "error", "cnt": 2},
                {"status": "timeout", "cnt": 1},
            ],
            # Second call: durations
            [
                {"dur": 5.0},
                {"dur": 10.0},
                {"dur": 15.0},
            ],
        ]

        result = await store.get_execution_stats()

        assert result["total"] == 13
        assert result["success"] == 10
        assert result["error"] == 2
        assert result["timeout"] == 1
        assert result["avg_duration_s"] == 10.0

    @pytest.mark.asyncio
    async def test_empty_stats(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.side_effect = [[], []]

        result = await store.get_execution_stats()

        assert result == {
            "total": 0, "success": 0, "error": 0,
            "timeout": 0, "avg_duration_s": 0.0,
        }

    @pytest.mark.asyncio
    async def test_with_cutoff(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.side_effect = [
            [{"status": "success", "cnt": 5}],
            [{"dur": 3.0}],
        ]

        result = await store.get_execution_stats(cutoff="2026-03-01T00:00:00Z")

        # Verify cutoff was passed in both queries
        for call in conn.fetch.call_args_list:
            assert "$1::timestamptz" in call[0][0]

    @pytest.mark.asyncio
    async def test_uses_extract_epoch(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.side_effect = [[], []]

        await store.get_execution_stats()

        # The duration query should use EXTRACT(EPOCH FROM ...)
        dur_call = conn.fetch.call_args_list[-1]
        assert "EXTRACT(EPOCH FROM" in dur_call[0][0]


# ── record_start ──────────────────────────────────────────────


class TestRecordStart:
    @pytest.mark.asyncio
    async def test_inserts_running_execution(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        await store.record_start("ex-1", "r-1", "default", "scheduler")

        args = conn.execute.call_args[0]
        assert "INSERT INTO routine_executions" in args[0]
        assert "'running'" in args[0]
        assert args[1] == "ex-1"
        assert args[2] == "r-1"


# ── record_completion ─────────────────────────────────────────


class TestRecordCompletion:
    @pytest.mark.asyncio
    async def test_updates_execution(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.record_completion(
            "ex-1", status="success", result_summary="Done", task_id="t-1",
        )

        args = conn.execute.call_args[0]
        assert "UPDATE routine_executions" in args[0]
        assert "completed_at = NOW()" in args[0]
        assert args[1] == "success"
        assert args[5] == "ex-1"


# ── cleanup_stale ─────────────────────────────────────────────


class TestCleanupStale:
    @pytest.mark.asyncio
    async def test_marks_running_as_interrupted(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 3"

        count = await store.cleanup_stale()

        assert count == 3
        args = conn.execute.call_args[0]
        assert "status = 'interrupted'" in args[0]
        assert "WHERE status = 'running'" in args[0]

    @pytest.mark.asyncio
    async def test_returns_zero_when_none_stale(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 0"

        count = await store.cleanup_stale()

        assert count == 0


# ── get_execution_history (None timestamps) ──────────────────


class TestGetExecutionHistoryEdgeCases:
    @pytest.mark.asyncio
    async def test_completed_at_none_returns_empty_string(self, store, mock_pool):
        """Still-running execution has completed_at=None → empty string."""
        _, conn = mock_pool
        now = datetime(2026, 3, 5, 12, 0, 0, tzinfo=timezone.utc)
        conn.fetch.return_value = [
            _make_execution_row(started_at=now, completed_at=None, status="running"),
        ]

        result = await store.get_execution_history("r-123")

        assert len(result) == 1
        assert result[0]["completed_at"] == ""
        assert result[0]["status"] == "running"
        # started_at should still have a value
        assert result[0]["started_at"] != ""


# ── get_execution_stats (duration filtering) ─────────────────


class TestGetExecutionStatsEdgeCases:
    @pytest.mark.asyncio
    async def test_filters_none_and_negative_durations(self, store, mock_pool):
        """None and negative durations should be excluded from avg."""
        _, conn = mock_pool
        conn.fetch.side_effect = [
            # status counts
            [{"status": "success", "cnt": 3}],
            # durations — includes None and negative
            [
                {"dur": 10.0},
                {"dur": None},
                {"dur": -1.0},
                {"dur": 20.0},
            ],
        ]

        result = await store.get_execution_stats()

        # Only 10.0 and 20.0 should count → avg = 15.0
        assert result["avg_duration_s"] == 15.0
        assert result["total"] == 3
