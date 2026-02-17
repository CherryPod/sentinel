"""Tests for db_pg — PostgreSQL database maintenance functions.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.db import (
    purge_old_audit_log,
    purge_old_routine_executions,
    run_db_maintenance,
)


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    conn = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = cm
    # Pre-configure transaction() as sync callable → async ctx mgr
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)
    return pool, conn


# ── purge_old_audit_log ──────────────────────────────────────


class TestPurgeOldAuditLog:
    @pytest.mark.asyncio
    async def test_deletes_old_entries(self, mock_pool):
        pool, conn = mock_pool
        conn.execute.return_value = "DELETE 10"

        result = await purge_old_audit_log(pool, days=7)

        assert result == 10
        sql = conn.execute.call_args[0][0]
        assert "audit_log" in sql
        assert "INTERVAL" in sql

    @pytest.mark.asyncio
    async def test_returns_zero_when_nothing_old(self, mock_pool):
        pool, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        result = await purge_old_audit_log(pool, days=7)

        assert result == 0

    @pytest.mark.asyncio
    async def test_custom_retention(self, mock_pool):
        pool, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        await purge_old_audit_log(pool, days=30)

        args = conn.execute.call_args[0]
        assert args[1] == 30


# ── purge_old_routine_executions ─────────────────────────────


class TestPurgeOldRoutineExecutions:
    @pytest.mark.asyncio
    async def test_deletes_old_entries(self, mock_pool):
        pool, conn = mock_pool
        conn.execute.return_value = "DELETE 5"

        result = await purge_old_routine_executions(pool, days=30)

        assert result == 5
        sql = conn.execute.call_args[0][0]
        assert "routine_executions" in sql
        assert "started_at" in sql

    @pytest.mark.asyncio
    async def test_returns_zero_when_nothing_old(self, mock_pool):
        pool, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        result = await purge_old_routine_executions(pool, days=30)

        assert result == 0


# ── run_db_maintenance ───────────────────────────────────────


class TestRunDbMaintenance:
    @pytest.mark.asyncio
    async def test_calls_all_purge_functions(self, mock_pool):
        pool, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        results = await run_db_maintenance(pool)

        assert "audit_log" in results
        assert "routine_executions" in results
        assert "provenance" in results
        assert "approvals" in results

    @pytest.mark.asyncio
    async def test_returns_counts(self, mock_pool):
        pool, conn = mock_pool
        # Different counts for each call
        conn.execute.side_effect = [
            "DELETE 3",   # audit_log
            "DELETE 1",   # routine_executions
            "DELETE 0",   # provenance file_provenance
            "DELETE 2",   # provenance
            "DELETE 5",   # approvals
        ]

        results = await run_db_maintenance(pool)

        assert results["audit_log"] == 3
        assert results["routine_executions"] == 1
        assert results["provenance"] == 2
        assert results["approvals"] == 5


# ── empty result edge cases ─────────────────────────────────


class TestPurgeEmptyResult:
    @pytest.mark.asyncio
    async def test_audit_log_none_result(self, mock_pool):
        """When execute returns None (edge case), should return 0."""
        pool, conn = mock_pool
        conn.execute.return_value = None

        result = await purge_old_audit_log(pool, days=7)

        assert result == 0

    @pytest.mark.asyncio
    async def test_routine_executions_none_result(self, mock_pool):
        pool, conn = mock_pool
        conn.execute.return_value = None

        result = await purge_old_routine_executions(pool, days=30)

        assert result == 0
