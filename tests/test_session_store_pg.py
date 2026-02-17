"""Tests for SessionStore — PostgreSQL backend for sessions.

Uses mock asyncpg pool/connection to verify SQL correctness, parameter
passing, and return value mapping without a real PostgreSQL instance.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.session.store import ConversationTurn, Session, SessionStore, _dt_to_iso


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    conn = AsyncMock()

    # pool.acquire() returns an async context manager
    acq_cm = MagicMock()
    acq_cm.__aenter__ = AsyncMock(return_value=conn)
    acq_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = acq_cm

    # conn.transaction() returns an async context manager (not a coroutine)
    tx_cm = MagicMock()
    tx_cm.__aenter__ = AsyncMock(return_value=None)
    tx_cm.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx_cm)

    # Default return for execute (asyncpg returns status strings)
    conn.execute.return_value = "SELECT 1"

    return pool, conn


@pytest.fixture
def store(mock_pool):
    pool, _ = mock_pool
    with patch("sentinel.session.store.settings") as mock_settings:
        mock_settings.session_ttl = 3600
        mock_settings.session_max_count = 100
        mock_settings.session_ttl_signal = 86400
        mock_settings.session_ttl_websocket = 1800
        mock_settings.session_ttl_api = 3600
        mock_settings.session_ttl_mcp = 3600
        mock_settings.session_ttl_routine = 0
        mock_settings.session_risk_decay_per_minute = 1.0
        mock_settings.session_lock_timeout_s = 300
        yield SessionStore(pool, ttl=3600, max_count=100)


def _make_session_row(
    session_id="test-session",
    source="api",
    cumulative_risk=0.0,
    violation_count=0,
    is_locked=False,
    task_in_progress=False,
):
    """Create a dict-like mock row matching the sessions SELECT."""
    now = datetime.now(timezone.utc)
    return {
        "session_id": session_id,
        "source": source,
        "cumulative_risk": cumulative_risk,
        "violation_count": violation_count,
        "is_locked": is_locked,
        "created_at": now,
        "last_active": now,
        "task_in_progress": task_in_progress,
    }


# ── get_or_create ─────────────────────────────────────────────


class TestGetOrCreate:
    @pytest.mark.asyncio
    async def test_creates_new_session(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None  # session not found
        conn.fetchval.return_value = 0  # count = 0
        conn.execute.return_value = "INSERT 0 1"

        session = await store.get_or_create("new-session", source="api")

        assert session.session_id == "new-session"
        assert session.source == "api"
        # Verify INSERT was called
        calls = [str(c) for c in conn.execute.call_args_list]
        assert any("INSERT INTO sessions" in c for c in calls)

    @pytest.mark.asyncio
    async def test_returns_existing_session(self, store, mock_pool):
        _, conn = mock_pool
        row = _make_session_row()
        conn.fetchrow.return_value = row
        conn.fetch.return_value = []  # no turns

        session = await store.get_or_create("test-session", source="api")

        assert session.session_id == "test-session"
        # Verify last_active was updated
        update_calls = [c for c in conn.execute.call_args_list
                        if "UPDATE sessions SET last_active" in str(c)]
        assert len(update_calls) >= 1

    @pytest.mark.asyncio
    async def test_generates_ephemeral_id_when_none(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None
        conn.fetchval.return_value = 0
        conn.execute.return_value = "INSERT 0 1"

        session = await store.get_or_create(None, source="api")

        assert session.session_id.startswith("ephemeral-")


# ── get ───────────────────────────────────────────────────────


class TestGet:
    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_session(self, store, mock_pool):
        _, conn = mock_pool
        row = _make_session_row()
        conn.fetchrow.return_value = row
        conn.fetch.return_value = []  # no turns

        session = await store.get("test-session")

        assert session is not None
        assert session.session_id == "test-session"


# ── add_turn ──────────────────────────────────────────────────


class TestAddTurn:
    @pytest.mark.asyncio
    async def test_inserts_turn(self, store, mock_pool):
        _, conn = mock_pool
        turn = ConversationTurn(
            request_text="test request",
            result_status="success",
            risk_score=0.1,
        )
        conn.execute.return_value = "INSERT 0 1"

        await store.add_turn("test-session", turn)

        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO conversation_turns" in str(c)]
        assert len(insert_calls) == 1
        args = insert_calls[0][0]
        assert "test request" in args
        assert "success" in args

    @pytest.mark.asyncio
    async def test_updates_session_when_provided(self, store, mock_pool):
        _, conn = mock_pool
        turn = ConversationTurn(request_text="test", result_status="blocked")
        session = Session(
            session_id="test-session",
            violation_count=2,
            cumulative_risk=0.5,
        )
        conn.execute.return_value = "INSERT 0 1"

        await store.add_turn("test-session", turn, session=session)

        update_calls = [c for c in conn.execute.call_args_list
                        if "UPDATE sessions SET last_active" in str(c)]
        assert len(update_calls) == 1


# ── lock_session / set_task_in_progress / clear_turns ─────────


class TestSimpleUpdates:
    @pytest.mark.asyncio
    async def test_lock_session(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.lock_session("test-session")

        args = conn.execute.call_args[0]
        assert "is_locked = TRUE" in args[0]
        assert args[1] == "test-session"

    @pytest.mark.asyncio
    async def test_set_task_in_progress(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.set_task_in_progress("test-session", True)

        args = conn.execute.call_args[0]
        assert "task_in_progress" in args[0]

    @pytest.mark.asyncio
    async def test_clear_turns(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 5"

        await store.clear_turns("test-session")

        args = conn.execute.call_args[0]
        assert "DELETE FROM conversation_turns" in args[0]
        assert args[1] == "test-session"


# ── accumulate_risk ───────────────────────────────────────────


class TestAccumulateRisk:
    @pytest.mark.asyncio
    async def test_uses_greatest(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.accumulate_risk("test-session", 0.7)

        args = conn.execute.call_args[0]
        assert "GREATEST(cumulative_risk" in args[0]
        assert args[1] == 0.7
        assert args[2] == "test-session"


# ── apply_decay ───────────────────────────────────────────────


class TestApplyDecay:
    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.apply_decay("nonexistent", 1.0, 300)

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_when_no_change(self, store, mock_pool):
        _, conn = mock_pool
        now = datetime.now(timezone.utc)
        conn.fetchrow.return_value = {
            "cumulative_risk": 0.0,
            "violation_count": 0,
            "is_locked": False,
            "last_active": now,
        }

        result = await store.apply_decay("test-session", 1.0, 300)

        assert result is False


# ── Metrics methods ───────────────────────────────────────────


class TestMetrics:
    @pytest.mark.asyncio
    async def test_get_auto_approved_count(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchval.return_value = 5

        result = await store.get_auto_approved_count()

        assert result == 5
        args = conn.fetchval.call_args[0]
        assert "auto_approved = TRUE" in args[0]

    @pytest.mark.asyncio
    async def test_get_auto_approved_count_with_cutoff(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchval.return_value = 3

        result = await store.get_auto_approved_count(cutoff="2026-03-01T00:00:00Z")

        assert result == 3
        args = conn.fetchval.call_args[0]
        assert "$1::timestamptz" in args[0]

    @pytest.mark.asyncio
    async def test_get_turn_outcome_counts(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"result_status": "success", "cnt": 10},
            {"result_status": "blocked", "cnt": 2},
        ]

        result = await store.get_turn_outcome_counts()

        assert result == {"success": 10, "blocked": 2}

    @pytest.mark.asyncio
    async def test_get_blocked_by_counts(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"blocked_by": ["PromptGuard", "VulnEcho"]},
            {"blocked_by": ["PromptGuard"]},
        ]

        result = await store.get_blocked_by_counts()

        assert result[0]["scanner"] == "PromptGuard"
        assert result[0]["count"] == 2
        assert result[1]["scanner"] == "VulnEcho"
        assert result[1]["count"] == 1

    @pytest.mark.asyncio
    async def test_get_session_health(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = {
            "total": 5,
            "locked": 1,
            "avg_risk": 0.123456,
            "total_violations": 3,
        }

        result = await store.get_session_health()

        assert result["active"] == 5
        assert result["locked"] == 1
        assert result["avg_risk"] == 0.123
        assert result["total_violations"] == 3

    @pytest.mark.asyncio
    async def test_get_response_time_stats_empty(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        result = await store.get_response_time_stats()

        assert result == {"avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0}

    @pytest.mark.asyncio
    async def test_get_response_time_stats(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"elapsed_s": 1.0},
            {"elapsed_s": 2.0},
            {"elapsed_s": 3.0},
            {"elapsed_s": 10.0},
        ]

        result = await store.get_response_time_stats()

        assert result["count"] == 4
        assert result["avg_s"] == 4.0
        assert result["p50_s"] == 2.5


# ── get_lock ──────────────────────────────────────────────────


class TestGetLock:
    def test_returns_asyncio_lock(self, store):
        import asyncio
        lock = store.get_lock("test-session")
        assert isinstance(lock, asyncio.Lock)

    def test_returns_same_lock_for_same_session(self, store):
        lock1 = store.get_lock("test-session")
        lock2 = store.get_lock("test-session")
        assert lock1 is lock2

    def test_returns_different_locks_for_different_sessions(self, store):
        lock1 = store.get_lock("session-1")
        lock2 = store.get_lock("session-2")
        assert lock1 is not lock2


# ── close ─────────────────────────────────────────────────────


class TestClose:
    @pytest.mark.asyncio
    async def test_close_clears_pool(self, store):
        assert store._pool is not None
        await store.close()
        assert store._pool is None


# ── dt_to_iso helper ──────────────────────────────────────────


class TestDtToIso:
    def test_converts_datetime(self):
        dt = datetime(2026, 3, 5, 12, 30, 45, 123456, tzinfo=timezone.utc)
        result = _dt_to_iso(dt)
        assert result == "2026-03-05T12:30:45.123456Z"

    def test_returns_now_for_none(self):
        result = _dt_to_iso(None)
        assert "T" in result
        assert result.endswith("Z")
