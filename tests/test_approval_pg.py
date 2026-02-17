"""Tests for ApprovalManager — PostgreSQL backend for approvals.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.approval import ApprovalManager
from sentinel.core.models import Plan, PlanStep


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
    return ApprovalManager(pool, timeout=300)


def _make_plan():
    return Plan(
        plan_summary="Test plan",
        steps=[
            PlanStep(
                id="s1",
                type="tool_call",
                description="Do something",
                prompt="test",
                tool="web_search",
            ),
        ],
    )


def _make_approval_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "approval_id": "a-123",
        "status": "pending",
        "plan_json": {"plan_summary": "Test plan", "steps": [
            {"id": "s1", "type": "tool_call", "description": "Do something",
             "prompt": "test", "tool": "web_search", "args": {}, "expects_code": False}
        ]},
        "decided_reason": "",
        "decided_by": "",
        "source_key": "",
        "user_request": "test request",
        "expires_at": now + timedelta(minutes=5),
        "created_at": now,
    }
    defaults.update(overrides)
    return defaults


# ── request_plan_approval ────────────────────────────────────


class TestRequestPlanApproval:
    @pytest.mark.asyncio
    async def test_creates_approval(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []  # _cleanup_expired
        conn.execute.return_value = "INSERT 0 1"

        approval_id = await store.request_plan_approval(
            plan=_make_plan(),
            source_key="session-1",
            user_request="do something",
        )

        assert approval_id  # UUID string
        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO approvals" in str(c)]
        assert len(insert_calls) == 1
        # Verify JSONB cast
        sql = insert_calls[0][0][0]
        assert "::jsonb" in sql


# ── check_approval ───────────────────────────────────────────


class TestCheckApproval:
    @pytest.mark.asyncio
    async def test_returns_pending(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []  # _cleanup_expired
        conn.fetchrow.return_value = _make_approval_row()

        result = await store.check_approval("a-123")

        assert result["status"] == "pending"
        assert "plan_summary" in result
        assert "steps" in result

    @pytest.mark.asyncio
    async def test_returns_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []  # _cleanup_expired
        conn.fetchrow.return_value = None

        result = await store.check_approval("nonexistent")

        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_returns_approved(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []
        conn.fetchrow.return_value = _make_approval_row(
            status="approved", decided_reason="looks good", decided_by="admin",
        )

        result = await store.check_approval("a-123")

        assert result["status"] == "approved"
        assert result["reason"] == "looks good"

    @pytest.mark.asyncio
    async def test_returns_expired(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []
        conn.fetchrow.return_value = _make_approval_row(status="expired")

        result = await store.check_approval("a-123")

        assert result["status"] == "expired"


# ── submit_approval ──────────────────────────────────────────


class TestSubmitApproval:
    @pytest.mark.asyncio
    async def test_approves_pending(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_approval_row()
        conn.execute.return_value = "UPDATE 1"

        result = await store.submit_approval("a-123", granted=True, reason="ok")

        assert result is True
        update_calls = [c for c in conn.execute.call_args_list
                        if "UPDATE approvals SET" in str(c)]
        assert len(update_calls) == 1

    @pytest.mark.asyncio
    async def test_rejects_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.submit_approval("nonexistent", granted=True)

        assert result is False

    @pytest.mark.asyncio
    async def test_rejects_expired(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_approval_row(
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        conn.execute.return_value = "UPDATE 1"

        result = await store.submit_approval("a-123", granted=True)

        assert result is False

    @pytest.mark.asyncio
    async def test_rejects_duplicate(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_approval_row(status="approved")

        result = await store.submit_approval("a-123", granted=True)

        assert result is False


# ── get_plan ─────────────────────────────────────────────────


class TestGetPlan:
    @pytest.mark.asyncio
    async def test_returns_plan(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_approval_row()

        plan = await store.get_plan("a-123")

        assert plan is not None
        assert plan.plan_summary == "Test plan"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get_plan("nonexistent")

        assert result is None


# ── is_approved ──────────────────────────────────────────────


class TestIsApproved:
    @pytest.mark.asyncio
    async def test_returns_true_when_approved(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []  # _cleanup_expired
        conn.fetchval.return_value = "approved"

        result = await store.is_approved("a-123")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_denied(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []
        conn.fetchval.return_value = "denied"

        result = await store.is_approved("a-123")

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_none_when_pending(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []
        conn.fetchval.return_value = "pending"

        result = await store.is_approved("a-123")

        assert result is None


# ── purge_old ────────────────────────────────────────────────


class TestPurgeOld:
    @pytest.mark.asyncio
    async def test_deletes_old_entries(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 3"

        result = await store.purge_old(days=7)

        assert result == 3

    @pytest.mark.asyncio
    async def test_returns_zero_when_nothing_old(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        result = await store.purge_old(days=7)

        assert result == 0


# ── get_status_counts ────────────────────────────────────────


class TestGetStatusCounts:
    @pytest.mark.asyncio
    async def test_returns_counts(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"status": "approved", "cnt": 5},
            {"status": "pending", "cnt": 2},
        ]

        result = await store.get_status_counts()

        assert result == {"approved": 5, "pending": 2}

    @pytest.mark.asyncio
    async def test_with_cutoff(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [{"status": "approved", "cnt": 1}]

        result = await store.get_status_counts(cutoff="2026-03-01T00:00:00Z")

        sql = conn.fetch.call_args[0][0]
        assert "::timestamptz" in sql


# ── cleanup_and_notify ───────────────────────────────────────


class TestCleanupAndNotify:
    @pytest.mark.asyncio
    async def test_publishes_events(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"approval_id": "a-1", "source_key": "s-1"},
        ]
        conn.execute.return_value = "UPDATE 1"

        event_bus = AsyncMock()
        store._event_bus = event_bus

        expired = await store.cleanup_and_notify()

        assert len(expired) == 1
        event_bus.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_events_when_nothing_expired(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        event_bus = AsyncMock()
        store._event_bus = event_bus

        expired = await store.cleanup_and_notify()

        assert expired == []
        event_bus.publish.assert_not_called()


# ── get_pending ──────────────────────────────────────────────


class TestGetPending:
    @pytest.mark.asyncio
    async def test_returns_pending_entry(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_approval_row()

        result = await store.get_pending("a-123")

        assert result is not None
        assert "plan" in result
        assert result["user_request"] == "test request"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get_pending("nonexistent")

        assert result is None
