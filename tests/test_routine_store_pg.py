"""Tests for RoutineStore — PostgreSQL backend for routines.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.routines.store import Routine, RoutineStore, _row_to_routine


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
    return RoutineStore(pool)


def _make_routine_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "routine_id": "r-123",
        "user_id": 1,
        "name": "Test Routine",
        "description": "A test routine",
        "trigger_type": "cron",
        "trigger_config": '{"cron": "0 9 * * *"}',
        "action_config": '{"prompt": "do stuff"}',
        "enabled": True,
        "last_run_at": None,
        "next_run_at": None,
        "cooldown_s": 0,
        "created_at": now,
        "updated_at": now,
    }
    defaults.update(overrides)
    return defaults


# ── create ────────────────────────────────────────────────────


class TestCreate:
    @pytest.mark.asyncio
    async def test_creates_routine(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        routine = await store.create(
            name="Daily",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "summarise"},
        )

        assert routine.name == "Daily"
        assert routine.trigger_type == "cron"
        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO routines" in str(c)]
        assert len(insert_calls) == 1

    @pytest.mark.asyncio
    async def test_enforces_max_per_user(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchval.return_value = 5  # already at limit

        with pytest.raises(ValueError, match="limit reached"):
            await store.create(
                name="Extra",
                trigger_type="cron",
                trigger_config={},
                action_config={},
                max_per_user=5,
            )


# ── get ───────────────────────────────────────────────────────


class TestGet:
    @pytest.mark.asyncio
    async def test_returns_routine(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_routine_row()

        routine = await store.get("r-123")

        assert routine is not None
        assert routine.routine_id == "r-123"
        assert routine.trigger_config == {"cron": "0 9 * * *"}

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get("nonexistent")

        assert result is None


# ── list ──────────────────────────────────────────────────────


class TestList:
    @pytest.mark.asyncio
    async def test_lists_routines(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_routine_row(), _make_routine_row(routine_id="r-456")]

        routines = await store.list()

        assert len(routines) == 2

    @pytest.mark.asyncio
    async def test_list_enabled_only(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_routine_row()]

        routines = await store.list(enabled_only=True)

        assert len(routines) == 1
        args = conn.fetch.call_args[0]
        assert "enabled = TRUE" in args[0]


# ── update ────────────────────────────────────────────────────


class TestUpdate:
    @pytest.mark.asyncio
    async def test_updates_fields(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_routine_row()  # for get()
        conn.execute.return_value = "UPDATE 1"

        routine = await store.update("r-123", name="Updated", enabled=False)

        assert routine is not None
        assert routine.name == "Updated"
        assert routine.enabled is False

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.update("nonexistent", name="X")

        assert result is None

    @pytest.mark.asyncio
    async def test_rejects_bad_fields(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_routine_row()

        with pytest.raises(ValueError, match="Invalid update fields"):
            await store.update("r-123", evil_field="drop table")

    @pytest.mark.asyncio
    async def test_jsonb_fields_serialised(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_routine_row()
        conn.execute.return_value = "UPDATE 1"

        await store.update("r-123", trigger_config={"cron": "0 12 * * *"})

        # The execute call should contain ::jsonb cast
        execute_calls = [c for c in conn.execute.call_args_list
                         if "UPDATE routines SET" in str(c)]
        assert len(execute_calls) == 1
        sql = execute_calls[0][0][0]
        assert "::jsonb" in sql


# ── delete ────────────────────────────────────────────────────


class TestDelete:
    @pytest.mark.asyncio
    async def test_returns_true_when_deleted(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 1"

        result = await store.delete("r-123")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        result = await store.delete("nonexistent")

        assert result is False


# ── list_due ──────────────────────────────────────────────────


class TestListDue:
    @pytest.mark.asyncio
    async def test_queries_enabled_with_next_run(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_routine_row()]

        routines = await store.list_due("2026-03-05T12:00:00.000Z")

        args = conn.fetch.call_args[0]
        assert "enabled = TRUE" in args[0]
        assert "next_run_at IS NOT NULL" in args[0]
        assert "next_run_at <= $1" in args[0]


# ── list_event_triggered ──────────────────────────────────────


class TestListEventTriggered:
    @pytest.mark.asyncio
    async def test_queries_event_type(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        await store.list_event_triggered()

        args = conn.fetch.call_args[0]
        assert "trigger_type = 'event'" in args[0]
        assert "enabled = TRUE" in args[0]

    @pytest.mark.asyncio
    async def test_all_event_triggered(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        await store.list_event_triggered(enabled_only=False)

        args = conn.fetch.call_args[0]
        assert "trigger_type = 'event'" in args[0]
        assert "enabled = TRUE" not in args[0]


# ── update_run_state ──────────────────────────────────────────


class TestUpdateRunState:
    @pytest.mark.asyncio
    async def test_updates_run_state(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.update_run_state("r-123", "2026-03-05T12:00:00Z", "2026-03-06T09:00:00Z")

        args = conn.execute.call_args[0]
        assert "last_run_at" in args[0]
        assert "next_run_at" in args[0]


# ── _row_to_routine ───────────────────────────────────────────


class TestRowToRoutine:
    def test_converts_row(self):
        row = _make_routine_row()
        routine = _row_to_routine(row)

        assert isinstance(routine, Routine)
        assert routine.routine_id == "r-123"
        assert routine.trigger_config == {"cron": "0 9 * * *"}
        assert isinstance(routine.trigger_config, dict)

    def test_handles_dict_json_fields(self):
        row = _make_routine_row(
            trigger_config={"cron": "0 12 * * *"},
            action_config={"prompt": "test"},
        )
        routine = _row_to_routine(row)

        assert routine.trigger_config == {"cron": "0 12 * * *"}
        assert routine.action_config == {"prompt": "test"}


# ── count_for_user ──────────────────────────────────────────


class TestCountForUser:
    @pytest.mark.asyncio
    async def test_returns_count(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchval.return_value = 3

        result = await store.count_for_user("alice")

        assert result == 3
        args = conn.fetchval.call_args[0]
        assert "COUNT(*)" in args[0]
        assert "user_id = $1" in args[0]
        assert args[1] == "alice"

    @pytest.mark.asyncio
    async def test_returns_zero_for_new_user(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchval.return_value = 0

        result = await store.count_for_user("new_user")

        assert result == 0


# ── create (additional edge cases) ──────────────────────────


class TestCreateEdgeCases:
    @pytest.mark.asyncio
    async def test_no_limit_skips_count_check(self, store, mock_pool):
        """When max_per_user=0 (default), count_for_user should NOT be called."""
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        await store.create(
            name="Unlimited",
            trigger_type="cron",
            trigger_config={},
            action_config={},
            max_per_user=0,
        )

        # fetchval is used by count_for_user — should not be called
        conn.fetchval.assert_not_called()


# ── update (additional edge cases) ──────────────────────────


class TestUpdateEdgeCases:
    @pytest.mark.asyncio
    async def test_action_config_gets_jsonb_cast(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_routine_row()
        conn.execute.return_value = "UPDATE 1"

        await store.update("r-123", action_config={"prompt": "new"})

        execute_calls = [c for c in conn.execute.call_args_list
                         if "UPDATE routines SET" in str(c)]
        assert len(execute_calls) == 1
        sql = execute_calls[0][0][0]
        assert "action_config" in sql
        assert "::jsonb" in sql


# ── update_run_state (additional edge cases) ─────────────────


class TestUpdateRunStateEdgeCases:
    @pytest.mark.asyncio
    async def test_next_run_at_none(self, store, mock_pool):
        """Event-triggered routines may pass next_run_at=None."""
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.update_run_state("r-123", "2026-03-05T12:00:00Z", None)

        args = conn.execute.call_args[0]
        assert args[2] is None  # next_run_at param


# ── list_due (additional edge cases) ─────────────────────────


class TestListDueEdgeCases:
    @pytest.mark.asyncio
    async def test_returns_empty_list(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        routines = await store.list_due("2026-03-05T12:00:00.000Z")

        assert routines == []
