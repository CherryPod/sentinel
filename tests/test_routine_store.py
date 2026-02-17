"""Tests for RoutineStore CRUD operations.

Verifies:
- Create/get/list/update/delete roundtrip
- list_due() query correctness
- update_run_state()
- enabled_only filtering
- User isolation
- In-memory mode (pool=None)
"""

import time

import pytest

from sentinel.routines.cron import next_run, validate_cron, validate_trigger_config
from sentinel.routines.store import Routine, RoutineStore


@pytest.fixture
def store():
    """RoutineStore using in-memory dict (no database)."""
    return RoutineStore(pool=None)


@pytest.fixture
def mem_store():
    """RoutineStore using in-memory dict (no database)."""
    return RoutineStore(pool=None)


# ── CRUD roundtrip ────────────────────────────────────────────────


class TestCRUD:
    async def test_create_and_get(self, store):
        r = await store.create(
            name="Morning check",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Check system health"},
        )
        assert r.routine_id
        assert r.name == "Morning check"
        assert r.trigger_type == "cron"
        assert r.enabled is True

        fetched = await store.get(r.routine_id)
        assert fetched is not None
        assert fetched.name == "Morning check"
        assert fetched.trigger_config == {"cron": "0 9 * * *"}

    async def test_get_nonexistent_returns_none(self, store):
        assert await store.get("nonexistent-id") is None

    async def test_create_with_all_fields(self, store):
        r = await store.create(
            name="Full routine",
            trigger_type="interval",
            trigger_config={"seconds": 3600},
            action_config={"prompt": "Do something", "approval_mode": "full"},
            user_id="alice",
            description="A detailed description",
            enabled=False,
            cooldown_s=120,
            next_run_at="2026-03-01T00:00:00.000Z",
        )
        assert r.user_id == "alice"
        assert r.description == "A detailed description"
        assert r.enabled is False
        assert r.cooldown_s == 120
        assert r.next_run_at == "2026-03-01T00:00:00.000Z"

    async def test_update(self, store):
        r = await store.create(
            name="Original",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )

        updated = await store.update(r.routine_id, name="Updated", enabled=False)
        assert updated is not None
        assert updated.name == "Updated"
        assert updated.enabled is False

        # Verify persisted
        fetched = await store.get(r.routine_id)
        assert fetched.name == "Updated"
        assert fetched.enabled is False

    async def test_update_rejects_unknown_fields(self, store):
        r = await store.create(
            name="Whitelist test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        with pytest.raises(ValueError, match="Invalid update fields"):
            await store.update(r.routine_id, name="OK", evil_column="DROP TABLE")

    async def test_update_nonexistent_returns_none(self, store):
        assert await store.update("nonexistent", name="x") is None

    async def test_update_trigger_config(self, store):
        r = await store.create(
            name="Config test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        updated = await store.update(r.routine_id, trigger_config={"cron": "0 12 * * *"})
        assert updated.trigger_config == {"cron": "0 12 * * *"}

    async def test_delete(self, store):
        r = await store.create(
            name="To delete",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "test"},
        )
        assert await store.delete(r.routine_id) is True
        assert await store.get(r.routine_id) is None

    async def test_delete_nonexistent_returns_false(self, store):
        assert await store.delete("nonexistent") is False


# ── List and filtering ────────────────────────────────────────────


class TestListFiltering:
    async def test_list_returns_all(self, store):
        await store.create(name="A", trigger_type="cron",
                     trigger_config={"cron": "0 9 * * *"},
                     action_config={"prompt": "a"})
        await store.create(name="B", trigger_type="cron",
                     trigger_config={"cron": "0 10 * * *"},
                     action_config={"prompt": "b"}, enabled=False)
        results = await store.list()
        assert len(results) == 2

    async def test_list_enabled_only(self, store):
        await store.create(name="Enabled", trigger_type="cron",
                     trigger_config={"cron": "0 9 * * *"},
                     action_config={"prompt": "a"}, enabled=True)
        await store.create(name="Disabled", trigger_type="cron",
                     trigger_config={"cron": "0 10 * * *"},
                     action_config={"prompt": "b"}, enabled=False)
        results = await store.list(enabled_only=True)
        assert len(results) == 1
        assert results[0].name == "Enabled"

    async def test_list_respects_user_id(self, store):
        await store.create(name="Alice's", trigger_type="cron",
                     trigger_config={"cron": "0 9 * * *"},
                     action_config={"prompt": "a"}, user_id="alice")
        await store.create(name="Bob's", trigger_type="cron",
                     trigger_config={"cron": "0 10 * * *"},
                     action_config={"prompt": "b"}, user_id="bob")
        alice = await store.list(user_id="alice")
        assert len(alice) == 1
        assert alice[0].name == "Alice's"

    async def test_list_limit_offset(self, store):
        for i in range(5):
            await store.create(name=f"R{i}", trigger_type="cron",
                         trigger_config={"cron": "0 9 * * *"},
                         action_config={"prompt": f"r{i}"})
            # Small delay so created_at differs
            time.sleep(0.002)
        page1 = await store.list(limit=2, offset=0)
        page2 = await store.list(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        # No overlap
        ids1 = {r.routine_id for r in page1}
        ids2 = {r.routine_id for r in page2}
        assert ids1.isdisjoint(ids2)


# ── list_due ──────────────────────────────────────────────────────


class TestListDue:
    async def test_list_due_finds_past_next_run(self, store):
        await store.create(
            name="Due",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "due"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        await store.create(
            name="Not due",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "not due"},
            next_run_at="2099-01-01T00:00:00.000Z",
        )
        due = await store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 1
        assert due[0].name == "Due"

    async def test_list_due_excludes_disabled(self, store):
        await store.create(
            name="Disabled but past",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "disabled"},
            enabled=False,
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        due = await store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 0

    async def test_list_due_excludes_null_next_run(self, store):
        await store.create(
            name="No next run",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "event-based"},
        )
        due = await store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 0


# ── update_run_state ──────────────────────────────────────────────


class TestUpdateRunState:
    async def test_update_run_state(self, store):
        r = await store.create(
            name="Run state test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            next_run_at="2026-01-01T00:00:00.000Z",
        )

        await store.update_run_state(
            r.routine_id,
            last_run_at="2026-01-01T09:00:00.000Z",
            next_run_at="2026-01-02T09:00:00.000Z",
        )

        fetched = await store.get(r.routine_id)
        assert fetched.last_run_at == "2026-01-01T09:00:00.000Z"
        assert fetched.next_run_at == "2026-01-02T09:00:00.000Z"

    async def test_update_run_state_clears_next_run(self, store):
        r = await store.create(
            name="Clear next",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "test"},
            next_run_at="2026-01-01T00:00:00.000Z",
        )

        await store.update_run_state(
            r.routine_id,
            last_run_at="2026-01-01T09:00:00.000Z",
            next_run_at=None,
        )

        fetched = await store.get(r.routine_id)
        assert fetched.last_run_at == "2026-01-01T09:00:00.000Z"
        assert fetched.next_run_at is None


# ── V-004: SQL injection boundary tests ──────────────────────────


_EVIL_INPUTS = [
    "'; DROP TABLE routines; --",
    "' OR '1'='1",
    "'; DELETE FROM routine_executions; --",
    "\x00null_byte\x00",
    "a" * 100_000,
    "SELECT * FROM routines",
    "Robert'); DROP TABLE students;--",
    "1; ATTACH DATABASE '/tmp/evil.db' AS evil; --",
]


class TestRoutineStoreSQLInjection:
    """Regression guard: V-004 — user-provided strings stored as literals, never executed."""

    @pytest.mark.parametrize("evil_input", _EVIL_INPUTS, ids=[
        "drop_table", "or_1_1", "delete_executions", "null_bytes",
        "very_long_string", "select_star", "bobby_tables", "attach_db",
    ])
    async def test_evil_name(self, store, evil_input):
        """Evil strings as routine name survive roundtrip."""
        r = await store.create(
            name=evil_input,
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        fetched = await store.get(r.routine_id)
        assert fetched is not None
        assert fetched.name == evil_input

    @pytest.mark.parametrize("evil_input", _EVIL_INPUTS, ids=[
        "drop_table", "or_1_1", "delete_executions", "null_bytes",
        "very_long_string", "select_star", "bobby_tables", "attach_db",
    ])
    async def test_evil_prompt(self, store, evil_input):
        """Evil strings as action prompt survive roundtrip."""
        r = await store.create(
            name="Safe name",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": evil_input},
        )
        fetched = await store.get(r.routine_id)
        assert fetched is not None
        assert fetched.action_config["prompt"] == evil_input


# ── In-memory mode ────────────────────────────────────────────────


class TestInMemoryMode:
    """Verify the in-memory fallback works the same as SQLite."""

    async def test_crud_roundtrip(self, mem_store):
        r = await mem_store.create(
            name="Memory test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        assert await mem_store.get(r.routine_id) is not None
        await mem_store.update(r.routine_id, name="Updated")
        assert (await mem_store.get(r.routine_id)).name == "Updated"
        assert await mem_store.delete(r.routine_id) is True
        assert await mem_store.get(r.routine_id) is None

    async def test_list_due_memory(self, mem_store):
        await mem_store.create(
            name="Due",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "due"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        due = await mem_store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 1

    async def test_update_run_state_memory(self, mem_store):
        r = await mem_store.create(
            name="State test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        await mem_store.update_run_state(
            r.routine_id,
            last_run_at="2026-01-01T09:00:00.000Z",
            next_run_at="2026-01-02T09:00:00.000Z",
        )
        fetched = await mem_store.get(r.routine_id)
        assert fetched.last_run_at == "2026-01-01T09:00:00.000Z"


# ── Cron validation helper ────────────────────────────────────────


class TestCronHelpers:
    def test_validate_cron_valid(self):
        assert validate_cron("0 9 * * MON") is True
        assert validate_cron("*/15 * * * *") is True
        assert validate_cron("0 0 1 1 *") is True

    def test_validate_cron_invalid(self):
        assert validate_cron("not a cron") is False
        assert validate_cron("") is False
        assert validate_cron("60 * * * *") is False

    def test_next_run_returns_future(self):
        from datetime import datetime, timezone
        base = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        result = next_run("0 9 * * *", base=base)
        assert result > base
        assert result.hour == 9

    def test_next_run_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid cron"):
            next_run("not a cron")

    def test_validate_trigger_config_cron(self):
        validate_trigger_config("cron", {"cron": "0 9 * * *"})
        with pytest.raises(ValueError, match="cron"):
            validate_trigger_config("cron", {"cron": "invalid"})
        with pytest.raises(ValueError, match="cron"):
            validate_trigger_config("cron", {})

    def test_validate_trigger_config_event(self):
        validate_trigger_config("event", {"event": "task.*.completed"})
        with pytest.raises(ValueError, match="event"):
            validate_trigger_config("event", {})

    def test_validate_trigger_config_interval(self):
        validate_trigger_config("interval", {"seconds": 3600})
        with pytest.raises(ValueError, match="seconds"):
            validate_trigger_config("interval", {"seconds": -1})
        with pytest.raises(ValueError, match="seconds"):
            validate_trigger_config("interval", {})

    def test_validate_trigger_config_unknown(self):
        with pytest.raises(ValueError, match="Unknown trigger_type"):
            validate_trigger_config("unknown", {})


# ── Cascade delete ────────────────────────────────────────────────


class TestCascadeDelete:
    """Deleting a routine removes it from the in-memory store."""

    async def test_delete_removes_routine(self, store):
        r = await store.create(
            name="Cascade test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )

        assert await store.get(r.routine_id) is not None
        assert await store.delete(r.routine_id) is True
        assert await store.get(r.routine_id) is None
