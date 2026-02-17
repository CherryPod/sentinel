"""Tests for RoutineStore CRUD operations.

Verifies:
- Create/get/list/update/delete roundtrip
- list_due() query correctness
- update_run_state()
- enabled_only filtering
- User isolation
- Both SQLite and in-memory modes
"""

import sqlite3
import time

import pytest

from sentinel.core.db import init_db
from sentinel.routines.cron import next_run, validate_cron, validate_trigger_config
from sentinel.routines.store import Routine, RoutineStore


@pytest.fixture
def db():
    """In-memory SQLite database with schema."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def store(db):
    """RoutineStore backed by in-memory SQLite."""
    return RoutineStore(db=db)


@pytest.fixture
def mem_store():
    """RoutineStore using in-memory dict (no database)."""
    return RoutineStore(db=None)


# ── CRUD roundtrip ────────────────────────────────────────────────


class TestCRUD:
    def test_create_and_get(self, store):
        r = store.create(
            name="Morning check",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Check system health"},
        )
        assert r.routine_id
        assert r.name == "Morning check"
        assert r.trigger_type == "cron"
        assert r.enabled is True

        fetched = store.get(r.routine_id)
        assert fetched is not None
        assert fetched.name == "Morning check"
        assert fetched.trigger_config == {"cron": "0 9 * * *"}

    def test_get_nonexistent_returns_none(self, store):
        assert store.get("nonexistent-id") is None

    def test_create_with_all_fields(self, store):
        r = store.create(
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

    def test_update(self, store):
        r = store.create(
            name="Original",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )

        updated = store.update(r.routine_id, name="Updated", enabled=False)
        assert updated is not None
        assert updated.name == "Updated"
        assert updated.enabled is False

        # Verify persisted
        fetched = store.get(r.routine_id)
        assert fetched.name == "Updated"
        assert fetched.enabled is False

    def test_update_nonexistent_returns_none(self, store):
        assert store.update("nonexistent", name="x") is None

    def test_update_trigger_config(self, store):
        r = store.create(
            name="Config test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        updated = store.update(r.routine_id, trigger_config={"cron": "0 12 * * *"})
        assert updated.trigger_config == {"cron": "0 12 * * *"}

    def test_delete(self, store):
        r = store.create(
            name="To delete",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "test"},
        )
        assert store.delete(r.routine_id) is True
        assert store.get(r.routine_id) is None

    def test_delete_nonexistent_returns_false(self, store):
        assert store.delete("nonexistent") is False


# ── List and filtering ────────────────────────────────────────────


class TestListFiltering:
    def test_list_returns_all(self, store):
        store.create(name="A", trigger_type="cron",
                     trigger_config={"cron": "0 9 * * *"},
                     action_config={"prompt": "a"})
        store.create(name="B", trigger_type="cron",
                     trigger_config={"cron": "0 10 * * *"},
                     action_config={"prompt": "b"}, enabled=False)
        results = store.list()
        assert len(results) == 2

    def test_list_enabled_only(self, store):
        store.create(name="Enabled", trigger_type="cron",
                     trigger_config={"cron": "0 9 * * *"},
                     action_config={"prompt": "a"}, enabled=True)
        store.create(name="Disabled", trigger_type="cron",
                     trigger_config={"cron": "0 10 * * *"},
                     action_config={"prompt": "b"}, enabled=False)
        results = store.list(enabled_only=True)
        assert len(results) == 1
        assert results[0].name == "Enabled"

    def test_list_respects_user_id(self, store):
        store.create(name="Alice's", trigger_type="cron",
                     trigger_config={"cron": "0 9 * * *"},
                     action_config={"prompt": "a"}, user_id="alice")
        store.create(name="Bob's", trigger_type="cron",
                     trigger_config={"cron": "0 10 * * *"},
                     action_config={"prompt": "b"}, user_id="bob")
        alice = store.list(user_id="alice")
        assert len(alice) == 1
        assert alice[0].name == "Alice's"

    def test_list_limit_offset(self, store):
        for i in range(5):
            store.create(name=f"R{i}", trigger_type="cron",
                         trigger_config={"cron": "0 9 * * *"},
                         action_config={"prompt": f"r{i}"})
            # Small delay so created_at differs
            time.sleep(0.002)
        page1 = store.list(limit=2, offset=0)
        page2 = store.list(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        # No overlap
        ids1 = {r.routine_id for r in page1}
        ids2 = {r.routine_id for r in page2}
        assert ids1.isdisjoint(ids2)


# ── list_due ──────────────────────────────────────────────────────


class TestListDue:
    def test_list_due_finds_past_next_run(self, store):
        store.create(
            name="Due",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "due"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        store.create(
            name="Not due",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "not due"},
            next_run_at="2099-01-01T00:00:00.000Z",
        )
        due = store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 1
        assert due[0].name == "Due"

    def test_list_due_excludes_disabled(self, store):
        store.create(
            name="Disabled but past",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "disabled"},
            enabled=False,
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        due = store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 0

    def test_list_due_excludes_null_next_run(self, store):
        store.create(
            name="No next run",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "event-based"},
        )
        due = store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 0


# ── update_run_state ──────────────────────────────────────────────


class TestUpdateRunState:
    def test_update_run_state(self, store):
        r = store.create(
            name="Run state test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
            next_run_at="2026-01-01T00:00:00.000Z",
        )

        store.update_run_state(
            r.routine_id,
            last_run_at="2026-01-01T09:00:00.000Z",
            next_run_at="2026-01-02T09:00:00.000Z",
        )

        fetched = store.get(r.routine_id)
        assert fetched.last_run_at == "2026-01-01T09:00:00.000Z"
        assert fetched.next_run_at == "2026-01-02T09:00:00.000Z"

    def test_update_run_state_clears_next_run(self, store):
        r = store.create(
            name="Clear next",
            trigger_type="event",
            trigger_config={"event": "task.*.completed"},
            action_config={"prompt": "test"},
            next_run_at="2026-01-01T00:00:00.000Z",
        )

        store.update_run_state(
            r.routine_id,
            last_run_at="2026-01-01T09:00:00.000Z",
            next_run_at=None,
        )

        fetched = store.get(r.routine_id)
        assert fetched.last_run_at == "2026-01-01T09:00:00.000Z"
        assert fetched.next_run_at is None


# ── In-memory mode ────────────────────────────────────────────────


class TestInMemoryMode:
    """Verify the in-memory fallback works the same as SQLite."""

    def test_crud_roundtrip(self, mem_store):
        r = mem_store.create(
            name="Memory test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        assert mem_store.get(r.routine_id) is not None
        mem_store.update(r.routine_id, name="Updated")
        assert mem_store.get(r.routine_id).name == "Updated"
        assert mem_store.delete(r.routine_id) is True
        assert mem_store.get(r.routine_id) is None

    def test_list_due_memory(self, mem_store):
        mem_store.create(
            name="Due",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "due"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )
        due = mem_store.list_due("2026-01-01T00:00:00.000Z")
        assert len(due) == 1

    def test_update_run_state_memory(self, mem_store):
        r = mem_store.create(
            name="State test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )
        mem_store.update_run_state(
            r.routine_id,
            last_run_at="2026-01-01T09:00:00.000Z",
            next_run_at="2026-01-02T09:00:00.000Z",
        )
        fetched = mem_store.get(r.routine_id)
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
    """Deleting a routine should cascade to routine_executions."""

    def test_execution_cascade(self, db, store):
        r = store.create(
            name="Cascade test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "test"},
        )

        # Insert a fake execution record
        db.execute(
            """INSERT INTO routine_executions
               (execution_id, routine_id, user_id, triggered_by, status)
               VALUES ('exec-1', ?, 'default', 'manual', 'success')""",
            (r.routine_id,),
        )
        db.commit()

        # Verify it exists
        row = db.execute(
            "SELECT * FROM routine_executions WHERE routine_id = ?",
            (r.routine_id,),
        ).fetchone()
        assert row is not None

        # Delete routine — should cascade
        store.delete(r.routine_id)

        row = db.execute(
            "SELECT * FROM routine_executions WHERE routine_id = ?",
            (r.routine_id,),
        ).fetchone()
        assert row is None
