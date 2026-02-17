"""SQLite-specific session store tests.

Tests write-through persistence, TTL eviction via SQL, capacity eviction,
turn persistence, and cascade delete.
"""

import pytest

from sentinel.core.db import init_db
from sentinel.session.store import ConversationTurn, Session, SessionStore


@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def store(db):
    return SessionStore(db=db, ttl=3600, max_count=5)


class TestSessionStoreSQLite:
    def test_create_session(self, store):
        session = store.get_or_create("s1", source="test")
        assert session.session_id == "s1"
        assert session.source == "test"
        assert len(session.turns) == 0
        assert store.count == 1

    def test_get_existing_session(self, store):
        store.get_or_create("s1")
        s2 = store.get_or_create("s1")
        assert s2.session_id == "s1"
        assert store.count == 1

    def test_ephemeral_session(self, store):
        session = store.get_or_create(None)
        assert session.session_id.startswith("ephemeral-")
        assert store.count == 1

    def test_get_nonexistent(self, store):
        assert store.get("nonexistent") is None

    def test_add_turn_persists(self, store):
        session = store.get_or_create("s1")
        session.add_turn(ConversationTurn(
            request_text="hello", result_status="success",
        ))
        assert len(session.turns) == 1

        # Re-fetch from store — turn should be loaded from SQLite
        session2 = store.get("s1")
        assert session2 is not None
        assert len(session2.turns) == 1
        assert session2.turns[0].request_text == "hello"
        assert session2.turns[0].result_status == "success"

    def test_violation_count_increments(self, store):
        session = store.get_or_create("s1")
        session.add_turn(ConversationTurn(
            request_text="bad", result_status="blocked",
            blocked_by=["scanner"],
        ))
        assert session.violation_count == 1

        # Persisted to SQLite
        s2 = store.get("s1")
        assert s2.violation_count == 1

    def test_lock_persists(self, store):
        session = store.get_or_create("s1")
        session.lock()
        assert session.is_locked is True

        s2 = store.get("s1")
        assert s2.is_locked is True

    def test_ttl_eviction(self, db):
        """Sessions with last_active older than TTL are evicted."""
        store = SessionStore(db=db, ttl=10, max_count=100)
        store.get_or_create("s1")

        # Backdate the session in SQLite to simulate TTL expiry
        db.execute("UPDATE sessions SET last_active = '2020-01-01T00:00:00.000000Z' WHERE session_id = 's1'")
        db.commit()

        assert store.get("s1") is None

    def test_capacity_eviction(self, db):
        """Adding beyond max_count evicts the oldest session."""
        store = SessionStore(db=db, ttl=3600, max_count=3)
        store.get_or_create("s1")
        store.get_or_create("s2")
        store.get_or_create("s3")
        assert store.count == 3

        store.get_or_create("s4")
        assert store.count == 3
        # s1 was oldest → evicted
        assert store.get("s1") is None

    def test_cascade_delete_removes_turns(self, db):
        """Deleting a session cascades to its conversation turns."""
        store = SessionStore(db=db, ttl=3600, max_count=5)
        session = store.get_or_create("s1")
        session.add_turn(ConversationTurn(request_text="t1", result_status="success"))
        session.add_turn(ConversationTurn(request_text="t2", result_status="success"))

        # Verify turns exist
        count = db.execute("SELECT COUNT(*) FROM conversation_turns WHERE session_id = 's1'").fetchone()[0]
        assert count == 2

        # Delete the session
        db.execute("DELETE FROM sessions WHERE session_id = 's1'")
        db.commit()

        # Turns should be cascade-deleted
        count = db.execute("SELECT COUNT(*) FROM conversation_turns WHERE session_id = 's1'").fetchone()[0]
        assert count == 0

    def test_persistence_across_store_instances(self, db):
        """Data persists even when creating a new SessionStore instance."""
        store1 = SessionStore(db=db, ttl=3600, max_count=5)
        session = store1.get_or_create("s1", source="test")
        session.add_turn(ConversationTurn(request_text="hello", result_status="success"))

        store2 = SessionStore(db=db, ttl=3600, max_count=5)
        s2 = store2.get("s1")
        assert s2 is not None
        assert s2.source == "test"
        assert len(s2.turns) == 1

    def test_blocked_by_json_roundtrip(self, store):
        """blocked_by list survives JSON serialization in SQLite."""
        session = store.get_or_create("s1")
        session.add_turn(ConversationTurn(
            request_text="bad",
            result_status="blocked",
            blocked_by=["scanner", "prompt_guard"],
        ))

        s2 = store.get("s1")
        assert s2.turns[0].blocked_by == ["scanner", "prompt_guard"]

    def test_cumulative_risk_persists(self, store):
        """Cumulative risk from session object persists to SQLite."""
        session = store.get_or_create("s1")
        session.cumulative_risk = 3.5
        session.add_turn(ConversationTurn(request_text="test", result_status="success"))

        s2 = store.get("s1")
        assert s2.cumulative_risk == 3.5
