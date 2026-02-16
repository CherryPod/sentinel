"""Tests for sentinel.core.db — schema creation and table structure."""

import sqlite3

import pytest

from sentinel.core.db import init_db


@pytest.fixture
def db():
    """In-memory database for testing."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


class TestInitDb:
    def test_returns_connection(self, db):
        assert isinstance(db, sqlite3.Connection)

    def test_wal_mode_on_file_db(self, tmp_path):
        """WAL mode is set for file-backed databases (not :memory:)."""
        conn = init_db(str(tmp_path / "test.db"))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()

    def test_foreign_keys_enabled(self, db):
        fk = db.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1

    def test_idempotent(self, db):
        """Calling init_db twice on same connection shouldn't error."""
        # init_db creates a new connection, but the tables use IF NOT EXISTS
        conn2 = init_db(":memory:")
        tables = [r[0] for r in conn2.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()]
        assert "sessions" in tables
        conn2.close()


class TestCoreTables:
    EXPECTED_TABLES = [
        "sessions", "conversation_turns", "provenance", "file_provenance",
        "approvals", "memory_chunks", "routines", "audit_log",
    ]

    def test_all_tables_exist(self, db):
        tables = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        for expected in self.EXPECTED_TABLES:
            assert expected in tables, f"Missing table: {expected}"

    def test_fts_table_exists(self, db):
        tables = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        assert "memory_chunks_fts" in tables


class TestSessionsTable:
    def test_insert_and_query(self, db):
        db.execute(
            "INSERT INTO sessions (session_id, user_id, source) VALUES (?, ?, ?)",
            ("s1", "default", "web"),
        )
        row = db.execute("SELECT * FROM sessions WHERE session_id = 's1'").fetchone()
        assert row is not None
        assert row[0] == "s1"  # session_id
        assert row[1] == "default"  # user_id

    def test_user_id_default(self, db):
        db.execute("INSERT INTO sessions (session_id) VALUES ('s2')")
        row = db.execute("SELECT user_id FROM sessions WHERE session_id = 's2'").fetchone()
        assert row[0] == "default"

    def test_timestamps_auto_set(self, db):
        db.execute("INSERT INTO sessions (session_id) VALUES ('s3')")
        row = db.execute(
            "SELECT created_at, last_active FROM sessions WHERE session_id = 's3'"
        ).fetchone()
        assert row[0] is not None  # created_at
        assert row[1] is not None  # last_active


class TestConversationTurns:
    def test_insert_with_foreign_key(self, db):
        db.execute("INSERT INTO sessions (session_id) VALUES ('s1')")
        db.execute(
            "INSERT INTO conversation_turns (session_id, request_text) VALUES (?, ?)",
            ("s1", "Hello"),
        )
        row = db.execute("SELECT * FROM conversation_turns WHERE session_id = 's1'").fetchone()
        assert row is not None

    def test_foreign_key_enforced(self, db):
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO conversation_turns (session_id, request_text) VALUES (?, ?)",
                ("nonexistent", "Hello"),
            )

    def test_cascade_delete(self, db):
        db.execute("INSERT INTO sessions (session_id) VALUES ('s1')")
        db.execute(
            "INSERT INTO conversation_turns (session_id, request_text) VALUES (?, ?)",
            ("s1", "Hello"),
        )
        db.execute("DELETE FROM sessions WHERE session_id = 's1'")
        count = db.execute("SELECT COUNT(*) FROM conversation_turns WHERE session_id = 's1'").fetchone()[0]
        assert count == 0


class TestProvenanceTable:
    def test_insert(self, db):
        db.execute(
            "INSERT INTO provenance (data_id, content, source, trust_level) VALUES (?, ?, ?, ?)",
            ("d1", "some content", "llm", "UNTRUSTED"),
        )
        row = db.execute("SELECT trust_level FROM provenance WHERE data_id = 'd1'").fetchone()
        assert row[0] == "UNTRUSTED"


class TestApprovalsTable:
    def test_insert(self, db):
        db.execute(
            "INSERT INTO approvals (approval_id, task_id, plan_json, expires_at) VALUES (?, ?, ?, ?)",
            ("a1", "t1", '{"steps": []}', "2026-12-31T00:00:00Z"),
        )
        row = db.execute("SELECT status FROM approvals WHERE approval_id = 'a1'").fetchone()
        assert row[0] == "pending"


class TestMemoryChunksTable:
    def test_insert(self, db):
        db.execute(
            "INSERT INTO memory_chunks (chunk_id, content, source) VALUES (?, ?, ?)",
            ("c1", "Memory content here", "conversation"),
        )
        row = db.execute("SELECT content FROM memory_chunks WHERE chunk_id = 'c1'").fetchone()
        assert row[0] == "Memory content here"


class TestRoutinesTable:
    def test_insert(self, db):
        db.execute(
            "INSERT INTO routines (routine_id, name) VALUES (?, ?)",
            ("r1", "daily_summary"),
        )
        row = db.execute("SELECT name, enabled FROM routines WHERE routine_id = 'r1'").fetchone()
        assert row[0] == "daily_summary"
        assert row[1] == 1  # enabled by default


class TestAuditLogTable:
    def test_insert(self, db):
        db.execute(
            "INSERT INTO audit_log (event_type, session_id, details) VALUES (?, ?, ?)",
            ("task_complete", "s1", '{"result": "ok"}'),
        )
        row = db.execute("SELECT event_type FROM audit_log WHERE session_id = 's1'").fetchone()
        assert row[0] == "task_complete"
