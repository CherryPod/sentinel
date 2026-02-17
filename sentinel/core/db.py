"""SQLite database schema for Sentinel.

Schema-only module — creates tables for sessions, conversation turns, provenance,
approvals, memory chunks (with FTS5 + sqlite-vec), routines, and audit logs.
No migration of in-memory stores yet (that happens in Phase 1.2).
"""

import sqlite3
from pathlib import Path


def init_db(db_path: str = "sentinel.db") -> sqlite3.Connection:
    """Initialise the Sentinel database and create all tables.

    Args:
        db_path: Path to the SQLite database file, or ':memory:' for in-memory.

    Returns:
        An open sqlite3.Connection with WAL mode and foreign keys enabled.
    """
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    _create_tables(conn)
    _create_fts_index(conn)
    _try_create_vec_table(conn)

    conn.commit()
    return conn


def _create_tables(conn: sqlite3.Connection) -> None:
    """Create all core tables."""

    # -- Sessions --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id      TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL DEFAULT 'default',
            source          TEXT NOT NULL DEFAULT '',
            cumulative_risk REAL NOT NULL DEFAULT 0.0,
            violation_count INTEGER NOT NULL DEFAULT 0,
            is_locked       INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            last_active     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)

    # -- Conversation turns --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS conversation_turns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            user_id         TEXT NOT NULL DEFAULT 'default',
            request_text    TEXT NOT NULL,
            result_status   TEXT NOT NULL DEFAULT '',
            blocked_by      TEXT NOT NULL DEFAULT '[]',
            risk_score      REAL NOT NULL DEFAULT 0.0,
            plan_summary    TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_turns_session
        ON conversation_turns(session_id)
    """)

    # -- Provenance --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS provenance (
            data_id         TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL DEFAULT 'default',
            content         TEXT NOT NULL,
            source          TEXT NOT NULL,
            trust_level     TEXT NOT NULL,
            originated_from TEXT NOT NULL DEFAULT '',
            parent_ids      TEXT NOT NULL DEFAULT '[]',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)

    # -- File provenance --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_provenance (
            file_path       TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL DEFAULT 'default',
            writer_data_id  TEXT NOT NULL REFERENCES provenance(data_id),
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)

    # -- Approvals --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS approvals (
            approval_id     TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL DEFAULT 'default',
            task_id         TEXT NOT NULL DEFAULT '',
            plan_json       TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            decided_at      TEXT,
            decided_reason  TEXT NOT NULL DEFAULT '',
            decided_by      TEXT NOT NULL DEFAULT '',
            expires_at      TEXT NOT NULL,
            source_key      TEXT NOT NULL DEFAULT '',
            user_request    TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_approvals_status
        ON approvals(status)
    """)

    # -- Memory chunks (for Phase 2 hybrid search) --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memory_chunks (
            chunk_id        TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL DEFAULT 'default',
            content         TEXT NOT NULL,
            source          TEXT NOT NULL DEFAULT '',
            metadata        TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)

    # -- Routines (Phase 5) --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS routines (
            routine_id      TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL DEFAULT 'default',
            name            TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            trigger_type    TEXT NOT NULL DEFAULT 'cron',
            trigger_config  TEXT NOT NULL DEFAULT '{}',
            action_config   TEXT NOT NULL DEFAULT '{}',
            enabled         INTEGER NOT NULL DEFAULT 1,
            last_run_at     TEXT,
            next_run_at     TEXT,
            cooldown_s      INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_routines_enabled_next
        ON routines(enabled, next_run_at) WHERE enabled = 1
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_routines_user_id
        ON routines(user_id)
    """)

    # -- Routine executions (Phase 5) --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS routine_executions (
            execution_id    TEXT PRIMARY KEY,
            routine_id      TEXT NOT NULL REFERENCES routines(routine_id) ON DELETE CASCADE,
            user_id         TEXT NOT NULL DEFAULT 'default',
            triggered_by    TEXT NOT NULL DEFAULT 'scheduler',
            started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            completed_at    TEXT,
            status          TEXT NOT NULL DEFAULT 'running',
            result_summary  TEXT NOT NULL DEFAULT '',
            error           TEXT NOT NULL DEFAULT '',
            task_id         TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_routine_exec_routine
        ON routine_executions(routine_id, started_at)
    """)

    # -- Audit log (structured supplement to JSONL) --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         TEXT NOT NULL DEFAULT 'default',
            event_type      TEXT NOT NULL,
            session_id      TEXT,
            details         TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_event_type
        ON audit_log(event_type)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_session
        ON audit_log(session_id)
    """)


def _create_fts_index(conn: sqlite3.Connection) -> None:
    """Create FTS5 full-text search index on memory_chunks."""
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS memory_chunks_fts
        USING fts5(content, source, content=memory_chunks, content_rowid=rowid)
    """)


def _try_create_vec_table(conn: sqlite3.Connection) -> None:
    """Attempt to create sqlite-vec virtual table for vector search.

    Silently skips if sqlite-vec extension is not available — the vector
    table is optional until Phase 2 when embeddings are generated.
    """
    try:
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_chunks_vec
            USING vec0(chunk_id TEXT PRIMARY KEY, embedding float[768])
        """)
    except sqlite3.OperationalError:
        # sqlite-vec extension not loaded — skip vector table
        pass
