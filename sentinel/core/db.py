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
    _migrate_tables(conn)
    _create_fts_index(conn)
    _try_create_vec_table(conn)
    _create_episodic_fts_index(conn)

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
            last_active     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            task_in_progress INTEGER NOT NULL DEFAULT 0
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
            auto_approved   INTEGER NOT NULL DEFAULT 0,
            elapsed_s       REAL,
            step_outcomes   TEXT,
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

    # -- Webhooks (C1) --
    # HMAC secrets stored plaintext — encryption requires raw value for verification.
    # Mitigated by container read_only and file permissions. See H-002 for PIN hashing
    # approach (PINs can be hashed; HMAC secrets cannot).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id      TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            secret          TEXT NOT NULL,
            enabled         INTEGER NOT NULL DEFAULT 1,
            user_id         TEXT NOT NULL DEFAULT 'default',
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)

    # -- Audit log (structured supplement to JSONL) --
    # TODO: Add retention policy — consider daily cleanup of entries older than 90 days
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

    # -- Episodic records (F4: long-term structured memory) --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS episodic_records (
            record_id       TEXT PRIMARY KEY,
            session_id      TEXT NOT NULL,
            task_id         TEXT NOT NULL DEFAULT '',
            user_id         TEXT NOT NULL DEFAULT 'default',
            user_request    TEXT NOT NULL,
            task_status     TEXT NOT NULL,
            plan_summary    TEXT NOT NULL DEFAULT '',
            step_count      INTEGER NOT NULL DEFAULT 0,
            success_count   INTEGER NOT NULL DEFAULT 0,
            file_paths      TEXT NOT NULL DEFAULT '[]',
            error_patterns  TEXT NOT NULL DEFAULT '[]',
            defined_symbols TEXT NOT NULL DEFAULT '[]',
            step_outcomes   TEXT,
            linked_records  TEXT NOT NULL DEFAULT '[]',
            relevance_score REAL NOT NULL DEFAULT 1.0,
            access_count    INTEGER NOT NULL DEFAULT 0,
            last_accessed   TEXT,
            memory_chunk_id TEXT,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_episodic_session
        ON episodic_records(session_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_episodic_created
        ON episodic_records(created_at DESC)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_episodic_status
        ON episodic_records(task_status)
    """)

    # -- Episodic file index (F4: normalised file-path-to-record mapping) --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS episodic_file_index (
            file_path   TEXT NOT NULL,
            record_id   TEXT NOT NULL REFERENCES episodic_records(record_id) ON DELETE CASCADE,
            action      TEXT NOT NULL DEFAULT 'modified',
            PRIMARY KEY (file_path, record_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_episodic_file_path
        ON episodic_file_index(file_path)
    """)

    # -- Episodic facts (F4: short keyword-rich extracted facts) --
    conn.execute("""
        CREATE TABLE IF NOT EXISTS episodic_facts (
            fact_id     TEXT PRIMARY KEY,
            record_id   TEXT NOT NULL REFERENCES episodic_records(record_id) ON DELETE CASCADE,
            fact_type   TEXT NOT NULL,
            content     TEXT NOT NULL,
            file_path   TEXT,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_fact_record
        ON episodic_facts(record_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_fact_file_path
        ON episodic_facts(file_path)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_fact_type
        ON episodic_facts(fact_type)
    """)


def _migrate_tables(conn: sqlite3.Connection) -> None:
    """Add columns introduced after initial schema (idempotent)."""
    cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(conversation_turns)").fetchall()
    }
    if "auto_approved" not in cols:
        conn.execute(
            "ALTER TABLE conversation_turns ADD COLUMN auto_approved INTEGER NOT NULL DEFAULT 0"
        )
    if "elapsed_s" not in cols:
        conn.execute(
            "ALTER TABLE conversation_turns ADD COLUMN elapsed_s REAL"
        )
    if "step_outcomes" not in cols:
        conn.execute(
            "ALTER TABLE conversation_turns ADD COLUMN step_outcomes TEXT"
        )

    # F2: task_in_progress on sessions
    session_cols = {
        row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()
    }
    if "task_in_progress" not in session_cols:
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN task_in_progress INTEGER NOT NULL DEFAULT 0"
        )


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


def _create_episodic_fts_index(conn: sqlite3.Connection) -> None:
    """Create FTS5 index on episodic_facts for keyword search."""
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS episodic_facts_fts
        USING fts5(content, fact_type, content=episodic_facts, content_rowid=rowid)
    """)
