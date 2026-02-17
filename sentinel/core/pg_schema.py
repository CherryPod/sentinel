"""PostgreSQL schema creation — all tables, indexes, extensions, and generated columns.

Called from app.py lifespan after the asyncpg pool is created.
Idempotent — safe to call on every startup (IF NOT EXISTS everywhere).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("sentinel.core.pg_schema")

# ── SQL statements in dependency order ──────────────────────────────

# Extensions (must come before any table that uses vector types)
_EXTENSIONS = [
    "CREATE EXTENSION IF NOT EXISTS vector;",
]

# Tables with no FK dependencies (users MUST be first — other tables reference it)
_TABLES_NO_FK = [
    # 4.14 Users (contact registry — system identity, created first for FK references)
    """
    CREATE TABLE IF NOT EXISTS users (
        user_id         SERIAL PRIMARY KEY,
        display_name    TEXT NOT NULL,
        pin_hash        TEXT,
        is_active       BOOLEAN NOT NULL DEFAULT TRUE,
        role            TEXT NOT NULL DEFAULT 'user'
                        CHECK (role IN ('owner', 'admin', 'user', 'pending')),
        trust_level     INTEGER CHECK (trust_level BETWEEN 0 AND 4),
        sessions_invalidated_at TIMESTAMPTZ,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.1 Sessions
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id      TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        source          TEXT NOT NULL DEFAULT '',
        cumulative_risk DOUBLE PRECISION NOT NULL DEFAULT 0.0,
        violation_count INTEGER NOT NULL DEFAULT 0,
        is_locked       BOOLEAN NOT NULL DEFAULT FALSE,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_active     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        task_in_progress BOOLEAN NOT NULL DEFAULT FALSE
    );
    """,
    # 4.6 Memory Chunks (with tsvector generated column and pgvector embedding)
    """
    CREATE TABLE IF NOT EXISTS memory_chunks (
        chunk_id        TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        content         TEXT NOT NULL,
        source          TEXT NOT NULL DEFAULT '',
        metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        search_vector   tsvector GENERATED ALWAYS AS (
            setweight(to_tsvector('english', coalesce(source, '')), 'A') ||
            setweight(to_tsvector('english', coalesce(content, '')), 'B')
        ) STORED,
        embedding       vector(768)
    );
    """,
    # 4.7 Routines
    """
    CREATE TABLE IF NOT EXISTS routines (
        routine_id      TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        name            TEXT NOT NULL,
        description     TEXT NOT NULL DEFAULT '',
        trigger_type    TEXT NOT NULL DEFAULT 'cron',
        trigger_config  JSONB NOT NULL DEFAULT '{}'::jsonb,
        action_config   JSONB NOT NULL DEFAULT '{}'::jsonb,
        enabled         BOOLEAN NOT NULL DEFAULT TRUE,
        last_run_at     TIMESTAMPTZ,
        next_run_at     TIMESTAMPTZ,
        cooldown_s      INTEGER NOT NULL DEFAULT 0,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.9 Webhooks
    """
    CREATE TABLE IF NOT EXISTS webhooks (
        webhook_id      TEXT PRIMARY KEY,
        name            TEXT NOT NULL,
        secret          TEXT NOT NULL,
        enabled         BOOLEAN NOT NULL DEFAULT TRUE,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.10 Audit Log
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id              INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        event_type      TEXT NOT NULL,
        session_id      TEXT,
        details         JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.11 Episodic Records
    """
    CREATE TABLE IF NOT EXISTS episodic_records (
        record_id       TEXT PRIMARY KEY,
        session_id      TEXT NOT NULL,
        task_id         TEXT NOT NULL DEFAULT '',
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        user_request    TEXT NOT NULL,
        task_status     TEXT NOT NULL,
        plan_summary    TEXT NOT NULL DEFAULT '',
        step_count      INTEGER NOT NULL DEFAULT 0,
        success_count   INTEGER NOT NULL DEFAULT 0,
        file_paths      JSONB NOT NULL DEFAULT '[]'::jsonb,
        error_patterns  JSONB NOT NULL DEFAULT '[]'::jsonb,
        defined_symbols JSONB NOT NULL DEFAULT '[]'::jsonb,
        step_outcomes   JSONB,
        linked_records  JSONB NOT NULL DEFAULT '[]'::jsonb,
        relevance_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
        access_count    INTEGER NOT NULL DEFAULT 0,
        last_accessed   TIMESTAMPTZ,
        memory_chunk_id TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.3 Provenance
    """
    CREATE TABLE IF NOT EXISTS provenance (
        data_id         TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        content         TEXT NOT NULL,
        source          TEXT NOT NULL,
        trust_level     TEXT NOT NULL,
        originated_from TEXT NOT NULL DEFAULT '',
        parent_ids      JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.5 Approvals
    """
    CREATE TABLE IF NOT EXISTS approvals (
        approval_id     TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        task_id         TEXT NOT NULL DEFAULT '',
        plan_json       JSONB NOT NULL,
        status          TEXT NOT NULL DEFAULT 'pending',
        decided_at      TIMESTAMPTZ,
        decided_reason  TEXT NOT NULL DEFAULT '',
        decided_by      TEXT NOT NULL DEFAULT '',
        expires_at      TIMESTAMPTZ NOT NULL,
        source_key      TEXT NOT NULL DEFAULT '',
        user_request    TEXT NOT NULL DEFAULT '',
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.17 Confirmations (action-level confirmation gate)
    """
    CREATE TABLE IF NOT EXISTS confirmations (
        confirmation_id TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        channel         TEXT NOT NULL DEFAULT '',
        source_key      TEXT NOT NULL DEFAULT '',
        tool_name       TEXT NOT NULL,
        tool_params     JSONB NOT NULL DEFAULT '{}'::jsonb,
        preview_text    TEXT NOT NULL DEFAULT '',
        original_request TEXT NOT NULL DEFAULT '',
        status          TEXT NOT NULL DEFAULT 'pending',
        task_id         TEXT NOT NULL DEFAULT '',
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at      TIMESTAMPTZ NOT NULL
    );
    """,
]

# Tables with FK dependencies
_TABLES_FK = [
    # 4.2 Conversation Turns (depends on sessions)
    """
    CREATE TABLE IF NOT EXISTS conversation_turns (
        id              INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        session_id      TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        request_text    TEXT NOT NULL,
        result_status   TEXT NOT NULL DEFAULT '',
        blocked_by      JSONB NOT NULL DEFAULT '[]'::jsonb,
        risk_score      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
        plan_summary    TEXT NOT NULL DEFAULT '',
        auto_approved   BOOLEAN NOT NULL DEFAULT FALSE,
        elapsed_s       DOUBLE PRECISION,
        step_outcomes   JSONB,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.4 File Provenance (depends on provenance)
    """
    CREATE TABLE IF NOT EXISTS file_provenance (
        file_path       TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        writer_data_id  TEXT NOT NULL REFERENCES provenance(data_id),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """,
    # 4.8 Routine Executions (depends on routines)
    """
    CREATE TABLE IF NOT EXISTS routine_executions (
        execution_id    TEXT PRIMARY KEY,
        routine_id      TEXT NOT NULL REFERENCES routines(routine_id) ON DELETE CASCADE,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        triggered_by    TEXT NOT NULL DEFAULT 'scheduler',
        started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at    TIMESTAMPTZ,
        status          TEXT NOT NULL DEFAULT 'running',
        result_summary  TEXT NOT NULL DEFAULT '',
        error           TEXT NOT NULL DEFAULT '',
        task_id         TEXT
    );
    """,
    # 4.15 Contacts (depends on users — address book entries per user)
    """
    CREATE TABLE IF NOT EXISTS contacts (
        contact_id      SERIAL PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        display_name    TEXT NOT NULL,
        linked_user_id  INTEGER REFERENCES users(user_id),
        is_user         BOOLEAN NOT NULL DEFAULT FALSE,
        is_system       BOOLEAN NOT NULL DEFAULT FALSE,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, display_name)
    );
    """,
    # 4.16 Contact Channels (depends on contacts — channel-specific identifiers)
    """
    CREATE TABLE IF NOT EXISTS contact_channels (
        id              SERIAL PRIMARY KEY,
        contact_id      INTEGER NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
        channel         TEXT NOT NULL,
        identifier      TEXT NOT NULL,
        is_default      BOOLEAN NOT NULL DEFAULT TRUE,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(channel, identifier)
    );
    """,
    # 4.12 Episodic File Index (depends on episodic_records)
    """
    CREATE TABLE IF NOT EXISTS episodic_file_index (
        file_path   TEXT NOT NULL,
        record_id   TEXT NOT NULL REFERENCES episodic_records(record_id) ON DELETE CASCADE,
        action      TEXT NOT NULL DEFAULT 'modified',
        user_id     INTEGER NOT NULL REFERENCES users(user_id),
        PRIMARY KEY (file_path, record_id)
    );
    """,
    # 4.13 Episodic Facts (depends on episodic_records, with tsvector)
    """
    CREATE TABLE IF NOT EXISTS episodic_facts (
        fact_id     TEXT PRIMARY KEY,
        record_id   TEXT NOT NULL REFERENCES episodic_records(record_id) ON DELETE CASCADE,
        fact_type   TEXT NOT NULL,
        content     TEXT NOT NULL,
        file_path   TEXT,
        user_id     INTEGER NOT NULL REFERENCES users(user_id),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        search_vector tsvector GENERATED ALWAYS AS (
            setweight(to_tsvector('english', coalesce(fact_type, '')), 'A') ||
            setweight(to_tsvector('english', coalesce(content, '')), 'B')
        ) STORED
    );
    """,
    # 4.18 Strategy Patterns (tracked per domain per user for canonical extraction)
    """
    CREATE TABLE IF NOT EXISTS strategy_patterns (
        pattern_id      TEXT PRIMARY KEY,
        domain          TEXT NOT NULL,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        strategy_name   TEXT NOT NULL,
        step_sequence   JSONB NOT NULL DEFAULT '[]'::jsonb,
        occurrence_count INTEGER NOT NULL DEFAULT 0,
        success_count   INTEGER NOT NULL DEFAULT 0,
        avg_duration_s  DOUBLE PRECISION,
        last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(domain, user_id, strategy_name)
    );
    """,
    # 4.17 Domain Summaries (aggregated episodic intelligence per domain per user)
    """
    CREATE TABLE IF NOT EXISTS domain_summaries (
        domain          TEXT NOT NULL,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        total_tasks     INTEGER NOT NULL DEFAULT 0,
        success_count   INTEGER NOT NULL DEFAULT 0,
        summary_text    TEXT NOT NULL DEFAULT '',
        patterns_json   JSONB NOT NULL DEFAULT '[]'::jsonb,
        last_task_count INTEGER NOT NULL DEFAULT 0,
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (domain, user_id)
    );
    """,
    # 4.19 User Credentials (per-user encrypted service credentials)
    """
    CREATE TABLE IF NOT EXISTS user_credentials (
        credential_id   SERIAL PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(user_id),
        service         TEXT NOT NULL,
        encrypted_value BYTEA NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, service)
    );
    """,
]

# GIN indexes for tsvector full-text search
_FTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_memory_chunks_fts ON memory_chunks USING GIN (search_vector);",
    "CREATE INDEX IF NOT EXISTS idx_episodic_facts_fts ON episodic_facts USING GIN (search_vector);",
]

# HNSW index for pgvector cosine similarity search
_VECTOR_INDEXES = [
    """
    CREATE INDEX IF NOT EXISTS idx_memory_chunks_embedding
        ON memory_chunks USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64);
    """,
]

# All other indexes from the research doc
_OTHER_INDEXES = [
    # Conversation turns — session lookup
    "CREATE INDEX IF NOT EXISTS idx_turns_session ON conversation_turns(session_id);",
    # Approvals — status filter
    "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);",
    # Routines — enabled + next_run partial index
    "CREATE INDEX IF NOT EXISTS idx_routines_enabled_next ON routines(enabled, next_run_at) WHERE enabled = TRUE;",
    # Routines — user_id
    "CREATE INDEX IF NOT EXISTS idx_routines_user_id ON routines(user_id);",
    # Routine executions — routine + started_at
    "CREATE INDEX IF NOT EXISTS idx_routine_exec_routine ON routine_executions(routine_id, started_at);",
    # Audit log — event_type and session_id
    "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);",
    "CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);",
    # Episodic records — session, created_at, status
    "CREATE INDEX IF NOT EXISTS idx_episodic_session ON episodic_records(session_id);",
    "CREATE INDEX IF NOT EXISTS idx_episodic_created ON episodic_records(created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_episodic_status ON episodic_records(task_status);",
    # Episodic file index — file_path lookup
    "CREATE INDEX IF NOT EXISTS idx_episodic_file_path ON episodic_file_index(file_path);",
    # Episodic facts — record_id, file_path, fact_type
    "CREATE INDEX IF NOT EXISTS idx_fact_record ON episodic_facts(record_id);",
    "CREATE INDEX IF NOT EXISTS idx_fact_file_path ON episodic_facts(file_path);",
    "CREATE INDEX IF NOT EXISTS idx_fact_type ON episodic_facts(fact_type);",
    # Episodic file index — user_id for privacy filtering
    "CREATE INDEX IF NOT EXISTS idx_efi_user_id ON episodic_file_index(user_id);",
    # Episodic facts — user_id for privacy filtering
    "CREATE INDEX IF NOT EXISTS idx_ef_user_id ON episodic_facts(user_id);",
    # Contacts — user_id lookup
    "CREATE INDEX IF NOT EXISTS idx_contacts_user_id ON contacts(user_id);",
    # Contact channels — contact_id lookup + reverse lookup by channel/identifier
    "CREATE INDEX IF NOT EXISTS idx_contact_channels_contact ON contact_channels(contact_id);",
    "CREATE INDEX IF NOT EXISTS idx_contact_channels_lookup ON contact_channels(channel, identifier);",
    # Confirmations — source_key lookup for pending check, status filter
    "CREATE INDEX IF NOT EXISTS idx_confirmations_source_key ON confirmations(source_key) WHERE status = 'pending';",
    "CREATE INDEX IF NOT EXISTS idx_confirmations_status ON confirmations(status);",
    # Memory chunks — user_id for RLS performance
    "CREATE INDEX IF NOT EXISTS idx_memory_chunks_user_id ON memory_chunks(user_id);",
    # Embedding version tracking (Step 1.7) — detect stale embeddings after model/format changes
    "ALTER TABLE memory_chunks ADD COLUMN IF NOT EXISTS embed_model TEXT DEFAULT 'nomic-embed-text';",
    "ALTER TABLE memory_chunks ADD COLUMN IF NOT EXISTS render_version INTEGER DEFAULT 1;",
    # Task domain classification (Step 1.2) — domain-filtered retrieval
    "ALTER TABLE episodic_records ADD COLUMN IF NOT EXISTS task_domain TEXT;",
    "ALTER TABLE memory_chunks ADD COLUMN IF NOT EXISTS task_domain TEXT;",
    "CREATE INDEX IF NOT EXISTS idx_mc_domain ON memory_chunks(task_domain) WHERE task_domain IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_er_domain ON episodic_records(task_domain) WHERE task_domain IS NOT NULL;",
    # Strategy patterns — domain + user lookup
    "CREATE INDEX IF NOT EXISTS idx_sp_domain_user ON strategy_patterns(domain, user_id);",
]


# Triggers — must run AFTER table creation
_TRIGGERS = [
    # Immutable audit log — prevent UPDATE/DELETE on audit_log rows
    # sentinel_owner is exempted for legitimate maintenance (purge_old_audit_log)
    """
    CREATE OR REPLACE FUNCTION prevent_audit_modification()
    RETURNS TRIGGER AS $$
    BEGIN
        IF current_user = 'sentinel_owner' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'Audit log entries cannot be modified or deleted';
    END;
    $$ LANGUAGE plpgsql;
    """,
    # DROP + CREATE is more robust than DO$$/IF NOT EXISTS — the DO$$ wrapper
    # can swallow errors silently, leaving the trigger undeployed.
    "DROP TRIGGER IF EXISTS trg_immutable_audit ON audit_log;",
    """
    CREATE TRIGGER trg_immutable_audit
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
    """,
]

# Role setup — ownership transfer + DML grants (runs as superuser after tables exist)
_ROLE_SETUP = [
    # Transfer table ownership to sentinel_owner (idempotent — no error if already owned)
    """
    DO $$
    DECLARE
        tbl TEXT;
    BEGIN
        FOR tbl IN
            SELECT tablename FROM pg_tables WHERE schemaname = 'public'
        LOOP
            EXECUTE format('ALTER TABLE %I OWNER TO sentinel_owner', tbl);
        END LOOP;
        -- Also transfer sequences
        FOR tbl IN
            SELECT sequencename FROM pg_sequences WHERE schemaname = 'public'
        LOOP
            EXECUTE format('ALTER SEQUENCE %I OWNER TO sentinel_owner', tbl);
        END LOOP;
    END
    $$;
    """,
    # Grant DML to sentinel_app
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app;",
    "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app;",
    # Revoke DELETE and UPDATE on audit_log from app role (immutability)
    # sentinel_owner retains DELETE for maintenance (purge_old_audit_log)
    # — the trg_immutable_audit trigger blocks sentinel_app at trigger level
    "REVOKE UPDATE, DELETE ON audit_log FROM sentinel_app;",
    # Revoke SELECT on audit_log from app role — admin-read-only (S1 hardening)
    "REVOKE SELECT ON audit_log FROM sentinel_app;",
    # Default privileges for future tables (so new tables auto-grant)
    "ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;",
    "ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;",
    # NOTE: plpgsql revoke lives in container/entrypoint.sh (runs as postgres
    # superuser). sentinel_owner cannot revoke from PUBLIC — only postgres can.
    # See entrypoint.sh for: REVOKE ALL ON LANGUAGE plpgsql FROM PUBLIC;
]

# ── Row-Level Security policies ──────────────────────────────────────

# Tables that get standard RLS (user_id = session variable)
_RLS_DIRECT_TABLES = [
    "sessions",
    "conversation_turns",
    "memory_chunks",
    "routines",
    "routine_executions",
    "webhooks",
    "episodic_records",
    "episodic_file_index",
    "episodic_facts",
    "provenance",
    "file_provenance",
    "approvals",
    "confirmations",
    "contacts",
    "domain_summaries",
    "strategy_patterns",
    "user_credentials",
]

_RLS_POLICIES: list[str] = []

# Standard policies for all direct tables
for _tbl in _RLS_DIRECT_TABLES:
    _RLS_POLICIES.extend([
        f"ALTER TABLE {_tbl} ENABLE ROW LEVEL SECURITY;",
        f"ALTER TABLE {_tbl} FORCE ROW LEVEL SECURITY;",
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE tablename = '{_tbl}' AND policyname = 'user_isolation'
            ) THEN
                CREATE POLICY user_isolation ON {_tbl}
                    USING (user_id = current_setting('app.current_user_id')::INTEGER)
                    WITH CHECK (user_id = current_setting('app.current_user_id')::INTEGER);
            END IF;
        END
        $$;
        """,
        # Owner bypass — sentinel_owner needs unrestricted access for maintenance,
        # FK constraint checks, and admin operations. Required because FORCE RLS
        # makes even the table owner obey policies.
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE tablename = '{_tbl}' AND policyname = 'owner_full_access'
            ) THEN
                CREATE POLICY owner_full_access ON {_tbl}
                    TO sentinel_owner
                    USING (TRUE)
                    WITH CHECK (TRUE);
            END IF;
        END
        $$;
        """,
    ])

# audit_log — admin-read-only: sentinel_app can INSERT but never SELECT.
# Attackers must not see what's being logged. Owner reads via owner_read_access.
# (UPDATE/DELETE blocked by immutable trigger, not RLS)
_RLS_POLICIES.extend([
    "ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;",
    # Drop legacy per-user policies — audit_log is admin-read-only now
    "DROP POLICY IF EXISTS user_isolation_select ON audit_log;",
    "DROP POLICY IF EXISTS user_isolation_insert ON audit_log;",
    # sentinel_app can write audit events but never read them
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'audit_log' AND policyname = 'app_insert_only'
        ) THEN
            CREATE POLICY app_insert_only ON audit_log
                FOR INSERT
                TO sentinel_app
                WITH CHECK (TRUE);
        END IF;
    END
    $$;
    """,
    # Owner policies for audit_log — SELECT + INSERT only (no UPDATE/DELETE).
    # Replaces the old owner_full_access policy that allowed destructive ops.
    "DROP POLICY IF EXISTS owner_full_access ON audit_log;",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'audit_log' AND policyname = 'owner_read_access'
        ) THEN
            CREATE POLICY owner_read_access ON audit_log
                FOR SELECT
                TO sentinel_owner
                USING (TRUE);
        END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'audit_log' AND policyname = 'owner_insert_access'
        ) THEN
            CREATE POLICY owner_insert_access ON audit_log
                FOR INSERT
                TO sentinel_owner
                WITH CHECK (TRUE);
        END IF;
    END
    $$;
    """,
])

# users table — RLS protects pin_hash and user data from app pool.
# Uses user_id = user_id (self-access only). sentinel_owner has full access
# for migrations and admin operations.
_RLS_POLICIES.extend([
    "ALTER TABLE users ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE users FORCE ROW LEVEL SECURITY;",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'users' AND policyname = 'user_isolation'
        ) THEN
            CREATE POLICY user_isolation ON users
                USING (user_id = current_setting('app.current_user_id')::INTEGER)
                WITH CHECK (user_id = current_setting('app.current_user_id')::INTEGER);
        END IF;
    END
    $$;
    """,
    # Owner bypass — sentinel_owner needs unrestricted access for migrations,
    # bootstrap seeding, and admin operations
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'users' AND policyname = 'owner_full_access'
        ) THEN
            CREATE POLICY owner_full_access ON users
                TO sentinel_owner
                USING (TRUE)
                WITH CHECK (TRUE);
        END IF;
    END
    $$;
    """,
])

# contact_channels — no user_id, scope via parent contacts table
_RLS_POLICIES.extend([
    "ALTER TABLE contact_channels ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE contact_channels FORCE ROW LEVEL SECURITY;",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'contact_channels' AND policyname = 'user_isolation'
        ) THEN
            CREATE POLICY user_isolation ON contact_channels
                USING (contact_id IN (
                    SELECT contact_id FROM contacts
                    WHERE user_id = current_setting('app.current_user_id')::INTEGER
                ))
                WITH CHECK (contact_id IN (
                    SELECT contact_id FROM contacts
                    WHERE user_id = current_setting('app.current_user_id')::INTEGER
                ));
        END IF;
    END
    $$;
    """,
    # Owner bypass for contact_channels (admin/maintenance access)
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'contact_channels' AND policyname = 'owner_full_access'
        ) THEN
            CREATE POLICY owner_full_access ON contact_channels
                TO sentinel_owner
                USING (TRUE)
                WITH CHECK (TRUE);
        END IF;
    END
    $$;
    """,
])

# Bootstrap user and contact — placeholder values only.
# Real contact details should be configured via the /api/contacts endpoints
# or environment/secrets, NOT hardcoded here.
_BOOTSTRAP_USER_SQL = """
INSERT INTO users (user_id, display_name, role, trust_level) VALUES (1, 'Admin', 'owner', 4)
ON CONFLICT (user_id) DO UPDATE SET role = 'owner', trust_level = 4
WHERE users.role IS DISTINCT FROM 'owner' OR users.trust_level IS DISTINCT FROM 4;
"""

_BOOTSTRAP_CONTACT_SQL = """
INSERT INTO contacts (user_id, display_name, linked_user_id, is_user)
VALUES (1, 'Admin', 1, TRUE)
ON CONFLICT (user_id, display_name) DO NOTHING;
"""

# Channel entries for user 1's self-contact (inserted after contact exists).
# These are placeholder identifiers — replace with real values via the
# /api/contacts/{id}/channels endpoints after deployment.
_BOOTSTRAP_CHANNELS_SQL = [
    """
    INSERT INTO contact_channels (contact_id, channel, identifier)
    VALUES (
        (SELECT contact_id FROM contacts WHERE user_id = 1 AND display_name = 'Admin'),
        'signal', '00000000-0000-0000-0000-000000000000'
    ) ON CONFLICT (channel, identifier) DO NOTHING;
    """,
    """
    INSERT INTO contact_channels (contact_id, channel, identifier, is_default)
    VALUES (
        (SELECT contact_id FROM contacts WHERE user_id = 1 AND display_name = 'Admin'),
        'signal_phone', '+440000000000', FALSE
    ) ON CONFLICT (channel, identifier) DO NOTHING;
    """,
    """
    INSERT INTO contact_channels (contact_id, channel, identifier)
    VALUES (
        (SELECT contact_id FROM contacts WHERE user_id = 1 AND display_name = 'Admin'),
        'telegram', '0000000000'
    ) ON CONFLICT (channel, identifier) DO NOTHING;
    """,
    """
    INSERT INTO contact_channels (contact_id, channel, identifier)
    VALUES (
        (SELECT contact_id FROM contacts WHERE user_id = 1 AND display_name = 'Admin'),
        'email', 'admin@example.com'
    ) ON CONFLICT (channel, identifier) DO NOTHING;
    """,
]

# Sentinel system contact — owned by user 1 for RLS, is_system=TRUE prevents deletion
_BOOTSTRAP_SENTINEL_CONTACT_SQL = """
INSERT INTO contacts (user_id, display_name, is_system, is_user)
VALUES (1, 'Sentinel', TRUE, FALSE)
ON CONFLICT (user_id, display_name) DO UPDATE SET is_system = TRUE;
"""

# Tables that need user_id migrated from TEXT DEFAULT 'default' to INT DEFAULT 1
_USER_ID_MIGRATION_TABLES = [
    "sessions",
    "memory_chunks",
    "routines",
    "webhooks",
    "audit_log",
    "episodic_records",
    "provenance",
    "approvals",
    "conversation_turns",
    "file_provenance",
    "routine_executions",
]


async def _bootstrap_user(conn: Any) -> None:
    """Seed user 1 with self-contact, Sentinel system contact, and placeholder channels.

    Must run after users/contacts/contact_channels tables exist but before
    ALTER statements that add FK constraints pointing to users(user_id).
    Idempotent — uses ON CONFLICT throughout.
    """
    # Migrate existing DBs: add new columns if missing
    for col, defn in [
        ("role", "TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('owner','admin','user','pending'))"),
        ("trust_level", "INTEGER CHECK (trust_level BETWEEN 0 AND 4)"),
        ("sessions_invalidated_at", "TIMESTAMPTZ"),
    ]:
        await conn.execute(
            f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {defn}"  # noqa: S608
        )
    await conn.execute(
        "ALTER TABLE contacts ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT FALSE"
    )
    # Drop DEFAULT 1 from all user_id columns (fail-closed for multi-user)
    for table in _USER_ID_MIGRATION_TABLES:
        col_default = await conn.fetchval(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = $1 AND column_name = 'user_id'",
            table,
        )
        if col_default == "1":
            await conn.execute(
                f"ALTER TABLE {table} ALTER COLUMN user_id DROP DEFAULT"  # noqa: S608
            )
            logger.info("Dropped DEFAULT 1 from %s.user_id", table)
    # Also drop DEFAULT 1 from episodic child tables
    for table in ("episodic_file_index", "episodic_facts"):
        col_default = await conn.fetchval(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = $1 AND column_name = 'user_id'",
            table,
        )
        if col_default == "1":
            await conn.execute(
                f"ALTER TABLE {table} ALTER COLUMN user_id DROP DEFAULT"  # noqa: S608
            )
            logger.info("Dropped DEFAULT 1 from %s.user_id", table)

    await conn.execute(_BOOTSTRAP_USER_SQL)
    await conn.execute(_BOOTSTRAP_CONTACT_SQL)
    for sql in _BOOTSTRAP_CHANNELS_SQL:
        await conn.execute(sql)
    await conn.execute(_BOOTSTRAP_SENTINEL_CONTACT_SQL)
    logger.info("Bootstrap user 1 + Sentinel system contact seeded")


async def _migrate_user_id_columns(conn: Any) -> None:
    """Migrate user_id columns from TEXT DEFAULT 'default' to INT DEFAULT 1.

    Idempotent — checks column type before altering (skips if already integer).
    Converts existing 'default' string values to 1 before type change.
    """
    for table in _USER_ID_MIGRATION_TABLES:
        # Check current column type (skip if already integer)
        col_type = await conn.fetchval(
            """
            SELECT data_type FROM information_schema.columns
            WHERE table_name = $1 AND column_name = 'user_id'
            """,
            table,
        )
        if col_type is None:
            logger.warning("Table %s has no user_id column — skipping", table)
            continue
        if col_type == "integer":
            continue

        # Convert 'default' string values to '1' before type cast
        await conn.execute(
            f"UPDATE {table} SET user_id = '1' WHERE user_id = 'default'"  # noqa: S608
        )
        # Drop TEXT default before type change (PG can't auto-cast 'default' to int)
        await conn.execute(
            f"ALTER TABLE {table} ALTER COLUMN user_id DROP DEFAULT"  # noqa: S608
        )
        # Change column type from TEXT to INT with DEFAULT 1
        await conn.execute(
            f"ALTER TABLE {table} ALTER COLUMN user_id TYPE INTEGER USING user_id::integer"  # noqa: S608
        )
        # No DEFAULT — force explicit user_id on every INSERT (fail-closed)
        # Add FK constraint (idempotent — ON CONFLICT not available for constraints,
        # so we check if constraint already exists)
        constraint_name = f"fk_{table}_user_id"
        exists = await conn.fetchval(
            """
            SELECT 1 FROM information_schema.table_constraints
            WHERE table_name = $1 AND constraint_name = $2
            """,
            table,
            constraint_name,
        )
        if not exists:
            await conn.execute(
                f"ALTER TABLE {table} ADD CONSTRAINT {constraint_name} "  # noqa: S608
                f"FOREIGN KEY (user_id) REFERENCES users(user_id)"
            )
        logger.info("Migrated %s.user_id TEXT → INT", table)


async def create_pg_schema(conn: Any) -> None:
    """Create all PostgreSQL tables, indexes, and extensions.

    Idempotent — safe to call on every startup (uses IF NOT EXISTS everywhere).
    Called with a connection from the asyncpg pool.
    """
    async with conn.transaction():
        # 1. Extensions (vector must exist before tables that use vector(768))
        for sql in _EXTENSIONS:
            await conn.execute(sql)

        # 2. Tables with no FK dependencies
        for sql in _TABLES_NO_FK:
            await conn.execute(sql)

        # 3. Tables with FK dependencies (order matters)
        for sql in _TABLES_FK:
            await conn.execute(sql)

        # 4. Bootstrap user 1 (must exist before FK migration)
        await _bootstrap_user(conn)

        # 5. Migrate user_id columns TEXT → INT (idempotent)
        await _migrate_user_id_columns(conn)

        # 5b. Add user_id to child tables that predate the column (idempotent)
        for table in ("episodic_file_index", "episodic_facts"):
            col_exists = await conn.fetchval(
                """
                SELECT 1 FROM information_schema.columns
                WHERE table_name = $1 AND column_name = 'user_id'
                """,
                table,
            )
            if not col_exists:
                await conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN user_id INTEGER NOT NULL "  # noqa: S608
                    f"REFERENCES users(user_id)"
                )
                logger.info("Added user_id column to %s", table)

        # 6. GIN indexes for tsvector full-text search
        for sql in _FTS_INDEXES:
            await conn.execute(sql)

        # 7. HNSW index for pgvector
        for sql in _VECTOR_INDEXES:
            await conn.execute(sql)

        # 8. All other indexes
        for sql in _OTHER_INDEXES:
            await conn.execute(sql)

        # 9. Triggers (must run after tables exist)
        for sql in _TRIGGERS:
            await conn.execute(sql)

        # 10. Role setup (ownership + grants — must run as superuser/owner)
        for sql in _ROLE_SETUP:
            await conn.execute(sql)

        # 11. Row-Level Security policies
        for sql in _RLS_POLICIES:
            await conn.execute(sql)

    logger.info("PostgreSQL schema created/verified (18 tables, %d indexes)",
                len(_FTS_INDEXES) + len(_VECTOR_INDEXES) + len(_OTHER_INDEXES))


def get_all_sql_statements() -> list[str]:
    """Return all SQL statements for testing/inspection.

    Not used at runtime — provided for test introspection of the schema.
    """
    return (
        _EXTENSIONS
        + _TABLES_NO_FK
        + _TABLES_FK
        + _FTS_INDEXES
        + _VECTOR_INDEXES
        + _OTHER_INDEXES
        + _TRIGGERS
    )
