"""Tests for sentinel.core.pg_schema — schema SQL validation.

No real PostgreSQL instance in unit tests. These verify the SQL statements
are well-formed and contain the expected structures. Integration tests
against a real database come in Phase 5.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.pg_schema import (
    _BOOTSTRAP_CHANNELS_SQL,
    _BOOTSTRAP_CONTACT_SQL,
    _BOOTSTRAP_USER_SQL,
    _RLS_DIRECT_TABLES,
    _RLS_POLICIES,
    _ROLE_SETUP,
    _TRIGGERS,
    _USER_ID_MIGRATION_TABLES,
    _bootstrap_user,
    _migrate_user_id_columns,
    create_pg_schema,
    get_all_sql_statements,
)


class TestPgSchemaImportable:
    """Verify the module is importable and callable."""

    def test_create_pg_schema_is_async_callable(self):
        import asyncio
        assert asyncio.iscoroutinefunction(create_pg_schema)

    def test_get_all_sql_statements_returns_list(self):
        stmts = get_all_sql_statements()
        assert isinstance(stmts, list)
        assert len(stmts) > 0


class TestPgSchemaTableCoverage:
    """Verify all 13 tables are present in the schema."""

    EXPECTED_TABLES = [
        "sessions",
        "conversation_turns",
        "provenance",
        "file_provenance",
        "approvals",
        "memory_chunks",
        "routines",
        "routine_executions",
        "webhooks",
        "audit_log",
        "episodic_records",
        "episodic_file_index",
        "episodic_facts",
    ]

    @pytest.fixture
    def all_sql(self):
        return "\n".join(get_all_sql_statements())

    @pytest.mark.parametrize("table", EXPECTED_TABLES)
    def test_table_exists(self, all_sql, table):
        assert table in all_sql, f"Table {table!r} not found in schema SQL"


class TestPgSchemaIdempotency:
    """Verify IF NOT EXISTS is used everywhere for idempotent startup."""

    @pytest.fixture
    def all_sql(self):
        return "\n".join(get_all_sql_statements())

    def test_all_create_table_use_if_not_exists(self, all_sql):
        import re
        creates = re.findall(r"CREATE TABLE\b[^;]+", all_sql, re.IGNORECASE)
        for stmt in creates:
            assert "IF NOT EXISTS" in stmt.upper(), (
                f"CREATE TABLE without IF NOT EXISTS: {stmt[:80]}..."
            )

    def test_all_create_index_use_if_not_exists(self, all_sql):
        import re
        creates = re.findall(r"CREATE INDEX\b[^;]+", all_sql, re.IGNORECASE)
        for stmt in creates:
            assert "IF NOT EXISTS" in stmt.upper(), (
                f"CREATE INDEX without IF NOT EXISTS: {stmt[:80]}..."
            )

    def test_all_create_extension_use_if_not_exists(self, all_sql):
        import re
        creates = re.findall(r"CREATE EXTENSION\b[^;]+", all_sql, re.IGNORECASE)
        for stmt in creates:
            assert "IF NOT EXISTS" in stmt.upper(), (
                f"CREATE EXTENSION without IF NOT EXISTS: {stmt[:80]}..."
            )


class TestPgSchemaTsvector:
    """Verify tsvector generated columns and GIN indexes."""

    @pytest.fixture
    def all_sql(self):
        return "\n".join(get_all_sql_statements())

    def test_memory_chunks_has_generated_tsvector(self, all_sql):
        assert "search_vector" in all_sql
        assert "GENERATED ALWAYS AS" in all_sql
        assert "to_tsvector('english'" in all_sql

    def test_memory_chunks_has_gin_index(self, all_sql):
        assert "idx_memory_chunks_fts" in all_sql
        assert "USING GIN (search_vector)" in all_sql

    def test_episodic_facts_has_generated_tsvector(self, all_sql):
        # Both memory_chunks and episodic_facts have search_vector
        import re
        tsvector_tables = re.findall(
            r"CREATE TABLE IF NOT EXISTS (\w+)[^;]*?search_vector\s+tsvector\s+GENERATED",
            all_sql,
            re.DOTALL | re.IGNORECASE,
        )
        assert "memory_chunks" in tsvector_tables
        assert "episodic_facts" in tsvector_tables

    def test_episodic_facts_has_gin_index(self, all_sql):
        assert "idx_episodic_facts_fts" in all_sql

    def test_tsvector_uses_weighted_fields(self, all_sql):
        assert "setweight(" in all_sql
        assert "'A'" in all_sql
        assert "'B'" in all_sql


class TestPgSchemaPgvector:
    """Verify pgvector extension, vector column, and HNSW index."""

    @pytest.fixture
    def all_sql(self):
        return "\n".join(get_all_sql_statements())

    def test_vector_extension_created(self, all_sql):
        assert "CREATE EXTENSION IF NOT EXISTS vector" in all_sql

    def test_memory_chunks_has_vector_column(self, all_sql):
        assert "vector(768)" in all_sql

    def test_hnsw_index_exists(self, all_sql):
        assert "idx_memory_chunks_embedding" in all_sql
        assert "USING hnsw" in all_sql
        assert "vector_cosine_ops" in all_sql

    def test_hnsw_index_parameters(self, all_sql):
        assert "m = 16" in all_sql
        assert "ef_construction = 64" in all_sql


class TestPgSchemaForeignKeys:
    """Verify FK relationships are defined."""

    @pytest.fixture
    def all_sql(self):
        return "\n".join(get_all_sql_statements())

    def test_conversation_turns_references_sessions(self, all_sql):
        assert "REFERENCES sessions(session_id)" in all_sql

    def test_file_provenance_references_provenance(self, all_sql):
        assert "REFERENCES provenance(data_id)" in all_sql

    def test_routine_executions_references_routines(self, all_sql):
        assert "REFERENCES routines(routine_id)" in all_sql

    def test_episodic_file_index_references_episodic_records(self, all_sql):
        assert "REFERENCES episodic_records(record_id)" in all_sql

    def test_episodic_facts_references_episodic_records(self, all_sql):
        # episodic_facts also references episodic_records
        import re
        refs = re.findall(
            r"CREATE TABLE IF NOT EXISTS (\w+)[^;]*?REFERENCES episodic_records",
            all_sql,
            re.DOTALL | re.IGNORECASE,
        )
        assert "episodic_file_index" in refs
        assert "episodic_facts" in refs

    def test_cascade_deletes(self, all_sql):
        assert all_sql.count("ON DELETE CASCADE") >= 4


class TestPgSchemaColumnTypes:
    """Verify PostgreSQL-specific column types are used correctly."""

    @pytest.fixture
    def all_sql(self):
        return "\n".join(get_all_sql_statements())

    def test_uses_timestamptz(self, all_sql):
        assert "TIMESTAMPTZ" in all_sql

    def test_uses_jsonb(self, all_sql):
        assert "JSONB" in all_sql

    def test_uses_double_precision(self, all_sql):
        assert "DOUBLE PRECISION" in all_sql

    def test_uses_boolean(self, all_sql):
        assert "BOOLEAN" in all_sql

    def test_uses_generated_identity(self, all_sql):
        assert "GENERATED ALWAYS AS IDENTITY" in all_sql

    def test_no_sqlite_types(self, all_sql):
        # Should not contain SQLite-specific constructs
        assert "AUTOINCREMENT" not in all_sql.upper()
        assert "strftime" not in all_sql


class TestPgSchemaStatementOrder:
    """Verify extensions come before tables, no-FK before FK tables."""

    def test_vector_extension_before_vector_column(self):
        stmts = get_all_sql_statements()
        ext_idx = next(i for i, s in enumerate(stmts) if "CREATE EXTENSION" in s)
        vec_idx = next(i for i, s in enumerate(stmts) if "vector(768)" in s)
        assert ext_idx < vec_idx, "vector extension must be created before vector column"

    def test_sessions_before_conversation_turns(self):
        stmts = get_all_sql_statements()
        sessions_idx = next(i for i, s in enumerate(stmts) if "CREATE TABLE" in s and "sessions" in s and "session_id      TEXT PRIMARY KEY" in s)
        turns_idx = next(i for i, s in enumerate(stmts) if "conversation_turns" in s and "CREATE TABLE" in s)
        assert sessions_idx < turns_idx

    def test_provenance_before_file_provenance(self):
        stmts = get_all_sql_statements()
        prov_idx = next(i for i, s in enumerate(stmts) if "CREATE TABLE" in s and "provenance" in s and "file_provenance" not in s)
        fprov_idx = next(i for i, s in enumerate(stmts) if "file_provenance" in s and "CREATE TABLE" in s)
        assert prov_idx < fprov_idx

    def test_routines_before_routine_executions(self):
        stmts = get_all_sql_statements()
        rtn_idx = next(i for i, s in enumerate(stmts) if "CREATE TABLE" in s and "routines" in s and "routine_executions" not in s)
        exec_idx = next(i for i, s in enumerate(stmts) if "routine_executions" in s and "CREATE TABLE" in s)
        assert rtn_idx < exec_idx

    def test_episodic_records_before_episodic_file_index(self):
        stmts = get_all_sql_statements()
        rec_idx = next(i for i, s in enumerate(stmts) if "CREATE TABLE" in s and "episodic_records" in s and "episodic_file" not in s and "episodic_facts" not in s)
        fidx_idx = next(i for i, s in enumerate(stmts) if "episodic_file_index" in s and "CREATE TABLE" in s)
        assert rec_idx < fidx_idx

    def test_users_before_all_referencing_tables(self):
        """users table must be created first — all other tables reference it."""
        stmts = get_all_sql_statements()
        users_idx = next(i for i, s in enumerate(stmts) if "CREATE TABLE" in s and "users" in s and "SERIAL PRIMARY KEY" in s)
        # Every table with REFERENCES users(user_id) must come after
        for i, s in enumerate(stmts):
            if "CREATE TABLE" in s and "REFERENCES users(user_id)" in s:
                assert users_idx < i, f"users table must be created before statement at index {i}"


class TestUserIdColumnTypes:
    """Verify all CREATE TABLE definitions use INTEGER for user_id (not TEXT)."""

    TABLES_WITH_USER_ID = [
        "sessions", "memory_chunks", "routines", "webhooks", "audit_log",
        "episodic_records", "provenance", "approvals", "confirmations",
        "conversation_turns", "file_provenance", "routine_executions",
    ]

    def test_no_text_user_id_in_create_table(self):
        """No CREATE TABLE should define user_id as TEXT."""
        import re
        all_sql = "\n".join(get_all_sql_statements())
        # Find any CREATE TABLE with user_id TEXT
        matches = re.findall(
            r"CREATE TABLE.*?;",
            all_sql,
            re.DOTALL | re.IGNORECASE,
        )
        for stmt in matches:
            if "user_id" in stmt:
                assert "user_id         TEXT" not in stmt and "user_id TEXT" not in stmt, (
                    f"Found TEXT user_id in CREATE TABLE: {stmt[:80]}..."
                )

    @pytest.mark.parametrize("table", TABLES_WITH_USER_ID)
    def test_user_id_is_integer(self, table):
        """Each table with user_id should define it as INTEGER."""
        import re
        all_sql = "\n".join(get_all_sql_statements())
        # Find the CREATE TABLE for this specific table
        pattern = rf"CREATE TABLE IF NOT EXISTS {table}\s*\(.*?\);"
        match = re.search(pattern, all_sql, re.DOTALL | re.IGNORECASE)
        assert match is not None, f"CREATE TABLE for {table} not found"
        assert "INTEGER" in match.group() and "user_id" in match.group(), (
            f"{table} user_id should be INTEGER"
        )


# ── Phase 3: Bootstrap & user_id migration ─────────────────────────


class TestBootstrapSql:
    """Verify bootstrap SQL seeds user 1 with correct data."""

    def test_bootstrap_user_sql_inserts_admin(self):
        assert "Admin" in _BOOTSTRAP_USER_SQL
        assert "ON CONFLICT" in _BOOTSTRAP_USER_SQL
        assert "DO UPDATE" in _BOOTSTRAP_USER_SQL  # Upserts role/trust_level

    def test_bootstrap_contact_sql_creates_self_contact(self):
        assert "linked_user_id" in _BOOTSTRAP_CONTACT_SQL
        assert "is_user" in _BOOTSTRAP_CONTACT_SQL
        assert "TRUE" in _BOOTSTRAP_CONTACT_SQL
        assert "ON CONFLICT" in _BOOTSTRAP_CONTACT_SQL

    def test_bootstrap_channels_has_four_entries(self):
        assert len(_BOOTSTRAP_CHANNELS_SQL) == 4

    def test_bootstrap_channels_cover_all_types(self):
        all_sql = "\n".join(_BOOTSTRAP_CHANNELS_SQL)
        assert "'signal'" in all_sql
        assert "'signal_phone'" in all_sql
        assert "'telegram'" in all_sql
        assert "'email'" in all_sql

    def test_bootstrap_channels_have_placeholder_identifiers(self):
        all_sql = "\n".join(_BOOTSTRAP_CHANNELS_SQL)
        assert "00000000-0000-0000-0000-000000000000" in all_sql
        assert "+440000000000" in all_sql
        assert "0000000000" in all_sql
        assert "admin@example.com" in all_sql

    def test_bootstrap_channels_are_idempotent(self):
        for sql in _BOOTSTRAP_CHANNELS_SQL:
            assert "ON CONFLICT" in sql
            assert "DO NOTHING" in sql


class TestBootstrapFunction:
    """Verify _bootstrap_user calls the right SQL statements."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        return conn

    def test_bootstrap_user_executes_all_statements(self, mock_conn):
        # fetchval returns None (no default to drop) to skip ALTER DROP DEFAULT
        mock_conn.fetchval = AsyncMock(return_value=None)
        asyncio.get_event_loop().run_until_complete(_bootstrap_user(mock_conn))
        # 3 ALTER ADD COLUMN + 1 ALTER contacts + 1 user + 1 contact + 4 channels + 1 sentinel = 11
        # Plus fetchval calls for default-drop checks (but no execute for those since default is None)
        assert mock_conn.execute.call_count >= 7  # At minimum: 4 ALTERs + user + contact + sentinel

    def test_bootstrap_user_seeds_sentinel_contact(self, mock_conn):
        mock_conn.fetchval = AsyncMock(return_value=None)
        asyncio.get_event_loop().run_until_complete(_bootstrap_user(mock_conn))
        calls = [c.args[0] for c in mock_conn.execute.call_args_list]
        # Should include Sentinel system contact bootstrap
        sentinel_calls = [c for c in calls if "Sentinel" in c]
        assert len(sentinel_calls) == 1


class TestUserIdMigrationTables:
    """Verify the migration table list is correct and complete."""

    EXPECTED_TABLES = [
        "sessions", "memory_chunks", "routines", "webhooks", "audit_log",
        "episodic_records", "provenance", "approvals", "conversation_turns",
        "file_provenance", "routine_executions",
    ]

    def test_all_11_tables_listed(self):
        assert len(_USER_ID_MIGRATION_TABLES) == 11

    @pytest.mark.parametrize("table", EXPECTED_TABLES)
    def test_table_in_migration_list(self, table):
        assert table in _USER_ID_MIGRATION_TABLES

    def test_no_episodic_child_tables(self):
        assert "episodic_file_index" not in _USER_ID_MIGRATION_TABLES
        assert "episodic_facts" not in _USER_ID_MIGRATION_TABLES


class TestMigrateUserIdColumns:
    """Verify _migrate_user_id_columns skips already-migrated tables."""

    def test_skips_integer_columns(self):
        conn = AsyncMock()
        # Simulate all tables already migrated (data_type = 'integer')
        conn.fetchval = AsyncMock(return_value="integer")
        asyncio.get_event_loop().run_until_complete(_migrate_user_id_columns(conn))
        # Only fetchval calls (type checks), no execute calls (no ALTERs)
        assert conn.fetchval.call_count == 11
        conn.execute.assert_not_called()


class TestProtocolUserIdTypes:
    """Verify protocol interfaces use int user_id after Phase 3."""

    def test_memory_store_protocol_user_id_is_int(self):
        from sentinel.core.store_protocols import MemoryStoreProtocol
        import inspect
        sig = inspect.signature(MemoryStoreProtocol.store)
        assert sig.parameters["user_id"].default == 1
        assert sig.parameters["user_id"].annotation == "int"

    def test_routine_store_protocol_user_id_is_int(self):
        from sentinel.core.store_protocols import RoutineStoreProtocol
        import inspect
        sig = inspect.signature(RoutineStoreProtocol.create)
        assert sig.parameters["user_id"].default == 1
        assert sig.parameters["user_id"].annotation == "int"

    def test_episodic_store_protocol_user_id_is_int(self):
        from sentinel.core.store_protocols import EpisodicStoreProtocol
        import inspect
        sig = inspect.signature(EpisodicStoreProtocol.create)
        assert sig.parameters["user_id"].default == 1
        assert sig.parameters["user_id"].annotation == "int"

    def test_webhook_registry_protocol_user_id_is_int(self):
        from sentinel.core.store_protocols import WebhookRegistryProtocol
        import inspect
        sig = inspect.signature(WebhookRegistryProtocol.register)
        assert sig.parameters["user_id"].default == 1
        assert sig.parameters["user_id"].annotation == "int"


# ── Immutable audit log trigger ─────────────────────────────────────


class TestAuditLogImmutableTrigger:
    """Verify the immutable audit log trigger SQL is present in schema."""

    def test_trigger_function_defined(self):
        all_sql = "\n".join(_TRIGGERS)
        assert "prevent_audit_modification" in all_sql
        assert "RAISE EXCEPTION" in all_sql

    def test_trigger_attached_to_audit_log(self):
        all_sql = "\n".join(_TRIGGERS)
        assert "trg_immutable_audit" in all_sql
        assert "audit_log" in all_sql

    def test_trigger_fires_on_update_and_delete(self):
        all_sql = "\n".join(_TRIGGERS)
        assert "BEFORE UPDATE OR DELETE" in all_sql

    def test_trigger_is_per_row(self):
        all_sql = "\n".join(_TRIGGERS)
        assert "FOR EACH ROW" in all_sql

    def test_trigger_is_idempotent(self):
        """Trigger uses DROP IF EXISTS + CREATE for robust idempotency."""
        all_sql = "\n".join(_TRIGGERS)
        assert "DROP TRIGGER IF EXISTS trg_immutable_audit ON audit_log" in all_sql
        assert "CREATE TRIGGER trg_immutable_audit" in all_sql

    def test_trigger_function_uses_create_or_replace(self):
        all_sql = "\n".join(_TRIGGERS)
        assert "CREATE OR REPLACE FUNCTION" in all_sql

    def test_triggers_included_in_get_all_sql_statements(self):
        all_stmts = get_all_sql_statements()
        trigger_sql = "\n".join(all_stmts)
        assert "trg_immutable_audit" in trigger_sql

    def test_trigger_after_audit_log_table_in_statement_order(self):
        """Trigger must come after audit_log table creation."""
        stmts = get_all_sql_statements()
        audit_idx = next(
            i for i, s in enumerate(stmts)
            if "CREATE TABLE" in s and "audit_log" in s
        )
        trigger_idx = next(
            i for i, s in enumerate(stmts)
            if "trg_immutable_audit" in s
        )
        assert audit_idx < trigger_idx, (
            "Trigger must be created after audit_log table"
        )


# ── Role setup (T1: RLS & Role Separation) ──────────────────────────


class TestRoleSetupSql:
    """Verify role setup SQL is included in schema creation."""

    def test_role_setup_has_minimum_statements(self):
        assert len(_ROLE_SETUP) >= 4

    def test_role_setup_references_both_roles(self):
        combined = " ".join(_ROLE_SETUP)
        assert "sentinel_owner" in combined
        assert "sentinel_app" in combined

    def test_role_setup_includes_revoke(self):
        """audit_log immutability — REVOKE UPDATE/DELETE from sentinel_app."""
        combined = " ".join(_ROLE_SETUP)
        assert "REVOKE" in combined
        assert "audit_log" in combined

    def test_role_setup_includes_default_privileges(self):
        """Future tables auto-grant DML to sentinel_app."""
        combined = " ".join(_ROLE_SETUP)
        assert "DEFAULT PRIVILEGES" in combined

    def test_role_setup_transfers_ownership(self):
        combined = " ".join(_ROLE_SETUP)
        assert "OWNER TO sentinel_owner" in combined


# ── RLS policies (T2: RLS & Role Separation) ────────────────────────


class TestRlsPolicies:
    """Verify RLS policies cover all user-scoped tables."""

    def test_rls_enable_count(self):
        """16 direct tables + audit_log + contact_channels + users = 19 ENABLE statements."""
        combined = " ".join(_RLS_POLICIES)
        assert combined.count("ENABLE ROW LEVEL SECURITY") == 20

    def test_rls_force_count(self):
        """19 FORCE ROW LEVEL SECURITY statements (even owner obeys policies)."""
        combined = " ".join(_RLS_POLICIES)
        assert combined.count("FORCE ROW LEVEL SECURITY") == 20

    def test_all_direct_tables_covered(self):
        combined = " ".join(_RLS_POLICIES)
        for tbl in _RLS_DIRECT_TABLES:
            assert f"ALTER TABLE {tbl} ENABLE" in combined, (
                f"Missing ENABLE RLS for {tbl}"
            )

    def test_audit_log_special_case(self):
        """audit_log is admin-read-only: legacy policies dropped, app_insert_only added."""
        combined = " ".join(_RLS_POLICIES)
        # Legacy policies are dropped (strings exist as DROP statements)
        assert "DROP POLICY IF EXISTS user_isolation_select ON audit_log" in combined
        assert "DROP POLICY IF EXISTS user_isolation_insert ON audit_log" in combined
        # New app_insert_only policy for sentinel_app
        assert "app_insert_only" in combined
        assert "FOR INSERT" in combined

    def test_contact_channels_fk_join(self):
        """contact_channels scoped via subquery on contacts.user_id."""
        combined = " ".join(_RLS_POLICIES)
        assert "ALTER TABLE contact_channels ENABLE" in combined
        assert "SELECT contact_id FROM contacts" in combined

    def test_direct_tables_list_has_17_entries(self):
        assert len(_RLS_DIRECT_TABLES) == 17

    def test_policies_use_session_variable(self):
        """All policies reference app.current_user_id."""
        combined = " ".join(_RLS_POLICIES)
        assert "current_setting('app.current_user_id')" in combined


# ── Schema hardening (B5 database security) ──────────────────────────


class TestSchemaHardening:
    """F19 + Priority 6: Missing index and plpgsql revoke."""

    def test_memory_chunks_user_id_index_exists(self):
        """idx_memory_chunks_user_id should be in the index list."""
        from sentinel.core.pg_schema import _OTHER_INDEXES
        index_sql = " ".join(_OTHER_INDEXES)
        assert "idx_memory_chunks_user_id" in index_sql

    def test_plpgsql_revoked_in_entrypoint(self):
        """REVOKE ALL ON LANGUAGE plpgsql FROM PUBLIC should be in entrypoint.sh."""
        from pathlib import Path
        entrypoint = Path(__file__).parent.parent / "container" / "entrypoint.sh"
        content = entrypoint.read_text()
        assert "REVOKE ALL ON LANGUAGE plpgsql FROM PUBLIC" in content
