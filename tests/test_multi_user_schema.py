"""Tests for multi-user schema changes (Phase 0).

Validates schema definitions, bootstrap SQL, role guard, PinVerifier
serialisation, and trust level resolution — all without a running database.
"""

import re

import pytest

from sentinel.api.auth import PinVerifier
from sentinel.api.role_guard import ROLE_LEVELS, require_role
from sentinel.core.context import resolve_trust_level
from sentinel.core.pg_schema import (
    _BOOTSTRAP_SENTINEL_CONTACT_SQL,
    _BOOTSTRAP_USER_SQL,
    _TABLES_FK,
    _TABLES_NO_FK,
    get_all_sql_statements,
)


# ── Task 0.1: Role column ─────────────────────────────────────────


class TestRoleColumn:
    """Verify users table has a role column with correct CHECK constraint."""

    def test_users_table_has_role_column(self):
        all_sql = "\n".join(get_all_sql_statements())
        users_match = re.search(
            r"CREATE TABLE IF NOT EXISTS users\s*\(.*?\);",
            all_sql, re.DOTALL | re.IGNORECASE,
        )
        assert users_match, "users table CREATE not found"
        users_sql = users_match.group()
        assert "role" in users_sql

    def test_role_has_check_constraint(self):
        all_sql = "\n".join(get_all_sql_statements())
        assert "owner" in all_sql
        assert "admin" in all_sql
        assert "pending" in all_sql
        assert "CHECK (role IN" in all_sql

    def test_role_defaults_to_user(self):
        all_sql = "\n".join(get_all_sql_statements())
        assert "DEFAULT 'user'" in all_sql

    def test_bootstrap_user_is_owner(self):
        assert "'owner'" in _BOOTSTRAP_USER_SQL
        assert "role" in _BOOTSTRAP_USER_SQL


# ── Task 0.2: Trust level column ──────────────────────────────────


class TestTrustLevelColumn:
    """Verify users table has a nullable trust_level column."""

    def test_users_table_has_trust_level_column(self):
        all_sql = "\n".join(get_all_sql_statements())
        users_match = re.search(
            r"CREATE TABLE IF NOT EXISTS users\s*\(.*?\);",
            all_sql, re.DOTALL | re.IGNORECASE,
        )
        assert users_match
        assert "trust_level" in users_match.group()

    def test_trust_level_has_range_check(self):
        all_sql = "\n".join(get_all_sql_statements())
        assert "trust_level BETWEEN 0 AND 4" in all_sql

    def test_bootstrap_user_has_trust_level_4(self):
        assert "trust_level" in _BOOTSTRAP_USER_SQL
        assert "4" in _BOOTSTRAP_USER_SQL


# ── Task 0.3: is_system contact ───────────────────────────────────


class TestIsSystemContact:
    """Verify contacts table has is_system flag and Sentinel system contact."""

    def test_contacts_table_has_is_system(self):
        all_sql = "\n".join(get_all_sql_statements())
        contacts_match = re.search(
            r"CREATE TABLE IF NOT EXISTS contacts\s*\(.*?\);",
            all_sql, re.DOTALL | re.IGNORECASE,
        )
        assert contacts_match
        assert "is_system" in contacts_match.group()

    def test_is_system_defaults_to_false(self):
        all_sql = "\n".join(get_all_sql_statements())
        assert "is_system       BOOLEAN NOT NULL DEFAULT FALSE" in all_sql

    def test_sentinel_contact_bootstrap_exists(self):
        assert "Sentinel" in _BOOTSTRAP_SENTINEL_CONTACT_SQL
        assert "is_system" in _BOOTSTRAP_SENTINEL_CONTACT_SQL
        assert "TRUE" in _BOOTSTRAP_SENTINEL_CONTACT_SQL

    def test_sentinel_contact_is_idempotent(self):
        assert "ON CONFLICT" in _BOOTSTRAP_SENTINEL_CONTACT_SQL


# ── Task 0.4: No DEFAULT 1 on user_id ─────────────────────────────


class TestNoDefaultOneOnUserId:
    """No table should default user_id to 1 — omitting user_id must fail."""

    TABLES_WITH_USER_ID = [
        "sessions", "memory_chunks", "routines", "webhooks", "audit_log",
        "episodic_records", "provenance", "approvals", "confirmations",
        "conversation_turns", "file_provenance", "routine_executions",
        "episodic_file_index", "episodic_facts",
    ]

    @pytest.mark.parametrize("table", TABLES_WITH_USER_ID)
    def test_no_default_1_in_create_table(self, table):
        all_sql = "\n".join(get_all_sql_statements())
        pattern = rf"CREATE TABLE IF NOT EXISTS {table}\s*\(.*?\);"
        match = re.search(pattern, all_sql, re.DOTALL | re.IGNORECASE)
        assert match, f"CREATE TABLE for {table} not found"
        stmt = match.group()
        # user_id should not have DEFAULT 1
        user_id_line = [
            line for line in stmt.split("\n")
            if "user_id" in line and "INTEGER" in line
        ]
        for line in user_id_line:
            assert "DEFAULT 1" not in line, (
                f"{table} still has DEFAULT 1 on user_id: {line.strip()}"
            )


# ── Task 0.5: Trust level resolution ──────────────────────────────


class TestResolveTrustLevel:
    """Per-user trust_level overrides system default."""

    def test_explicit_overrides_system(self):
        assert resolve_trust_level(user_trust_level=4, system_default=2) == 4

    def test_none_falls_back_to_system(self):
        assert resolve_trust_level(user_trust_level=None, system_default=2) == 2

    def test_zero_is_valid_override(self):
        assert resolve_trust_level(user_trust_level=0, system_default=4) == 0


# ── Task 0.5: ContactStore.get_user_trust_level ───────────────────


class TestContactStoreUserMethods:
    """Test in-memory trust_level and role accessors."""

    @pytest.fixture
    def store(self):
        from sentinel.contacts.store import ContactStore
        s = ContactStore(pool=None)
        s._users[1] = {
            "user_id": 1, "display_name": "Admin", "pin_hash": None,
            "is_active": True, "role": "owner", "trust_level": 4,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        s._users[2] = {
            "user_id": 2, "display_name": "Bob", "pin_hash": None,
            "is_active": True, "role": "user", "trust_level": None,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        return s

    @pytest.mark.asyncio
    async def test_get_user_trust_level_explicit(self, store):
        assert await store.get_user_trust_level(1) == 4

    @pytest.mark.asyncio
    async def test_get_user_trust_level_none(self, store):
        assert await store.get_user_trust_level(2) is None

    @pytest.mark.asyncio
    async def test_get_user_trust_level_missing(self, store):
        assert await store.get_user_trust_level(999) is None

    @pytest.mark.asyncio
    async def test_get_user_role_owner(self, store):
        assert await store.get_user_role(1) == "owner"

    @pytest.mark.asyncio
    async def test_get_user_role_user(self, store):
        assert await store.get_user_role(2) == "user"

    @pytest.mark.asyncio
    async def test_get_user_role_missing(self, store):
        assert await store.get_user_role(999) is None


# ── Task 0.6: Role guard ──────────────────────────────────────────


class TestRoleGuard:
    """Verify role hierarchy and enforcement."""

    def test_role_hierarchy(self):
        assert ROLE_LEVELS["owner"] > ROLE_LEVELS["admin"]
        assert ROLE_LEVELS["admin"] > ROLE_LEVELS["user"]
        assert ROLE_LEVELS["user"] > ROLE_LEVELS["pending"]

    @pytest.mark.asyncio
    async def test_owner_passes_admin_check(self):
        from unittest.mock import AsyncMock
        from sentinel.core.context import current_user_id
        token = current_user_id.set(1)
        try:
            store = AsyncMock()
            store.get_user_role.return_value = "owner"
            # Should not raise
            await require_role("admin", store)
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_user_fails_admin_check(self):
        from unittest.mock import AsyncMock
        from fastapi import HTTPException
        from sentinel.core.context import current_user_id
        token = current_user_id.set(2)
        try:
            store = AsyncMock()
            store.get_user_role.return_value = "user"
            with pytest.raises(HTTPException) as exc_info:
                await require_role("admin", store)
            assert exc_info.value.status_code == 403
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_pending_fails_user_check(self):
        from unittest.mock import AsyncMock
        from fastapi import HTTPException
        from sentinel.core.context import current_user_id
        token = current_user_id.set(3)
        try:
            store = AsyncMock()
            store.get_user_role.return_value = "pending"
            with pytest.raises(HTTPException) as exc_info:
                await require_role("user", store)
            assert exc_info.value.status_code == 403
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_unknown_user_fails(self):
        from unittest.mock import AsyncMock
        from fastapi import HTTPException
        from sentinel.core.context import current_user_id
        token = current_user_id.set(999)
        try:
            store = AsyncMock()
            store.get_user_role.return_value = None
            with pytest.raises(HTTPException) as exc_info:
                await require_role("user", store)
            assert exc_info.value.status_code == 403
        finally:
            current_user_id.reset(token)


# ── Task 0.7: PinVerifier serialisation ───────────────────────────


class TestPinVerifierSerialisation:
    """Verify PinVerifier can round-trip through to_stored()/from_stored()."""

    def test_to_stored_format(self):
        v = PinVerifier("1234")
        stored = v.to_stored()
        # Format: hex(salt):hex(hash)
        parts = stored.split(":")
        assert len(parts) == 2
        # Both parts should be valid hex
        bytes.fromhex(parts[0])
        bytes.fromhex(parts[1])

    def test_from_stored_verifies_correctly(self):
        v = PinVerifier("secure_pin")
        stored = v.to_stored()
        v2 = PinVerifier.from_stored(stored)
        assert v2.verify("secure_pin")
        assert not v2.verify("wrong_pin")

    def test_stored_is_not_plaintext(self):
        v = PinVerifier("1234")
        stored = v.to_stored()
        assert "1234" not in stored

    def test_round_trip_preserves_hash(self):
        v = PinVerifier("test")
        stored = v.to_stored()
        v2 = PinVerifier.from_stored(stored)
        # Internal state should match
        assert v._hash == v2._hash
        assert v._salt == v2._salt


# ── Task 0.4: Bootstrap user updated SQL ──────────────────────────


class TestBootstrapUserUpdated:
    """Verify bootstrap SQL uses ON CONFLICT DO UPDATE for role/trust_level."""

    def test_bootstrap_user_upserts_role(self):
        assert "DO UPDATE SET role = 'owner'" in _BOOTSTRAP_USER_SQL

    def test_bootstrap_user_upserts_trust_level(self):
        assert "trust_level = 4" in _BOOTSTRAP_USER_SQL

    def test_bootstrap_user_is_conditional(self):
        # Only update if values differ (IS DISTINCT FROM)
        assert "IS DISTINCT FROM" in _BOOTSTRAP_USER_SQL


# ── Sessions invalidated_at column ────────────────────────────────


class TestSessionsInvalidatedAt:
    """Verify users table has sessions_invalidated_at for JWT revocation."""

    def test_users_table_has_sessions_invalidated_at(self):
        all_sql = "\n".join(get_all_sql_statements())
        users_match = re.search(
            r"CREATE TABLE IF NOT EXISTS users\s*\(.*?\);",
            all_sql, re.DOTALL | re.IGNORECASE,
        )
        assert users_match
        assert "sessions_invalidated_at" in users_match.group()
