"""Tests for ProvenanceStore — PostgreSQL backend for provenance tracking.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.security.provenance import ProvenanceStore, _row_to_tagged


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
    return ProvenanceStore(pool)


def _make_provenance_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "data_id": "d-123",
        "content": "test content",
        "source": "user",
        "trust_level": "trusted",
        "originated_from": "",
        "parent_ids": [],
        "created_at": now,
    }
    defaults.update(overrides)
    return defaults


# ── create_tagged_data ────────────────────────────────────────


class TestCreateTaggedData:
    @pytest.mark.asyncio
    async def test_creates_entry(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"
        # get_tagged_data won't be called (no parent_ids)

        tagged = await store.create_tagged_data(
            content="hello",
            source=DataSource.USER,
            trust_level=TrustLevel.TRUSTED,
        )

        assert tagged.content == "hello"
        assert tagged.trust_level == TrustLevel.TRUSTED
        assert tagged.source == DataSource.USER
        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO provenance" in str(c)]
        assert len(insert_calls) == 1

    @pytest.mark.asyncio
    async def test_inherits_untrusted_from_parent(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"
        # Mock get_tagged_data to return an untrusted parent
        conn.fetchrow.return_value = _make_provenance_row(trust_level="untrusted")

        tagged = await store.create_tagged_data(
            content="derived",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=["parent-1"],
        )

        assert tagged.trust_level == TrustLevel.UNTRUSTED

    @pytest.mark.asyncio
    async def test_untrusted_when_parent_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"
        conn.fetchrow.return_value = None  # parent not found

        tagged = await store.create_tagged_data(
            content="orphan",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=["missing-parent"],
        )

        assert tagged.trust_level == TrustLevel.UNTRUSTED


# ── get_tagged_data ──────────────────────────────────────────


class TestGetTaggedData:
    @pytest.mark.asyncio
    async def test_returns_data(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_provenance_row()

        result = await store.get_tagged_data("d-123")

        assert result is not None
        assert result.id == "d-123"
        assert result.trust_level == TrustLevel.TRUSTED

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get_tagged_data("nonexistent")

        assert result is None


# ── update_content ────────────────────────────────────────────


class TestUpdateContent:
    @pytest.mark.asyncio
    async def test_returns_true_on_update(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        result = await store.update_content("d-123", "new content")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 0"

        result = await store.update_content("nonexistent", "new")

        assert result is False


# ── get_provenance_chain ─────────────────────────────────────


class TestGetProvenanceChain:
    @pytest.mark.asyncio
    async def test_returns_chain(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            _make_provenance_row(data_id="d-1"),
            _make_provenance_row(data_id="d-2", parent_ids=["d-1"]),
        ]

        chain = await store.get_provenance_chain("d-2")

        assert len(chain) == 2
        # Verify the recursive CTE query uses jsonb_array_elements_text
        sql = conn.fetch.call_args[0][0]
        assert "jsonb_array_elements_text" in sql
        assert "CROSS JOIN LATERAL" in sql

    @pytest.mark.asyncio
    async def test_empty_chain(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        chain = await store.get_provenance_chain("nonexistent")

        assert chain == []


# ── is_trust_safe_for_execution ──────────────────────────────


class TestIsTrustSafe:
    @pytest.mark.asyncio
    async def test_safe_when_all_trusted(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            _make_provenance_row(data_id="d-1"),
        ]

        result = await store.is_trust_safe_for_execution("d-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_unsafe_when_untrusted_in_chain(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            _make_provenance_row(data_id="d-1"),
            _make_provenance_row(data_id="d-2", trust_level="untrusted"),
        ]

        result = await store.is_trust_safe_for_execution("d-2")

        assert result is False


# ── record_file_write / get_file_writer ──────────────────────


class TestFileProvenance:
    @pytest.mark.asyncio
    async def test_record_file_write_uses_upsert(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        await store.record_file_write("/workspace/test.py", "d-123")

        sql = conn.execute.call_args[0][0]
        assert "ON CONFLICT" in sql
        assert "DO UPDATE SET" in sql
        assert "content_sha256" in sql

    @pytest.mark.asyncio
    async def test_get_file_writer(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = {
            "writer_data_id": "d-123",
            "content_sha256": "abc123hash",
        }

        result = await store.get_file_writer("/workspace/test.py")

        assert result == ("d-123", "abc123hash")

    @pytest.mark.asyncio
    async def test_get_file_writer_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get_file_writer("/nonexistent")

        assert result is None


# ── cleanup_old ──────────────────────────────────────────────


class TestCleanupOld:
    @pytest.mark.asyncio
    async def test_deletes_old_entries(self, store, mock_pool):
        _, conn = mock_pool
        # asyncpg transaction() is sync callable → async context manager
        tx = MagicMock()
        tx.__aenter__ = AsyncMock(return_value=None)
        tx.__aexit__ = AsyncMock(return_value=False)
        conn.transaction = MagicMock(return_value=tx)
        conn.execute.return_value = "DELETE 5"

        result = await store.cleanup_old(days=7)

        assert result == 5
        # Should have called delete on file_provenance and provenance
        execute_calls = [c for c in conn.execute.call_args_list]
        assert len(execute_calls) >= 2

    @pytest.mark.asyncio
    async def test_returns_zero_when_nothing_old(self, store, mock_pool):
        _, conn = mock_pool
        tx = MagicMock()
        tx.__aenter__ = AsyncMock(return_value=None)
        tx.__aexit__ = AsyncMock(return_value=False)
        conn.transaction = MagicMock(return_value=tx)
        conn.execute.return_value = "DELETE 0"

        result = await store.cleanup_old(days=7)

        assert result == 0


# ── reset_store ──────────────────────────────────────────────


class TestResetStore:
    @pytest.mark.asyncio
    async def test_clears_both_tables(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        await store.reset_store()

        calls = [str(c) for c in conn.execute.call_args_list]
        assert any("DELETE FROM file_provenance" in c for c in calls)
        assert any("DELETE FROM provenance" in c for c in calls)


# ── _row_to_tagged ───────────────────────────────────────────


class TestRowToTagged:
    def test_converts_row(self):
        row = _make_provenance_row()
        tagged = _row_to_tagged(row)

        assert isinstance(tagged, TaggedData)
        assert tagged.id == "d-123"
        assert tagged.trust_level == TrustLevel.TRUSTED
        assert tagged.source == DataSource.USER

    def test_handles_string_parent_ids(self):
        row = _make_provenance_row(parent_ids='["p-1", "p-2"]')
        tagged = _row_to_tagged(row)

        assert tagged.derived_from == ["p-1", "p-2"]

    def test_handles_none_parent_ids(self):
        row = _make_provenance_row(parent_ids=None)
        tagged = _row_to_tagged(row)

        assert tagged.derived_from == []

    def test_handles_list_parent_ids(self):
        row = _make_provenance_row(parent_ids=["p-1"])
        tagged = _row_to_tagged(row)

        assert tagged.derived_from == ["p-1"]

    def test_non_datetime_created_at_falls_back_to_now(self):
        """When created_at is not a datetime, falls back to datetime.now()."""
        row = _make_provenance_row(created_at="2026-03-05T12:00:00Z")
        tagged = _row_to_tagged(row)

        # Should still produce a TaggedData (falls back to datetime.now())
        assert isinstance(tagged, TaggedData)
        assert isinstance(tagged.timestamp, datetime)


# ── create_tagged_data (multi-parent trust) ──────────────────


class TestCreateTaggedDataMultiParent:
    @pytest.mark.asyncio
    async def test_all_parents_trusted_preserves_trust(self, store, mock_pool):
        """Two trusted parents → result is TRUSTED."""
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"
        # Both parents return trusted
        conn.fetchrow.side_effect = [
            _make_provenance_row(data_id="p-1", trust_level="trusted"),
            _make_provenance_row(data_id="p-2", trust_level="trusted"),
        ]

        tagged = await store.create_tagged_data(
            content="derived",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=["p-1", "p-2"],
        )

        assert tagged.trust_level == TrustLevel.TRUSTED

    @pytest.mark.asyncio
    async def test_second_parent_untrusted_breaks_trust(self, store, mock_pool):
        """Two parents, second untrusted → early-break, result is UNTRUSTED."""
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"
        # First parent trusted, second untrusted
        conn.fetchrow.side_effect = [
            _make_provenance_row(data_id="p-1", trust_level="trusted"),
            _make_provenance_row(data_id="p-2", trust_level="untrusted"),
        ]

        tagged = await store.create_tagged_data(
            content="derived",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=["p-1", "p-2"],
        )

        assert tagged.trust_level == TrustLevel.UNTRUSTED


# ── get_provenance_chain (max_depth) ─────────────────────────


class TestGetProvenanceChainEdgeCases:
    @pytest.mark.asyncio
    async def test_custom_max_depth(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_provenance_row()]

        await store.get_provenance_chain("d-1", max_depth=5)

        args = conn.fetch.call_args[0]
        assert args[2] == 5  # $2 param is max_depth


# ── is_trust_safe_for_execution (empty chain) ────────────────


class TestIsTrustSafeEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_chain_returns_false(self, store, mock_pool):
        """Empty chain = unknown data_id = untrusted (unknown ≠ safe)."""
        _, conn = mock_pool
        conn.fetch.return_value = []  # empty chain

        result = await store.is_trust_safe_for_execution("nonexistent")

        assert result is False


# ── get_file_writer user_id isolation ────────────────────────


class TestGetFileWriterUserIsolation:
    @pytest.mark.asyncio
    async def test_get_file_writer_filters_by_user_id(self, store, mock_pool):
        """get_file_writer with user_id should add AND user_id = $2."""
        _, conn = mock_pool
        conn.fetchrow.return_value = {
            "writer_data_id": "d-user1",
            "content_sha256": "hash-user1",
        }

        result = await store.get_file_writer("/workspace/test.py", user_id=1)

        assert result == ("d-user1", "hash-user1")
        sql = conn.fetchrow.call_args[0][0]
        assert "user_id = $2" in sql
        # Verify user_id parameter was passed
        assert conn.fetchrow.call_args[0][2] == 1

    @pytest.mark.asyncio
    async def test_get_file_writer_no_user_id_omits_filter(self, store, mock_pool):
        """get_file_writer without user_id should not filter by user."""
        _, conn = mock_pool
        conn.fetchrow.return_value = {
            "writer_data_id": "d-any",
            "content_sha256": "hash-any",
        }

        result = await store.get_file_writer("/workspace/test.py")

        assert result == ("d-any", "hash-any")
        sql = conn.fetchrow.call_args[0][0]
        assert "user_id" not in sql


# ── get_provenance_chain user_id isolation ───────────────────


class TestGetProvenanceChainUserIsolation:
    @pytest.mark.asyncio
    async def test_get_provenance_chain_filters_by_user_id(self, store, mock_pool):
        """Provenance chain with user_id should add WHERE p.user_id = $3."""
        _, conn = mock_pool
        conn.fetch.return_value = [
            _make_provenance_row(data_id="d-1"),
        ]

        chain = await store.get_provenance_chain("d-1", user_id=1)

        assert len(chain) == 1
        sql = conn.fetch.call_args[0][0]
        # user_id filter on the final SELECT, not inside the CTE
        assert "p.user_id = $3" in sql
        # CTE should still walk across all users (no user_id in recursive part)
        cte_part = sql.split("SELECT DISTINCT")[0]
        assert "user_id" not in cte_part
        # Verify user_id parameter was passed
        assert conn.fetch.call_args[0][3] == 1

    @pytest.mark.asyncio
    async def test_get_provenance_chain_no_user_id_omits_filter(self, store, mock_pool):
        """Provenance chain without user_id should not filter by user."""
        _, conn = mock_pool
        conn.fetch.return_value = [
            _make_provenance_row(data_id="d-1"),
        ]

        chain = await store.get_provenance_chain("d-1")

        assert len(chain) == 1
        sql = conn.fetch.call_args[0][0]
        assert "user_id = $3" not in sql


# ── file_provenance composite PK (file_path, user_id) ────────


class TestFileProvenanceMultiUserPK:
    """Verify composite PK (file_path, user_id) allows per-user provenance."""

    @pytest.fixture
    def store(self, mock_pool):
        pool, _ = mock_pool
        return ProvenanceStore(pool=pool)

    @pytest.mark.asyncio
    async def test_two_users_same_path_separate_records(self, store, mock_pool):
        """Two users writing the same path should create separate provenance records."""
        _, mock_conn = mock_pool
        await store.record_file_write("/workspace/index.html", "data-1", content="<h1>A</h1>", user_id=1)
        insert_call = mock_conn.execute.call_args
        sql = insert_call[0][0]
        assert "ON CONFLICT (file_path, user_id)" in sql, (
            "ON CONFLICT must use composite key (file_path, user_id)"
        )

    @pytest.mark.asyncio
    async def test_get_file_writer_user_scoped(self, store, mock_pool):
        """get_file_writer with user_id should filter by user."""
        _, mock_conn = mock_pool
        mock_conn.fetchrow.return_value = {"writer_data_id": "d1", "content_sha256": "abc"}
        result = await store.get_file_writer("/workspace/index.html", user_id=1)
        sql = mock_conn.fetchrow.call_args[0][0]
        assert "user_id" in sql
        assert result == ("d1", "abc")


# ── cleanup_old user_id scoping ──────────────────────────────


class TestCleanupOldUserScoped:
    """Verify cleanup_old can be scoped to a user."""

    @pytest.fixture
    def store(self, mock_pool):
        pool, _ = mock_pool
        return ProvenanceStore(pool=pool)

    @pytest.mark.asyncio
    async def test_cleanup_with_user_id_filters(self, store, mock_pool):
        _, mock_conn = mock_pool
        # asyncpg transaction() is sync callable → async context manager
        tx = MagicMock()
        tx.__aenter__ = AsyncMock(return_value=None)
        tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=tx)
        mock_conn.execute.return_value = "DELETE 5"

        await store.cleanup_old(days=7, user_id=1)

        calls = mock_conn.execute.call_args_list
        for call in calls:
            sql = call[0][0]
            if "DELETE" in sql:
                assert "user_id" in sql, f"DELETE should filter by user_id: {sql}"

    @pytest.mark.asyncio
    async def test_cleanup_without_user_id_is_global(self, store, mock_pool):
        _, mock_conn = mock_pool
        tx = MagicMock()
        tx.__aenter__ = AsyncMock(return_value=None)
        tx.__aexit__ = AsyncMock(return_value=False)
        mock_conn.transaction = MagicMock(return_value=tx)
        mock_conn.execute.return_value = "DELETE 3"

        await store.cleanup_old(days=7)

        calls = mock_conn.execute.call_args_list
        for call in calls:
            sql = call[0][0]
            if "DELETE" in sql:
                assert "user_id =" not in sql, f"Global cleanup should not filter by user_id: {sql}"
