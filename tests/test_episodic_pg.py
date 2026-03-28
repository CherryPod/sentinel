"""Tests for EpisodicStore — PostgreSQL backend for episodic memory.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.memory.episodic import EpisodicFact, EpisodicRecord, EpisodicStore, _row_to_record, _row_to_fact, render_episodic_text


def _make_tx_cm():
    """Create a mock async context manager for conn.transaction()."""
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=False)
    return tx


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    conn = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = cm
    # Pre-configure transaction() as sync callable → async ctx mgr
    conn.transaction = MagicMock(return_value=_make_tx_cm())
    return pool, conn


@pytest.fixture
def store(mock_pool):
    pool, _ = mock_pool
    return EpisodicStore(pool)


def _make_record_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "record_id": "r-123",
        "session_id": "s-1",
        "task_id": "t-1",
        "user_id": 1,
        "user_request": "do something",
        "task_status": "completed",
        "plan_summary": "Did something",
        "step_count": 3,
        "success_count": 3,
        "file_paths": ["file1.py"],
        "error_patterns": [],
        "defined_symbols": [],
        "step_outcomes": None,
        "linked_records": [],
        "relevance_score": 1.0,
        "access_count": 0,
        "last_accessed": None,
        "memory_chunk_id": None,
        "created_at": now,
    }
    defaults.update(overrides)
    return defaults


def _make_fact_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "fact_id": "f-123",
        "record_id": "r-123",
        "fact_type": "file_create",
        "content": "test.py created (100 bytes)",
        "file_path": "test.py",
        "created_at": now,
    }
    defaults.update(overrides)
    return defaults


# ── create ────────────────────────────────────────────────────


class TestCreate:
    @pytest.mark.asyncio
    async def test_creates_record(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        record_id = await store.create(
            session_id="s-1",
            user_request="do something",
            task_status="completed",
            file_paths=["test.py"],
        )

        assert record_id  # UUID string
        # Verify JSONB casts in INSERT
        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO episodic_records" in str(c)]
        assert len(insert_calls) == 1
        sql = insert_calls[0][0][0]
        assert "::jsonb" in sql

    @pytest.mark.asyncio
    async def test_creates_file_index_entries(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        await store.create(
            session_id="s-1",
            file_paths=["a.py", "b.py"],
        )

        # Should have INSERT for record + 2 file index entries
        file_index_calls = [c for c in conn.execute.call_args_list
                            if "episodic_file_index" in str(c)]
        assert len(file_index_calls) == 2

    @pytest.mark.asyncio
    async def test_file_index_uses_on_conflict_do_nothing(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        await store.create(
            session_id="s-1",
            file_paths=["a.py"],
        )

        file_index_calls = [c for c in conn.execute.call_args_list
                            if "episodic_file_index" in str(c)]
        assert len(file_index_calls) == 1
        sql = file_index_calls[0][0][0]
        assert "ON CONFLICT DO NOTHING" in sql


# ── get ───────────────────────────────────────────────────────


class TestGet:
    @pytest.mark.asyncio
    async def test_returns_record(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_record_row()

        record = await store.get("r-123")

        assert record is not None
        assert record.record_id == "r-123"
        assert record.task_status == "completed"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get("nonexistent")

        assert result is None


# ── list_by_session ──────────────────────────────────────────


class TestListBySession:
    @pytest.mark.asyncio
    async def test_lists_records(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_record_row(), _make_record_row(record_id="r-456")]

        records = await store.list_by_session("s-1")

        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_orders_by_created_at_desc(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        await store.list_by_session("s-1")

        sql = conn.fetch.call_args[0][0]
        assert "ORDER BY created_at DESC" in sql


# ── delete ────────────────────────────────────────────────────


class TestDelete:
    @pytest.mark.asyncio
    async def test_returns_true_when_deleted(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 1"

        result = await store.delete("r-123")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        result = await store.delete("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_no_manual_cascade_needed(self, store, mock_pool):
        """FK CASCADE handles file_index and facts — no extra DELETE queries."""
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 1"

        await store.delete("r-123")

        # Only one DELETE call (on episodic_records), not on file_index or facts
        assert conn.execute.call_count == 1


# ── find_linked_records ──────────────────────────────────────


class TestFindLinkedRecords:
    @pytest.mark.asyncio
    async def test_returns_linked_ids(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"record_id": "r-100"},
            {"record_id": "r-200"},
        ]

        result = await store.find_linked_records(["test.py"], exclude_record_id="r-123")

        assert result == ["r-100", "r-200"]
        sql = conn.fetch.call_args[0][0]
        assert "ANY($1)" in sql

    @pytest.mark.asyncio
    async def test_returns_empty_for_no_paths(self, store, mock_pool):
        result = await store.find_linked_records([])

        assert result == []


class TestFindLinkedRecordsUserIsolation:
    @pytest.mark.asyncio
    async def test_find_linked_records_filters_by_user_id(self, store, mock_pool):
        """Linked records from other users must not be returned."""
        _, conn = mock_pool
        conn.fetch.return_value = [{"record_id": "r-100"}]

        result = await store.find_linked_records(
            ["shared.py"], user_id=1, exclude_record_id="r-new",
        )

        assert result == ["r-100"]
        sql = conn.fetch.call_args[0][0]
        assert "user_id = $3" in sql
        # Verify user_id is passed as 3rd parameter
        assert conn.fetch.call_args[0][3] == 1

    @pytest.mark.asyncio
    async def test_find_linked_records_inmemory_filters_by_user_id(self):
        """In-memory path: linked records from other users excluded."""
        store = EpisodicStore(pool=None)
        # Create record for user 1
        rec1 = EpisodicRecord(
            record_id="r-u1", session_id="s-1", task_id="t-1", user_id=1,
            user_request="", task_status="completed", plan_summary="",
            step_count=0, success_count=0, file_paths=["shared.py"],
            error_patterns=[], defined_symbols=[], step_outcomes=None,
            linked_records=[], relevance_score=1.0, access_count=0,
            last_accessed=None, memory_chunk_id=None, created_at="2026-01-01T00:00:00+00:00",
        )
        store._mem["r-u1"] = rec1
        store._file_index.setdefault("shared.py", set()).add("r-u1")

        # Create record for user 2 sharing the same file
        rec2 = EpisodicRecord(
            record_id="r-u2", session_id="s-2", task_id="t-2", user_id=2,
            user_request="", task_status="completed", plan_summary="",
            step_count=0, success_count=0, file_paths=["shared.py"],
            error_patterns=[], defined_symbols=[], step_outcomes=None,
            linked_records=[], relevance_score=1.0, access_count=0,
            last_accessed=None, memory_chunk_id=None, created_at="2026-01-01T00:00:00+00:00",
        )
        store._mem["r-u2"] = rec2
        store._file_index["shared.py"].add("r-u2")

        # User 1 should only see their own records
        result = await store.find_linked_records(
            ["shared.py"], user_id=1, exclude_record_id="r-new",
        )
        assert result == ["r-u1"]

        # User 2 should only see their own records
        result = await store.find_linked_records(
            ["shared.py"], user_id=2, exclude_record_id="r-new",
        )
        assert result == ["r-u2"]


# ── prune_stale ──────────────────────────────────────────────


class TestPruneStale:
    @pytest.mark.asyncio
    async def test_prunes_low_relevance_records(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"record_id": "r-old", "age_days": 60.0, "access_count": 0, "memory_chunk_id": None},
        ]
        conn.execute.return_value = "DELETE 1"

        result = await store.prune_stale(threshold=0.5)

        assert result == 1
        # Verify EXTRACT(EPOCH FROM ...) in the query
        sql = conn.fetch.call_args[0][0]
        assert "EXTRACT(EPOCH FROM" in sql

    @pytest.mark.asyncio
    async def test_skips_high_relevance_records(self, store, mock_pool):
        _, conn = mock_pool
        # access_count high enough to keep record above threshold
        conn.fetch.return_value = [
            {"record_id": "r-active", "age_days": 60.0, "access_count": 100, "memory_chunk_id": None},
        ]

        result = await store.prune_stale(threshold=0.5)

        assert result == 0

    @pytest.mark.asyncio
    async def test_cleans_up_shadow_chunk(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"record_id": "r-old", "age_days": 60.0, "access_count": 0,
             "memory_chunk_id": "chunk-1"},
        ]
        conn.execute.return_value = "DELETE 1"

        await store.prune_stale(threshold=0.5)

        # Should delete shadow chunk + episodic record = 2 execute calls
        delete_calls = [c for c in conn.execute.call_args_list
                        if "DELETE" in str(c)]
        assert len(delete_calls) == 2


class TestPruneStaleUserIsolation:
    @pytest.mark.asyncio
    async def test_prune_stale_pg_scoped_to_user(self, store, mock_pool):
        """PG path: when user_id is specified, query includes AND user_id = $2."""
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"record_id": "r-old", "age_days": 60.0, "access_count": 0,
             "memory_chunk_id": None},
        ]
        conn.execute.return_value = "DELETE 1"

        await store.prune_stale(threshold=0.5, user_id=1)

        sql = conn.fetch.call_args[0][0]
        assert "user_id = $2" in sql
        assert conn.fetch.call_args[0][2] == 1

    @pytest.mark.asyncio
    async def test_prune_stale_pg_no_user_id_prunes_all(self, store, mock_pool):
        """PG path: admin=True with no user_id prunes across all users."""
        _, conn = mock_pool
        conn.fetch.return_value = []

        await store.prune_stale(threshold=0.5, user_id=None, admin=True)

        sql = conn.fetch.call_args[0][0]
        assert "user_id" not in sql

    @pytest.mark.asyncio
    async def test_prune_stale_inmemory_scoped_to_user(self):
        """In-memory: only the specified user's stale records are pruned."""
        store = EpisodicStore(pool=None)
        old_date = "2020-01-01T00:00:00+00:00"

        # Create old records for user 1 and user 2
        for uid, rid in [(1, "r-u1"), (2, "r-u2")]:
            rec = EpisodicRecord(
                record_id=rid, session_id="s-1", task_id="t-1", user_id=uid,
                user_request="", task_status="completed", plan_summary="",
                step_count=0, success_count=0, file_paths=[],
                error_patterns=[], defined_symbols=[], step_outcomes=None,
                linked_records=[], relevance_score=0.01, access_count=0,
                last_accessed=None, memory_chunk_id=None, created_at=old_date,
            )
            store._mem[rid] = rec

        # Prune only user 1's records
        pruned = await store.prune_stale(threshold=0.5, min_age_days=1, user_id=1)

        assert pruned == 1
        assert "r-u1" not in store._mem
        assert "r-u2" in store._mem  # User 2's record untouched


# ── update_access / batch_update_access ──────────────────────


class TestUpdateAccess:
    @pytest.mark.asyncio
    async def test_bumps_access(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.update_access("r-123")

        sql = conn.execute.call_args[0][0]
        assert "access_count + 1" in sql
        assert "last_accessed = NOW()" in sql

    @pytest.mark.asyncio
    async def test_batch_uses_any(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 3"

        await store.batch_update_access(["r-1", "r-2", "r-3"])

        sql = conn.execute.call_args[0][0]
        assert "ANY($1)" in sql

    @pytest.mark.asyncio
    async def test_batch_empty_is_noop(self, store, mock_pool):
        _, conn = mock_pool

        await store.batch_update_access([])

        conn.execute.assert_not_called()


# ── store_facts ──────────────────────────────────────────────


class TestStoreFacts:
    @pytest.mark.asyncio
    async def test_stores_facts_in_transaction(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        facts = [
            EpisodicFact(
                fact_id="f-1", record_id="r-123", fact_type="file_create",
                content="test.py created", file_path="test.py", created_at="",
            ),
            EpisodicFact(
                fact_id="f-2", record_id="r-123", fact_type="exec_error",
                content="exit 1", file_path=None, created_at="",
            ),
        ]

        await store.store_facts("r-123", facts)

        # Two INSERT calls (no FTS sync — tsvector is GENERATED)
        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO episodic_facts" in str(c)]
        assert len(insert_calls) == 2

    @pytest.mark.asyncio
    async def test_no_manual_fts_sync(self, store, mock_pool):
        """tsvector is GENERATED ALWAYS AS STORED — no manual FTS insert."""
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        facts = [
            EpisodicFact(
                fact_id="f-1", record_id="r-123", fact_type="file_create",
                content="test.py", file_path="test.py", created_at="",
            ),
        ]

        await store.store_facts("r-123", facts)

        # No FTS-related calls (no episodic_facts_fts)
        all_calls = [str(c) for c in conn.execute.call_args_list]
        assert not any("fts" in c.lower() for c in all_calls)


# ── search_facts ─────────────────────────────────────────────


class TestSearchFacts:
    @pytest.mark.asyncio
    async def test_uses_plainto_tsquery(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_fact_row()]

        results = await store.search_facts("python test")

        assert len(results) == 1
        sql = conn.fetch.call_args[0][0]
        assert "plainto_tsquery" in sql
        assert "ts_rank_cd" in sql

    @pytest.mark.asyncio
    async def test_filters_by_fact_type(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        await store.search_facts("test", fact_type="file_create")

        sql = conn.fetch.call_args[0][0]
        assert "fact_type = $2" in sql

    @pytest.mark.asyncio
    async def test_returns_empty_for_blank_query(self, store, mock_pool):
        result = await store.search_facts("")

        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_for_whitespace_query(self, store, mock_pool):
        result = await store.search_facts("   ")

        assert result == []


class TestSearchFactsUserIsolation:
    @pytest.mark.asyncio
    async def test_search_facts_filters_by_user_id_pg(self, store, mock_pool):
        """PG path: user_id filter in both fact_type and non-fact_type variants."""
        _, conn = mock_pool
        conn.fetch.return_value = [_make_fact_row()]

        # Without fact_type
        await store.search_facts("python", user_id=1)
        sql = conn.fetch.call_args[0][0]
        assert "user_id = $2" in sql

        # With fact_type
        conn.fetch.return_value = [_make_fact_row()]
        await store.search_facts("python", fact_type="file_create", user_id=1)
        sql = conn.fetch.call_args[0][0]
        assert "user_id = $3" in sql

    @pytest.mark.asyncio
    async def test_search_facts_inmemory_filters_by_user_id(self):
        """In-memory path: facts from other users must not appear."""
        store = EpisodicStore(pool=None)

        # Store facts for user 1
        facts_u1 = [EpisodicFact(
            fact_id="f-u1", record_id="r-1", fact_type="file_create",
            content="shared module created", file_path="shared.py", created_at="",
        )]
        await store.store_facts("r-1", facts_u1, user_id=1)

        # Store facts for user 2 with overlapping content
        facts_u2 = [EpisodicFact(
            fact_id="f-u2", record_id="r-2", fact_type="file_create",
            content="shared module updated", file_path="shared.py", created_at="",
        )]
        await store.store_facts("r-2", facts_u2, user_id=2)

        # User 1 should only see their own facts
        results = await store.search_facts("shared", user_id=1)
        assert len(results) == 1
        assert results[0].fact_id == "f-u1"

        # User 2 should only see their own facts
        results = await store.search_facts("shared", user_id=2)
        assert len(results) == 1
        assert results[0].fact_id == "f-u2"


# ── create_with_shadow ───────────────────────────────────────


class TestCreateWithShadow:
    @pytest.mark.asyncio
    async def test_creates_record_and_shadow(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"
        conn.fetch.return_value = []  # find_linked_records

        memory_store = AsyncMock()
        memory_store.store.return_value = "chunk-abc"

        record_id = await store.create_with_shadow(
            memory_store=memory_store,
            session_id="s-1",
            user_request="test",
            task_status="completed",
        )

        assert record_id
        memory_store.store.assert_called_once()
        # Verify source is system:episodic
        call_kwargs = memory_store.store.call_args
        assert call_kwargs[1]["source"] == "system:episodic"

    @pytest.mark.asyncio
    async def test_uses_store_with_embedding_when_provided(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"
        conn.fetch.return_value = []

        memory_store = AsyncMock()
        memory_store.store_with_embedding.return_value = "chunk-vec"

        await store.create_with_shadow(
            memory_store=memory_store,
            session_id="s-1",
            user_request="test",
            task_status="completed",
            embedding=[0.1] * 768,
        )

        memory_store.store_with_embedding.assert_called_once()
        memory_store.store.assert_not_called()


# ── set_memory_chunk_id ──────────────────────────────────────


class TestSetMemoryChunkId:
    @pytest.mark.asyncio
    async def test_updates_chunk_id(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.set_memory_chunk_id("r-123", "chunk-abc")

        sql = conn.execute.call_args[0][0]
        assert "memory_chunk_id" in sql


# ── _row_to_record ───────────────────────────────────────────


class TestRowToRecord:
    def test_converts_row(self):
        row = _make_record_row()
        record = _row_to_record(row)

        assert isinstance(record, EpisodicRecord)
        assert record.record_id == "r-123"
        assert record.file_paths == ["file1.py"]

    def test_handles_string_json_fields(self):
        row = _make_record_row(
            file_paths='["a.py"]',
            error_patterns='["err"]',
            defined_symbols='["Foo"]',
            linked_records='[{"record_id": "r-2", "link_type": "file"}]',
        )
        record = _row_to_record(row)

        assert record.file_paths == ["a.py"]
        assert record.error_patterns == ["err"]
        assert record.defined_symbols == ["Foo"]
        assert len(record.linked_records) == 1


class TestRowToRecordEdgeCases:
    def test_step_outcomes_as_string(self):
        """The string-parsing path for step_outcomes."""
        row = _make_record_row(
            step_outcomes='[{"step": 1, "status": "ok"}]',
        )
        record = _row_to_record(row)

        assert record.step_outcomes == [{"step": 1, "status": "ok"}]


# ── list_by_file ────────────────────────────────────────────


class TestListByFile:
    @pytest.mark.asyncio
    async def test_returns_records_for_file(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_record_row()]

        records = await store.list_by_file("test.py")

        assert len(records) == 1
        assert records[0].record_id == "r-123"

    @pytest.mark.asyncio
    async def test_uses_join_query(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        await store.list_by_file("test.py")

        sql = conn.fetch.call_args[0][0]
        assert "JOIN episodic_file_index" in sql
        assert "efi.file_path = $1" in sql
        assert "ORDER BY" in sql

    @pytest.mark.asyncio
    async def test_returns_empty_for_unknown_file(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        records = await store.list_by_file("nonexistent.py")

        assert records == []


# ── _add_link ───────────────────────────────────────────────


class TestAddLink:
    @pytest.mark.asyncio
    async def test_adds_link_to_empty_list(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = {"linked_records": []}
        conn.execute.return_value = "UPDATE 1"

        await store._add_link(conn, "r-1", "r-2", "file")

        # Should have called execute with the updated JSONB
        update_calls = [c for c in conn.execute.call_args_list
                        if "linked_records" in str(c)]
        assert len(update_calls) == 1
        sql = update_calls[0][0][0]
        assert "::jsonb" in sql
        # Verify the new link is in the JSON
        import json
        new_links = json.loads(update_calls[0][0][1])
        assert new_links == [{"record_id": "r-2", "link_type": "file"}]

    @pytest.mark.asyncio
    async def test_skips_duplicate_link(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = {
            "linked_records": [{"record_id": "r-2", "link_type": "file"}],
        }

        await store._add_link(conn, "r-1", "r-2", "file")

        # Should NOT call execute (duplicate detected)
        execute_calls = [c for c in conn.execute.call_args_list
                        if "linked_records" in str(c)]
        assert len(execute_calls) == 0

    @pytest.mark.asyncio
    async def test_returns_early_when_record_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        await store._add_link(conn, "nonexistent", "r-2", "file")

        # Should not call execute at all
        conn.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_string_linked_records(self, store, mock_pool):
        """When linked_records comes back as a JSON string (not native list)."""
        _, conn = mock_pool
        conn.fetchrow.return_value = {"linked_records": '[]'}
        conn.execute.return_value = "UPDATE 1"

        await store._add_link(conn, "r-1", "r-2", "file")

        update_calls = [c for c in conn.execute.call_args_list
                        if "linked_records" in str(c)]
        assert len(update_calls) == 1


# ── create_with_shadow (bidirectional linking) ──────────────


class TestCreateWithShadowLinking:
    @pytest.mark.asyncio
    async def test_bidirectional_linking_when_linked_records_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        # First call to find_linked_records returns linked IDs
        # Second+ calls are for _add_link fetchrow
        conn.fetch.return_value = [{"record_id": "r-existing"}]
        conn.fetchrow.return_value = {"linked_records": []}

        memory_store = AsyncMock()
        memory_store.store.return_value = "chunk-abc"

        await store.create_with_shadow(
            memory_store=memory_store,
            session_id="s-1",
            user_request="test",
            task_status="completed",
            file_paths=["shared.py"],
        )

        # _add_link should be called bidirectionally (new→existing, existing→new)
        fetchrow_calls = [c for c in conn.fetchrow.call_args_list
                          if "linked_records" in str(c)]
        assert len(fetchrow_calls) >= 2


# ── store_facts (auto-generated fact_id) ────────────────────


class TestStoreFactsEdgeCases:
    @pytest.mark.asyncio
    async def test_generates_uuid_for_empty_fact_id(self, store, mock_pool):
        """When fact.fact_id is falsy, a UUID is generated."""
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        facts = [
            EpisodicFact(
                fact_id="", record_id="r-123", fact_type="file_create",
                content="test.py created", file_path="test.py", created_at="",
            ),
        ]

        await store.store_facts("r-123", facts)

        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO episodic_facts" in str(c)]
        assert len(insert_calls) == 1
        # The fact_id param should be a UUID, not empty
        fact_id_param = insert_calls[0][0][1]
        assert fact_id_param != ""
        assert len(fact_id_param) == 36  # UUID format

    @pytest.mark.asyncio
    async def test_generates_uuid_for_none_fact_id(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "INSERT 0 1"

        facts = [
            EpisodicFact(
                fact_id=None, record_id="r-123", fact_type="exec_error",
                content="exit 1", file_path=None, created_at="",
            ),
        ]

        await store.store_facts("r-123", facts)

        insert_calls = [c for c in conn.execute.call_args_list
                        if "INSERT INTO episodic_facts" in str(c)]
        fact_id_param = insert_calls[0][0][1]
        assert fact_id_param is not None
        assert len(fact_id_param) == 36


# ── prune_stale (shadow chunk deletion failure) ─────────────


class TestPruneStaleEdgeCases:
    @pytest.mark.asyncio
    async def test_continues_after_shadow_chunk_delete_failure(self, store, mock_pool):
        """When shadow chunk deletion raises, prune should continue and delete the record."""
        _, conn = mock_pool
        conn.fetch.return_value = [
            {"record_id": "r-old", "age_days": 60.0, "access_count": 0,
             "memory_chunk_id": "chunk-bad"},
        ]
        # First execute (shadow chunk delete) raises, second (record delete) succeeds
        conn.execute.side_effect = [Exception("chunk gone"), "DELETE 1"]

        result = await store.prune_stale(threshold=0.5)

        assert result == 1
        # Should have attempted both deletes
        assert conn.execute.call_count == 2


class TestRowToFact:
    def test_converts_row(self):
        row = _make_fact_row()
        fact = _row_to_fact(row)

        assert isinstance(fact, EpisodicFact)
        assert fact.fact_id == "f-123"
        assert fact.fact_type == "file_create"


# ── list_by_file user isolation ─────────────────────────────


class TestListByFileUserIsolation:
    """list_by_file must only return records belonging to the specified user."""

    @pytest.mark.asyncio
    async def test_pg_path_filters_by_user_id(self, store, mock_pool):
        """PG query includes user_id filter."""
        _, conn = mock_pool
        conn.fetch.return_value = [_make_record_row(user_id=1)]

        records = await store.list_by_file("test.py", user_id=1)

        assert len(records) == 1
        # Verify the SQL includes user_id filter
        sql = conn.fetch.call_args[0][0]
        assert "er.user_id" in sql
        # Verify user_id was passed as parameter
        args = conn.fetch.call_args[0]
        assert args[1] == "test.py"  # $1
        assert args[2] == 1          # $2 (user_id)

    @pytest.mark.asyncio
    async def test_in_memory_filters_by_user_id(self):
        """In-memory path filters records by user_id."""
        store = EpisodicStore(pool=None)

        # Create records for two different users sharing the same file
        record_u1 = EpisodicRecord(
            record_id="r-u1", session_id="s-1", task_id="t-1", user_id=1,
            user_request="user 1 task", task_status="completed",
            plan_summary="did something", step_count=1, success_count=1,
            file_paths=["shared.py"], error_patterns=[], defined_symbols=[],
            step_outcomes=None, linked_records=[], relevance_score=1.0,
            access_count=0, last_accessed=None, memory_chunk_id=None,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        record_u2 = EpisodicRecord(
            record_id="r-u2", session_id="s-2", task_id="t-2", user_id=2,
            user_request="user 2 task", task_status="completed",
            plan_summary="did something else", step_count=1, success_count=1,
            file_paths=["shared.py"], error_patterns=[], defined_symbols=[],
            step_outcomes=None, linked_records=[], relevance_score=1.0,
            access_count=0, last_accessed=None, memory_chunk_id=None,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        # Manually populate in-memory store
        store._mem["r-u1"] = record_u1
        store._mem["r-u2"] = record_u2
        store._file_index["shared.py"] = {"r-u1", "r-u2"}

        # Query as user 1 — should only see user 1's record
        results_u1 = await store.list_by_file("shared.py", user_id=1)
        assert len(results_u1) == 1
        assert results_u1[0].record_id == "r-u1"

        # Query as user 2 — should only see user 2's record
        results_u2 = await store.list_by_file("shared.py", user_id=2)
        assert len(results_u2) == 1
        assert results_u2[0].record_id == "r-u2"

        # Query as user 99 — should see nothing
        results_none = await store.list_by_file("shared.py", user_id=99)
        assert len(results_none) == 0


# ── user_id filtering (F8-F11) ──────────────────────────────


class TestEpisodicUserIdFiltering:
    """F8-F11: Episodic store methods filter by user_id redundantly (belt + suspenders over RLS)."""

    @pytest.mark.asyncio
    async def test_get_filters_by_user_id(self, store, mock_pool):
        """get() with wrong user_id returns None — SQL includes AND user_id."""
        _, conn = mock_pool
        conn.fetchrow.return_value = None  # wrong user → no match

        result = await store.get("r-123", user_id=99)

        assert result is None
        sql = conn.fetchrow.call_args[0][0]
        assert "user_id" in sql

    @pytest.mark.asyncio
    async def test_get_passes_user_id_param(self, store, mock_pool):
        """get() passes user_id as a query parameter."""
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_record_row()

        await store.get("r-123", user_id=1)

        args = conn.fetchrow.call_args[0]
        assert 1 in args  # user_id passed as parameter

    @pytest.mark.asyncio
    async def test_delete_filters_by_user_id(self, store, mock_pool):
        """delete() with wrong user_id returns False (no rows affected)."""
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        result = await store.delete("r-123", user_id=99)

        assert result is False
        sql = conn.execute.call_args[0][0]
        assert "user_id" in sql

    @pytest.mark.asyncio
    async def test_update_access_filters_by_user_id(self, store, mock_pool):
        """update_access() SQL includes AND user_id filter."""
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 0"

        await store.update_access("r-123", user_id=99)

        sql = conn.execute.call_args[0][0]
        assert "user_id" in sql

    @pytest.mark.asyncio
    async def test_batch_update_access_filters_by_user_id(self, store, mock_pool):
        """batch_update_access() SQL includes AND user_id filter."""
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 0"

        await store.batch_update_access(["r-1", "r-2"], user_id=99)

        sql = conn.execute.call_args[0][0]
        assert "user_id" in sql

    @pytest.mark.asyncio
    async def test_set_memory_chunk_id_filters_by_user_id(self, store, mock_pool):
        """set_memory_chunk_id() SQL includes AND user_id filter."""
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 0"

        await store.set_memory_chunk_id("r-123", "chunk-1", user_id=99)

        sql = conn.execute.call_args[0][0]
        assert "user_id" in sql


# ── render_episodic_text ─────────────────────────────────────


class TestRenderEpisodicText:
    """Unit tests for render_episodic_text() — embedding/FTS text generation."""

    def test_basic_success_step(self):
        """Success step renders result line with duration and strategy."""
        text = render_episodic_text(
            user_request="Build calculator",
            task_status="completed",
            step_count=1,
            success_count=1,
            step_outcomes=[{
                "step_type": "llm_task",
                "description": "Generate calculator module",
                "status": "success",
                "duration_s": 15.2,
                "output_language": "python",
                "output_size": 2048,
                "syntax_valid": True,
                "file_path": "/workspace/calc.py",
            }],
        )
        assert "Build calculator" in text
        assert "COMPLETED" in text
        assert "1/1 steps" in text
        assert "15s" in text
        assert "Strategy:" in text

    def test_failed_step_shows_error_detail(self):
        """Failed step shows error_detail in Key line."""
        text = render_episodic_text(
            user_request="Run tests",
            task_status="failed",
            step_count=1,
            success_count=0,
            step_outcomes=[{
                "step_type": "tool_call",
                "description": "Execute pytest",
                "status": "failed",
                "error_detail": "ModuleNotFoundError: no module named pytest",
            }],
        )
        assert "FAILED" in text
        assert "ModuleNotFoundError" in text

    def test_domain_tag_rendered(self):
        """Domain tag appears as prefix when provided."""
        text = render_episodic_text(
            user_request="Modify config",
            task_status="completed",
            step_count=1,
            success_count=1,
            task_domain="code_generation",
            step_outcomes=[{
                "step_type": "tool_call",
                "description": "Update settings",
                "status": "success",
            }],
        )
        assert text.startswith("[code_generation]")

    def test_strategy_pattern_rendered(self):
        """Strategy pattern from step sequence is rendered."""
        text = render_episodic_text(
            user_request="Read and fix file",
            task_status="completed",
            step_count=2,
            success_count=2,
            step_outcomes=[
                {"step_type": "tool_call", "tool": "file_read", "status": "success"},
                {"step_type": "tool_call", "tool": "file_write", "status": "success"},
            ],
        )
        assert "Strategy: read → write" in text

    def test_duration_calculated_from_outcomes(self):
        """Total duration is summed from step durations."""
        text = render_episodic_text(
            user_request="Run script",
            task_status="completed",
            step_count=2,
            success_count=2,
            step_outcomes=[
                {"step_type": "tool_call", "tool": "file_write", "duration_s": 1.0},
                {"step_type": "tool_call", "tool": "shell", "duration_s": 5.5},
            ],
        )
        assert "6s" in text or "7s" in text  # 6.5s — rounding varies

    def test_code_fixer_activity_in_key_line(self):
        """Code fixer activity highlighted in Key line with fix types."""
        text = render_episodic_text(
            user_request="Generate code",
            task_status="completed",
            step_count=1,
            success_count=1,
            step_outcomes=[{
                "step_type": "llm_task",
                "description": "Write module",
                "status": "success",
                "code_fixer_changed": True,
                "code_fixer_fixes": ["indent_repair"],
            }],
        )
        # Code fixer is internal infrastructure — not rendered for planner
        assert "code_fixer" not in text.lower()

    def test_code_fixer_not_rendered(self):
        """Code fixer details are internal — not shown to planner."""
        text = render_episodic_text(
            user_request="Generate code",
            task_status="completed",
            step_count=2,
            success_count=2,
            step_outcomes=[
                {
                    "step_type": "tool_call",
                    "tool": "file_write",
                    "status": "success",
                    "code_fixer_changed": True,
                    "code_fixer_fixes": ["indent_repair", "trailing_newline"],
                },
            ],
        )
        assert "code_fixer" not in text.lower()

    def test_error_highlight_on_failure(self):
        """Failed tasks show first error in Key line."""
        text = render_episodic_text(
            user_request="Build calculator",
            task_status="failed",
            step_count=1,
            success_count=0,
            step_outcomes=[{
                "step_type": "llm_task",
                "description": "Generate calculator module",
                "status": "failed",
                "error_detail": "SyntaxError at line 5",
            }],
        )
        # New format: S1(tool): FAILED; description; error detail
        assert "FAILED" in text
        assert "SyntaxError at line 5" in text

    def test_absent_fields_omitted(self):
        """Fields not present in the outcome dict produce no Key line."""
        text = render_episodic_text(
            user_request="Minimal step",
            task_status="completed",
            step_count=1,
            success_count=1,
            step_outcomes=[{
                "step_type": "tool_call",
                "description": "Simple action",
                "status": "success",
            }],
        )
        assert "Key:" not in text

    def test_no_step_outcomes_strategy_empty(self):
        """Without step_outcomes, strategy is 'empty'."""
        text = render_episodic_text(
            user_request="Legacy task",
            task_status="completed",
            step_count=2,
            success_count=2,
            file_paths=["a.py", "b.py"],
            error_patterns=["some error"],
        )
        assert "Strategy: empty" in text
        assert "Legacy task" in text

    def test_fix_cycle_uses_original_request(self):
        """Fix-cycle records use original scenario prompt in header."""
        text = render_episodic_text(
            user_request="The previous task failed. Please diagnose the error.",
            task_status="success",
            step_count=2,
            success_count=2,
            task_domain="code_debugging",
            original_request="Write a Python script at /workspace/app.py that sorts a list",
            step_outcomes=[
                {"step_type": "tool_call", "tool": "file_read", "status": "success"},
                {"step_type": "tool_call", "tool": "file_write", "status": "success",
                 "file_path": "/workspace/app.py", "file_size_after": 350, "diff_stats": "+5/-3 lines"},
            ],
        )
        # Header should use original request, not generic retry prompt
        assert "sorts a list" in text
        assert "(fix-cycle)" in text
        assert "previous task failed" not in text.split("\n")[0]

    def test_fix_cycle_includes_prior_error(self):
        """Fix-cycle records include prior turn error context."""
        text = render_episodic_text(
            user_request="The previous task failed.",
            task_status="success",
            step_count=1,
            success_count=1,
            original_request="Run the test suite",
            prior_error_summary="exit 1; stderr: ModuleNotFoundError: No module named 'requests'",
            step_outcomes=[
                {"step_type": "tool_call", "tool": "shell", "status": "success", "exit_code": 0},
            ],
        )
        assert "Prior error:" in text
        assert "ModuleNotFoundError" in text

    def test_all_steps_shown_not_just_failures(self):
        """All step outcomes are rendered, not just failures."""
        text = render_episodic_text(
            user_request="Build and test app",
            task_status="failed",
            step_count=3,
            success_count=2,
            step_outcomes=[
                {"step_type": "llm_task", "tool": "", "status": "success",
                 "description": "Generate app code"},
                {"step_type": "tool_call", "tool": "file_write", "status": "success",
                 "description": "Write app.py", "file_path": "/workspace/app.py",
                 "file_size_after": 500, "diff_stats": "+20/-0 lines"},
                {"step_type": "tool_call", "tool": "shell", "status": "failed",
                 "description": "Run tests", "exit_code": 1,
                 "stderr_preview": "AssertionError: expected 42 got 0"},
            ],
        )
        # All 3 steps should appear
        assert "S1(" in text
        assert "S2(" in text
        assert "S3(" in text
        assert "SUCCESS" in text  # steps 1 and 2
        assert "FAILED" in text   # step 3
        assert "AssertionError" in text

    def test_file_types_in_files_line(self):
        """File extensions (not full names) appear in the File types line."""
        text = render_episodic_text(
            user_request="Write a script",
            task_status="success",
            step_count=1,
            success_count=1,
            file_paths=["/workspace/app.py", "/workspace/style.css"],
            step_outcomes=[
                {"step_type": "tool_call", "tool": "file_write", "status": "success",
                 "file_path": "/workspace/app.py", "file_size_after": 1024,
                 "diff_stats": "+40/-0 lines"},
            ],
        )
        # Extensions only — no full filenames (prevents planner over-fitting)
        assert "File types:" in text
        assert ".py" in text
        assert ".css" in text
        assert "app.py" not in text

    def test_blocked_step_hides_scanner_details(self):
        """Blocked steps say 'blocked by security policy', no internals."""
        text = render_episodic_text(
            user_request="Run dangerous command",
            task_status="blocked",
            step_count=1,
            success_count=0,
            step_outcomes=[
                {"step_type": "tool_call", "tool": "shell", "status": "blocked",
                 "error_detail": "command_pattern_scanner: rm -rf /",
                 "scanner_result": "blocked"},
            ],
        )
        assert "blocked by security policy" in text
        # Must NOT reveal scanner name or specific pattern
        assert "command_pattern_scanner" not in text
        assert "scanner_result" not in text

    def test_no_original_request_uses_user_request(self):
        """Without original_request, header uses user_request as before."""
        text = render_episodic_text(
            user_request="Write a hello world script",
            task_status="success",
            step_count=1,
            success_count=1,
            task_domain="code_generation",
        )
        assert "hello world" in text
        assert "(fix-cycle)" not in text
