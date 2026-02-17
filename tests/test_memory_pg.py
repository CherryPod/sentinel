"""Tests for MemoryStore — PostgreSQL backend for memory chunks.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.memory.chunks import MemoryChunk, MemoryStore, _embedding_to_pg


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
    return MemoryStore(pool)


def _make_chunk_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "chunk_id": "chunk-abc",
        "user_id": 1,
        "content": "test content",
        "source": "test",
        "metadata": {"key": "value"},
        "created_at": now,
        "updated_at": now,
    }
    defaults.update(overrides)
    return defaults


# ── embedding format ─────────────────────────────────────────


class TestEmbeddingFormat:
    def test_converts_to_pgvector_string(self):
        result = _embedding_to_pg([0.1, 0.2, 0.3])
        assert result == "[0.1,0.2,0.3]"

    def test_empty_embedding(self):
        result = _embedding_to_pg([])
        assert result == "[]"

    def test_single_value(self):
        result = _embedding_to_pg([1.0])
        assert result == "[1.0]"


# ── store ────────────────────────────────────────────────────


class TestStore:
    @pytest.mark.asyncio
    async def test_inserts_chunk(self, store, mock_pool):
        _, conn = mock_pool

        chunk_id = await store.store("hello world", source="test")

        assert chunk_id  # UUID generated
        args = conn.execute.call_args[0]
        assert "INSERT INTO memory_chunks" in args[0]
        # No FTS sync query — only one execute call
        assert conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_metadata_serialised_as_jsonb(self, store, mock_pool):
        _, conn = mock_pool

        await store.store("content", metadata={"key": "val"})

        args = conn.execute.call_args[0]
        assert "$5::jsonb" in args[0]
        assert args[5] == '{"key": "val"}'

    @pytest.mark.asyncio
    async def test_no_fts_sync_calls(self, store, mock_pool):
        """PostgreSQL tsvector is auto-generated — no sync queries needed."""
        _, conn = mock_pool

        await store.store("content")

        # Only the INSERT, no FTS INSERT
        assert conn.execute.call_count == 1


# ── store_with_embedding ─────────────────────────────────────


class TestStoreWithEmbedding:
    @pytest.mark.asyncio
    async def test_inserts_with_vector(self, store, mock_pool):
        _, conn = mock_pool

        chunk_id = await store.store_with_embedding(
            "hello", embedding=[0.1, 0.2, 0.3]
        )

        assert chunk_id
        args = conn.execute.call_args[0]
        assert "INSERT INTO memory_chunks" in args[0]
        assert "embedding" in args[0]
        assert "$6::vector" in args[0]
        # Embedding passed as pgvector string
        assert args[6] == "[0.1,0.2,0.3]"

    @pytest.mark.asyncio
    async def test_no_vec_sync_calls(self, store, mock_pool):
        """Embedding stored directly — no separate vec table sync."""
        _, conn = mock_pool

        await store.store_with_embedding("hello", embedding=[0.1, 0.2])

        # Only the INSERT, no vec INSERT
        assert conn.execute.call_count == 1


# ── get ──────────────────────────────────────────────────────


class TestGet:
    @pytest.mark.asyncio
    async def test_returns_chunk(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_chunk_row()

        chunk = await store.get("chunk-abc")

        assert chunk is not None
        assert isinstance(chunk, MemoryChunk)
        assert chunk.chunk_id == "chunk-abc"
        assert chunk.content == "test content"
        assert chunk.metadata == {"key": "value"}

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_metadata_string_parsed(self, store, mock_pool):
        """asyncpg may return JSONB as dict or string depending on codec."""
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_chunk_row(metadata='{"a": 1}')

        chunk = await store.get("chunk-abc")

        assert chunk is not None
        assert chunk.metadata == {"a": 1}


# ── list_chunks ──────────────────────────────────────────────


class TestListChunks:
    @pytest.mark.asyncio
    async def test_lists_with_pagination(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_chunk_row(), _make_chunk_row(chunk_id="chunk-def")]

        chunks = await store.list_chunks(limit=10, offset=5)

        assert len(chunks) == 2
        args = conn.fetch.call_args[0]
        assert "LIMIT $2 OFFSET $3" in args[0]

    @pytest.mark.asyncio
    async def test_filters_by_source(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_chunk_row()]

        await store.list_chunks(source="system:heartbeat")

        args = conn.fetch.call_args[0]
        assert "AND source = $2" in args[0]

    @pytest.mark.asyncio
    async def test_empty_list(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        result = await store.list_chunks()

        assert result == []


# ── update ───────────────────────────────────────────────────


class TestUpdate:
    @pytest.mark.asyncio
    async def test_updates_content(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        result = await store.update("chunk-abc", "new content")

        assert result is True
        args = conn.execute.call_args[0]
        assert "UPDATE memory_chunks SET content = $1" in args[0]
        # No FTS delete/insert — tsvector auto-regenerates
        assert conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_updates_with_metadata(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        result = await store.update("chunk-abc", "new", metadata={"x": 1})

        assert result is True
        args = conn.execute.call_args[0]
        assert "metadata = $2::jsonb" in args[0]

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 0"

        result = await store.update("nonexistent", "content")

        assert result is False

    @pytest.mark.asyncio
    async def test_no_fts_sync_on_update(self, store, mock_pool):
        """No manual FTS delete+insert needed — generated column handles it."""
        _, conn = mock_pool
        conn.execute.return_value = "UPDATE 1"

        await store.update("chunk-abc", "updated")

        # Just the UPDATE, no FTS sync
        assert conn.execute.call_count == 1


# ── delete ───────────────────────────────────────────────────


class TestDelete:
    @pytest.mark.asyncio
    async def test_deletes_chunk(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = {"source": "test"}
        conn.execute.return_value = "DELETE 1"

        result = await store.delete("chunk-abc")

        assert result is True
        args = conn.execute.call_args[0]
        assert "DELETE FROM memory_chunks" in args[0]
        # No FTS/vec cleanup — only the source check + DELETE
        assert conn.fetchrow.call_count == 1
        assert conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.delete("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_raises_for_system_protected(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = {"source": "system:heartbeat"}

        with pytest.raises(ValueError, match="system-protected"):
            await store.delete("chunk-abc")


# ── get_latest_by_source ─────────────────────────────────────


class TestGetLatestBySource:
    @pytest.mark.asyncio
    async def test_returns_latest(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_chunk_row(source="daily-summary")

        chunk = await store.get_latest_by_source("daily-summary")

        assert chunk is not None
        assert chunk.source == "daily-summary"
        args = conn.fetchrow.call_args[0]
        assert "ORDER BY created_at DESC LIMIT 1" in args[0]

    @pytest.mark.asyncio
    async def test_returns_none_when_empty(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get_latest_by_source("nonexistent")

        assert result is None


# ── close ────────────────────────────────────────────────────


class TestClose:
    @pytest.mark.asyncio
    async def test_close_is_noop(self, store):
        await store.close()  # Should not raise
