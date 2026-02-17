"""Tests for sentinel.memory.chunks — MemoryStore CRUD with in-memory fallback."""

import pytest

from sentinel.memory.chunks import MemoryChunk, MemoryStore


@pytest.fixture
def store():
    """MemoryStore in pure in-memory mode (no PostgreSQL)."""
    return MemoryStore(pool=None)


class TestStore:
    """MemoryStore.store() — insert chunk."""

    async def test_store_returns_chunk_id(self, store):
        chunk_id = await store.store(content="Hello world", source="test")
        assert isinstance(chunk_id, str)
        assert len(chunk_id) == 36  # UUID format

    async def test_store_with_metadata(self, store):
        chunk_id = await store.store(
            content="Test",
            source="test",
            metadata={"key": "value"},
        )
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.metadata == {"key": "value"}

    async def test_store_default_user_id(self, store):
        chunk_id = await store.store(content="Test", source="test")
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.user_id == 1

    async def test_store_custom_user_id(self, store):
        chunk_id = await store.store(content="Test", source="test", user_id=2)
        # get() is now user_id-scoped — must pass matching user_id
        chunk = await store.get(chunk_id, user_id=2)
        assert chunk is not None
        assert chunk.user_id == 2

    async def test_store_custom_user_id_isolation(self, store):
        """get() with wrong user_id returns None (defence-in-depth)."""
        chunk_id = await store.store(content="Test", source="test", user_id=2)
        assert await store.get(chunk_id, user_id=1) is None
        assert await store.get(chunk_id, user_id=2) is not None


class TestStoreWithEmbedding:
    """MemoryStore.store_with_embedding() — insert with embedding."""

    async def test_store_with_embedding_returns_id(self, store):
        embedding = [0.1] * 768
        chunk_id = await store.store_with_embedding(
            content="Embedded text",
            embedding=embedding,
            source="test",
        )
        assert isinstance(chunk_id, str)

    async def test_store_with_embedding_persists_content(self, store):
        embedding = [0.1] * 768
        chunk_id = await store.store_with_embedding(
            content="Embedded text",
            embedding=embedding,
            source="embed_test",
        )
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "Embedded text"
        assert chunk.source == "embed_test"


class TestGet:
    """MemoryStore.get() — fetch by ID."""

    async def test_get_existing(self, store):
        chunk_id = await store.store(content="Fetch me", source="test")
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert isinstance(chunk, MemoryChunk)
        assert chunk.content == "Fetch me"

    async def test_get_nonexistent(self, store):
        assert await store.get("nonexistent-id") is None

    async def test_get_has_timestamps(self, store):
        chunk_id = await store.store(content="Timestamps", source="test")
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.created_at is not None
        assert chunk.updated_at is not None


class TestListChunks:
    """MemoryStore.list_chunks() — paginated listing."""

    async def test_list_empty(self, store):
        result = await store.list_chunks()
        assert result == []

    async def test_list_returns_chunks(self, store):
        await store.store(content="A", source="test")
        await store.store(content="B", source="test")
        result = await store.list_chunks()
        assert len(result) == 2

    async def test_list_respects_user_id(self, store):
        await store.store(content="User1 chunk", source="test", user_id="user1")
        await store.store(content="User2 chunk", source="test", user_id="user2")
        result = await store.list_chunks(user_id="user1")
        assert len(result) == 1
        assert result[0].content == "User1 chunk"

    async def test_list_pagination(self, store):
        for i in range(5):
            await store.store(content=f"Chunk {i}", source="test")
        result = await store.list_chunks(limit=2, offset=0)
        assert len(result) == 2
        result2 = await store.list_chunks(limit=2, offset=2)
        assert len(result2) == 2


class TestUpdate:
    """MemoryStore.update() — update content."""

    async def test_update_content(self, store):
        chunk_id = await store.store(content="Original", source="test")
        updated = await store.update(chunk_id, content="Updated")
        assert updated is True
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "Updated"

    async def test_update_nonexistent(self, store):
        assert await store.update("nonexistent", content="New") is False

    async def test_update_metadata(self, store):
        chunk_id = await store.store(content="Test", source="test", metadata={"k": "v"})
        await store.update(chunk_id, content="Test", metadata={"k": "v2", "new": True})
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.metadata == {"k": "v2", "new": True}


class TestDelete:
    """MemoryStore.delete() — delete chunk."""

    async def test_delete_existing(self, store):
        chunk_id = await store.store(content="Delete me", source="test")
        deleted = await store.delete(chunk_id)
        assert deleted is True
        assert await store.get(chunk_id) is None

    async def test_delete_nonexistent(self, store):
        assert await store.delete("nonexistent") is False


class TestInMemoryFallback:
    """MemoryStore with pool=None — pure in-memory mode."""

    async def test_store_and_get(self, store):
        chunk_id = await store.store(content="In memory", source="test")
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "In memory"

    async def test_list_chunks(self, store):
        await store.store(content="A", source="test")
        await store.store(content="B", source="test")
        result = await store.list_chunks()
        assert len(result) == 2

    async def test_delete(self, store):
        chunk_id = await store.store(content="Delete me", source="test")
        assert await store.delete(chunk_id) is True
        assert await store.get(chunk_id) is None

    async def test_update(self, store):
        chunk_id = await store.store(content="Original", source="test")
        assert await store.update(chunk_id, content="Updated") is True
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "Updated"

    async def test_get_latest_by_source(self, store):
        await store.store(content="First", source="daily")
        await store.store(content="Second", source="daily")
        result = await store.get_latest_by_source("daily")
        assert result is not None

    async def test_system_protected_delete(self, store):
        chunk_id = await store.store(content="Protected", source="system:heartbeat")
        with pytest.raises(ValueError, match="system-protected"):
            await store.delete(chunk_id)


# ── V-004: SQL injection boundary tests ──────────────────────────


_EVIL_INPUTS = [
    "'; DROP TABLE memory_chunks; --",
    "' OR '1'='1",
    "'; DELETE FROM memory_chunks_fts; --",
    "\x00null_byte\x00",
    "a" * 100_000,
    "SELECT * FROM memory_chunks",
    "Robert'); DROP TABLE students;--",
    "1; ATTACH DATABASE '/tmp/evil.db' AS evil; --",
]


class TestMemoryStoreSQLInjection:
    """Regression guard: V-004 — user-provided strings stored as literals, never executed."""

    @pytest.mark.parametrize("evil_input", _EVIL_INPUTS, ids=[
        "drop_table", "or_1_1", "delete_fts", "null_bytes",
        "very_long_string", "select_star", "bobby_tables", "attach_db",
    ])
    async def test_evil_content(self, store, evil_input):
        """Evil strings as chunk content are stored and retrieved as literals."""
        chunk_id = await store.store(content=evil_input, source="test")
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == evil_input

    @pytest.mark.parametrize("evil_input", _EVIL_INPUTS, ids=[
        "drop_table", "or_1_1", "delete_fts", "null_bytes",
        "very_long_string", "select_star", "bobby_tables", "attach_db",
    ])
    async def test_evil_source(self, store, evil_input):
        """Evil strings as chunk source survive roundtrip."""
        chunk_id = await store.store(content="Safe content", source=evil_input)
        chunk = await store.get(chunk_id)
        assert chunk is not None
        assert chunk.source == evil_input

    @pytest.mark.parametrize("evil_input", _EVIL_INPUTS, ids=[
        "drop_table", "or_1_1", "delete_fts", "null_bytes",
        "very_long_string", "select_star", "bobby_tables", "attach_db",
    ])
    async def test_evil_user_id(self, store, evil_input):
        """Evil strings as user_id survive roundtrip."""
        chunk_id = await store.store(
            content="Test", source="test", user_id=evil_input
        )
        # get() is now user_id-scoped — must pass matching user_id
        chunk = await store.get(chunk_id, user_id=evil_input)
        assert chunk is not None
        assert chunk.user_id == evil_input
