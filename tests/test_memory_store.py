"""Tests for sentinel.memory.chunks — MemoryStore CRUD + FTS5/vec sync."""

import json
import sqlite3

import pytest

from sentinel.core.db import init_db
from sentinel.memory.chunks import MemoryChunk, MemoryStore


@pytest.fixture
def db():
    """In-memory SQLite database with full schema."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def store(db):
    """MemoryStore backed by in-memory SQLite."""
    return MemoryStore(db=db)


@pytest.fixture
def mem_store():
    """MemoryStore in pure in-memory mode (no SQLite)."""
    return MemoryStore(db=None)


class TestStore:
    """MemoryStore.store() — insert chunk with FTS5 sync."""

    def test_store_returns_chunk_id(self, store):
        chunk_id = store.store(content="Hello world", source="test")
        assert isinstance(chunk_id, str)
        assert len(chunk_id) == 36  # UUID format

    def test_store_persists_to_db(self, store, db):
        chunk_id = store.store(content="Stored text", source="api")
        row = db.execute(
            "SELECT content, source FROM memory_chunks WHERE chunk_id = ?",
            (chunk_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "Stored text"
        assert row[1] == "api"

    def test_store_syncs_fts5(self, store, db):
        chunk_id = store.store(content="searchable content here", source="test")
        # FTS5 should find it
        rows = db.execute(
            "SELECT rowid FROM memory_chunks_fts WHERE memory_chunks_fts MATCH ?",
            ('"searchable"',),
        ).fetchall()
        assert len(rows) == 1

    def test_store_with_metadata(self, store):
        chunk_id = store.store(
            content="Test",
            source="test",
            metadata={"key": "value"},
        )
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert chunk.metadata == {"key": "value"}

    def test_store_default_user_id(self, store):
        chunk_id = store.store(content="Test", source="test")
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert chunk.user_id == "default"

    def test_store_custom_user_id(self, store):
        chunk_id = store.store(content="Test", source="test", user_id="user1")
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert chunk.user_id == "user1"


class TestStoreWithEmbedding:
    """MemoryStore.store_with_embedding() — insert + vec sync."""

    def test_store_with_embedding_returns_id(self, store):
        embedding = [0.1] * 768
        chunk_id = store.store_with_embedding(
            content="Embedded text",
            embedding=embedding,
            source="test",
        )
        assert isinstance(chunk_id, str)

    def test_store_with_embedding_persists_content(self, store):
        embedding = [0.1] * 768
        chunk_id = store.store_with_embedding(
            content="Embedded text",
            embedding=embedding,
            source="embed_test",
        )
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "Embedded text"
        assert chunk.source == "embed_test"

    def test_store_with_embedding_syncs_fts5(self, store, db):
        embedding = [0.1] * 768
        store.store_with_embedding(
            content="vector searchable text",
            embedding=embedding,
            source="test",
        )
        rows = db.execute(
            "SELECT rowid FROM memory_chunks_fts WHERE memory_chunks_fts MATCH ?",
            ('"vector"',),
        ).fetchall()
        assert len(rows) == 1


class TestGet:
    """MemoryStore.get() — fetch by ID."""

    def test_get_existing(self, store):
        chunk_id = store.store(content="Fetch me", source="test")
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert isinstance(chunk, MemoryChunk)
        assert chunk.content == "Fetch me"

    def test_get_nonexistent(self, store):
        assert store.get("nonexistent-id") is None

    def test_get_has_timestamps(self, store):
        chunk_id = store.store(content="Timestamps", source="test")
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert chunk.created_at is not None
        assert chunk.updated_at is not None


class TestListChunks:
    """MemoryStore.list_chunks() — paginated listing."""

    def test_list_empty(self, store):
        result = store.list_chunks()
        assert result == []

    def test_list_returns_chunks(self, store):
        store.store(content="A", source="test")
        store.store(content="B", source="test")
        result = store.list_chunks()
        assert len(result) == 2

    def test_list_respects_user_id(self, store):
        store.store(content="User1 chunk", source="test", user_id="user1")
        store.store(content="User2 chunk", source="test", user_id="user2")
        result = store.list_chunks(user_id="user1")
        assert len(result) == 1
        assert result[0].content == "User1 chunk"

    def test_list_pagination(self, store):
        for i in range(5):
            store.store(content=f"Chunk {i}", source="test")
        result = store.list_chunks(limit=2, offset=0)
        assert len(result) == 2
        result2 = store.list_chunks(limit=2, offset=2)
        assert len(result2) == 2

    def test_list_ordered_by_created_at_desc(self, store, db):
        """Newest chunks should appear first in list."""
        cid1 = store.store(content="First", source="test")
        cid2 = store.store(content="Second", source="test")
        # Force different timestamps since both may land in the same ms
        db.execute(
            "UPDATE memory_chunks SET created_at = '2020-01-01T00:00:00.000Z' "
            "WHERE chunk_id = ?",
            (cid1,),
        )
        db.commit()
        result = store.list_chunks()
        assert result[0].content == "Second"
        assert result[1].content == "First"


class TestUpdate:
    """MemoryStore.update() — update content + re-sync FTS5."""

    def test_update_content(self, store):
        chunk_id = store.store(content="Original", source="test")
        updated = store.update(chunk_id, content="Updated")
        assert updated is True
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "Updated"

    def test_update_nonexistent(self, store):
        assert store.update("nonexistent", content="New") is False

    def test_update_syncs_fts5(self, store, db):
        chunk_id = store.store(content="original searchterm", source="test")
        store.update(chunk_id, content="updated newterm")
        # Old term should not match
        rows = db.execute(
            "SELECT rowid FROM memory_chunks_fts WHERE memory_chunks_fts MATCH ?",
            ('"original"',),
        ).fetchall()
        assert len(rows) == 0
        # New term should match
        rows = db.execute(
            "SELECT rowid FROM memory_chunks_fts WHERE memory_chunks_fts MATCH ?",
            ('"newterm"',),
        ).fetchall()
        assert len(rows) == 1

    def test_update_metadata(self, store):
        chunk_id = store.store(content="Test", source="test", metadata={"k": "v"})
        store.update(chunk_id, content="Test", metadata={"k": "v2", "new": True})
        chunk = store.get(chunk_id)
        assert chunk is not None
        assert chunk.metadata == {"k": "v2", "new": True}


class TestDelete:
    """MemoryStore.delete() — delete from chunk + FTS5 + vec."""

    def test_delete_existing(self, store):
        chunk_id = store.store(content="Delete me", source="test")
        deleted = store.delete(chunk_id)
        assert deleted is True
        assert store.get(chunk_id) is None

    def test_delete_nonexistent(self, store):
        assert store.delete("nonexistent") is False

    def test_delete_removes_fts5_entry(self, store, db):
        chunk_id = store.store(content="deletable term", source="test")
        store.delete(chunk_id)
        rows = db.execute(
            "SELECT rowid FROM memory_chunks_fts WHERE memory_chunks_fts MATCH ?",
            ('"deletable"',),
        ).fetchall()
        assert len(rows) == 0


class TestInMemoryFallback:
    """MemoryStore with db=None — pure in-memory mode."""

    def test_store_and_get(self, mem_store):
        chunk_id = mem_store.store(content="In memory", source="test")
        chunk = mem_store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "In memory"

    def test_list_chunks(self, mem_store):
        mem_store.store(content="A", source="test")
        mem_store.store(content="B", source="test")
        result = mem_store.list_chunks()
        assert len(result) == 2

    def test_delete(self, mem_store):
        chunk_id = mem_store.store(content="Delete me", source="test")
        assert mem_store.delete(chunk_id) is True
        assert mem_store.get(chunk_id) is None

    def test_update(self, mem_store):
        chunk_id = mem_store.store(content="Original", source="test")
        assert mem_store.update(chunk_id, content="Updated") is True
        chunk = mem_store.get(chunk_id)
        assert chunk is not None
        assert chunk.content == "Updated"

    def test_has_vec_table_false(self, mem_store):
        assert mem_store._has_vec_table() is False
