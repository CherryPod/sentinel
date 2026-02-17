"""Tests for memory API endpoints — store, search, get, delete.

Uses a minimal FastAPI app with real MemoryStore + mocked EmbeddingClient
to avoid full lifespan dependencies (Claude API key, policy files, etc.).
"""

import pytest
from unittest.mock import AsyncMock

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel, field_validator

from sentinel.core.db import init_db
from sentinel.memory.chunks import MemoryStore
from sentinel.memory.embeddings import EmbeddingClient
from sentinel.memory.search import hybrid_search
from sentinel.memory.splitter import split_text


# ── Minimal test app replicating memory endpoints ──────────────


def _normalize_text(v, *, min_length=1, field_name="Text"):
    v = v.strip()
    if not v:
        raise ValueError(f"{field_name} must not be empty")
    return v


class MemoryStoreRequest(BaseModel):
    text: str
    source: str = ""
    metadata: dict | None = None

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")


def _make_memory_app(memory_store: MemoryStore, embedding_client):
    """Build a minimal FastAPI app with only memory endpoints."""
    app = FastAPI()

    @app.post("/api/memory")
    async def store_memory(req: MemoryStoreRequest):
        chunks = split_text(req.text)
        if not chunks:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "reason": "Text produced no chunks"},
            )
        try:
            embeddings = await embedding_client.embed_batch(chunks)
        except Exception:
            chunk_ids = []
            for chunk_text in chunks:
                cid = memory_store.store(
                    content=chunk_text, source=req.source, metadata=req.metadata,
                )
                chunk_ids.append(cid)
            return {"status": "ok", "chunk_ids": chunk_ids, "chunks_stored": len(chunk_ids), "embedded": False}

        chunk_ids = []
        for chunk_text, embedding in zip(chunks, embeddings):
            cid = memory_store.store_with_embedding(
                content=chunk_text, embedding=embedding, source=req.source, metadata=req.metadata,
            )
            chunk_ids.append(cid)
        return {"status": "ok", "chunk_ids": chunk_ids, "chunks_stored": len(chunk_ids), "embedded": True}

    @app.get("/api/memory/search")
    async def search_memory(
        query: str = Query(..., min_length=1),
        k: int = Query(10, ge=1, le=100),
    ):
        query_embedding = None
        try:
            query_embedding = await embedding_client.embed(query)
        except Exception:
            pass
        results = hybrid_search(
            db=memory_store._db, query=query, embedding=query_embedding, k=k,
        )
        return {
            "status": "ok",
            "results": [
                {"chunk_id": r.chunk_id, "content": r.content, "source": r.source,
                 "score": round(r.score, 6), "match_type": r.match_type}
                for r in results
            ],
            "count": len(results),
        }

    @app.get("/api/memory/{chunk_id}")
    async def get_memory_chunk(chunk_id: str):
        chunk = memory_store.get(chunk_id)
        if chunk is None:
            return JSONResponse(status_code=404, content={"status": "error", "reason": "Chunk not found"})
        return {
            "status": "ok",
            "chunk": {
                "chunk_id": chunk.chunk_id, "user_id": chunk.user_id,
                "content": chunk.content, "source": chunk.source,
                "metadata": chunk.metadata, "created_at": chunk.created_at,
                "updated_at": chunk.updated_at,
            },
        }

    @app.delete("/api/memory/{chunk_id}")
    async def delete_memory_chunk(chunk_id: str):
        deleted = memory_store.delete(chunk_id)
        if not deleted:
            return JSONResponse(status_code=404, content={"status": "error", "reason": "Chunk not found"})
        return {"status": "ok", "deleted": chunk_id}

    return app


@pytest.fixture
def db():
    # Use check_same_thread=False because TestClient runs the app in a separate thread
    import sqlite3
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    from sentinel.core.db import _create_tables, _create_fts_index, _try_create_vec_table
    _create_tables(conn)
    _create_fts_index(conn)
    _try_create_vec_table(conn)
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def memory_store(db):
    return MemoryStore(db=db)


@pytest.fixture
def mock_embed():
    """Mock EmbeddingClient that returns fake 768-dim vectors."""
    client = AsyncMock(spec=EmbeddingClient)
    client.embed = AsyncMock(return_value=[0.1] * 768)
    client.embed_batch = AsyncMock(return_value=[[0.1] * 768])
    return client


@pytest.fixture
def client(memory_store, mock_embed):
    app = _make_memory_app(memory_store, mock_embed)
    return TestClient(app)


class TestStoreEndpoint:
    """POST /api/memory — store text in memory."""

    def test_store_success(self, client):
        resp = client.post("/api/memory", json={"text": "Hello world", "source": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["chunks_stored"] >= 1
        assert len(data["chunk_ids"]) >= 1
        assert data["embedded"] is True

    def test_store_empty_text_rejected(self, client):
        resp = client.post("/api/memory", json={"text": "", "source": "test"})
        assert resp.status_code == 422

    def test_store_with_metadata(self, client):
        resp = client.post(
            "/api/memory",
            json={"text": "Test content", "source": "api", "metadata": {"tag": "important"}},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_store_large_text_splits(self, client, mock_embed):
        """Large text should be split into multiple chunks."""
        large_text = " ".join(f"word{i}" for i in range(800))
        # Make embed_batch return enough embeddings for multiple chunks
        mock_embed.embed_batch = AsyncMock(
            return_value=[[0.1] * 768 for _ in range(10)]  # enough for any split
        )
        resp = client.post("/api/memory", json={"text": large_text, "source": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["chunks_stored"] >= 2

    def test_store_fallback_without_embeddings(self, client, mock_embed):
        """If embedding fails, should still store without vectors."""
        mock_embed.embed_batch = AsyncMock(side_effect=Exception("Ollama down"))
        resp = client.post("/api/memory", json={"text": "Fallback test", "source": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["embedded"] is False


class TestSearchEndpoint:
    """GET /api/memory/search — hybrid search."""

    def test_search_returns_results(self, client, memory_store):
        memory_store.store(content="Python programming language", source="docs")
        resp = client.get("/api/memory/search", params={"query": "Python"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["count"] >= 1

    def test_search_no_results(self, client):
        resp = client.get("/api/memory/search", params={"query": "nonexistent"})
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_search_missing_query(self, client):
        resp = client.get("/api/memory/search")
        assert resp.status_code == 422

    def test_search_respects_k(self, client, memory_store):
        for i in range(5):
            memory_store.store(content=f"Python document {i}", source="test")
        resp = client.get("/api/memory/search", params={"query": "Python", "k": 2})
        assert resp.status_code == 200
        assert resp.json()["count"] <= 2


class TestGetEndpoint:
    """GET /api/memory/{chunk_id} — get specific chunk."""

    def test_get_existing_chunk(self, client, memory_store):
        chunk_id = memory_store.store(content="Fetch me", source="test")
        resp = client.get(f"/api/memory/{chunk_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["chunk"]["content"] == "Fetch me"

    def test_get_nonexistent_chunk(self, client):
        resp = client.get("/api/memory/nonexistent-id")
        assert resp.status_code == 404


class TestDeleteEndpoint:
    """DELETE /api/memory/{chunk_id} — delete chunk."""

    def test_delete_existing_chunk(self, client, memory_store):
        chunk_id = memory_store.store(content="Delete me", source="test")
        resp = client.delete(f"/api/memory/{chunk_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["deleted"] == chunk_id
        assert memory_store.get(chunk_id) is None

    def test_delete_nonexistent_chunk(self, client):
        resp = client.delete("/api/memory/nonexistent-id")
        assert resp.status_code == 404
