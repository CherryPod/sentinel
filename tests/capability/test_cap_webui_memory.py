"""E2b capability tests — Memory view (search, store, list, delete APIs).

Tests verify the memory API endpoints return correct data for the
memory management view: search, store, list, and delete operations.
"""

import sqlite3

import pytest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel, field_validator

from sentinel.core.db import _create_tables, _create_fts_index, _try_create_vec_table
from sentinel.memory.chunks import MemoryStore
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


def _make_memory_app(memory_store: MemoryStore, embedding_client=None):
    """Build a minimal FastAPI app with memory endpoints for testing."""
    app = FastAPI()

    @app.post("/api/memory")
    async def store_memory(req: MemoryStoreRequest):
        chunks = split_text(req.text)
        if not chunks:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "reason": "Text produced no chunks"},
            )
        # Store without embeddings for test simplicity
        chunk_ids = []
        for chunk_text in chunks:
            cid = memory_store.store(
                content=chunk_text, source=req.source, metadata=req.metadata,
            )
            chunk_ids.append(cid)
        return {
            "status": "ok",
            "chunk_ids": chunk_ids,
            "chunks_stored": len(chunk_ids),
            "embedded": False,
        }

    @app.get("/api/memory/search")
    async def search_memory(
        query: str = Query(..., min_length=1),
        k: int = Query(10, ge=1, le=100),
    ):
        results = hybrid_search(
            db=memory_store._db,
            query=query,
            embedding=None,
            k=k,
        )
        return {
            "status": "ok",
            "results": [
                {
                    "chunk_id": r.chunk_id,
                    "content": r.content,
                    "source": r.source,
                    "score": round(r.score, 6),
                    "match_type": r.match_type,
                }
                for r in results
            ],
            "count": len(results),
        }

    @app.get("/api/memory/list")
    async def list_memory_chunks(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ):
        chunks = memory_store.list_chunks(limit=limit, offset=offset)
        return {
            "status": "ok",
            "chunks": [
                {
                    "chunk_id": c.chunk_id,
                    "content": c.content,
                    "source": c.source,
                    "created_at": c.created_at,
                    "updated_at": c.updated_at,
                }
                for c in chunks
            ],
            "count": len(chunks),
        }

    @app.get("/api/memory/{chunk_id}")
    async def get_memory_chunk(chunk_id: str):
        chunk = memory_store.get(chunk_id)
        if chunk is None:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "reason": "Chunk not found"},
            )
        return {
            "status": "ok",
            "chunk": {
                "chunk_id": chunk.chunk_id,
                "content": chunk.content,
                "source": chunk.source,
            },
        }

    @app.delete("/api/memory/{chunk_id}")
    async def delete_memory_chunk(chunk_id: str):
        deleted = memory_store.delete(chunk_id)
        if not deleted:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "reason": "Chunk not found"},
            )
        return {"status": "ok", "deleted": chunk_id}

    return app


@pytest.fixture
def memory_store():
    """Create an in-memory MemoryStore with FTS5.

    Uses check_same_thread=False because TestClient runs the app
    in a separate thread.
    """
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _create_tables(conn)
    _create_fts_index(conn)
    _try_create_vec_table(conn)
    conn.commit()
    store = MemoryStore(conn)
    yield store
    conn.close()


@pytest.fixture
def client(memory_store):
    return TestClient(_make_memory_app(memory_store))


class TestMemorySearch:
    """Memory search API tests for the memory view."""

    @pytest.mark.capability
    def test_memory_search_returns_results(self, client, memory_store):
        """Search returns stored content matching the query."""
        memory_store.store(content="The quick brown fox jumps", source="test")
        memory_store.store(content="A lazy dog sleeps", source="test")

        resp = client.get("/api/memory/search?query=fox")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["count"] >= 1
        contents = [r["content"] for r in data["results"]]
        assert any("fox" in c for c in contents)

    @pytest.mark.capability
    def test_memory_search_no_results(self, client, memory_store):
        """Search for nonexistent content returns empty results."""
        memory_store.store(content="Hello world", source="test")

        resp = client.get("/api/memory/search?query=xyznonexistent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["count"] == 0
        assert data["results"] == []

    @pytest.mark.capability
    def test_memory_search_empty_query(self, client):
        """Search with empty query is rejected (min_length=1)."""
        resp = client.get("/api/memory/search?query=")
        assert resp.status_code == 422  # validation error


class TestMemoryStoreAndDelete:
    """Memory store/delete API tests for the memory view."""

    @pytest.mark.capability
    def test_memory_store_and_retrieve(self, client):
        """POST /api/memory stores text, GET /api/memory/{id} retrieves it."""
        resp = client.post(
            "/api/memory",
            json={"text": "Test memory content", "source": "webui"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["chunks_stored"] >= 1
        chunk_id = data["chunk_ids"][0]

        # Retrieve it
        resp2 = client.get(f"/api/memory/{chunk_id}")
        assert resp2.status_code == 200
        assert resp2.json()["chunk"]["content"] == "Test memory content"

    @pytest.mark.capability
    def test_memory_delete_chunk(self, client, memory_store):
        """DELETE /api/memory/{id} removes the chunk."""
        cid = memory_store.store(content="To be deleted", source="test")

        resp = client.delete(f"/api/memory/{cid}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        # Verify it's gone
        resp2 = client.get(f"/api/memory/{cid}")
        assert resp2.status_code == 404

    @pytest.mark.capability
    def test_memory_delete_nonexistent(self, client):
        """DELETE /api/memory/{id} for nonexistent chunk returns 404."""
        resp = client.delete("/api/memory/nonexistent-chunk-id")
        assert resp.status_code == 404
        assert resp.json()["status"] == "error"
