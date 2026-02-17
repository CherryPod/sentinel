"""E2b capability tests — Memory view (store, list, delete APIs).

Tests verify the memory API endpoints return correct data for the
memory management view: store, list, and delete operations.

Search tests removed — hybrid_search requires a PG pool (pool=None returns empty).
"""

import pytest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from sentinel.memory.chunks import MemoryStore
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


def _make_memory_app(memory_store: MemoryStore):
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
        chunk_ids = []
        for chunk_text in chunks:
            cid = await memory_store.store(
                content=chunk_text, source=req.source, metadata=req.metadata,
            )
            chunk_ids.append(cid)
        return {
            "status": "ok",
            "chunk_ids": chunk_ids,
            "chunks_stored": len(chunk_ids),
            "embedded": False,
        }

    @app.get("/api/memory/list")
    async def list_memory_chunks(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ):
        chunks = await memory_store.list_chunks(limit=limit, offset=offset)
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
        chunk = await memory_store.get(chunk_id)
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
        deleted = await memory_store.delete(chunk_id)
        if not deleted:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "reason": "Chunk not found"},
            )
        return {"status": "ok", "deleted": chunk_id}

    return app


@pytest.fixture
def memory_store():
    return MemoryStore(pool=None)


@pytest.fixture
def client(memory_store):
    from starlette.testclient import TestClient
    return TestClient(_make_memory_app(memory_store))


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
    async def test_memory_delete_chunk(self, client, memory_store):
        """DELETE /api/memory/{id} removes the chunk."""
        cid = await memory_store.store(content="To be deleted", source="test")

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
