"""Memory CRUD route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  POST   /api/memory              — store text in memory (auto-chunks + embeds)
  GET    /api/memory/search       — hybrid search across memory chunks
  GET    /api/memory/list         — list memory chunks (paginated)
  GET    /api/memory/{chunk_id}   — get a specific memory chunk
  DELETE /api/memory/{chunk_id}   — delete a memory chunk
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from sentinel.api.models import MemoryStoreRequest
from sentinel.memory.splitter import split_text

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_memory_store: Any = None
_embedding_client: Any = None
_hybrid_search_fn: Any = None
_audit: Any = None


def init(
    *,
    memory_store: Any = None,
    embedding_client: Any = None,
    hybrid_search_fn: Any = None,
    audit: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _memory_store, _embedding_client, _hybrid_search_fn, _audit
    _memory_store = memory_store
    _embedding_client = embedding_client
    _hybrid_search_fn = hybrid_search_fn
    _audit = audit


# ── Store ──────────────────────────────────────────────────────────


@router.post("/memory")
async def store_memory(req: MemoryStoreRequest):
    """Store text in memory — splits large texts into chunks automatically."""
    if _memory_store is None or _embedding_client is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    # Split text into chunks
    chunks = split_text(req.text)
    if not chunks:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reason": "Text produced no chunks after splitting"},
        )

    # Embed all chunks in a single batch call
    try:
        embeddings = await _embedding_client.embed_batch(chunks)
    except Exception as exc:
        # Graceful degradation: store without embeddings if Ollama is unavailable
        if _audit:
            _audit.warning(
                "Embedding failed, storing without vectors",
                extra={"event": "memory_embed_fallback", "error": str(exc)},
            )
        chunk_ids = []
        for chunk_text in chunks:
            cid = await _memory_store.store(
                content=chunk_text,
                source=req.source,
                metadata=req.metadata,
            )
            chunk_ids.append(cid)
        return {
            "status": "ok",
            "chunk_ids": chunk_ids,
            "chunks_stored": len(chunk_ids),
            "embedded": False,
        }

    # Store each chunk with its embedding
    chunk_ids = []
    for chunk_text, embedding in zip(chunks, embeddings):
        cid = await _memory_store.store_with_embedding(
            content=chunk_text,
            embedding=embedding,
            source=req.source,
            metadata=req.metadata,
        )
        chunk_ids.append(cid)

    return {
        "status": "ok",
        "chunk_ids": chunk_ids,
        "chunks_stored": len(chunk_ids),
        "embedded": True,
    }


# ── Search ─────────────────────────────────────────────────────────


@router.get("/memory/search")
async def search_memory(
    query: str = Query(..., min_length=1, description="Search query"),
    k: int = Query(10, ge=1, le=100, description="Number of results"),
):
    """Hybrid search across memory — full-text keyword + vector semantic with RRF fusion."""
    if _memory_store is None or _hybrid_search_fn is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    # Try to embed the query for vector search; fall back to full-text-only
    query_embedding = None
    if _embedding_client is not None:
        try:
            query_embedding = await _embedding_client.embed(query)
        except Exception:
            pass  # graceful degradation to full-text-only

    results = await _hybrid_search_fn(
        query=query,
        embedding=query_embedding,
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


# ── List ───────────────────────────────────────────────────────────


@router.get("/memory/list")
async def list_memory_chunks(
    limit: int = Query(50, ge=1, le=500, description="Number of chunks to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """List memory chunks, newest first. Paginated."""
    if _memory_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    chunks = await _memory_store.list_chunks(limit=limit, offset=offset)
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


# ── Get ────────────────────────────────────────────────────────────


@router.get("/memory/{chunk_id}")
async def get_memory_chunk(chunk_id: str):
    """Get a specific memory chunk by ID."""
    if _memory_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    chunk = await _memory_store.get(chunk_id)
    if chunk is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Chunk not found"},
        )

    return {
        "status": "ok",
        "chunk": {
            "chunk_id": chunk.chunk_id,
            "user_id": chunk.user_id,
            "content": chunk.content,
            "source": chunk.source,
            "metadata": chunk.metadata,
            "created_at": chunk.created_at,
            "updated_at": chunk.updated_at,
        },
    }


# ── Delete ─────────────────────────────────────────────────────────


@router.delete("/memory/{chunk_id}")
async def delete_memory_chunk(chunk_id: str):
    """Delete a memory chunk and its index entries."""
    if _memory_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    try:
        deleted = await _memory_store.delete(chunk_id)
    except ValueError as exc:
        return JSONResponse(
            status_code=403,
            content={"status": "error", "reason": str(exc)},
        )

    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Chunk not found"},
        )

    return {"status": "ok", "deleted": chunk_id}
