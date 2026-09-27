"""Memory chunk store — PostgreSQL backend with in-memory fallback.

Implements MemoryStoreProtocol using asyncpg. The tsvector column
(search_vector) is GENERATED ALWAYS AS ... STORED, so no FTS sync
is needed. Embeddings are stored directly in the vector(768) column.

When pool is None, falls back to in-memory dict (useful for tests).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC
from typing import TYPE_CHECKING, Any, cast

from sentinel.core.context import get_task_id, require_user_id

logger = logging.getLogger(__name__)


@dataclass
class MemoryChunk:
    """A stored memory chunk with metadata."""

    chunk_id: str
    user_id: int
    content: str
    source: str
    metadata: dict
    created_at: str
    updated_at: str


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dt_to_iso(dt: Any) -> str:
    """Convert an asyncpg datetime to ISO 8601 string."""
    if dt is None:
        return _now_iso()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _row_to_chunk(row: Any) -> MemoryChunk:
    """Convert an asyncpg Record to a MemoryChunk dataclass."""
    metadata = row["metadata"]
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    return MemoryChunk(
        chunk_id=row["chunk_id"],
        user_id=row["user_id"],
        content=row["content"],
        source=row["source"],
        metadata=metadata if metadata is not None else {},
        created_at=_dt_to_iso(row["created_at"]),
        updated_at=_dt_to_iso(row["updated_at"]),
    )


def _embedding_to_pg(embedding: list[float]) -> str:
    """Convert a list of floats to pgvector string format: '[0.1,0.2,...]'."""
    return "[" + ",".join(str(v) for v in embedding) + "]"


class MemoryStore:
    """PostgreSQL memory chunk store with in-memory fallback for tests.

    When pool is None, uses an in-memory dict for all operations.
    """

    def __init__(self, pool: Any = None):
        self._pool = pool
        self._mem: dict[str, MemoryChunk] = {}  # fallback for tests

    @property
    def pool(self) -> Any:
        """Expose the asyncpg pool for hybrid_search calls."""
        return self._pool

    async def store(
        self,
        content: str,
        source: str = "",
        metadata: dict | None = None,
        user_id: int | None = None,
        task_domain: str | None = None,
    ) -> str:
        """Insert a chunk. Returns chunk_id. tsvector auto-generated."""
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.store")
        chunk_id = str(uuid.uuid4())
        meta_json = json.dumps(metadata or {})

        if self._pool is not None:
            logger.debug("store: match", extra={"event": "chunks.store.match"})
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO memory_chunks "
                    "(chunk_id, user_id, content, source, metadata, task_domain) "
                    "VALUES ($1, $2, $3, $4, $5::jsonb, $6)",
                    chunk_id,
                    user_id,
                    content,
                    source,
                    meta_json,
                    task_domain,
                )
        else:
            logger.debug("store: clean", extra={"event": "chunks.store.clean"})
            now = _now_iso()
            self._mem[chunk_id] = MemoryChunk(
                chunk_id=chunk_id,
                user_id=user_id,
                content=content,
                source=source,
                metadata=metadata or {},
                created_at=now,
                updated_at=now,
            )

        logger.info(
            "Memory chunk stored",
            extra={
                "event": "memory.store",
                "chunk_id": chunk_id,
                "source": source,
                "content_length": len(content),
                "task_id": get_task_id(),
            },
        )
        return chunk_id

    # Current embedding model and render format version — used to detect stale entries
    CURRENT_EMBED_MODEL = "nomic-embed-text"
    CURRENT_RENDER_VERSION = 1

    async def store_with_embedding(
        self,
        content: str,
        embedding: list[float],
        source: str = "",
        metadata: dict | None = None,
        user_id: int | None = None,
        embed_model: str = "nomic-embed-text",
        render_version: int = 1,
        task_domain: str | None = None,
    ) -> str:
        """Insert a chunk with vector embedding. Returns chunk_id."""
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.store_with_embedding")
        chunk_id = str(uuid.uuid4())
        meta_json = json.dumps(metadata or {})
        vec_str = _embedding_to_pg(embedding)

        if self._pool is not None:
            logger.debug(
                "store_with_embedding: match",
                extra={"event": "chunks.store_with_embedding.match"},
            )
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO memory_chunks "
                    "(chunk_id, user_id, content, source, metadata, embedding, embed_model, render_version, task_domain) "
                    "VALUES ($1, $2, $3, $4, $5::jsonb, $6::vector, $7, $8, $9)",
                    chunk_id,
                    user_id,
                    content,
                    source,
                    meta_json,
                    vec_str,
                    embed_model,
                    render_version,
                    task_domain,
                )
        else:
            logger.debug(
                "store_with_embedding: clean",
                extra={"event": "chunks.store_with_embedding.clean"},
            )
            now = _now_iso()
            self._mem[chunk_id] = MemoryChunk(
                chunk_id=chunk_id,
                user_id=user_id,
                content=content,
                source=source,
                metadata=metadata or {},
                created_at=now,
                updated_at=now,
            )

        logger.debug(
            "Memory chunk stored with embedding",
            extra={
                "event": "memory.store_embedded",
                "chunk_id": chunk_id,
                "source": source,
                "content_length": len(content),
                "embedding_dims": len(embedding),
                "task_id": get_task_id(),
            },
        )
        return chunk_id

    async def count_stale_embeddings(self, user_id: int | None = None) -> int:
        """Count memory chunks where embed_model or render_version doesn't match current."""
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.count_stale_embeddings")
        if self._pool is None:
            return 0
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) AS cnt FROM memory_chunks "
                "WHERE user_id = $1 AND embedding IS NOT NULL "
                "AND (embed_model != $2 OR render_version != $3)",
                user_id,
                self.CURRENT_EMBED_MODEL,
                self.CURRENT_RENDER_VERSION,
            )
            return row["cnt"] if row else 0

    async def re_embed_stale(
        self,
        embedding_client,
        render_fn,
        user_id: int | None = None,
        batch_size: int = 10,
    ) -> int:
        """Re-embed stale chunks. Returns count of updated chunks.

        render_fn: callable(content) -> str that re-renders content for embedding
        embedding_client: EmbeddingBase with embed() method
        """
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.re_embed_stale")
        if self._pool is None:
            return 0

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT chunk_id, content FROM memory_chunks "
                "WHERE user_id = $1 AND embedding IS NOT NULL "
                "AND (embed_model != $2 OR render_version != $3) "
                "LIMIT $4",
                user_id,
                self.CURRENT_EMBED_MODEL,
                self.CURRENT_RENDER_VERSION,
                batch_size,
            )

        updated = 0
        for row in rows:
            try:
                text = render_fn(row["content"])
                new_embedding = await embedding_client.embed(
                    text, prefix="search_document: "
                )
                vec_str = _embedding_to_pg(new_embedding)
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE memory_chunks SET embedding = $1::vector, "
                        "embed_model = $2, render_version = $3, updated_at = NOW() "
                        "WHERE chunk_id = $4",
                        vec_str,
                        self.CURRENT_EMBED_MODEL,
                        self.CURRENT_RENDER_VERSION,
                        row["chunk_id"],
                    )
                updated += 1
            except Exception as exc:  # catch-all: per-chunk re-embed isolation
                logger.warning(
                    "Re-embed failed for chunk",
                    extra={
                        "event": "chunks.re_embed_failed",
                        "chunk_id": row["chunk_id"],
                        "error": str(exc),
                    },
                    exc_info=True,
                )

        return updated

    async def get(
        self, chunk_id: str, user_id: int | None = None
    ) -> MemoryChunk | None:
        """Fetch a single chunk by ID, scoped to user_id."""
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.get")
        logger.debug(
            "get called",
            extra={"event": "chunks.get", "chunk_id": chunk_id, "user_id": user_id},
        )
        resolved_user_id = user_id
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT chunk_id, user_id, content, source, metadata, "
                    "created_at, updated_at FROM memory_chunks "
                    "WHERE chunk_id = $1 AND user_id = $2",
                    chunk_id,
                    resolved_user_id,
                )
                if row is None:
                    return None
                return _row_to_chunk(row)

        # In-memory fallback — filter by user_id
        chunk = self._mem.get(chunk_id)
        if chunk is not None and chunk.user_id != resolved_user_id:
            return None
        return chunk

    async def list_chunks(
        self,
        user_id: int | None = None,
        limit: int = 50,
        offset: int = 0,
        source: str | None = None,
    ) -> list[MemoryChunk]:
        """Paginated list of chunks for a user, newest first."""
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.list_chunks")
        logger.debug(
            "list_chunks called",
            extra={
                "event": "chunks.list_chunks",
                "user_id": user_id,
                "limit": limit,
                "offset": offset,
            },
        )
        if self._pool is not None:
            logger.debug(
                "list_chunks: pg query", extra={"event": "chunks.list_chunks.pg"}
            )
            async with self._pool.acquire() as conn:
                if source is not None:
                    logger.debug(
                        "list_chunks: source filter",
                        extra={"event": "chunks.list_chunks.source_filter"},
                    )
                    rows = await conn.fetch(
                        "SELECT chunk_id, user_id, content, source, metadata, "
                        "created_at, updated_at FROM memory_chunks "
                        "WHERE user_id = $1 AND source = $2 "
                        "ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                        user_id,
                        source,
                        limit,
                        offset,
                    )
                else:
                    logger.debug(
                        "list_chunks: clean",
                        extra={"event": "chunks.list_chunks.clean"},
                    )
                    rows = await conn.fetch(
                        "SELECT chunk_id, user_id, content, source, metadata, "
                        "created_at, updated_at FROM memory_chunks "
                        "WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                        user_id,
                        limit,
                        offset,
                    )
                return [_row_to_chunk(r) for r in rows]

        # In-memory fallback
        chunks = [c for c in self._mem.values() if c.user_id == user_id]
        if source is not None:
            logger.debug(
                "list_chunks: match", extra={"event": "chunks.list_chunks.match"}
            )
            chunks = [c for c in chunks if c.source == source]
        chunks.sort(key=lambda c: c.created_at, reverse=True)
        return chunks[offset : offset + limit]

    async def update(
        self,
        chunk_id: str,
        content: str,
        metadata: dict | None = None,
        user_id: int | None = None,
    ) -> bool:
        """Update chunk content. tsvector auto-regenerates. Returns True if found."""
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.update")
        logger.debug(
            "update called",
            extra={
                "event": "chunks.update",
                "chunk_id": chunk_id,
                "content_len": len(content) if hasattr(content, "__len__") else 0,
                "metadata_len": len(metadata) if hasattr(metadata, "__len__") else 0,
            },
        )
        resolved_user_id = user_id
        if self._pool is not None:
            logger.debug("update: match", extra={"event": "chunks.update.match"})
            async with self._pool.acquire() as conn:
                if metadata is not None:
                    logger.debug(
                        "update: match", extra={"event": "chunks.update.match"}
                    )
                    meta_json = json.dumps(metadata)
                    result = await conn.execute(
                        "UPDATE memory_chunks SET content = $1, metadata = $2::jsonb, "
                        "updated_at = NOW() WHERE chunk_id = $3 AND user_id = $4",
                        content,
                        meta_json,
                        chunk_id,
                        resolved_user_id,
                    )
                else:
                    logger.debug(
                        "update: clean", extra={"event": "chunks.update.clean"}
                    )
                    result = await conn.execute(
                        "UPDATE memory_chunks SET content = $1, "
                        "updated_at = NOW() WHERE chunk_id = $2 AND user_id = $3",
                        content,
                        chunk_id,
                        resolved_user_id,
                    )
                # asyncpg returns "UPDATE N" where N is affected rows
                return result == "UPDATE 1"

        # In-memory fallback — filter by user_id
        chunk = self._mem.get(chunk_id)
        if chunk is None or chunk.user_id != resolved_user_id:
            return False
        chunk.content = content
        if metadata is not None:
            logger.debug("update: match", extra={"event": "chunks.update.match"})
            chunk.metadata = metadata
        return True

    async def delete(self, chunk_id: str, user_id: int | None = None) -> bool:
        """Delete a chunk. No FTS/vec cleanup needed — cascades automatically.

        Raises ValueError for system-protected entries (source starts with 'system:').
        """
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.delete")
        resolved_user_id = user_id
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                # Check existence and source for system protection
                row = await conn.fetchrow(
                    "SELECT source FROM memory_chunks "
                    "WHERE chunk_id = $1 AND user_id = $2",
                    chunk_id,
                    resolved_user_id,
                )
                if row is None:
                    return False

                if row["source"].startswith("system:"):
                    raise ValueError("Cannot delete system-protected memory entries")

                result = await conn.execute(
                    "DELETE FROM memory_chunks WHERE chunk_id = $1 AND user_id = $2",
                    chunk_id,
                    resolved_user_id,
                )

            logger.info(
                "Memory chunk deleted",
                extra={"event": "memory.delete", "chunk_id": chunk_id},
            )
            return result == "DELETE 1"

        # In-memory fallback — filter by user_id
        chunk = self._mem.get(chunk_id)
        if chunk is None or chunk.user_id != resolved_user_id:
            return False
        if chunk.source.startswith("system:"):
            raise ValueError("Cannot delete system-protected memory entries")
        del self._mem[chunk_id]
        return True

    async def get_latest_by_source(
        self,
        source: str,
        user_id: int | None = None,
    ) -> MemoryChunk | None:
        """Return the most recent chunk with the given source, or None."""
        # Q4-F9: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "MemoryStore.get_latest_by_source")
        logger.debug(
            "get_latest_by_source called",
            extra={
                "event": "chunks.get_latest_by_source",
                "source_len": len(source) if hasattr(source, "__len__") else 0,
                "user_id": user_id,
            },
        )
        resolved_user_id = user_id
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT chunk_id, user_id, content, source, metadata, "
                    "created_at, updated_at FROM memory_chunks "
                    "WHERE source = $1 AND user_id = $2 "
                    "ORDER BY created_at DESC LIMIT 1",
                    source,
                    resolved_user_id,
                )
                if row is None:
                    return None
                return _row_to_chunk(row)

        # In-memory fallback — filter by user_id
        matches = [
            c
            for c in self._mem.values()
            if c.source == source and c.user_id == resolved_user_id
        ]
        if not matches:
            return None
        matches.sort(key=lambda c: c.created_at, reverse=True)
        return matches[0]

    async def close(self) -> None:
        """No-op — pool lifecycle managed by app lifespan."""


if TYPE_CHECKING:
    from sentinel.core.store_protocols import MemoryStoreProtocol

    _: MemoryStoreProtocol = cast("MemoryStoreProtocol", MemoryStore(None))
