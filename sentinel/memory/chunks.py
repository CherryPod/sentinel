"""Memory chunk store — CRUD with FTS5 and sqlite-vec sync.

Follows the dual-mode pattern from session/store.py and security/provenance.py:
SQLite for persistence, in-memory dict fallback for tests without a database.

FTS5 and vec tables are synced at the application layer (not via triggers)
because the FTS5 content table uses content=memory_chunks which requires
explicit INSERT/DELETE to keep in sync.
"""

import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field

logger = logging.getLogger("sentinel.audit")


@dataclass
class MemoryChunk:
    """A stored memory chunk with metadata."""

    chunk_id: str
    user_id: str
    content: str
    source: str
    metadata: dict
    created_at: str
    updated_at: str


class MemoryStore:
    """CRUD store for memory chunks with FTS5 and sqlite-vec index sync.

    When db is None, falls back to in-memory dict (useful for tests).
    """

    def __init__(self, db: sqlite3.Connection | None = None):
        self._db = db
        self._mem: dict[str, MemoryChunk] = {}  # fallback for tests
        self._has_vec: bool | None = None  # cached check

    def store(
        self,
        content: str,
        source: str = "",
        metadata: dict | None = None,
        user_id: str = "default",
    ) -> str:
        """Insert a chunk and sync FTS5. Returns chunk_id."""
        chunk_id = str(uuid.uuid4())
        meta_json = json.dumps(metadata or {})

        if self._db is not None:
            self._db.execute(
                "INSERT INTO memory_chunks "
                "(chunk_id, user_id, content, source, metadata) "
                "VALUES (?, ?, ?, ?, ?)",
                (chunk_id, user_id, content, source, meta_json),
            )
            self._sync_fts_insert(chunk_id, content, source)
            self._db.commit()
        else:
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
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
                "event": "memory_store",
                "chunk_id": chunk_id,
                "source": source,
                "content_length": len(content),
            },
        )
        return chunk_id

    def store_with_embedding(
        self,
        content: str,
        embedding: list[float],
        source: str = "",
        metadata: dict | None = None,
        user_id: str = "default",
    ) -> str:
        """Insert a chunk with FTS5 + vec sync. Returns chunk_id."""
        chunk_id = str(uuid.uuid4())
        meta_json = json.dumps(metadata or {})

        if self._db is not None:
            self._db.execute(
                "INSERT INTO memory_chunks "
                "(chunk_id, user_id, content, source, metadata) "
                "VALUES (?, ?, ?, ?, ?)",
                (chunk_id, user_id, content, source, meta_json),
            )
            self._sync_fts_insert(chunk_id, content, source)
            self._sync_vec_insert(chunk_id, embedding)
            self._db.commit()
        else:
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
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
            "Memory chunk stored with embedding",
            extra={
                "event": "memory_store_embedded",
                "chunk_id": chunk_id,
                "source": source,
                "content_length": len(content),
                "embedding_dims": len(embedding),
            },
        )
        return chunk_id

    def get(self, chunk_id: str) -> MemoryChunk | None:
        """Fetch a single chunk by ID."""
        if self._db is not None:
            row = self._db.execute(
                "SELECT chunk_id, user_id, content, source, metadata, "
                "created_at, updated_at FROM memory_chunks WHERE chunk_id = ?",
                (chunk_id,),
            ).fetchone()
            if row is None:
                return None
            return MemoryChunk(
                chunk_id=row[0],
                user_id=row[1],
                content=row[2],
                source=row[3],
                metadata=json.loads(row[4]),
                created_at=row[5],
                updated_at=row[6],
            )
        return self._mem.get(chunk_id)

    def list_chunks(
        self,
        user_id: str = "default",
        limit: int = 50,
        offset: int = 0,
    ) -> list[MemoryChunk]:
        """Paginated list of chunks for a user, newest first."""
        if self._db is not None:
            rows = self._db.execute(
                "SELECT chunk_id, user_id, content, source, metadata, "
                "created_at, updated_at FROM memory_chunks "
                "WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (user_id, limit, offset),
            ).fetchall()
            return [
                MemoryChunk(
                    chunk_id=r[0],
                    user_id=r[1],
                    content=r[2],
                    source=r[3],
                    metadata=json.loads(r[4]),
                    created_at=r[5],
                    updated_at=r[6],
                )
                for r in rows
            ]

        # In-memory fallback
        chunks = [c for c in self._mem.values() if c.user_id == user_id]
        chunks.sort(key=lambda c: c.created_at, reverse=True)
        return chunks[offset : offset + limit]

    def update(self, chunk_id: str, content: str, metadata: dict | None = None) -> bool:
        """Update chunk content and re-sync FTS5. Returns True if found."""
        if self._db is not None:
            # Check existence
            existing = self._db.execute(
                "SELECT source FROM memory_chunks WHERE chunk_id = ?",
                (chunk_id,),
            ).fetchone()
            if existing is None:
                return False

            source = existing[0]
            meta_json = json.dumps(metadata) if metadata is not None else None

            # Delete old FTS5 entry, update row, insert new FTS5 entry
            self._sync_fts_delete(chunk_id)

            if meta_json is not None:
                self._db.execute(
                    "UPDATE memory_chunks SET content = ?, metadata = ?, "
                    "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
                    "WHERE chunk_id = ?",
                    (content, meta_json, chunk_id),
                )
            else:
                self._db.execute(
                    "UPDATE memory_chunks SET content = ?, "
                    "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
                    "WHERE chunk_id = ?",
                    (content, chunk_id),
                )

            self._sync_fts_insert(chunk_id, content, source)
            self._db.commit()
            return True

        # In-memory fallback
        chunk = self._mem.get(chunk_id)
        if chunk is None:
            return False
        chunk.content = content
        if metadata is not None:
            chunk.metadata = metadata
        return True

    def delete(self, chunk_id: str) -> bool:
        """Delete chunk from all tables (chunk, FTS5, vec). Returns True if found."""
        if self._db is not None:
            existing = self._db.execute(
                "SELECT chunk_id FROM memory_chunks WHERE chunk_id = ?",
                (chunk_id,),
            ).fetchone()
            if existing is None:
                return False

            self._sync_fts_delete(chunk_id)
            self._sync_vec_delete(chunk_id)
            self._db.execute(
                "DELETE FROM memory_chunks WHERE chunk_id = ?",
                (chunk_id,),
            )
            self._db.commit()

            logger.info(
                "Memory chunk deleted",
                extra={"event": "memory_delete", "chunk_id": chunk_id},
            )
            return True

        # In-memory fallback
        if chunk_id in self._mem:
            del self._mem[chunk_id]
            return True
        return False

    # ── FTS5 sync (application-layer) ──────────────────────────────

    def _sync_fts_insert(self, chunk_id: str, content: str, source: str) -> None:
        """Insert into FTS5 index using the chunk's rowid."""
        if self._db is None:
            return
        self._db.execute(
            "INSERT INTO memory_chunks_fts(rowid, content, source) "
            "VALUES ((SELECT rowid FROM memory_chunks WHERE chunk_id = ?), ?, ?)",
            (chunk_id, content, source),
        )

    def _sync_fts_delete(self, chunk_id: str) -> None:
        """Delete from FTS5 index using the chunk's rowid and current content."""
        if self._db is None:
            return
        # FTS5 content-sync tables require delete with matching content values
        row = self._db.execute(
            "SELECT rowid, content, source FROM memory_chunks WHERE chunk_id = ?",
            (chunk_id,),
        ).fetchone()
        if row is not None:
            self._db.execute(
                "INSERT INTO memory_chunks_fts(memory_chunks_fts, rowid, content, source) "
                "VALUES ('delete', ?, ?, ?)",
                (row[0], row[1], row[2]),
            )

    # ── sqlite-vec sync (application-layer) ────────────────────────

    def _has_vec_table(self) -> bool:
        """Check if the memory_chunks_vec table exists (cached)."""
        if self._has_vec is not None:
            return self._has_vec
        if self._db is None:
            self._has_vec = False
            return False
        try:
            self._db.execute(
                "SELECT count(*) FROM memory_chunks_vec LIMIT 1"
            )
            self._has_vec = True
        except sqlite3.OperationalError:
            self._has_vec = False
        return self._has_vec

    def _sync_vec_insert(self, chunk_id: str, embedding: list[float]) -> None:
        """Insert into vec table if available."""
        if not self._has_vec_table():
            return
        # sqlite-vec expects the embedding as a JSON array string or bytes
        import struct

        vec_bytes = struct.pack(f"{len(embedding)}f", *embedding)
        self._db.execute(  # type: ignore[union-attr]
            "INSERT INTO memory_chunks_vec(chunk_id, embedding) VALUES (?, ?)",
            (chunk_id, vec_bytes),
        )

    def _sync_vec_delete(self, chunk_id: str) -> None:
        """Delete from vec table if available."""
        if not self._has_vec_table():
            return
        self._db.execute(  # type: ignore[union-attr]
            "DELETE FROM memory_chunks_vec WHERE chunk_id = ?",
            (chunk_id,),
        )
