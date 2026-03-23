"""Provenance tracking with trust inheritance.

ProvenanceStore class handles PostgreSQL-backed provenance tracking.
Module-level functions delegate to a default store for backward compatibility
(10+ files import from here; zero changes needed in callers).

When pool is None, uses in-memory dicts (for tests).
When pool is provided, uses asyncpg with JSONB parent_ids.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

from sentinel.core.context import current_user_id, get_task_id
from sentinel.core.models import DataSource, TaggedData, TrustLevel

logger = logging.getLogger("sentinel.audit")

MAX_PROVENANCE_ENTRIES = 10_000
MAX_FILE_PROVENANCE_ENTRIES = 10_000


def _dt_to_iso(dt: datetime | None) -> str:
    if dt is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row_to_tagged(row: Any) -> TaggedData:
    """Convert an asyncpg Record to a TaggedData instance."""
    parent_ids = row["parent_ids"]
    if isinstance(parent_ids, str):
        parent_ids = json.loads(parent_ids)
    elif parent_ids is None:
        parent_ids = []
    # asyncpg returns JSONB as native list — no parsing needed in that case

    return TaggedData(
        id=row["data_id"],
        content=row["content"],
        trust_level=TrustLevel(row["trust_level"]),
        source=DataSource(row["source"]),
        originated_from=row["originated_from"],
        derived_from=parent_ids,
        timestamp=row["created_at"] if isinstance(row["created_at"], datetime)
        else datetime.now(timezone.utc),
    )


class ProvenanceStore:
    """Provenance store backed by PostgreSQL or in-memory dict.

    When pool is None, uses in-memory dicts (for tests).
    When pool is provided, uses asyncpg with the provenance and file_provenance tables.
    """

    def __init__(self, pool: Any = None):
        self._pool = pool
        self._in_memory = pool is None
        if self._in_memory:
            self._store: dict[str, TaggedData] = {}
            self._file_provenance: dict[str, str] = {}

    async def reset_store(self) -> None:
        """Clear all provenance data (used in tests)."""
        if self._in_memory:
            self._store.clear()
            self._file_provenance.clear()
            return
        async with self._pool.acquire() as conn:
            # Delete file_provenance first (FK references provenance)
            await conn.execute("DELETE FROM file_provenance")
            await conn.execute("DELETE FROM provenance")

    async def create_tagged_data(
        self,
        content: str,
        source: DataSource,
        trust_level: TrustLevel,
        originated_from: str = "",
        parent_ids: list[str] | None = None,
        user_id: int | None = None,
    ) -> TaggedData:
        """Create a new TaggedData entry with trust inheritance."""
        effective_trust = trust_level
        derived = list(parent_ids) if parent_ids else []

        if parent_ids:
            for pid in parent_ids:
                parent = await self.get_tagged_data(pid)
                if parent is None:
                    effective_trust = TrustLevel.UNTRUSTED
                    break
                if parent.trust_level == TrustLevel.UNTRUSTED:
                    effective_trust = TrustLevel.UNTRUSTED
                    break

        # Resolve user_id: explicit param > ContextVar > 0 (orphan)
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if resolved_user_id == 0:
            logger.warning(
                "provenance_orphan: user_id resolved to 0",
                extra={
                    "source": source.value,
                    "trust_level": trust_level.value,
                    "task_id": get_task_id(),
                },
            )

        tagged = TaggedData(
            id=str(uuid.uuid4()),
            content=content,
            trust_level=effective_trust,
            source=source,
            originated_from=originated_from,
            timestamp=datetime.now(timezone.utc),
            derived_from=derived,
        )

        if self._in_memory:
            self._store[tagged.id] = tagged
            self._evict_oldest(self._store, MAX_PROVENANCE_ENTRIES)
            return tagged

        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO provenance "
                "(data_id, content, source, trust_level, originated_from, parent_ids, user_id) "
                "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)",
                tagged.id,
                tagged.content,
                tagged.source.value,
                tagged.trust_level.value,
                tagged.originated_from,
                json.dumps(tagged.derived_from),
                resolved_user_id,
            )

        return tagged

    async def get_tagged_data(
        self, data_id: str, user_id: int | None = None,
    ) -> TaggedData | None:
        """Retrieve a single provenance entry by data_id.

        When user_id is provided, only returns the entry if it belongs to
        that user (RLS defence-in-depth at the application layer).
        """
        if self._in_memory:
            return self._store.get(data_id)
        if user_id is not None:
            sql = (
                "SELECT data_id, content, source, trust_level, originated_from, "
                "parent_ids, created_at "
                "FROM provenance WHERE data_id = $1 AND user_id = $2"
            )
            params: tuple = (data_id, user_id)
        else:
            sql = (
                "SELECT data_id, content, source, trust_level, originated_from, "
                "parent_ids, created_at "
                "FROM provenance WHERE data_id = $1"
            )
            params = (data_id,)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *params)
            if row is None:
                return None
            return _row_to_tagged(row)

    async def update_content(
        self, data_id: str, content: str, user_id: int | None = None,
    ) -> bool:
        """Update the content of an existing provenance entry.

        When user_id is provided, only updates if the entry belongs to that
        user (defence-in-depth: application-layer isolation on top of RLS).
        """
        if self._in_memory:
            item = self._store.get(data_id)
            if item is not None:
                item.content = content
                return True
            return False
        if user_id is not None:
            sql = "UPDATE provenance SET content = $1 WHERE data_id = $2 AND user_id = $3"
            params: tuple = (content, data_id, user_id)
        else:
            sql = "UPDATE provenance SET content = $1 WHERE data_id = $2"
            params = (content, data_id)
        async with self._pool.acquire() as conn:
            result = await conn.execute(sql, *params)
            # asyncpg returns "UPDATE N"
            return result == "UPDATE 1"

    async def get_provenance_chain(
        self, data_id: str, max_depth: int = 50,
        user_id: int | None = None,
    ) -> list[TaggedData]:
        """Walk the provenance chain back to the roots.

        When user_id is provided, the recursive CTE still walks across all
        users (trust inheritance is global) but the final SELECT only returns
        nodes belonging to that user.
        """
        if self._in_memory:
            return self._get_provenance_chain_mem(data_id, max_depth)

        # Build optional user_id filter on the final SELECT
        if user_id is not None:
            user_filter = "AND p.user_id = $3"
            params: tuple = (data_id, max_depth, user_id)
        else:
            user_filter = ""
            params = (data_id, max_depth)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""
                WITH RECURSIVE chain(data_id, depth) AS (
                    SELECT $1::text, 0
                    UNION
                    SELECT j.value::text, chain.depth + 1
                    FROM chain
                    JOIN provenance p ON p.data_id = chain.data_id
                    CROSS JOIN LATERAL jsonb_array_elements_text(p.parent_ids) AS j(value)
                    WHERE chain.depth < $2
                )
                SELECT DISTINCT p.data_id, p.content, p.source, p.trust_level,
                       p.originated_from, p.parent_ids, p.created_at
                FROM chain
                JOIN provenance p ON p.data_id = chain.data_id
                {user_filter}
                """,
                *params,
            )
            return [_row_to_tagged(r) for r in rows]

    async def is_trust_safe_for_execution(self, data_id: str) -> bool:
        """Check whether data (and all its ancestors) are trusted.

        Returns False for unknown data_ids (empty chain) — unknown = untrusted.
        """
        chain = await self.get_provenance_chain(data_id)
        if not chain:
            return False
        return all(item.trust_level == TrustLevel.TRUSTED for item in chain)

    async def record_file_write(
        self, path: str, data_id: str, content: str | bytes = "",
        user_id: int | None = None,
    ) -> None:
        """Record that a file was written by a specific provenance chain entry.

        Stores a SHA-256 hash of *content* so that ``get_file_writer`` can
        later verify the file hasn't been overwritten outside the pipeline
        (prevents trust laundering via the provenance-overwrite attack).
        """
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        content_bytes = content.encode() if isinstance(content, str) else content
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        if self._in_memory:
            self._file_provenance[path] = (data_id, content_hash)
            self._evict_oldest(self._file_provenance, MAX_FILE_PROVENANCE_ENTRIES)
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO file_provenance (file_path, writer_data_id, user_id, content_sha256) "
                "VALUES ($1, $2, $3, $4) "
                "ON CONFLICT (file_path) DO UPDATE SET "
                "writer_data_id = EXCLUDED.writer_data_id, user_id = EXCLUDED.user_id, "
                "content_sha256 = EXCLUDED.content_sha256, created_at = NOW()",
                path, data_id, resolved_user_id, content_hash,
            )

    async def get_file_writer(
        self, path: str, user_id: int | None = None,
    ) -> tuple[str, str] | None:
        """Get the (data_id, content_sha256) of the last provenance write to this file.

        Returns None if no provenance record exists.
        When user_id is provided, only matches writes by that user.
        """
        if self._in_memory:
            return self._file_provenance.get(path)
        if user_id is not None:
            sql = ("SELECT writer_data_id, content_sha256 FROM file_provenance "
                   "WHERE file_path = $1 AND user_id = $2")
            params: tuple = (path, user_id)
        else:
            sql = ("SELECT writer_data_id, content_sha256 FROM file_provenance "
                   "WHERE file_path = $1")
            params = (path,)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *params)
            if row is None:
                return None
            return (row["writer_data_id"], row["content_sha256"])

    async def cleanup_old(self, days: int = 7) -> int:
        """Delete provenance entries older than N days."""
        if self._in_memory:
            return 0
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Delete file_provenance rows referencing old entries
                await conn.execute(
                    "DELETE FROM file_provenance WHERE writer_data_id IN ("
                    "  SELECT data_id FROM provenance "
                    "  WHERE created_at < NOW() - INTERVAL '1 day' * $1"
                    ")",
                    days,
                )
                result = await conn.execute(
                    "DELETE FROM provenance "
                    "WHERE created_at < NOW() - INTERVAL '1 day' * $1",
                    days,
                )
                # asyncpg returns "DELETE N"
                deleted = int(result.split()[-1]) if result else 0

        if deleted > 0:
            logger.info(
                "Provenance cleanup",
                extra={"event": "provenance_cleanup", "deleted": deleted, "days": days},
            )
        return deleted

    # ── In-memory helpers ──────────────────────────────────────

    def _get_provenance_chain_mem(self, data_id: str, max_depth: int) -> list[TaggedData]:
        chain: list[TaggedData] = []
        visited: set[str] = set()
        queue = [data_id]

        while queue and len(chain) < max_depth:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)

            item = self._store.get(current_id)
            if item is None:
                continue

            chain.append(item)
            for parent_id in item.derived_from:
                if parent_id not in visited:
                    queue.append(parent_id)

        return chain

    @staticmethod
    def _evict_oldest(store: dict, max_size: int) -> None:
        if len(store) > max_size:
            excess = len(store) - max_size
            for key in list(store.keys())[:excess]:
                del store[key]


# ── Module-level default store + wrapper functions ─────────────

_default_store = ProvenanceStore(pool=None)
_store_lock = threading.Lock()  # C-004: protect default store swap


def set_default_store(store: ProvenanceStore) -> None:
    """Switch the default provenance store (called at app startup with PG store)."""
    global _default_store
    with _store_lock:
        _default_store = store


async def reset_store() -> None:
    """Clear the provenance store and file provenance registry (used in tests)."""
    await _default_store.reset_store()


async def create_tagged_data(
    content: str,
    source: DataSource,
    trust_level: TrustLevel,
    originated_from: str = "",
    parent_ids: list[str] | None = None,
    user_id: int | None = None,
) -> TaggedData:
    return await _default_store.create_tagged_data(
        content, source, trust_level, originated_from, parent_ids, user_id,
    )


async def get_tagged_data(data_id: str, user_id: int | None = None) -> TaggedData | None:
    return await _default_store.get_tagged_data(data_id, user_id=user_id)


async def get_provenance_chain(
    data_id: str, max_depth: int = 50, user_id: int | None = None,
) -> list[TaggedData]:
    return await _default_store.get_provenance_chain(data_id, max_depth, user_id=user_id)


async def is_trust_safe_for_execution(data_id: str) -> bool:
    return await _default_store.is_trust_safe_for_execution(data_id)


async def record_file_write(
    path: str, data_id: str, content: str | bytes = "",
    user_id: int | None = None,
) -> None:
    await _default_store.record_file_write(path, data_id, content=content, user_id=user_id)


async def get_file_writer(path: str, user_id: int | None = None) -> tuple[str, str] | None:
    return await _default_store.get_file_writer(path, user_id=user_id)


async def update_content(data_id: str, content: str, user_id: int | None = None) -> bool:
    return await _default_store.update_content(data_id, content, user_id=user_id)


if TYPE_CHECKING:
    from sentinel.core.store_protocols import ProvenanceStoreProtocol

    _: ProvenanceStoreProtocol = cast(ProvenanceStoreProtocol, ProvenanceStore())
