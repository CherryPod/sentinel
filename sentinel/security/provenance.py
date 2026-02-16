"""Provenance tracking with trust inheritance.

ProvenanceStore class handles SQLite-backed provenance tracking.
Module-level functions delegate to a default store for backward compatibility
(10+ files import from here; zero changes needed in callers).
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from sentinel.core.models import DataSource, TaggedData, TrustLevel

MAX_PROVENANCE_ENTRIES = 10_000
MAX_FILE_PROVENANCE_ENTRIES = 10_000


class ProvenanceStore:
    """Provenance store backed by SQLite or in-memory dict.

    When db is None, uses in-memory dicts (backward compat for tests).
    When db is provided, uses the provenance and file_provenance tables.
    """

    def __init__(self, db: sqlite3.Connection | None = None):
        self._db = db
        # In-memory fallback (used when db is None)
        self._store: dict[str, TaggedData] = {}
        self._file_provenance: dict[str, str] = {}

    def reset_store(self) -> None:
        """Clear all provenance data (used in tests)."""
        self._store.clear()
        self._file_provenance.clear()
        if self._db is not None:
            # Delete file_provenance first (FK references provenance)
            self._db.execute("DELETE FROM file_provenance")
            self._db.execute("DELETE FROM provenance")
            self._db.commit()

    def create_tagged_data(
        self,
        content: str,
        source: DataSource,
        trust_level: TrustLevel,
        originated_from: str = "",
        parent_ids: list[str] | None = None,
    ) -> TaggedData:
        """Create a new TaggedData entry with trust inheritance.

        If any parent is untrusted, the child inherits untrusted regardless
        of the explicitly passed trust_level.
        """
        effective_trust = trust_level
        derived = list(parent_ids) if parent_ids else []

        if parent_ids:
            for pid in parent_ids:
                parent = self.get_tagged_data(pid)
                if parent and parent.trust_level == TrustLevel.UNTRUSTED:
                    effective_trust = TrustLevel.UNTRUSTED
                    break

        tagged = TaggedData(
            id=str(uuid.uuid4()),
            content=content,
            trust_level=effective_trust,
            source=source,
            originated_from=originated_from,
            timestamp=datetime.now(timezone.utc),
            derived_from=derived,
        )

        if self._db is not None:
            self._db.execute(
                "INSERT INTO provenance (data_id, content, source, trust_level, originated_from, parent_ids) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    tagged.id,
                    tagged.content,
                    tagged.source.value,
                    tagged.trust_level.value,
                    tagged.originated_from,
                    json.dumps(tagged.derived_from),
                ),
            )
            self._db.commit()
        else:
            self._store[tagged.id] = tagged
            self._evict_oldest(self._store, MAX_PROVENANCE_ENTRIES)

        return tagged

    def get_tagged_data(self, data_id: str) -> TaggedData | None:
        if self._db is not None:
            return self._get_tagged_data_sql(data_id)
        return self._store.get(data_id)

    def get_provenance_chain(self, data_id: str, max_depth: int = 50) -> list[TaggedData]:
        """Walk the provenance chain back to the roots.

        Returns a list ordered from the given item back to its oldest ancestor.
        Includes cycle detection via a visited set.
        """
        if self._db is not None:
            return self._get_provenance_chain_sql(data_id, max_depth)
        return self._get_provenance_chain_mem(data_id, max_depth)

    def is_trust_safe_for_execution(self, data_id: str) -> bool:
        """Check whether data (and all its ancestors) are trusted."""
        chain = self.get_provenance_chain(data_id)
        return all(item.trust_level == TrustLevel.TRUSTED for item in chain)

    def record_file_write(self, path: str, data_id: str) -> None:
        """Record that a file was written by a specific provenance chain entry."""
        if self._db is not None:
            self._db.execute(
                "INSERT OR REPLACE INTO file_provenance (file_path, writer_data_id) VALUES (?, ?)",
                (path, data_id),
            )
            self._db.commit()
        else:
            self._file_provenance[path] = data_id
            self._evict_oldest(self._file_provenance, MAX_FILE_PROVENANCE_ENTRIES)

    def get_file_writer(self, path: str) -> str | None:
        """Get the data_id of the provenance entry that last wrote to this file."""
        if self._db is not None:
            row = self._db.execute(
                "SELECT writer_data_id FROM file_provenance WHERE file_path = ?",
                (path,),
            ).fetchone()
            return row[0] if row else None
        return self._file_provenance.get(path)

    # ── SQLite helpers ─────────────────────────────────────────

    def _get_tagged_data_sql(self, data_id: str) -> TaggedData | None:
        row = self._db.execute(
            "SELECT data_id, content, source, trust_level, originated_from, parent_ids, created_at "
            "FROM provenance WHERE data_id = ?",
            (data_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_tagged(row)

    def _get_provenance_chain_sql(self, data_id: str, max_depth: int) -> list[TaggedData]:
        """Walk the provenance chain using a recursive CTE."""
        # Use recursive CTE with json_each to walk parent_ids
        rows = self._db.execute("""
            WITH RECURSIVE chain(data_id, depth) AS (
                SELECT ?, 0
                UNION
                SELECT j.value, chain.depth + 1
                FROM chain
                JOIN provenance p ON p.data_id = chain.data_id
                JOIN json_each(p.parent_ids) j
                WHERE chain.depth < ?
            )
            SELECT DISTINCT p.data_id, p.content, p.source, p.trust_level,
                   p.originated_from, p.parent_ids, p.created_at
            FROM chain
            JOIN provenance p ON p.data_id = chain.data_id
        """, (data_id, max_depth)).fetchall()
        return [self._row_to_tagged(r) for r in rows]

    def _row_to_tagged(self, row) -> TaggedData:
        data_id, content, source, trust_level, originated_from, parent_ids, created_at = row
        return TaggedData(
            id=data_id,
            content=content,
            trust_level=TrustLevel(trust_level),
            source=DataSource(source),
            originated_from=originated_from,
            derived_from=json.loads(parent_ids) if parent_ids else [],
            timestamp=datetime.fromisoformat(created_at.replace("Z", "+00:00")) if created_at else datetime.now(timezone.utc),
        )

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

_default_store = ProvenanceStore(db=None)


def set_default_store(store: ProvenanceStore) -> None:
    """Switch the default provenance store (called at app startup with SQLite store)."""
    global _default_store
    _default_store = store


def reset_store() -> None:
    """Clear the provenance store and file provenance registry (used in tests)."""
    _default_store.reset_store()


def create_tagged_data(
    content: str,
    source: DataSource,
    trust_level: TrustLevel,
    originated_from: str = "",
    parent_ids: list[str] | None = None,
) -> TaggedData:
    return _default_store.create_tagged_data(
        content, source, trust_level, originated_from, parent_ids,
    )


def get_tagged_data(data_id: str) -> TaggedData | None:
    return _default_store.get_tagged_data(data_id)


def get_provenance_chain(data_id: str, max_depth: int = 50) -> list[TaggedData]:
    return _default_store.get_provenance_chain(data_id, max_depth)


def is_trust_safe_for_execution(data_id: str) -> bool:
    return _default_store.is_trust_safe_for_execution(data_id)


def record_file_write(path: str, data_id: str) -> None:
    _default_store.record_file_write(path, data_id)


def get_file_writer(path: str) -> str | None:
    return _default_store.get_file_writer(path)
