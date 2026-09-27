"""Anchor map storage — extracted from EpisodicStore.

Handles CRUD for anchor map facts (file_path → symbol mapping) stored in the
``episodic_facts`` table with ``fact_type = 'anchor_map'``. Uses a partial
unique index ``(fact_type, file_path, user_id)`` for race-free upserts.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.core.context import require_user_id
from sentinel.memory.episodic import EpisodicFact, _now_iso, _row_to_fact

logger = logging.getLogger(__name__)


class AnchorMapStore:
    """CRUD operations for anchor map facts.

    Operates against the ``episodic_facts`` table when a pool is provided,
    or against a shared in-memory ``_facts`` dict otherwise.

    Parameters
    ----------
    pool : asyncpg pool or None
        Database connection pool. ``None`` activates in-memory fallback.
    facts_dict : dict
        Shared ``record_id → list[EpisodicFact]`` dict for in-memory mode.
        Passed by reference from EpisodicStore so both classes see the same data.
    """

    def __init__(
        self,
        pool: Any = None,
        facts_dict: dict[str, list[EpisodicFact]] | None = None,
    ):
        self._pool = pool
        self._facts = facts_dict if facts_dict is not None else {}

    async def upsert_anchor_map(
        self,
        fact_id: str,
        record_id: str,
        content: str,
        file_path: str,
        user_id: int | None = None,
    ) -> None:
        """Atomically insert or update an anchor map fact.

        Uses INSERT ... ON CONFLICT against the idx_anchor_map_unique
        partial index (fact_type, file_path, user_id) so the upsert is
        race-free and doesn't depend on search_facts full-text lookup.
        """
        # Q4-F8: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "AnchorMapStore.upsert_anchor_map")
        logger.debug(
            "upsert_anchor_map called",
            extra={
                "event": "episodic.upsert_anchor_map",
                "file_path": file_path,
                "fact_id": fact_id,
                "record_id": record_id,
                "user_id": user_id,
                "backend": "pg" if self._pool is not None else "memory",
            },
        )
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO episodic_facts "
                    "(fact_id, record_id, fact_type, content, file_path, user_id) "
                    "VALUES ($1, $2, 'anchor_map', $3, $4, $5) "
                    "ON CONFLICT (fact_type, file_path, user_id) "
                    "WHERE fact_type = 'anchor_map' "
                    "DO UPDATE SET content = EXCLUDED.content, "
                    "record_id = EXCLUDED.record_id",
                    fact_id,
                    record_id,
                    content,
                    file_path,
                    user_id,
                )
            logger.debug(
                "upsert_anchor_map completed",
                extra={
                    "event": "episodic.upsert_anchor_map_done",
                    "file_path": file_path,
                    "fact_id": fact_id,
                },
            )
        else:
            # In-memory fallback: replace existing anchor_map for this path
            logger.debug(
                "upsert_anchor_map: clean",
                extra={"event": "episodic.upsert_anchor_map.mem.clean"},
            )
            for rec_facts in self._facts.values():
                rec_facts[:] = [
                    f
                    for f in rec_facts
                    if not (
                        f.fact_type == "anchor_map"
                        and f.file_path == file_path
                        and f.user_id == user_id
                    )
                ]
            if record_id not in self._facts:
                logger.debug(
                    "upsert_anchor_map: match",
                    extra={"event": "episodic.upsert_anchor_map.match"},
                )
                self._facts[record_id] = []
            self._facts[record_id].append(
                EpisodicFact(
                    fact_id=fact_id,
                    record_id=record_id,
                    fact_type="anchor_map",
                    content=content,
                    file_path=file_path,
                    created_at=_now_iso(),
                    user_id=user_id,
                )
            )

    async def get_anchor_map(
        self,
        file_path: str,
        user_id: int | None = None,
    ) -> EpisodicFact | None:
        """Retrieve anchor map by exact file_path (not full-text search)."""
        # Q4-F8: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "AnchorMapStore.get_anchor_map")
        logger.debug(
            "get_anchor_map called",
            extra={
                "event": "episodic.get_anchor_map",
                "file_path": file_path,
                "user_id": user_id,
                "backend": "pg" if self._pool is not None else "memory",
            },
        )
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT fact_id, record_id, fact_type, content, file_path, "
                    "created_at, user_id "
                    "FROM episodic_facts "
                    "WHERE fact_type = 'anchor_map' AND file_path = $1 "
                    "AND user_id = $2 LIMIT 1",
                    file_path,
                    user_id,
                )
                if row is None:
                    logger.debug(
                        "get_anchor_map: no map found",
                        extra={
                            "event": "episodic.get_anchor_map_miss",
                            "file_path": file_path,
                            "user_id": user_id,
                        },
                    )
                    return None
                logger.debug(
                    "get_anchor_map: found",
                    extra={
                        "event": "episodic.get_anchor_map_hit",
                        "file_path": file_path,
                        "fact_id": row["fact_id"],
                    },
                )
                return _row_to_fact(row)
        else:
            logger.debug(
                "get_anchor_map: clean",
                extra={"event": "episodic.get_anchor_map.mem.clean"},
            )
            for rec_facts in self._facts.values():
                for f in rec_facts:
                    if (
                        f.fact_type == "anchor_map"
                        and f.file_path == file_path
                        and f.user_id == user_id
                    ):
                        logger.debug(
                            "get_anchor_map: match",
                            extra={"event": "episodic.get_anchor_map.match"},
                        )
                        return f
            return None

    async def delete_anchor_map(
        self,
        file_path: str,
        user_id: int | None = None,
    ) -> bool:
        """Delete anchor map by exact file_path. Returns True if deleted."""
        # Q4-F8: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "AnchorMapStore.delete_anchor_map")
        logger.debug(
            "delete_anchor_map called",
            extra={
                "event": "episodic.delete_anchor_map",
                "file_path": file_path,
                "user_id": user_id,
            },
        )
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM episodic_facts "
                    "WHERE fact_type = 'anchor_map' AND file_path = $1 "
                    "AND user_id = $2",
                    file_path,
                    user_id,
                )
                deleted = result != "DELETE 0"
                logger.debug(
                    "delete_anchor_map result",
                    extra={
                        "event": "episodic.delete_anchor_map_done",
                        "file_path": file_path,
                        "deleted": deleted,
                    },
                )
                return deleted
        else:
            logger.debug(
                "delete_anchor_map: clean",
                extra={"event": "episodic.delete_anchor_map.mem.clean"},
            )
            deleted = False
            for rec_facts in self._facts.values():
                before = len(rec_facts)
                rec_facts[:] = [
                    f
                    for f in rec_facts
                    if not (
                        f.fact_type == "anchor_map"
                        and f.file_path == file_path
                        and f.user_id == user_id
                    )
                ]
                if len(rec_facts) < before:
                    deleted = True
            return deleted
