"""Episodic fact storage — extracted from EpisodicStore.

Handles storage and full-text search of extracted facts linked to episodic
records. PostgreSQL uses tsvector for search; in-memory fallback uses
case-insensitive substring matching.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sentinel.core.context import require_user_id
from sentinel.memory.episodic import EpisodicFact, _now_iso, _row_to_fact

logger = logging.getLogger(__name__)


class EpisodicFactIndex:
    """Stores and searches episodic facts (keywords, patterns, file references).

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

    async def store_facts(
        self,
        record_id: str,
        facts: list[EpisodicFact],
        user_id: int | None = None,
    ) -> None:
        """Store extracted facts for a record.

        tsvector search_vector is GENERATED ALWAYS AS STORED — no manual sync.
        """
        # Q4-F7: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicFactIndex.store_facts")
        logger.debug(
            "store_facts called",
            extra={
                "event": "episodic.store_facts",
                "record_id": record_id,
                "facts_count": len(facts),
                "user_id": user_id,
                "backend": "pg" if self._pool is not None else "memory",
            },
        )
        if self._pool is not None:
            async with self._pool.acquire() as conn, conn.transaction():
                for fact in facts:
                    fact_id = fact.fact_id or str(uuid.uuid4())
                    await conn.execute(
                        "INSERT INTO episodic_facts "
                        "(fact_id, record_id, fact_type, content, file_path, user_id) "
                        "VALUES ($1, $2, $3, $4, $5, $6)",
                        fact_id,
                        record_id,
                        fact.fact_type,
                        fact.content,
                        fact.file_path,
                        user_id,
                    )
        else:
            if record_id not in self._facts:
                logger.debug(
                    "store_facts: new record_id",
                    extra={"event": "episodic.store_facts.mem.new_record"},
                )
                self._facts[record_id] = []
            now = _now_iso()
            for fact in facts:
                stored = EpisodicFact(
                    fact_id=fact.fact_id or str(uuid.uuid4()),
                    record_id=record_id,
                    fact_type=fact.fact_type,
                    content=fact.content,
                    file_path=fact.file_path,
                    created_at=fact.created_at or now,
                    user_id=user_id,
                )
                self._facts[record_id].append(stored)

    async def search_facts(
        self,
        query: str,
        fact_type: str | None = None,
        user_id: int | None = None,
        limit: int = 20,
    ) -> list[EpisodicFact]:
        """Search facts via tsvector full-text search."""
        # Q4-F7: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicFactIndex.search_facts")
        if not query or not query.strip():
            logger.debug(
                "search_facts: empty query",
                extra={"event": "episodic.search_facts.empty_query"},
            )
            return []

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if fact_type:
                    logger.debug(
                        "search_facts: db filtered",
                        extra={"event": "episodic.search_facts.db.filtered"},
                    )
                    rows = await conn.fetch(
                        "SELECT fact_id, record_id, fact_type, content, file_path, "
                        "created_at, user_id "
                        "FROM episodic_facts "
                        "WHERE search_vector @@ plainto_tsquery('english', $1) "
                        "AND fact_type = $2 AND user_id = $3 "
                        "ORDER BY ts_rank_cd(search_vector, plainto_tsquery('english', $1)) DESC "
                        "LIMIT $4",
                        query,
                        fact_type,
                        user_id,
                        limit,
                    )
                else:
                    logger.debug(
                        "search_facts: db unfiltered",
                        extra={"event": "episodic.search_facts.db.unfiltered"},
                    )
                    rows = await conn.fetch(
                        "SELECT fact_id, record_id, fact_type, content, file_path, "
                        "created_at, user_id "
                        "FROM episodic_facts "
                        "WHERE search_vector @@ plainto_tsquery('english', $1) "
                        "AND user_id = $2 "
                        "ORDER BY ts_rank_cd(search_vector, plainto_tsquery('english', $1)) DESC "
                        "LIMIT $3",
                        query,
                        user_id,
                        limit,
                    )

                return [_row_to_fact(r) for r in rows]

        # In-memory fallback: simple case-insensitive substring match
        query_lower = query.lower()
        results: list[EpisodicFact] = []
        for fact_list in self._facts.values():
            for fact in fact_list:
                if fact.user_id != user_id:
                    continue
                if fact_type and fact.fact_type != fact_type:
                    continue
                if query_lower in fact.content.lower():
                    results.append(fact)
                    if len(results) >= limit:
                        logger.debug(
                            "search_facts: mem limit reached",
                            extra={
                                "event": "episodic.search_facts.mem.limit_reached",
                                "limit": limit,
                            },
                        )
                        return results
        return results
