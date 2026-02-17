"""PostgreSQL search — FTS (tsvector), vector (pgvector), and RRF hybrid.

Uses PostgreSQL equivalents:
- plainto_tsquery + ts_rank_cd for full-text search
- cosine distance (<=> operator) for vector search
- RRF fusion for hybrid search

When pool is None, returns empty results (for tests without a database).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sentinel.memory.chunks import _embedding_to_pg

logger = logging.getLogger("sentinel.audit")


@dataclass
class SearchResult:
    """A single search result with score and match type."""

    chunk_id: str
    content: str
    source: str
    score: float
    match_type: str  # "fts", "vec", "hybrid"
    embedding: list[float] | None = None  # available from vec_search


async def fts_search(
    pool: Any,
    query: str,
    user_id: int = 1,
    k: int = 10,
    task_domain: str | None = None,
) -> list[SearchResult]:
    """Full-text search using tsvector + plainto_tsquery.

    plainto_tsquery handles tokenisation and escaping — no manual
    quoting needed. Space-separated terms become AND.
    ts_rank_cd returns positive values, higher = better (sort DESC).
    """
    terms = query.split()
    if not terms:
        return []

    if pool is None:
        return []

    async with pool.acquire() as conn:
        if task_domain:
            rows = await conn.fetch(
                "SELECT chunk_id, content, source, "
                "ts_rank_cd(search_vector, plainto_tsquery('english', $1)) AS rank "
                "FROM memory_chunks "
                "WHERE search_vector @@ plainto_tsquery('english', $1) AND user_id = $2 "
                "AND source IN ('conversation', 'system:episodic', 'planner:auto') "
                "AND task_domain = $4 "
                "ORDER BY rank DESC "
                "LIMIT $3",
                query, user_id, k, task_domain,
            )
        else:
            rows = await conn.fetch(
                "SELECT chunk_id, content, source, "
                "ts_rank_cd(search_vector, plainto_tsquery('english', $1)) AS rank "
                "FROM memory_chunks "
                "WHERE search_vector @@ plainto_tsquery('english', $1) AND user_id = $2 "
                "AND source IN ('conversation', 'system:episodic', 'planner:auto') "
                "ORDER BY rank DESC "
                "LIMIT $3",
                query, user_id, k,
            )

    return [
        SearchResult(
            chunk_id=row["chunk_id"],
            content=row["content"],
            source=row["source"],
            score=float(row["rank"]),
            match_type="fts",
        )
        for row in rows
    ]


async def vec_search(
    pool: Any,
    embedding: list[float],
    user_id: int = 1,
    k: int = 10,
    task_domain: str | None = None,
) -> list[SearchResult]:
    """Vector similarity search using pgvector cosine distance.

    <=> is cosine distance. 1 - distance = similarity (0 to 1).
    Only searches chunks that have an embedding (IS NOT NULL filter).
    """
    if pool is None:
        return []

    vec_str = _embedding_to_pg(embedding)

    async with pool.acquire() as conn:
        if task_domain:
            rows = await conn.fetch(
                "SELECT chunk_id, content, source, "
                "1 - (embedding <=> $1::vector) AS similarity "
                "FROM memory_chunks "
                "WHERE user_id = $2 AND embedding IS NOT NULL "
                "AND source IN ('conversation', 'system:episodic', 'planner:auto') "
                "AND task_domain = $4 "
                "ORDER BY embedding <=> $1::vector "
                "LIMIT $3",
                vec_str, user_id, k, task_domain,
            )
        else:
            rows = await conn.fetch(
                "SELECT chunk_id, content, source, "
                "1 - (embedding <=> $1::vector) AS similarity "
                "FROM memory_chunks "
                "WHERE user_id = $2 AND embedding IS NOT NULL "
                "AND source IN ('conversation', 'system:episodic', 'planner:auto') "
                "ORDER BY embedding <=> $1::vector "
                "LIMIT $3",
                vec_str, user_id, k,
            )

    return [
        SearchResult(
            chunk_id=row["chunk_id"],
            content=row["content"],
            source=row["source"],
            score=float(row["similarity"]),
            match_type="vec",
        )
        for row in rows
    ]


async def hybrid_search(
    pool: Any,
    query: str,
    embedding: list[float] | None = None,
    user_id: int = 1,
    k: int = 10,
    rrf_k: int = 60,
    task_domain: str | None = None,
) -> list[SearchResult]:
    """RRF hybrid search combining FTS and vector results.

    If embedding is None, falls back to FTS-only.
    If pool is None, returns empty results.
    """
    fts_results = await fts_search(pool, query, user_id=user_id, k=k * 2, task_domain=task_domain)

    vec_results: list[SearchResult] = []
    if embedding is not None:
        vec_results = await vec_search(pool, embedding, user_id=user_id, k=k * 2, task_domain=task_domain)

    if not vec_results:
        return fts_results[:k]

    # RRF fusion: merge both ranked lists
    scores: dict[str, float] = {}
    content_map: dict[str, tuple[str, str]] = {}  # chunk_id -> (content, source)
    match_sources: dict[str, set[str]] = {}  # chunk_id -> {"fts", "vec"}

    for rank, result in enumerate(fts_results, start=1):
        scores[result.chunk_id] = scores.get(result.chunk_id, 0.0) + 1.0 / (rrf_k + rank)
        content_map[result.chunk_id] = (result.content, result.source)
        match_sources.setdefault(result.chunk_id, set()).add("fts")

    for rank, result in enumerate(vec_results, start=1):
        scores[result.chunk_id] = scores.get(result.chunk_id, 0.0) + 1.0 / (rrf_k + rank)
        content_map[result.chunk_id] = (result.content, result.source)
        match_sources.setdefault(result.chunk_id, set()).add("vec")

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    results = []
    for chunk_id, score in ranked[:k]:
        content, source = content_map[chunk_id]
        sources = match_sources[chunk_id]
        match_type = "hybrid" if len(sources) > 1 else next(iter(sources))
        results.append(SearchResult(
            chunk_id=chunk_id,
            content=content,
            source=source,
            score=score,
            match_type=match_type,
        ))

    logger.info(
        "Hybrid search completed",
        extra={
            "event": "memory_search",
            "query_length": len(query),
            "fts_hits": len(fts_results),
            "vec_hits": len(vec_results),
            "fused_hits": len(results),
        },
    )
    return results
