"""RRF hybrid search combining FTS5 keyword search and sqlite-vec semantic search.

Reciprocal Rank Fusion (RRF) merges ranked lists from different retrieval
methods: score(doc) = Σ 1/(rrf_k + rank) for each method where the doc appears.
Higher rrf_k values reduce the impact of high-ranking outliers.

Graceful degradation: if sqlite-vec is not available, falls back to FTS5-only.
"""

import logging
import sqlite3
import struct
from dataclasses import dataclass

logger = logging.getLogger("sentinel.audit")


@dataclass
class SearchResult:
    """A single search result with score and match type."""

    chunk_id: str
    content: str
    source: str
    score: float
    match_type: str  # "fts", "vec", "hybrid"


def hybrid_search(
    db: sqlite3.Connection,
    query: str,
    embedding: list[float] | None = None,
    user_id: str = "default",
    k: int = 10,
    rrf_k: int = 60,
) -> list[SearchResult]:
    """Run RRF hybrid search combining FTS5 and vector results.

    If embedding is None or vec table unavailable, falls back to FTS5-only.
    """
    fts_results = fts_search(db, query, user_id=user_id, k=k * 2)

    vec_results: list[SearchResult] = []
    if embedding is not None:
        vec_results = vec_search(db, embedding, user_id=user_id, k=k * 2)

    if not vec_results:
        # FTS5-only fallback
        return fts_results[:k]

    # RRF fusion: merge both ranked lists
    scores: dict[str, float] = {}
    content_map: dict[str, tuple[str, str]] = {}  # chunk_id → (content, source)
    match_sources: dict[str, set[str]] = {}  # chunk_id → {"fts", "vec"}

    for rank, result in enumerate(fts_results, start=1):
        scores[result.chunk_id] = scores.get(result.chunk_id, 0.0) + 1.0 / (rrf_k + rank)
        content_map[result.chunk_id] = (result.content, result.source)
        match_sources.setdefault(result.chunk_id, set()).add("fts")

    for rank, result in enumerate(vec_results, start=1):
        scores[result.chunk_id] = scores.get(result.chunk_id, 0.0) + 1.0 / (rrf_k + rank)
        content_map[result.chunk_id] = (result.content, result.source)
        match_sources.setdefault(result.chunk_id, set()).add("vec")

    # Sort by fused score descending
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


def fts_search(
    db: sqlite3.Connection,
    query: str,
    user_id: str = "default",
    k: int = 10,
) -> list[SearchResult]:
    """FTS5 keyword search on memory_chunks_fts.

    Uses MATCH with BM25 ranking (FTS5 default). The query is escaped to
    prevent FTS5 syntax injection — only simple term matching is used.
    """
    # Escape FTS5 special characters: strip double-quotes (prevents FTS5 syntax
    # injection), then wrap each term in double-quotes for literal matching
    terms = query.split()
    if not terms:
        return []
    safe_query = " ".join(f'"{term.replace(chr(34), "")}"' for term in terms)
    # If all terms were empty after stripping, bail out
    if safe_query.replace('"', "").strip() == "":
        return []

    try:
        rows = db.execute(
            "SELECT mc.chunk_id, mc.content, mc.source, fts.rank "
            "FROM memory_chunks_fts fts "
            "JOIN memory_chunks mc ON mc.rowid = fts.rowid "
            "WHERE memory_chunks_fts MATCH ? AND mc.user_id = ? "
            "ORDER BY fts.rank "
            "LIMIT ?",
            (safe_query, user_id, k),
        ).fetchall()
    except sqlite3.OperationalError:
        # FTS5 query error (e.g. empty after escaping) — return empty
        return []

    return [
        SearchResult(
            chunk_id=row[0],
            content=row[1],
            source=row[2],
            score=abs(row[3]),  # FTS5 rank is negative (lower = better)
            match_type="fts",
        )
        for row in rows
    ]


def vec_search(
    db: sqlite3.Connection,
    embedding: list[float],
    user_id: str = "default",
    k: int = 10,
) -> list[SearchResult]:
    """sqlite-vec semantic search on memory_chunks_vec.

    Returns empty list if sqlite-vec is not available.
    """
    try:
        vec_bytes = struct.pack(f"{len(embedding)}f", *embedding)
        rows = db.execute(
            "SELECT v.chunk_id, v.distance, mc.content, mc.source "
            "FROM memory_chunks_vec v "
            "JOIN memory_chunks mc ON mc.chunk_id = v.chunk_id "
            "WHERE v.embedding MATCH ? AND k = ? AND mc.user_id = ? "
            "ORDER BY v.distance",
            (vec_bytes, k, user_id),
        ).fetchall()
    except sqlite3.OperationalError:
        # sqlite-vec not loaded or table doesn't exist
        return []

    return [
        SearchResult(
            chunk_id=row[0],
            content=row[2],
            source=row[3],
            score=1.0 / (1.0 + row[1]),  # Convert distance to similarity
            match_type="vec",
        )
        for row in rows
    ]
