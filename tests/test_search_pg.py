"""Tests for Search — PostgreSQL FTS, vector, and hybrid search.

Uses mock asyncpg pool/connection to verify SQL queries and parameter mapping.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.memory.search import SearchResult, fts_search, hybrid_search, vec_search


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    conn = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = cm
    return pool, conn


def _fts_row(chunk_id="c1", content="hello world", source="test", rank=0.5):
    return {"chunk_id": chunk_id, "content": content, "source": source, "rank": rank}


def _vec_row(chunk_id="c1", content="hello world", source="test", similarity=0.9):
    return {"chunk_id": chunk_id, "content": content, "source": source, "similarity": similarity}


# ── fts_search ───────────────────────────────────────────────


class TestFtsSearch:
    @pytest.mark.asyncio
    async def test_uses_plainto_tsquery(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = [_fts_row()]

        results = await fts_search(pool, "hello world")

        args = conn.fetch.call_args[0]
        assert "plainto_tsquery('english', $1)" in args[0]
        assert "ts_rank_cd" in args[0]
        assert args[1] == "hello world"  # raw query, not quoted

    @pytest.mark.asyncio
    async def test_returns_search_results(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = [
            _fts_row(chunk_id="c1", rank=0.8),
            _fts_row(chunk_id="c2", rank=0.3),
        ]

        results = await fts_search(pool, "test query")

        assert len(results) == 2
        assert all(isinstance(r, SearchResult) for r in results)
        assert results[0].chunk_id == "c1"
        assert results[0].match_type == "fts"
        assert results[0].score == 0.8

    @pytest.mark.asyncio
    async def test_empty_query_returns_empty(self, mock_pool):
        pool, _ = mock_pool

        results = await fts_search(pool, "")

        assert results == []

    @pytest.mark.asyncio
    async def test_whitespace_only_returns_empty(self, mock_pool):
        pool, _ = mock_pool

        results = await fts_search(pool, "   ")

        assert results == []

    @pytest.mark.asyncio
    async def test_passes_user_id_and_limit(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = []

        await fts_search(pool, "query", user_id="alice", k=5)

        args = conn.fetch.call_args[0]
        assert args[2] == "alice"
        assert args[3] == 5

    @pytest.mark.asyncio
    async def test_no_manual_quoting(self, mock_pool):
        """plainto_tsquery handles escaping — raw user input is safe."""
        pool, conn = mock_pool
        conn.fetch.return_value = []

        await fts_search(pool, 'DROP TABLE "memory_chunks"')

        # Query passed directly — plainto_tsquery escapes it
        args = conn.fetch.call_args[0]
        assert args[1] == 'DROP TABLE "memory_chunks"'


# ── vec_search ───────────────────────────────────────────────


class TestVecSearch:
    @pytest.mark.asyncio
    async def test_uses_cosine_distance(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = [_vec_row()]

        results = await vec_search(pool, [0.1, 0.2, 0.3])

        args = conn.fetch.call_args[0]
        assert "<=> $1::vector" in args[0]
        assert "1 - (embedding <=> $1::vector) AS similarity" in args[0]
        assert "embedding IS NOT NULL" in args[0]

    @pytest.mark.asyncio
    async def test_embedding_as_pgvector_string(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = []

        await vec_search(pool, [0.1, 0.2, 0.3])

        args = conn.fetch.call_args[0]
        assert args[1] == "[0.1,0.2,0.3]"  # pgvector string format

    @pytest.mark.asyncio
    async def test_returns_similarity_scores(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = [_vec_row(similarity=0.95)]

        results = await vec_search(pool, [0.1, 0.2])

        assert len(results) == 1
        assert results[0].score == 0.95
        assert results[0].match_type == "vec"

    @pytest.mark.asyncio
    async def test_passes_user_id_and_limit(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = []

        await vec_search(pool, [0.1], user_id="bob", k=3)

        args = conn.fetch.call_args[0]
        assert args[2] == "bob"
        assert args[3] == 3


# ── hybrid_search ────────────────────────────────────────────


class TestHybridSearch:
    @pytest.mark.asyncio
    async def test_fts_only_when_no_embedding(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = [_fts_row(chunk_id="c1")]

        results = await hybrid_search(pool, "test query")

        assert len(results) == 1
        assert results[0].match_type == "fts"

    @pytest.mark.asyncio
    async def test_fts_only_when_vec_returns_empty(self, mock_pool):
        pool, conn = mock_pool
        # First call (FTS) returns results, second call (vec) returns empty
        conn.fetch.side_effect = [
            [_fts_row(chunk_id="c1")],
            [],
        ]

        results = await hybrid_search(pool, "test", embedding=[0.1, 0.2])

        assert len(results) == 1
        assert results[0].match_type == "fts"

    @pytest.mark.asyncio
    async def test_rrf_fusion_merges_results(self, mock_pool):
        pool, conn = mock_pool
        # FTS returns c1, c2; vec returns c2, c3
        conn.fetch.side_effect = [
            [_fts_row(chunk_id="c1"), _fts_row(chunk_id="c2")],
            [_vec_row(chunk_id="c2"), _vec_row(chunk_id="c3")],
        ]

        results = await hybrid_search(pool, "test", embedding=[0.1])

        chunk_ids = {r.chunk_id for r in results}
        assert "c1" in chunk_ids
        assert "c2" in chunk_ids
        assert "c3" in chunk_ids

    @pytest.mark.asyncio
    async def test_hybrid_deduplicates(self, mock_pool):
        pool, conn = mock_pool
        # c1 appears in both FTS and vec
        conn.fetch.side_effect = [
            [_fts_row(chunk_id="c1")],
            [_vec_row(chunk_id="c1")],
        ]

        results = await hybrid_search(pool, "test", embedding=[0.1])

        assert len(results) == 1
        assert results[0].chunk_id == "c1"
        assert results[0].match_type == "hybrid"

    @pytest.mark.asyncio
    async def test_hybrid_respects_k_limit(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.side_effect = [
            [_fts_row(chunk_id=f"c{i}") for i in range(10)],
            [_vec_row(chunk_id=f"v{i}") for i in range(10)],
        ]

        results = await hybrid_search(pool, "test", embedding=[0.1], k=3)

        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_rrf_scores_overlap_higher(self, mock_pool):
        """Documents appearing in both lists should score higher."""
        pool, conn = mock_pool
        conn.fetch.side_effect = [
            [_fts_row(chunk_id="overlap"), _fts_row(chunk_id="fts_only")],
            [_vec_row(chunk_id="overlap"), _vec_row(chunk_id="vec_only")],
        ]

        results = await hybrid_search(pool, "test", embedding=[0.1], k=10)

        # Overlap should be first (highest RRF score)
        assert results[0].chunk_id == "overlap"
        assert results[0].match_type == "hybrid"
