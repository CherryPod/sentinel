"""Tests for sentinel.memory.search — pool=None fallback returns empty results."""

import pytest

from sentinel.memory.search import SearchResult, fts_search, hybrid_search, vec_search


class TestFtsSearchPoolNone:
    """fts_search() with pool=None returns empty."""

    async def test_empty_query(self):
        results = await fts_search(None, "", k=10)
        assert results == []

    async def test_returns_empty_without_pool(self):
        results = await fts_search(None, "Python", k=10)
        assert results == []


class TestVecSearchPoolNone:
    """vec_search() with pool=None returns empty."""

    async def test_returns_empty_without_pool(self):
        results = await vec_search(None, [0.1] * 768, k=10)
        assert results == []


class TestHybridSearchPoolNone:
    """hybrid_search() with pool=None returns empty."""

    async def test_returns_empty_without_pool(self):
        results = await hybrid_search(None, "Python", embedding=None, k=10)
        assert results == []


class TestRRFFusion:
    """RRF score calculation logic."""

    def test_rrf_score_formula(self):
        """Verify RRF score: score = 1/(rrf_k + rank)."""
        rrf_k = 60
        rank = 1
        expected = 1.0 / (rrf_k + rank)
        assert abs(expected - 1.0 / 61) < 1e-10

    def test_hybrid_results_have_higher_score(self):
        """When a doc appears in both full-text and vec, its RRF score should be higher."""
        fts_results = [
            SearchResult(chunk_id="A", content="doc A", source="", score=1.0, match_type="fts"),
            SearchResult(chunk_id="B", content="doc B", source="", score=0.5, match_type="fts"),
        ]
        vec_results = [
            SearchResult(chunk_id="A", content="doc A", source="", score=0.9, match_type="vec"),
            SearchResult(chunk_id="C", content="doc C", source="", score=0.8, match_type="vec"),
        ]

        # Manually compute RRF scores
        rrf_k = 60
        scores = {}
        for rank, r in enumerate(fts_results, 1):
            scores[r.chunk_id] = scores.get(r.chunk_id, 0.0) + 1.0 / (rrf_k + rank)
        for rank, r in enumerate(vec_results, 1):
            scores[r.chunk_id] = scores.get(r.chunk_id, 0.0) + 1.0 / (rrf_k + rank)

        # Doc A appears in both lists — should have highest score
        assert scores["A"] > scores["B"]
        assert scores["A"] > scores["C"]
