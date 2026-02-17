"""Tests for Step 3.1: FlashRank reranker integration.

Verifies Reranker graceful degradation, correct re-ranking output,
score ordering, and empty candidate handling.
"""

from unittest.mock import MagicMock, patch

import pytest

from sentinel.memory.reranker import Reranker, RerankResult


def _make_search_result(chunk_id: str, content: str, score: float, source: str = "system:episodic", match_type: str = "hybrid"):
    """Create a mock SearchResult."""
    r = MagicMock()
    r.chunk_id = chunk_id
    r.content = content
    r.score = score
    r.source = source
    r.match_type = match_type
    return r


# ── Graceful degradation ──────────────────────────────────────


class TestRerankerGracefulDegradation:
    """When flashrank is not available, reranker returns candidates by original score."""

    def test_unavailable_when_flashrank_missing(self):
        """Reranker.available is False when _ranker is None."""
        with patch("sentinel.memory.reranker._flashrank_available", False):
            r = Reranker()
        assert r.available is False

    def test_fallback_returns_by_original_score(self):
        """Without flashrank, rerank returns candidates sorted by original score."""
        with patch("sentinel.memory.reranker._flashrank_available", False):
            r = Reranker()

        candidates = [
            _make_search_result("c1", "low relevance", 0.3),
            _make_search_result("c2", "high relevance", 0.9),
            _make_search_result("c3", "medium relevance", 0.6),
        ]

        results = r.rerank("fix the bug", candidates, top_k=2)
        assert len(results) == 2
        # Sorted by original score descending
        assert results[0].chunk_id == "c2"
        assert results[1].chunk_id == "c3"
        # All results are RerankResult
        assert isinstance(results[0], RerankResult)
        # rerank_score == original_score in fallback mode
        assert results[0].rerank_score == 0.9

    def test_fallback_preserves_fields(self):
        """Fallback preserves chunk_id, content, source, match_type."""
        with patch("sentinel.memory.reranker._flashrank_available", False):
            r = Reranker()

        candidates = [
            _make_search_result("c1", "some content", 0.5, source="conversation", match_type="fts"),
        ]

        results = r.rerank("query", candidates, top_k=5)
        assert len(results) == 1
        assert results[0].chunk_id == "c1"
        assert results[0].content == "some content"
        assert results[0].source == "conversation"
        assert results[0].match_type == "fts"


# ── Empty candidates ──────────────────────────────────────────


class TestRerankerEmptyCandidates:
    """Empty input returns empty output."""

    def test_empty_candidates_returns_empty(self):
        with patch("sentinel.memory.reranker._flashrank_available", False):
            r = Reranker()

        results = r.rerank("query", [], top_k=5)
        assert results == []


# ── Re-ranking with mock FlashRank ────────────────────────────


class TestRerankerWithFlashRank:
    """When FlashRank is available, candidates are re-ranked by cross-encoder score."""

    def _make_reranker_with_mock(self):
        """Create a Reranker with a mocked internal _ranker and _RerankRequest."""
        with patch("sentinel.memory.reranker._flashrank_available", False):
            r = Reranker()
        # Inject a mock ranker to simulate FlashRank
        mock_ranker = MagicMock()
        r._ranker = mock_ranker
        return r, mock_ranker

    def _patch_rerank_request(self):
        """Patch _RerankRequest so it works even when flashrank isn't installed."""
        # Create a simple stand-in for RerankRequest that just stores attrs
        class FakeRerankRequest:
            def __init__(self, query=None, passages=None):
                self.query = query
                self.passages = passages
        return patch("sentinel.memory.reranker._RerankRequest", FakeRerankRequest)

    def test_rerank_returns_top_k(self):
        """Reranker returns exactly top_k results after re-ranking."""
        r, mock_ranker = self._make_reranker_with_mock()

        candidates = [
            _make_search_result(f"c{i}", f"content {i}", 0.5 - i * 0.1)
            for i in range(10)
        ]

        # Mock FlashRank to return items reverse-sorted (c9 is "best")
        mock_ranker.rerank.return_value = [
            {"id": 9 - i, "text": f"content {9 - i}", "score": 0.9 - i * 0.05, "meta": {"chunk_id": f"c{9 - i}"}}
            for i in range(10)
        ]

        with self._patch_rerank_request():
            results = r.rerank("fix the issue", candidates, top_k=3)
        assert len(results) == 3

    def test_rerank_scores_ordered_descending(self):
        """Results are in descending rerank_score order."""
        r, mock_ranker = self._make_reranker_with_mock()

        candidates = [
            _make_search_result("c0", "bad match", 0.9),
            _make_search_result("c1", "good match", 0.3),
            _make_search_result("c2", "best match", 0.1),
        ]

        # FlashRank re-orders: c2 best, c1 good, c0 bad
        mock_ranker.rerank.return_value = [
            {"id": 2, "text": "best match", "score": 0.95, "meta": {"chunk_id": "c2"}},
            {"id": 1, "text": "good match", "score": 0.70, "meta": {"chunk_id": "c1"}},
            {"id": 0, "text": "bad match", "score": 0.10, "meta": {"chunk_id": "c0"}},
        ]

        with self._patch_rerank_request():
            results = r.rerank("find the best", candidates, top_k=3)
        assert results[0].chunk_id == "c2"
        assert results[0].rerank_score == 0.95
        assert results[1].chunk_id == "c1"
        assert results[2].chunk_id == "c0"

    def test_rerank_preserves_original_fields(self):
        """Re-ranked results preserve original chunk_id, content, source, match_type."""
        r, mock_ranker = self._make_reranker_with_mock()

        candidates = [
            _make_search_result("chunk_abc", "episodic content", 0.5, source="system:episodic", match_type="hybrid"),
        ]

        mock_ranker.rerank.return_value = [
            {"id": 0, "text": "episodic content", "score": 0.88, "meta": {"chunk_id": "chunk_abc"}},
        ]

        with self._patch_rerank_request():
            results = r.rerank("query", candidates, top_k=5)
        assert len(results) == 1
        assert results[0].chunk_id == "chunk_abc"
        assert results[0].content == "episodic content"
        assert results[0].source == "system:episodic"
        assert results[0].match_type == "hybrid"
        assert results[0].original_score == 0.5
        assert results[0].rerank_score == 0.88

    def test_rerank_error_falls_back_to_original_order(self):
        """If FlashRank.rerank() raises, falls back to original score order."""
        r, mock_ranker = self._make_reranker_with_mock()
        mock_ranker.rerank.side_effect = RuntimeError("ONNX failure")

        candidates = [
            _make_search_result("c0", "low", 0.2),
            _make_search_result("c1", "high", 0.8),
        ]

        with self._patch_rerank_request():
            results = r.rerank("query", candidates, top_k=2)
        # Falls back to original score order
        assert results[0].chunk_id == "c1"
        assert results[1].chunk_id == "c0"
        assert results[0].rerank_score == 0.8  # Uses original score in fallback
