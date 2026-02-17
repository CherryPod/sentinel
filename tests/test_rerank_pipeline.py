"""Tests for Step 3.2: Over-retrieve + re-rank pipeline.

Verifies that build_learning_context over-retrieves k=15 when a reranker
is available, falls back to k=5 without, and correctly wires through
the reranker.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.planner.builders import build_learning_context


def _make_memory_store(pool=True):
    """Create a mock MemoryStore with a non-None pool by default."""
    store = MagicMock()
    store.pool = MagicMock() if pool else None
    return store


def _make_search_result(content: str, chunk_id: str = "c1"):
    """Create a mock SearchResult with .content, .chunk_id, .source, .score, .match_type."""
    r = MagicMock()
    r.content = content
    r.chunk_id = chunk_id
    r.source = "system:episodic"
    r.score = 0.5
    r.match_type = "hybrid"
    return r


def _make_reranker(available: bool = True):
    """Create a mock Reranker."""
    r = MagicMock()
    r.available = available
    return r


# ── Test: over-retrieve k=15 with reranker ────────────────────


@pytest.mark.asyncio
async def test_over_retrieves_k15_with_reranker():
    """When reranker is available, hybrid_search is called with k=15."""
    memory_store = _make_memory_store()
    reranker = _make_reranker(available=True)

    # Mock reranker.rerank to return RerankResult-like objects with .content
    rerank_result = MagicMock()
    rerank_result.content = "reranked content"
    reranker.rerank.return_value = [rerank_result]

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result(f"result {i}", f"c{i}")
            for i in range(15)
        ]
        await build_learning_context(
            user_request="fix the broken parser",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            reranker=reranker,
        )

    # hybrid_search should have been called with k=15
    call_args = mock_hs.call_args_list[0]
    assert call_args.kwargs.get("k") == 15 or call_args[1].get("k") == 15


# ── Test: fallback k=5 without reranker ───────────────────────


@pytest.mark.asyncio
async def test_fallback_k5_without_reranker():
    """Without reranker, hybrid_search is called with k=5."""
    memory_store = _make_memory_store()

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result(f"result {i}", f"c{i}")
            for i in range(5)
        ]
        await build_learning_context(
            user_request="fix the broken parser",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            reranker=None,
        )

    call_args = mock_hs.call_args_list[0]
    assert call_args.kwargs.get("k") == 5 or call_args[1].get("k") == 5


# ── Test: fallback k=5 with unavailable reranker ──────────────


@pytest.mark.asyncio
async def test_fallback_k5_with_unavailable_reranker():
    """When reranker exists but is not available, behaves like no reranker."""
    memory_store = _make_memory_store()
    reranker = _make_reranker(available=False)

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result(f"result {i}", f"c{i}")
            for i in range(5)
        ]
        await build_learning_context(
            user_request="fix the broken parser",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            reranker=reranker,
        )

    call_args = mock_hs.call_args_list[0]
    assert call_args.kwargs.get("k") == 5 or call_args[1].get("k") == 5
    # reranker.rerank should NOT have been called
    reranker.rerank.assert_not_called()


# ── Test: reranker receives all candidates ────────────────────


@pytest.mark.asyncio
async def test_reranker_receives_all_candidates():
    """Reranker.rerank is called with all hybrid_search results and top_k=5."""
    memory_store = _make_memory_store()
    reranker = _make_reranker(available=True)

    candidates = [_make_search_result(f"result {i}", f"c{i}") for i in range(10)]

    rerank_result = MagicMock()
    rerank_result.content = "best result"
    reranker.rerank.return_value = [rerank_result]

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = candidates
        await build_learning_context(
            user_request="debug this error",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            reranker=reranker,
        )

    # Reranker was called with all 10 candidates and top_k=5
    reranker.rerank.assert_called_once()
    call_kwargs = reranker.rerank.call_args.kwargs
    assert call_kwargs["top_k"] == 5
    assert len(call_kwargs["candidates"]) == 10


# ── Test: reranked content appears in output ──────────────────


@pytest.mark.asyncio
async def test_reranked_content_in_output():
    """After re-ranking, the reranked results appear in the output."""
    memory_store = _make_memory_store()
    reranker = _make_reranker(available=True)

    # The re-ranked result has different content ordering
    rerank_result = MagicMock()
    rerank_result.content = "The best episodic match"
    reranker.rerank.return_value = [rerank_result]

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result("Less relevant", "c0"),
            _make_search_result("The best episodic match", "c1"),
        ]
        result = await build_learning_context(
            user_request="fix the broken parser",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            reranker=reranker,
        )

    assert "The best episodic match" in result
    assert "[EPISODIC CONTEXT" in result
