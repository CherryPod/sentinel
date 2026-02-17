"""Tests for Step 1.3: Domain-filtered retrieval.

Verifies that fts_search/vec_search/hybrid_search accept task_domain,
that _classify_request_domain maps keywords correctly, and that
build_cross_session_context retries without domain when filtered
results are fewer than 3.
"""

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.memory.search import fts_search, vec_search, hybrid_search, SearchResult
from sentinel.planner.builders import _classify_request_domain, build_cross_session_context


# ── Signature tests ──────────────────────────────────────────────


def test_fts_search_accepts_task_domain():
    sig = inspect.signature(fts_search)
    assert "task_domain" in sig.parameters
    param = sig.parameters["task_domain"]
    assert param.default is None


def test_vec_search_accepts_task_domain():
    sig = inspect.signature(vec_search)
    assert "task_domain" in sig.parameters
    param = sig.parameters["task_domain"]
    assert param.default is None


def test_hybrid_search_accepts_task_domain():
    sig = inspect.signature(hybrid_search)
    assert "task_domain" in sig.parameters
    param = sig.parameters["task_domain"]
    assert param.default is None


# ── _classify_request_domain tests ───────────────────────────────


@pytest.mark.parametrize("request_text,expected", [
    ("fix the broken login page", "code_debugging"),
    ("debug this error in the parser", "code_debugging"),
    ("the API is not working", "code_debugging"),
    ("there's a bug in the email handler", "code_debugging"),
    ("send a message to Alice", "messaging"),
    ("email the report to the team", "messaging"),
    ("forward this on signal", "messaging"),
    ("notify via telegram", "messaging"),
    ("search for Python tutorials", "search"),
    ("find the latest news about AI", "search"),
    ("look up the weather forecast", "search"),
    ("google this topic", "search"),
    ("add a calendar event for Monday", "calendar"),
    ("schedule a meeting at 3pm", "calendar"),
    ("what events do I have today", "calendar"),
    ("create a website for my project", None),
    ("hello world", None),
    ("write a poem about cats", None),
])
def test_classify_request_domain(request_text, expected):
    assert _classify_request_domain(request_text) == expected


def test_classify_request_domain_case_insensitive():
    assert _classify_request_domain("FIX the ERROR") == "code_debugging"
    assert _classify_request_domain("SEND a MESSAGE") == "messaging"


# ── Pool=None returns empty (search functions with domain) ───────


@pytest.mark.asyncio
async def test_fts_search_none_pool_with_domain():
    results = await fts_search(pool=None, query="test", task_domain="messaging")
    assert results == []


@pytest.mark.asyncio
async def test_vec_search_none_pool_with_domain():
    results = await vec_search(pool=None, embedding=[0.1] * 768, task_domain="messaging")
    assert results == []


@pytest.mark.asyncio
async def test_hybrid_search_none_pool_with_domain():
    results = await hybrid_search(pool=None, query="test", task_domain="messaging")
    assert results == []


# ── Fallback test ────────────────────────────────────────────────


def _make_result(chunk_id: str) -> SearchResult:
    return SearchResult(
        chunk_id=chunk_id,
        content=f"content-{chunk_id}",
        source="conversation",
        score=0.5,
        match_type="fts",
    )


@pytest.mark.asyncio
async def test_cross_session_fallback_retries_without_domain():
    """When domain-filtered search returns <3 results, retry unfiltered."""
    memory_store = MagicMock()
    memory_store.pool = MagicMock()

    # First call (with domain) returns 1 result, second (without) returns 3
    filtered_results = [_make_result("a")]
    unfiltered_results = [_make_result("a"), _make_result("b"), _make_result("c")]

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_search:
        mock_search.side_effect = [filtered_results, unfiltered_results]

        result = await build_cross_session_context(
            user_request="debug the broken parser",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
        )

    # Should have been called twice: first with domain, then without
    assert mock_search.call_count == 2
    first_call = mock_search.call_args_list[0]
    second_call = mock_search.call_args_list[1]
    assert first_call.kwargs.get("task_domain") == "code_debugging"
    assert second_call.kwargs.get("task_domain") is None
    # Result should contain content from the unfiltered search
    assert "content-b" in result


@pytest.mark.asyncio
async def test_cross_session_no_fallback_when_enough_results():
    """When domain-filtered search returns >=3 results, no retry."""
    memory_store = MagicMock()
    memory_store.pool = MagicMock()

    filtered_results = [_make_result("a"), _make_result("b"), _make_result("c")]

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_search:
        mock_search.return_value = filtered_results

        await build_cross_session_context(
            user_request="fix the error in login",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
        )

    # Only one call — no fallback needed
    assert mock_search.call_count == 1
    assert mock_search.call_args.kwargs.get("task_domain") == "code_debugging"


@pytest.mark.asyncio
async def test_cross_session_no_fallback_when_no_domain():
    """When domain is None (generic request), search once without filter."""
    memory_store = MagicMock()
    memory_store.pool = MagicMock()

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_search:
        mock_search.return_value = [_make_result("a")]

        await build_cross_session_context(
            user_request="write a poem about cats",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
        )

    # Only one call — domain was None, no fallback path
    assert mock_search.call_count == 1
    assert mock_search.call_args.kwargs.get("task_domain") is None
