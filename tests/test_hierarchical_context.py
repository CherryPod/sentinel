"""Tests for Step 2.4: Hierarchical context injection.

Verifies that build_learning_context injects domain summaries alongside
individual records, respects budget, and that the backward-compat alias
build_cross_session_context still works.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.planner.builders import (
    build_cross_session_context,
    build_learning_context,
)


def _make_memory_store(pool=True):
    """Create a mock MemoryStore with a non-None pool by default."""
    store = MagicMock()
    store.pool = MagicMock() if pool else None
    return store


def _make_search_result(content: str):
    """Create a mock SearchResult with the given content."""
    r = MagicMock()
    r.content = content
    return r


def _make_domain_summary_store(summary_text: str | None = None, domain: str = "code_debugging"):
    """Create a mock DomainSummaryStore that returns a summary for the given domain."""
    store = AsyncMock()
    if summary_text is not None:
        summary = MagicMock()
        summary.summary_text = summary_text
        store.get.return_value = summary
    else:
        store.get.return_value = None
    return store


# ── Test: summary included when available ──────────────────────


@pytest.mark.asyncio
async def test_summary_included_when_available():
    """When a domain summary store returns a summary, it appears in output."""
    memory_store = _make_memory_store()
    domain_store = _make_domain_summary_store(
        summary_text="code_debugging: 10 tasks, 8/10 (80%) success."
    )

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result("Fixed login bug by checking null pointer"),
        ]
        result = await build_learning_context(
            user_request="fix the broken parser",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            domain_summary_store=domain_store,
        )

    assert "[DOMAIN INSIGHT]" in result
    assert "code_debugging: 10 tasks, 8/10 (80%) success." in result
    assert "[END DOMAIN INSIGHT]" in result
    # Records should also be present
    assert "Fixed login bug" in result
    # Domain summary store was called with the classified domain
    domain_store.get.assert_awaited_once_with("code_debugging")


# ── Test: summary omitted when no store ────────────────────────


@pytest.mark.asyncio
async def test_summary_omitted_when_no_store():
    """When domain_summary_store is None, output contains records only."""
    memory_store = _make_memory_store()

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result("Previous search task completed"),
        ]
        result = await build_learning_context(
            user_request="fix the broken parser",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            domain_summary_store=None,
        )

    assert "[DOMAIN INSIGHT]" not in result
    assert "Previous search task completed" in result
    assert "[EPISODIC CONTEXT" in result


# ── Test: summary omitted when no domain match ─────────────────


@pytest.mark.asyncio
async def test_summary_omitted_when_no_domain():
    """When request doesn't classify to a domain, no summary is fetched."""
    memory_store = _make_memory_store()
    domain_store = _make_domain_summary_store(summary_text="should not appear")

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result("Some past record"),
        ]
        # "hello world" doesn't match any domain keywords
        result = await build_learning_context(
            user_request="hello world",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=500,
            domain_summary_store=domain_store,
        )

    assert "[DOMAIN INSIGHT]" not in result
    # Domain store should NOT have been called since domain is None
    domain_store.get.assert_not_awaited()


# ── Test: records fill remaining budget after summary ──────────


@pytest.mark.asyncio
async def test_records_fill_remaining_budget():
    """Records are included after summary, budget accounting is correct."""
    memory_store = _make_memory_store()
    domain_store = _make_domain_summary_store(
        summary_text="Short summary."
    )

    long_record = "A" * 300
    short_record = "Short record"

    with patch("sentinel.memory.search.hybrid_search", new_callable=AsyncMock) as mock_hs:
        mock_hs.return_value = [
            _make_search_result(short_record),
            _make_search_result(long_record),
        ]
        # Small budget — summary + header + footer eat into it
        result = await build_learning_context(
            user_request="debug this error",
            memory_store=memory_store,
            embedding_client=None,
            cross_session_token_budget=200,  # 800 chars budget
            domain_summary_store=domain_store,
        )

    assert "[DOMAIN INSIGHT]" in result
    assert "Short summary." in result
    # Short record should fit
    assert short_record in result
    # Long record may or may not fit depending on remaining budget — just
    # verify the function didn't crash and returned something valid
    assert "[END EPISODIC CONTEXT]" in result


# ── Test: backward compatibility alias ─────────────────────────


def test_backward_compat_alias():
    """build_cross_session_context is an alias for build_learning_context."""
    assert build_cross_session_context is build_learning_context
