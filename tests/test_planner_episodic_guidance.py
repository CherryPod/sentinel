"""Tests for Step 1.6: Planner prompt episodic learning guidance.

Verifies the <episodic_learning> section in the planner system prompt
and the updated cross-session context header format.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_planner_system_prompt_contains_episodic_learning():
    """The planner system prompt must include the <episodic_learning> section."""
    with patch("sentinel.planner.planner.settings") as mock_settings:
        mock_settings.claude_api_key_file = "/dev/null"
        with patch("sentinel.planner.planner.anthropic"):
            with patch.object(
                __import__("sentinel.planner.planner", fromlist=["ClaudePlanner"]).ClaudePlanner,
                "_load_api_key",
                return_value="fake-key",
            ):
                from sentinel.planner.planner import ClaudePlanner
                planner = ClaudePlanner(api_key="fake-key")
                prompt = planner._build_system_prompt(tool_descriptions="test tools")

    assert "<episodic_learning>" in prompt
    assert "</episodic_learning>" in prompt
    assert "PREFER strategies that succeeded" in prompt
    assert "AVOID approaches that previously failed" in prompt
    assert "IGNORE specific file paths" in prompt
    assert "DO NOT mention episodic context" in prompt
    assert "Gather context early" in prompt


@pytest.mark.asyncio
async def test_cross_session_context_header_format():
    """Cross-session context should use the EPISODIC CONTEXT header."""
    from sentinel.planner.builders import build_cross_session_context
    from sentinel.memory.search import SearchResult

    mock_memory = MagicMock()
    mock_memory.pool = MagicMock()

    mock_results = [
        SearchResult(
            chunk_id="c1",
            content="Previous task: fix syntax error. Success.",
            source="system:episodic",
            score=0.9,
            match_type="hybrid",
        ),
    ]

    with patch(
        "sentinel.memory.search.hybrid_search",
        new_callable=AsyncMock,
        return_value=mock_results,
    ):
        result = await build_cross_session_context(
            user_request="fix the bug",
            memory_store=mock_memory,
            embedding_client=None,
            cross_session_token_budget=2000,
        )

    assert result.startswith("[EPISODIC CONTEXT")
    assert "[END EPISODIC CONTEXT]" in result


@pytest.mark.asyncio
async def test_cross_session_context_empty_returns_empty():
    """Empty search results should return empty string."""
    from sentinel.planner.builders import build_cross_session_context

    mock_memory = MagicMock()
    mock_memory.pool = MagicMock()

    with patch(
        "sentinel.memory.search.hybrid_search",
        new_callable=AsyncMock,
        return_value=[],
    ):
        result = await build_cross_session_context(
            user_request="test",
            memory_store=mock_memory,
            embedding_client=None,
            cross_session_token_budget=2000,
        )

    assert result == ""
