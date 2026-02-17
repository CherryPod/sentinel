"""B2: Web Search Capability Tests.

Verifies web search dispatches correctly, handles errors, respects config,
parses both Brave and SearXNG backends, and tags results as UNTRUSTED.
All tests mock httpx — no real HTTP calls.

12 tests total.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sentinel.core.models import DataSource, Plan, PlanStep, PolicyResult, TaggedData, TrustLevel, ValidationResult
from sentinel.tools.executor import ToolError, ToolExecutor
from sentinel.tools.web_search import (
    BraveSearchBackend,
    SearXNGBackend,
    SearchError,
    SearchResult,
    format_results,
    _sanitize_text,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_engine() -> MagicMock:
    """PolicyEngine that allows everything."""
    engine = MagicMock()
    allowed = ValidationResult(status=PolicyResult.ALLOWED, path="")
    engine.check_file_read.return_value = allowed
    engine.check_file_write.return_value = allowed
    engine.check_command.return_value = allowed
    engine._policy = {"network": {"http_tool_allowed_domains": []}}
    return engine


def _brave_response(results: list[dict]) -> httpx.Response:
    """Build a mock Brave API response."""
    return httpx.Response(
        status_code=200,
        json={"web": {"results": results}},
    )


def _searxng_response(results: list[dict]) -> httpx.Response:
    """Build a mock SearXNG API response."""
    return httpx.Response(
        status_code=200,
        json={"results": results},
    )


SAMPLE_BRAVE_RESULTS = [
    {
        "title": "Python Documentation",
        "url": "https://docs.python.org",
        "description": "Official <b>Python</b> documentation.",
    },
    {
        "title": "Python Tutorial",
        "url": "https://docs.python.org/tutorial",
        "description": "A comprehensive Python tutorial.",
    },
]

SAMPLE_SEARXNG_RESULTS = [
    {
        "title": "Rust Programming Language",
        "url": "https://www.rust-lang.org",
        "content": "A language empowering everyone to build reliable software.",
    },
    {
        "title": "Rust By Example",
        "url": "https://doc.rust-lang.org/rust-by-example/",
        "content": "Learn Rust with examples.",
    },
]


# ---------------------------------------------------------------------------
# Test 1: Web search returns formatted results
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_returns_formatted_results():
    """Successful search -> formatted text with title/url/snippet."""
    mock_resp = _brave_response(SAMPLE_BRAVE_RESULTS)

    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                result, _ = await executor.execute("web_search", {"query": "python docs"})

    assert isinstance(result, TaggedData)
    assert "Python Documentation" in result.content
    assert "https://docs.python.org" in result.content
    assert result.source == DataSource.WEB
    assert result.trust_level == TrustLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Test 2: Web search backend unavailable
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_backend_unavailable():
    """Connection error -> ToolError."""
    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch(
            "httpx.AsyncClient.get",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                with pytest.raises(ToolError, match="Web search failed.*unavailable"):
                    await executor.execute("web_search", {"query": "test"})


# ---------------------------------------------------------------------------
# Test 3: Web search API timeout
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_api_timeout():
    """httpx.TimeoutException -> ToolError."""
    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch(
            "httpx.AsyncClient.get",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("request timed out"),
        ):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                with pytest.raises(ToolError, match="Web search failed.*timed out"):
                    await executor.execute("web_search", {"query": "test"})


# ---------------------------------------------------------------------------
# Test 4: Web search API rate limited
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_api_rate_limited():
    """429 response -> ToolError("rate limited")."""
    mock_resp = httpx.Response(status_code=429, json={"error": "rate limited"})

    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                with pytest.raises(ToolError, match="rate limited"):
                    await executor.execute("web_search", {"query": "test"})


# ---------------------------------------------------------------------------
# Test 5: Web search empty results
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_empty_results():
    """No results -> empty formatted output (not an error)."""
    mock_resp = _brave_response([])

    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                result, _ = await executor.execute("web_search", {"query": "obscure query"})

    assert isinstance(result, TaggedData)
    assert "No results found" in result.content
    assert result.source == DataSource.WEB
    assert result.trust_level == TrustLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Test 6: Web search config disabled
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_config_disabled():
    """web_search_enabled=False -> ToolError("disabled")."""
    with patch("sentinel.core.config.settings") as mock_settings:
        mock_settings.web_search_enabled = False

        executor = ToolExecutor(policy_engine=_mock_engine())
        with pytest.raises(ToolError, match="disabled"):
            await executor.execute("web_search", {"query": "test"})


# ---------------------------------------------------------------------------
# Test 7: Web search max results enforcement
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_max_results_enforcement():
    """count > max_results capped to max."""
    # 10 results available but max_results is 3
    many_results = [
        {"title": f"Result {i}", "url": f"https://example.com/{i}", "description": f"Desc {i}"}
        for i in range(10)
    ]
    mock_resp = _brave_response(many_results)

    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 3
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                result, _ = await executor.execute("web_search", {"query": "test", "count": "10"})

    assert isinstance(result, TaggedData)
    # The backend receives count=3 (capped), so API gets count=3
    call_args = mock_get.call_args
    assert call_args.kwargs["params"]["count"] == 3


# ---------------------------------------------------------------------------
# Test 8: Brave backend parsing
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_brave_backend():
    """BraveSearchBackend parses Brave API JSON correctly."""
    mock_resp = _brave_response(SAMPLE_BRAVE_RESULTS)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        backend = BraveSearchBackend(
            api_url="https://api.search.brave.com/res/v1",
            api_key="test-key",
        )
        results = await backend.search("python", count=2)

    assert len(results) == 2
    assert results[0].title == "Python Documentation"
    assert results[0].url == "https://docs.python.org"
    # HTML tags should be stripped from description
    assert "<b>" not in results[0].snippet
    assert "Python" in results[0].snippet


# ---------------------------------------------------------------------------
# Test 9: SearXNG backend parsing
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_searxng_backend():
    """SearXNGBackend parses SearXNG JSON correctly."""
    mock_resp = _searxng_response(SAMPLE_SEARXNG_RESULTS)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        backend = SearXNGBackend(api_url="https://searxng.local")
        results = await backend.search("rust", count=2)

    assert len(results) == 2
    assert results[0].title == "Rust Programming Language"
    assert results[0].url == "https://www.rust-lang.org"
    assert "reliable software" in results[0].snippet


# ---------------------------------------------------------------------------
# Test 10: Credential isolation
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_credential_isolation():
    """API key not in TaggedData content or originated_from."""
    mock_resp = _brave_response(SAMPLE_BRAVE_RESULTS)
    api_key = "supersecret-brave-api-key-12345"

    with patch("sentinel.tools.web_search._load_api_key", return_value=api_key):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                result, _ = await executor.execute("web_search", {"query": "test"})

    # API key must not appear anywhere in the result
    assert api_key not in result.content
    assert api_key not in result.originated_from
    assert api_key not in result.id


# ---------------------------------------------------------------------------
# Test 11: Provenance tagging
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_provenance_tagging():
    """Result has source=WEB, trust_level=UNTRUSTED."""
    mock_resp = _brave_response(SAMPLE_BRAVE_RESULTS)

    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                executor = ToolExecutor(policy_engine=_mock_engine())
                result, _ = await executor.execute("web_search", {"query": "test"})

    assert result.source == DataSource.WEB
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert "web_search:brave" in result.originated_from


# ---------------------------------------------------------------------------
# Test 12: Full plan flow — planner creates plan with web_search step
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_web_search_full_plan_flow():
    """Planner creates plan with web_search step -> executor dispatches correctly."""
    # Verify web_search appears in tool descriptions
    executor = ToolExecutor(policy_engine=_mock_engine())
    descriptions = executor.get_tool_descriptions()
    tool_names = [d["name"] for d in descriptions]
    assert "web_search" in tool_names

    # Verify the description includes key info
    ws_desc = next(d for d in descriptions if d["name"] == "web_search")
    assert "UNTRUSTED" in ws_desc["description"]
    assert "query" in ws_desc["args"]
    assert "count" in ws_desc["args"]

    # Verify a plan step can dispatch to web_search
    mock_resp = _brave_response(SAMPLE_BRAVE_RESULTS)
    with patch("sentinel.tools.web_search._load_api_key", return_value="test-key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("sentinel.core.config.settings") as mock_settings:
                mock_settings.web_search_enabled = True
                mock_settings.web_search_backend = "brave"
                mock_settings.web_search_api_url = "https://api.search.brave.com/res/v1"
                mock_settings.web_search_api_key_file = "/run/secrets/brave_api_key"
                mock_settings.web_search_max_results = 5
                mock_settings.web_search_timeout = 10

                result, _ = await executor.execute("web_search", {"query": "latest news"})

    assert isinstance(result, TaggedData)
    assert result.source == DataSource.WEB
