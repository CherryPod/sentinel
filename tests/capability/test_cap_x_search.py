"""Capability tests for X search via Grok API.

All tests mock httpx — no real API calls.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sentinel.core.models import DataSource, PolicyResult, TrustLevel, ValidationResult
from sentinel.tools.executor import ToolError, ToolExecutor
from sentinel.tools.x_search import XSearchError, search_x


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


def _grok_response(text: str) -> httpx.Response:
    """Build a mock Grok Responses API response."""
    return httpx.Response(
        status_code=200,
        json={
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": text}
                    ],
                }
            ]
        },
    )


def _x_search_settings() -> MagicMock:
    """Settings mock with x_search enabled."""
    s = MagicMock()
    s.x_search_enabled = True
    s.x_search_api_key_file = "/run/secrets/grok_api_key"
    s.x_search_model = "grok-4-1-fast-reasoning"
    s.x_search_api_url = "https://api.x.ai/v1"
    s.x_search_timeout = 30
    s.x_search_max_results = 10
    # Other settings the executor needs
    s.trust_level = 4
    s.web_search_enabled = False
    s.email_backend = "imap"
    s.imap_host = ""
    s.gmail_enabled = False
    s.calendar_backend = "google"
    s.calendar_enabled = False
    s.sandbox_enabled = False
    s.signal_enabled = False
    s.telegram_enabled = False
    return s


# ---------------------------------------------------------------------------
# Module-level tests (x_search.py)
# ---------------------------------------------------------------------------

class TestXSearchModule:
    """Tests for the x_search.py module directly."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_search_x_returns_text(self):
        """Successful search returns Grok's synthesised text."""
        mock_resp = _grok_response("People are discussing AI safety actively.")
        with patch("sentinel.tools.x_search._load_api_key", return_value="test-key"):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
                result = await search_x(
                    "AI safety",
                    api_url="https://api.x.ai/v1",
                    api_key_file="/fake/key",
                    model="grok-4-1-fast-reasoning",
                )
        assert "AI safety" in result

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_search_x_timeout_raises(self):
        """Timeout from Grok API raises XSearchError."""
        with patch("sentinel.tools.x_search._load_api_key", return_value="test-key"):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.TimeoutException("timeout")):
                with pytest.raises(XSearchError, match="timed out"):
                    await search_x(
                        "test",
                        api_url="https://api.x.ai/v1",
                        api_key_file="/fake/key",
                        model="grok-4-1-fast-reasoning",
                    )

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_search_x_rate_limited(self):
        """429 from Grok API raises XSearchError."""
        mock_resp = httpx.Response(status_code=429, json={})
        with patch("sentinel.tools.x_search._load_api_key", return_value="test-key"):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
                with pytest.raises(XSearchError, match="Rate limited"):
                    await search_x(
                        "test",
                        api_url="https://api.x.ai/v1",
                        api_key_file="/fake/key",
                        model="grok-4-1-fast-reasoning",
                    )

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_search_x_bad_auth(self):
        """401 from Grok API raises XSearchError."""
        mock_resp = httpx.Response(status_code=401, json={})
        with patch("sentinel.tools.x_search._load_api_key", return_value="bad-key"):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
                with pytest.raises(XSearchError, match="Invalid Grok API key"):
                    await search_x(
                        "test",
                        api_url="https://api.x.ai/v1",
                        api_key_file="/fake/key",
                        model="grok-4-1-fast-reasoning",
                    )

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_search_x_empty_response(self):
        """Empty output from Grok raises XSearchError."""
        mock_resp = httpx.Response(status_code=200, json={"output": []})
        with patch("sentinel.tools.x_search._load_api_key", return_value="test-key"):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
                with pytest.raises(XSearchError, match="empty response"):
                    await search_x(
                        "test",
                        api_url="https://api.x.ai/v1",
                        api_key_file="/fake/key",
                        model="grok-4-1-fast-reasoning",
                    )


# ---------------------------------------------------------------------------
# Executor integration tests
# ---------------------------------------------------------------------------

class TestXSearchExecutor:
    """Tests for x_search via the ToolExecutor."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_x_search_disabled_raises(self):
        """x_search with feature disabled raises ToolError."""
        settings = _x_search_settings()
        settings.x_search_enabled = False
        with patch("sentinel.core.config.settings", settings):
            executor = ToolExecutor(policy_engine=_mock_engine())
            with pytest.raises(ToolError, match="disabled"):
                await executor.execute("x_search", {"query": "test"})

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_x_search_empty_query_raises(self):
        """x_search with empty query raises ToolError."""
        settings = _x_search_settings()
        with patch("sentinel.core.config.settings", settings):
            executor = ToolExecutor(policy_engine=_mock_engine())
            with pytest.raises(ToolError, match="query is required"):
                await executor.execute("x_search", {"query": ""})

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_x_search_returns_untrusted_tagged_data(self):
        """Successful x_search returns TaggedData with UNTRUSTED trust level."""
        settings = _x_search_settings()
        mock_resp = _grok_response("Lots of discussion about Brighton.")
        with patch("sentinel.core.config.settings", settings):
            with patch("sentinel.tools.x_search._load_api_key", return_value="test-key"):
                with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
                    executor = ToolExecutor(policy_engine=_mock_engine())
                    result, _ = await executor.execute("x_search", {"query": "Brighton"})
        from sentinel.core.models import TaggedData
        assert isinstance(result, TaggedData)
        assert result.trust_level == TrustLevel.UNTRUSTED
        assert result.source == DataSource.WEB
        assert "Brighton" in result.content

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_x_search_api_error_raises_tool_error(self):
        """API errors from Grok are wrapped as ToolError."""
        settings = _x_search_settings()
        with patch("sentinel.core.config.settings", settings):
            with patch("sentinel.tools.x_search._load_api_key", return_value="test-key"):
                with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.TimeoutException("timeout")):
                    executor = ToolExecutor(policy_engine=_mock_engine())
                    with pytest.raises(ToolError, match="X search failed"):
                        await executor.execute("x_search", {"query": "test"})
