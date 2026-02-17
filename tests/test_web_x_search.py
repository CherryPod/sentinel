"""Tests for web_search and x_search parameter handling and error paths (BH3-102)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.tools.web_search import (
    BraveSearchBackend,
    SearXNGBackend,
    SearchError,
    SearchResult,
    _sanitize_text,
    format_results,
    create_search_backend,
)
from sentinel.tools.x_search import (
    XSearchError,
    _load_api_key,
    search_x,
    _api_key_cache,
)


# ── web_search tests ────────────────────────────────────────────


class TestSanitizeText:
    def test_strips_html_tags(self):
        assert _sanitize_text("<b>bold</b> text") == "bold text"

    def test_decodes_entities(self):
        assert _sanitize_text("A &amp; B") == "A & B"

    def test_truncates_long_text(self):
        long = "x" * 600
        result = _sanitize_text(long)
        assert len(result) == 503  # 500 + "..."
        assert result.endswith("...")

    def test_collapses_whitespace(self):
        assert _sanitize_text("a   b\n\tc") == "a b c"


class TestFormatResults:
    def test_empty(self):
        assert format_results([]) == "No results found."

    def test_formats_numbered(self):
        results = [
            SearchResult(title="Title 1", url="https://a.com", snippet="Snippet 1"),
            SearchResult(title="Title 2", url="https://b.com", snippet="Snippet 2"),
        ]
        output = format_results(results)
        assert "1. Title 1" in output
        assert "URL: https://a.com" in output
        assert "2. Title 2" in output


class TestCreateSearchBackend:
    def test_brave_backend(self, tmp_path):
        key_file = tmp_path / "key.txt"
        key_file.write_text("test-api-key")
        settings = MagicMock()
        settings.web_search_backend = "brave"
        settings.web_search_api_url = "https://api.search.brave.com"
        settings.web_search_api_key_file = str(key_file)
        settings.web_search_timeout = 10
        backend = create_search_backend(settings)
        assert isinstance(backend, BraveSearchBackend)

    def test_searxng_backend(self):
        settings = MagicMock()
        settings.web_search_backend = "searxng"
        settings.web_search_api_url = "http://localhost:8888"
        settings.web_search_timeout = 10
        backend = create_search_backend(settings)
        assert isinstance(backend, SearXNGBackend)

    def test_unknown_backend_raises(self):
        settings = MagicMock()
        settings.web_search_backend = "google"
        with pytest.raises(SearchError, match="Unknown search backend"):
            create_search_backend(settings)


class TestBraveSearchErrors:
    @pytest.mark.asyncio
    async def test_timeout_raises_search_error(self):
        import httpx
        backend = BraveSearchBackend(
            api_url="https://api.search.brave.com",
            api_key="test-key",
            timeout=1,
        )
        with patch("sentinel.tools.web_search.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client
            with pytest.raises(SearchError, match="timed out"):
                await backend.search("test query")


class TestSearXNGSearchErrors:
    @pytest.mark.asyncio
    async def test_timeout_raises_search_error(self):
        import httpx
        backend = SearXNGBackend(api_url="http://localhost:8888", timeout=1)
        with patch("sentinel.tools.web_search.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client
            with pytest.raises(SearchError, match="timed out"):
                await backend.search("test query")


# ── x_search tests ──────────────────────────────────────────────


class TestXSearchLoadApiKey:
    def test_loads_key_from_file(self, tmp_path):
        key_file = tmp_path / "xai_key.txt"
        key_file.write_text("  xai-test-key-123  \n")
        # Clear cache for this test
        _api_key_cache.clear()
        key = _load_api_key(str(key_file))
        assert key == "xai-test-key-123"

    def test_caches_key(self, tmp_path):
        key_file = tmp_path / "xai_key2.txt"
        key_file.write_text("cached-key")
        _api_key_cache.clear()
        key1 = _load_api_key(str(key_file))
        key2 = _load_api_key(str(key_file))
        assert key1 == key2 == "cached-key"

    def test_missing_file_raises(self):
        _api_key_cache.clear()
        with pytest.raises(XSearchError, match="not found"):
            _load_api_key("/nonexistent/key.txt")


class TestSearchXErrors:
    @pytest.mark.asyncio
    async def test_timeout_raises(self, tmp_path):
        import httpx
        key_file = tmp_path / "key.txt"
        key_file.write_text("test-key")
        _api_key_cache.clear()
        with patch("sentinel.tools.x_search.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client
            with pytest.raises(XSearchError, match="timed out"):
                await search_x(
                    "test",
                    api_url="https://api.x.ai/v1",
                    api_key_file=str(key_file),
                    model="grok-3-mini",
                )

    @pytest.mark.asyncio
    async def test_empty_response_raises(self, tmp_path):
        key_file = tmp_path / "key.txt"
        key_file.write_text("test-key")
        _api_key_cache.clear()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"output": []}

        with patch("sentinel.tools.x_search.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client
            with pytest.raises(XSearchError, match="empty response"):
                await search_x(
                    "test",
                    api_url="https://api.x.ai/v1",
                    api_key_file=str(key_file),
                    model="grok-3-mini",
                )
