"""Web search tool with pluggable backends (Brave, SearXNG).

Runs in Python (not through sidecar). All results are tagged as
DataSource.WEB / TrustLevel.UNTRUSTED by the executor.
"""

import html
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

logger = logging.getLogger("sentinel.audit")

# Maximum snippet length after sanitisation
_MAX_SNIPPET_LEN = 500


@dataclass
class SearchResult:
    """A single search result."""
    title: str
    url: str
    snippet: str


class SearchError(Exception):
    """Error during web search."""


class SearchBackend(ABC):
    """Abstract base for search backends."""

    @abstractmethod
    async def search(self, query: str, count: int = 5) -> list[SearchResult]:
        """Execute a search query and return results."""


class BraveSearchBackend(SearchBackend):
    """Brave Search API backend."""

    def __init__(self, api_url: str, api_key: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    async def search(self, query: str, count: int = 5) -> list[SearchResult]:
        """Search via Brave Web Search API."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/web/search",
                    params={"q": query, "count": count},
                    headers={
                        "X-Subscription-Token": self._api_key,
                        "Accept": "application/json",
                    },
                )
        except httpx.TimeoutException as exc:
            raise SearchError(f"search request timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            raise SearchError(f"search backend unavailable: {exc}") from exc

        if resp.status_code == 429:
            raise SearchError("rate limited by search API")
        if resp.status_code != 200:
            raise SearchError(f"search API returned {resp.status_code}")

        data = resp.json()
        web_results = data.get("web", {}).get("results", [])

        results = []
        for item in web_results[:count]:
            results.append(SearchResult(
                title=_sanitize_text(item.get("title", "")),
                url=item.get("url", ""),
                snippet=_sanitize_text(item.get("description", "")),
            ))
        return results


class SearXNGBackend(SearchBackend):
    """SearXNG self-hosted search backend."""

    def __init__(self, api_url: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout

    async def search(self, query: str, count: int = 5) -> list[SearchResult]:
        """Search via SearXNG JSON API."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/search",
                    params={"q": query, "format": "json"},
                )
        except httpx.TimeoutException as exc:
            raise SearchError(f"search request timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            raise SearchError(f"search backend unavailable: {exc}") from exc

        if resp.status_code == 429:
            raise SearchError("rate limited by search API")
        if resp.status_code != 200:
            raise SearchError(f"search API returned {resp.status_code}")

        data = resp.json()
        raw_results = data.get("results", [])

        results = []
        for item in raw_results[:count]:
            results.append(SearchResult(
                title=_sanitize_text(item.get("title", "")),
                url=item.get("url", ""),
                snippet=_sanitize_text(item.get("content", "")),
            ))
        return results


def format_results(results: list[SearchResult]) -> str:
    """Format search results as numbered text for LLM consumption."""
    if not results:
        return "No results found."

    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.title}")
        lines.append(f"   URL: {r.url}")
        lines.append(f"   {r.snippet}")
        lines.append("")
    return "\n".join(lines).rstrip()


# HTML tag pattern for sanitisation
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _sanitize_text(text: str) -> str:
    """Strip HTML tags, decode entities, truncate to max length."""
    # Strip HTML tags
    text = _HTML_TAG_RE.sub("", text)
    # Decode HTML entities
    text = html.unescape(text)
    # Collapse whitespace
    text = " ".join(text.split())
    # Truncate
    if len(text) > _MAX_SNIPPET_LEN:
        text = text[:_MAX_SNIPPET_LEN] + "..."
    return text


def _load_api_key(key_file: str) -> str:
    """Read API key from secrets file, strip whitespace."""
    try:
        with open(key_file) as f:
            return f.read().strip()
    except FileNotFoundError:
        raise SearchError(f"API key file not found: {key_file}")
    except OSError as exc:
        raise SearchError(f"Cannot read API key file: {exc}")


def create_search_backend(settings) -> SearchBackend:
    """Factory: settings.web_search_backend -> BraveSearchBackend or SearXNGBackend."""
    backend_name = settings.web_search_backend.lower()
    timeout = settings.web_search_timeout

    if backend_name == "brave":
        api_key = _load_api_key(settings.web_search_api_key_file)
        return BraveSearchBackend(
            api_url=settings.web_search_api_url,
            api_key=api_key,
            timeout=timeout,
        )
    elif backend_name == "searxng":
        return SearXNGBackend(
            api_url=settings.web_search_api_url,
            timeout=timeout,
        )
    else:
        raise SearchError(f"Unknown search backend: {backend_name}")
