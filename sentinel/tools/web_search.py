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

from sentinel.crypto.blind_index import log_hash

logger = logging.getLogger(__name__)

# Maximum snippet length after sanitisation
_MAX_SNIPPET_LEN = 500


@dataclass
class SearchResult:
    """A single search result."""

    title: str
    url: str
    snippet: str


# Moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import SearchError


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
        logger.debug(
            "search called",
            extra={
                "event": "web_search.search",
                "query_len": len(query) if hasattr(query, "__len__") else 0,
                "count": count,
            },
        )  # auto:entry
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
            exc_str = str(exc)
            try:
                exc_hash = log_hash(exc_str)
            except Exception:
                logger.warning(
                    "log_hash unavailable for exc, using fallback",
                    exc_info=True,
                    extra={"event": "crypto.log_hash_fallback"},
                )
                exc_hash = "hash-error"
            logger.debug(
                "search request timed out",
                extra={
                    "event": "web_search.timeout",
                    "exc_hash": exc_hash,
                    "exc_len": len(exc_str),
                },
            )
            raise SearchError("search request timed out") from exc
        except httpx.ConnectError as exc:
            exc_str = str(exc)
            try:
                exc_hash = log_hash(exc_str)
            except Exception:
                logger.warning(
                    "log_hash unavailable for exc, using fallback",
                    exc_info=True,
                    extra={"event": "crypto.log_hash_fallback"},
                )
                exc_hash = "hash-error"
            logger.debug(
                "search backend unavailable",
                extra={
                    "event": "web_search.connect_error",
                    "exc_hash": exc_hash,
                    "exc_len": len(exc_str),
                },
            )
            raise SearchError("search backend unavailable") from exc

        if resp.status_code == 429:
            raise SearchError("rate limited by search API")
        if resp.status_code != 200:
            raise SearchError(f"search API returned {resp.status_code}")

        data = resp.json()
        web_results = data.get("web", {}).get("results", [])

        results = []
        for item in web_results[:count]:
            results.append(
                SearchResult(
                    title=_sanitize_text(item.get("title", "")),
                    url=item.get("url", ""),
                    snippet=_sanitize_text(item.get("description", "")),
                )
            )
        return results


class SearXNGBackend(SearchBackend):
    """SearXNG self-hosted search backend."""

    def __init__(self, api_url: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout

    async def search(self, query: str, count: int = 5) -> list[SearchResult]:
        """Search via SearXNG JSON API."""
        logger.debug(
            "search called",
            extra={
                "event": "web_search.search",
                "query_len": len(query) if hasattr(query, "__len__") else 0,
                "count": count,
            },
        )  # auto:entry
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/search",
                    params={"q": query, "format": "json"},
                )
        except httpx.TimeoutException as exc:
            exc_str = str(exc)
            try:
                exc_hash = log_hash(exc_str)
            except Exception:
                logger.warning(
                    "log_hash unavailable for exc, using fallback",
                    exc_info=True,
                    extra={"event": "crypto.log_hash_fallback"},
                )
                exc_hash = "hash-error"
            logger.debug(
                "search request timed out",
                extra={
                    "event": "web_search.timeout",
                    "exc_hash": exc_hash,
                    "exc_len": len(exc_str),
                },
            )
            raise SearchError("search request timed out") from exc
        except httpx.ConnectError as exc:
            exc_str = str(exc)
            try:
                exc_hash = log_hash(exc_str)
            except Exception:
                logger.warning(
                    "log_hash unavailable for exc, using fallback",
                    exc_info=True,
                    extra={"event": "crypto.log_hash_fallback"},
                )
                exc_hash = "hash-error"
            logger.debug(
                "search backend unavailable",
                extra={
                    "event": "web_search.connect_error",
                    "exc_hash": exc_hash,
                    "exc_len": len(exc_str),
                },
            )
            raise SearchError("search backend unavailable") from exc

        if resp.status_code == 429:
            raise SearchError("rate limited by search API")
        if resp.status_code != 200:
            raise SearchError(f"search API returned {resp.status_code}")

        data = resp.json()
        raw_results = data.get("results", [])

        results = []
        for item in raw_results[:count]:
            results.append(
                SearchResult(
                    title=_sanitize_text(item.get("title", "")),
                    url=item.get("url", ""),
                    snippet=_sanitize_text(item.get("content", "")),
                )
            )
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
    logger.debug(
        "_sanitize_text called",
        extra={
            "event": "web_search._sanitize_text",
            "text_len": len(text) if hasattr(text, "__len__") else 0,
        },
    )  # auto:entry
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
    except FileNotFoundError as exc:
        raise SearchError(f"API key file not found: {key_file}") from exc
    except OSError as exc:
        exc_str = str(exc)
        try:
            exc_hash = log_hash(exc_str)
        except Exception:
            logger.warning(
                "log_hash unavailable for exc, using fallback",
                exc_info=True,
                extra={"event": "crypto.log_hash_fallback"},
            )
            exc_hash = "hash-error"
        logger.debug(
            "API key file read failed",
            extra={
                "event": "web_search.load_api_key_error",
                "exc_hash": exc_hash,
                "exc_len": len(exc_str),
            },
        )
        raise SearchError("cannot read API key file") from exc


def create_search_backend(settings) -> SearchBackend:
    """Factory: settings.web_search_backend -> BraveSearchBackend or SearXNGBackend."""
    logger.debug(
        "create_search_backend called",
        extra={
            "event": "web_search.create_search_backend",
            "settings_type": type(settings).__name__,
        },
    )  # auto:entry
    backend_name = settings.web_search_backend.lower()
    timeout = settings.web_search_timeout

    if backend_name == "brave":
        api_key = _load_api_key(settings.web_search_api_key_file)
        return BraveSearchBackend(
            api_url=settings.web_search_api_url,
            api_key=api_key,
            timeout=timeout,
        )
    if backend_name == "searxng":
        return SearXNGBackend(
            api_url=settings.web_search_api_url,
            timeout=timeout,
        )
    raise SearchError(f"Unknown search backend: {backend_name}")
