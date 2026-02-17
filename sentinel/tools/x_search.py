"""X (Twitter) search via xAI Grok Responses API.

Sends a query to Grok with the x_search server-side tool enabled.
Grok autonomously searches X and returns a synthesised answer.
All results are tagged DataSource.WEB / TrustLevel.UNTRUSTED by the executor.
"""

import logging

import httpx

logger = logging.getLogger("sentinel.audit")

# Grok system prompt — constrains output to concise, factual summaries
_SYSTEM_PROMPT = (
    "You are a concise research assistant. Search X for posts matching the query. "
    "Return only the key findings — what people are saying, any notable posts or "
    "usernames, consensus or disagreement. No source links, no citations, no "
    "preamble, no filler. Be direct. Under 500 words."
)


class XSearchError(Exception):
    """Error during X search via Grok."""


_api_key_cache: dict[str, str] = {}


def _load_api_key(key_file: str) -> str:
    """Read API key from secrets file (cached after first read)."""
    cached = _api_key_cache.get(key_file)
    if cached is not None:
        return cached
    try:
        with open(key_file) as f:
            key = f.read().strip()
    except FileNotFoundError:
        raise XSearchError(f"API key file not found: {key_file}")
    except OSError as exc:
        raise XSearchError(f"Cannot read API key file: {exc}")
    _api_key_cache[key_file] = key
    return key


async def search_x(
    query: str,
    *,
    api_url: str,
    api_key_file: str,
    model: str,
    timeout: int = 30,
) -> str:
    """Search X via Grok Responses API and return the synthesised answer.

    Note: The Grok Responses API returns a synthesised answer (not raw
    results), so there is no max_results parameter to pass downstream.
    Result count is governed by Grok's internal search + system prompt.
    """
    api_key = _load_api_key(api_key_file)

    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ],
        "tools": [{"type": "x_search"}],
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{api_url}/responses",
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
    except httpx.TimeoutException as exc:
        raise XSearchError(f"Grok API request timed out: {exc}") from exc
    except httpx.ConnectError as exc:
        raise XSearchError(f"Grok API unavailable: {exc}") from exc

    if resp.status_code == 429:
        raise XSearchError("Rate limited by Grok API")
    if resp.status_code == 401:
        raise XSearchError("Invalid Grok API key")
    if resp.status_code != 200:
        raise XSearchError(f"Grok API returned {resp.status_code}")

    data = resp.json()

    # Extract text from Responses API output
    # Response structure: {"output": [{"type": "message", "content": [{"type": "output_text", "text": "..."}]}]}
    output_items = data.get("output", [])
    text_parts = []
    for item in output_items:
        if item.get("type") == "message":
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    text_parts.append(content.get("text", ""))

    if not text_parts:
        raise XSearchError("Grok returned empty response")

    return "\n".join(text_parts)
