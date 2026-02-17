"""Tests for Step 1.1: Nomic task prefixes for embeddings.

Verifies that search_document:/search_query: prefixes are correctly
prepended to text before sending to Ollama.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_mock_response(num_texts: int, dims: int = 768):
    """Create a mock httpx response with fake embeddings."""
    embeddings = [[0.1] * dims for _ in range(num_texts)]
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"embeddings": embeddings}
    resp.raise_for_status = MagicMock()
    return resp


@pytest.mark.asyncio
async def test_embed_with_search_document_prefix():
    """embed() with prefix='search_document: ' should prepend to text."""
    from sentinel.memory.embeddings import EmbeddingClient

    client = EmbeddingClient(base_url="http://localhost:11434")

    mock_resp = _make_mock_response(1)
    mock_http_client = AsyncMock()
    mock_http_client.post = AsyncMock(return_value=mock_resp)
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_http_client):
        result = await client.embed("hello world", prefix="search_document: ")

    # Verify the payload sent to Ollama contains prefixed text
    call_kwargs = mock_http_client.post.call_args
    payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
    assert payload["input"] == ["search_document: hello world"]
    assert len(result) == 768


@pytest.mark.asyncio
async def test_embed_batch_with_prefix():
    """embed_batch() with prefix should prepend to all texts."""
    from sentinel.memory.embeddings import EmbeddingClient

    client = EmbeddingClient(base_url="http://localhost:11434")

    mock_resp = _make_mock_response(3)
    mock_http_client = AsyncMock()
    mock_http_client.post = AsyncMock(return_value=mock_resp)
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)

    texts = ["foo", "bar", "baz"]
    with patch("httpx.AsyncClient", return_value=mock_http_client):
        results = await client.embed_batch(texts, prefix="search_query: ")

    call_kwargs = mock_http_client.post.call_args
    payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
    assert payload["input"] == [
        "search_query: foo",
        "search_query: bar",
        "search_query: baz",
    ]
    assert len(results) == 3


@pytest.mark.asyncio
async def test_embed_without_prefix():
    """embed() without prefix should send raw text (backward compat)."""
    from sentinel.memory.embeddings import EmbeddingClient

    client = EmbeddingClient(base_url="http://localhost:11434")

    mock_resp = _make_mock_response(1)
    mock_http_client = AsyncMock()
    mock_http_client.post = AsyncMock(return_value=mock_resp)
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_http_client):
        await client.embed("hello world")

    call_kwargs = mock_http_client.post.call_args
    payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
    assert payload["input"] == ["hello world"]


@pytest.mark.asyncio
async def test_embed_with_none_prefix():
    """embed() with prefix=None should behave same as no prefix."""
    from sentinel.memory.embeddings import EmbeddingClient

    client = EmbeddingClient(base_url="http://localhost:11434")

    mock_resp = _make_mock_response(1)
    mock_http_client = AsyncMock()
    mock_http_client.post = AsyncMock(return_value=mock_resp)
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_http_client):
        await client.embed("hello world", prefix=None)

    call_kwargs = mock_http_client.post.call_args
    payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
    assert payload["input"] == ["hello world"]
