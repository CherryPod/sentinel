"""Tests for sentinel.memory.embeddings — Ollama embedding client (mocked)."""

import pytest
import httpx

from sentinel.memory.embeddings import EmbeddingClient
from sentinel.worker.ollama import (
    OllamaConnectionError,
    OllamaModelNotFound,
    OllamaTimeoutError,
)


_FAKE_REQUEST = httpx.Request("POST", "http://fake:11434/api/embed")


def _mock_response(status_code, json_data):
    """Build a mock httpx.Response with a request set (needed for raise_for_status)."""
    return httpx.Response(status_code, json=json_data, request=_FAKE_REQUEST)


def _mock_embed_response(texts, dims=768):
    """Build a mock Ollama /api/embed response."""
    return {
        "embeddings": [[0.1] * dims for _ in texts],
    }


class TestEmbed:
    """EmbeddingClient.embed() — single text embedding."""

    async def test_embed_returns_vector(self, monkeypatch):
        client = EmbeddingClient(base_url="http://fake:11434")
        response = _mock_response(200, _mock_embed_response(["test"]))

        async def mock_post(self, url, **kwargs):
            return response

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        result = await client.embed("test text")
        assert len(result) == 768
        assert all(isinstance(v, float) for v in result)

    async def test_embed_calls_correct_endpoint(self, monkeypatch):
        client = EmbeddingClient(base_url="http://fake:11434", model="test-model")
        captured = {}

        async def mock_post(self, url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json", {})
            return _mock_response(200, _mock_embed_response(["test"]))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        await client.embed("hello")
        assert captured["url"] == "http://fake:11434/api/embed"
        assert captured["json"]["model"] == "test-model"
        assert captured["json"]["input"] == ["hello"]


class TestEmbedBatch:
    """EmbeddingClient.embed_batch() — batch embedding."""

    async def test_batch_returns_correct_count(self, monkeypatch):
        client = EmbeddingClient(base_url="http://fake:11434")
        texts = ["text1", "text2", "text3"]
        response = _mock_response(200, _mock_embed_response(texts))

        async def mock_post(self, url, **kwargs):
            return response

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        result = await client.embed_batch(texts)
        assert len(result) == 3
        assert all(len(v) == 768 for v in result)

    async def test_batch_empty_returns_empty(self):
        client = EmbeddingClient(base_url="http://fake:11434")
        result = await client.embed_batch([])
        assert result == []

    async def test_batch_sends_all_texts(self, monkeypatch):
        client = EmbeddingClient(base_url="http://fake:11434")
        texts = ["a", "b"]
        captured = {}

        async def mock_post(self, url, **kwargs):
            captured["input"] = kwargs.get("json", {}).get("input")
            return _mock_response(200, _mock_embed_response(texts))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        await client.embed_batch(texts)
        assert captured["input"] == ["a", "b"]


class TestErrorHandling:
    """Error handling and retry logic."""

    async def test_model_not_found_raises(self, monkeypatch):
        client = EmbeddingClient(base_url="http://fake:11434")

        async def mock_post(self, url, **kwargs):
            return _mock_response(404, {"error": "not found"})

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        with pytest.raises(OllamaModelNotFound):
            await client.embed("test")

    async def test_model_not_found_no_retry(self, monkeypatch):
        """404 should not be retried."""
        client = EmbeddingClient(base_url="http://fake:11434")
        call_count = 0

        async def mock_post(self, url, **kwargs):
            nonlocal call_count
            call_count += 1
            return _mock_response(404, {"error": "not found"})

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        with pytest.raises(OllamaModelNotFound):
            await client.embed("test")
        assert call_count == 1

    async def test_timeout_retries_then_raises(self, monkeypatch):
        client = EmbeddingClient(base_url="http://fake:11434", timeout=1)
        call_count = 0

        async def mock_post(self, url, **kwargs):
            nonlocal call_count
            call_count += 1
            raise httpx.ReadTimeout("timeout")

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        with pytest.raises(OllamaTimeoutError):
            await client.embed("test")
        assert call_count == 2  # initial + 1 retry

    async def test_connection_error_retries_then_raises(self, monkeypatch):
        client = EmbeddingClient(base_url="http://fake:11434")
        call_count = 0

        async def mock_post(self, url, **kwargs):
            nonlocal call_count
            call_count += 1
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        with pytest.raises(OllamaConnectionError):
            await client.embed("test")
        assert call_count == 2

    async def test_mismatched_embedding_count_raises(self, monkeypatch):
        """If Ollama returns wrong number of embeddings, raise error."""
        client = EmbeddingClient(base_url="http://fake:11434")
        # Request 2 embeddings but response has 1
        response = _mock_response(200, _mock_embed_response(["only_one"]))

        async def mock_post(self, url, **kwargs):
            return response

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        with pytest.raises(OllamaConnectionError, match="Expected 2 embeddings"):
            await client.embed_batch(["a", "b"])
