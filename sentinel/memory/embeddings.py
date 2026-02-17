"""Async Ollama embedding client for nomic-embed-text.

Separate from OllamaWorker because it uses a different model (/api/embed
endpoint) and runs on CPU while Qwen uses GPU. Shares the same Ollama URL.
"""

import asyncio
import logging
import random

import httpx

from sentinel.worker.base import EmbeddingBase
from sentinel.worker.ollama import (
    OllamaConnectionError,
    OllamaModelNotFound,
    OllamaTimeoutError,
)

logger = logging.getLogger("sentinel.audit")


class EmbeddingClient(EmbeddingBase):
    """Async client for Ollama /api/embed — produces 768-dim vectors."""

    def __init__(
        self,
        base_url: str = "http://sentinel-qwen:11434",
        model: str = "nomic-embed-text",
        timeout: int = 30,
    ):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    async def embed(self, text: str, prefix: str | None = None) -> list[float]:
        """Embed a single text string, returning a 768-dim vector.

        Retries once on transient failures (connection, timeout, HTTP errors).
        """
        results = await self.embed_batch([text], prefix=prefix)
        return results[0]

    async def embed_batch(self, texts: list[str], prefix: str | None = None) -> list[list[float]]:
        """Embed multiple texts in a single Ollama call.

        The /api/embed endpoint accepts {"input": [...]} for batch embedding.
        Returns one vector per input text, in the same order.
        """
        if not texts:
            return []

        # Nomic task prefixes: "search_document: " for storage,
        # "search_query: " for retrieval — improves relevance 5-15%
        prefixed = [f"{prefix}{t}" for t in texts] if prefix else texts

        payload = {
            "model": self._model,
            "input": prefixed,
            # Force CPU-only: nomic is tiny and fast on CPU. Without this,
            # Ollama loads nomic to GPU, evicting Qwen's 41 layers, then
            # reloads Qwen for the next worker call. 148 evictions in Run 15.
            "options": {"num_gpu": 0},
        }

        # K-002: Creates a new httpx.AsyncClient per request. This is intentional —
        # the Ollama server is on an internal network with sub-1ms latency, and
        # a persistent client would need lifecycle management across async contexts.
        #
        # Retry policy: only retry transient errors (5xx, timeouts, connection
        # errors). 4xx errors are not retried. Exponential backoff with ±20%
        # jitter between attempts (BH3-052).
        _RETRY_BACKOFF_BASE = [1.0, 2.0]
        last_error: Exception | None = None
        for attempt in range(2):  # initial + 1 retry
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(self._timeout)
                ) as client:
                    resp = await client.post(
                        f"{self._base_url}/api/embed",
                        json=payload,
                    )

                if resp.status_code == 404:
                    raise OllamaModelNotFound(
                        f"Model '{self._model}' not found on Ollama server"
                    )

                resp.raise_for_status()
                data = resp.json()

                embeddings = data.get("embeddings", [])
                if len(embeddings) != len(texts):
                    raise OllamaConnectionError(
                        f"Expected {len(texts)} embeddings, got {len(embeddings)}"
                    )

                logger.info(
                    "Embeddings generated",
                    extra={
                        "event": "embedding_complete",
                        "model": self._model,
                        "count": len(texts),
                        "dims": len(embeddings[0]) if embeddings else 0,
                    },
                )
                return embeddings

            except OllamaModelNotFound:
                raise  # don't retry 404s

            except httpx.TimeoutException as exc:
                last_error = OllamaTimeoutError(
                    f"Embedding request timed out after {self._timeout}s"
                )
                logger.warning(
                    "Embedding timeout",
                    extra={
                        "event": "embedding_timeout",
                        "attempt": attempt + 1,
                        "timeout_s": self._timeout,
                    },
                )
                if attempt == 0:
                    await asyncio.sleep(_RETRY_BACKOFF_BASE[0] * random.uniform(0.8, 1.2))
                    continue
                raise last_error from exc

            except httpx.ConnectError as exc:
                last_error = OllamaConnectionError(
                    f"Cannot connect to Ollama at {self._base_url}"
                )
                logger.warning(
                    "Embedding connection error",
                    extra={
                        "event": "embedding_connect_error",
                        "attempt": attempt + 1,
                        "base_url": self._base_url,
                        "error": str(exc),
                    },
                )
                if attempt == 0:
                    await asyncio.sleep(_RETRY_BACKOFF_BASE[0] * random.uniform(0.8, 1.2))
                    continue
                raise last_error from exc

            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                last_error = OllamaConnectionError(
                    f"Ollama returned HTTP {status_code}"
                )
                logger.warning(
                    "Embedding HTTP error",
                    extra={
                        "event": "embedding_http_error",
                        "attempt": attempt + 1,
                        "status_code": status_code,
                    },
                )
                # Only retry 5xx (server) errors — 4xx are client errors
                if status_code < 500:
                    raise last_error from exc
                if attempt == 0:
                    await asyncio.sleep(_RETRY_BACKOFF_BASE[0] * random.uniform(0.8, 1.2))
                    continue
                raise last_error from exc

        # Should not reach here, but just in case
        raise last_error  # type: ignore[misc]
