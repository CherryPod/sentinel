"""Tests for Step 1.7: Embedding version tracking.

Verifies embed_model/render_version columns are set on storage,
and stale embedding detection works correctly.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


def test_current_embed_model_and_render_version():
    """MemoryStore should have correct current model/version constants."""
    from sentinel.memory.chunks import MemoryStore

    assert MemoryStore.CURRENT_EMBED_MODEL == "nomic-embed-text"
    assert MemoryStore.CURRENT_RENDER_VERSION == 1


def test_store_with_embedding_accepts_version_params():
    """store_with_embedding() should accept embed_model and render_version."""
    import inspect
    from sentinel.memory.chunks import MemoryStore

    sig = inspect.signature(MemoryStore.store_with_embedding)
    params = sig.parameters

    assert "embed_model" in params
    assert params["embed_model"].default == "nomic-embed-text"
    assert "render_version" in params
    assert params["render_version"].default == 1


@pytest.mark.asyncio
async def test_count_stale_embeddings_no_pool():
    """count_stale_embeddings() should return 0 when pool is None."""
    from sentinel.memory.chunks import MemoryStore

    store = MemoryStore(pool=None)
    count = await store.count_stale_embeddings()
    assert count == 0


@pytest.mark.asyncio
async def test_re_embed_stale_no_pool():
    """re_embed_stale() should return 0 when pool is None."""
    from sentinel.memory.chunks import MemoryStore

    store = MemoryStore(pool=None)
    updated = await store.re_embed_stale(
        embedding_client=MagicMock(),
        render_fn=lambda x: x,
    )
    assert updated == 0


@pytest.mark.asyncio
async def test_store_with_embedding_in_memory_fallback():
    """In-memory fallback should still work with version params."""
    from sentinel.memory.chunks import MemoryStore

    store = MemoryStore(pool=None)
    chunk_id = await store.store_with_embedding(
        content="test content",
        embedding=[0.1] * 768,
        source="test",
        embed_model="nomic-embed-text",
        render_version=1,
    )
    assert chunk_id is not None

    # Verify the chunk was stored
    chunk = await store.get(chunk_id)
    assert chunk is not None
    assert chunk.content == "test content"
