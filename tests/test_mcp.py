"""Tests for MCP server implementation."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.channels.mcp_server import create_mcp_server
from sentinel.core.bus import EventBus
from sentinel.core.models import TaskResult


# ── Helpers ───────────────────────────────────────────────────────


def make_mcp_server(
    orchestrator=None,
    memory_store=None,
    embedding_client=None,
    event_bus=None,
):
    """Create an MCP server with mocked dependencies."""
    return create_mcp_server(
        orchestrator=orchestrator or MagicMock(),
        memory_store=memory_store,
        embedding_client=embedding_client,
        event_bus=event_bus or EventBus(),
    )


# ── Tool registration tests ──────────────────────────────────────


class TestMCPToolRegistration:
    def test_all_tools_registered(self):
        """MCP server has all 4 expected tools."""
        mcp = make_mcp_server()
        # FastMCP stores tools internally — use list_tools to verify
        # The tools are registered via @mcp.tool() decorators
        # We can check the tool names by looking at the internal registry
        tool_names = set()
        for tool in mcp._tool_manager._tools.values():
            tool_names.add(tool.name)

        assert "search_memory" in tool_names
        assert "store_memory" in tool_names
        assert "run_task" in tool_names
        assert "health_check" in tool_names

    def test_returns_fastmcp_instance(self):
        """create_mcp_server returns a FastMCP instance."""
        from mcp.server.fastmcp import FastMCP
        mcp = make_mcp_server()
        assert isinstance(mcp, FastMCP)
        assert mcp.name == "sentinel"


# ── health_check tool ─────────────────────────────────────────────


class TestHealthCheckTool:
    async def test_health_check_returns_status(self):
        """health_check returns system component status."""
        orch = MagicMock()
        mem = MagicMock()
        emb = MagicMock()
        bus = EventBus()
        mcp = create_mcp_server(orch, mem, emb, bus)

        result = await mcp._tool_manager._tools["health_check"].fn()
        data = json.loads(result)

        assert data["status"] == "ok"
        assert data["orchestrator"] is True
        assert data["memory"] is True
        assert data["embeddings"] is True
        assert data["event_bus"] is True

    async def test_health_check_no_components(self):
        """health_check shows False for missing components."""
        mcp = create_mcp_server(None, None, None, None)

        result = await mcp._tool_manager._tools["health_check"].fn()
        data = json.loads(result)

        assert data["status"] == "ok"
        assert data["orchestrator"] is False
        assert data["memory"] is False


# ── search_memory tool ────────────────────────────────────────────


class TestSearchMemoryTool:
    async def test_search_no_memory_store(self):
        """search_memory returns error when memory store is not initialized."""
        mcp = create_mcp_server(MagicMock(), None, None, EventBus())
        result = await mcp._tool_manager._tools["search_memory"].fn(query="test")
        data = json.loads(result)
        assert data["status"] == "error"

    async def test_search_calls_hybrid_search(self):
        """search_memory calls hybrid_search and returns results."""
        from sentinel.memory.search import SearchResult

        mem = MagicMock()
        mem._db = MagicMock()
        emb = AsyncMock()
        emb.embed = AsyncMock(return_value=[0.1] * 768)
        mcp = create_mcp_server(MagicMock(), mem, emb, EventBus())

        mock_results = [
            SearchResult(chunk_id="c1", content="hello", source="test", score=0.5, match_type="fts"),
        ]

        with patch("sentinel.memory.search.hybrid_search", return_value=mock_results) as mock_hs:
            result = await mcp._tool_manager._tools["search_memory"].fn(query="hello", k=5)

        data = json.loads(result)
        assert data["status"] == "ok"
        assert data["count"] == 1
        assert data["results"][0]["chunk_id"] == "c1"

    async def test_search_graceful_embedding_fallback(self):
        """search_memory degrades to FTS5-only if embedding fails."""
        mem = MagicMock()
        mem._db = MagicMock()
        emb = AsyncMock()
        emb.embed = AsyncMock(side_effect=RuntimeError("connection refused"))
        mcp = create_mcp_server(MagicMock(), mem, emb, EventBus())

        with patch("sentinel.memory.search.hybrid_search", return_value=[]) as mock_hs:
            result = await mcp._tool_manager._tools["search_memory"].fn(query="test")

        data = json.loads(result)
        assert data["status"] == "ok"
        # hybrid_search was called with embedding=None (fallback)
        mock_hs.assert_called_once()
        call_kwargs = mock_hs.call_args
        assert call_kwargs.kwargs.get("embedding") is None or call_kwargs[1].get("embedding") is None


# ── store_memory tool ─────────────────────────────────────────────


class TestStoreMemoryTool:
    async def test_store_no_memory(self):
        """store_memory returns error when memory store is missing."""
        mcp = create_mcp_server(MagicMock(), None, None, EventBus())
        result = await mcp._tool_manager._tools["store_memory"].fn(text="hello")
        data = json.loads(result)
        assert data["status"] == "error"

    async def test_store_with_embeddings(self):
        """store_memory stores chunks with embeddings when available."""
        mem = MagicMock()
        mem.store_with_embedding = MagicMock(return_value="chunk-1")
        emb = AsyncMock()
        emb.embed_batch = AsyncMock(return_value=[[0.1] * 768])
        mcp = create_mcp_server(MagicMock(), mem, emb, EventBus())

        with patch("sentinel.memory.splitter.split_text", return_value=["hello world"]):
            result = await mcp._tool_manager._tools["store_memory"].fn(text="hello world")

        data = json.loads(result)
        assert data["status"] == "ok"
        assert data["chunks_stored"] == 1
        assert data["embedded"] is True

    async def test_store_without_embeddings(self):
        """store_memory falls back to non-embedded storage."""
        mem = MagicMock()
        mem.store = MagicMock(return_value="chunk-1")
        mcp = create_mcp_server(MagicMock(), mem, None, EventBus())

        with patch("sentinel.memory.splitter.split_text", return_value=["hello"]):
            result = await mcp._tool_manager._tools["store_memory"].fn(text="hello")

        data = json.loads(result)
        assert data["status"] == "ok"
        assert data["embedded"] is False


# ── run_task tool ─────────────────────────────────────────────────


class TestRunTaskTool:
    async def test_run_task_no_orchestrator(self):
        """run_task returns error when orchestrator is missing."""
        mcp = create_mcp_server(None, None, None, EventBus())
        result = await mcp._tool_manager._tools["run_task"].fn(request="test")
        data = json.loads(result)
        assert data["status"] == "error"

    async def test_run_task_calls_orchestrator(self):
        """run_task routes through orchestrator.handle_task."""
        orch = AsyncMock()
        orch.handle_task = AsyncMock(return_value=TaskResult(
            status="success", plan_summary="Did the thing",
        ))
        mcp = create_mcp_server(orch, None, None, EventBus())

        result = await mcp._tool_manager._tools["run_task"].fn(request="What is 2+2?")

        data = json.loads(result)
        assert data["status"] == "success"
        orch.handle_task.assert_called_once()
        call_kwargs = orch.handle_task.call_args.kwargs
        assert call_kwargs["user_request"] == "What is 2+2?"
        assert call_kwargs["source"] == "mcp"

    async def test_run_task_handles_exception(self):
        """run_task returns error when orchestrator raises."""
        orch = AsyncMock()
        orch.handle_task = AsyncMock(side_effect=RuntimeError("boom"))
        mcp = create_mcp_server(orch, None, None, EventBus())

        result = await mcp._tool_manager._tools["run_task"].fn(request="test")
        data = json.loads(result)
        assert data["status"] == "error"
        assert "boom" in data["reason"]


# ── Trust tier classification ─────────────────────────────────────


class TestMCPTrustTiers:
    def test_memory_ops_are_safe(self):
        """memory_search and memory_store are classified as SAFE."""
        from sentinel.planner.trust_router import classify_operation, TrustTier
        assert classify_operation("memory_search") == TrustTier.SAFE
        assert classify_operation("memory_store") == TrustTier.SAFE
        assert classify_operation("memory_list") == TrustTier.SAFE

    def test_run_task_is_dangerous(self):
        """run_task is classified as DANGEROUS (not in SAFE_OPS)."""
        from sentinel.planner.trust_router import classify_operation, TrustTier
        assert classify_operation("run_task") == TrustTier.DANGEROUS

    def test_health_check_is_safe(self):
        """health_check is classified as SAFE."""
        from sentinel.planner.trust_router import classify_operation, TrustTier
        assert classify_operation("health_check") == TrustTier.SAFE
