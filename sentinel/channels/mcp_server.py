"""MCP server for Sentinel — exposes tools to MCP clients (e.g. Claude Desktop).

Tools are classified into trust tiers:
  - SAFE: memory search, memory store, health check — bypass CaMeL pipeline
  - DANGEROUS: run_task — goes through full CaMeL security pipeline

The MCP server is mounted as a sub-app and handles its own transport.
"""

import json
import logging

from mcp.server.fastmcp import FastMCP

from sentinel.core.config import settings

logger = logging.getLogger("sentinel.audit")


def create_mcp_server(orchestrator, memory_store, embedding_client, event_bus) -> FastMCP:
    """Create and configure the MCP server with all Sentinel tools.

    Args:
        orchestrator: The CaMeL orchestrator for running tasks.
        memory_store: MemoryStore for persistent memory operations.
        embedding_client: EmbeddingClient for generating embeddings.
        event_bus: EventBus for real-time event publishing.

    Returns:
        Configured FastMCP instance ready to be mounted.
    """
    mcp = FastMCP("sentinel")

    @mcp.tool()
    async def search_memory(query: str, k: int = 10) -> str:
        """Search Sentinel's persistent memory using hybrid search (FTS5 + vector).

        Returns up to k results ranked by Reciprocal Rank Fusion.
        This is a SAFE operation — it does not go through the CaMeL pipeline.
        """
        # Clamp k to prevent unbounded result sets
        k = min(k, 100)

        if memory_store is None or memory_store._db is None:
            return json.dumps({"status": "error", "reason": "Memory system not initialized"})

        # Import here to avoid circular imports at module level
        from sentinel.memory.search import hybrid_search

        query_embedding = None
        if embedding_client is not None:
            try:
                query_embedding = await embedding_client.embed(query)
            except Exception:
                pass  # graceful degradation to FTS5-only

        results = hybrid_search(
            db=memory_store._db,
            query=query,
            embedding=query_embedding,
            k=k,
        )

        return json.dumps({
            "status": "ok",
            "results": [
                {
                    "chunk_id": r.chunk_id,
                    "content": r.content,
                    "source": r.source,
                    "score": round(r.score, 6),
                    "match_type": r.match_type,
                }
                for r in results
            ],
            "count": len(results),
        })

    @mcp.tool()
    async def store_memory(text: str, source: str = "mcp") -> str:
        """Store text in Sentinel's persistent memory.

        The text is automatically chunked and embedded for future search.
        This is a SAFE operation — it does not go through the CaMeL pipeline.
        """
        if memory_store is None:
            return json.dumps({"status": "error", "reason": "Memory system not initialized"})

        from sentinel.memory.splitter import split_text

        chunks = split_text(text)
        if not chunks:
            return json.dumps({"status": "error", "reason": "Text produced no chunks"})

        chunk_ids = []
        embedded = False

        if embedding_client is not None:
            try:
                embeddings = await embedding_client.embed_batch(chunks)
                for chunk_text, emb in zip(chunks, embeddings):
                    cid = memory_store.store_with_embedding(
                        content=chunk_text,
                        embedding=emb,
                        source=source,
                    )
                    chunk_ids.append(cid)
                embedded = True
            except Exception:
                pass  # fall through to non-embedded store

        if not chunk_ids:
            for chunk_text in chunks:
                cid = memory_store.store(content=chunk_text, source=source)
                chunk_ids.append(cid)

        return json.dumps({
            "status": "ok",
            "chunk_ids": chunk_ids,
            "chunks_stored": len(chunk_ids),
            "embedded": embedded,
        })

    @mcp.tool()
    async def run_task(request: str) -> str:
        """Submit a task through the full CaMeL security pipeline.

        The task is planned by Claude, executed by Qwen, and scanned at every step.
        This is a DANGEROUS operation — it uses the full CaMeL pipeline with all
        10 security layers active.
        """
        if orchestrator is None:
            return json.dumps({"status": "error", "reason": "Orchestrator not initialized"})

        try:
            result = await orchestrator.handle_task(
                user_request=request,
                source="mcp",
                approval_mode=settings.approval_mode,
            )
            return json.dumps(result.model_dump(), default=str)
        except Exception as exc:
            logger.error(
                "MCP run_task failed",
                extra={"event": "mcp_task_error", "error": str(exc)},
            )
            return json.dumps({"status": "error", "reason": str(exc)})

    @mcp.tool()
    async def health_check() -> str:
        """Check Sentinel system health and component status.

        This is a SAFE operation — it does not go through the CaMeL pipeline.
        """
        return json.dumps({
            "status": "ok",
            "orchestrator": orchestrator is not None,
            "memory": memory_store is not None,
            "embeddings": embedding_client is not None,
            "event_bus": event_bus is not None,
        })

    return mcp
