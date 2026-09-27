"""MCP server for Sentinel — exposes tools to MCP clients (e.g. Claude Desktop).

Tools are classified into trust tiers:
  - SAFE: memory search, memory store, health check — bypass CaMeL pipeline
  - DANGEROUS: run_task — goes through full CaMeL security pipeline

The MCP server is mounted as a sub-app and handles its own transport.
Authentication is enforced via Bearer token (SENTINEL_MCP_AUTH_TOKEN).
"""

import hashlib
import hmac
import json
import logging
from uuid import uuid4

from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from sentinel.core.config import settings
from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import create_tagged_data

logger = logging.getLogger(__name__)

# MCP input size caps — module-level constants
MCP_MAX_TASK_LENGTH = 10_000
MCP_MAX_MEMORY_LENGTH = 50_000


class MCPAuthMiddleware:
    """ASGI middleware that enforces Bearer token auth on MCP endpoints.

    Wraps the MCP sub-app. Rejects requests without a valid Authorization
    header. Uses constant-time comparison to prevent timing attacks.
    """

    def __init__(self, app: ASGIApp, token: str):
        self._app = app
        self._token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            # Extract Authorization header from ASGI scope
            headers = dict(scope.get("headers", []))
            auth_value = headers.get(b"authorization", b"").decode(
                "utf-8", errors="replace"
            )

            expected = f"Bearer {self._token}"
            # Q13-F10: hmac.compare_digest is constant-time only across equal-
            # length inputs; mismatched lengths short-circuit and leak the
            # expected length via timing. Hash both sides to fixed-length
            # SHA-256 digests before comparison so length is unobservable.
            auth_digest = hashlib.sha256(auth_value.encode("utf-8")).digest()
            expected_digest = hashlib.sha256(expected.encode("utf-8")).digest()
            if not auth_value or not hmac.compare_digest(auth_digest, expected_digest):
                response = JSONResponse(
                    status_code=401,
                    content={
                        "status": "error",
                        "reason": "MCP: invalid or missing auth token",
                    },
                )
                await response(scope, receive, send)
                return

        await self._app(scope, receive, send)


def create_mcp_server(
    orchestrator, memory_store, embedding_client, event_bus
) -> FastMCP:
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
        """Search Sentinel's persistent memory using hybrid search (full-text + vector).

        Returns up to k results ranked by Reciprocal Rank Fusion.
        This is a SAFE operation — it does not go through the CaMeL pipeline.
        """
        # Clamp k to prevent unbounded result sets
        k = min(k, 100)

        if memory_store is None or memory_store.pool is None:
            return json.dumps(
                {"status": "error", "reason": "Memory system not initialized"}
            )

        # Import here to avoid circular imports at module level
        from sentinel.memory.search import hybrid_search

        query_embedding = None
        if embedding_client is not None:
            try:
                query_embedding = await embedding_client.embed(query)
            except Exception:  # catch-all: embedding fallback to FTS-only
                logger.debug(
                    "search_memory: Exception suppressed",
                    extra={"event": "mcp_server.search_memory.suppressed"},
                    exc_info=True,
                )

        results = await hybrid_search(
            pool=memory_store.pool,
            query=query,
            embedding=query_embedding,
            k=k,
        )

        return json.dumps(
            {
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
            }
        )

    @mcp.tool()
    async def store_memory(text: str, source: str = "mcp") -> str:
        """Store text in Sentinel's persistent memory.

        The text is automatically chunked and embedded for future search.
        This is a SAFE operation — it does not go through the CaMeL pipeline.
        """
        if memory_store is None:
            return json.dumps(
                {"status": "error", "reason": "Memory system not initialized"}
            )

        if len(text) > MCP_MAX_MEMORY_LENGTH:
            return json.dumps(
                {
                    "status": "error",
                    "reason": f"Text too long ({len(text)} chars, max {MCP_MAX_MEMORY_LENGTH})",
                }
            )

        from sentinel.memory.splitter import split_text

        chunks = split_text(text)
        if not chunks:
            return json.dumps({"status": "error", "reason": "Text produced no chunks"})

        chunk_ids = []
        embedded = False

        if embedding_client is not None:
            try:
                embeddings = await embedding_client.embed_batch(chunks)
                for chunk_text, emb in zip(chunks, embeddings, strict=True):
                    cid = await memory_store.store_with_embedding(
                        content=chunk_text,
                        embedding=emb,
                        source=source,
                    )
                    chunk_ids.append(cid)
                embedded = True
            except Exception:  # catch-all: embedding fallback to plain store
                logger.debug(
                    "store_memory: Exception suppressed",
                    extra={"event": "mcp_server.store_memory.suppressed"},
                    exc_info=True,
                )

        if not chunk_ids:
            logger.debug(
                "store_memory: falling back to text-only storage",
                extra={"event": "mcp_server.store_memory.text_only"},
            )
            for chunk_text in chunks:
                cid = await memory_store.store(content=chunk_text, source=source)
                chunk_ids.append(cid)

        return json.dumps(
            {
                "status": "ok",
                "chunk_ids": chunk_ids,
                "chunks_stored": len(chunk_ids),
                "embedded": embedded,
            }
        )

    @mcp.tool()
    async def run_task(request: str) -> str:
        """Submit a task through the full CaMeL security pipeline.

        The task is planned by Claude, executed by Qwen, and scanned at every step.
        This is a DANGEROUS operation — it uses the full CaMeL pipeline with all
        10 security layers active.
        """
        if orchestrator is None:
            return json.dumps(
                {"status": "error", "reason": "Orchestrator not initialized"}
            )

        if len(request) > MCP_MAX_TASK_LENGTH:
            return json.dumps(
                {
                    "status": "error",
                    "reason": f"Request too long ({len(request)} chars, max {MCP_MAX_TASK_LENGTH})",
                }
            )

        try:
            # NOTE: MCP has no per-client auth — a per-call UUID prevents shared
            # session state across concurrent invocations, but cross-client
            # principal identity is still unresolved (see audit U1/SEC-1).
            task_id = str(uuid4())
            source_key = f"mcp:{task_id}"  # reuse the task UUID — one per call

            # Q8.fix.b — wrap the MCP run_task request as UNTRUSTED at the
            # adapter boundary. MCP `run_task(request: str)` parameter shape
            # is declared at the MCP tool boundary with no trust field; D4
            # fail-closed holds.
            tagged_request = await create_tagged_data(
                content=request,
                source=DataSource.USER,
                trust_level=TrustLevel.UNTRUSTED,
                originated_from=f"ingress:mcp:run_task:{source_key}",
            )
            user_request_data_id = tagged_request.id
            logger.info(
                "MCP run_task ingress tagged UNTRUSTED",
                extra={
                    "event": "mcp.run_task.ingress_tagged",
                    "task_id": task_id,
                    "data_id": user_request_data_id,
                    "request_len": len(request),
                },
            )

            result = await orchestrator.handle_task(
                user_request=request,
                source="mcp",
                source_key=source_key,
                task_id=task_id,
                approval_mode=settings.approval_mode,
                user_request_data_id=user_request_data_id,
            )
            return json.dumps(result.model_dump(), default=str)
        except Exception as exc:  # catch-all: MCP handler boundary
            # Q14-F7: raw str(exc) was returned in the MCP JSON error body to
            # external MCP clients (AI consumers of the Sentinel MCP server).
            # Whatever exception text escaped the orchestrator or tool stack —
            # internal paths, tool args, asyncpg schema hints — was reflected
            # verbatim. Fixed safe reason; detail stays server-side via
            # exc_info=True on the warning above.
            logger.warning(
                "MCP run_task failed",
                extra={"event": "mcp.task_error", "error": str(exc)},
                exc_info=True,
            )
            return json.dumps(
                {"status": "error", "reason": "Task processing failed"},
            )

    @mcp.tool()
    async def health_check() -> str:
        """Check Sentinel system health and component status.

        This is a SAFE operation — it does not go through the CaMeL pipeline.
        """
        return json.dumps(
            {
                "status": "ok",
                "orchestrator": orchestrator is not None,
                "memory": memory_store is not None,
                "embeddings": embedding_client is not None,
                "event_bus": event_bus is not None,
            }
        )

    return mcp


def wrap_mcp_with_auth(mcp_app: ASGIApp, token: str) -> ASGIApp:
    """Wrap an MCP ASGI app with Bearer token authentication.

    Args:
        mcp_app: The ASGI app from mcp.streamable_http_app().
        token: The expected Bearer token value.

    Returns:
        The wrapped ASGI app that rejects unauthenticated requests.
    """
    return MCPAuthMiddleware(mcp_app, token)
