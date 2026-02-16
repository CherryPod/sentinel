import asyncio
import re
import time
import unicodedata
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sse_starlette.sse import EventSourceResponse
from starlette.websockets import WebSocket, WebSocketDisconnect

from sentinel.core.approval import ApprovalManager
from sentinel.core.bus import EventBus
from sentinel.core.db import init_db
from .auth import PinAuthMiddleware, _FailureTracker
from .middleware import CSRFMiddleware, RequestSizeLimitMiddleware, SecurityHeadersMiddleware
from .redirect import HTTPSRedirectApp
from sentinel.audit.logger import setup_audit_logger
from sentinel.core.config import settings
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.planner.orchestrator import Orchestrator
from sentinel.security.pipeline import ScanPipeline, SecurityViolation
from sentinel.planner.planner import ClaudePlanner, PlannerError
from sentinel.security.policy_engine import PolicyEngine
from sentinel.security import codeshield, prompt_guard
from sentinel.security.provenance import ProvenanceStore, set_default_store
from sentinel.security.scanner import CommandPatternScanner, CredentialScanner, SensitivePathScanner
from sentinel.memory.chunks import MemoryStore
from sentinel.memory.embeddings import EmbeddingClient
from sentinel.memory.search import hybrid_search
from sentinel.memory.splitter import split_text
from sentinel.session.store import SessionStore
from sentinel.channels.base import ChannelRouter, IncomingMessage
from sentinel.channels.web import SSEWriter, WebSocketChannel
from sentinel.tools.executor import ToolExecutor

# Rate limiter — per-IP, in-memory storage
limiter = Limiter(key_func=get_remote_address)

# Module-level references populated at startup
_pin: str | None = None
_engine: PolicyEngine | None = None
_cred_scanner: CredentialScanner | None = None
_path_scanner: SensitivePathScanner | None = None
_cmd_scanner: CommandPatternScanner | None = None
_pipeline: ScanPipeline | None = None
_orchestrator: Orchestrator | None = None
_session_store: SessionStore | None = None
_prompt_guard_loaded: bool = False
_codeshield_loaded: bool = False
_planner_available: bool = False
_memory_store: MemoryStore | None = None
_embedding_client: EmbeddingClient | None = None
_event_bus: EventBus | None = None
_mcp_server = None
_ws_failure_tracker = _FailureTracker()
_audit = None

# ── Input validation constants ────────────────────────────────────
MAX_TEXT_LENGTH = 50_000
MIN_TASK_REQUEST_LENGTH = 3
MAX_REASON_LENGTH = 1_000
_CONSECUTIVE_NEWLINES = re.compile(r"\n{3,}")


def _normalize_text(v: str, *, min_length: int = 1, max_length: int = MAX_TEXT_LENGTH, field_name: str = "Text") -> str:
    """Shared validation: strip, NFC normalize, collapse newlines, enforce length."""
    v = v.strip()
    v = unicodedata.normalize("NFC", v)
    v = _CONSECUTIVE_NEWLINES.sub("\n\n", v)
    if not v:
        raise ValueError(f"{field_name} must not be empty")
    if len(v) < min_length:
        raise ValueError(f"{field_name} too short (minimum {min_length} characters)")
    if len(v) > max_length:
        raise ValueError(f"{field_name} too long (maximum {max_length:,} characters)")
    return v


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pin, _engine, _cred_scanner, _path_scanner, _cmd_scanner, _pipeline
    global _prompt_guard_loaded, _codeshield_loaded, _session_store, _audit

    _audit = setup_audit_logger(
        log_dir=settings.log_dir,
        log_level=settings.log_level,
    )
    _audit.info("Starting sentinel-controller", extra={"event": "startup"})

    # Initialize SQLite database
    db_conn = init_db(settings.db_path)
    _audit.info(
        "Database initialized",
        extra={"event": "db_init", "db_path": settings.db_path},
    )

    # Switch provenance to SQLite-backed store
    set_default_store(ProvenanceStore(db=db_conn))

    # Load PIN for authentication
    if settings.pin_required:
        try:
            with open(settings.pin_file) as f:
                _pin = f.read().strip()
            _audit.info("PIN auth enabled", extra={"event": "pin_loaded"})
        except FileNotFoundError:
            _pin = None
            _audit.warning(
                "PIN file not found, auth disabled",
                extra={"event": "pin_missing", "path": settings.pin_file},
            )
    else:
        _pin = None
        _audit.info("PIN auth disabled by config", extra={"event": "pin_disabled"})

    policy_path = settings.policy_file
    _engine = PolicyEngine(policy_path, workspace_path=settings.workspace_path)
    _audit.info(
        "Policy loaded",
        extra={"event": "policy_loaded", "path": policy_path},
    )

    _cred_scanner = CredentialScanner(_engine.policy.get("credential_patterns", []))
    _path_scanner = SensitivePathScanner(_engine.policy.get("sensitive_path_patterns", []))
    _cmd_scanner = CommandPatternScanner()

    # Initialize Prompt Guard (Phase 2)
    if settings.prompt_guard_enabled:
        t0 = time.monotonic()
        _prompt_guard_loaded = prompt_guard.initialize(settings.prompt_guard_model)
        elapsed = time.monotonic() - t0
        _audit.info(
            "Prompt Guard init",
            extra={
                "event": "prompt_guard_init",
                "loaded": _prompt_guard_loaded,
                "elapsed_s": round(elapsed, 2),
            },
        )

    # Initialize scan pipeline (Phase 2)
    _pipeline = ScanPipeline(
        cred_scanner=_cred_scanner,
        path_scanner=_path_scanner,
        cmd_scanner=_cmd_scanner,
    )

    # Initialize CodeShield (Phase 5)
    t0 = time.monotonic()
    _codeshield_loaded = codeshield.initialize()
    elapsed = time.monotonic() - t0
    _audit.info(
        "CodeShield init",
        extra={
            "event": "codeshield_init",
            "loaded": _codeshield_loaded,
            "elapsed_s": round(elapsed, 2),
        },
    )

    # Initialize session store + conversation analyzer (Phase 5)
    global _session_store
    _session_store = SessionStore(db=db_conn)
    conversation_analyzer = ConversationAnalyzer()
    _audit.info(
        "Conversation tracking initialized",
        extra={
            "event": "conversation_init",
            "enabled": settings.conversation_enabled,
            "session_ttl": settings.session_ttl,
        },
    )

    # Initialize memory store + embedding client (Phase 2)
    global _memory_store, _embedding_client
    _memory_store = MemoryStore(db=db_conn)
    _embedding_client = EmbeddingClient(
        base_url=settings.ollama_url,
        model=settings.embeddings_model,
        timeout=settings.embeddings_timeout,
    )
    _audit.info(
        "Memory store initialized",
        extra={
            "event": "memory_init",
            "embeddings_model": settings.embeddings_model,
            "auto_memory": settings.auto_memory,
        },
    )

    # Initialize event bus (Phase 3)
    global _event_bus
    _event_bus = EventBus()
    _audit.info("Event bus initialized", extra={"event": "bus_init"})

    # Initialize Claude planner + orchestrator (Phase 3)
    global _orchestrator, _planner_available
    try:
        planner = ClaudePlanner()
        approval_mgr = ApprovalManager(db=db_conn)
        tool_executor = ToolExecutor(policy_engine=_engine)
        _orchestrator = Orchestrator(
            planner=planner,
            pipeline=_pipeline,
            tool_executor=tool_executor,
            approval_manager=approval_mgr,
            session_store=_session_store,
            conversation_analyzer=conversation_analyzer,
            memory_store=_memory_store,
            embedding_client=_embedding_client,
            event_bus=_event_bus,
        )
        _planner_available = True
        _audit.info(
            "Claude planner initialized",
            extra={"event": "planner_init", "model": settings.claude_model},
        )
    except PlannerError as exc:
        _audit.warning(
            "Claude planner not available: %s",
            exc,
            extra={"event": "planner_init_failed", "error": str(exc)},
        )
        _planner_available = False

    # Initialize MCP server (Phase 3)
    global _mcp_server
    if settings.mcp_enabled:
        try:
            from sentinel.channels.mcp_server import create_mcp_server
            _mcp_server = create_mcp_server(
                orchestrator=_orchestrator,
                memory_store=_memory_store,
                embedding_client=_embedding_client,
                event_bus=_event_bus,
            )
            # Mount MCP transport at /mcp/ — streamable HTTP is the modern approach
            app.mount("/mcp", _mcp_server.streamable_http_app())
            _audit.info("MCP server initialized", extra={"event": "mcp_init"})
        except Exception as exc:
            _audit.warning(
                "MCP server init failed: %s",
                exc,
                extra={"event": "mcp_init_failed", "error": str(exc)},
            )

    # Start HTTP→HTTPS redirect server (only when TLS is active)
    redirect_server = None
    if settings.redirect_enabled and settings.tls_cert_file:
        try:
            import uvicorn
            redirect_config = uvicorn.Config(
                app=HTTPSRedirectApp(),
                host=settings.host,
                port=settings.http_port,
                log_level="warning",
            )
            redirect_server = uvicorn.Server(redirect_config)
            asyncio.create_task(redirect_server.serve())
            _audit.info(
                "HTTP redirect server started",
                extra={
                    "event": "redirect_started",
                    "http_port": settings.http_port,
                    "https_port": settings.external_https_port,
                },
            )
        except Exception as exc:
            _audit.warning(
                "Failed to start redirect server: %s",
                exc,
                extra={"event": "redirect_failed", "error": str(exc)},
            )

    yield

    # Shutdown redirect server if running
    if redirect_server is not None:
        redirect_server.should_exit = True

    # Close database connection
    db_conn.close()

    _audit.info("Shutting down sentinel-controller", extra={"event": "shutdown"})


app = FastAPI(title="Sentinel Controller", lifespan=lifespan)
app.state.limiter = limiter

# Middleware stack (outermost first): SecurityHeaders → RequestSizeLimit → CSRF → PinAuth
# Starlette adds middleware as a stack: last added = outermost = runs first.
app.add_middleware(PinAuthMiddleware, pin_getter=lambda: _pin)
app.add_middleware(
    CSRFMiddleware,
    allowed_origins=[o.strip() for o in settings.allowed_origins.split(",") if o.strip()],
)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Return JSON 429 when rate limit is exceeded."""
    if _audit:
        _audit.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate_limit_exceeded",
                "path": str(request.url.path),
                "remote": request.client.host if request.client else "unknown",
            },
        )
    return JSONResponse(
        status_code=429,
        content={
            "status": "error",
            "reason": "Rate limit exceeded — try again later",
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensure all errors return JSON, never HTML error pages."""
    if _audit:
        _audit.error(
            "Unhandled exception",
            extra={
                "event": "unhandled_exception",
                "path": str(request.url.path),
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "reason": f"Internal server error: {type(exc).__name__}: {exc}",
        },
    )


# ── Root health endpoint (container probes, always outside /api/) ──

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
        "prompt_guard_loaded": _prompt_guard_loaded,
        "codeshield_loaded": _codeshield_loaded,
        "planner_available": _planner_available,
        "conversation_tracking": settings.conversation_enabled,
        "pin_auth_enabled": _pin is not None,
    }


# ── API router (all client-facing endpoints under /api/) ──────────

api_router = APIRouter(prefix="/api")


@api_router.get("/health")
async def api_health():
    """Client-facing health check at /api/health."""
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
        "prompt_guard_loaded": _prompt_guard_loaded,
        "codeshield_loaded": _codeshield_loaded,
        "planner_available": _planner_available,
        "conversation_tracking": settings.conversation_enabled,
        "pin_auth_enabled": _pin is not None,
    }


@api_router.get("/validate/path")
async def validate_path(
    path: str = Query(..., description="File path to validate"),
    operation: str = Query("read", description="'read' or 'write'"),
) -> ValidationResult:
    if _engine is None:
        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=path,
            reason="Policy engine not loaded",
        )

    if operation == "write":
        result = _engine.check_file_write(path)
    else:
        result = _engine.check_file_read(path)

    if _audit:
        _audit.info(
            "Path validation",
            extra={
                "event": "validate_path",
                "path": path,
                "operation": operation,
                "result": result.status.value,
                "reason": result.reason,
            },
        )
    return result


@api_router.get("/validate/command")
async def validate_command(
    command: str = Query(..., description="Shell command to validate"),
) -> ValidationResult:
    if _engine is None:
        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=command,
            reason="Policy engine not loaded",
        )

    result = _engine.check_command(command)

    if _audit:
        _audit.info(
            "Command validation",
            extra={
                "event": "validate_command",
                "command": command,
                "result": result.status.value,
                "reason": result.reason,
            },
        )
    return result


# ── Phase 2 endpoints ────────────────────────────────────────────


class ScanRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")


class ProcessRequest(BaseModel):
    text: str
    untrusted_data: str | None = None

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")

    @field_validator("untrusted_data")
    @classmethod
    def validate_untrusted_data(cls, v: str | None) -> str | None:
        if v is None:
            return v
        # No minimum — can be empty string if explicitly provided, but enforce max
        v = unicodedata.normalize("NFC", v)
        if len(v) > MAX_TEXT_LENGTH:
            raise ValueError(f"Untrusted data too long (maximum {MAX_TEXT_LENGTH:,} characters)")
        return v


@api_router.post("/scan")
async def scan_text(req: ScanRequest):
    """Run full scan pipeline on text (Prompt Guard + credential + path)."""
    if _pipeline is None:
        return {"error": "Pipeline not initialized"}

    result = _pipeline.scan_output(req.text)
    return {
        "clean": result.is_clean,
        "results": {
            name: {
                "found": sr.found,
                "matches": [m.model_dump() for m in sr.matches],
            }
            for name, sr in result.results.items()
        },
    }


@api_router.post("/process")
async def process_text(req: ProcessRequest):
    """Send text through the full Qwen pipeline (scan → spotlight → Qwen → scan)."""
    if _pipeline is None:
        return {"error": "Pipeline not initialized"}

    try:
        tagged = await _pipeline.process_with_qwen(
            prompt=req.text,
            untrusted_data=req.untrusted_data,
        )
        return {
            "status": "ok",
            "data_id": tagged.id,
            "content": tagged.content,
            "trust_level": tagged.trust_level.value,
            "scan_results": {
                name: {
                    "found": sr.found,
                    "matches": [m.model_dump() for m in sr.matches],
                }
                for name, sr in tagged.scan_results.items()
            },
        }
    except SecurityViolation as exc:
        return {
            "status": "blocked",
            "reason": str(exc),
            "violations": {
                name: {
                    "found": sr.found,
                    "matches": [m.model_dump() for m in sr.matches],
                }
                for name, sr in exc.scan_results.items()
            },
        }


# ── Phase 3 endpoints ────────────────────────────────────────────


class TaskRequest(BaseModel):
    request: str
    source: str = "api"
    session_id: str | None = None  # Accepted but ignored — server assigns sessions

    @field_validator("request")
    @classmethod
    def validate_request(cls, v: str) -> str:
        return _normalize_text(v, min_length=MIN_TASK_REQUEST_LENGTH, field_name="Request")


@api_router.post("/task")
@limiter.limit("10/minute")
async def handle_task(req: TaskRequest, request: Request):
    """Full CaMeL pipeline: user request → Claude plans → Qwen executes → scanned result."""
    if _orchestrator is None:
        return {"status": "error", "reason": "Orchestrator not initialized"}

    # Server-side session binding: derive session from client IP, not client-provided ID.
    # This prevents attackers from rotating session IDs to bypass conversation tracking.
    client_ip = request.client.host if request.client else "unknown"
    source_key = f"{req.source}:{client_ip}"

    result = await _orchestrator.handle_task(
        user_request=req.request,
        source=req.source,
        approval_mode=settings.approval_mode,
        source_key=source_key,
    )
    return result.model_dump()


@api_router.get("/approval/{approval_id}")
async def check_approval(approval_id: str):
    """Check the status of an approval request."""
    if _orchestrator is None or _orchestrator._approval_manager is None:
        return {"status": "error", "reason": "Approval manager not available"}

    return _orchestrator._approval_manager.check_approval(approval_id)


class ApprovalDecision(BaseModel):
    granted: bool
    reason: str = ""

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        if len(v) > MAX_REASON_LENGTH:
            raise ValueError(f"Reason too long (maximum {MAX_REASON_LENGTH:,} characters)")
        return v


@api_router.post("/approve/{approval_id}")
async def submit_approval(approval_id: str, decision: ApprovalDecision):
    """Submit an approval decision, then execute the plan if approved."""
    if _orchestrator is None or _orchestrator._approval_manager is None:
        return {"status": "error", "reason": "Approval manager not available"}

    accepted = _orchestrator._approval_manager.submit_approval(
        approval_id=approval_id,
        granted=decision.granted,
        reason=decision.reason,
    )
    if not accepted:
        return {"status": "error", "reason": "Invalid, expired, or duplicate approval"}

    if decision.granted:
        result = await _orchestrator.execute_approved_plan(approval_id)
        return result.model_dump()

    return {"status": "denied", "reason": decision.reason}


# ── Session debug endpoint ─────────────────────────────────────


@api_router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Debug endpoint: view session state and conversation history."""
    if _session_store is None:
        return {"error": "Session store not initialized"}

    session = _session_store.get(session_id)
    if session is None:
        return {"error": "Session not found or expired"}

    return {
        "session_id": session.session_id,
        "source": session.source,
        "turn_count": len(session.turns),
        "cumulative_risk": session.cumulative_risk,
        "violation_count": session.violation_count,
        "is_locked": session.is_locked,
        "turns": [
            {
                "request_preview": t.request_text[:100],
                "result_status": t.result_status,
                "blocked_by": t.blocked_by,
                "risk_score": t.risk_score,
            }
            for t in session.turns
        ],
    }


# ── Memory endpoints (Phase 2) ────────────────────────────────


class MemoryStoreRequest(BaseModel):
    text: str
    source: str = ""
    metadata: dict | None = None

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")


@api_router.post("/memory")
async def store_memory(req: MemoryStoreRequest):
    """Store text in memory — splits large texts into chunks automatically."""
    if _memory_store is None or _embedding_client is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    # Split text into chunks
    chunks = split_text(req.text)
    if not chunks:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reason": "Text produced no chunks after splitting"},
        )

    # Embed all chunks in a single batch call
    try:
        embeddings = await _embedding_client.embed_batch(chunks)
    except Exception as exc:
        # Graceful degradation: store without embeddings if Ollama is unavailable
        if _audit:
            _audit.warning(
                "Embedding failed, storing without vectors",
                extra={"event": "memory_embed_fallback", "error": str(exc)},
            )
        chunk_ids = []
        for chunk_text in chunks:
            cid = _memory_store.store(
                content=chunk_text,
                source=req.source,
                metadata=req.metadata,
            )
            chunk_ids.append(cid)
        return {
            "status": "ok",
            "chunk_ids": chunk_ids,
            "chunks_stored": len(chunk_ids),
            "embedded": False,
        }

    # Store each chunk with its embedding
    chunk_ids = []
    for chunk_text, embedding in zip(chunks, embeddings):
        cid = _memory_store.store_with_embedding(
            content=chunk_text,
            embedding=embedding,
            source=req.source,
            metadata=req.metadata,
        )
        chunk_ids.append(cid)

    return {
        "status": "ok",
        "chunk_ids": chunk_ids,
        "chunks_stored": len(chunk_ids),
        "embedded": True,
    }


@api_router.get("/memory/search")
async def search_memory(
    query: str = Query(..., min_length=1, description="Search query"),
    k: int = Query(10, ge=1, le=100, description="Number of results"),
):
    """Hybrid search across memory — FTS5 keyword + vector semantic with RRF fusion."""
    if _memory_store is None or _memory_store._db is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    # Try to embed the query for vector search; fall back to FTS5-only
    query_embedding = None
    if _embedding_client is not None:
        try:
            query_embedding = await _embedding_client.embed(query)
        except Exception:
            pass  # graceful degradation to FTS5-only

    results = hybrid_search(
        db=_memory_store._db,
        query=query,
        embedding=query_embedding,
        k=k,
    )

    return {
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


@api_router.get("/memory/{chunk_id}")
async def get_memory_chunk(chunk_id: str):
    """Get a specific memory chunk by ID."""
    if _memory_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    chunk = _memory_store.get(chunk_id)
    if chunk is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Chunk not found"},
        )

    return {
        "status": "ok",
        "chunk": {
            "chunk_id": chunk.chunk_id,
            "user_id": chunk.user_id,
            "content": chunk.content,
            "source": chunk.source,
            "metadata": chunk.metadata,
            "created_at": chunk.created_at,
            "updated_at": chunk.updated_at,
        },
    }


@api_router.delete("/memory/{chunk_id}")
async def delete_memory_chunk(chunk_id: str):
    """Delete a memory chunk and its FTS5/vec index entries."""
    if _memory_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    deleted = _memory_store.delete(chunk_id)
    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Chunk not found"},
        )

    return {"status": "ok", "deleted": chunk_id}


# ── WebSocket endpoint (Phase 3) ────────────────────────────────


@api_router.get("/events")
async def sse_events(request: Request, task_id: str = Query(..., min_length=1)):
    """SSE stream for real-time task updates. PIN auth enforced by middleware."""
    if _event_bus is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Event bus not initialized"},
        )

    writer = SSEWriter(_event_bus)
    await writer.subscribe(task_id)
    return EventSourceResponse(writer.event_generator())


# Include API router before static file mount — API routes take priority
app.include_router(api_router)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint with PIN auth and real-time task execution."""
    await websocket.accept()

    channel = WebSocketChannel(
        websocket=websocket,
        pin_getter=lambda: _pin,
        failure_tracker=_ws_failure_tracker,
    )

    if not await channel.authenticate():
        return  # Connection closed with 4001

    if _orchestrator is None or _event_bus is None:
        try:
            await websocket.send_json({
                "type": "error",
                "reason": "Orchestrator not initialized",
            })
        except Exception:
            pass
        await channel.stop()
        return

    router = ChannelRouter(_orchestrator, _event_bus, _audit)

    try:
        async for message in channel.receive():
            msg_type = message.metadata.get("type", "")

            if msg_type == "task":
                # Add source_key for session binding
                client_ip = websocket.client.host if websocket.client else "unknown"
                message.metadata["source_key"] = f"websocket:{client_ip}"
                try:
                    task_id = await router.handle_message(channel, message)
                except Exception as exc:
                    await websocket.send_json({
                        "type": "error",
                        "reason": str(exc),
                    })

            elif msg_type == "approval":
                try:
                    result = await router.handle_approval(
                        channel,
                        approval_id=message.metadata.get("approval_id", ""),
                        granted=message.metadata.get("granted", False),
                        reason=message.metadata.get("reason", ""),
                    )
                    await websocket.send_json({
                        "type": "approval_result",
                        "data": result,
                    })
                except Exception as exc:
                    await websocket.send_json({
                        "type": "error",
                        "reason": str(exc),
                    })

            else:
                await websocket.send_json({
                    "type": "error",
                    "reason": f"Unknown message type: {msg_type}",
                })

    except WebSocketDisconnect:
        pass
    except Exception:
        pass

# Serve static files (UI) at / — catch-all after API routes.
# html=True provides SPA fallback (unmatched paths serve index.html).
# Guarded so tests without a ui/ directory don't crash.
if Path(settings.static_dir).is_dir():
    app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="static")
