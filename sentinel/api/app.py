import asyncio
import json
import logging
import re
import sqlite3
import time
import unicodedata
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
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
from .auth import PinAuthMiddleware, PinVerifier, _FailureTracker
from .middleware import CSRFMiddleware, RequestSizeLimitMiddleware, SecurityHeadersMiddleware
from .redirect import HTTPSRedirectApp
from sentinel.audit.logger import setup_audit_logger
from sentinel.core.config import settings
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.api.metrics import get_metrics
from sentinel.planner.orchestrator import Orchestrator
from sentinel.security.pipeline import ScanPipeline, SecurityViolation
from sentinel.planner.planner import ClaudePlanner, PlannerError
from sentinel.security.policy_engine import PolicyEngine
from sentinel.security import semgrep_scanner, prompt_guard
from sentinel.security.provenance import ProvenanceStore, set_default_store
from sentinel.security.scanner import CommandPatternScanner, CredentialScanner, SensitivePathScanner
from sentinel.memory.chunks import MemoryStore
from sentinel.memory.embeddings import EmbeddingClient
from sentinel.memory.search import hybrid_search
from sentinel.memory.splitter import split_text
from sentinel.session.store import SessionStore
from sentinel.api.a2a import (
    AGENT_CARD,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    a2a_sse_generator,
    build_a2a_task,
    handle_tasks_get,
    handle_tasks_send,
    jsonrpc_error,
    jsonrpc_success,
    parse_jsonrpc_request,
)
from sentinel.channels.base import ChannelRouter, IncomingMessage
from sentinel.channels.signal_channel import SignalChannel, SignalConfig
from sentinel.channels.telegram_channel import TelegramChannel, TelegramConfig
from sentinel.channels.web import SSEWriter, WebSocketChannel
from sentinel.channels.webhook import (
    RateLimiter as WebhookRateLimiter,
    WebhookRegistry,
    check_idempotency,
    verify_signature,
    verify_timestamp,
)
from sentinel.routines.cron import validate_trigger_config
from sentinel.routines.engine import RoutineEngine
from sentinel.routines.heartbeat import HeartbeatManager, seed_heartbeat_routine
from sentinel.routines.store import RoutineStore
from sentinel.tools.executor import ToolExecutor
from sentinel.tools.sandbox import PodmanSandbox
from sentinel.tools.sidecar import SidecarClient
from sentinel.worker.factory import create_embedding_client, create_planner

# Rate limiter — per-IP, in-memory storage
limiter = Limiter(key_func=get_remote_address)

# Module-level references populated at startup
_pin_verifier: PinVerifier | None = None
_engine: PolicyEngine | None = None
_cred_scanner: CredentialScanner | None = None
_path_scanner: SensitivePathScanner | None = None
_cmd_scanner: CommandPatternScanner | None = None
_pipeline: ScanPipeline | None = None
_orchestrator: Orchestrator | None = None
_session_store: SessionStore | None = None
_prompt_guard_loaded: bool = False
_semgrep_loaded: bool = False
_planner_available: bool = False
_memory_store: MemoryStore | None = None
_embedding_client: EmbeddingClient | None = None
_event_bus: EventBus | None = None
_mcp_server = None
_routine_store: RoutineStore | None = None
_routine_engine: RoutineEngine | None = None
_sidecar: SidecarClient | None = None
_sandbox: PodmanSandbox | None = None
_signal_channel: SignalChannel | None = None
_telegram_channel: TelegramChannel | None = None
_ws_failure_tracker = _FailureTracker()
_webhook_registry: WebhookRegistry | None = None
_webhook_rate_limiter: WebhookRateLimiter | None = None
# In-memory only — cleared on restart. Acceptable for single-instance
# self-hosted deployment. Duplicate webhook delivery re-runs idempotently.
_idempotency_cache: dict = {}
_heartbeat_manager: HeartbeatManager | None = None
_db: sqlite3.Connection | None = None
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
    global _pin_verifier, _engine, _cred_scanner, _path_scanner, _cmd_scanner, _pipeline
    global _prompt_guard_loaded, _semgrep_loaded, _session_store, _audit, _db

    _audit = setup_audit_logger(
        log_dir=settings.log_dir,
        log_level=settings.log_level,
    )
    _audit.info("Starting sentinel-controller", extra={"event": "startup"})

    # Initialize SQLite database
    db_conn = init_db(settings.db_path)
    _db = db_conn
    _audit.info(
        "Database initialized",
        extra={"event": "db_init", "db_path": settings.db_path},
    )

    # Switch provenance to SQLite-backed store
    set_default_store(ProvenanceStore(db=db_conn))

    # Load PIN for authentication — hash immediately, never store plaintext (H-002)
    if settings.pin_required:
        try:
            with open(settings.pin_file) as f:
                raw_pin = f.read().strip()
            _pin_verifier = PinVerifier(raw_pin)
            del raw_pin  # Clear plaintext from local scope
            _audit.info("PIN auth enabled (hashed)", extra={"event": "pin_loaded"})
        except FileNotFoundError:
            _pin_verifier = None
            _audit.warning(
                "PIN file not found, auth disabled",
                extra={"event": "pin_missing", "path": settings.pin_file},
            )
    else:
        _pin_verifier = None
        _audit.info("PIN auth disabled by config", extra={"event": "pin_disabled"})

    policy_path = settings.policy_file
    _engine = PolicyEngine(
        policy_path,
        workspace_path=settings.workspace_path,
        trust_level=settings.trust_level,
    )
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

    # Initialize Semgrep scanner (replaces CodeShield)
    t0 = time.monotonic()
    _semgrep_loaded = semgrep_scanner.initialize()
    elapsed = time.monotonic() - t0
    _audit.info(
        "Semgrep init",
        extra={
            "event": "semgrep_init",
            "loaded": _semgrep_loaded,
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

    # Initialize memory store + embedding client (Phase 2, factory in Phase 5)
    global _memory_store, _embedding_client
    _memory_store = MemoryStore(db=db_conn)
    _embedding_client = create_embedding_client(settings)
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

    # Initialize WASM sidecar (Phase 4) — opt-in via SENTINEL_SIDECAR_ENABLED
    global _sidecar
    if settings.sidecar_enabled:
        _sidecar = SidecarClient(
            socket_path=settings.sidecar_socket,
            timeout=settings.sidecar_timeout,
            sidecar_binary_path=settings.sidecar_binary,
            tool_dir=settings.sidecar_tool_dir,
        )
        _audit.info(
            "WASM sidecar client initialized",
            extra={
                "event": "sidecar_init",
                "socket": settings.sidecar_socket,
                "binary": settings.sidecar_binary,
                "tool_dir": settings.sidecar_tool_dir,
            },
        )
    else:
        _audit.info("WASM sidecar disabled", extra={"event": "sidecar_disabled"})

    # Initialize Podman sandbox (E5) — opt-in via SENTINEL_SANDBOX_ENABLED
    global _sandbox
    if settings.sandbox_enabled:
        _sandbox = PodmanSandbox(
            socket_path=settings.sandbox_socket,
            image=settings.sandbox_image,
            default_timeout=settings.sandbox_timeout,
            max_timeout=settings.sandbox_max_timeout,
            memory_limit=settings.sandbox_memory_limit,
            cpu_quota=settings.sandbox_cpu_quota,
            workspace_volume=settings.sandbox_workspace_volume,
            output_limit=settings.sandbox_output_limit,
        )
        # Health check — verify socket and image are available
        sandbox_healthy = await _sandbox.health_check()
        if sandbox_healthy:
            # Clean up any stale containers from previous runs
            cleaned = await _sandbox.cleanup_stale()
            _audit.info(
                "Podman sandbox initialized",
                extra={
                    "event": "sandbox_init",
                    "socket": settings.sandbox_socket,
                    "image": settings.sandbox_image,
                    "stale_cleaned": cleaned,
                },
            )
        else:
            _audit.warning(
                "Podman sandbox health check failed — sandbox disabled",
                extra={"event": "sandbox_init_failed"},
            )
            _sandbox = None
    else:
        _audit.info("Podman sandbox disabled", extra={"event": "sandbox_disabled"})

    # Initialize Google OAuth2 manager (B3) — needed by B4 (Gmail) and B5 (Calendar)
    google_oauth = None
    if settings.google_oauth_client_id and settings.google_oauth_client_secret_file:
        try:
            from sentinel.integrations.google_auth import GoogleOAuthManager
            # Read client secret from file
            with open(settings.google_oauth_client_secret_file) as f:
                client_secret = f.read().strip()
            scopes = [s.strip() for s in settings.google_oauth_scopes.split(",") if s.strip()]
            google_oauth = GoogleOAuthManager(
                client_id=settings.google_oauth_client_id,
                client_secret=client_secret,
                refresh_token_file=settings.google_oauth_refresh_token_file,
                scopes=scopes,
            )
            _audit.info(
                "Google OAuth2 manager initialized",
                extra={"event": "google_oauth_init", "scopes": len(scopes)},
            )
        except Exception as exc:
            _audit.warning(
                "Google OAuth2 init failed: %s",
                exc,
                extra={"event": "google_oauth_init_failed", "error": str(exc)},
            )

    # Initialize routine store (needed by orchestrator for SAFE tool handlers)
    global _routine_store
    _routine_store = RoutineStore(db=db_conn)

    # Initialize planner + orchestrator (Phase 3, factory in Phase 5)
    global _orchestrator, _planner_available
    try:
        planner = create_planner(settings)
        approval_mgr = ApprovalManager(db=db_conn)
        tool_executor = ToolExecutor(
            policy_engine=_engine,
            sidecar=_sidecar,
            google_oauth=google_oauth,
            sandbox=_sandbox,
            trust_level=settings.trust_level,
        )
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
            routine_store=_routine_store,
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

    # Initialize routine engine (Phase 5) — opt-in via SENTINEL_ROUTINE_ENABLED
    global _routine_engine
    if settings.routine_enabled and _orchestrator is not None:
        _routine_engine = RoutineEngine(
            store=_routine_store,
            orchestrator=_orchestrator,
            event_bus=_event_bus,
            db=db_conn,
            tick_interval=settings.routine_scheduler_interval,
            max_concurrent=settings.routine_max_concurrent,
            execution_timeout=settings.routine_execution_timeout,
        )
        await _routine_engine.start()
        _routine_engine.seed_defaults()
        # Wire routine engine into orchestrator (breaks circular dep:
        # RoutineEngine needs Orchestrator, Orchestrator needs RoutineEngine)
        _orchestrator.set_routine_engine(_routine_engine)
        _audit.info(
            "Routine engine started",
            extra={
                "event": "routine_engine_init",
                "tick_interval": settings.routine_scheduler_interval,
                "max_concurrent": settings.routine_max_concurrent,
            },
        )
    else:
        _audit.info(
            "Routine engine disabled",
            extra={
                "event": "routine_engine_disabled",
                "routine_enabled": settings.routine_enabled,
                "orchestrator_available": _orchestrator is not None,
            },
        )

    # Initialize webhook registry (C1)
    global _webhook_registry, _webhook_rate_limiter
    _webhook_registry = WebhookRegistry(db=db_conn)
    _webhook_rate_limiter = WebhookRateLimiter()
    _audit.info("Webhook registry initialized", extra={"event": "webhook_init"})

    # Initialize heartbeat system (C2)
    global _heartbeat_manager

    async def _health_check() -> dict:
        sidecar_status = "disabled"
        if _sidecar is not None:
            sidecar_status = "running" if _sidecar.is_running else "stopped"
        signal_status = "disabled"
        if _signal_channel is not None:
            signal_status = "running" if _signal_channel._running else "stopped"
        sandbox_status = "disabled"
        if _sandbox is not None:
            sandbox_status = "enabled"
        telegram_status = "disabled"
        if _telegram_channel is not None:
            telegram_status = "running" if _telegram_channel._running else "stopped"
        return {
            "planner_available": _planner_available,
            "semgrep_loaded": _semgrep_loaded,
            "prompt_guard_loaded": _prompt_guard_loaded,
            "sidecar": sidecar_status,
            "signal": signal_status,
            "telegram": telegram_status,
            "sandbox": sandbox_status,
        }

    _heartbeat_manager = HeartbeatManager(
        memory_store=_memory_store,
        health_check_fn=_health_check,
        db=db_conn,
    )
    if _routine_store is not None:
        seed_heartbeat_routine(_routine_store)

    async def _heartbeat_loop() -> None:
        while True:
            await asyncio.sleep(1800)  # 30 minutes
            try:
                await _heartbeat_manager.run_heartbeat()
            except Exception as e:
                logging.getLogger("sentinel.audit").warning(
                    "Heartbeat error: %s", e,
                    extra={"event": "heartbeat_error", "error": str(e)},
                )

    asyncio.create_task(_heartbeat_loop())
    _audit.info("Heartbeat system initialized", extra={"event": "heartbeat_init"})

    # Initialize Signal channel (A3) — opt-in via SENTINEL_SIGNAL_ENABLED
    global _signal_channel
    if settings.signal_enabled and _orchestrator is not None and _event_bus is not None:
        allowed = {
            s.strip() for s in settings.signal_allowed_senders.split(",") if s.strip()
        }
        sig_config = SignalConfig(
            signal_cli_path=settings.signal_cli_path,
            signal_cli_config=settings.signal_cli_config,
            socket_path=settings.signal_socket_path,
            account=settings.signal_account,
            allowed_senders=allowed,
            rate_limit=settings.signal_rate_limit,
            max_message_length=settings.signal_max_message_length,
        )
        _signal_channel = SignalChannel(sig_config, event_bus=_event_bus)
        await _signal_channel.start()

        # Background task: consume incoming Signal messages and route through orchestrator
        async def _signal_receive_loop() -> None:
            router = ChannelRouter(_orchestrator, _event_bus, _audit)
            async for message in _signal_channel.receive():
                try:
                    message.metadata["source_key"] = f"signal:{message.channel_id}"
                    await router.handle_message(_signal_channel, message)
                except Exception as exc:
                    logger.error(
                        "Signal message handling failed",
                        extra={"event": "signal_handle_error", "error": str(exc)},
                    )

        asyncio.create_task(_signal_receive_loop())
        _audit.info(
            "Signal channel started",
            extra={
                "event": "signal_channel_init",
                "account": settings.signal_account,
                "allowed_senders": len(allowed),
                "rate_limit": settings.signal_rate_limit,
            },
        )
    else:
        _audit.info(
            "Signal channel disabled",
            extra={
                "event": "signal_channel_disabled",
                "signal_enabled": settings.signal_enabled,
                "orchestrator_available": _orchestrator is not None,
            },
        )

    # Initialize Telegram channel — opt-in via SENTINEL_TELEGRAM_ENABLED
    global _telegram_channel
    if settings.telegram_enabled and _orchestrator is not None and _event_bus is not None:
        try:
            token = ""
            if settings.telegram_bot_token_file:
                with open(settings.telegram_bot_token_file) as f:
                    token = f.read().strip()

            allowed_chats: set[int] = set()
            if settings.telegram_allowed_chat_ids:
                allowed_chats = {
                    int(c.strip())
                    for c in settings.telegram_allowed_chat_ids.split(",")
                    if c.strip()
                }

            tg_config = TelegramConfig(
                bot_token=token,
                allowed_chat_ids=allowed_chats,
                rate_limit=settings.telegram_rate_limit,
                max_message_length=settings.telegram_max_message_length,
                polling_timeout=settings.telegram_polling_timeout,
            )
            _telegram_channel = TelegramChannel(tg_config, event_bus=_event_bus)
            await _telegram_channel.start()

            # Background task: consume incoming Telegram messages
            async def _telegram_receive_loop() -> None:
                router = ChannelRouter(_orchestrator, _event_bus, _audit)
                async for message in _telegram_channel.receive():
                    try:
                        message.metadata["source_key"] = f"telegram:{message.channel_id}"
                        await router.handle_message(_telegram_channel, message)
                    except Exception as exc:
                        logger.error(
                            "Telegram message handling failed",
                            extra={"event": "telegram_handle_error", "error": str(exc)},
                        )

            asyncio.create_task(_telegram_receive_loop())
            await _telegram_channel.start_polling()

            _audit.info(
                "Telegram channel started",
                extra={
                    "event": "telegram_channel_init",
                    "allowed_chats": len(allowed_chats),
                    "rate_limit": settings.telegram_rate_limit,
                },
            )
        except Exception as exc:
            logger.error(
                "Telegram channel failed to start",
                extra={"event": "telegram_channel_error", "error": str(exc)},
            )
    else:
        _audit.info(
            "Telegram channel disabled",
            extra={"event": "telegram_channel_disabled"},
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

    # Mount static files LAST — the "/" catch-all must come after every
    # other route (API, WebSocket, MCP, red-team).  Routes added during
    # lifespan (like the B2 red-team endpoint) are appended to app.routes,
    # so any catch-all registered at module level would shadow them.
    if Path(settings.static_dir).is_dir():
        app.mount(
            "/", StaticFiles(directory=settings.static_dir, html=True), name="static",
        )

    yield

    # Shutdown Signal channel if running
    if _signal_channel is not None:
        await _signal_channel.stop()

    # Shutdown Telegram channel if running
    if _telegram_channel is not None:
        await _telegram_channel.stop()

    # Shutdown WASM sidecar if running
    if _sidecar is not None:
        await _sidecar.stop_sidecar()

    # Shutdown routine engine if running
    if _routine_engine is not None:
        await _routine_engine.stop()

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
app.add_middleware(PinAuthMiddleware, pin_verifier_getter=lambda: _pin_verifier)
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
            "reason": "Internal server error",
        },
    )


# ── Root health endpoint (container probes, always outside /api/) ──

@app.get("/health")
async def health():
    sidecar_status = "disabled"
    if _sidecar is not None:
        sidecar_status = "running" if _sidecar.is_running else "stopped"
    signal_status = "disabled"
    if _signal_channel is not None:
        signal_status = "running" if _signal_channel._running else "stopped"
    sandbox_status = "disabled"
    if _sandbox is not None:
        sandbox_status = "enabled"
    telegram_status = "disabled"
    if _telegram_channel is not None:
        telegram_status = "running" if _telegram_channel._running else "stopped"
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
        "prompt_guard_loaded": _prompt_guard_loaded,
        "semgrep_loaded": _semgrep_loaded,
        "planner_available": _planner_available,
        "conversation_tracking": settings.conversation_enabled,
        "pin_auth_enabled": _pin_verifier is not None,
        "sidecar": sidecar_status,
        "signal": signal_status,
        "telegram": telegram_status,
        "sandbox": sandbox_status,
    }


# ── A2A protocol endpoints ─────────────────────────────────────────
# Agent Card discovery + JSON-RPC 2.0 task endpoint.
# These live outside /api/ to match A2A spec conventions.


@app.get("/.well-known/agent.json")
async def agent_card():
    """A2A Agent Card — static metadata for agent discovery."""
    return JSONResponse(content=AGENT_CARD)


@app.post("/a2a")
@limiter.limit("10/minute")
async def a2a_endpoint(request: Request):
    """A2A JSON-RPC 2.0 endpoint — translates A2A methods to Sentinel internals.

    Supported methods:
      - tasks/send: submit a task (maps to orchestrator.handle_task)
      - tasks/sendSubscribe: submit + stream SSE updates
      - tasks/get: query task/approval status
      - tasks/cancel: not yet implemented (returns method-not-found)
    """
    # Parse JSON body
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content=jsonrpc_error(None, INVALID_REQUEST, "Invalid JSON"))

    # Validate JSON-RPC structure
    parsed = parse_jsonrpc_request(body)
    if isinstance(parsed, dict):
        # parse_jsonrpc_request returned an error response
        return JSONResponse(content=parsed)

    req_id, method, params = parsed

    # Route to the appropriate handler
    if method == "tasks/send":
        if _orchestrator is None:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Orchestrator not initialized"),
            )
        try:
            client_ip = request.client.host if request.client else "unknown"
            task_result = await handle_tasks_send(params, _orchestrator, client_ip)
            a2a_task = build_a2a_task(task_result)
            return JSONResponse(content=jsonrpc_success(req_id, a2a_task))
        except ValueError as exc:
            return JSONResponse(
                content=jsonrpc_error(req_id, INVALID_REQUEST, str(exc)),
            )
        except Exception as exc:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, f"Task execution failed: {exc}"),
            )

    elif method == "tasks/sendSubscribe":
        if _orchestrator is None or _event_bus is None:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Orchestrator not initialized"),
            )
        try:
            client_ip = request.client.host if request.client else "unknown"
            task_result = await handle_tasks_send(params, _orchestrator, client_ip)
            return EventSourceResponse(
                a2a_sse_generator(task_result, _event_bus),
            )
        except ValueError as exc:
            return JSONResponse(
                content=jsonrpc_error(req_id, INVALID_REQUEST, str(exc)),
            )
        except Exception as exc:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, f"Task failed: {exc}"),
            )

    elif method == "tasks/get":
        if _orchestrator is None:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Orchestrator not initialized"),
            )
        try:
            task = await handle_tasks_get(params, _orchestrator)
            if task is None:
                return JSONResponse(
                    content=jsonrpc_error(req_id, INVALID_REQUEST, "Task not found"),
                )
            return JSONResponse(content=jsonrpc_success(req_id, task))
        except Exception as exc:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, f"Lookup failed: {exc}"),
            )

    elif method == "tasks/cancel":
        return JSONResponse(
            content=jsonrpc_error(req_id, METHOD_NOT_FOUND, "tasks/cancel not yet implemented"),
        )

    else:
        return JSONResponse(
            content=jsonrpc_error(req_id, METHOD_NOT_FOUND, f"Unknown method: {method}"),
        )


# ── API router (all client-facing endpoints under /api/) ──────────

api_router = APIRouter(prefix="/api")


@api_router.get("/health")
async def api_health():
    """Client-facing health check at /api/health."""
    sidecar_status = "disabled"
    if _sidecar is not None:
        sidecar_status = "running" if _sidecar.is_running else "stopped"
    signal_status = "disabled"
    if _signal_channel is not None:
        signal_status = "running" if _signal_channel._running else "stopped"
    sandbox_status = "disabled"
    if _sandbox is not None:
        sandbox_status = "enabled"
    telegram_status = "disabled"
    if _telegram_channel is not None:
        telegram_status = "running" if _telegram_channel._running else "stopped"
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
        "prompt_guard_loaded": _prompt_guard_loaded,
        "semgrep_loaded": _semgrep_loaded,
        "planner_available": _planner_available,
        "conversation_tracking": settings.conversation_enabled,
        "pin_auth_enabled": _pin_verifier is not None,
        "sidecar": sidecar_status,
        "signal": signal_status,
        "telegram": telegram_status,
        "sandbox": sandbox_status,
    }


@api_router.get("/metrics")
async def dashboard_metrics(
    window: str = Query("24h", pattern=r"^(24h|7d|30d|all)$"),
):
    """Dashboard metrics aggregated over a time window."""
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    data = get_metrics(_db, window)
    return {
        "status": "ok",
        "window": window,
        "trust_level": settings.trust_level,
        "data": data,
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


# Valid source values for task requests. Unknown values default to "api"
# to prevent session-key rotation (different source = different session = reset risk scores).
_VALID_TASK_SOURCES = frozenset({"api", "signal", "webhook", "mcp"})


class TaskRequest(BaseModel):
    request: str
    source: str = "api"
    session_id: str | None = None  # Accepted but ignored — server assigns sessions

    @field_validator("request")
    @classmethod
    def validate_request(cls, v: str) -> str:
        return _normalize_text(v, min_length=MIN_TASK_REQUEST_LENGTH, field_name="Request")

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        # In benchmark mode, allow arbitrary source values so the stress test
        # can create unique sessions per prompt (bypasses H-003 restriction).
        if settings.benchmark_mode:
            return v
        if v not in _VALID_TASK_SOURCES:
            return "api"
        return v


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
    if _memory_store is None or _memory_store.db is None:
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
        db=_memory_store.db,
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


@api_router.get("/memory/list")
async def list_memory_chunks(
    limit: int = Query(50, ge=1, le=500, description="Number of chunks to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """List memory chunks, newest first. Paginated."""
    if _memory_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Memory system not initialized"},
        )

    chunks = _memory_store.list_chunks(limit=limit, offset=offset)
    return {
        "status": "ok",
        "chunks": [
            {
                "chunk_id": c.chunk_id,
                "content": c.content,
                "source": c.source,
                "created_at": c.created_at,
                "updated_at": c.updated_at,
            }
            for c in chunks
        ],
        "count": len(chunks),
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

    try:
        deleted = _memory_store.delete(chunk_id)
    except ValueError as exc:
        return JSONResponse(
            status_code=403,
            content={"status": "error", "reason": str(exc)},
        )

    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Chunk not found"},
        )

    return {"status": "ok", "deleted": chunk_id}


# ── Routine endpoints (Phase 5) ─────────────────────────────────


class CreateRoutineRequest(BaseModel):
    name: str
    trigger_type: str
    trigger_config: dict
    action_config: dict
    description: str = ""
    enabled: bool = True
    cooldown_s: int = 0

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, max_length=200, field_name="Name")

    @field_validator("trigger_type")
    @classmethod
    def validate_trigger_type(cls, v: str) -> str:
        if v not in ("cron", "event", "interval"):
            raise ValueError("trigger_type must be 'cron', 'event', or 'interval'")
        return v

    @field_validator("action_config")
    @classmethod
    def validate_action_config(cls, v: dict) -> dict:
        if "prompt" not in v or not v["prompt"]:
            raise ValueError("action_config must contain a non-empty 'prompt' key")
        return v


class UpdateRoutineRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    trigger_type: str | None = None
    trigger_config: dict | None = None
    action_config: dict | None = None
    enabled: bool | None = None
    cooldown_s: int | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            return _normalize_text(v, min_length=1, max_length=200, field_name="Name")
        return v

    @field_validator("trigger_type")
    @classmethod
    def validate_trigger_type(cls, v: str | None) -> str | None:
        if v is not None and v not in ("cron", "event", "interval"):
            raise ValueError("trigger_type must be 'cron', 'event', or 'interval'")
        return v

    @field_validator("action_config")
    @classmethod
    def validate_action_config(cls, v: dict | None) -> dict | None:
        if v is not None:
            if "prompt" not in v or not v["prompt"]:
                raise ValueError("action_config must contain a non-empty 'prompt' key")
        return v


def _routine_to_dict(r) -> dict:
    return {
        "routine_id": r.routine_id,
        "user_id": r.user_id,
        "name": r.name,
        "description": r.description,
        "trigger_type": r.trigger_type,
        "trigger_config": r.trigger_config,
        "action_config": r.action_config,
        "enabled": r.enabled,
        "last_run_at": r.last_run_at,
        "next_run_at": r.next_run_at,
        "cooldown_s": r.cooldown_s,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }


@api_router.post("/routine")
@limiter.limit("10/minute")
async def create_routine(req: CreateRoutineRequest, request: Request):
    """Create a new routine."""
    if _routine_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # Validate trigger_config matches trigger_type
    try:
        validate_trigger_config(req.trigger_type, req.trigger_config)
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reason": str(exc)},
        )

    # Calculate initial next_run_at for cron/interval triggers
    next_run_at = None
    if req.trigger_type == "cron" and req.enabled:
        from sentinel.routines.cron import next_run
        try:
            dt = next_run(req.trigger_config["cron"])
            next_run_at = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except ValueError:
            pass
    elif req.trigger_type == "interval" and req.enabled:
        from datetime import datetime, timedelta, timezone
        seconds = req.trigger_config.get("seconds", 0)
        if seconds > 0:
            dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
            next_run_at = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    try:
        routine = _routine_store.create(
            name=req.name,
            trigger_type=req.trigger_type,
            trigger_config=req.trigger_config,
            action_config=req.action_config,
            description=req.description,
            enabled=req.enabled,
            cooldown_s=req.cooldown_s,
            next_run_at=next_run_at,
            max_per_user=settings.routine_max_per_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    return {"status": "ok", "routine": _routine_to_dict(routine)}


@api_router.get("/routine")
async def list_routines(
    enabled_only: bool = Query(False, description="Only return enabled routines"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List all routines for the current user."""
    if _routine_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    routines = _routine_store.list(enabled_only=enabled_only, limit=limit, offset=offset)
    return {
        "status": "ok",
        "routines": [_routine_to_dict(r) for r in routines],
        "count": len(routines),
    }


@api_router.get("/routine/{routine_id}")
async def get_routine(routine_id: str):
    """Get a single routine by ID."""
    if _routine_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    routine = _routine_store.get(routine_id)
    if routine is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "routine": _routine_to_dict(routine)}


@api_router.patch("/routine/{routine_id}")
async def update_routine(routine_id: str, req: UpdateRoutineRequest):
    """Update a routine."""
    if _routine_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # Build kwargs from non-None fields
    updates = {}
    if req.name is not None:
        updates["name"] = req.name
    if req.description is not None:
        updates["description"] = req.description
    if req.trigger_type is not None:
        updates["trigger_type"] = req.trigger_type
    if req.trigger_config is not None:
        updates["trigger_config"] = req.trigger_config
    if req.action_config is not None:
        updates["action_config"] = req.action_config
    if req.enabled is not None:
        updates["enabled"] = req.enabled
    if req.cooldown_s is not None:
        updates["cooldown_s"] = req.cooldown_s

    # Validate trigger_config if both type and config are being updated
    trigger_type = req.trigger_type
    trigger_config = req.trigger_config
    if trigger_type or trigger_config:
        # Need both to validate — fetch existing if one is missing
        existing = _routine_store.get(routine_id)
        if existing is None:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "reason": "Routine not found"},
            )
        effective_type = trigger_type or existing.trigger_type
        effective_config = trigger_config or existing.trigger_config
        try:
            validate_trigger_config(effective_type, effective_config)
        except ValueError as exc:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "reason": str(exc)},
            )

    if not updates:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reason": "No fields to update"},
        )

    routine = _routine_store.update(routine_id, **updates)
    if routine is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "routine": _routine_to_dict(routine)}


@api_router.delete("/routine/{routine_id}")
async def delete_routine(routine_id: str):
    """Delete a routine."""
    if _routine_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    deleted = _routine_store.delete(routine_id)
    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "deleted": routine_id}


@api_router.post("/routine/{routine_id}/run")
@limiter.limit("5/minute")
async def trigger_routine(routine_id: str, request: Request):
    """Manually trigger a routine execution."""
    if _routine_engine is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine engine not running"},
        )

    execution_id = await _routine_engine.trigger_manual(routine_id)
    if execution_id is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "execution_id": execution_id}


@api_router.get("/routine/{routine_id}/executions")
async def get_routine_executions(
    routine_id: str,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Get execution history for a routine."""
    if _routine_engine is None and _routine_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # Verify routine exists
    if _routine_store is not None:
        routine = _routine_store.get(routine_id)
        if routine is None:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "reason": "Routine not found"},
            )

    executions = []
    if _routine_engine is not None:
        executions = _routine_engine.get_execution_history(
            routine_id, limit=limit, offset=offset,
        )

    return {
        "status": "ok",
        "executions": executions,
        "count": len(executions),
    }


# ── Webhook endpoints (C1) ──────────────────────────────────────


class RegisterWebhookRequest(BaseModel):
    name: str
    secret: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, max_length=200, field_name="Name")

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 16:
            raise ValueError("Secret must be at least 16 characters")
        return v


def _webhook_to_dict(config) -> dict:
    return {
        "webhook_id": config.webhook_id,
        "name": config.name,
        "enabled": config.enabled,
        "user_id": config.user_id,
        "created_at": config.created_at,
    }


@api_router.post("/webhook")
@limiter.limit("10/minute")
async def register_webhook(req: RegisterWebhookRequest, request: Request):
    """Register a new webhook endpoint."""
    if _webhook_registry is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    config = _webhook_registry.register(name=req.name, secret=req.secret)
    return {
        "status": "ok",
        "webhook": _webhook_to_dict(config),
        "receive_url": f"/api/webhook/{config.webhook_id}/receive",
    }


@api_router.get("/webhook")
async def list_webhooks():
    """List all registered webhooks (secrets excluded)."""
    if _webhook_registry is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    webhooks = _webhook_registry.list()
    return {
        "status": "ok",
        "webhooks": [_webhook_to_dict(w) for w in webhooks],
        "count": len(webhooks),
    }


@api_router.delete("/webhook/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """Delete a registered webhook."""
    if _webhook_registry is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    deleted = _webhook_registry.delete(webhook_id)
    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Webhook not found"},
        )

    return {"status": "ok", "deleted": webhook_id}


@api_router.post("/webhook/{webhook_id}/receive")
async def receive_webhook(webhook_id: str, request: Request):
    """Receive an inbound webhook payload from an external service.

    Security checks (in order):
    1. Webhook exists and is enabled
    2. HMAC-SHA256 signature verification (X-Signature-256 header)
    3. Timestamp freshness (X-Timestamp header, 5-minute window)
    4. Idempotency dedup (X-Idempotency-Key header)
    5. Per-webhook rate limiting
    """
    if _webhook_registry is None or _event_bus is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    # 1. Look up webhook
    config = _webhook_registry.get(webhook_id)
    if config is None or not config.enabled:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Webhook not found"},
        )

    # Read raw body for signature verification
    body = await request.body()

    # 2. Verify HMAC signature
    signature = request.headers.get("X-Signature-256", "")
    if not signature or not verify_signature(body, signature, config.secret):
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reason": "Invalid signature"},
        )

    # 3. Verify timestamp freshness
    timestamp = request.headers.get("X-Timestamp", "")
    if not timestamp or not verify_timestamp(timestamp, config.timestamp_tolerance):
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reason": "Timestamp expired or invalid"},
        )

    # 4. Idempotency check
    idempotency_key = request.headers.get("X-Idempotency-Key", "")
    if idempotency_key:
        if check_idempotency(idempotency_key, _idempotency_cache):
            return JSONResponse(
                status_code=409,
                content={"status": "error", "reason": "Duplicate request"},
            )

    # 5. Rate limiting
    if _webhook_rate_limiter is not None and not _webhook_rate_limiter.check(webhook_id):
        return JSONResponse(
            status_code=429,
            content={"status": "error", "reason": "Rate limit exceeded"},
        )

    # Parse payload
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        payload = {"raw": body.decode("utf-8", errors="replace")}

    # Publish event to bus — routine engine listens for webhook.* events
    await _event_bus.publish(f"webhook.{webhook_id}.received", {
        "webhook_id": webhook_id,
        "webhook_name": config.name,
        "payload": payload,
    })

    # If payload contains a "prompt" field, route through orchestrator as a task
    task_triggered = False
    if isinstance(payload, dict) and payload.get("prompt") and _orchestrator is not None:
        router = ChannelRouter(_orchestrator, _event_bus, _audit)
        message = IncomingMessage(
            channel_id=f"webhook:{webhook_id}",
            source="webhook",
            content=payload["prompt"],
            metadata={
                "source_key": f"webhook:{webhook_id}",
                "approval_mode": settings.approval_mode,
                "type": "task",
            },
        )
        # Create a minimal channel for the router (webhook is fire-and-forget)
        from sentinel.channels.web import WebSocketChannel
        dummy_channel = type("WebhookSend", (), {
            "channel_type": "webhook",
            "send": lambda self, msg: None,
        })()
        try:
            await router.handle_message(dummy_channel, message)
            task_triggered = True
        except Exception:
            pass

    return {"status": "ok", "event_published": True, "task_triggered": task_triggered}


# ── Heartbeat endpoint (C2) ─────────────────────────────────────


@api_router.get("/heartbeat")
async def get_heartbeat():
    """Get heartbeat status summary including component health."""
    if _heartbeat_manager is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Heartbeat system not initialized"},
        )

    return {"status": "ok", "heartbeat": _heartbeat_manager.get_status_summary()}


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


# ── Log stream SSE endpoint ───────────────────────────────────────


class LogSSEWriter:
    """Streams log entries as SSE events by attaching a handler to the audit logger.

    Attaches a logging.Handler to ``sentinel.audit``, queues records, and yields
    them as structured SSE events. Handler is removed in the ``finally`` block
    when the client disconnects.
    """

    def __init__(self, min_level: int = logging.INFO):
        self._queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=1000)
        self._min_level = min_level
        self._handler: logging.Handler | None = None
        self._logger = logging.getLogger("sentinel.audit")

    def attach(self) -> None:
        """Attach the queue handler to the audit logger."""
        writer = self

        class _QueueHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                entry = {
                    "timestamp": record.created,
                    "level": record.levelname,
                    "message": record.getMessage(),
                    "event": getattr(record, "event", ""),
                }
                try:
                    writer._queue.put_nowait(entry)
                except asyncio.QueueFull:
                    pass  # Drop oldest if consumer is too slow

        self._handler = _QueueHandler()
        self._handler.setLevel(self._min_level)
        self._logger.addHandler(self._handler)

    def detach(self) -> None:
        """Remove the handler from the audit logger."""
        if self._handler is not None:
            self._logger.removeHandler(self._handler)
            self._handler = None

    async def event_generator(self):
        """Yield SSE events from the queue with keepalive."""
        try:
            while True:
                try:
                    entry = await asyncio.wait_for(self._queue.get(), timeout=30.0)
                    yield {
                        "event": "log",
                        "data": json.dumps(entry),
                    }
                except asyncio.TimeoutError:
                    yield {"comment": "keepalive"}
        finally:
            self.detach()


@api_router.get("/logs/stream")
async def log_stream(
    request: Request,
    level: str = Query("INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$"),
):
    """SSE stream of audit log entries. PIN auth enforced by middleware."""
    min_level = getattr(logging, level.upper(), logging.INFO)
    writer = LogSSEWriter(min_level=min_level)
    writer.attach()
    return EventSourceResponse(writer.event_generator())


# Include API router before static file mount — API routes take priority
app.include_router(api_router)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint with PIN auth and real-time task execution."""
    await websocket.accept()

    channel = WebSocketChannel(
        websocket=websocket,
        pin_verifier_getter=lambda: _pin_verifier,
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

    # Subscribe to routine events and forward to this WS client
    async def _forward_routine_event(topic: str, data: dict) -> None:
        try:
            await websocket.send_json({
                "type": "routine_event",
                "event": topic,
                "data": data,
            })
        except Exception:
            pass  # Client disconnected — cleanup handled below

    _event_bus.subscribe("routine.*", _forward_routine_event)

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
    finally:
        # Unsubscribe routine event forwarder on disconnect
        try:
            _event_bus.unsubscribe("routine.*", _forward_routine_event)
        except Exception:
            pass

# Static file mount moved to lifespan() — must be registered LAST so that
# routes added during lifespan (B2 red-team, MCP) aren't shadowed by the
# catch-all "/" mount.  See comment above the yield in lifespan().
