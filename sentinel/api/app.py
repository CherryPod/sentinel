"""Sentinel Controller — FastAPI application entry point.

This module creates the FastAPI app, registers middleware, exception handlers,
and routers. All lifecycle logic (startup/shutdown) lives in lifecycle.py.

Module-level globals are re-exported from lifecycle.py for backward compatibility
with route-module fallbacks and safety-net test patches. The lifecycle functions
sync values back to this module via _sync_to_app_module().
"""

import logging

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import lifecycle — the lifespan context manager and all module-level globals
# live there. We import the module itself (not from ... import) so that the
# middleware lambda can read lifecycle._pin_verifier at call time (getting the
# value set by _init_security, not a stale copy).
import sentinel.api.lifecycle as lifecycle
from sentinel.api.auth_routes import router as auth_router
from sentinel.api.contacts import router as contacts_router
from sentinel.api.credentials import router as credentials_router
from sentinel.api.lifecycle import lifespan
from sentinel.api.routes import (
    a2a as a2a_routes,
)
from sentinel.api.routes import (
    health as health_routes,
)
from sentinel.api.routes import (
    loop as loop_routes,
)
from sentinel.api.routes import (
    memory as memory_routes,
)
from sentinel.api.routes import (
    routines as routine_routes,
)
from sentinel.api.routes import (
    security as security_routes,
)
from sentinel.api.routes import (
    streaming as streaming_routes,
)
from sentinel.api.routes import (
    task as task_routes,
)
from sentinel.api.routes import (
    webhooks as webhook_routes,
)
from sentinel.api.routes import (
    websocket as websocket_routes,
)
from sentinel.core.config import settings

from .middleware import (
    CSRFMiddleware,
    RequestCorrelationMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    UserContextMiddleware,
)
from .rate_limit import limiter

logger = logging.getLogger(__name__)


# ── Backward-compat re-exports ────────────────────────────────────────
# Route modules read these via `import sentinel.api.app as _app; _app._shutting_down`.
# Safety-net tests patch them via `patch.object(app_module, "_pin_verifier", ...)`.
# lifecycle._sync_to_app_module() keeps them in sync at runtime; these initial
# values are the pre-startup defaults.
_pin_verifier = None
_engine = None
_pipeline = None
_prompt_guard_loaded = False
_semgrep_loaded = False
_planner_available = False
_ollama_reachable = False
_sidecar = None
_sandbox = None
_channel_registry = None
_shutting_down = False
_background_tasks = lifecycle._background_tasks

# Re-export lifecycle functions used by safety-net tests (CI-6)
_track_task = lifecycle._track_task


# ── FastAPI app ───────────────────────────────────────────────────────

app = FastAPI(title="Sentinel Controller", lifespan=lifespan)
app.state.limiter = limiter
# SlowAPIMiddleware enforces @limiter.limit() decorators — without this, all
# rate limit decorators are silently ignored (no-ops).
app.add_middleware(SlowAPIMiddleware)

# Middleware stack (outermost first): SecurityHeaders → RequestSizeLimit → CSRF → UserContext
# Starlette adds middleware as a stack: last added = outermost = runs first.
# UserContextMiddleware is JWT-only (no PIN fallback). It reads contact_store
# from request.app.state at dispatch time (wired by lifecycle.py during lifespan).
app.add_middleware(
    CSRFMiddleware,
    allowed_origins=[
        o.strip() for o in settings.allowed_origins.split(",") if o.strip()
    ],
)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(UserContextMiddleware)
app.add_middleware(RequestCorrelationMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Return JSON 429 when rate limit is exceeded."""
    audit = getattr(request.app.state, "audit", None)
    if audit:
        audit.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate.limit_exceeded",
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


# Registered before global_exception_handler: Starlette dispatches by MRO
# (most-derived type wins), so HTTPException always routes here, never to
# the bare-Exception handler below.
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Normalize HTTPException to the standard {status, reason} envelope."""
    reason = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "reason": reason},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensure all errors return JSON, never HTML error pages."""
    audit = getattr(request.app.state, "audit", None)
    if audit:
        audit.error(
            "Unhandled exception",
            exc_info=exc,
            extra={
                "event": "unhandled.exception",
                "path": str(request.url.path),
                "error_type": type(exc).__name__,
                "error_length": len(str(exc)),
            },
        )
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "reason": "Internal server error",
        },
    )


# ── PostgreSQL health probe (re-export for backward compat) ────────
# Moved to sentinel.api.routes.health — kept here for test_pg_infrastructure.py
_check_pg_ready = health_routes.check_pg_ready


# A2A protocol endpoints moved to sentinel.api.routes.a2a


# ── API router (all client-facing endpoints under /api/) ──────────
api_router = APIRouter(prefix="/api")


# Health and metrics endpoints moved to sentinel.api.routes.health
# Validation and scan endpoints moved to sentinel.api.routes.security
# Task, approval, and session endpoints moved to sentinel.api.routes.task
# Memory endpoints moved to sentinel.api.routes.memory
# Routine endpoints moved to sentinel.api.routes.routines
# Webhook endpoints moved to sentinel.api.routes.webhooks
# Heartbeat, SSE events, and log streaming moved to sentinel.api.routes.streaming


# Include API router before static file mount — API routes take priority
app.include_router(api_router)
app.include_router(auth_router)
app.include_router(contacts_router)
app.include_router(credentials_router)
# Health routes: root_router serves /health, api_router serves /api/health + /api/metrics
app.include_router(health_routes.root_router)
app.include_router(health_routes.api_router, prefix="/api")
# Security routes: validation + scanning at /api/validate/*, /api/scan, /api/process
app.include_router(security_routes.router, prefix="/api")
# Task routes: task submission, approval workflow, session debug at /api/task, /api/approve/*, etc.
app.include_router(task_routes.router, prefix="/api")
# Memory routes: store, search, list, get, delete at /api/memory/*
app.include_router(memory_routes.router, prefix="/api")
# Routine routes: CRUD, trigger, history at /api/routine/*
app.include_router(routine_routes.router, prefix="/api")
# Webhook routes: register, list, delete, receive at /api/webhook/*
app.include_router(webhook_routes.router, prefix="/api")
# Streaming routes: SSE events, log stream, heartbeat at /api/events, /api/logs/stream, /api/heartbeat
app.include_router(streaming_routes.router, prefix="/api")

# WebSocket route: PIN auth, channel routing, bidirectional messaging at /ws
app.include_router(websocket_routes.router)

# Loop routes: loop management + insight endpoints at /api/loop, /api/insights
app.include_router(loop_routes.router, prefix="/api")

# A2A routes: Agent Card at /.well-known/agent-card.json, JSON-RPC at /a2a (no prefix)
app.include_router(a2a_routes.router)

# Static file mount moved to lifespan() — must be registered LAST so that
# routes added during lifespan (such as MCP) aren't shadowed by the
# catch-all "/" mount.  See comment above the yield in lifespan().
