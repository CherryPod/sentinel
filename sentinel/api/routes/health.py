"""Health and metrics route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  GET /health       — container probe (root-level, no /api/ prefix)
  GET /api/health   — client-facing health check
  GET /api/metrics  — dashboard metrics aggregated over a time window
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request

from sentinel.core.config import settings

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────
# No prefix — health routes serve at /health (root) and /api/health,
# /api/metrics (via separate sub-router included on /api).

root_router = APIRouter()
api_router = APIRouter()


# ── HealthState dataclass ───────────────────────────────────────────
# Bundles the component references that _gather_component_status() needs,
# replacing the 10+ separate module globals it used to read from app.py.

@dataclass
class HealthState:
    """Snapshot of component availability for health endpoints."""

    prompt_guard_loaded: bool = False
    semgrep_loaded: bool = False
    ollama_reachable: bool = False
    planner_available: bool = False
    sidecar: Any = None
    sandbox: Any = None
    signal_channel: Any = None
    telegram_channel: Any = None
    engine: Any = None
    pin_verifier: Any = None


# ── Module globals (init pattern) ──────────────────────────────────

_health_state: HealthState | None = None

# Metrics endpoint needs different dependencies than health
_session_store: Any = None
_orchestrator: Any = None
_routine_engine: Any = None
_get_metrics_fn: Any = None


def init(
    *,
    health_state: HealthState,
    session_store: Any = None,
    orchestrator: Any = None,
    routine_engine: Any = None,
    get_metrics_fn: Any = None,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _health_state, _session_store, _orchestrator, _routine_engine, _get_metrics_fn
    _health_state = health_state
    _session_store = session_store
    _orchestrator = orchestrator
    _routine_engine = routine_engine
    _get_metrics_fn = get_metrics_fn


# ── Accessors ──────────────────────────────────────────────────────

def _get_health_state() -> HealthState:
    if _health_state is None:
        raise HTTPException(status_code=503, detail="Health state not initialized")
    return _health_state


def _get_session_store():
    if _session_store is None:
        raise HTTPException(status_code=503, detail="Database not available")
    return _session_store


def _get_orchestrator():
    if _orchestrator is None:
        raise HTTPException(status_code=503, detail="Database not available")
    return _orchestrator


def _get_metrics_callable():
    if _get_metrics_fn is None:
        raise HTTPException(status_code=503, detail="Metrics not available")
    return _get_metrics_fn


# ── Helpers ────────────────────────────────────────────────────────

def gather_component_status(state: HealthState | None = None) -> dict:
    """Build component status dict shared by /health, /api/health, and heartbeat.

    Accepts an explicit HealthState, or falls back to the module-level one.
    Public because the heartbeat system calls this too.
    """
    hs = state if state is not None else _health_state
    if hs is None:
        # Pre-init: return safe defaults (all disabled/False)
        return {
            "planner_available": False,
            "semgrep_loaded": False,
            "prompt_guard_loaded": False,
            "ollama_reachable": False,
            "sidecar": "disabled",
            "signal": "disabled",
            "telegram": "disabled",
            "sandbox": "disabled",
        }

    sidecar_status = "disabled"
    if hs.sidecar is not None:
        sidecar_status = "running" if hs.sidecar.is_running else "stopped"

    signal_status = "disabled"
    if hs.signal_channel is not None:
        signal_status = "running" if hs.signal_channel._running else "stopped"

    sandbox_status = "disabled"
    if hs.sandbox is not None:
        sandbox_status = "enabled"

    telegram_status = "disabled"
    if hs.telegram_channel is not None:
        telegram_status = "running" if hs.telegram_channel._running else "stopped"

    return {
        "planner_available": hs.planner_available,
        "semgrep_loaded": hs.semgrep_loaded,
        "prompt_guard_loaded": hs.prompt_guard_loaded,
        "ollama_reachable": hs.ollama_reachable,
        "sidecar": sidecar_status,
        "signal": signal_status,
        "telegram": telegram_status,
        "sandbox": sandbox_status,
    }


async def check_pg_ready(app_instance: FastAPI) -> bool | None:
    """Check PostgreSQL pool health. Returns True/False, or None if not using PostgreSQL."""
    pool = getattr(app_instance.state, "pg_pool", None)
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return True
    except Exception:
        return False


# ── Root health endpoint (container probes, always outside /api/) ──

@root_router.get("/health")
async def health(request: Request):
    hs = _health_state
    status = gather_component_status(hs)
    # BOOT-1: Flag degraded when both security scanners are offline
    pg_loaded = hs.prompt_guard_loaded if hs else False
    sg_loaded = hs.semgrep_loaded if hs else False
    degraded = not pg_loaded and not sg_loaded
    result = {
        "status": "ok",
        "degraded": degraded,
        "policy_loaded": (hs.engine is not None) if hs else False,
        "conversation_tracking": settings.conversation_enabled,
        "baseline_mode": settings.baseline_mode,
        "pin_auth_enabled": (hs.pin_verifier is not None) if hs else False,
        "approval_mode": settings.approval_mode,
        "benchmark_mode": settings.benchmark_mode,
        **status,
    }
    pg_ready = await check_pg_ready(request.app)
    if pg_ready is not None:
        result["pg_ready"] = pg_ready
    return result


# ── Client-facing health check at /api/health ─────────────────────

@api_router.get("/health")
async def api_health(request: Request):
    """Client-facing health check at /api/health."""
    hs = _health_state
    status = gather_component_status(hs)

    # Email status — config-level (no persistent runtime service)
    if settings.email_backend == "imap" and settings.imap_host:
        email_status = "enabled (IMAP)"
    elif settings.gmail_enabled:
        email_status = "enabled (Gmail)"
    else:
        email_status = "disabled"

    # Calendar status — config-level
    if settings.calendar_backend == "caldav" and settings.caldav_url:
        calendar_status = "enabled (CalDAV)"
    elif settings.calendar_enabled:
        calendar_status = "enabled (Google)"
    else:
        calendar_status = "disabled"

    # BOOT-1: Flag degraded when both security scanners are offline
    pg_loaded = hs.prompt_guard_loaded if hs else False
    sg_loaded = hs.semgrep_loaded if hs else False
    degraded = not pg_loaded and not sg_loaded
    result = {
        "status": "ok",
        "degraded": degraded,
        "policy_loaded": (hs.engine is not None) if hs else False,
        "conversation_tracking": settings.conversation_enabled,
        "pin_auth_enabled": (hs.pin_verifier is not None) if hs else False,
        "approval_mode": settings.approval_mode,
        "benchmark_mode": settings.benchmark_mode,
        **status,
        "email": email_status,
        "calendar": calendar_status,
    }
    pg_ready = await check_pg_ready(request.app)
    if pg_ready is not None:
        result["pg_ready"] = pg_ready
    return result


# ── Dashboard metrics ──────────────────────────────────────────────

@api_router.get("/metrics")
async def dashboard_metrics(
    window: str = Query("24h", pattern=r"^(24h|7d|30d|all)$"),
):
    """Dashboard metrics aggregated over a time window."""
    if _session_store is None or _orchestrator is None:
        raise HTTPException(status_code=503, detail="Database not available")
    data = await _get_metrics_fn(
        session_store=_session_store,
        approval_manager=_orchestrator.approval_manager,
        routine_engine=_routine_engine,
        window=window,
    )
    return {
        "status": "ok",
        "window": window,
        "trust_level": settings.trust_level,
        "data": data,
    }
