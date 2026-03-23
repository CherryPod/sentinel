"""Task execution and approval route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  POST /api/task                    — submit a new task (main CaMeL pipeline entry)
  GET  /api/approval/{approval_id}  — check approval status
  POST /api/approve/{approval_id}   — approve or deny a pending approval
  POST /api/confirm/{confirmation_id} — confirm or cancel a fast-path confirmation gate action
  GET  /api/session/{session_id}    — debug endpoint for session state

Compatibility note: the safety-net test CI-2 patches app_module._shutting_down
directly and expects POST /api/task → 503.  The _resolve_shutting_down() accessor
checks request.app.state first, then falls back to the app module global.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import ApprovalDecision, TaskRequest
from sentinel.api.rate_limit import limiter
from sentinel.core.config import settings

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_orchestrator: Any = None
_message_router: Any = None
_session_store: Any = None
_audit: Any = None


def init(
    *,
    orchestrator: Any = None,
    message_router: Any = None,
    session_store: Any = None,
    audit: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _orchestrator, _message_router, _session_store, _audit
    _orchestrator = orchestrator
    _message_router = message_router
    _session_store = session_store
    _audit = audit


# ── Accessors (with app-module fallback for safety-net compat) ────

def _resolve_orchestrator():
    """Return orchestrator from init() globals or app module fallback."""
    if _orchestrator is not None:
        return _orchestrator
    import sentinel.api.app as _app
    return getattr(_app, "_orchestrator", None)


def _resolve_message_router():
    """Return message router from init() globals or app module fallback."""
    if _message_router is not None:
        return _message_router
    import sentinel.api.app as _app
    return getattr(_app, "_message_router", None)


def _resolve_session_store():
    """Return session store from init() globals or app module fallback."""
    if _session_store is not None:
        return _session_store
    import sentinel.api.app as _app
    return getattr(_app, "_session_store", None)


def _resolve_shutting_down(request: Request) -> bool:
    """Check shutdown flag from app.state, then app module fallback."""
    # Prefer app.state (set by lifespan dual-write)
    state_val = getattr(request.app.state, "shutting_down", None)
    if state_val is not None:
        return state_val
    # Fallback: safety-net tests set app_module._shutting_down directly
    import sentinel.api.app as _app
    return _app._shutting_down


# ── Task endpoint ─────────────────────────────────────────────────


@router.post("/task")
@limiter.limit(lambda: settings.rate_limit_tasks)
async def handle_task(req: TaskRequest, request: Request):
    """Full CaMeL pipeline: user request → Claude plans → Qwen executes → scanned result."""
    if _resolve_shutting_down(request):
        return JSONResponse(status_code=503, content={"status": "error", "reason": "Server is shutting down"})

    orchestrator = _resolve_orchestrator()
    if orchestrator is None:
        return {"status": "error", "reason": "Orchestrator not initialized"}

    # Server-side session binding: derive session from client IP, not client-provided ID.
    # This prevents attackers from rotating session IDs to bypass conversation tracking.
    client_ip = request.client.host if request.client else "unknown"
    source_key = f"{req.source}:{client_ip}"

    try:
        message_router = _resolve_message_router()
        if message_router is not None:
            result = await asyncio.wait_for(
                message_router.route(
                    user_request=req.request,
                    source=req.source,
                    source_key=source_key,
                    approval_mode=settings.approval_mode,
                ),
                timeout=settings.api_task_timeout,
            )
        else:
            result = await asyncio.wait_for(
                orchestrator.handle_task(
                    user_request=req.request,
                    source=req.source,
                    approval_mode=settings.approval_mode,
                    source_key=source_key,
                ),
                timeout=settings.api_task_timeout,
            )
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=504,
            content={
                "status": "error",
                "reason": f"Task timed out after {settings.api_task_timeout}s",
            },
        )
    return result.model_dump()


# ── Approval endpoints ────────────────────────────────────────────


@router.get("/approval/{approval_id}")
async def check_approval(approval_id: str):
    """Check the status of an approval request."""
    orchestrator = _resolve_orchestrator()
    if orchestrator is None or orchestrator.approval_manager is None:
        return {"status": "error", "reason": "Approval manager not available"}

    return await orchestrator.check_approval(approval_id)


@router.post("/approve/{approval_id}")
async def submit_approval(approval_id: str, decision: ApprovalDecision):
    """Submit an approval decision, then execute the plan if approved."""
    orchestrator = _resolve_orchestrator()
    if orchestrator is None or orchestrator.approval_manager is None:
        return {"status": "error", "reason": "Approval manager not available"}

    accepted = await orchestrator.submit_approval(
        approval_id=approval_id,
        granted=decision.granted,
        reason=decision.reason,
    )
    if not accepted:
        return {"status": "error", "reason": "Invalid, expired, or duplicate approval"}

    if decision.granted:
        result = await orchestrator.execute_approved_plan(approval_id)
        return result.model_dump()

    return {"status": "denied", "reason": decision.reason}


@router.post("/confirm/{confirmation_id}")
async def submit_confirmation(confirmation_id: str, decision: ApprovalDecision):
    """Confirm or cancel a pending fast-path confirmation gate action.

    Same contract as /approve — returns the tool execution result on confirm,
    or a denied/error status dict.
    """
    from sentinel.core.context import current_user_id

    if _message_router is None:
        return {"status": "error", "reason": "Router not available"}

    gate = getattr(_message_router, "_confirmation_gate", None)
    fast_path = getattr(_message_router, "_fast_path", None)
    if gate is None or fast_path is None:
        return {"status": "error", "reason": "Confirmation gate not available"}

    ctx_token = current_user_id.set(1)
    try:
        if decision.granted:
            entry = await gate.confirm(confirmation_id)
            if entry is None:
                return {"status": "error", "reason": "Invalid, expired, or duplicate confirmation"}
            result = await fast_path.execute_confirmed(
                entry.tool_name, entry.tool_params, entry.task_id,
            )
            return result
        else:
            await gate.cancel(confirmation_id)
            return {"status": "denied", "reason": decision.reason or "Cancelled via WebUI"}
    finally:
        current_user_id.reset(ctx_token)


# ── Session debug endpoint ────────────────────────────────────────


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Debug endpoint: view session state and conversation history."""
    session_store = _resolve_session_store()
    if session_store is None:
        return {"error": "Session store not initialized"}

    session = await session_store.get(session_id)
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
