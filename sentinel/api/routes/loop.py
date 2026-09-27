"""Loop management and insight API route handlers.

Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  POST   /api/loop              — start a new goal-pursuit loop
  GET    /api/loop               — list loops for current user
  GET    /api/loop/{loop_id}     — get loop status and iteration history
  DELETE /api/loop/{loop_id}     — cancel a running loop
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import LoopRequest
from sentinel.api.rate_limit import limiter
from sentinel.core.config import settings
from sentinel.core.context import current_user_id, spawn_task
from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import create_tagged_data

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────

MAX_LOOP_TIMEOUT_SECONDS = 7200  # 2 hours — hard cap on user-requested timeouts

# ── Router ──────────────────────────────────────────────────────

router = APIRouter()

# ── Module globals (init pattern) ───────────────────────────────

_orchestrator: Any = None
_loop_store: Any = None
_loop_controller: Any = None
_event_bus: Any = None
_audit: Any = None
_insight_store: Any = None
_insight_extractor: Any = None


def init(
    *,
    orchestrator: Any = None,
    loop_store: Any = None,
    loop_controller: Any = None,
    event_bus: Any = None,
    audit: Any = None,
    insight_store: Any = None,
    insight_extractor: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from lifecycle.py lifespan."""
    logger.debug("init called", extra={"event": "loop.init"})
    global _orchestrator, _loop_store, _loop_controller, _event_bus, _audit
    global _insight_store, _insight_extractor
    _orchestrator = orchestrator
    _loop_store = loop_store
    _loop_controller = loop_controller
    _event_bus = event_bus
    _audit = audit
    _insight_store = insight_store
    _insight_extractor = insight_extractor


# ── Endpoints ───────────────────────────────────────────────────


@router.post("/loop", status_code=202)
@limiter.limit(lambda: settings.rate_limit_tasks)
async def start_loop(req: LoopRequest, request: Request):
    """Start a new goal-pursuit loop. Returns immediately; loop runs async."""
    if _loop_controller is None or _loop_store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Loop controller not initialized"},
        )

    user_id = current_user_id.get()
    if user_id == 0:
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )

    # Concurrency guard: one active loop per user
    if await _loop_store.has_active_loop(user_id):
        return JSONResponse(
            status_code=409,
            content={
                "status": "error",
                "reason": "A loop is already running for this user",
            },
        )

    loop_id = str(uuid.uuid4())
    max_iter = min(req.max_iterations, settings.loop_max_per_request)
    timeout = min(req.timeout_seconds, MAX_LOOP_TIMEOUT_SECONDS)

    # Q3-F8: bind a unique source_key for the loop so full-approval iterations
    # can key approvals against a real (principal, session) pair. Shape mirrors
    # /api/task: {source}:{client_ip}:{user_id}, with loop_id appended so
    # concurrent loops from the same user at the same IP don't collide.
    client_ip = request.client.host if request.client else "unknown"
    loop_source_key = f"loop:{client_ip}:{user_id}:{loop_id}"

    # Q8.fix.b — wrap the incoming request as UNTRUSTED at the /api/loop
    # ingress boundary. `/api/loop` has no `execute_fn` closure (unlike
    # `/api/task`) so data_id threads through `run_loop` → `_execute_iteration`
    # else-branch → `orchestrator.handle_task` directly. The same data_id is
    # reused across every iteration — gap-retry enrichment is an internal
    # transform per fix-design §Internal transformations.
    tagged_request = await create_tagged_data(
        content=req.request,
        source=DataSource.USER,
        trust_level=TrustLevel.UNTRUSTED,
        originated_from=f"ingress:loop:{loop_source_key}",
    )
    user_request_data_id = tagged_request.id
    logger.info(
        "Loop ingress tagged UNTRUSTED",
        extra={
            "event": "loop.ingress_tagged",
            "loop_id": loop_id,
            "user_id": user_id,
            "data_id": user_request_data_id,
            "request_len": len(req.request),
        },
    )

    # Spawn loop as user-scoped background task
    spawn_task(
        _loop_controller.run_loop(
            loop_id=loop_id,
            user_id=user_id,
            request=req.request,
            max_iterations=max_iter,
            timeout_seconds=timeout,
            source_key=loop_source_key,
            user_request_data_id=user_request_data_id,
        ),
        name=f"loop-{loop_id[:8]}",
    )

    logger.info(
        "Loop started: %s for user %d (%d max, %ds timeout)",
        loop_id,
        user_id,
        max_iter,
        timeout,
        extra={"event": "loop.api_start", "loop_id": loop_id, "user_id": user_id},
    )

    return {
        "loop_id": loop_id,
        "status": "running",
        "message": f"Loop started, {max_iter} iterations max, {timeout}s timeout",
    }


@router.get("/loop")
async def list_loops(request: Request):
    """List recent loops for the current user."""
    logger.debug(
        "list_loops called",
        extra={
            "event": "api.routes.loop.list_loops",
            "request_type": type(request).__name__,
        },
    )  # auto:entry
    if _loop_store is None:
        return JSONResponse(
            status_code=503, content={"status": "error", "reason": "Not initialized"}
        )

    user_id = current_user_id.get()
    if user_id == 0:
        logger.warning(
            "list_loops: zero-principal blocked at Rule 1",
            extra={"event": "loop.list_loops.rule1.blocked"},
        )
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )
    logger.debug(
        "list_loops: user_id_eq_0_passed",
        extra={
            "event": "api.routes.loop.list_loops.rule1.blocked.passed",
            "reason": "user_id_eq_0_passed",
        },
    )  # auto:neg
    loops = await _loop_store.list_by_user(user_id)

    return {
        "loops": [
            {
                "loop_id": ls.loop_id,
                "status": ls.status,
                "original_request": ls.original_request[:200],
                "iteration_count": ls.iteration_count,
                "created_at": ls.created_at.isoformat() if ls.created_at else None,
            }
            for ls in loops
        ],
    }


@router.get("/loop/{loop_id}")
async def get_loop(loop_id: str, request: Request):
    """Get loop status and iteration history."""
    logger.debug(
        "get_loop called",
        extra={
            "event": "loop.get_loop",
            "loop_id": loop_id,
            "request_type": type(request).__name__,
        },
    )
    if _loop_store is None:
        logger.debug("get_loop: match", extra={"event": "loop.get_loop.match"})
        return JSONResponse(
            status_code=503, content={"status": "error", "reason": "Not initialized"}
        )

    user_id = current_user_id.get()
    if user_id == 0:
        logger.debug(
            "get_loop: user_id_eq_0",
            extra={"event": "api.routes.loop.get_loop.match", "reason": "user_id_eq_0"},
        )  # auto:neg
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )
    logger.debug(
        "get_loop: user_id_eq_0_passed",
        extra={
            "event": "api.routes.loop.get_loop.passed",
            "reason": "user_id_eq_0_passed",
        },
    )  # auto:neg
    state = await _loop_store.get(loop_id, user_id=user_id)

    if state is None:
        logger.debug("get_loop: match", extra={"event": "loop.get_loop.match"})
        return JSONResponse(
            status_code=404, content={"status": "error", "reason": "Loop not found"}
        )

    elapsed = None
    if state.created_at and state.status == "running":
        logger.debug("get_loop: match", extra={"event": "loop.get_loop.match"})
        from datetime import datetime

        elapsed = (datetime.now(UTC) - state.created_at).total_seconds()
    elif state.created_at and state.finished_at:
        logger.debug("get_loop: clean", extra={"event": "loop.get_loop.clean"})
        elapsed = (state.finished_at - state.created_at).total_seconds()

    return {
        "loop_id": state.loop_id,
        "status": state.status,
        "original_request": state.original_request,
        "iteration_count": state.iteration_count,
        "max_iterations": state.max_iterations,
        "cancelled_at_iteration": state.cancelled_at_iteration,
        "elapsed_seconds": round(elapsed, 1) if elapsed else None,
        "iterations": state.iterations,
        "created_at": state.created_at.isoformat() if state.created_at else None,
        "finished_at": state.finished_at.isoformat() if state.finished_at else None,
    }


@router.delete("/loop/{loop_id}")
async def cancel_loop(loop_id: str, request: Request):
    """Cancel a running loop. Current iteration completes before stopping."""
    if _loop_store is None:
        return JSONResponse(
            status_code=503, content={"status": "error", "reason": "Not initialized"}
        )

    user_id = current_user_id.get()
    if user_id == 0:
        logger.warning(
            "cancel_loop: zero-principal blocked at Rule 1",
            extra={"event": "loop.cancel_loop.rule1.blocked"},
        )
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )
    state = await _loop_store.get(loop_id, user_id=user_id)

    if state is None:
        return JSONResponse(
            status_code=404, content={"status": "error", "reason": "Loop not found"}
        )

    if state.status != "running":
        return JSONResponse(
            status_code=409,
            content={"status": "error", "reason": f"Loop already {state.status}"},
        )

    # Set cancelled — the loop controller checks this before each iteration
    await _loop_store.set_status(
        loop_id=loop_id,
        user_id=user_id,
        status="cancelled",
        cancelled_at_iteration=state.iteration_count,
    )

    logger.info(
        "Loop cancelled: %s at iteration %d",
        loop_id,
        state.iteration_count,
        extra={"event": "loop.api_cancel", "loop_id": loop_id},
    )

    return {
        "loop_id": loop_id,
        "status": "cancelled",
        "message": "Loop will stop after current iteration completes",
    }


# ── Insight endpoints ───────────────────────────────────────────


@router.post("/insights/extract")
async def extract_insights(request: Request):
    """Manually trigger insight extraction from plan-outcome pairs."""
    if _insight_extractor is None:
        return JSONResponse(
            status_code=503, content={"status": "error", "reason": "Not initialized"}
        )

    user_id = current_user_id.get()
    if user_id == 0:
        logger.warning(
            "extract_insights: zero-principal blocked at Rule 1",
            extra={"event": "loop.extract_insights.rule1.blocked"},
        )
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )

    # Parse optional body
    body = {}
    try:
        body = await request.json()
    except Exception:  # catch-all: optional JSON body parse
        logger.debug(
            "extract_insights: Exception suppressed",
            extra={"event": "loop.extract_insights.suppressed"},
            exc_info=True,
        )

    since = None
    if "since" in body:
        from datetime import datetime

        since = datetime.fromisoformat(body["since"])

    limit = body.get("limit", 50)

    insights = await _insight_extractor.extract(
        user_id=user_id, since=since, limit=limit
    )

    return {
        "extracted": len(insights),
        "insights": [
            {
                "insight_id": ins.insight_id,
                "category": ins.category,
                "insight": ins.insight,
                "evidence_count": ins.evidence_count,
                "confidence": ins.confidence,
                "domain": ins.domain,
            }
            for ins in insights
        ],
    }


@router.get("/insights")
async def list_insights(request: Request):
    """List current planning insights for the user."""
    logger.debug(
        "list_insights called",
        extra={"event": "loop.list_insights", "request_type": type(request).__name__},
    )
    if _insight_store is None:
        logger.debug(
            "list_insights: match", extra={"event": "loop.list_insights.match"}
        )
        return JSONResponse(
            status_code=503, content={"status": "error", "reason": "Not initialized"}
        )

    user_id = current_user_id.get()
    if user_id == 0:
        logger.warning(
            "list_insights: zero-principal blocked at Rule 1",
            extra={"event": "loop.list_insights.rule1.blocked"},
        )
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )
    domain = request.query_params.get("domain")
    min_confidence = float(request.query_params.get("min_confidence", 0))

    if domain:
        logger.debug(
            "list_insights: match", extra={"event": "loop.list_insights.match"}
        )
        insights = await _insight_store.get_top(
            user_id=user_id, domain=domain, limit=50
        )
    else:
        logger.debug(
            "list_insights: clean", extra={"event": "loop.list_insights.clean"}
        )
        insights = await _insight_store.list_all(user_id=user_id)

    filtered = [i for i in insights if i.confidence >= min_confidence]

    return {
        "insights": [
            {
                "insight_id": ins.insight_id,
                "category": ins.category,
                "insight": ins.insight,
                "evidence_count": ins.evidence_count,
                "confidence": ins.confidence,
                "domain": ins.domain,
            }
            for ins in filtered
        ],
    }
