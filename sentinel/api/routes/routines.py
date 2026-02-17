"""Routine management route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  GET    /api/routine                        — list all routines
  POST   /api/routine                        — create a new routine
  GET    /api/routine/{routine_id}            — get a routine by ID
  PATCH  /api/routine/{routine_id}            — update a routine
  DELETE /api/routine/{routine_id}            — delete a routine
  POST   /api/routine/{routine_id}/run        — manually trigger a routine
  GET    /api/routine/{routine_id}/executions — execution history
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import CreateRoutineRequest, UpdateRoutineRequest
from sentinel.api.rate_limit import limiter
from sentinel.core.config import settings
from sentinel.routines.cron import validate_trigger_config

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_routine_store: Any = None
_routine_engine: Any = None


def init(
    *,
    routine_store: Any = None,
    routine_engine: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _routine_store, _routine_engine
    _routine_store = routine_store
    _routine_engine = routine_engine


# ── Accessors ──────────────────────────────────────────────────────

def _get_routine_store():
    """Return routine store or fall back to app module global."""
    if _routine_store is not None:
        return _routine_store
    import sentinel.api.app as _app
    return getattr(_app, "_routine_store", None)


def _get_routine_engine():
    """Return routine engine or fall back to app module global."""
    if _routine_engine is not None:
        return _routine_engine
    import sentinel.api.app as _app
    return getattr(_app, "_routine_engine", None)


# ── Serialisation helper ───────────────────────────────────────────


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


# ── Routine endpoints ─────────────────────────────────────────────


@router.post("/routine")
@limiter.limit(lambda: settings.rate_limit_tasks)
async def create_routine(req: CreateRoutineRequest, request: Request):
    """Create a new routine."""
    store = _get_routine_store()
    if store is None:
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
        routine = await store.create(
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


@router.get("/routine")
async def list_routines(
    enabled_only: bool = Query(False, description="Only return enabled routines"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List all routines for the current user."""
    store = _get_routine_store()
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    routines = await store.list(enabled_only=enabled_only, limit=limit, offset=offset)
    return {
        "status": "ok",
        "routines": [_routine_to_dict(r) for r in routines],
        "count": len(routines),
    }


@router.get("/routine/{routine_id}")
async def get_routine(routine_id: str):
    """Get a single routine by ID."""
    store = _get_routine_store()
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    routine = await store.get(routine_id)
    if routine is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "routine": _routine_to_dict(routine)}


@router.patch("/routine/{routine_id}")
async def update_routine(routine_id: str, req: UpdateRoutineRequest):
    """Update a routine."""
    store = _get_routine_store()
    if store is None:
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
        existing = await store.get(routine_id)
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

    routine = await store.update(routine_id, **updates)
    if routine is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "routine": _routine_to_dict(routine)}


@router.delete("/routine/{routine_id}")
async def delete_routine(routine_id: str):
    """Delete a routine."""
    store = _get_routine_store()
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    deleted = await store.delete(routine_id)
    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "deleted": routine_id}


@router.post("/routine/{routine_id}/run")
@limiter.limit(lambda: settings.rate_limit_routines)
async def trigger_routine(routine_id: str, request: Request):
    """Manually trigger a routine execution."""
    engine = _get_routine_engine()
    if engine is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine engine not running"},
        )

    execution_id = await engine.trigger_manual(routine_id)
    if execution_id is None:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    return {"status": "ok", "execution_id": execution_id}


@router.get("/routine/{routine_id}/executions")
async def get_routine_executions(
    routine_id: str,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Get execution history for a routine."""
    engine = _get_routine_engine()
    store = _get_routine_store()
    if engine is None and store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # Verify routine exists
    if store is not None:
        routine = await store.get(routine_id)
        if routine is None:
            return JSONResponse(
                status_code=404,
                content={"status": "error", "reason": "Routine not found"},
            )

    executions = []
    if engine is not None:
        executions = await engine.get_execution_history(
            routine_id, limit=limit, offset=offset,
        )

    return {
        "status": "ok",
        "executions": executions,
        "count": len(executions),
    }
