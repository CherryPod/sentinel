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
from datetime import UTC
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import CreateRoutineRequest, UpdateRoutineRequest
from sentinel.api.rate_limit import limiter
from sentinel.core.config import settings
from sentinel.core.context import PrincipalRequiredError, current_user_id
from sentinel.routines.cron import validate_trigger_config
from sentinel.routines.engine import compute_next_run_at

logger = logging.getLogger(__name__)

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_routine_store: Any = None
_routine_engine: Any = None
_scan_pipeline: Any = None
_audit_emitter: Any = None


def init(
    *,
    routine_store: Any = None,
    routine_engine: Any = None,
    scan_pipeline: Any = None,
    audit_emitter: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _routine_store, _routine_engine, _scan_pipeline, _audit_emitter
    _routine_store = routine_store
    _routine_engine = routine_engine
    _scan_pipeline = scan_pipeline
    _audit_emitter = audit_emitter


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
        logger.debug(
            "create_routine: match", extra={"event": "routines.create_routine.match"}
        )
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # Finding #3: Extract user_id from auth context, not hardcoded
    user_id = current_user_id.get()
    if user_id == 0:
        logger.debug(
            "create_routine: user_id_eq_0",
            extra={
                "event": "api.routes.routines.create_routine.match",
                "reason": "user_id_eq_0",
            },
        )  # auto:neg
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )

    # Validate trigger_config matches trigger_type
    try:
        validate_trigger_config(req.trigger_type, req.trigger_config)
    except ValueError as exc:
        logger.debug("routines.create_routine_validation_failed", exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reason": str(exc)},
        )

    # Finding #2: S1 scan on prompt before storage — reject injection payloads
    # before they can execute autonomously on schedule.
    if _scan_pipeline is not None:
        prompt = req.action_config.get("prompt", "")
        try:
            scan_result = await _scan_pipeline.scan_input(prompt)
            if not scan_result.is_clean:
                violation_details = []
                for (
                    scanner_name,
                    verdicts,
                ) in scan_result.unsuppressed_by_scanner().items():
                    patterns = [v.match.rule_id for v in verdicts]
                    violation_details.append(f"{scanner_name}: {', '.join(patterns)}")
                reason = "Prompt blocked by security scan — " + "; ".join(
                    violation_details
                )
                logger.warning(
                    "Routine creation blocked by S1 scan",
                    extra={
                        "event": "routine.create_blocked",
                        "violations": list(scan_result.violated_scanners()),
                    },
                )
                return JSONResponse(
                    status_code=400,
                    content={"status": "error", "reason": reason},
                )
        except Exception as exc:
            # Fail closed — if scanning fails, reject the routine
            logger.exception(
                "S1 scan failed during routine creation, rejecting (fail-closed)",
                extra={"event": "routine.create_scan_error", "error": str(exc)},
            )
            return JSONResponse(
                status_code=503,
                content={
                    "status": "error",
                    "reason": "Security scan unavailable — try again later",
                },
            )

    # Calculate initial next_run_at using shared compute helper (CRIT-10)
    next_run_at = compute_next_run_at(req.trigger_type, req.trigger_config, req.enabled)

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
            user_id=user_id,
        )
    except PrincipalRequiredError:
        # Q4.fix.f Coord review follow-up (Codex catch): the broad
        # `except ValueError` below would silently absorb this subclass
        # and misclassify a principal/auth failure as HTTP 429. Re-raise
        # so the fail-closed invariant signals a 500 instead.
        raise
    except ValueError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    return {"status": "ok", "routine": _routine_to_dict(routine)}


@router.get("/routine")
async def list_routines(
    enabled_only: Annotated[
        bool, Query(description="Only return enabled routines")
    ] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """List all routines for the current user."""
    logger.debug(
        "list_routines called",
        extra={
            "event": "routines.list_routines",
            "enabled_only": enabled_only,
            "limit": limit,
            "offset": offset,
        },
    )
    store = _get_routine_store()
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    user_id = current_user_id.get()
    routines = await store.list(
        user_id=user_id, enabled_only=enabled_only, limit=limit, offset=offset
    )
    return {
        "status": "ok",
        "routines": [_routine_to_dict(r) for r in routines],
        "count": len(routines),
    }


@router.get("/routine/{routine_id}")
async def get_routine(routine_id: str):
    """Get a single routine by ID."""
    logger.debug(
        "get_routine called",
        extra={"event": "routines.get_routine", "routine_id": routine_id},
    )
    store = _get_routine_store()
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # FL-C19-a1 (D30): Ownership check — split into two arms so each denial
    # reason is individually observable in the audit stream. RoutineStore.get
    # user-scopes queries, so cross-owner attempts arrive as None (production
    # arm); the explicit user_id check is defence-in-depth for store-bypass.
    user_id = current_user_id.get()
    routine = await store.get(routine_id)
    if routine is None:
        logger.debug(
            "get_routine: routine_is_None",
            extra={
                "event": "api.routes.routines.get_routine.match",
                "reason": "routine_is_None",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.get_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "not_found_or_ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "get_routine: audit emit failed (not_found path)",
                    extra={
                        "event": "routines.get_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    if routine.user_id != user_id:
        logger.debug(
            "get_routine: ownership_mismatch_explicit",
            extra={
                "event": "api.routes.routines.get_routine.match",
                "reason": "ownership_mismatch_explicit",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.get_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "get_routine: audit emit failed (ownership_mismatch path)",
                    extra={
                        "event": "routines.get_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    logger.debug(
        "get_routine: user_id_noteq_user_id_passed",
        extra={
            "event": "api.routes.routines.get_routine.passed",
            "reason": "user_id_noteq_user_id_passed",
        },
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

    # FL-C19-a1 (D30): Ownership check — split into two arms (see get_routine).
    # Variable name `existing` preserved from original code.
    user_id = current_user_id.get()
    existing = await store.get(routine_id)
    if existing is None:
        logger.debug(
            "update_routine: routine_is_None",
            extra={
                "event": "api.routes.routines.update_routine.match",
                "reason": "routine_is_None",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.update_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "not_found_or_ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "update_routine: audit emit failed (not_found path)",
                    extra={
                        "event": "routines.update_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    if existing.user_id != user_id:
        logger.debug(
            "update_routine: ownership_mismatch_explicit",
            extra={
                "event": "api.routes.routines.update_routine.match",
                "reason": "ownership_mismatch_explicit",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.update_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "update_routine: audit emit failed (ownership_mismatch path)",
                    extra={
                        "event": "routines.update_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    logger.debug(
        "update_routine: user_id_noteq_user_id_passed",
        extra={
            "event": "api.routes.routines.update_routine.passed",
            "reason": "user_id_noteq_user_id_passed",
        },
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

    # Validate trigger_config if type or config is being updated.
    # Use `is not None` (not truthiness) so an empty dict {} is still validated
    # and not silently accepted, which would corrupt the schedule via D5 recompute.
    trigger_type = req.trigger_type
    trigger_config = req.trigger_config
    if trigger_type is not None or trigger_config is not None:
        effective_type = trigger_type if trigger_type is not None else existing.trigger_type
        effective_config = trigger_config if trigger_config is not None else existing.trigger_config
        try:
            validate_trigger_config(effective_type, effective_config)
        except ValueError as exc:
            logger.debug("routines.update_routine_validation_failed", exc_info=True)
            return JSONResponse(
                status_code=400,
                content={"status": "error", "reason": str(exc)},
            )

    # Finding #2: S1 scan on prompt update
    if req.action_config is not None and _scan_pipeline is not None:
        prompt = req.action_config.get("prompt", "")
        if prompt:
            try:
                scan_result = await _scan_pipeline.scan_input(prompt)
                if not scan_result.is_clean:
                    violation_details = []
                    for (
                        scanner_name,
                        verdicts,
                    ) in scan_result.unsuppressed_by_scanner().items():
                        patterns = [v.match.rule_id for v in verdicts]
                        violation_details.append(
                            f"{scanner_name}: {', '.join(patterns)}"
                        )
                    reason = "Prompt blocked by security scan — " + "; ".join(
                        violation_details
                    )
                    return JSONResponse(
                        status_code=400,
                        content={"status": "error", "reason": reason},
                    )
            except Exception as exc:
                logger.exception(
                    "S1 scan failed for routine update: %s",
                    exc,
                    extra={"event": "routine.scan_error", "routine_id": routine_id},
                )
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "error",
                        "reason": "Security scan unavailable — try again later",
                    },
                )

    if not updates:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reason": "No fields to update"},
        )

    # Recompute next_run_at when any schedule-relevant field changes (CRIT-10 D5).
    # Merges request fields with existing values so partial PATCH updates work
    # correctly. Included in the single store.update() call to avoid partial-write risk.
    schedule_fields = {"trigger_type", "trigger_config", "enabled"}
    if schedule_fields & updates.keys():
        effective_type = updates.get("trigger_type", existing.trigger_type)
        effective_config = updates.get("trigger_config", existing.trigger_config)
        effective_enabled = updates.get("enabled", existing.enabled)
        updates["next_run_at"] = compute_next_run_at(
            effective_type, effective_config, effective_enabled
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
    """Delete a routine with cascade-cancel in-flight executions.

    Q5.fix.e D3: orchestrates the three-step split cascade per
    ``docs/hardening/2026-04-20-hardening-Q5-ttl-coupling-findings.md``
    §Design D3d:

      1. ``store.precancel_cascade`` — delete pending approvals +
         confirmations BEFORE cancelling tasks.
      2. ``engine.cancel_routine_executions`` — task.cancel() + bounded
         5s wait on any in-flight executions.
      3. ``store.delete`` — single-TX post-wait cascade over approvals +
         confirmations + sessions + routines (FK cascade on
         routine_executions fires automatically inside the same TX).

    Auto-cancel semantic (D3c): running executions are cancelled rather
    than rejected, matching OS force-quit + delete ergonomics. Response
    reports how many executions were cancelled so operators can see the
    impact.
    """
    logger.debug(
        "delete_routine called",
        extra={"event": "routines.delete_routine", "routine_id": routine_id},
    )
    store = _get_routine_store()
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # Finding #3: Ownership check before delete.
    # Q5-FL3 (cleanup-C19): emit `routine.delete_denied` audit event so
    # operators see attempted deletes blocked by ownership-mismatch in the
    # audit stream, not just the engine_unavailable DENIED path and the
    # SUCCESS path. The two arms emit different `reason` values because
    # `RoutineStore.get` is already user-scoped (sentinel/routines/store.py
    # :220-243): in production, cross-owner attempts arrive here as
    # `routine is None`, NOT as `routine.user_id != user_id`. The latter
    # arm is a defence-in-depth check that only fires if store-scoping is
    # bypassed (e.g. mock-injection in tests, future regression).
    user_id = current_user_id.get()
    routine = await store.get(routine_id)
    if routine is None:
        logger.debug(
            "delete_routine: routine_is_None",
            extra={
                "event": "api.routes.routines.delete_routine.match",
                "reason": "routine_is_None",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.delete_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "not_found_or_ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "delete_routine: audit emit failed (not_found path)",
                    extra={
                        "event": "routines.delete_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    if routine.user_id != user_id:
        logger.debug(
            "delete_routine: ownership_mismatch_explicit",
            extra={
                "event": "api.routes.routines.delete_routine.match",
                "reason": "ownership_mismatch_explicit",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.delete_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "delete_routine: audit emit failed (ownership_mismatch path)",
                    extra={
                        "event": "routines.delete_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    logger.debug(
        "delete_routine: user_id_noteq_user_id_passed",
        extra={
            "event": "api.routes.routines.delete_routine.passed",
            "reason": "user_id_noteq_user_id_passed",
        },
    )  # auto:neg

    # Q5.fix.e merge-gate Cx-2 (Codex thread `019dc075-92d2-7352-b203-1c4590f77fe4`):
    # fail-closed if the routine engine is absent. Without it we cannot run
    # D3 step 2 (cancel_routine_executions), so delete would silently regress
    # to pre-fix behaviour (leave in-flight tasks orphaned). Matches the
    # canonical 503 "Routine engine not running" reason used at
    # `trigger_routine`. Emit denial audit so operators see the block in the
    # audit stream, not just HTTP logs.
    engine = _get_routine_engine()
    if engine is None:
        logger.warning(
            "delete_routine blocked — engine unavailable",
            extra={
                "event": "routines.delete_routine.blocked_engine_unavailable",
                "routine_id": routine_id,
            },
        )
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.delete_blocked",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "engine_unavailable",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "delete_routine: audit emit failed (engine_unavailable path)",
                    extra={
                        "event": "routines.delete_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "reason": "Routine engine not running",
            },
        )

    # D3d §1: pre-cancel cascade (approvals + confirmations only — sessions
    # excluded because in-flight add_turn FK-requires the session row).
    await store.precancel_cascade(routine_id, user_id=user_id)

    # D3d §2: cancel in-flight executions + bounded 5s wait.
    cancelled_executions = await engine.cancel_routine_executions(routine_id)

    # D3d §3: post-wait TX cascade + routine delete.
    deleted = await store.delete(routine_id, user_id=user_id)
    if not deleted:
        # Concurrent delete won the race, or ownership check passed but
        # the row vanished between get() and delete(). 404 still correct.
        logger.debug(
            "delete_routine: not_deleted",
            extra={
                "event": "api.routes.routines.delete_routine.match",
                "reason": "not_deleted",
            },
        )  # auto:neg
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )

    if _audit_emitter is not None:
        try:
            from sentinel.audit import (
                SecurityAuditEvent,  # local import avoids boot cycle
            )

            await _audit_emitter.emit(
                SecurityAuditEvent(
                    event_type="routine.deleted",
                    source_component="routines",
                    # SecurityAuditEvent enforces outcome ∈ _VALID_OUTCOMES
                    # (sentinel/audit/events.py). Design doc D3c used "OK"
                    # descriptively; the enum-valid mapping is "SUCCESS".
                    outcome="SUCCESS",
                    details={
                        "routine_id": routine_id,
                        "cancelled_executions": cancelled_executions,
                    },
                )
            )
        except Exception:  # catch-all: audit emit best-effort
            logger.warning(
                "delete_routine: audit emit failed",
                extra={
                    "event": "routines.delete_routine.audit_emit_failed",
                    "routine_id": routine_id,
                },
                exc_info=True,
            )

    logger.info(
        "Routine deleted",
        extra={
            "event": "routines.delete_routine.done",
            "routine_id": routine_id,
            "cancelled_executions": cancelled_executions,
        },
    )
    return {
        "status": "ok",
        "deleted": routine_id,
        "cancelled_executions": cancelled_executions,
    }


@router.post("/routine/{routine_id}/run")
@limiter.limit(lambda: settings.rate_limit_routines)
async def trigger_routine(routine_id: str, request: Request):
    """Manually trigger a routine execution."""
    logger.debug(
        "trigger_routine called",
        extra={
            "event": "routines.trigger_routine",
            "routine_id": routine_id,
            "request_type": type(request).__name__,
        },
    )
    engine = _get_routine_engine()
    store = _get_routine_store()
    if engine is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine engine not running"},
        )

    # Finding #3: Ownership check before manual trigger — store must be available
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine store not available"},
        )
    # FL-C19-a1 (D30): Ownership check — split into two arms (see get_routine).
    # The second 404 below (engine.trigger_manual → None) is NOT an ownership
    # denial; do not attach routine.trigger_denied to that path.
    user_id = current_user_id.get()
    routine = await store.get(routine_id)
    if routine is None:
        logger.debug(
            "trigger_routine: routine_is_None",
            extra={
                "event": "api.routes.routines.trigger_routine.match",
                "reason": "routine_is_None",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.trigger_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "not_found_or_ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "trigger_routine: audit emit failed (not_found path)",
                    extra={
                        "event": "routines.trigger_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    if routine.user_id != user_id:
        logger.debug(
            "trigger_routine: ownership_mismatch_explicit",
            extra={
                "event": "api.routes.routines.trigger_routine.match",
                "reason": "ownership_mismatch_explicit",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.trigger_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "trigger_routine: audit emit failed (ownership_mismatch path)",
                    extra={
                        "event": "routines.trigger_routine.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    logger.debug(
        "trigger_routine: user_id_noteq_user_id_passed",
        extra={
            "event": "api.routes.routines.trigger_routine.passed",
            "reason": "user_id_noteq_user_id_passed",
        },
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
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Get execution history for a routine."""
    logger.debug(
        "get_routine_executions called",
        extra={
            "event": "routines.get_routine_executions",
            "routine_id": routine_id,
            "limit": limit,
            "offset": offset,
        },
    )
    engine = _get_routine_engine()
    store = _get_routine_store()
    if engine is None and store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine system not initialized"},
        )

    # Finding #3: Verify routine exists AND belongs to current user — store must be available
    if store is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Routine store not available"},
        )
    # FL-C19-a1 (D30): Ownership check — split into two arms (see get_routine).
    user_id = current_user_id.get()
    routine = await store.get(routine_id)
    if routine is None:
        logger.debug(
            "get_routine_executions: routine_is_None",
            extra={
                "event": "api.routes.routines.get_routine_executions.match",
                "reason": "routine_is_None",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.executions_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "not_found_or_ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "get_routine_executions: audit emit failed (not_found path)",
                    extra={
                        "event": "routines.get_routine_executions.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    if routine.user_id != user_id:
        logger.debug(
            "get_routine_executions: ownership_mismatch_explicit",
            extra={
                "event": "api.routes.routines.get_routine_executions.match",
                "reason": "ownership_mismatch_explicit",
            },
        )  # auto:neg
        if _audit_emitter is not None:
            try:
                from sentinel.audit import (
                    SecurityAuditEvent,  # local import avoids boot cycle
                )

                await _audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="routine.executions_denied",
                        source_component="routines",
                        outcome="DENIED",
                        severity="MEDIUM",
                        details={
                            "routine_id": routine_id,
                            "reason": "ownership_mismatch",
                        },
                    )
                )
            except Exception:  # catch-all: audit emit best-effort
                logger.warning(
                    "get_routine_executions: audit emit failed (ownership_mismatch path)",
                    extra={
                        "event": "routines.get_routine_executions.audit_emit_failed",
                        "routine_id": routine_id,
                    },
                    exc_info=True,
                )
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Routine not found"},
        )
    logger.debug(
        "get_routine_executions: user_id_noteq_user_id_passed",
        extra={
            "event": "api.routes.routines.get_routine_executions.passed",
            "reason": "user_id_noteq_user_id_passed",
        },
    )

    executions = []
    if engine is not None:
        executions = await engine.get_execution_history(
            routine_id,
            limit=limit,
            offset=offset,
        )

    return {
        "status": "ok",
        "executions": executions,
        "count": len(executions),
    }
