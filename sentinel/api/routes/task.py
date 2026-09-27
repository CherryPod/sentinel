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

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import ApprovalDecision, TaskRequest
from sentinel.api.rate_limit import limiter
from sentinel.core.config import settings
from sentinel.core.exceptions import ToolBlockedError
from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import create_tagged_data

logger = logging.getLogger(__name__)

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_orchestrator: Any = None
_message_router: Any = None
_session_store: Any = None
_audit: Any = None
_loop_controller: Any = None
_loop_store: Any = None


def init(
    *,
    orchestrator: Any = None,
    message_router: Any = None,
    session_store: Any = None,
    audit: Any = None,
    loop_controller: Any = None,
    loop_store: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    logger.debug("init called", extra={"event": "task.init"})
    global _orchestrator, _message_router, _session_store, _audit
    global _loop_controller, _loop_store
    _orchestrator = orchestrator
    _message_router = message_router
    _session_store = session_store
    _audit = audit
    _loop_controller = loop_controller
    _loop_store = loop_store


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


from sentinel.api.routes._common import resolve_shutting_down as _resolve_shutting_down

# ── Task endpoint ─────────────────────────────────────────────────


@router.post("/task")
@limiter.limit(lambda: settings.rate_limit_tasks)
async def handle_task(req: TaskRequest, request: Request):
    """Full CaMeL pipeline: user request → Claude plans → Qwen executes → scanned result."""
    if _resolve_shutting_down(request):
        logger.debug("handle_task: match", extra={"event": "task.handle_task.match"})
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Server is shutting down"},
        )
    logger.debug(
        "handle_task: resolve_shutting_down_request_passed",
        extra={
            "event": "task.handle_task.passed",
            "reason": "resolve_shutting_down_request_passed",
        },
    )  # auto:neg

    orchestrator = _resolve_orchestrator()
    if orchestrator is None:
        logger.debug("handle_task: match", extra={"event": "task.handle_task.match"})
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Orchestrator not initialized"},
        )

    # Server-side session binding: derive session from client IP + authenticated user_id.
    # Including user_id ensures sessions are per-user, not shared across accounts at the
    # same IP (e.g. office NAT, household). The ContextVar is set by JWTMiddleware before
    # this handler runs.
    from sentinel.core.context import current_user_id

    client_ip = request.client.host if request.client else "unknown"
    user_id = current_user_id.get()
    if user_id == 0:
        logger.debug(
            "handle_task: user_id_eq_0",
            extra={
                "event": "api.routes.task.handle_task.match",
                "reason": "user_id_eq_0",
            },
        )  # auto:neg
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )

    # Q14.review Cx-3: widen try to cover create_tagged_data() — ProvenanceStore
    # explicitly re-raises persistence failures (sentinel/security/provenance.py),
    # which previously escaped the catch-all (the try started below at the
    # _execute build) and fell through to the FastAPI global handler with no
    # task.error audit emission. The logger.info + source_key setup are included
    # inside the try so a crash on any pre-execution setup also degrades
    # gracefully through the audit-emitting catch-all rather than leaking
    # to the FastAPI 500 default.
    try:
        logger.info(
            "Task submitted by user_id=%d from %s: %.200s",
            user_id,
            client_ip,
            req.request,
            extra={"event": "task.submitted", "user_id": user_id, "source": req.source},
        )

        source_key = f"{req.source}:{client_ip}:{user_id}"

        # Q8.fix.b — wrap the incoming request as UNTRUSTED at the HTTP handler
        # entry point. The same data_id threads through every loop-controller
        # iteration via the `_execute` closure — per-iteration gap-retry enrichment
        # is an internal transform per fix-design §Internal transformations.
        tagged_request = await create_tagged_data(
            content=req.request,
            source=DataSource.USER,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from=f"ingress:api:task:{source_key}",
        )
        user_request_data_id = tagged_request.id
        logger.info(
            "Task ingress tagged UNTRUSTED",
            extra={
                "event": "task.ingress_tagged",
                "user_id": user_id,
                "source": req.source,
                "data_id": user_request_data_id,
                "request_len": len(req.request),
            },
        )

        # Build the execution function — routes through message_router if available
        # (preserves fast path, input scanning, session binding), otherwise direct
        # to orchestrator.
        message_router = _resolve_message_router()

        async def _execute(user_request: str, source: str):
            """Single-pass execution via message router or orchestrator.

            Closes over `user_request_data_id` so every per-iteration dispatch
            reuses the ingress-time data_id (fix-design §Internal
            transformations — content-vs-label divergence is by design).
            """
            if message_router is not None:
                logger.debug(
                    "handle_task: match", extra={"event": "task.handle_task.match"}
                )
                return await message_router.route(
                    user_request=user_request,
                    source=source,
                    source_key=source_key,
                    approval_mode=settings.approval_mode,
                    user_request_data_id=user_request_data_id,
                )
            return await orchestrator.handle_task(
                user_request=user_request,
                source=source,
                approval_mode=settings.approval_mode,
                source_key=source_key,
                user_request_data_id=user_request_data_id,
            )

        # Loop controller wraps every task with gap-driven retry (default 5 attempts).
        # If no loop controller is available, falls back to single-pass execution.
        if _loop_controller is not None and _loop_store is not None:
            logger.debug(
                "handle_task: match", extra={"event": "task.handle_task.match"}
            )
            import uuid

            loop_id = str(uuid.uuid4())
            loop_result = await asyncio.wait_for(
                _loop_controller.run_loop(
                    loop_id=loop_id,
                    user_id=user_id,
                    request=req.request,
                    max_iterations=settings.loop_max_iterations,
                    timeout_seconds=settings.loop_timeout_seconds,
                    source=req.source,
                    execute_fn=_execute,
                ),
                timeout=settings.loop_timeout_seconds
                + 60,  # Grace period beyond loop timeout
            )
            # Convert LoopResult to TaskResult-compatible response
            from sentinel.core.models import TaskResult

            final_status = loop_result.status
            # Map loop statuses to task statuses the UI understands
            if final_status == "succeeded":
                final_status = "success"
            result = TaskResult(
                status=final_status,
                plan_summary=(
                    loop_result.iterations[-1].get("plan_summary", "")
                    if loop_result.iterations
                    else ""
                ),
                reason=(
                    loop_result.iterations[-1].get("gap_summary", "")
                    if loop_result.iterations and final_status != "success"
                    else ""
                ),
            )
        else:
            # Fallback: single-pass (no loop controller available)
            logger.debug(
                "handle_task: clean", extra={"event": "task.handle_task.clean"}
            )
            result = await asyncio.wait_for(
                _execute(req.request, req.source),
                timeout=settings.api_task_timeout,
            )
    except TimeoutError:
        logger.warning(
            "Task timed out after %ds",
            settings.api_task_timeout,
            extra={"event": "task.timeout"},
            exc_info=True,
        )
        return JSONResponse(
            status_code=504,
            content={
                "status": "error",
                "reason": f"Task timed out after {settings.api_task_timeout}s",
            },
        )
    except HTTPException:
        # Preserve FastAPI's default HTTPException handling (status code + detail)
        # — mirrors the a2a.py:197-205 Q4.fix.d precedent. Without this, the broad
        # `except Exception` below would absorb, e.g., a PrincipalRequiredError
        # re-raised as HTTPException(401), collapsing it to HTTP 500.
        raise
    except Exception as exc:
        # Q14-F5: defence-in-depth catch-all at the /api/task boundary. Sibling
        # surfaces already had generic catch-alls (a2a.py:225, websocket.py:164);
        # REST /api/task previously let everything except TimeoutError fall through
        # to the FastAPI global handler, which returned HTTP 500 "Internal server
        # error" with NO `task.error` audit emission. This loses observability on
        # any upstream failure not covered by Q14-F3 (e.g. _loop_controller.run_loop
        # / message_router.route internal bugs). Log exc_info=True server-side,
        # emit a `task.error` audit event, return scrubbed JSONResponse.
        logger.exception(
            "REST /api/task failed",
            extra={
                "event": "task.error",
                "user_id": user_id,
                "source": req.source,
                "error": str(exc),
            },
        )
        return JSONResponse(
            status_code=500,
            content={"status": "error", "reason": "Task processing failed"},
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
    logger.debug(
        "submit_approval called",
        extra={
            "event": "task.submit_approval",
            "approval_id": approval_id,
            "decision_type": type(decision).__name__,
        },
    )
    from sentinel.core.context import current_user_id

    try:
        orchestrator = _resolve_orchestrator()
        if orchestrator is None or orchestrator.approval_manager is None:
            return {"status": "error", "reason": "Approval manager not available"}

        accepted = await orchestrator.submit_approval(
            approval_id=approval_id,
            granted=decision.granted,
            reason=decision.reason,
        )
        if not accepted:
            return {
                "status": "error",
                "reason": "Invalid, expired, or duplicate approval",
            }

        if decision.granted:
            logger.info(
                "Task approval granted",
                extra={
                    "event": "task.approval_granted",
                    "approval_id": approval_id,
                    "user_id": current_user_id.get(),
                },
            )
            result = await orchestrator.execute_approved_plan(approval_id)
            return result.model_dump()

        logger.warning(
            "Task approval denied",
            extra={
                "event": "task.approval_denied",
                "approval_id": approval_id,
                "reason": decision.reason,
                "user_id": current_user_id.get(),
            },
        )
        return {"status": "denied", "reason": decision.reason}
    except HTTPException:
        # Mirror F5: preserve FastAPI's default HTTPException handling (status
        # code + detail). Without this, the broad `except Exception` below
        # would absorb future auth/ownership HTTPException raises and collapse
        # them to HTTP 500.
        raise
    except Exception as exc:
        # Q14-FL2 (cleanup-pass C24): defence-in-depth catch-all parallel to
        # Q14-F5 (`task.error`) and Q14-F6 (`confirmation.error`). REST
        # /approve/{approval_id} previously had no route-local catch-all;
        # any failure escaping `_resolve_orchestrator`, `submit_approval`,
        # `execute_approved_plan`, or `result.model_dump` fell through to
        # the FastAPI global handler (HTTP 500 "Internal server error") with
        # NO `approval.error` audit emission. Log `exc_info=True` server-side,
        # emit an `approval.error` audit event, return scrubbed JSONResponse.
        logger.exception(
            "/api/approve/{approval_id} failed",
            extra={
                "event": "approval.error",
                "approval_id": approval_id,
                "user_id": current_user_id.get(),
                "error": str(exc),
            },
        )
        return JSONResponse(
            status_code=500,
            content={"status": "error", "reason": "Approval processing failed"},
        )


@router.post("/confirm/{confirmation_id}")
async def submit_confirmation(confirmation_id: str, decision: ApprovalDecision):
    """Confirm or cancel a pending fast-path confirmation gate action.

    Same contract as /approve — returns the tool execution result on confirm,
    or a denied/error status dict.
    """
    # The JWTMiddleware has already set current_user_id in the ContextVar before this
    # handler runs — no need to set it manually here.
    logger.debug(
        "submit_confirmation called",
        extra={
            "event": "task.submit_confirmation",
            "confirmation_id": confirmation_id,
            "decision_type": type(decision).__name__,
        },
    )
    if _message_router is None:
        return {"status": "error", "reason": "Router not available"}

    gate = getattr(_message_router, "_confirmation_gate", None)
    fast_path = getattr(_message_router, "_fast_path", None)
    if gate is None or fast_path is None:
        return {"status": "error", "reason": "Confirmation gate not available"}

    from sentinel.core.context import current_user_id

    if decision.granted:
        # Q14.review Cx-1: the catch-all below MUST cover gate.confirm() in
        # addition to fast_path.execute_confirmed(). gate.confirm() can raise
        # before returning via require_user_id() or DB fetchrow in the PG path
        # (confirmation.py:210, :240) — those escapes previously bypassed the
        # confirmation.error audit + the scrubbed envelope and fell through to
        # the FastAPI global handler. Widen the try-block to start at
        # gate.confirm(), keep the ToolBlockedError narrow-catch intact for the
        # execute_confirmed branch only (gate.confirm doesn't raise that type).
        try:
            entry = await gate.confirm(confirmation_id)
            if entry is None:
                return {
                    "status": "error",
                    "reason": "Invalid, expired, or duplicate confirmation",
                }
            logger.info(
                "Task confirmation granted",
                extra={
                    "event": "task.confirmation_granted",
                    "confirmation_id": confirmation_id,
                    "user_id": current_user_id.get(),
                },
            )
            result = await fast_path.execute_confirmed(
                entry.tool_name,
                entry.tool_params,
                entry.task_id,
            )
        except ToolBlockedError as exc:
            # Q9-F3: FastPathExecutor narrow-raises ToolBlockedError so the D5
            # BLOCKED signal is distinguishable from generic tool errors. Map
            # here to the same status-dict shape that execute_confirmed would
            # normally return, keeping the /confirm response contract intact.
            # Audit event was already emitted by ToolExecutor before the raise.
            logger.exception(
                "submit_confirmation: ToolBlockedError",
                extra={"event": "api.routes.task.submit_confirmation_toolblockederror"},
            )  # auto:except
            return {
                "status": "blocked",
                "reason": f"Tool blocked by policy: {exc}",
            }
        except Exception as exc:
            # Q14-F6: /api/confirm previously caught only ToolBlockedError; any
            # ToolError / TimeoutError / policy exception escaping
            # execute_confirmed OR gate.confirm fell through to the FastAPI
            # global handler (HTTP 500 "Internal server error") with NO
            # confirmation.error audit emission. Added defence-in-depth
            # catch-all mirroring the ToolBlockedError branch: structured
            # status-dict return, emit the confirmation.error audit event,
            # keep exc detail in server logs.
            logger.exception(
                "submit_confirmation failed",
                extra={
                    "event": "confirmation.error",
                    "confirmation_id": confirmation_id,
                    "user_id": current_user_id.get(),
                    "error": str(exc),
                },
            )
            return {
                "status": "error",
                "reason": "Confirmation processing failed",
            }
        return result
    logger.warning(
        "Task confirmation denied",
        extra={
            "event": "task.confirmation_denied",
            "confirmation_id": confirmation_id,
            "reason": decision.reason or "Cancelled via WebUI",
            "user_id": current_user_id.get(),
        },
    )
    await gate.cancel(confirmation_id)
    return {"status": "denied", "reason": decision.reason or "Cancelled via WebUI"}


# ── Session debug endpoint ────────────────────────────────────────


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Debug endpoint: view session state and conversation history."""
    logger.debug(
        "get_session called",
        extra={"event": "task.get_session", "session_id": session_id},
    )
    session_store = _resolve_session_store()
    if session_store is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Session store not initialized"},
        )

    # SessionStore.get() already scopes by current_user_id via ContextVar —
    # a user can only retrieve their own sessions (RLS + user_id filter).
    session = await session_store.get(session_id)
    if session is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Session not found or expired"},
        )

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
