"""A2A (Agent-to-Agent) protocol route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  GET  /.well-known/agent.json  -- A2A Agent Card discovery
  POST /a2a                     -- A2A JSON-RPC 2.0 task endpoint

Compatibility note: the safety-net test CI-2 patches app_module._shutting_down
directly and expects POST /a2a -> 503.  The _resolve_shutting_down() accessor
checks request.app.state first, then falls back to the app module global.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

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
from sentinel.api.rate_limit import limiter
from sentinel.core.config import settings

logger = logging.getLogger("sentinel.a2a")

# -- Router ----------------------------------------------------------------

router = APIRouter()


# -- Module globals (init pattern) -----------------------------------------

_orchestrator: Any = None
_event_bus: Any = None


def init(
    *,
    orchestrator: Any = None,
    event_bus: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies -- called once from app.py lifespan."""
    global _orchestrator, _event_bus
    _orchestrator = orchestrator
    _event_bus = event_bus


# -- Accessors (with app-module fallback for safety-net compat) ------------

def _resolve_orchestrator():
    """Return orchestrator from init() globals or app module fallback."""
    if _orchestrator is not None:
        return _orchestrator
    import sentinel.api.app as _app
    return getattr(_app, "_orchestrator", None)


def _resolve_event_bus():
    """Return event bus from init() globals or app module fallback."""
    if _event_bus is not None:
        return _event_bus
    import sentinel.api.app as _app
    return getattr(_app, "_event_bus", None)


def _resolve_shutting_down(request: Request) -> bool:
    """Check shutdown flag from app.state, then app module fallback."""
    # Prefer app.state (set by lifespan dual-write)
    state_val = getattr(request.app.state, "shutting_down", None)
    if state_val is not None:
        return state_val
    # Fallback: safety-net tests set app_module._shutting_down directly
    import sentinel.api.app as _app
    return _app._shutting_down


# -- Route handlers --------------------------------------------------------


@router.get("/.well-known/agent.json")
async def agent_card(request: Request):
    """A2A Agent Card -- static metadata for agent discovery.

    BH3-023: URL derived from request headers instead of hardcoded localhost.
    """
    card = {**AGENT_CARD, "url": str(request.base_url).rstrip("/")}
    return JSONResponse(content=card)


@router.post("/a2a")
@limiter.limit(lambda: settings.rate_limit_tasks)
async def a2a_endpoint(request: Request):
    """A2A JSON-RPC 2.0 endpoint -- translates A2A methods to Sentinel internals.

    Supported methods:
      - tasks/send: submit a task (maps to orchestrator.handle_task)
      - tasks/sendSubscribe: submit + stream SSE updates
      - tasks/get: query task/approval status
      - tasks/cancel: not yet implemented (returns method-not-found)
    """
    if _resolve_shutting_down(request):
        return JSONResponse(status_code=503, content={"status": "error", "reason": "Server is shutting down"})

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
        orchestrator = _resolve_orchestrator()
        if orchestrator is None:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Orchestrator not initialized"),
            )
        try:
            client_ip = request.client.host if request.client else "unknown"
            task_result = await handle_tasks_send(params, orchestrator, client_ip)
            a2a_task = build_a2a_task(task_result)
            # BH3-024: Return 504 for timeout instead of 200 with error body
            if task_result.status == "error" and "timed out" in (task_result.reason or ""):
                return JSONResponse(
                    status_code=504,
                    content=jsonrpc_error(req_id, INTERNAL_ERROR, task_result.reason or "Task timed out"),
                )
            return JSONResponse(content=jsonrpc_success(req_id, a2a_task))
        except ValueError as exc:
            return JSONResponse(
                content=jsonrpc_error(req_id, INVALID_REQUEST, str(exc)),
            )
        except Exception as exc:
            logger.error(
                "A2A tasks/send failed",
                extra={"event": "a2a_error", "method": "tasks/send", "error": str(exc)},
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Task processing failed"),
            )

    elif method == "tasks/sendSubscribe":
        orchestrator = _resolve_orchestrator()
        event_bus = _resolve_event_bus()
        if orchestrator is None or event_bus is None:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Orchestrator not initialized"),
            )
        try:
            client_ip = request.client.host if request.client else "unknown"
            task_result = await handle_tasks_send(params, orchestrator, client_ip)
            return EventSourceResponse(
                a2a_sse_generator(task_result, event_bus),
            )
        except ValueError as exc:
            return JSONResponse(
                content=jsonrpc_error(req_id, INVALID_REQUEST, str(exc)),
            )
        except Exception as exc:
            logger.error(
                "A2A tasks/sendSubscribe failed",
                extra={"event": "a2a_error", "method": "tasks/sendSubscribe", "error": str(exc)},
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Task processing failed"),
            )

    elif method == "tasks/get":
        orchestrator = _resolve_orchestrator()
        if orchestrator is None:
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Orchestrator not initialized"),
            )
        try:
            task = await handle_tasks_get(params, orchestrator)
            if task is None:
                return JSONResponse(
                    content=jsonrpc_error(req_id, INVALID_REQUEST, "Task not found"),
                )
            return JSONResponse(content=jsonrpc_success(req_id, task))
        except Exception as exc:
            logger.error(
                "A2A tasks/get failed",
                extra={"event": "a2a_error", "method": "tasks/get", "error": str(exc)},
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Task lookup failed"),
            )

    elif method == "tasks/cancel":
        return JSONResponse(
            content=jsonrpc_error(req_id, METHOD_NOT_FOUND, "tasks/cancel not yet implemented"),
        )

    else:
        return JSONResponse(
            content=jsonrpc_error(req_id, METHOD_NOT_FOUND, f"Unknown method: {method}"),
        )
