"""A2A (Agent-to-Agent) protocol route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  GET  /.well-known/agent-card.json  -- A2A Agent Card discovery (spec §14.3)
  POST /a2a                           -- A2A JSON-RPC 2.0 task endpoint

Compatibility note: the safety-net test CI-2 patches app_module._shutting_down
directly and expects POST /a2a -> 503.  The _resolve_shutting_down() accessor
checks request.app.state first, then falls back to the app module global.
"""

from __future__ import annotations

import copy
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from sentinel.api.a2a import (
    AGENT_CARD,
    DUPLICATE_REQUEST,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    DuplicateTaskError,
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

logger = logging.getLogger(__name__)

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


from sentinel.api.routes._common import resolve_shutting_down as _resolve_shutting_down

# -- Route handlers --------------------------------------------------------


def _resolve_agent_card(request: Request) -> dict[str, Any]:
    """Return AGENT_CARD with supportedInterfaces[0].url rewritten to request.base_url.

    BH3-023 behaviour preserved under proto-v1.0.0 shape: the JSON-RPC endpoint
    URL lives inside AgentInterface, so we rewrite `supportedInterfaces[0].url`
    at request time rather than the retired top-level `url` field.

    `copy.deepcopy` (not shallow-merge): the module-global AGENT_CARD contains
    a nested list of dicts; shallow-merge would preserve the same list reference
    across requests so mutating `supportedInterfaces[0]` would stamp the host
    name onto every subsequent request's copy.
    """
    base = str(request.base_url).rstrip("/")
    card = copy.deepcopy(AGENT_CARD)
    if card["supportedInterfaces"]:
        card["supportedInterfaces"][0]["url"] = f"{base}/a2a"
    return card


@router.get("/.well-known/agent-card.json")
async def agent_card(request: Request) -> JSONResponse:
    """A2A Agent Card at the IANA-registered well-known URI (spec §14.3).

    Served per A2A v1.0.0 proto shape (see sentinel.api.a2a.AGENT_CARD). The
    legacy path /.well-known/agent.json was retired in Q13.fix.g — A2A has
    zero Sentinel production clients, so straight-migrate is defensible.
    """
    return JSONResponse(content=_resolve_agent_card(request))


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
        logger.debug("a2a_endpoint: match", extra={"event": "a2a.a2a_endpoint.match"})
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Server is shutting down"},
        )

    # Parse JSON body
    try:
        body = await request.json()
    except Exception:  # catch-all: API boundary — invalid request body
        logger.debug(
            "A2A invalid JSON body",
            extra={"event": "a2a.invalid_json"},
            exc_info=True,
        )
        return JSONResponse(
            content=jsonrpc_error(None, INVALID_REQUEST, "Invalid JSON")
        )

    # Validate JSON-RPC structure
    parsed = parse_jsonrpc_request(body)
    if isinstance(parsed, dict):
        # parse_jsonrpc_request returned an error response
        logger.debug("a2a_endpoint: match", extra={"event": "a2a.a2a_endpoint.match"})
        return JSONResponse(content=parsed)

    req_id, method, params = parsed

    # Route to the appropriate handler
    if method == "tasks/send":
        orchestrator = _resolve_orchestrator()
        if orchestrator is None:
            logger.debug(
                "a2a_endpoint: match", extra={"event": "a2a.a2a_endpoint.match"}
            )
            return JSONResponse(
                content=jsonrpc_error(
                    req_id, INTERNAL_ERROR, "Orchestrator not initialized"
                ),
            )
        try:
            client_ip = request.client.host if request.client else "unknown"
            task_result = await handle_tasks_send(params, orchestrator, client_ip)
            a2a_task = build_a2a_task(task_result)
            # BH3-024: Return 504 for timeout instead of 200 with error body
            if task_result.status == "error" and "timed out" in (
                task_result.reason or ""
            ):
                logger.debug(
                    "a2a_endpoint: match", extra={"event": "a2a.a2a_endpoint.match"}
                )
                return JSONResponse(
                    status_code=504,
                    content=jsonrpc_error(
                        req_id, INTERNAL_ERROR, task_result.reason or "Task timed out"
                    ),
                )
            logger.info(
                "A2A task received: %s", req_id, extra={"event": "a2a.task_received"}
            )
            return JSONResponse(content=jsonrpc_success(req_id, a2a_task))
        except HTTPException:
            # Q4.fix.d Merge Coord fix-now: narrow-raise HTTPException past the
            # broad `except Exception` below so the Rule 1 HTTPException(401)
            # raised by `handle_tasks_send` on zero-principal propagates to
            # FastAPI's default handler as HTTP 401, not absorbed into a
            # generic JSON-RPC INTERNAL_ERROR. Mirrors Q4.fix.f precedent
            # (commit 22ea0015) where api/routes/{routines,memory}.py had
            # `except ValueError` absorbing PrincipalRequiredError.
            raise
        except DuplicateTaskError as exc:
            # Q13.fix.a (F9): duplicate tasks/send within the idempotency
            # window — surface as JSON-RPC DUPLICATE_REQUEST (-32002) in the
            # response body (HTTP 200 per JSON-RPC 2.0 transport convention).
            logger.info(
                "A2A tasks/send duplicate rejected",
                extra={
                    "event": "a2a.duplicate_rejected",
                    "method": "tasks/send",
                },
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, DUPLICATE_REQUEST, str(exc)),
            )
        except ValueError as exc:
            logger.debug("a2a.tasks_send_validation_failed", exc_info=True)
            return JSONResponse(
                content=jsonrpc_error(req_id, INVALID_REQUEST, str(exc)),
            )
        except Exception as exc:
            logger.exception(
                "A2A tasks/send failed",
                extra={"event": "a2a.error", "method": "tasks/send", "error": str(exc)},
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Task processing failed"),
            )

    elif method == "tasks/sendSubscribe":
        orchestrator = _resolve_orchestrator()
        event_bus = _resolve_event_bus()
        if orchestrator is None or event_bus is None:
            logger.debug(
                "a2a_endpoint: match", extra={"event": "a2a.a2a_endpoint.match"}
            )
            return JSONResponse(
                content=jsonrpc_error(
                    req_id, INTERNAL_ERROR, "Orchestrator not initialized"
                ),
            )
        try:
            client_ip = request.client.host if request.client else "unknown"
            task_result = await handle_tasks_send(params, orchestrator, client_ip)
            return EventSourceResponse(
                a2a_sse_generator(task_result, event_bus),
            )
        except HTTPException:
            # Q4.fix.d Merge Coord fix-now: same narrow-raise as tasks/send
            # above. Rule 1 HTTPException(401) must propagate to FastAPI's
            # default handler as HTTP 401, not be absorbed as JSON-RPC
            # INTERNAL_ERROR.
            raise
        except DuplicateTaskError as exc:
            # Q13.fix.a (F9): same dedup semantics as tasks/send above —
            # tasks/sendSubscribe wraps the same handle_tasks_send producer
            # so the replayed-id rejection must land in the same body shape.
            logger.info(
                "A2A tasks/sendSubscribe duplicate rejected",
                extra={
                    "event": "a2a.duplicate_rejected",
                    "method": "tasks/sendSubscribe",
                },
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, DUPLICATE_REQUEST, str(exc)),
            )
        except ValueError as exc:
            logger.debug("a2a.tasks_send_subscribe_validation_failed", exc_info=True)
            return JSONResponse(
                content=jsonrpc_error(req_id, INVALID_REQUEST, str(exc)),
            )
        except Exception as exc:
            logger.exception(
                "A2A tasks/sendSubscribe failed",
                extra={
                    "event": "a2a.error",
                    "method": "tasks/sendSubscribe",
                    "error": str(exc),
                },
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Task processing failed"),
            )

    elif method == "tasks/get":
        orchestrator = _resolve_orchestrator()
        if orchestrator is None:
            logger.debug(
                "a2a_endpoint: match", extra={"event": "a2a.a2a_endpoint.match"}
            )
            return JSONResponse(
                content=jsonrpc_error(
                    req_id, INTERNAL_ERROR, "Orchestrator not initialized"
                ),
            )
        try:
            task = await handle_tasks_get(params, orchestrator)
            if task is None:
                logger.debug(
                    "a2a_endpoint: match", extra={"event": "a2a.a2a_endpoint.match"}
                )
                return JSONResponse(
                    content=jsonrpc_error(req_id, INVALID_REQUEST, "Task not found"),
                )
            return JSONResponse(content=jsonrpc_success(req_id, task))
        except Exception as exc:
            logger.exception(
                "A2A tasks/get failed",
                extra={
                    "event": "a2a.tasks_get_failed",
                    "method": "tasks/get",
                    "error_type": type(exc).__name__,
                },
            )
            return JSONResponse(
                content=jsonrpc_error(req_id, INTERNAL_ERROR, "Task lookup failed"),
            )

    elif method == "tasks/cancel":
        logger.debug(
            "a2a_endpoint: unimplemented method",
            extra={"event": "a2a.method_not_implemented", "method": "tasks/cancel"},
        )
        return JSONResponse(
            content=jsonrpc_error(
                req_id, METHOD_NOT_FOUND, "tasks/cancel not yet implemented"
            ),
        )

    else:
        logger.debug(
            "a2a_endpoint: unknown method",
            extra={"event": "a2a.method_unknown", "method": method},
        )
        return JSONResponse(
            content=jsonrpc_error(
                req_id, METHOD_NOT_FOUND, f"Unknown method: {method}"
            ),
        )
