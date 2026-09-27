"""Streaming and SSE route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  GET /api/events     — SSE event stream for real-time task updates
  GET /api/logs/stream — SSE log streaming for audit log viewer
  GET /api/heartbeat  — heartbeat status summary

Classes:
  LogSSEWriter — streams audit log entries as SSE events via a logging handler
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from sentinel.channels.web import SSEWriter
from sentinel.core.context import current_user_id
from sentinel.api.role_guard import require_role

logger = logging.getLogger(__name__)

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()

# ── Module globals (init pattern) ──────────────────────────────────

_event_bus: Any = None
_heartbeat_manager: Any = None
_audit: Any = None
_orchestrator: Any = None
_contact_store: Any = None
_audit_emitter: Any = None


def init(
    *,
    event_bus: Any = None,
    heartbeat_manager: Any = None,
    audit: Any = None,
    orchestrator: Any = None,
    contact_store: Any = None,
    audit_emitter: Any = None,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    logger.debug("init called", extra={"event": "streaming.init"})
    global _event_bus, _heartbeat_manager, _audit, _orchestrator, _contact_store, _audit_emitter
    _event_bus = event_bus
    _heartbeat_manager = heartbeat_manager
    _audit = audit
    _orchestrator = orchestrator
    _contact_store = contact_store
    _audit_emitter = audit_emitter


# ── Accessors ──────────────────────────────────────────────────────


def _get_event_bus():
    if _event_bus is None:
        raise HTTPException(status_code=503, detail="Event bus not initialized")
    return _event_bus


def _get_heartbeat_manager():
    if _heartbeat_manager is None:
        raise HTTPException(status_code=503, detail="Heartbeat system not initialized")
    return _heartbeat_manager


def _get_contact_store():
    if _contact_store is None:
        logger.warning(
            "log_stream: role store unavailable — request blocked",
            extra={"event": "streaming.contact_store_unavailable"},
        )
        raise HTTPException(status_code=503, detail="Auth service not available")
    return _contact_store


# ── LogSSEWriter ───────────────────────────────────────────────────


class LogSSEWriter:
    """Streams log entries as SSE events by attaching a handler to the sentinel logger.

    Attaches a logging.Handler to the ``sentinel`` parent logger so all
    ``sentinel.*`` child loggers (planner, executor, scanner, etc.) flow
    through to the SSE stream. Handler is removed in the ``finally`` block
    when the client disconnects.
    """

    def __init__(self, min_level: int = logging.INFO):
        self._queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=1000)
        self._min_level = min_level
        self._handler: logging.Handler | None = None
        self._logger = logging.getLogger("sentinel")

    def attach(self) -> None:
        """Attach the queue handler to the audit logger."""
        logger.debug("attach called", extra={"event": "streaming.attach"})
        writer = self

        class _QueueHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                entry = {
                    "timestamp": record.created,
                    "level": record.levelname,
                    "message": record.getMessage(),
                    "event": getattr(record, "event", ""),
                    "task_id": getattr(record, "task_id", ""),
                    "source": getattr(record, "source", "") or record.name,
                }
                try:
                    writer._queue.put_nowait(entry)
                except asyncio.QueueFull:
                    pass  # Drop entry — backpressure on slow clients is expected

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
                except TimeoutError:
                    # Expected keepalive cycle — not an error
                    logger.debug(
                        "event_generator: keepalive",
                        extra={"event": "streaming.event_generator_keepalive"},
                    )
                    yield {"comment": "keepalive"}
        finally:
            self.detach()


# ── Heartbeat endpoint (C2) ─────────────────────────────────────


@router.get("/heartbeat")
async def get_heartbeat():
    """Get heartbeat status summary including component health."""
    if _heartbeat_manager is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Heartbeat system not initialized"},
        )

    return {"status": "ok", "heartbeat": _heartbeat_manager.get_status_summary()}


# ── SSE event stream ──────────────────────────────────────────────


@router.get("/events")
async def sse_events(request: Request, task_id: Annotated[str, Query(min_length=1)]):
    """SSE stream for real-time task updates. Auth enforced by middleware."""
    logger.debug(
        "sse_events called",
        extra={
            "event": "streaming.sse_events",
            "request_type": type(request).__name__,
            "task_id": task_id,
        },
    )
    if _event_bus is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Event bus not initialized"},
        )

    # Cross-user isolation: verify the requesting user owns this task.
    # When orchestrator is None (degraded startup — planner startup tolerates
    # PlannerError by leaving orchestrator unset), the check is skipped with a
    # warning rather than hard-failing.
    if _orchestrator is not None:
        owner_id = _orchestrator.get_task_owner(task_id)
        uid = current_user_id.get()
        if owner_id is not None and owner_id != uid:
            logger.warning(
                "Cross-user SSE subscription rejected",
                extra={
                    "event": "streaming.cross_user_rejected",
                    "task_id": task_id,
                    "requesting_user": uid,
                    "task_owner": owner_id,
                },
            )
            return JSONResponse(
                status_code=403,
                content={"error": "Not authorised for this task"},
            )
        logger.debug(
            "SSE ownership check passed",
            extra={
                "event": "streaming.ownership_check_passed",
                "task_id": task_id,
                "user_id": uid,
            },
        )
    else:
        # SECURITY: ownership check bypassed; event bus topic isolation is the only remaining guard.
        logger.warning(
            "sse_events: orchestrator unavailable — ownership check skipped during degraded startup",
            extra={"event": "streaming.orchestrator_unavailable", "task_id": task_id},
        )

    writer = SSEWriter(_event_bus)
    await writer.subscribe(task_id)
    return EventSourceResponse(writer.event_generator())


# ── Log stream SSE endpoint ───────────────────────────────────────


@router.get("/logs/stream")
async def log_stream(
    request: Request,
    level: Annotated[
        str, Query(pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    ] = "INFO",
):
    """SSE stream of audit log entries. Admin only."""
    # Cross-user isolation: audit logs contain all users' data — restrict to admin+
    logger.debug(
        "log_stream called",
        extra={
            "event": "streaming.log_stream",
            "request_type": type(request).__name__,
            "level": level,
        },
    )
    await require_role("admin", _get_contact_store(), audit_emitter=_audit_emitter)

    min_level = getattr(logging, level.upper(), logging.INFO)
    writer = LogSSEWriter(min_level=min_level)
    writer.attach()
    return EventSourceResponse(writer.event_generator())
