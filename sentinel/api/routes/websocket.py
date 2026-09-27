"""WebSocket route handler.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  WS /ws — WebSocket endpoint with cookie-based JWT auth, channel routing,
            bidirectional messaging

The WebSocket authenticates via the HttpOnly session cookie sent automatically
by the browser on the WS upgrade request (same-origin). A _FailureTracker
instance is created here to rate-limit brute-force attempts on the WS PIN.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID, uuid4

import jwt as _jwt
from fastapi import APIRouter
from starlette.websockets import WebSocket, WebSocketDisconnect

from sentinel.api.auth import _FailureTracker
from sentinel.api.sessions import verify_session_token
from sentinel.channels.base import ChannelRouter
from sentinel.channels.web import WebSocketChannel
from sentinel.core.context import current_user_id

logger = logging.getLogger(__name__)

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()

# ── Module globals (init pattern) ──────────────────────────────────

_orchestrator: Any = None
_event_bus: Any = None
_message_router: Any = None
_pin_verifier: Any = None
_audit: Any = None
_loop_controller: Any = None
_loop_store: Any = None
_ws_failure_tracker = _FailureTracker()


def init(
    *,
    orchestrator: Any = None,
    event_bus: Any = None,
    message_router: Any = None,
    pin_verifier: Any = None,
    audit: Any = None,
    loop_controller: Any = None,
    loop_store: Any = None,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    logger.debug("init called", extra={"event": "websocket.init"})
    global _orchestrator, _event_bus, _message_router, _pin_verifier, _audit
    global _loop_controller, _loop_store
    _orchestrator = orchestrator
    _event_bus = event_bus
    _message_router = message_router
    _pin_verifier = pin_verifier
    _audit = audit
    _loop_controller = loop_controller
    _loop_store = loop_store


# ── Sub-functions ────────────────────────────────────────────────────


async def _authenticate_ws(websocket: WebSocket) -> tuple[int, str] | None:
    """Authenticate a WebSocket connection via session cookie.

    The browser sends the HttpOnly session cookie automatically on the WS
    upgrade request (same-origin). Returns (user_id, raw_token) on success,
    or None if auth fails (caller should return immediately — the socket is
    already closed/rejected). The raw_token is needed for per-message
    re-validation.
    """
    raw_token = websocket.cookies.get("session", "")

    if not raw_token:
        logger.debug(
            "WebSocket connection rejected: no session cookie",
            extra={"event": "websocket.auth_no_cookie"},
        )
        try:
            await websocket.close(code=4001, reason="No session cookie")
        except Exception:  # catch-all: best-effort close on auth failure
            logger.debug(
                "Exception during auth-failure close",
                extra={"event": "websocket.auth_close_error"},
                exc_info=True,
            )
        return None

    try:
        ws_payload = verify_session_token(raw_token)
        ws_user_id = int(ws_payload["user_id"])
        if ws_user_id <= 0:
            raise ValueError("invalid sub")
    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError, KeyError, ValueError):
        logger.debug(
            "WebSocket connection rejected: invalid/expired session cookie",
            extra={"event": "websocket.auth_invalid"},
        )
        try:
            await websocket.close(code=4001, reason="Invalid session")
        except Exception:  # catch-all: best-effort close on auth failure
            logger.debug(
                "Exception during auth-failure close",
                extra={"event": "websocket.auth_close_error"},
                exc_info=True,
            )
        return None

    await websocket.accept()

    # Confirm auth to client — UI waits for this before switching to message handler
    await websocket.send_json({"type": "auth_ok"})

    logger.debug(
        "WebSocket authenticated",
        extra={"event": "websocket.authenticated", "user_id": ws_user_id},
    )
    return ws_user_id, raw_token


async def _handle_task_message(
    websocket: WebSocket,
    message: Any,
    raw_token: str,
    ws_user_id: int,
    connection_id: UUID,
    router_inst: ChannelRouter,
    channel: WebSocketChannel,
) -> bool:
    """Handle an inbound 'task' message. Returns False if session expired."""
    # Re-validate the JWT on each message to catch mid-session expiry.
    try:
        verify_session_token(raw_token)
    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError):
        logger.debug(
            "WebSocket JWT expired mid-session (task)",
            extra={"event": "websocket.jwt_expired_task"},
            exc_info=True,
        )
        await websocket.send_json({"type": "error", "reason": "Session expired"})
        await websocket.close(code=4001)
        return False

    ctx_token = current_user_id.set(ws_user_id)
    client_ip = websocket.client.host if websocket.client else "unknown"
    message.metadata["source_key"] = (
        f"websocket:{client_ip}:{ws_user_id}:{connection_id}"
    )
    task_id = None
    try:
        task_id = await router_inst.handle_message(channel, message)
    except Exception as exc:
        # Q14-F4: raw str(exc) was echoed to the browser as `reason`. Upstream
        # messages can carry internal paths, tool args, contact identifiers, or
        # grep-friendly PrincipalRequiredError strings. Fixed safe reason to
        # match /a2a + REST global-handler convention; detail stays in server
        # logs via exc_info=True.
        logger.error(
            "WebSocket task error",
            exc_info=True,
            extra={"event": "ws.task_error", "error": str(exc)},
        )
        error_payload: dict[str, Any] = {
            "type": "error",
            "reason": "Request processing failed",
        }
        if task_id:
            error_payload["task_id"] = task_id
        await websocket.send_json(error_payload)
    finally:
        current_user_id.reset(ctx_token)
    return True


async def _handle_approval_message(
    websocket: WebSocket,
    message: Any,
    raw_token: str,
    ws_user_id: int,
    connection_id: UUID,
    router_inst: ChannelRouter,
    channel: WebSocketChannel,
) -> bool:
    """Handle an inbound 'approval' message. Returns False if session expired.

    `connection_id` identifies the live WebSocket connection. It is used
    to build the source_key passed through to `submit_approval`, which
    enforces transport-session binding on approval submission (Q3-F4):
    a reconnected socket (new connection_id → new source_key) cannot
    submit an approval created by a dropped socket even if it knows the
    approval_id. See fix-design §7.3.
    """
    try:
        verify_session_token(raw_token)
    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError):
        logger.debug(
            "WebSocket JWT expired mid-session (approval)",
            extra={
                "event": "websocket.jwt_expired_approval",
                "connection_id": str(connection_id),
            },
            exc_info=True,
        )
        await websocket.send_json({"type": "error", "reason": "Session expired"})
        await websocket.close(code=4001)
        return False

    ctx_token = current_user_id.set(ws_user_id)
    client_ip = websocket.client.host if websocket.client else "unknown"
    source_key = f"websocket:{client_ip}:{ws_user_id}:{connection_id}"
    try:
        result = await router_inst.handle_approval(
            channel,
            approval_id=message.metadata.get("approval_id", ""),
            granted=message.metadata.get("granted", False),
            reason=message.metadata.get("reason", ""),
            source_key=source_key,
        )
        await websocket.send_json({"type": "approval_result", "data": result})
    except Exception as exc:  # catch-all: websocket message handler
        # Q14-F4: raw str(exc) was echoed to the browser as `reason`. Fixed
        # safe reason for the user-facing surface; detail stays in server logs.
        logger.warning(
            "WebSocket approval error",
            extra={"event": "websocket.approval_error", "error": str(exc)},
            exc_info=True,
        )
        await websocket.send_json(
            {"type": "error", "reason": "Approval processing failed"},
        )
    finally:
        current_user_id.reset(ctx_token)
    return True


# ── WebSocket endpoint ────────────────────────────────────────────


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint with cookie-based auth and real-time task execution.

    Auth flow:
      1. Browser sends HttpOnly session cookie automatically on WS upgrade.
      2. We validate the cookie before accepting. Invalid/missing cookie →
         close with code 4001.
      3. The resolved user_id is stored and set into current_user_id on each
         inbound message.
      4. Each inbound message re-validates the token to catch mid-session expiry.
    """
    # --- Step 1: Authenticate ---
    auth_result = await _authenticate_ws(websocket)
    if auth_result is None:
        return
    ws_user_id, raw_token = auth_result

    # Per-connection identity. Each WebSocket connection — including reconnects
    # from the same user/IP and concurrent tabs/devices — gets a fresh UUID.
    # This closes Q3-F4: source_key is bound to the transport-session, not just
    # the (ip, user_id) pair. Reconnects are new sessions by design — see
    # docs/hardening/2026-04-20-hardening-Q3-source-key-findings.md §Design.
    connection_id = uuid4()
    logger.debug(
        "WebSocket connection established",
        extra={
            "event": "websocket.connection_established",
            "user_id": ws_user_id,
            "connection_id": str(connection_id),
        },
    )

    # --- Step 2: Setup channel + router ---

    channel = WebSocketChannel(
        websocket=websocket,
        pin_verifier_getter=lambda: _pin_verifier,
        failure_tracker=_ws_failure_tracker,
    )

    if _orchestrator is None or _event_bus is None:
        try:
            await websocket.send_json(
                {"type": "error", "reason": "Orchestrator not initialized"}
            )
        except Exception:  # catch-all: best-effort error send
            logger.debug(
                "Exception sending orchestrator-missing error",
                extra={"event": "websocket.send_error"},
                exc_info=True,
            )
        await channel.stop()
        return

    router_inst = ChannelRouter(
        _orchestrator,
        _event_bus,
        _audit,
        message_router=_message_router,
        loop_controller=_loop_controller,
        loop_store=_loop_store,
    )

    # Subscribe to routine events and forward to this WS client (filtered by user)
    async def _forward_routine_event(topic: str, data: dict) -> None:
        """Forward routine events only if they belong to this user."""
        try:
            event_user_id = data.get("user_id") if isinstance(data, dict) else None
            if event_user_id is not None and event_user_id != ws_user_id:
                return
            await websocket.send_json(
                {"type": "routine_event", "event": topic, "data": data}
            )
        except Exception:  # catch-all: event forward best-effort
            logger.debug(
                "Routine event forward failed",
                extra={"event": "websocket.routine_forward_error"},
                exc_info=True,
            )

    _event_bus.subscribe("routine.*", _forward_routine_event)

    # --- Step 3: Message loop ---
    try:
        async for message in channel.receive():
            msg_type = message.metadata.get("type", "")

            if msg_type == "task":
                logger.debug(
                    "websocket_endpoint: clean",
                    extra={"event": "websocket.unknown_msg_type.clean"},
                )
                if not await _handle_task_message(
                    websocket,
                    message,
                    raw_token,
                    ws_user_id,
                    connection_id,
                    router_inst,
                    channel,
                ):
                    break

            elif msg_type == "approval":
                logger.debug(
                    "websocket_endpoint: clean",
                    extra={"event": "websocket.unknown_msg_type.clean"},
                )
                if not await _handle_approval_message(
                    websocket,
                    message,
                    raw_token,
                    ws_user_id,
                    connection_id,
                    router_inst,
                    channel,
                ):
                    break

            else:
                logger.debug(
                    "Unknown WebSocket message type",
                    extra={"event": "websocket.unknown_msg_type", "msg_type": msg_type},
                )
                await websocket.send_json(
                    {"type": "error", "reason": f"Unknown message type: {msg_type}"}
                )

    except WebSocketDisconnect:
        logger.debug(
            "WebSocket client disconnected",
            extra={"event": "websocket.disconnect"},
        )
    except Exception:  # catch-all: websocket message loop
        logger.warning(
            "WebSocket message handling error",
            extra={"event": "websocket.message_error"},
            exc_info=True,
        )
    finally:
        try:
            _event_bus.unsubscribe("routine.*", _forward_routine_event)
        except Exception:  # catch-all: cleanup best-effort
            logger.debug(
                "Exception during event bus unsubscribe",
                extra={"event": "websocket.unsubscribe_error"},
                exc_info=True,
            )
