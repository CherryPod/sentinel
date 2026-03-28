"""WebSocket route handler.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  WS /ws — WebSocket endpoint with PIN auth, channel routing, bidirectional messaging

The WebSocket has its own PIN authentication flow (via WebSocketChannel),
separate from the HTTP PinAuthMiddleware.  A _FailureTracker instance is
created here to rate-limit brute-force attempts on the WS PIN.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter
from starlette.websockets import WebSocket, WebSocketDisconnect

from sentinel.api.auth import _FailureTracker
from sentinel.channels.base import ChannelRouter
from sentinel.channels.web import WebSocketChannel

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()

# ── Module globals (init pattern) ──────────────────────────────────

_orchestrator: Any = None
_event_bus: Any = None
_message_router: Any = None
_pin_verifier: Any = None
_audit: Any = None
_ws_failure_tracker = _FailureTracker()


def init(
    *,
    orchestrator: Any = None,
    event_bus: Any = None,
    message_router: Any = None,
    pin_verifier: Any = None,
    audit: Any = None,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _orchestrator, _event_bus, _message_router, _pin_verifier, _audit
    _orchestrator = orchestrator
    _event_bus = event_bus
    _message_router = message_router
    _pin_verifier = pin_verifier
    _audit = audit


# ── WebSocket endpoint ────────────────────────────────────────────


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint with JWT auth and real-time task execution.

    Auth flow:
      1. Client passes ?token=<JWT> as a query parameter at connection time.
      2. We validate the token before accepting any messages. Invalid/missing
         token → close with code 4001 (same as the old PIN failure path).
      3. The resolved user_id is stored and set into current_user_id on each
         inbound message, replacing the old hardcoded set(1).
      4. Each inbound message re-validates the token to catch mid-session expiry.
    """
    from sentinel.core.context import current_user_id
    from sentinel.api.sessions import verify_session_token
    import jwt as _jwt

    # --- Step 1: Extract JWT from query param or first-message auth ---
    # Check query param first for backwards compatibility, then fall back to
    # first-message auth (preferred — avoids token in server logs/URL).
    raw_token = websocket.query_params.get("token", "")
    if not raw_token:
        # No query param — accept connection and wait for auth message
        await websocket.accept()
        try:
            auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=10)
        except (asyncio.TimeoutError, Exception):
            await websocket.close(code=4001, reason="Auth required")
            return
        if auth_msg.get("type") != "auth" or not auth_msg.get("token"):
            await websocket.close(code=4001, reason="Auth required")
            return
        raw_token = auth_msg["token"]

    try:
        ws_payload = verify_session_token(raw_token)
        ws_user_id = int(ws_payload["user_id"])
        if ws_user_id <= 0:
            raise ValueError("invalid sub")
    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError, KeyError, ValueError):
        logger.debug("WebSocket connection rejected from %s: invalid/missing token",
                     websocket.client.host if websocket.client else "unknown")
        # If we already accepted (first-message path), close with reason
        try:
            await websocket.close(code=4001, reason="Invalid token")
        except Exception:
            pass
        return

    # Accept only if we haven't already (first-message path accepts before reading)
    if websocket.query_params.get("token", ""):
        await websocket.accept()

    # Confirm auth to client — UI waits for this before switching to message handler
    await websocket.send_json({"type": "auth_ok"})

    channel = WebSocketChannel(
        websocket=websocket,
        pin_verifier_getter=lambda: _pin_verifier,
        failure_tracker=_ws_failure_tracker,
    )
    # Skip PIN auth — JWT already authenticated above.

    if _orchestrator is None or _event_bus is None:
        try:
            await websocket.send_json({
                "type": "error",
                "reason": "Orchestrator not initialized",
            })
        except Exception:
            pass
        await channel.stop()
        return

    router_inst = ChannelRouter(_orchestrator, _event_bus, _audit, message_router=_message_router)

    # Subscribe to routine events and forward to this WS client (filtered by user)
    async def _forward_routine_event(topic: str, data: dict) -> None:
        """Forward routine events only if they belong to this user."""
        try:
            # Cross-user isolation: skip events belonging to other users
            event_user_id = data.get("user_id") if isinstance(data, dict) else None
            if event_user_id is not None and event_user_id != ws_user_id:
                return
            await websocket.send_json({
                "type": "routine_event",
                "event": topic,
                "data": data,
            })
        except Exception:
            pass  # Client disconnected — cleanup handled below

    _event_bus.subscribe("routine.*", _forward_routine_event)

    try:
        async for message in channel.receive():
            msg_type = message.metadata.get("type", "")

            if msg_type == "task":
                # Re-validate the JWT on each message to catch mid-session expiry.
                try:
                    verify_session_token(raw_token)
                except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError):
                    await websocket.send_json({"type": "error", "reason": "Session expired"})
                    await websocket.close(code=4001)
                    break

                # Set user context for RLS; use the user_id resolved at connect time.
                ctx_token = current_user_id.set(ws_user_id)
                # Include user_id in source_key for per-user session isolation.
                client_ip = websocket.client.host if websocket.client else "unknown"
                message.metadata["source_key"] = f"websocket:{client_ip}:{ws_user_id}"
                task_id = None
                try:
                    task_id = await router_inst.handle_message(channel, message)
                except Exception as exc:
                    # BH3-020: Include task_id in error so the UI can match the response
                    logger.error("WebSocket task error", exc_info=True, extra={"event": "ws_task_error", "error": str(exc)})
                    error_payload = {"type": "error", "reason": str(exc)}
                    if task_id:
                        error_payload["task_id"] = task_id
                    await websocket.send_json(error_payload)
                finally:
                    current_user_id.reset(ctx_token)

            elif msg_type == "approval":
                # Re-validate JWT before processing approval actions.
                try:
                    verify_session_token(raw_token)
                except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError):
                    await websocket.send_json({"type": "error", "reason": "Session expired"})
                    await websocket.close(code=4001)
                    break

                ctx_token = current_user_id.set(ws_user_id)
                try:
                    result = await router_inst.handle_approval(
                        channel,
                        approval_id=message.metadata.get("approval_id", ""),
                        granted=message.metadata.get("granted", False),
                        reason=message.metadata.get("reason", ""),
                    )
                    await websocket.send_json({
                        "type": "approval_result",
                        "data": result,
                    })
                except Exception as exc:
                    await websocket.send_json({
                        "type": "error",
                        "reason": str(exc),
                    })
                finally:
                    current_user_id.reset(ctx_token)

            else:
                await websocket.send_json({
                    "type": "error",
                    "reason": f"Unknown message type: {msg_type}",
                })

    except WebSocketDisconnect:
        pass
    except Exception:
        logger.warning("WebSocket message handling error", exc_info=True)
    finally:
        # Unsubscribe routine event forwarder on disconnect
        try:
            _event_bus.unsubscribe("routine.*", _forward_routine_event)
        except Exception:
            pass
