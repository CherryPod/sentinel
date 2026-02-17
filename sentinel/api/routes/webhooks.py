"""Webhook route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  POST   /api/webhook                         — register a new webhook
  GET    /api/webhook                         — list registered webhooks
  DELETE /api/webhook/{webhook_id}            — delete a webhook
  POST   /api/webhook/{webhook_id}/receive    — receive an inbound webhook event

Security-critical:
  - HMAC-SHA256 signature verification (verify_signature)
  - Timestamp freshness validation (verify_timestamp)
  - Idempotency dedup (check_idempotency)
  All imported from sentinel.channels.webhook — not inline code.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import RegisterWebhookRequest
from sentinel.api.rate_limit import limiter
from sentinel.channels.base import ChannelRouter, IncomingMessage, NullChannel
from sentinel.channels.webhook import (
    check_idempotency,
    verify_signature,
    verify_timestamp,
)
from sentinel.core.config import settings

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_webhook_registry: Any = None
_webhook_rate_limiter: Any = None
_orchestrator: Any = None
_message_router: Any = None
_event_bus: Any = None
_audit: Any = None
# In-memory only — cleared on restart. Acceptable for single-instance
# self-hosted deployment. Duplicate webhook delivery re-runs idempotently.
_idempotency_cache: dict = {}


def init(
    *,
    webhook_registry: Any = None,
    webhook_rate_limiter: Any = None,
    orchestrator: Any = None,
    message_router: Any = None,
    event_bus: Any = None,
    idempotency_cache: dict | None = None,
    audit: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _webhook_registry, _webhook_rate_limiter, _orchestrator
    global _message_router, _event_bus, _idempotency_cache, _audit
    _webhook_registry = webhook_registry
    _webhook_rate_limiter = webhook_rate_limiter
    _orchestrator = orchestrator
    _message_router = message_router
    _event_bus = event_bus
    if idempotency_cache is not None:
        _idempotency_cache = idempotency_cache
    _audit = audit


# ── Helpers ────────────────────────────────────────────────────────


def _webhook_to_dict(config) -> dict:
    return {
        "webhook_id": config.webhook_id,
        "name": config.name,
        "enabled": config.enabled,
        "user_id": config.user_id,
        "created_at": config.created_at,
    }


# ── Endpoints ──────────────────────────────────────────────────────


@router.post("/webhook")
@limiter.limit(lambda: settings.rate_limit_tasks)
async def register_webhook(req: RegisterWebhookRequest, request: Request):
    """Register a new webhook endpoint."""
    if _webhook_registry is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    config = await _webhook_registry.register(name=req.name, secret=req.secret)
    return {
        "status": "ok",
        "webhook": _webhook_to_dict(config),
        "receive_url": f"/api/webhook/{config.webhook_id}/receive",
    }


@router.get("/webhook")
async def list_webhooks():
    """List all registered webhooks (secrets excluded)."""
    if _webhook_registry is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    webhooks = await _webhook_registry.list()
    return {
        "status": "ok",
        "webhooks": [_webhook_to_dict(w) for w in webhooks],
        "count": len(webhooks),
    }


@router.delete("/webhook/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """Delete a registered webhook."""
    if _webhook_registry is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    deleted = await _webhook_registry.delete(webhook_id)
    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Webhook not found"},
        )

    return {"status": "ok", "deleted": webhook_id}


@router.post("/webhook/{webhook_id}/receive")
async def receive_webhook(webhook_id: str, request: Request):
    """Receive an inbound webhook payload from an external service.

    Security checks (in order):
    1. Webhook exists and is enabled
    2. HMAC-SHA256 signature verification (X-Signature-256 header)
    3. Timestamp freshness (X-Timestamp header, 5-minute window)
    4. Idempotency dedup (X-Idempotency-Key header)
    5. Per-webhook rate limiting
    """
    if _webhook_registry is None or _event_bus is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    # 1. Look up webhook
    config = await _webhook_registry.get(webhook_id)
    if config is None or not config.enabled:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Webhook not found"},
        )

    # Read raw body for signature verification
    body = await request.body()

    # 2. Verify HMAC signature
    signature = request.headers.get("X-Signature-256", "")
    if not signature or not verify_signature(body, signature, config.secret):
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reason": "Invalid signature"},
        )

    # 3. Verify timestamp freshness
    timestamp = request.headers.get("X-Timestamp", "")
    if not timestamp or not verify_timestamp(timestamp, config.timestamp_tolerance):
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reason": "Timestamp expired or invalid"},
        )

    # 4. Idempotency check
    idempotency_key = request.headers.get("X-Idempotency-Key", "")
    if idempotency_key:
        if check_idempotency(idempotency_key, _idempotency_cache):
            return JSONResponse(
                status_code=409,
                content={"status": "error", "reason": "Duplicate request"},
            )

    # 5. Rate limiting
    if _webhook_rate_limiter is not None and not _webhook_rate_limiter.check(webhook_id):
        return JSONResponse(
            status_code=429,
            content={"status": "error", "reason": "Rate limit exceeded"},
        )

    # Parse payload
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        payload = {"raw": body.decode("utf-8", errors="replace")}

    # Publish event to bus — routine engine listens for webhook.* events
    await _event_bus.publish(f"webhook.{webhook_id}.received", {
        "webhook_id": webhook_id,
        "webhook_name": config.name,
        "payload": payload,
    })

    # If payload contains a "prompt" field, route through orchestrator as a task
    task_triggered = False
    if isinstance(payload, dict) and payload.get("prompt") and _orchestrator is not None:
        router_instance = ChannelRouter(_orchestrator, _event_bus, _audit, message_router=_message_router)
        message = IncomingMessage(
            channel_id=f"webhook:{webhook_id}",
            source="webhook",
            content=payload["prompt"],
            metadata={
                "source_key": f"webhook:{webhook_id}",
                "approval_mode": settings.approval_mode,
                "type": "task",
            },
        )
        # Fire-and-forget: NullChannel discards responses asynchronously
        dummy_channel = NullChannel()
        try:
            await router_instance.handle_message(dummy_channel, message)
            task_triggered = True
        except Exception as exc:
            if _audit is not None:
                _audit.warning(
                    "Webhook task routing failed",
                    extra={
                        "event": "webhook_task_error",
                        "webhook_id": webhook_id,
                        "error": str(exc),
                    },
                )

    return {"status": "ok", "event_published": True, "task_triggered": task_triggered}
