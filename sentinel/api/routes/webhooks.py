"""Webhook route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  POST   /api/webhook                         — register a new webhook
  GET    /api/webhook                         — list registered webhooks
  DELETE /api/webhook/{webhook_id}            — delete a webhook
  POST   /api/webhook/{webhook_id}/receive    — receive an inbound webhook event

Security-critical:
  - HMAC-SHA256 signature verification (verify_signature, v2= and legacy sha256=)
  - Timestamp freshness validation (verify_timestamp)
  - Replay fingerprint persistence (check_replay_fingerprint, Postgres-backed)
  All imported from sentinel.channels.webhook — not inline code.

Q13.fix.e (F3): receive path rewired for the v2 signature scheme.
  * X-Timestamp is REQUIRED — missing/empty → 400 (protocol framing
    defect, not an auth defect so not 401).
  * Signature verified BEFORE freshness check — signature validates
    secret knowledge first; the timestamp freshness window is only
    meaningful post-signature (the timestamp is signed under v2).
  * Replay fingerprint (server-computed HMAC digest) persisted in
    Postgres via admin_pool — survives restart. Receive path bypasses
    RLS (auth-exempt, current_user_id=0 under middleware exempt list)
    via WebhookRegistry.get_for_receive().
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import RegisterWebhookRequest
from sentinel.api.rate_limit import limiter
from sentinel.channels.base import ChannelRouter, IncomingMessage, NullChannel
from sentinel.channels.webhook import (
    WebhookRegistry,
    check_replay_fingerprint,
    compute_fingerprint,
    verify_signature,
    verify_timestamp,
)
from sentinel.core.config import settings
from sentinel.core.context import current_user_id

logger = logging.getLogger(__name__)

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_webhook_registry: Any = None
_webhook_rate_limiter: Any = None
_orchestrator: Any = None
_message_router: Any = None
_event_bus: Any = None
_audit: Any = None
# Q13.fix.e: admin pool (sentinel_owner, bypasses RLS) for receive-path
# webhook lookups + replay-fingerprint persistence. REQUIRED in production;
# in-memory fallback below is test-only.
_admin_pool: Any = None
# In-memory replay-fingerprint fallback — test-only. In production the
# admin pool is set and check_replay_fingerprint persists to Postgres.
# Retained as a fallback so WebhookRegistry(pool=None) unit tests keep
# working without a real Postgres.
_replay_seen: dict = {}


_loop_controller: Any = None
_loop_store: Any = None


def init(
    *,
    webhook_registry: Any = None,
    webhook_rate_limiter: Any = None,
    orchestrator: Any = None,
    message_router: Any = None,
    event_bus: Any = None,
    admin_pool: Any = None,
    replay_seen: dict | None = None,
    audit: Any = None,
    loop_controller: Any = None,
    loop_store: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan.

    Q13.fix.e: ``admin_pool`` is REQUIRED in production — without it,
    the receive route cannot reach the ``webhooks`` table (RLS blocks
    the auth-exempt ``current_user_id=0`` context) and cannot persist
    replay fingerprints. The lifespan init site (api/init/channels.py)
    fails startup if ``admin_pool`` is None when webhook routes are
    wired, so the ``None`` branch below is a test-only affordance.
    """
    logger.debug("init called", extra={"event": "webhooks.init"})
    global _webhook_registry, _webhook_rate_limiter, _orchestrator
    global _message_router, _event_bus, _audit
    global _loop_controller, _loop_store
    global _admin_pool, _replay_seen
    _webhook_registry = webhook_registry
    _webhook_rate_limiter = webhook_rate_limiter
    _orchestrator = orchestrator
    _message_router = message_router
    _event_bus = event_bus
    _admin_pool = admin_pool
    if replay_seen is not None:
        _replay_seen = replay_seen
    _audit = audit
    _loop_controller = loop_controller
    _loop_store = loop_store


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

    uid = current_user_id.get()
    config = await _webhook_registry.register(
        name=req.name, secret=req.secret, user_id=uid
    )
    logger.info(
        "Webhook registered: %s by user_id=%d",
        req.name,
        uid,
        extra={"event": "webhook.registered"},
    )
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

    uid = current_user_id.get()
    webhooks = await _webhook_registry.list(user_id=uid)
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

    # Ownership check: verify webhook belongs to current user before deleting
    uid = current_user_id.get()
    config = await _webhook_registry.get(webhook_id)
    if config is None or getattr(config, "user_id", None) != uid:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Webhook not found"},
        )

    deleted = await _webhook_registry.delete(webhook_id)
    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Webhook not found"},
        )

    logger.info(
        "Webhook deleted: %s by user_id=%d",
        webhook_id,
        uid,
        extra={"event": "webhook.deleted"},
    )
    return {"status": "ok", "deleted": webhook_id}


@router.post("/webhook/{webhook_id}/receive")
async def receive_webhook(webhook_id: str, request: Request):
    """Receive an inbound webhook payload from an external service.

    Q13.fix.e enforcement sequence:
    1. Webhook exists and is enabled (admin-pool lookup bypasses RLS —
       receive is auth-exempt so ``current_user_id=0`` can't read the
       user-scoped ``webhooks`` table through the RLS pool).
    2. Read raw body.
    3. ``X-Timestamp`` header REQUIRED — missing/empty → 400 (framing).
    4. HMAC signature verification: ``v2=`` (timestamp-dot-body) or
       legacy ``sha256=`` (body-only, gated on the config flag). Invalid
       → 401.
    5. Timestamp freshness: within ``timestamp_tolerance`` seconds of
       now (checked AFTER signature so the window is only applied to
       requests that have already proven secret knowledge). Expired or
       unparseable → 401.
    6. Replay fingerprint: server-computed HMAC hex digest inserted
       into ``webhook_replay_fingerprints`` via ``ON CONFLICT DO
       NOTHING``. Duplicate → 409. Database unavailable → 503 (never
       silently degrade; design §Enforcement sequence).
    7. Per-webhook rate limiting.
    8. Parse + publish.
    """
    logger.debug(
        "receive_webhook called",
        extra={
            "event": "webhooks.receive_webhook",
            "webhook_id": webhook_id,
            "request_type": type(request).__name__,
        },
    )
    if _webhook_registry is None or _event_bus is None:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Webhook system not initialized"},
        )

    # 1. Look up webhook. Production uses the admin pool (owner bypass
    # of RLS — receive is auth-exempt so current_user_id=0 can't match
    # rows through the RLS pool). Tests with pool=None registry fall
    # through to the in-memory dict via _webhook_registry.get.
    # PG unavailable → 503 (never silently degrade, per spec §PG
    # unavailable). Wrapping both the admin-pool lookup AND the
    # fingerprint insert keeps the error contract identical at every
    # PG-dependent boundary of the receive path.
    try:
        if _admin_pool is not None:
            config = await WebhookRegistry.get_for_receive(_admin_pool, webhook_id)
        else:
            config = await _webhook_registry.get(webhook_id)
    except Exception as exc:
        logger.exception(
            "Webhook lookup DB unavailable",
            extra={
                "event": "webhook.lookup.db_unavailable",
                "webhook_id": webhook_id,
                "error_category": type(exc).__name__,
            },
        )
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "reason": "Webhook lookup store unavailable",
            },
        )
    if config is None or not config.enabled:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "reason": "Webhook not found"},
        )

    # 2. Read raw body for signature verification
    body = await request.body()

    # 3. X-Timestamp REQUIRED (framing defect — 400, not 401)
    timestamp = request.headers.get("X-Timestamp", "")
    if not timestamp:
        logger.warning(
            "X-Timestamp header missing or empty",
            extra={
                "event": "webhook.signature.timestamp_missing",
                "webhook_id": webhook_id,
            },
        )
        return JSONResponse(
            status_code=400,
            content={"status": "error", "reason": "X-Timestamp header required"},
        )
    logger.debug(
        "receive_webhook: not_timestamp_passed",
        extra={
            "event": "api.routes.webhooks.receive_webhook.not_timestamp_passed",
            "reason": "not_timestamp_passed",
        },
    )  # auto:neg

    # 4. Verify HMAC signature (scheme-aware router). The digest
    # returned on success is reused as the replay fingerprint in step 6
    # — byte-identical to what was just verified, no re-compute.
    signature = request.headers.get("X-Signature-256", "")
    signature_valid, scheme, digest = verify_signature(
        body,
        signature,
        config.secret,
        timestamp=timestamp,
        legacy_allowed=settings.webhook_legacy_signature_enabled,
    )
    if not signature_valid:
        if scheme == "sha256" and not settings.webhook_legacy_signature_enabled:
            logger.warning(
                "Legacy sha256= signature rejected (flag disabled)",
                extra={
                    "event": "webhook.signature.legacy_rejected_flag_off",
                    "webhook_id": webhook_id,
                },
            )
        else:
            logger.warning(
                "Webhook signature invalid",
                extra={
                    "event": "webhook.signature.invalid",
                    "webhook_id": webhook_id,
                    "scheme": scheme,
                },
            )
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reason": "Invalid signature"},
        )

    # 5. Verify timestamp freshness (post-signature — 401 if outside
    # tolerance or unparseable; 401 is the right class because the
    # attacker has proven secret knowledge to reach this check).
    if not verify_timestamp(timestamp, config.timestamp_tolerance):
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reason": "Timestamp expired or invalid"},
        )

    # Successful signature verify — emit scheme-specific audit.
    if scheme == "v2":
        logger.debug(
            "v2 signature accepted",
            extra={
                "event": "webhook.signature.v2_accepted",
                "webhook_id": webhook_id,
            },
        )
    elif scheme == "sha256":
        logger.info(
            "Legacy sha256= signature accepted (deprecated)",
            extra={
                "event": "webhook.signature.legacy_accepted",
                "webhook_id": webhook_id,
            },
        )

    # 6. Replay fingerprint — reuse the HMAC digest the verifier just
    # produced (byte-identical to the verified signature). Atomic
    # insert-or-reject via composite PK + ON CONFLICT DO NOTHING. PG
    # unavailable → 503 (never fall back to in-memory in production —
    # that would reintroduce the cross-restart replay window).
    # ``compute_fingerprint`` is an identity helper; naming it at the
    # call site documents the boundary.
    fingerprint = compute_fingerprint(digest)
    try:
        is_duplicate = await check_replay_fingerprint(
            _admin_pool,
            webhook_id,
            fingerprint,
            seen=_replay_seen,
        )
    except Exception as exc:
        logger.exception(
            "Webhook replay fingerprint DB unavailable",
            extra={
                "event": "webhook.replay.db_unavailable",
                "webhook_id": webhook_id,
                "error_category": type(exc).__name__,
            },
        )
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "reason": "Replay-protection store unavailable",
            },
        )
    if is_duplicate:
        logger.warning(
            "Duplicate webhook rejected (replay fingerprint)",
            extra={
                "event": "webhook.replay.duplicate_rejected",
                "webhook_id": webhook_id,
                "fingerprint_prefix": fingerprint[:12],
            },
        )
        return JSONResponse(
            status_code=409,
            content={"status": "error", "reason": "Duplicate request"},
        )

    # Optional idempotency key: kept for producer-side correlation
    # (length logged, value not used as the replay defence).
    idempotency_key = request.headers.get("X-Idempotency-Key", "")
    if idempotency_key:
        logger.debug(
            "X-Idempotency-Key observed (length only)",
            extra={
                "event": "webhook.received",
                "webhook_id": webhook_id,
                "caller_idempotency_key_len": len(idempotency_key),
            },
        )

    # 7. Rate limiting
    if _webhook_rate_limiter is not None and not _webhook_rate_limiter.check(
        webhook_id
    ):
        return JSONResponse(
            status_code=429,
            content={"status": "error", "reason": "Rate limit exceeded"},
        )

    # Parse payload
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        logger.warning(
            "receive_webhook: JSONDecodeError | ValueError",
            extra={"event": "webhooks.receive_webhook_error"},
            exc_info=True,
        )
        payload = {"raw": body.decode("utf-8", errors="replace")}

    # Publish event to bus — routine engine listens for webhook.* events
    await _event_bus.publish(
        f"webhook.{webhook_id}.received",
        {
            "webhook_id": webhook_id,
            "webhook_name": config.name,
            "payload": payload,
        },
    )

    # If payload contains a "prompt" field, route through orchestrator as a task
    task_triggered = False
    if (
        isinstance(payload, dict)
        and payload.get("prompt")
        and _orchestrator is not None
    ):
        # Set user context from the webhook's owner — webhooks carry a user_id foreign key
        # so tasks they trigger run in the correct RLS context, not as a shared user_id=1.
        webhook_user_id = getattr(config, "user_id", 1)
        ctx_token = current_user_id.set(webhook_user_id)
        try:
            router_instance = ChannelRouter(
                _orchestrator,
                _event_bus,
                _audit,
                message_router=_message_router,
                loop_controller=_loop_controller,
                loop_store=_loop_store,
            )
            # Per-invocation identifier: prefer the caller-supplied
            # X-Idempotency-Key when present (so duplicate deliveries share
            # the same session/approval namespace), fall back to a fresh
            # UUID so every invocation gets its own source_key. Binds
            # approval/confirmation state to the invocation, not the
            # webhook endpoint.
            invocation_id = idempotency_key or str(uuid.uuid4())
            source_key = f"webhook:{webhook_id}:{invocation_id}"
            message = IncomingMessage(
                channel_id=f"webhook:{webhook_id}",
                source="webhook",
                content=payload["prompt"],
                metadata={
                    "source_key": source_key,
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
                logger.exception(
                    "receive_webhook: Exception",
                    extra={"event": "webhooks.receive_webhook_error"},
                )
                if _audit is not None:
                    _audit.warning(
                        "Webhook task routing failed",
                        extra={
                            "event": "webhook.task_error",
                            "webhook_id": webhook_id,
                            "error": str(exc),
                        },
                        exc_info=True,
                    )
        finally:
            current_user_id.reset(ctx_token)

    return {"status": "ok", "event_published": True, "task_triggered": task_triggered}
