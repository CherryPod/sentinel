"""Inbound webhook channel — receives HTTP push events from external services.

Provides HMAC-SHA256 signature verification, timestamp validation, idempotency
dedup, and per-webhook rate limiting. Webhook payloads are treated as UNTRUSTED
external data and routed through the event bus (and optionally the orchestrator).

PostgreSQL-backed via asyncpg.  When pool=None, falls back to an in-memory
dict for tests.

Q13.fix.e — signature format migration (F3):
  Signatures now ship as ``v2=<hex>`` with HMAC input
  ``f"{timestamp}.".encode() + body`` (Slack/Stripe pattern). The legacy
  ``sha256=<hex>`` format (body-only HMAC) continues to verify while
  ``settings.webhook_legacy_signature_enabled`` is True, providing a
  backward-compatible migration path for existing producers.

  **Signing byte-exactness contract (producer-authoritative):** the
  ``X-Timestamp`` header value is fed to HMAC as the exact bytes the
  producer sends. No canonicalisation is performed on the verifier side.
  Producers must sign the timestamp header bytes verbatim — any
  round-trip through ``datetime.fromisoformat`` + re-formatting breaks
  the signature. Equivalent to Stripe's opaque-timestamp contract.

  Replay protection uses a server-computed fingerprint (the HMAC hex
  digest itself — already fixed-length and collision-resistant over the
  signed input) persisted in the ``webhook_replay_fingerprints`` table
  with composite PK ``(webhook_id, fingerprint)``. Full protection for
  v2 signatures; best-effort short-window dedup only for legacy (the
  body-only signature re-verifies under any fresh ``X-Timestamp``, so a
  post-sweep replay is admitted).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from sentinel.core.context import require_user_id

logger = logging.getLogger(__name__)

_RATE_WINDOW_SECONDS = 60.0


@dataclass
class WebhookConfig:
    """Configuration for a registered webhook."""

    webhook_id: str
    name: str
    secret: str
    enabled: bool = True
    # Q4: sentinel default; producer (register) enforces non-zero via
    # require_user_id. Reading from Postgres always populates user_id
    # (NOT NULL column).
    user_id: int = 0
    created_at: str = ""
    rate_limit: int = 30  # max requests per minute
    timestamp_tolerance: int = 300  # max age in seconds (5 min)


def _dt_to_iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class WebhookRegistry:
    """Manages registered webhooks — PostgreSQL-backed with in-memory fallback."""

    def __init__(self, pool: Any = None):
        self._pool = pool
        self._mem: dict[str, WebhookConfig] = {}

    async def register(
        self,
        name: str,
        secret: str,
        user_id: int | None = None,
    ) -> WebhookConfig:
        """Register a new webhook. Returns the created WebhookConfig."""
        user_id = require_user_id(user_id, "WebhookRegistry.register")
        webhook_id = str(uuid.uuid4())

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO webhooks (webhook_id, name, secret, enabled, user_id, created_at) "
                    "VALUES ($1, $2, $3, TRUE, $4, NOW()) "
                    "RETURNING created_at",
                    webhook_id,
                    name,
                    secret,
                    user_id,
                )

            config = WebhookConfig(
                webhook_id=webhook_id,
                name=name,
                secret=secret,
                user_id=user_id,
                created_at=_dt_to_iso(row["created_at"]) if row else "",
            )
        else:
            now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            config = WebhookConfig(
                webhook_id=webhook_id,
                name=name,
                secret=secret,
                user_id=user_id,
                created_at=now,
            )
            self._mem[webhook_id] = config

        logger.info(
            "Webhook registered",
            extra={
                "event": "webhook.registered",
                "webhook_id": webhook_id,
                "webhook_name": name,
            },
        )
        return config

    async def get(self, webhook_id: str) -> WebhookConfig | None:
        """Look up a webhook by ID (RLS-scoped to current_user_id)."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT webhook_id, name, secret, enabled, user_id, created_at "
                    "FROM webhooks WHERE webhook_id = $1",
                    webhook_id,
                )
                if row is None:
                    return None
                return WebhookConfig(
                    webhook_id=row["webhook_id"],
                    name=row["name"],
                    secret=row["secret"],
                    enabled=row["enabled"],
                    user_id=row["user_id"],
                    created_at=_dt_to_iso(row["created_at"]),
                )
        return self._mem.get(webhook_id)

    @staticmethod
    async def get_for_receive(admin_pool: Any, webhook_id: str) -> WebhookConfig | None:
        """Look up a webhook by ID using the admin (owner) pool.

        Q13.fix.e (CR-Cx-2): the webhook receive endpoint is auth-exempt
        (``/api/webhook/*`` in ``middleware._EXEMPT_PREFIXES``), so
        ``current_user_id.get()`` remains the context default ``0`` when
        a signed request arrives. The ``webhooks`` table has FORCE ROW
        LEVEL SECURITY with the user_isolation policy, so the standard
        RLS-wrapped pool would silently match zero rows for every
        receive. We therefore use the owner pool (``owner_full_access``
        policy) for receive-path lookups, which is semantically correct
        — webhook auth is the HMAC check, not the user-session RLS.

        ``admin_pool`` is the asyncpg pool directly (NOT the
        ``RLSPool`` wrapper). Must be None only in tests, where the
        in-memory fallback registry is used directly via ``get``.
        """
        async with admin_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT webhook_id, name, secret, enabled, user_id, created_at "
                "FROM webhooks WHERE webhook_id = $1",
                webhook_id,
            )
            if row is None:
                return None
            return WebhookConfig(
                webhook_id=row["webhook_id"],
                name=row["name"],
                secret=row["secret"],
                enabled=row["enabled"],
                user_id=row["user_id"],
                created_at=_dt_to_iso(row["created_at"]),
            )

    async def delete(self, webhook_id: str) -> bool:
        """Delete a webhook. Returns True if it existed."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM webhooks WHERE webhook_id = $1",
                    webhook_id,
                )
                return result == "DELETE 1"
        return self._mem.pop(webhook_id, None) is not None

    async def list(self, user_id: int | None = None) -> list[WebhookConfig]:
        """List all webhooks, optionally filtered by user.

        L-002: HMAC secrets are redacted in list results to prevent leaking
        via the API. Use get() for full config when verification is needed.
        """
        logger.debug("list called", extra={"event": "webhook.list", "user_id": user_id})
        if self._pool is not None:
            logger.debug("list: pg path", extra={"event": "webhook.list.pg"})
            async with self._pool.acquire() as conn:
                if user_id:
                    logger.debug(
                        "list: pg filtered by user",
                        extra={"event": "webhook.list.pg_user_filter"},
                    )
                    rows = await conn.fetch(
                        "SELECT webhook_id, name, secret, enabled, user_id, created_at "
                        "FROM webhooks WHERE user_id = $1 ORDER BY created_at DESC",
                        user_id,
                    )
                else:
                    logger.debug(
                        "list: pg unfiltered", extra={"event": "webhook.list.pg_all"}
                    )
                    rows = await conn.fetch(
                        "SELECT webhook_id, name, secret, enabled, user_id, created_at "
                        "FROM webhooks ORDER BY created_at DESC",
                    )
                # L-002: Redact secrets in list results
                return [
                    WebhookConfig(
                        webhook_id=r["webhook_id"],
                        name=r["name"],
                        secret="***",
                        enabled=r["enabled"],
                        user_id=r["user_id"],
                        created_at=_dt_to_iso(r["created_at"]),
                    )
                    for r in rows
                ]

        configs = []
        source = list(self._mem.values())
        if user_id:
            logger.debug(
                "list: mem filtered by user",
                extra={"event": "webhook.list.mem_user_filter"},
            )
            source = [c for c in source if c.user_id == user_id]
        for c in source:
            redacted = WebhookConfig(
                webhook_id=c.webhook_id,
                name=c.name,
                secret="***",
                enabled=c.enabled,
                user_id=c.user_id,
                created_at=c.created_at,
            )
            configs.append(redacted)
        return configs


# ── Verification helpers ──────────────────────────────────────────


def _compute_v2_hmac(timestamp: str, body: bytes, secret: str) -> str:
    """HMAC-SHA256 over ``f"{timestamp}.".encode() + body``.

    Timestamp is signed as opaque bytes — the producer is authoritative for
    the exact string used (no canonicalisation).
    """
    signed_bytes = timestamp.encode("utf-8") + b"." + body
    return hmac.new(
        secret.encode("utf-8"),
        signed_bytes,
        hashlib.sha256,
    ).hexdigest()


def _compute_legacy_hmac(body: bytes, secret: str) -> str:
    """HMAC-SHA256 over ``body`` only (legacy, deprecated)."""
    return hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(
    payload: bytes,
    signature: str,
    secret: str,
    *,
    timestamp: str = "",
    legacy_allowed: bool = True,
) -> tuple[bool, str, str]:
    """Scheme-aware signature verification router.

    Recognises ``v2=<hex>`` (Q13.fix.e — HMAC over ``timestamp + '.' + body``)
    and the legacy ``sha256=<hex>`` (HMAC over body only).

    Legacy acceptance is gated on ``legacy_allowed`` so the caller can
    drive migration via ``settings.webhook_legacy_signature_enabled``.

    Returns ``(is_valid, scheme, digest)`` where:
      * ``scheme`` is ``"v2"``, ``"sha256"``, or ``"unknown"``
        (never-matched prefix).
      * ``digest`` is the freshly-computed HMAC hex digest the verifier
        produced, or ``""`` for the unknown-scheme / legacy-rejected /
        v2-without-timestamp reject paths. The caller can store the
        digest directly as the replay fingerprint without re-computing
        (cheaper + guarantees byte-identity with what was just
        verified).

    Uses ``hmac.compare_digest`` for timing-safe comparison on both
    branches.
    """
    if signature.startswith("v2="):
        expected_sig = signature[3:]  # strip 'v2=' prefix
        if not timestamp:
            # v2 requires timestamp in the signed input — caller must enforce
            # X-Timestamp presence before invoking (we reject here defensively
            # rather than trusting an empty string).
            return (False, "v2", "")
        computed = _compute_v2_hmac(timestamp, payload, secret)
        return (hmac.compare_digest(computed, expected_sig), "v2", computed)

    if signature.startswith("sha256="):
        if not legacy_allowed:
            return (False, "sha256", "")
        expected_sig = signature[7:]  # strip 'sha256=' prefix
        computed = _compute_legacy_hmac(payload, secret)
        return (hmac.compare_digest(computed, expected_sig), "sha256", computed)

    return (False, "unknown", "")


def compute_fingerprint(signature_hex: str) -> str:
    """Replay-protection fingerprint for a verified HMAC signature.

    Identity helper — the HMAC hex digest itself is already fixed-length
    (64 chars) and collision-resistant over the signed input, so a second
    hash would be redundant. Named for call-site clarity at the persistence
    boundary; storing the signature directly gives a forensic audit-trail
    link (log line → replay table lookup without re-compute).
    """
    return signature_hex


def verify_timestamp(timestamp_str: str, tolerance: int = 300) -> bool:
    """Verify timestamp is within tolerance seconds of current time.

    Accepts ISO 8601 format. Returns False if timestamp is too old or
    cannot be parsed.
    """
    try:
        ts = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        now = datetime.now(UTC)
        age = abs((now - dt).total_seconds())
        return age <= tolerance
    except (ValueError, TypeError):
        logger.debug(
            "verify_timestamp: unparseable timestamp",
            extra={
                "event": "webhook.verify_timestamp_error",
                "timestamp_len": len(timestamp_str) if timestamp_str else 0,
            },
        )
        return False


_IDEMPOTENCY_MAX_SIZE = 10_000  # BH3-014: cap to prevent unbounded growth


async def check_replay_fingerprint(
    admin_pool: Any,
    webhook_id: str,
    fingerprint: str,
    *,
    seen: dict | None = None,
    ttl: int = 600,
) -> bool:
    """Atomic replay-fingerprint check for inbound webhook.

    Q13.fix.e (F3). The fingerprint is a server-computed HMAC hex digest
    over signed input (see ``compute_fingerprint``). Attempts to persist
    ``(webhook_id, fingerprint)`` in the ``webhook_replay_fingerprints``
    table via ``INSERT ... ON CONFLICT DO NOTHING``. Returns ``True`` if
    the fingerprint was already present (duplicate) and ``False`` if
    this is the first time we have seen it.

    **Production path:** ``admin_pool`` MUST be non-None. Uses the
    sentinel_owner role (``owner_full_access`` policy) because the
    replay table is NOT under RLS — webhook receive is auth-exempt and
    has no user context to scope by.

    **Test path:** when ``admin_pool is None``, falls back to the
    in-memory ``seen`` dict with the same semantics. The caller is
    responsible for passing a process-lifetime dict. This branch is
    NOT reached in production — the receive route fails startup if
    ``admin_pool`` is None (see ``api.init.channels``).

    Composite PK ``(webhook_id, fingerprint)``: webhooks sharing a
    secret do not collide on their first legitimate deliveries
    (CR-Cx-1). Conflict target matches the PK columns.
    """
    if admin_pool is None:
        # Test-mode fallback — in-memory TTL dict capped at
        # _IDEMPOTENCY_MAX_SIZE (BH3-014); oldest entry evicted at capacity.
        if seen is None:
            seen = {}
        key = f"{webhook_id}:{fingerprint}"
        now = time.monotonic()
        expired = [k for k, v in seen.items() if now - v > ttl]
        for k in expired:
            del seen[k]
        if key in seen:
            return True  # duplicate
        while len(seen) >= _IDEMPOTENCY_MAX_SIZE:
            oldest_key = min(seen, key=seen.get)  # type: ignore[arg-type]
            del seen[oldest_key]
        seen[key] = now
        return False  # new

    async with admin_pool.acquire() as conn:
        # INSERT ... ON CONFLICT DO NOTHING RETURNING — atomic insert-or-reject.
        # Rows returned iff the insert actually happened (first-time
        # fingerprint). Empty result ⇒ PK collision ⇒ duplicate.
        row = await conn.fetchrow(
            "INSERT INTO webhook_replay_fingerprints (webhook_id, fingerprint) "
            "VALUES ($1, $2) "
            "ON CONFLICT (webhook_id, fingerprint) DO NOTHING "
            "RETURNING fingerprint",
            webhook_id,
            fingerprint,
        )
    return row is None  # True = duplicate, False = new


class RateLimiter:
    """Sliding-window rate limiter per webhook ID."""

    def __init__(self, max_per_minute: int = 30):
        self._max = max_per_minute
        self._windows: dict[str, list[float]] = {}

    def check(self, webhook_id: str) -> bool:
        """Returns True if the request is ALLOWED, False if rate-limited."""
        logger.debug(
            "check called", extra={"event": "webhook.check", "webhook_id": webhook_id}
        )
        now = time.monotonic()
        window = self._windows.setdefault(webhook_id, [])

        # Remove entries older than the rate window
        cutoff = now - _RATE_WINDOW_SECONDS
        self._windows[webhook_id] = [t for t in window if t > cutoff]
        window = self._windows[webhook_id]

        if len(window) >= self._max:
            logger.warning(
                "Webhook rate-limit exceeded",
                extra={
                    "event": "webhook.rate_limited",
                    "webhook_id": webhook_id,
                    "window_size": len(window),
                    "max_allowed": self._max,
                },
            )
            return False

        window.append(now)
        logger.debug(
            "Webhook rate-limit check passed",
            extra={
                "event": "webhook.rate_limit_passed",
                "webhook_id": webhook_id,
                "window_size": len(window),
                "max_allowed": self._max,
            },
        )
        return True


if TYPE_CHECKING:
    from sentinel.core.store_protocols import WebhookRegistryProtocol

    _: WebhookRegistryProtocol = cast("WebhookRegistryProtocol", WebhookRegistry())
