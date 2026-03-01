"""Inbound webhook channel — receives HTTP push events from external services.

Provides HMAC-SHA256 signature verification, timestamp validation, idempotency
dedup, and per-webhook rate limiting. Webhook payloads are treated as UNTRUSTED
external data and routed through the event bus (and optionally the orchestrator).
"""

import hashlib
import hmac
import json
import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.audit")


@dataclass
class WebhookConfig:
    """Configuration for a registered webhook."""
    webhook_id: str
    name: str
    secret: str
    enabled: bool = True
    user_id: str = "default"
    created_at: str = ""
    rate_limit: int = 30  # max requests per minute
    timestamp_tolerance: int = 300  # max age in seconds (5 min)


class WebhookRegistry:
    """Manages registered webhooks — SQLite-backed with in-memory fallback."""

    def __init__(self, db: sqlite3.Connection | None = None):
        self._db = db
        self._mem: dict[str, WebhookConfig] = {}

    def register(
        self,
        name: str,
        secret: str,
        user_id: str = "default",
    ) -> WebhookConfig:
        """Register a new webhook. Returns the created WebhookConfig."""
        webhook_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        config = WebhookConfig(
            webhook_id=webhook_id,
            name=name,
            secret=secret,
            user_id=user_id,
            created_at=now,
        )

        if self._db is not None:
            self._db.execute(
                """INSERT INTO webhooks (webhook_id, name, secret, enabled, user_id, created_at)
                   VALUES (?, ?, ?, 1, ?, ?)""",
                (webhook_id, name, secret, user_id, now),
            )
            self._db.commit()
        else:
            self._mem[webhook_id] = config

        logger.info(
            "Webhook registered",
            extra={
                "event": "webhook_registered",
                "webhook_id": webhook_id,
                "name": name,
            },
        )
        return config

    def get(self, webhook_id: str) -> WebhookConfig | None:
        """Look up a webhook by ID."""
        if self._db is not None:
            row = self._db.execute(
                "SELECT webhook_id, name, secret, enabled, user_id, created_at "
                "FROM webhooks WHERE webhook_id = ?",
                (webhook_id,),
            ).fetchone()
            if row is None:
                return None
            return WebhookConfig(
                webhook_id=row[0],
                name=row[1],
                secret=row[2],
                enabled=bool(row[3]),
                user_id=row[4],
                created_at=row[5] or "",
            )
        return self._mem.get(webhook_id)

    def delete(self, webhook_id: str) -> bool:
        """Delete a webhook. Returns True if it existed."""
        if self._db is not None:
            cursor = self._db.execute(
                "DELETE FROM webhooks WHERE webhook_id = ?",
                (webhook_id,),
            )
            self._db.commit()
            return cursor.rowcount > 0
        return self._mem.pop(webhook_id, None) is not None

    def list(self, user_id: str | None = None) -> list[WebhookConfig]:
        """List all webhooks, optionally filtered by user.

        L-002: HMAC secrets are redacted in list results to prevent leaking
        via the API. Use get() for full config when verification is needed.
        """
        if self._db is not None:
            if user_id:
                rows = self._db.execute(
                    "SELECT webhook_id, name, secret, enabled, user_id, created_at "
                    "FROM webhooks WHERE user_id = ? ORDER BY created_at DESC",
                    (user_id,),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT webhook_id, name, secret, enabled, user_id, created_at "
                    "FROM webhooks ORDER BY created_at DESC",
                ).fetchall()
            return [
                WebhookConfig(
                    webhook_id=r[0], name=r[1], secret="***",
                    enabled=bool(r[3]), user_id=r[4], created_at=r[5] or "",
                )
                for r in rows
            ]
        configs = []
        source = list(self._mem.values())
        if user_id:
            source = [c for c in source if c.user_id == user_id]
        for c in source:
            redacted = WebhookConfig(
                webhook_id=c.webhook_id, name=c.name, secret="***",
                enabled=c.enabled, user_id=c.user_id, created_at=c.created_at,
            )
            configs.append(redacted)
        return configs


# ── Verification helpers ──────────────────────────────────────────


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature. Signature format: 'sha256=<hex>'.

    Uses hmac.compare_digest for timing-safe comparison.
    """
    if not signature.startswith("sha256="):
        return False

    expected_sig = signature[7:]  # strip 'sha256=' prefix
    computed = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(computed, expected_sig)


def verify_timestamp(timestamp_str: str, tolerance: int = 300) -> bool:
    """Verify timestamp is within tolerance seconds of current time.

    Accepts ISO 8601 format. Returns False if timestamp is too old or
    cannot be parsed.
    """
    try:
        ts = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        now = datetime.now(timezone.utc)
        age = abs((now - dt).total_seconds())
        return age <= tolerance
    except (ValueError, TypeError):
        return False


def check_idempotency(nonce: str, seen: dict, ttl: int = 300) -> bool:
    """Check if a nonce has been seen before within the TTL window.

    Returns True if the nonce is a DUPLICATE (already seen).
    Returns False if the nonce is NEW (not seen before).

    Side effect: adds nonce to seen dict if new, cleans expired entries.
    """
    now = time.monotonic()

    # Clean expired entries periodically (every check is fine for low volume)
    expired = [k for k, v in seen.items() if now - v > ttl]
    for k in expired:
        del seen[k]

    if nonce in seen:
        return True  # duplicate

    seen[nonce] = now
    return False  # new


class RateLimiter:
    """Sliding-window rate limiter per webhook ID."""

    def __init__(self, max_per_minute: int = 30):
        self._max = max_per_minute
        self._windows: dict[str, list[float]] = {}

    def check(self, webhook_id: str) -> bool:
        """Returns True if the request is ALLOWED, False if rate-limited."""
        now = time.monotonic()
        window = self._windows.setdefault(webhook_id, [])

        # Remove entries older than 60 seconds
        cutoff = now - 60.0
        self._windows[webhook_id] = [t for t in window if t > cutoff]
        window = self._windows[webhook_id]

        if len(window) >= self._max:
            return False

        window.append(now)
        return True
