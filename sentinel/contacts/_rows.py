"""Shared utilities and constants for contact store mixins."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sentinel.core.context import require_user_id

logger = logging.getLogger(__name__)


def _resolve_user_id(user_id: int | None) -> int:
    """Resolve user_id from explicit param or ContextVar. Raises on zero (Q4)."""
    return require_user_id(user_id, "contacts._resolve_user_id")


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── Updatable field whitelists ────────────────────────────────────

USER_UPDATABLE = {
    "display_name",
    "pin_hash",
    "is_active",
    "role",
    "trust_level",
    "sessions_invalidated_at",
    "must_change_pin",
}
CONTACT_UPDATABLE = {"display_name", "linked_user_id", "is_user"}
CHANNEL_UPDATABLE = {"channel", "identifier", "is_default"}
