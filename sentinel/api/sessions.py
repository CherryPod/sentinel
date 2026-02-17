"""JWT session token infrastructure for multi-user auth.

Creates and verifies short-lived session tokens. Secret key is read from
/run/secrets/session_key (Podman secret) with a dev fallback.
"""

from __future__ import annotations

import logging
import os
import time

import jwt

logger = logging.getLogger("sentinel.api.sessions")

SESSION_TTL = 86400  # 24 hours

# Secret key: Podman secret in prod, fallback for dev/tests
_SECRET_PATH = "/run/secrets/session_key"
_DEV_SECRET = "sentinel-dev-session-key-not-for-production"


def _get_secret() -> str:
    """Load session signing secret from Podman secret or fall back to dev key."""
    if os.path.exists(_SECRET_PATH):
        with open(_SECRET_PATH) as f:
            return f.read().strip()
    logger.warning(
        "Session secret not found at %s — using dev fallback (NOT for production)",
        _SECRET_PATH,
    )
    return _DEV_SECRET


# Cache the secret at module load so we don't re-read on every request
_cached_secret: str | None = None


def get_secret() -> str:
    """Return the cached session secret, loading on first call."""
    global _cached_secret
    if _cached_secret is None:
        _cached_secret = _get_secret()
    return _cached_secret


def create_session_token(user_id: int, role: str = "user") -> str:
    """Create a signed JWT session token.

    Payload includes user_id, role, issued-at, and expiry (24h).
    """
    now = int(time.time())
    payload = {
        "user_id": user_id,
        "role": role,
        "iat": now,
        "exp": now + SESSION_TTL,
    }
    return jwt.encode(payload, get_secret(), algorithm="HS256")


def verify_session_token(token: str) -> dict:
    """Verify and decode a JWT session token.

    Returns the decoded payload dict. Raises jwt.ExpiredSignatureError or
    jwt.InvalidTokenError on failure.
    """
    return jwt.decode(token, get_secret(), algorithms=["HS256"])
