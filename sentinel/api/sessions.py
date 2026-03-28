"""JWT session token infrastructure for multi-user auth.

Creates and verifies short-lived session tokens. Secret key is read from
/run/secrets/session_key (Podman secret) with a dev fallback.

Fail-closed mode: if SENTINEL_REQUIRE_SECRETS=true and the secret file is
missing, a RuntimeError is raised instead of using the dev fallback. This
prevents silent insecurity in production deployments.
"""

from __future__ import annotations

import logging
import os
import time
import uuid

import jwt

logger = logging.getLogger("sentinel.api.sessions")

SESSION_TTL = 3600  # 1 hour

# Secret key: Podman secret in prod, fallback for dev/tests
_SECRET_PATH = "/run/secrets/session_key"
_DEV_SECRET = "sentinel-dev-session-key-not-for-production"


def _get_secret() -> str:
    """Load session signing secret from Podman secret or fall back to dev key.

    If SENTINEL_REQUIRE_SECRETS is set to a truthy value and the secret file
    is missing, raises RuntimeError (fail-closed). This prevents silent use of
    the weak dev key in production.
    """
    if os.path.exists(_SECRET_PATH):
        with open(_SECRET_PATH) as f:
            return f.read().strip()

    # Check whether we must fail-closed on a missing secret
    require_secrets = os.environ.get("SENTINEL_REQUIRE_SECRETS", "").lower()
    if require_secrets in ("1", "true", "yes"):
        raise RuntimeError(
            f"SENTINEL_REQUIRE_SECRETS is set but secret file {_SECRET_PATH!r} "
            "is missing — refusing to fall back to dev key"
        )

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

    Payload includes user_id, role, a unique jti (for revocation targeting),
    issued-at, and expiry (1h). Each call generates a fresh jti so tokens
    can be individually revoked without invalidating all sessions.
    """
    now = int(time.time())
    payload = {
        "user_id": user_id,
        "role": role,
        "jti": str(uuid.uuid4()),
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
