"""Auth endpoints — login, logout, session revocation.

Exempt from PinAuthMiddleware (these ARE the auth layer).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.api.auth import PinVerifier
from sentinel.api.role_guard import require_role
from sentinel.api.sessions import create_session_token
from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.api.auth_routes")

router = APIRouter(prefix="/api/auth")


# ── Store accessor (set during lifespan) ──────────────────────────

_contact_store: Any = None


def init_auth_store(contact_store: Any) -> None:
    """Called from app lifespan to inject store reference."""
    global _contact_store
    _contact_store = contact_store


def _get_store():
    if _contact_store is None:
        raise HTTPException(status_code=503, detail="Auth store not available")
    return _contact_store


# ── Request/Response models ───────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    pin: str


class LoginResponse(BaseModel):
    token: str
    user_id: int
    role: str
    display_name: str


# ── Login endpoint ────────────────────────────────────────────────


@router.post("/login")
async def login(req: LoginRequest):
    """Authenticate with username + PIN, returns a JWT session token.

    Looks up user by display_name (case-insensitive), verifies PIN,
    checks active status and role, then issues a session token.
    """
    store = _get_store()

    # Look up user by display_name — need to scan since we don't have
    # a by-name lookup. Use admin-style list (all users).
    users = await store.list_users(active_only=False)
    user = None
    for u in users:
        if u["display_name"].lower() == req.username.lower():
            user = u
            break

    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or PIN")

    # Check active
    if not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="Account is deactivated")

    # Check role (pending users can't log in)
    role = user.get("role", "user")
    if role == "pending":
        raise HTTPException(status_code=401, detail="Account is pending approval")

    # Verify PIN
    pin_hash = user.get("pin_hash")
    if not pin_hash:
        raise HTTPException(status_code=401, detail="No PIN configured for this account")

    try:
        verifier = PinVerifier.from_stored(pin_hash)
    except (ValueError, IndexError):
        # pin_hash is not in stored format — might be legacy plaintext
        # Try direct comparison as fallback for migration period
        if pin_hash != req.pin:
            raise HTTPException(status_code=401, detail="Invalid username or PIN")
    else:
        if not verifier.verify(req.pin):
            raise HTTPException(status_code=401, detail="Invalid username or PIN")

    # Check sessions_invalidated_at
    invalidated_at = user.get("sessions_invalidated_at")
    # (Only relevant for existing tokens — new tokens are always valid)

    # Issue token
    token = create_session_token(user["user_id"], role=role)

    return LoginResponse(
        token=token,
        user_id=user["user_id"],
        role=role,
        display_name=user["display_name"],
    )


# ── Session revocation ────────────────────────────────────────────


@router.post("/revoke-sessions/{user_id}")
async def revoke_sessions(user_id: int):
    """Invalidate all session tokens for a user. Requires admin role.

    Sets sessions_invalidated_at to now — tokens issued before this
    timestamp will be rejected by the middleware.
    """
    store = _get_store()
    await require_role("admin", store)

    now = datetime.now(timezone.utc)
    result = await store.update_user(
        user_id, sessions_invalidated_at=now,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")

    return {"status": "sessions_revoked", "user_id": user_id}
