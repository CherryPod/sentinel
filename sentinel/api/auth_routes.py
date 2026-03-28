"""Auth endpoints — login, logout, session revocation.

Exempt from PinAuthMiddleware (these ARE the auth layer).
"""

from __future__ import annotations

import hmac
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from starlette.responses import JSONResponse

from sentinel.api.rate_limit import limiter

from sentinel.api.auth import PinVerifier
from sentinel.api.role_guard import require_role
from sentinel.api.sessions import create_session_token
from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.api.auth_routes")

router = APIRouter(prefix="/api/auth")


# ── Store accessor (set during lifespan) ──────────────────────────

_contact_store: Any = None
_admin_pool: Any = None


def init_auth_store(contact_store: Any, admin_pool: Any = None) -> None:
    """Called from app lifespan to inject store reference and admin pool.

    The admin_pool bypasses RLS and is needed for login (which runs
    before any user context is set, so RLS returns zero rows).
    """
    global _contact_store, _admin_pool
    _contact_store = contact_store
    _admin_pool = admin_pool


def _get_store():
    if _contact_store is None:
        raise HTTPException(status_code=503, detail="Auth store not available")
    return _contact_store


# ── Request/Response models ───────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    pin: str


class PinChangeRequest(BaseModel):
    current_pin: str
    new_pin: str


class LoginResponse(BaseModel):
    token: str
    user_id: int
    role: str
    display_name: str


# ── Login endpoint ────────────────────────────────────────────────


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, req: LoginRequest):
    """Authenticate with username + PIN, returns a JWT session token.

    Looks up user by display_name (case-insensitive), verifies PIN,
    checks active status and role, then issues a session token.
    """
    store = _get_store()

    # Look up user by display_name — must use admin_pool to bypass RLS
    # because the login endpoint runs before any user context is set
    # (current_user_id=0 → RLS returns zero rows).
    if _admin_pool is not None:
        async with _admin_pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM users ORDER BY user_id")
        from sentinel.contacts.store import _user_from_row
        users = [_user_from_row(r) for r in rows]
    else:
        # Fallback for tests (in-memory store, no RLS)
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
        logger.warning("Login attempt for deactivated account: %s", req.username)
        raise HTTPException(status_code=401, detail="Invalid username or PIN")

    # Check role (pending users can't log in)
    role = user.get("role", "user")
    if role == "pending":
        logger.warning("Login attempt for pending account: %s", req.username)
        raise HTTPException(status_code=401, detail="Invalid username or PIN")

    # Verify PIN
    pin_hash = user.get("pin_hash")
    if not pin_hash:
        logger.warning("Login attempt for account with no PIN: %s", req.username)
        raise HTTPException(status_code=401, detail="Invalid username or PIN")

    try:
        verifier = PinVerifier.from_stored(pin_hash)
    except (ValueError, IndexError):
        # Legacy plaintext fallback — use constant-time comparison
        if not hmac.compare_digest(pin_hash.encode(), req.pin.encode()):
            raise HTTPException(status_code=401, detail="Invalid username or PIN")
        logger.warning(
            "Legacy plaintext PIN comparison for user_id=%d — migrate to PBKDF2",
            user.get("user_id", 0),
            extra={"event": "legacy_pin_comparison"},
        )
    else:
        if not verifier.verify(req.pin):
            raise HTTPException(status_code=401, detail="Invalid username or PIN")

    # Check sessions_invalidated_at
    invalidated_at = user.get("sessions_invalidated_at")
    # (Only relevant for existing tokens — new tokens are always valid)

    # Issue token
    token = create_session_token(user["user_id"], role=role)

    logger.info(
        "Login success for user_id=%d (%s) from %s",
        user["user_id"], user["display_name"], request.client.host,
        extra={"event": "login_success", "user_id": user["user_id"]},
    )

    return LoginResponse(
        token=token,
        user_id=user["user_id"],
        role=role,
        display_name=user["display_name"],
    )


# ── Logout ────────────────────────────────────────────────────────


@router.post("/logout")
async def logout(request: Request):
    """Revoke the calling user's current token."""
    from sentinel.api.sessions import verify_session_token
    from sentinel.api.revocation import get_revocation_set

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token provided")

    raw_token = auth_header[7:]
    try:
        payload = verify_session_token(raw_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    jti = payload.get("jti")
    if jti:
        get_revocation_set().revoke(jti)

    uid = payload.get("user_id", 0)
    logger.info("User logged out", extra={"event": "logout", "user_id": uid})

    return {"status": "ok", "message": "Logged out successfully"}


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


# ── PIN change ────────────────────────────────────────────────────


@router.post("/change-pin")
async def change_pin(req: PinChangeRequest):
    """Change the current user's PIN. Requires valid current PIN.

    Verifying the current PIN guards against stolen-token attacks — an
    attacker holding a session token cannot silently re-key the account
    without also knowing the original PIN. Clears must_change_pin on
    success so forced-reset flows complete correctly.
    """
    store = _get_store()
    user_id = current_user_id.get()

    # Middleware should have already rejected user_id == 0, but we check
    # here too so the endpoint is safe if called from an exempt path.
    if user_id == 0:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    user = await store.get_user(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})

    # Verify the current PIN before allowing a change
    stored_hash = user.get("pin_hash", "")
    if not stored_hash:
        return JSONResponse(status_code=400, content={"error": "No PIN set"})

    try:
        verifier = PinVerifier.from_stored(stored_hash)
        current_ok = verifier.verify(req.current_pin)
    except (ValueError, IndexError):
        # Legacy plaintext PIN — constant-time comparison as migration fallback
        current_ok = hmac.compare_digest(req.current_pin.encode(), stored_hash.encode())

    if not current_ok:
        return JSONResponse(status_code=403, content={"error": "Current PIN is incorrect"})

    # Hash the new PIN and persist it; clear the forced-reset flag in one update
    new_hash = PinVerifier(req.new_pin).to_stored()
    await store.update_user(user_id, pin_hash=new_hash, must_change_pin=False)

    logger.info("PIN changed for user_id=%d", user_id)
    return {"status": "ok", "message": "PIN changed successfully"}


# ── Profile (current user) ────────────────────────────────────────


@router.get("/me")
async def get_profile():
    """Return the current user's profile (role, trust level, must_change_pin).

    Uses the user_id from the JWT (set by middleware). Strips pin_hash
    before returning — the client only needs display fields.
    """
    store = _get_store()
    user_id = current_user_id.get()

    if user_id == 0:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    user = await store.get_user(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})

    return {
        "user_id": user["user_id"],
        "display_name": user["display_name"],
        "role": user.get("role", "user"),
        "trust_level": user.get("trust_level"),
        "must_change_pin": user.get("must_change_pin", False),
        "is_active": user["is_active"],
        "created_at": user["created_at"],
    }
