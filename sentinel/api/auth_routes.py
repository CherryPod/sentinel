"""Auth endpoints — login, logout, session revocation."""

from __future__ import annotations

import hmac
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse

from sentinel.api.auth import PinVerifier, create_failure_tracker
from sentinel.api.rate_limit import limiter
from sentinel.api.role_guard import require_role
from sentinel.api.sessions import SESSION_TTL, create_session_token
from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.context import current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth")


# ── Store accessor (set during lifespan) ──────────────────────────

_contact_store: Any = None
_admin_pool: Any = None
_audit_emitter: Any = None


def init_auth_store(
    contact_store: Any,
    admin_pool: Any = None,
    audit_emitter: Any = None,
) -> None:
    """Called from app lifespan to inject store reference and admin pool.

    The admin_pool bypasses RLS and is needed for login (which runs
    before any user context is set, so RLS returns zero rows).
    """
    global _contact_store, _admin_pool, _audit_emitter
    _contact_store = contact_store
    _admin_pool = admin_pool
    _audit_emitter = audit_emitter


def _get_audit_emitter(request: Request | None = None) -> Any | None:
    """Get the audit emitter from module state or request.app.state."""
    if _audit_emitter is not None:
        return _audit_emitter
    if request is not None:
        return getattr(request.app.state, "audit_emitter", None)
    return None


def _get_store():
    if _contact_store is None:
        raise HTTPException(status_code=503, detail="Auth store not available")
    return _contact_store


# ── Failure tracker (per-IP brute-force lockout) ─────────────────

_failure_tracker = create_failure_tracker()


def _hash_ip(ip: str) -> str:
    """One-way hash of IP for safe logging (no raw PII in logs)."""
    import hashlib

    return hashlib.sha256(ip.encode()).hexdigest()[:12]


async def _login_fail(
    request: Request,
    client_ip: str,
    fail_reason: str,
    log_event: str,
    log_message: str,
    user_id: int | None = None,
) -> None:
    """Record a login failure, emit audit event, and raise 401.

    Centralises the failure path shared by user-not-found, deactivated,
    pending, no-PIN, and wrong-PIN cases.

    Q6.fix.a — callers that have the authenticating account resolved
    (deactivated, pending, no-PIN, wrong-PIN) pass `user_id` so the audit
    event is attributed to that user's pool. `user_not_found` passes no
    `user_id` because no principal has been resolved (legitimate
    admin-pool emit).
    """
    fail_count = _failure_tracker.record_failure(client_ip)
    logger.warning(
        log_message,
        extra={
            "event": log_event,
            "ip_hash": _hash_ip(client_ip),
            "fail_count": fail_count,
        },
    )
    await _emit_auth_event(
        request,
        "auth.login",
        "FAILED",
        severity="MEDIUM",
        details={
            "fail_reason": fail_reason,
            "fail_count": fail_count,
            "ip_hash": _hash_ip(client_ip),
        },
        user_id=user_id,
    )
    raise HTTPException(status_code=401, detail="Invalid username or PIN")


async def _lookup_user_by_name(store: Any, username: str) -> dict | None:
    """Find a user by display_name (case-insensitive).

    Uses admin_pool to bypass RLS (login runs before user context is set),
    falls back to in-memory store for tests.
    """
    if _admin_pool is not None:
        logger.debug(
            "login: using admin pool", extra={"event": "auth_routes.login.admin_pool"}
        )
        async with _admin_pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM users ORDER BY user_id")
        from sentinel.contacts._users import user_from_row

        users = [user_from_row(r) for r in rows]
    else:
        logger.debug(
            "login: using in-memory store",
            extra={"event": "auth_routes.login.memory_store"},
        )
        users = await store.list_users(active_only=False)

    for u in users:
        if u["display_name"].lower() == username.lower():
            logger.debug(
                "login: user found", extra={"event": "auth_routes.login.user_found"}
            )
            return u
    return None


async def _emit_auth_event(
    request: Request | None,
    event_type: str,
    outcome: str,
    severity: str = "INFO",
    details: dict | None = None,
    user_id: int | None = None,
) -> None:
    """Emit a SecurityAuditEvent for auth operations. Fire-and-forget.

    Q6.fix.a — when the authenticating account is resolved (SUCCESS or
    known-account FAILURE), the caller passes `user_id` so the ContextVar
    is pinned for the duration of the emit. `AuditEmitter._build_db_payload`
    reads `current_user_id.get()` at write time and `_select_pool` routes
    `user_id!=0 → app_pool`. The `/api/auth/login` route is exempt from
    `UserContextMiddleware`, so without this explicit pin the emit would
    default to `user_id=0` and silently admin-pool the event.

    Anonymous / principal-not-resolved sites (`user_not_found`, `auth.lockout`)
    pass no `user_id` so the ContextVar remains at the legitimate system
    default (0 → admin pool).
    """
    audit = _get_audit_emitter(request)
    if audit is None:
        return
    if user_id is not None:
        token = current_user_id.set(user_id)
        try:
            await audit.emit(
                SecurityAuditEvent(
                    event_type=event_type,
                    source_component="auth_routes",
                    outcome=outcome,
                    severity=severity,
                    details=details or {},
                )
            )
        finally:
            current_user_id.reset(token)
    else:
        await audit.emit(
            SecurityAuditEvent(
                event_type=event_type,
                source_component="auth_routes",
                outcome=outcome,
                severity=severity,
                details=details or {},
            )
        )


# ── Request/Response models ───────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    pin: str


class PinChangeRequest(BaseModel):
    current_pin: str
    new_pin: str


class LoginResponse(BaseModel):
    user_id: int
    role: str
    display_name: str


# ── Cookie helpers ────────────────────────────────────────────────


def _is_secure_request(request: Request) -> bool:
    """Check if the request arrived over HTTPS (direct or via reverse proxy)."""
    return (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto") == "https"
    )


def _set_session_cookies(response: JSONResponse, token: str, *, secure: bool) -> None:
    """Set the HttpOnly session cookie and the client-readable auth flag."""
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
        max_age=SESSION_TTL,
    )
    # Non-HttpOnly flag so JS can check login status without reading the JWT
    response.set_cookie(
        key="sentinel_auth",
        value="1",
        httponly=False,
        samesite="lax",
        secure=secure,
        path="/",
        max_age=SESSION_TTL,
    )


def _clear_session_cookies(response: JSONResponse) -> None:
    """Clear both session cookies."""
    response.delete_cookie(key="session", path="/")
    response.delete_cookie(key="sentinel_auth", path="/")


# ── Login endpoint ────────────────────────────────────────────────


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, req: LoginRequest) -> JSONResponse:
    """Authenticate with username + PIN, sets HttpOnly session cookie.

    Looks up user by display_name (case-insensitive), verifies PIN,
    checks active status and role, then issues a session cookie.
    """
    store = _get_store()
    client_ip = get_remote_address(request)

    # Check per-IP lockout before doing any work
    if _failure_tracker.is_locked_out(client_ip):
        logger.warning(
            "Login rejected: IP locked out",
            extra={
                "event": "auth_routes.login.locked_out",
                "ip_hash": _hash_ip(client_ip),
            },
        )
        await _emit_auth_event(
            request,
            "auth.lockout",
            "LOCKED",
            severity="HIGH",
            details={
                "ip_hash": _hash_ip(client_ip),
                "lockout_duration_s": _failure_tracker.lockout_seconds,
                "fail_count": _failure_tracker.get_failure_count(client_ip),
            },
        )
        raise HTTPException(status_code=429, detail="Too many failed attempts")

    user = await _lookup_user_by_name(store, req.username)

    if user is None:
        # Timing side-channel defence: run dummy PBKDF2 so user-not-found
        # takes the same wall-clock time as user-found + wrong-PIN.
        PinVerifier.dummy_verify(req.pin)
        await _login_fail(
            request,
            client_ip,
            "user_not_found",
            "auth_routes.login.user_not_found",
            "login: user not found",
        )

    # Check active
    if not user.get("is_active", True):
        await _login_fail(
            request,
            client_ip,
            "account_deactivated",
            "auth_routes.login.deactivated",
            "Login attempt for deactivated account",
            user_id=user["user_id"],
        )

    # Check role (pending users can't log in)
    role = user.get("role", "user")
    if role == "pending":
        await _login_fail(
            request,
            client_ip,
            "account_pending",
            "auth_routes.login.pending",
            "Login attempt for pending account",
            user_id=user["user_id"],
        )

    # Verify PIN
    pin_hash = user.get("pin_hash")
    if not pin_hash:
        await _login_fail(
            request,
            client_ip,
            "no_pin_set",
            "auth_routes.login.no_pin",
            "Login attempt for account with no PIN",
            user_id=user["user_id"],
        )

    try:
        verifier = PinVerifier.from_stored(pin_hash)
    except (ValueError, IndexError):
        # Legacy plaintext fallback — use constant-time comparison
        if not hmac.compare_digest(pin_hash.encode(), req.pin.encode()):
            await _login_fail(
                request,
                client_ip,
                "invalid_pin",
                "auth_routes.login.legacy_pin_invalid",
                "login: legacy PIN mismatch",
                user_id=user["user_id"],
            )
        logger.warning(
            "Legacy plaintext PIN comparison for user_id=%d — migrate to PBKDF2",
            user.get("user_id", 0),
            extra={"event": "legacy.pin_comparison"},
            exc_info=True,  # auto:exc
        )
    else:
        if not verifier.verify(req.pin):
            await _login_fail(
                request,
                client_ip,
                "invalid_pin",
                "auth_routes.login.pin_invalid",
                "login: PIN mismatch",
                user_id=user["user_id"],
            )

    # Successful auth — clear any prior failures for this IP
    _failure_tracker.clear(client_ip)

    # Issue token
    token = create_session_token(user["user_id"], role=role)

    logger.info(
        "Login success for user_id=%d",
        user["user_id"],
        extra={
            "event": "login.success",
            "user_id": user["user_id"],
            "ip_hash": _hash_ip(client_ip),
            "display_name_len": len(user["display_name"]) if user["display_name"] else 0,
        },
    )

    await _emit_auth_event(
        request,
        "auth.login",
        "SUCCESS",
        details={
            "role": role,
            "trust_level": user.get("trust_level"),
            "ip_hash": _hash_ip(client_ip),
        },
        user_id=user["user_id"],
    )

    response = JSONResponse(
        content={
            "user_id": user["user_id"],
            "role": role,
            "display_name": user["display_name"],
        }
    )
    _set_session_cookies(response, token, secure=_is_secure_request(request))
    return response


# ── Logout ────────────────────────────────────────────────────────


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    """Revoke the calling user's current session cookie."""
    from sentinel.api.revocation import get_revocation_set
    from sentinel.api.sessions import verify_session_token

    raw_token = request.cookies.get("session", "")
    if not raw_token:
        raise HTTPException(status_code=401, detail="No session cookie")

    try:
        payload = verify_session_token(raw_token)
    except Exception:  # catch-all: token verification (crypto, format errors)
        raise HTTPException(status_code=401, detail="Invalid session") from None

    uid = payload.get("user_id", 0)
    if uid == 0:
        # Logout is middleware-exempt; mirror the middleware's zero-principal rejection
        # so a token signed with user_id=0 cannot produce a logout-success response.
        raise HTTPException(status_code=401, detail="Token has no authenticated user")

    jti = payload.get("jti")
    if not jti:
        # Middleware's jti-presence check no longer runs on the exempt path; enforce here.
        raise HTTPException(status_code=401, detail="Token missing jti claim")
    rev = get_revocation_set()
    if rev.is_revoked(jti):
        # Logout is middleware-exempt; middleware's revocation check no longer runs.
        # Reject replayed (already-revoked) tokens explicitly.
        raise HTTPException(status_code=401, detail="Session already revoked")

    # sessions_invalidated_at check (middleware invariant #3).
    # Fail-open when store unavailable — matches middleware behaviour at lines 170-196.
    contact_store = getattr(request.app.state, "contact_store", None)
    if contact_store is not None:
        try:
            user = await contact_store.get_user(uid)
            if user and user.get("sessions_invalidated_at"):
                inv_at = user["sessions_invalidated_at"]
                if isinstance(inv_at, datetime):
                    iat = payload.get("iat", 0)
                    if iat < inv_at.timestamp():
                        raise HTTPException(
                            status_code=401,
                            detail="Session was administratively revoked",
                        )
        except HTTPException:
            raise
        except Exception:
            logger.warning(
                "Failed to check sessions_invalidated_at for user %d during logout",
                uid,
                exc_info=True,
            )

    rev.revoke(jti)

    logger.info("User logged out", extra={"event": "auth.logout", "user_id": uid})

    await _emit_auth_event(request, "auth.logout", "SUCCESS", user_id=uid)

    response = JSONResponse(
        content={"status": "ok", "message": "Logged out successfully"}
    )
    _clear_session_cookies(response)
    return response


# ── Session revocation ────────────────────────────────────────────


@router.post("/revoke-sessions/{user_id}")
async def revoke_sessions(user_id: int) -> dict:
    """Invalidate all session tokens for a user. Requires admin role.

    Sets sessions_invalidated_at to now — tokens issued before this
    timestamp will be rejected by the middleware.
    """
    admin_user_id = current_user_id.get()
    if admin_user_id == 0:
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )
    logger.info(
        "Session revocation requested",
        extra={
            "event": "auth.revoke_sessions_requested",
            "target_user_id": user_id,
            "admin_user_id": admin_user_id,
        },
    )
    store = _get_store()
    await require_role("admin", store, audit_emitter=_audit_emitter)

    now = datetime.now(UTC)
    result = await store.update_user(
        user_id,
        sessions_invalidated_at=now,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(
        "User sessions revoked",
        extra={
            "event": "auth.sessions_revoked",
            "target_user_id": user_id,
            "admin_user_id": admin_user_id,
        },
    )

    await _emit_auth_event(
        None,
        "auth.session_revoke",
        "SUCCESS",
        details={
            "target_user_id": user_id,
            "admin_user_id": admin_user_id,
        },
    )

    return {"status": "sessions_revoked", "user_id": user_id}


# ── PIN change ────────────────────────────────────────────────────


@router.post("/change-pin")
async def change_pin(req: PinChangeRequest) -> dict:
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
        logger.warning(
            "change_pin: ValueError | IndexError",
            extra={"event": "auth_routes.change_pin_error"},
            exc_info=True,
        )
        current_ok = hmac.compare_digest(req.current_pin.encode(), stored_hash.encode())

    if not current_ok:
        return JSONResponse(
            status_code=403, content={"error": "Current PIN is incorrect"}
        )

    # Hash the new PIN and persist it; clear the forced-reset flag in one update
    new_hash = PinVerifier(req.new_pin).to_stored()
    await store.update_user(user_id, pin_hash=new_hash, must_change_pin=False)

    logger.info("PIN changed for user_id=%d", user_id)

    await _emit_auth_event(None, "auth.pin_change", "SUCCESS")

    return {"status": "ok", "message": "PIN changed successfully"}


# ── Profile (current user) ────────────────────────────────────────


@router.get("/me")
async def get_profile() -> dict:
    """Return the current user's profile (role, trust level, must_change_pin).

    Uses the user_id from the JWT (set by middleware). Strips pin_hash
    before returning — the client only needs display fields.
    """
    logger.debug("get_profile called", extra={"event": "auth_routes.get_profile"})
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
