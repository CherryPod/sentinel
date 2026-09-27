"""HTTP middleware for Sentinel API.

RequestCorrelationMiddleware — sets request_id contextvar + X-Request-ID header.
UserContextMiddleware — JWT-only auth, sets current_user_id, sliding refresh.
SecurityHeadersMiddleware — sets security headers on every response.
CSRFMiddleware — validates Origin header on state-changing requests.
RequestSizeLimitMiddleware — rejects oversized requests.
"""

import logging
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from sentinel.core.context import current_request_id, current_user_id

logger = logging.getLogger(__name__)

# Static file extensions that are exempt from auth (served without a token).
# These cover the UI build assets and common web resources.
_STATIC_EXTENSIONS = frozenset(
    (
        ".html",
        ".js",
        ".css",
        ".png",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
    )
)

# .json was previously in _STATIC_EXTENSIONS but created an auth bypass vector:
# requests like /api/credentials.json would match the extension check and skip
# authentication entirely. Removed — JSON files under /static/ are served by
# the static mount which is already auth-exempt via _EXEMPT_PREFIXES.

# Path prefixes that are exempt from auth. Login and health endpoints must be
# reachable without a token; /sites/ and /workspace/ are intentionally public
# so generated URLs can be shared without auth. Every entry is canonicalised
# to terminate the path segment with `/` so the matcher in `_is_exempt` can
# fail-safe against prefix-substring bypasses (e.g. `/.well-knownbackup`,
# `/mcp-evil`).
_EXEMPT_PREFIXES = (
    "/api/auth/login/",
    "/api/auth/logout/",  # Handler self-authenticates; exempt prevents sliding-refresh remint
    "/health/",
    "/api/health/",
    "/.well-known/",
    "/login/",
    "/sites/",
    "/workspace/",
    "/api/webhook/",  # Webhook endpoints use HMAC signature auth, not JWT
    "/mcp/",  # MCP endpoints use Bearer token auth via MCPAuthMiddleware, not JWT
)


def _is_exempt(path: str) -> bool:
    """Return True if the request path does not require authentication."""
    # Root path serves the static UI (auth handled client-side via JS)
    logger.debug(
        "_is_exempt called", extra={"event": "middleware._is_exempt", "path": path}
    )
    if path == "/":
        return True
    # Boundary-prefix match: each tuple entry terminates a path segment, so a
    # request matches when path equals the un-slashed entry (e.g. bare `/mcp`)
    # or starts with the slashed entry (e.g. `/mcp/tools/list`). The empty
    # and root-prefix guard fail-closes if a future commit ever adds `""` or
    # `"/"` to the tuple — those would otherwise short-circuit every request
    # past the auth gate.
    for prefix in _EXEMPT_PREFIXES:
        if not prefix or prefix == "/":
            continue
        boundary_prefix = prefix if prefix.endswith("/") else f"{prefix}/"
        if path == boundary_prefix[:-1] or path.startswith(boundary_prefix):
            return True
    # Static file extensions (UI assets) — only match in the final path segment
    # to prevent /api/tasks.json from bypassing auth (finding #10)
    segment = path.rsplit("/", 1)[-1]
    dot = segment.rfind(".")
    return bool(dot != -1 and segment[dot:].lower() in _STATIC_EXTENSIONS)


class UserContextMiddleware(BaseHTTPMiddleware):
    """Cookie-based auth middleware — sets current_user_id from session cookie.

    Every request MUST carry a valid ``session`` HttpOnly cookie unless
    the path is exempt (login, health, static assets, workspace). Unauthenticated
    requests receive a loud 401.

    Security checks performed on every authenticated request:
    1. JWT signature + expiry (via verify_session_token)
    2. JTI revocation (in-memory fast path via RevocationSet)
    3. sessions_invalidated_at (per-user session wipe via contact_store)
    4. user_id != 0 guard (paranoia — no anonymous authenticated requests)

    Sliding refresh: every authenticated response sets a fresh session cookie
    so the client's session never expires during active use.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        import jwt as pyjwt

        from sentinel.api.revocation import get_revocation_set
        from sentinel.api.sessions import (
            SESSION_TTL,
            create_session_token,
            verify_session_token,
        )

        # Exempt paths pass through without auth
        if _is_exempt(request.url.path):
            return await call_next(request)

        # Read JWT from HttpOnly session cookie
        raw_token = request.cookies.get("session", "")
        if not raw_token:
            return JSONResponse(
                status_code=401,
                content={"status": "error", "reason": "Authentication required"},
            )

        try:
            payload = verify_session_token(raw_token)
        except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError) as exc:
            logger.warning(
                "Token validation failed",
                extra={"event": "auth.token_invalid", "error_type": type(exc).__name__},
                exc_info=True,  # auto:exc
            )
            return JSONResponse(
                status_code=401,
                content={"status": "error", "reason": "Invalid or expired session"},
            )

        uid = payload.get("user_id", 0)

        # Loud 401 on user_id=0 — this should never happen with a valid token
        # but we guard against it explicitly rather than silently returning empty results
        if uid == 0:
            logger.warning(
                "Token decoded with user_id=0 — rejecting",
                extra={"event": "auth.user_id_zero"},
            )
            return JSONResponse(
                status_code=401,
                content={"status": "error", "reason": "Invalid user identity in token"},
            )

        # JTI revocation check (in-memory fast path)
        # Reject tokens without jti — fail-closed prevents forged tokens from
        # bypassing revocation entirely (finding #12)
        jti = payload.get("jti")
        if not jti:
            return JSONResponse(
                status_code=401,
                content={"status": "error", "reason": "Token missing jti claim"},
            )
        if get_revocation_set().is_revoked(jti):
            return JSONResponse(
                status_code=401,
                content={"status": "error", "reason": "Token has been revoked"},
            )

        # sessions_invalidated_at check — reads from app.state.contact_store
        # (wired by lifecycle.py during lifespan, not passed at __init__ time)
        contact_store = getattr(request.app.state, "contact_store", None)
        if contact_store is not None:
            try:
                user = await contact_store.get_user(uid)
                if user and user.get("sessions_invalidated_at"):
                    import datetime

                    inv_at = user["sessions_invalidated_at"]
                    if isinstance(inv_at, datetime.datetime):
                        iat = payload.get("iat", 0)
                        if iat < inv_at.timestamp():
                            return JSONResponse(
                                status_code=401,
                                content={
                                    "status": "error",
                                    "reason": "Session revoked — please log in again",
                                },
                            )
            except Exception:  # catch-all: session check — don't block request
                # If the contact store is unavailable, log but don't block the request.
                # The JTI revocation check above still provides protection.
                logger.warning(
                    "Failed to check sessions_invalidated_at for user %d",
                    uid,
                    exc_info=True,
                )

        # All checks passed — set the user context and call downstream
        ctx_token = current_user_id.set(uid)
        try:
            response = await call_next(request)
        finally:
            current_user_id.reset(ctx_token)

        # Sliding refresh: issue a fresh session cookie so the session
        # stays alive during active use (replaces X-Refreshed-Token header)
        role = payload.get("role", "user")
        refreshed = create_session_token(uid, role=role)
        is_secure = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto") == "https"
        )
        response.set_cookie(
            key="session",
            value=refreshed,
            httponly=True,
            samesite="lax",
            secure=is_secure,
            path="/",
            max_age=SESSION_TTL,
        )
        # Refresh the non-HttpOnly flag cookie so it doesn't expire before the session
        response.set_cookie(
            key="sentinel_auth",
            value="1",
            httponly=False,
            samesite="lax",
            secure=is_secure,
            path="/",
            max_age=SESSION_TTL,
        )

        return response


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """Generate a unique request_id per HTTP request for log correlation.

    Sets the ``current_request_id`` contextvar so downstream code can read it,
    and adds an ``X-Request-ID`` response header for client-side tracing.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        token = current_request_id.set(request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            current_request_id.reset(token)


# All 6 security headers previously set by nginx
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self' wss: ws:; frame-ancestors 'none';"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

# CSP for /sites — LLM-generated HTML may use inline styles but NOT inline scripts.
# Inline scripts would allow a compromised worker to inject XSS payloads.
# No connect-src (no API access), no frame-ancestors relaxation.
_SITES_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "frame-ancestors 'none';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set security headers on every response, including error responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        # /sites serves LLM-generated content — allow inline styles only (no inline scripts)
        if request.url.path.startswith("/sites/"):
            response.headers["Content-Security-Policy"] = _SITES_CSP
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Validate Origin header on state-changing requests to prevent CSRF.

    State-changing requests (POST/PUT/DELETE/PATCH) MUST include a valid Origin
    header unless the path is in the exempt list. Paths exempt from Origin
    checks have their own authentication (e.g. HMAC signatures for webhooks,
    shared-secret for MCP).
    """

    # Paths that legitimately receive Origin-less requests from non-browser clients.
    # Webhook receives have HMAC signature auth; MCP has its own auth; A2A is
    # agent-to-agent protocol.
    # Every entry is canonicalised to terminate the path segment with `/` so
    # the matcher fail-safes against prefix-substring bypasses
    # (e.g. `/mcp-evil`, `/a2a-spoof`).
    _ORIGIN_EXEMPT_PREFIXES = (
        "/api/auth/login/",  # Login endpoint — no session to hijack yet
        "/api/webhook/",  # External services sending webhook payloads (HMAC-authed)
        "/mcp/",  # MCP clients (tool integrations, not browsers)
        "/.well-known/",  # A2A agent card discovery
        "/a2a/",  # A2A agent-to-agent protocol — clients don't send Origin
    )

    def __init__(self, app, allowed_origins: list[str]):
        super().__init__(app)
        self._allowed = set(o.rstrip("/").lower() for o in allowed_origins)

    def _is_exempt(self, path: str) -> bool:
        """Check if this path is exempt from Origin header requirement.

        Boundary-prefix match: matches when path equals the un-slashed entry
        (bare `/mcp`, bare `/a2a`) or starts with the slashed entry. Empty and
        root-prefix guard fail-closes against accidental total-bypass if `""`
        or `"/"` ever appears in the tuple.
        """
        for prefix in self._ORIGIN_EXEMPT_PREFIXES:
            if not prefix or prefix == "/":
                continue
            boundary_prefix = prefix if prefix.endswith("/") else f"{prefix}/"
            if path == boundary_prefix[:-1] or path.startswith(boundary_prefix):
                return True
        return False

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if not self._is_exempt(request.url.path):
                origin = request.headers.get("origin", "")
                if not origin:
                    return JSONResponse(
                        status_code=403,
                        content={"status": "error", "reason": "CSRF: missing origin"},
                    )
                normalised = origin.rstrip("/").lower()
                if normalised not in self._allowed:
                    return JSONResponse(
                        status_code=403,
                        content={"status": "error", "reason": "CSRF: invalid origin"},
                    )
        return await call_next(request)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with Content-Length exceeding the configured limit.

    First-pass filter only. Chunked transfer-encoding (no Content-Length) bypasses
    this check, but is caught downstream by FastAPI body limits and
    MAX_TEXT_LENGTH (50K) in _normalize_text().
    """

    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        try:
            cl_int = int(content_length) if content_length else None
        except ValueError:
            logger.warning(
                "dispatch: malformed Content-Length header",
                extra={"event": "middleware.content_length_parse_error"},
                exc_info=True,
            )
            cl_int = None
        if cl_int is not None and cl_int > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={"status": "error", "reason": "Request too large"},
            )
        return await call_next(request)
