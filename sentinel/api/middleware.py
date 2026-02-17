"""HTTP middleware for Sentinel API.

RequestCorrelationMiddleware — sets request_id contextvar + X-Request-ID header.
SecurityHeadersMiddleware — sets security headers on every response.
CSRFMiddleware — validates Origin header on state-changing requests.
RequestSizeLimitMiddleware — rejects oversized requests.
"""

import uuid

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel.core.context import current_request_id, current_user_id


class UserContextMiddleware(BaseHTTPMiddleware):
    """Set current_user_id contextvar from session token or PIN fallback.

    Auth priority:
    1. Authorization: Bearer <JWT> → extract user_id from token
    2. X-Sentinel-Pin header → backwards compat, always user_id=1
    3. No auth → user_id=1 (single-user default for internal/test use)

    The JWT path also checks sessions_invalidated_at to support session
    revocation (POST /api/auth/revoke-sessions/{user_id}).
    """

    def __init__(self, app, contact_store=None):
        super().__init__(app)
        self._contact_store = contact_store

    async def dispatch(self, request: Request, call_next):
        import jwt as pyjwt
        from sentinel.api.sessions import verify_session_token

        # Try Bearer token first
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
            try:
                payload = verify_session_token(raw_token)
                uid = payload["user_id"]

                # Check session revocation if we have a contact store
                if self._contact_store is not None:
                    user = await self._contact_store.get_user(uid)
                    if user and user.get("sessions_invalidated_at"):
                        import datetime
                        inv_at = user["sessions_invalidated_at"]
                        if isinstance(inv_at, str):
                            pass  # In-memory mode, skip check
                        elif isinstance(inv_at, datetime.datetime):
                            iat = payload.get("iat", 0)
                            if iat < inv_at.timestamp():
                                return JSONResponse(
                                    status_code=401,
                                    content={"error": "Session revoked"},
                                )

                ctx_token = current_user_id.set(uid)
                try:
                    response = await call_next(request)
                finally:
                    current_user_id.reset(ctx_token)
                return response
            except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError):
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or expired token"},
                )

        # Fallback: PIN auth passes through PinAuthMiddleware, always user_id=1
        ctx_token = current_user_id.set(1)
        try:
            response = await call_next(request)
        finally:
            current_user_id.reset(ctx_token)
        return response


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """Generate a unique request_id per HTTP request for log correlation.

    Sets the ``current_request_id`` contextvar so downstream code can read it,
    and adds an ``X-Request-ID`` response header for client-side tracing.
    """

    async def dispatch(self, request: Request, call_next):
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

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        # /sites serves LLM-generated content — allow inline styles only (no inline scripts)
        if request.url.path.startswith("/sites"):
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
    # agent-to-agent protocol; red-team endpoint is gated by SENTINEL_RED_TEAM_MODE.
    _ORIGIN_EXEMPT_PREFIXES = (
        "/api/webhook/",   # External services sending webhook payloads (HMAC-authed)
        "/mcp",            # MCP clients (tool integrations, not browsers)
        "/.well-known/",   # A2A agent card discovery
        "/api/test/",      # Red team endpoint (only active in RED_TEAM_MODE)
    )

    def __init__(self, app, allowed_origins: list[str]):
        super().__init__(app)
        self._allowed = set(o.rstrip("/").lower() for o in allowed_origins)

    def _is_exempt(self, path: str) -> bool:
        """Check if this path is exempt from Origin header requirement."""
        return any(path.startswith(prefix) for prefix in self._ORIGIN_EXEMPT_PREFIXES)

    async def dispatch(self, request: Request, call_next):
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

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        try:
            cl_int = int(content_length) if content_length else None
        except ValueError:
            cl_int = None
        if cl_int is not None and cl_int > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={"status": "error", "reason": "Request too large"},
            )
        return await call_next(request)
