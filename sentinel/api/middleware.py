"""HTTP middleware for Sentinel API.

SecurityHeadersMiddleware — sets security headers on every response.
CSRFMiddleware — validates Origin header on state-changing requests.
RequestSizeLimitMiddleware — rejects oversized requests.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set security headers on every response, including error responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Validate Origin header on state-changing requests to prevent CSRF."""

    def __init__(self, app, allowed_origins: list[str]):
        super().__init__(app)
        self._allowed = set(o.rstrip("/").lower() for o in allowed_origins)

    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin", "")
            if origin:
                normalised = origin.rstrip("/").lower()
                if normalised not in self._allowed:
                    return JSONResponse(
                        status_code=403,
                        content={"status": "error", "reason": "CSRF: invalid origin"},
                    )
        return await call_next(request)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with Content-Length exceeding the configured limit."""

    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={"status": "error", "reason": "Request too large"},
            )
        return await call_next(request)
