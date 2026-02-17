import hmac
import logging
import threading
import time
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("sentinel.audit")

# Lockout settings
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 60


class _FailureTracker:
    """Thread-safe per-IP failed PIN attempt tracker with lockout."""

    def __init__(self):
        self._lock = threading.Lock()
        # {ip: (fail_count, last_fail_time)}
        self._attempts: dict[str, tuple[int, float]] = {}

    def is_locked_out(self, ip: str) -> bool:
        with self._lock:
            record = self._attempts.get(ip)
            if record is None:
                return False
            count, last_fail = record
            if count >= _MAX_FAILED_ATTEMPTS:
                if time.monotonic() - last_fail < _LOCKOUT_SECONDS:
                    return True
                # Lockout expired — reset
                del self._attempts[ip]
                return False
            return False

    def record_failure(self, ip: str) -> int:
        with self._lock:
            record = self._attempts.get(ip)
            now = time.monotonic()
            if record is None:
                self._attempts[ip] = (1, now)
                return 1
            count, last_fail = record
            # Reset if lockout period has passed
            if count >= _MAX_FAILED_ATTEMPTS and now - last_fail >= _LOCKOUT_SECONDS:
                self._attempts[ip] = (1, now)
                return 1
            self._attempts[ip] = (count + 1, now)
            return count + 1

    def clear(self, ip: str) -> None:
        with self._lock:
            self._attempts.pop(ip, None)


class PinAuthMiddleware(BaseHTTPMiddleware):
    """PIN authentication via X-Sentinel-Pin header.

    Uses constant-time comparison (hmac.compare_digest) to prevent timing
    side-channel attacks, and per-IP lockout after repeated failures.
    """

    def __init__(self, app, pin_getter: Callable[[], str | None]):
        super().__init__(app)
        self._pin_getter = pin_getter
        self._failures = _FailureTracker()

    async def dispatch(self, request: Request, call_next):
        pin = self._pin_getter()
        remote = request.client.host if request.client else "unknown"

        # PIN disabled (None) — pass through
        if pin is None:
            return await call_next(request)

        # Health, WebSocket, MCP, and static UI assets are exempt.
        # Static assets must load without PIN so the JS can show the PIN overlay.
        # API endpoints enforce PIN separately via X-Sentinel-Pin header.
        path = request.url.path
        _EXEMPT_PATHS = ("/health", "/api/health", "/ws")
        _EXEMPT_EXTENSIONS = (".html", ".js", ".css", ".png", ".ico", ".svg", ".woff", ".woff2")
        if (
            path in _EXEMPT_PATHS
            or path.startswith("/mcp")
            or path == "/"
            or any(path.endswith(ext) for ext in _EXEMPT_EXTENSIONS)
        ):
            return await call_next(request)

        # Check lockout before doing any comparison
        if self._failures.is_locked_out(remote):
            logger.warning(
                "PIN auth locked out",
                extra={
                    "event": "pin_auth_lockout",
                    "path": request.url.path,
                    "remote": remote,
                },
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many failed attempts — try again later"},
            )

        supplied = request.headers.get("x-sentinel-pin", "")
        if not hmac.compare_digest(supplied.encode(), pin.encode()):
            fail_count = self._failures.record_failure(remote)
            logger.warning(
                "PIN auth failed",
                extra={
                    "event": "pin_auth_failed",
                    "path": request.url.path,
                    "method": request.method,
                    "remote": remote,
                    "pin_supplied": bool(supplied),
                    "fail_count": fail_count,
                    "locked_out": fail_count >= _MAX_FAILED_ATTEMPTS,
                },
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing PIN"},
            )

        # Successful auth — clear any failure record
        self._failures.clear(remote)
        logger.debug(
            "PIN auth passed",
            extra={
                "event": "pin_auth_success",
                "path": request.url.path,
                "method": request.method,
                "remote": remote,
            },
        )
        return await call_next(request)
