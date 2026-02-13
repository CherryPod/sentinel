import logging
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("sentinel.audit")


class PinAuthMiddleware(BaseHTTPMiddleware):
    """Lightweight PIN authentication via X-Sentinel-Pin header."""

    def __init__(self, app, pin_getter: Callable[[], str | None]):
        super().__init__(app)
        self._pin_getter = pin_getter

    async def dispatch(self, request: Request, call_next):
        pin = self._pin_getter()

        # PIN disabled (None) — pass through
        if pin is None:
            return await call_next(request)

        # /health is always exempt
        if request.url.path == "/health":
            return await call_next(request)

        supplied = request.headers.get("x-sentinel-pin", "")
        if supplied != pin:
            logger.warning(
                "PIN auth failed",
                extra={
                    "event": "pin_auth_failed",
                    "path": request.url.path,
                    "remote": request.client.host if request.client else "unknown",
                },
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing PIN"},
            )

        return await call_next(request)
