"""Verify rate limiting middleware is registered and functional."""
from slowapi.middleware import SlowAPIMiddleware
from sentinel.api.app import app


def test_slowapi_middleware_registered():
    """SlowAPIMiddleware must be in the ASGI middleware stack."""
    middleware_types = [m.cls for m in app.user_middleware]
    assert SlowAPIMiddleware in middleware_types, (
        "SlowAPIMiddleware not registered — all @limiter.limit() decorators are no-ops"
    )
