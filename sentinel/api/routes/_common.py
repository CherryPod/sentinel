"""Shared utilities for route modules.

Small helpers used by multiple route files. Extracted to avoid
copy-pasting identical functions across the package.
"""

import logging

from starlette.requests import Request

logger = logging.getLogger(__name__)


def resolve_shutting_down(request: Request) -> bool:
    """Check shutdown flag from app.state, then app module fallback.

    Checks request.app.state first (set by lifespan dual-write), then
    falls back to the app module global for safety-net tests that patch
    app_module._shutting_down directly.
    """
    # Prefer app.state (set by lifespan dual-write)
    state_val = getattr(request.app.state, "shutting_down", None)
    if state_val is not None:
        return state_val
    # Fallback: safety-net tests set app_module._shutting_down directly
    import sentinel.api.app as _app

    return _app._shutting_down
