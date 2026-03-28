"""Request-scoped context variables for tracing.

Provides task_id and request_id propagation via contextvars so that
downstream code (pipeline, conversation analyser, etc.) can include
correlation IDs in log extras without threading them as parameters.

Set by:
  - HTTP middleware (request_id)
  - Orchestrator.handle_task (task_id)
"""

import asyncio
import contextvars
from contextvars import ContextVar

current_request_id: ContextVar[str | None] = ContextVar("current_request_id", default=None)
current_task_id: ContextVar[str | None] = ContextVar("current_task_id", default=None)
current_user_id: ContextVar[int] = ContextVar("current_user_id", default=0)


def set_user_context(user_id: int) -> contextvars.Token:
    """Set the current user ID for RLS scoping. Returns reset token."""
    return current_user_id.set(user_id)


def get_request_id() -> str | None:
    """Return the current request ID, or None if not in a request context."""
    return current_request_id.get()


def get_task_id() -> str | None:
    """Return the current task ID, or None if not in a task context."""
    return current_task_id.get()


def spawn_task(coro, *, name: str | None = None) -> asyncio.Task:
    """Create an asyncio task that inherits the current ContextVar values.

    Use this instead of bare asyncio.create_task() for any user-scoped work
    (task execution, logging, cleanup). The child task will see the same
    current_user_id, current_request_id, etc. as the parent.

    Infrastructure tasks (health checks, server lifecycle) can use bare
    asyncio.create_task() — add a comment explaining why.

    The context= parameter on asyncio.create_task was added in Python 3.11,
    and this project targets Python 3.12, so it is always available.
    """
    ctx = contextvars.copy_context()
    return asyncio.create_task(coro, name=name, context=ctx)


def resolve_trust_level(user_trust_level: int | None, system_default: int) -> int:
    """Return the user's trust level, falling back to system default if unset.

    Per-user trust_level (from users table) overrides the global setting.
    NULL means "use system default from settings.trust_level".
    """
    if user_trust_level is not None:
        return user_trust_level
    return system_default
