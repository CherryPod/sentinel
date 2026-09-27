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

current_request_id: ContextVar[str | None] = ContextVar(
    "current_request_id", default=None
)
current_task_id: ContextVar[str | None] = ContextVar("current_task_id", default=None)
current_user_id: ContextVar[int] = ContextVar("current_user_id", default=0)


def set_user_context(user_id: int) -> contextvars.Token:
    """Set the current user ID for RLS scoping. Returns reset token."""
    return current_user_id.set(user_id)


class PrincipalRequiredError(ValueError):
    """Raised by `require_user_id()` when the zero-principal fail-closed
    invariant is violated (Q4 hardening).

    Subclasses `ValueError` so existing `except ValueError` handlers still
    catch it AND existing `raises(ValueError)` tests still pass. But the
    dedicated subclass lets callers that wrap user-scoped operations in
    broad `except Exception` swallows narrow the catch to **re-raise**
    principal violations while still handling unrelated failures gracefully:

        try:
            await user_scoped_op(...)
        except PrincipalRequiredError:
            raise  # Q4: zero-principal must propagate to caller
        except Exception as exc:
            logger.warning("op failed (non-fatal)", exc_info=True)

    Q4.fix.f Coord review: without this discriminator, the raise from
    `require_user_id()` is silently swallowed at several call sites
    (`_file_write.py`, `_file_patch.py`, `_website.py`, `routines/engine.py`),
    defeating the fail-closed invariant at the producer boundary.
    """


def require_user_id(user_id: int | None, context: str) -> int:
    """Resolve user_id from explicit param or current_user_id ContextVar; fail-closed on 0.

    Q4 hardening invariant: every user-scoped store / producer site must have
    a non-zero user_id. The ContextVar default of 0 means "unset" — reaching
    a user-scoped sink with that value is a bug (silent mis-attribution).

    Behaviour:
      - If `user_id` is None, resolve from `current_user_id.get()`.
      - If the resolved value is 0, raise `PrincipalRequiredError` (subclass
        of `ValueError`, so existing ValueError handlers still catch it).
      - Otherwise, return the resolved value unchanged.

    The `context` argument names the calling site (e.g. "EpisodicStore.create",
    "core.approval.request_plan_approval") so the raised exception is grep-friendly
    in production logs.

    Excluded by design (do NOT call from): `audit/emitter.py:_select_pool`
    (system audit pool), `security/provenance.py` (intentional orphan sentinel),
    boot/startup tier in `lifecycle.py`, maintenance jobs in `routines/stats.py`.
    See `docs/hardening/2026-04-20-hardening-Q4-user-isolation-findings.md` §Design (zero-principal).
    """
    if user_id is None:
        user_id = current_user_id.get()
    if user_id == 0:
        raise PrincipalRequiredError(
            f"{context} requires user_id to be set (current_user_id unset — "
            "auth/middleware bypass?)"
        )
    return user_id


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
