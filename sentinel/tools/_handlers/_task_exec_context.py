"""Per-task execution context — replaces singleton mutable state on ToolExecutor.

Each task gets a fresh TaskExecutionContext at the start of _execute_plan().
State is scoped to the task lifetime and garbage collected when the task ends.
No cross-task leaks.

Addresses H10: _session_file_reads unbounded growth.

C45 (2026-04-26): the per-task context is exposed to handler mixins via a
module-level ContextVar (`_current_task_context`) accessed only through three
thin helpers — `get_current_task_context()`, `set_current_task_context()`,
`reset_current_task_context()`. The raw ContextVar stays private to this
module. `ToolExecutor.execute()` brackets dispatch with set/reset in
try/finally so each asyncio Task sees its own per-task binding under
concurrent execute() calls (cross-channel + multi-WebSocket reachability).
"""

from __future__ import annotations

import contextvars
from contextvars import ContextVar
from dataclasses import dataclass, field

from sentinel.tools.loop_detector import LoopDetector


@dataclass
class TaskExecutionContext:
    """Mutable state that lives for the duration of a single task execution.

    Created fresh in _execute_plan(), passed through execute() to handlers.
    Replaces _session_file_reads and _session_file_hashes on ToolExecutor.

    Attributes:
        file_reads: Paths read during this task — used by file_write to warn
            when overwriting a previously-read file (suggests file_patch instead).
        file_hashes: path -> SHA-256 at read time — used by the goal verifier's
            content_changed assertions to detect whether a file was actually modified.
        loop_detector: Per-task tool call loop detector — warns/blocks on
            repeated identical tool calls to prevent runaway agent loops.
    """

    file_reads: set[str] = field(default_factory=set)
    file_hashes: dict[str, str] = field(default_factory=dict)
    loop_detector: LoopDetector = field(default_factory=LoopDetector)


# Module-private ContextVar — no other module imports this name directly.
# Mixins call get_current_task_context(); ToolExecutor.execute() brackets
# dispatch with set/reset_current_task_context() in try/finally.
_current_task_context: ContextVar[TaskExecutionContext | None] = ContextVar(
    "current_task_context", default=None
)


def get_current_task_context() -> TaskExecutionContext | None:
    """Return the TaskExecutionContext for the currently-executing asyncio Task.

    Returns None when called outside a tool dispatch (e.g. setup / shutdown
    code, tests calling handlers directly without going through
    ToolExecutor.execute). Per-asyncio-Task isolation is provided by Python's
    contextvars module — sibling tasks see their own bindings.
    """
    return _current_task_context.get()


def set_current_task_context(
    ctx: TaskExecutionContext | None,
) -> contextvars.Token:
    """Bind the per-task context for the current asyncio Task.

    Returns the token that MUST be passed to reset_current_task_context() in
    the matching finally: clause. Thin wrapper over ContextVar.set() — NO
    validation logic. If validation is ever added, the widen-wrap audit
    must reapply: token initialisation must not be masked by a setter
    exception (refactoring guardrail: do not mask the token init).
    """
    return _current_task_context.set(ctx)


def reset_current_task_context(token: contextvars.Token) -> None:
    """Restore the previous binding for the current asyncio Task.

    Thin wrapper over ContextVar.reset() — NO validation logic (same
    widen-wrap discipline as set_current_task_context).
    """
    _current_task_context.reset(token)
