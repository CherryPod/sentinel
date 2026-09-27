"""Assertion evaluator registry — hub that maps type names to evaluator functions.

Adding a new assertion type:
1. Add the evaluator function to _evaluator_fns.py
2. Register it here in the EVALUATORS dict

This file stays small; _evaluator_fns.py holds the actual implementations.
"""

from __future__ import annotations

import inspect as _inspect
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class AssertionResult:
    assertion_type: str
    path: str | None
    passed: bool
    message: str
    recovery: str | None = None


def is_async_evaluator(fn) -> bool:
    """Check if an evaluator function is async (e.g. command_returns)."""
    return _inspect.iscoroutinefunction(fn)


# ── Evaluator Registry ───────────────────────────────────────────
# Import evaluator functions from the leaf module. This import must be
# after AssertionResult is defined (evaluator_fns imports it).

from sentinel.planner._evaluator_fns import (  # noqa: E402
    eval_command_returns,
    eval_content_changed,
    eval_file_contains,
    eval_file_exists,
    eval_file_not_contains,
    eval_file_not_empty,
    eval_response_contains,
    eval_symbol_count,
    eval_symbol_exists,
)

EVALUATORS: dict[str, Callable] = {
    "file_exists": eval_file_exists,
    "file_not_empty": eval_file_not_empty,
    "file_contains": eval_file_contains,
    "file_not_contains": eval_file_not_contains,
    "content_changed": eval_content_changed,
    "response_contains": eval_response_contains,
    "command_returns": eval_command_returns,
    "symbol_exists": eval_symbol_exists,
    "symbol_count": eval_symbol_count,
}
