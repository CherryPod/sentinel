"""Prompt and context builders — facade re-exporting from sub-modules.

All functional code has been extracted into focused modules:
  _plan_setup.py      — execution vars, destination routing, format enforcement, auto-approval
  _step_enrichment.py — F1 step outcome builder and enrichment helpers
  _error_context.py   — error genericisation, interrupted task warnings, session files
  _learning_context.py — episodic search, provider assembly, budget management
  _memory_persistence.py — auto-store memory, pre-pruning flush
  _history_rendering.py — detailed plan history rendering
"""

from __future__ import annotations

# ── Backward-compat re-exports ─────────────────────────────────
# These were previously defined or re-exported in builders.py and are
# imported by tests and downstream modules.
from ._context_provider import (  # noqa: F401
    ContextBuildArgs,
    ContextProvider,
    ContextSection,
)
from ._context_providers._episodic_records import (  # noqa: F401
    accumulate_records_within_budget,
)
from ._context_providers._insights import render_insights  # noqa: F401

# ── Error context ──────────────────────────────────────────────
from ._error_context import (  # noqa: F401
    build_interrupted_task_warning,
    build_session_files_context,
    genericise_error,
)

# ── History rendering ──────────────────────────────────────────
from ._history_rendering import render_plan_history  # noqa: F401

# ── Learning context ───────────────────────────────────────────
from ._learning_context import (  # noqa: F401
    _classify_request_domain,
    build_learning_context,
)

# ── Memory persistence ─────────────────────────────────────────
from ._memory_persistence import (  # noqa: F401
    auto_store_memory,
    flush_pruned_turns,
)

# ── Plan setup ─────────────────────────────────────────────────
from ._plan_setup import (  # noqa: F401
    CHAIN_REMINDER,
    FORMAT_INSTRUCTIONS,
    compute_execution_vars,
    enforce_tagged_format,
    get_destination,
    is_auto_approvable,
)

# ── Step enrichment (F1) ───────────────────────────────────────
from ._step_enrichment import build_step_outcome  # noqa: F401

# orchestrator.py imports this alias
build_cross_session_context = build_learning_context
