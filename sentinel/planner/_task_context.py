"""Cross-stage state for task execution pipelines.

TaskContext carries state for _handle_task_inner stage methods.
PlanExecState carries state for _execute_plan sub-methods.

Variables that are created and consumed within the same method stay as locals —
they do NOT belong in these dataclasses.

Each field documents which method creates it (writer) and which methods read it
(readers) so future maintainers can trace the data flow.

Field-naming rule: if a name collides with a LogRecord reserved attribute
(filename, module, funcName, etc.), prefix it to avoid silent logging failures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sentinel.core.models import (
        ConversationInfo,
        Plan,
        PlanStep,
        StepResult,
        TaskResult,
    )
    from sentinel.planner.intake import ContactResolutionResult, IntakeResult
    from sentinel.session.store import Session
    from sentinel.tools._handlers._task_exec_context import TaskExecutionContext


@dataclass
class TaskContext:
    """Accumulated state for a single task execution.

    Created at the top of _handle_task_inner, populated by stage methods,
    and consumed by downstream stages.  The dataclass replaces ~15 local
    variables that previously threaded through 999 lines of inline code.
    """

    # ── Parameters (set at creation, never mutated by stages) ────────
    # Writer: _handle_task_inner caller  |  Readers: all stages

    user_request: str
    """May be rewritten by Stage A (contact resolution)."""

    source: str
    approval_mode: str
    source_key: str | None
    task_id: str
    task_t0: float
    auto_approved: bool
    input_pre_scanned: bool = False
    """D42 (FL-C79-a2): scalar signal that the router already ran S1 input
    scan before dispatching to ``_handle_task_inner``.  Replaces the
    previous ``pre_scanned_session: Session | None`` carrier that smuggled
    a stale pre-lock snapshot into the locked region; the orchestrator now
    always reloads the session from the store inside its per-session lock
    via ``bind_session`` and uses this boolean only to decide whether to
    skip the S1 scan re-run.
    """

    user_request_data_id: str | None = None
    """Q8.fix.a: TaggedData id minted at the channel/API ingress adapter.

    Writer: ingress adapter (channels/base.py, api/routes/*, etc.).
    Readers: none today — the field is write-only at ingress in Q8.fix.a.
    Downstream consumption (S3 provenance gate resolving user-request-origin
    via `is_trust_safe_for_execution(data_id)`, and `ConversationTurn.request_text`
    persistence of the ingress-tagged content) lands with the Q2-U1 schema
    expansion (see `docs/hardening/2026-04-20-hardening-Q8-ingress-tagging-findings.md`
    §D3). Today S3 only reads `$var`-referenced ids from tool args via
    `ExecutionContext`, not user-request-origin ids. Compensating defences
    hold the invariant in the meantime (Q7.fix.b scrub + S1 `scan_input`
    on the user_request string).

    None when no adapter wrapped (legacy path); treat as not-yet-tagged,
    never as TRUSTED.
    """

    # ── Stage A outputs (pre-processing) ─────────────────────────────

    effective_tl: int = 4
    """Writer: Stage A (trust resolution)  |  Readers: C (planner), D (approval), E (execute)"""

    intake: IntakeResult | None = None
    """Writer: Stage A (bind_session)  |  Readers: A (input scan skip check)"""

    session: Session | None = None
    """Writer: Stage A (bind_session)  |  Readers: A, B, C, E, post-process, cleanup"""

    session_id: str | None = None
    """Writer: Stage A (interrupted task)  |  Readers: B (memory flush), E (execute)"""

    conv_info: ConversationInfo | None = None
    """Writer: Stage A (bind_session, conversation analysis)  |  Readers: C (error returns), E (result), post-process"""

    contact_result: ContactResolutionResult | None = None
    """Writer: Stage A (contact resolution)  |  Readers: C (planner), E (execute — user_id)"""

    interrupted_context: str = ""
    """Writer: Stage A (interrupted task detection)  |  Readers: C (planner)"""

    task_in_progress_set: bool = False
    """Writer: Stage A (after the new task's set_task_in_progress(True))  |  Readers: post-process (cleanup gate).

    C48 invariant: ``_cleanup_task`` clears the session's ``task_in_progress``
    flag only when this is ``True`` — i.e. when intake successfully registered
    the new task.  When intake blocks before the flag-set (input scan rejects,
    contact resolution rejects, conversation analysis blocks), the stale crash
    flag is preserved so the next entry-boundary touch can run reconciliation
    + emit ``system.session_crash_reconciliation``.  Without this gate, a
    blocked first-touch on a crashed session loses the audit row.
    """

    # ── Stage B outputs (planner preparation) ────────────────────────

    available_tools: list[dict] = field(default_factory=list)
    """Writer: Stage B (tool descriptions)  |  Readers: C (planner), E (execute)"""

    conversation_history: list[dict] | None = None
    """Writer: Stage B (history construction + pruning)  |  Readers: C (planner)"""

    cross_session_context: str = ""
    """Writer: Stage B (memory/episodic retrieval)  |  Readers: C (planner)"""

    session_files_context: str = ""
    """Writer: Stage B (workspace tracking)  |  Readers: C (planner)"""

    # ── Stage C outputs (plan creation) ──────────────────────────────

    plan: Plan | None = None
    """Writer: Stage C (planner invocation)  |  Readers: D (approval), E (execute, judge, episodic)"""

    planner_usage: dict | None = None
    """Writer: Stage C (planner token usage)  |  Readers: E (result enrichment)"""

    # ── Stage E outputs (execution + verification) ───────────────────

    result: TaskResult | None = None
    """Writer: Stage E (execute_plan)  |  Readers: E (judge, assertions), post-process (episodic, turn)"""

    task_elapsed: float = 0.0
    """Writer: Stage E (computed from task_t0)  |  Readers: post-process (episodic, turn, events)"""

    task_exec_context: TaskExecutionContext | None = None
    """Writer: _execute_and_verify (Stage E)  |  Readers: _evaluate_task_assertions, _execute_plan"""


@dataclass
class PlanExecState:
    """Mutable state for _execute_plan loop and its extracted sub-methods.

    Created at the top of _execute_plan, populated during the step loop,
    and consumed by _handle_continuation_replan, _handle_failure_replan,
    and _build_execution_result.  Replaces ~20 local variables that
    previously threaded through 882 lines of inline code.
    """

    # ── Parameters (set at creation, read-only after init) ───────────
    # Writer: _execute_plan init  |  Readers: all sub-methods

    plan: Plan
    """Original plan being executed."""

    user_input: str | None
    """User's original request text."""

    task_id: str
    """Task identifier for event emission."""

    session_id: str | None
    """Session identifier for worker context buffer."""

    user_id: int
    """User identifier for anchor map lookups."""

    effective_tl: int | None
    """Effective trust level for step execution."""

    available_tools: list[dict] | None
    """Tool descriptions for replan requests."""

    plan_t0: float
    """Monotonic timestamp when plan execution started."""

    max_replans: int = 3
    """Budget for success-triggered replans."""

    max_failure_replans: int = 3
    """Budget for failure-triggered replans."""

    # ── Loop accumulators ────────────────────────────────────────────
    # Writer: step loop  |  Readers: replan methods, result builder

    context: Any = None  # ExecutionContext — not importable here
    """Variable storage for step outputs (ExecutionContext instance)."""

    step_results: list[StepResult] = field(default_factory=list)
    """Accumulated StepResult objects from completed steps."""

    step_outcomes: list[dict] = field(default_factory=list)
    """Structured step outcome metadata for planner history."""

    remaining_steps: list[PlanStep] = field(default_factory=list)
    """Steps still to be executed (mutated by replan methods)."""

    executed_steps: list[PlanStep] = field(default_factory=list)
    """Steps already executed (for replan context)."""

    execution_vars: dict = field(default_factory=dict)
    """Computed execution variables (recomputed after each replan)."""

    # ── Plan-outcome memory ──────────────────────────────────────────
    # Writer: step loop + replan methods  |  Readers: result builder

    plan_phases: list[dict] = field(default_factory=list)
    """Closed plan phases (each replan opens a new phase)."""

    current_phase: dict = field(default_factory=dict)
    """Currently-open plan phase (step outcomes accumulate here)."""

    # ── Replan counters ──────────────────────────────────────────────
    # Writer: replan methods  |  Readers: replan methods, result builder

    replan_count: int = 0
    """Total replans executed (success + failure)."""

    failure_replan_count: int = 0
    """Failure-specific replan count (separate budget)."""

    budget_exhausted: bool = False
    """Set when success replan budget is hit — remaining steps execute as-is."""

    stagnation_aborted: bool = False
    """Set when stagnation abort threshold triggers an early return."""

    consecutive_no_mutation_replans: int = 0
    """Stagnation counter: consecutive replan cycles with no file mutations."""

    pre_replan_mutation_count: int = 0
    """File mutations before last replan (for stagnation diff)."""

    # ── Code fixer degradation ───────────────────────────────────────
    # Writer: step loop + failure replan  |  Readers: failure replan

    consecutive_fixer_error_iterations: int = 0
    """Count of consecutive steps with persistent code fixer errors."""

    fixer_degradation_applied: bool = False
    """One-time budget penalty flag per degradation episode."""

    # ── Anchor map cache ─────────────────────────────────────────────
    # Writer: _accumulate_anchor_maps  |  Readers: _request_continuation

    active_anchor_maps: dict[str, str] = field(default_factory=dict)
    """Per-execution anchor maps for file_read steps, keyed by file path.

    Accumulates formatted anchor map text for files read during this
    execution.  Injected into replan context on continuation calls.
    Scoped to PlanExecState (not the Orchestrator singleton) so
    concurrent tasks cannot clobber each other's maps.

    Populated only at continuation replan checkpoints
    (_handle_continuation_replan); failure replan checkpoints pass
    whatever has been accumulated so far.
    """
