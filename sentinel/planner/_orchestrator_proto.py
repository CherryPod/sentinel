"""Protocol defining the shared state contract for orchestrator mixins.

Each mixin type-hints ``self: OrchestratorServices`` on methods that
access shared state, giving IDE autocomplete and catching attribute
typos at type-check time.

Every method that one mixin calls on another must have a signature here.
This ensures mypy can catch interface violations at lint time, and
``@runtime_checkable`` catches missing attributes at startup.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import asyncio

    from sentinel.core.bus import EventBus
    from sentinel.core.models import (
        Plan,
        PlanStep,
        StepResult,
        TaskResult,
    )
    from sentinel.memory.episodic import EpisodicStore
    from sentinel.security.conversation import ConversationAnalyzer
    from sentinel.security.conversation.monitor import MultiTurnMonitor
    from sentinel.security.pipeline import ScanPipeline
    from sentinel.session.store import SessionStore
    from sentinel.tools._handlers._task_exec_context import TaskExecutionContext
    from sentinel.worker.base import EmbeddingBase, PlannerBase
    from sentinel.worker.context import WorkerContext

    from ._task_context import PlanExecState, TaskContext
    from .safe_tools import SafeToolHandlers


@runtime_checkable
class OrchestratorServices(Protocol):
    """Attributes and methods available to orchestrator mixins via ``self``.

    Attributes are the shared state that the Orchestrator ``__init__``
    sets up.  Methods are the cross-mixin calls — one mixin calling
    into another mixin's implementation.
    """

    # ------------------------------------------------------------------
    # Shared state (set in Orchestrator.__init__)
    # ------------------------------------------------------------------
    _planner: PlannerBase
    _pipeline: ScanPipeline
    _tool_executor: object  # ToolExecutor (avoid circular import)
    _approval_manager: object | None
    _session_store: SessionStore | None
    _conversation_analyzer: ConversationAnalyzer | None
    _multi_turn_monitor: MultiTurnMonitor | None
    _memory_store: object | None
    _embedding_client: EmbeddingBase | None
    _event_bus: EventBus | None
    _routine_store: object | None
    _routine_engine: object | None
    _contact_store: object | None
    _domain_summary_store: object | None
    _reranker: object | None
    _insight_store: object | None
    _safe_tool_handlers: SafeToolHandlers
    _worker_contexts: dict[str, WorkerContext]
    _worker_context_accessed: dict[str, float]
    _episodic_store: EpisodicStore | None
    _strategy_store: object | None
    _shutting_down: bool
    _background_tasks: set[asyncio.Task]
    _task_owners: dict[str, int]

    # Class-level constants
    MAX_JUDGE_REPLANS: int

    # ------------------------------------------------------------------
    # Cross-mixin methods (Orchestrator core)
    # ------------------------------------------------------------------

    async def _emit(self, task_id: str, event: str, data: dict | None = None) -> None:
        """Fire-and-forget event publish."""
        ...

    # ------------------------------------------------------------------
    # ExecutionMixin methods (called from orchestrator.py)
    # ------------------------------------------------------------------

    async def _execute_plan(
        self,
        plan: Plan,
        user_input: str | None = None,
        task_id: str = "",
        session_id: str | None = None,
        user_id: int | None = None,
        effective_tl: int | None = None,
        available_tools: list[dict] | None = None,
        task_exec_context: TaskExecutionContext | None = None,
    ) -> TaskResult:
        """Execute all steps in a plan sequentially, with dynamic replanning."""
        ...

    # ------------------------------------------------------------------
    # ReplanMixin methods (called from _execution.py)
    # ------------------------------------------------------------------

    async def _handle_continuation_replan(
        self,
        state: PlanExecState,
        step: PlanStep,
        result: StepResult,
    ) -> TaskResult | None:
        """Handle success-triggered dynamic replanning checkpoint."""
        ...

    async def _handle_failure_replan(
        self,
        state: PlanExecState,
        step: PlanStep,
        result: StepResult,
        exec_meta: dict | None,
    ) -> TaskResult | None:
        """Handle failure-triggered replanning for soft_failed steps."""
        ...

    # ------------------------------------------------------------------
    # VerificationMixin methods (called from orchestrator.py)
    # ------------------------------------------------------------------

    async def _evaluate_task_assertions(
        self, ctx: TaskContext, loop_label: str
    ) -> None:
        """Collect and evaluate assertions from all plan phases."""
        ...

    async def _invoke_judge(self, ctx: TaskContext, loop_label: str) -> bool:
        """Classify task and invoke planner-as-judge if needed.

        Returns True if judge-driven replan should be attempted.
        """
        ...

    async def _attempt_judge_replan(
        self,
        ctx: TaskContext,
        judge_replan_count: int,
        loop_label: str,
    ) -> bool:
        """Request a new plan after judge says goal was not met."""
        ...

    # ------------------------------------------------------------------
    # EpisodicMixin methods (called from orchestrator.py)
    # ------------------------------------------------------------------

    async def _store_episodic_record(
        self,
        session_id: str,
        task_id: str,
        user_request: str,
        task_status: str,
        plan_summary: str,
        step_outcomes: list[dict],
        original_request: str | None = None,
        prior_error_summary: str | None = None,
        plan_phases: list[dict] | None = None,
        completion: str = "full",
        goal_actions_executed: bool | None = None,
        file_mutations: list[dict] | None = None,
        assertion_failures: list[dict] | None = None,
        tool_output_warnings: list[dict] | None = None,
        judge_verdict: dict | None = None,
    ) -> None:
        """Store a structured episodic record after task completion."""
        ...
