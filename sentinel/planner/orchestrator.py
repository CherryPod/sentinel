"""Orchestrator — top-level task lifecycle coordinator.

Routes incoming user requests through a staged pipeline:
  Stage A: pre-processing (trust, session, contacts, input scan)
  Stage B: planner preparation (tools, history, memory)
  Stage C: plan creation (planner invocation)
  Stage D: approval gate
  Stage E: execution, verification, and post-processing

Delegates heavy lifting to mixins (ExecutionMixin, ReplanMixin,
VerificationMixin, EpisodicMixin, IntakeProcessingMixin,
PlanCreationMixin, ApprovalGateMixin, PostProcessingMixin)
via OrchestratorServices protocol.
"""

import asyncio
import logging
import time
import uuid

from sentinel.core.bus import EventBus
from sentinel.core.config import settings
from sentinel.core.context import (
    current_task_id,
    current_user_id,
    require_user_id,
    resolve_trust_level,
)
from sentinel.core.models import (
    Plan,
    TaskResult,
)
from sentinel.crypto.blind_index import log_hash
from sentinel.memory.episodic import EpisodicStore
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.security.pipeline import ScanPipeline
from sentinel.session._session_audit import (
    _maybe_emit_session_crash_reconciliation,
)
from sentinel.session.store import ConversationTurn, SessionStore
from sentinel.worker.base import EmbeddingBase, PlannerBase
from sentinel.worker.context import WorkerContext

from ._approval_gate import ApprovalGateMixin
from ._episodic import EpisodicMixin
from ._execution import (
    ExecutionContext,
    ExecutionMixin,
    _build_replan_summary,
    _categorise_error,
    _extract_prior_error,
    _failure_fingerprint,
    _truncate_plan_prompts,
)
from ._intake_processing import IntakeProcessingMixin
from ._orchestrator_deps import OrchestratorDeps
from ._plan_creation import PlanCreationMixin
from ._post_processing import PostProcessingMixin
from ._replan import ReplanMixin
from ._task_context import TaskContext
from ._verification import VerificationMixin, _should_invoke_judge
from .builders import auto_store_memory
from .safe_tools import SafeToolHandlers

logger = logging.getLogger(__name__)

# How long to keep idle worker contexts before eviction (seconds)
_WORKER_CONTEXT_TTL = 3600
# Event bus publish timeout — prevents a misbehaving subscriber handler
# from blocking the plan execution pipeline indefinitely.
_EVENT_EMIT_TIMEOUT = 5.0

# ── Re-exports for backward compatibility ────────────────────────
# Tests and external code may import these from orchestrator.py.
# The actual implementations now live in the mixin modules.
__all__ = [
    "ExecutionContext",
    "Orchestrator",
    "OrchestratorDeps",
    "_build_replan_summary",
    "_categorise_error",
    "_extract_prior_error",
    "_failure_fingerprint",
    "_should_invoke_judge",
    "_truncate_plan_prompts",
]


class Orchestrator(
    IntakeProcessingMixin,
    PlanCreationMixin,
    ApprovalGateMixin,
    PostProcessingMixin,
    ExecutionMixin,
    ReplanMixin,
    VerificationMixin,
    EpisodicMixin,
):
    """Main CaMeL execution loop: plan → execute → scan → return."""

    # Maximum judge-driven replans per task execution.
    # Used in both _execute_and_verify (loop control) and
    # _attempt_judge_replan (budget check).
    MAX_JUDGE_REPLANS: int = 1

    def __init__(
        self,
        planner: PlannerBase,
        pipeline: ScanPipeline,
        tool_executor=None,
        approval_manager=None,
        session_store: SessionStore | None = None,
        conversation_analyzer: ConversationAnalyzer | None = None,
        multi_turn_monitor: "MultiTurnMonitor | None" = None,
        memory_store=None,
        embedding_client: EmbeddingBase | None = None,
        event_bus: EventBus | None = None,
        routine_store=None,
        routine_engine=None,
        contact_store=None,
        domain_summary_store=None,  # Deprecated: use wire_late_deps()
        reranker=None,  # Deprecated: use wire_late_deps()
        insight_store=None,
    ):
        self._planner = planner
        self._pipeline = pipeline
        self._tool_executor = tool_executor
        self._approval_manager = approval_manager
        self._session_store = session_store
        self._conversation_analyzer = conversation_analyzer
        self._multi_turn_monitor = multi_turn_monitor
        self._memory_store = memory_store
        self._embedding_client = embedding_client
        self._event_bus = event_bus
        self._routine_store = routine_store
        self._routine_engine = routine_engine
        self._contact_store = contact_store
        self._domain_summary_store = domain_summary_store
        self._reranker = reranker
        self._insight_store = insight_store
        self._safe_tool_handlers = SafeToolHandlers(
            planner=planner,
            pipeline=pipeline,
            memory_store=memory_store,
            embedding_client=embedding_client,
            session_store=session_store,
            event_bus=event_bus,
            routine_store=routine_store,
            routine_engine=routine_engine,
        )
        # F3: Per-session worker turn buffers (in-memory, never persisted).
        # No lock needed: asyncio is single-threaded and all mutations
        # happen without an intervening await, so no interleaving is possible.
        self._worker_contexts: dict[str, WorkerContext] = {}
        # SYS-6: TTL tracking for _worker_contexts eviction (monotonic seconds)
        self._worker_context_accessed: dict[str, float] = {}
        self._episodic_store: EpisodicStore | None = None
        self._strategy_store = None
        # SYS-5a: Shutdown coordination — checked by _execute_plan before each step
        self._shutting_down: bool = False
        # SYS-5b: Track background tasks for graceful cancellation on shutdown.
        # ASYNCIO SAFETY: _background_tasks is mutated via .add() in
        # _episodic.py and .discard() via done-callback.  Both are
        # synchronous set operations that complete atomically between
        # await points on the single-threaded event loop — no lock
        # needed.  shutdown() iterates the set synchronously before any
        # await, so no concurrent mutation during iteration.
        # ⚠ If this ever moves to multi-threaded execution, add an
        # explicit asyncio.Lock around all _background_tasks access.
        self._background_tasks: set[asyncio.Task] = set()
        # Cross-user isolation: map task_id → user_id for ownership checks.
        # ASYNCIO SAFETY: _task_owners is mutated only via
        # _register_task_owner() which is a synchronous dict assignment
        # (no await between read and write).  Reads in get_task_owner()
        # are also synchronous.  The single-threaded event loop
        # guarantees no interleaving between these operations.
        # ⚠ If this ever moves to multi-threaded execution, add an
        # explicit asyncio.Lock around all _task_owners access.
        self._task_owners: dict[str, int] = {}
        # Immutable config after startup (audit §6) — once freeze() is called,
        # all set_*() methods raise RuntimeError to prevent runtime mutation
        self._frozen: bool = False

    def freeze(self) -> None:
        """Lock configuration — all set_*() methods raise after this call.

        Called at the end of startup after all post-init wiring is complete.
        Prevents accidental runtime mutation of service dependencies.
        """
        self._frozen = True
        logger.info(
            "Orchestrator configuration frozen",
            extra={"event": "orchestrator.freeze"},
        )

    def _check_frozen(self, method_name: str) -> None:
        """Raise if configuration is frozen (called by all set_*() methods)."""
        if self._frozen:
            raise RuntimeError(
                f"Cannot call {method_name}() after freeze() — "
                "orchestrator configuration is immutable after startup"
            )

    def set_routine_engine(self, engine) -> None:
        """Set routine engine after construction (breaks circular dep)."""
        self._check_frozen("set_routine_engine")
        self._routine_engine = engine
        self._safe_tool_handlers.set_routine_engine(engine)

    def wire_late_deps(
        self,
        deps: OrchestratorDeps | None = None,
        *,
        episodic_store=None,
        domain_summary_store=None,
        strategy_store=None,
        reranker=None,
    ) -> None:
        """Wire late-binding dependencies after all startup tiers complete.

        Replaces the former individual ``set_episodic_store``,
        ``set_domain_summary_store``, ``set_strategy_store``, and
        ``set_reranker`` methods with a single atomic call.  Must be
        called before ``freeze()``.

        Accepts either an ``OrchestratorDeps`` dataclass or keyword
        arguments directly (so callers don't need to import the dataclass).
        """
        self._check_frozen("wire_late_deps")
        if deps is not None:
            episodic_store = deps.episodic_store
            domain_summary_store = deps.domain_summary_store
            strategy_store = deps.strategy_store
            reranker = deps.reranker
        self._episodic_store = episodic_store
        self._safe_tool_handlers.set_episodic_store(episodic_store)
        self._domain_summary_store = domain_summary_store
        self._strategy_store = strategy_store
        self._reranker = reranker
        logger.info(
            "Late dependencies wired",
            extra={
                "event": "orchestrator.wire_late_deps",
                "has_episodic": episodic_store is not None,
                "has_domain_summary": domain_summary_store is not None,
                "has_strategy": strategy_store is not None,
                "has_reranker": reranker is not None,
            },
        )

    def get_task_owner(self, task_id: str) -> int | None:
        """Return the user_id that owns a task, or None if unknown.

        Logs a security warning when the caller's current_user_id does not
        match the task owner — provides an audit trail even if the API layer
        fails to enforce authorization.
        """
        owner = self._task_owners.get(task_id)
        caller_uid = current_user_id.get()
        logger.debug(
            "get_task_owner lookup",
            extra={
                "event": "orchestrator.get_task_owner",
                "task_id": task_id,
                "found": owner is not None,
                "caller_uid": caller_uid,
            },
        )
        # Defence-in-depth: warn on cross-user task queries so SOC can
        # detect misuse even if the caller forgets to enforce authorization.
        if owner is not None and caller_uid != 0 and caller_uid != owner:
            logger.warning(
                "Cross-user task owner query — caller does not own task",
                extra={
                    "event": "orchestrator.get_task_owner.cross_user",
                    "task_id": task_id,
                    "owner_uid": owner,
                    "caller_uid": caller_uid,
                },
            )
        return owner

    def _register_task_owner(self, task_id: str, user_id: int) -> None:
        """Record task ownership for cross-user isolation checks."""
        logger.debug(
            "Registering task owner",
            extra={
                "event": "orchestrator.registertaskowner",
                "task_id": task_id,
                "user_id": user_id,
            },
        )
        self._task_owners[task_id] = user_id

    def _evict_stale_contexts(self) -> None:
        """Remove worker contexts older than 1 hour.

        Safe without a lock: asyncio is single-threaded and there is no
        await in this loop, so no other coroutine can interleave.
        """
        now_mono = time.monotonic()
        stale = [
            sid
            for sid, ts in self._worker_context_accessed.items()
            if now_mono - ts > _WORKER_CONTEXT_TTL
        ]
        for sid in stale:
            self._worker_contexts.pop(sid, None)
            self._worker_context_accessed.pop(sid, None)

    @property
    def approval_manager(self) -> object | None:
        """Public access to the approval manager (or None)."""
        return self._approval_manager

    async def check_approval(self, approval_id: str) -> dict:
        """Check status of an approval request. Returns {"status": "not_found"} if no manager."""
        if self._approval_manager is None:
            return {"status": "not_found"}
        return await self._approval_manager.check_approval(approval_id)

    async def submit_approval(
        self,
        approval_id: str,
        granted: bool,
        reason: str = "",
        approved_by: str = "api",
        source_key: str | None = None,
    ) -> bool:
        """Submit an approval decision. Returns False if no manager.

        ``source_key`` is threaded through to ApprovalManager where, when
        provided, it enforces transport-session binding (Q3-F4): an
        approval created under source_key X cannot be submitted under a
        different source_key Y, even for the same user. Callers that
        don't bind to a transport-session pass None (default).
        """
        if self._approval_manager is None:
            return False
        return await self._approval_manager.submit_approval(
            approval_id=approval_id,
            granted=granted,
            reason=reason,
            approved_by=approved_by,
            source_key=source_key,
        )

    def set_channel_registry(self, channel_registry: object) -> None:
        """Forward channel registry to the tool executor for dynamic handler registration."""
        self._check_frozen("set_channel_registry")
        if self._tool_executor is not None:
            self._tool_executor.set_channel_registry(channel_registry)

    async def shutdown(self) -> None:
        """Signal the orchestrator to stop processing new plan steps.

        In-flight plans will exit early at the next step boundary.
        """
        self._shutting_down = True
        # Cancel tracked background tasks (domain summary refreshes, etc.)
        for task in self._background_tasks:
            task.cancel()
        logger.info(
            "Orchestrator shutdown requested — in-flight plans will stop at next step boundary",
            extra={
                "event": "orchestrator.orchestrator_shutdown",
                "cancelled_bg_tasks": len(self._background_tasks),
            },
        )

    async def _emit(self, task_id: str, event: str, data: dict | None = None) -> None:
        """Fire-and-forget event publish. No-op if event bus not configured."""
        if self._event_bus is not None and task_id:
            try:
                await asyncio.wait_for(
                    self._event_bus.publish(f"task.{task_id}.{event}", data or {}),
                    timeout=_EVENT_EMIT_TIMEOUT,
                )
            except TimeoutError:
                logger.warning(
                    "Event publish timed out (non-fatal)",
                    exc_info=True,
                    extra={
                        "event": "orchestrator.emit.timeout",
                        "topic": event,
                        "task_id": task_id,
                        "timeout_s": _EVENT_EMIT_TIMEOUT,
                    },
                )
            except Exception as exc:  # catch-all: event publish best-effort
                logger.warning(
                    "Event publish failed (non-fatal)",
                    exc_info=True,
                    extra={
                        "event": "orchestrator.emit.failed",
                        "topic": event,
                        "task_id": task_id,
                        "error": str(exc),
                    },
                )

    async def plan_and_execute(
        self,
        user_request: str,
        source: str = "api",
        approval_mode: str = "auto",
        source_key: str | None = None,
        task_id: str | None = None,
        input_pre_scanned: bool = True,
        user_request_data_id: str | None = None,
    ) -> TaskResult:
        """Plan and execute a task — input already scanned by router.

        Called by MessageRouter after input scanning.  Skips the S1 input
        scan (the router already ran it), goes straight to conversation
        analysis, F2 interrupted task detection, Claude planning, and
        execution.

        D42 (FL-C79-a2): no longer accepts a pre-loaded ``session``
        argument.  The router previously threaded its pre-acquire snapshot
        in here, which then got smuggled all the way down to writes inside
        the lock that washed concurrent counter bumps.  The session is now
        always reloaded by ``bind_session`` from inside the per-session
        lock (acquired below) and only the boolean ``input_pre_scanned``
        signal crosses the boundary.

        ``user_request_data_id`` — Q8.fix.a ingress-time provenance id
        threaded from the channel/API adapter. Symmetric with ``handle_task``.
        """
        if self._shutting_down:
            return TaskResult(
                status="error",
                reason="Server is shutting down — not accepting new tasks",
            )

        self._evict_stale_contexts()

        task_id = task_id or str(uuid.uuid4())
        self._register_task_owner(task_id, current_user_id.get())
        task_id_token = current_task_id.set(task_id)
        task_t0 = time.monotonic()
        auto_approved = False
        # Q14-F3 (amendment): declared before the try so `finally` always has
        # a defined name to consult, even if setup raises before acquire.
        # `lock_held` gates release — Q14a-r2 round-2 fix: if acquire() raises
        # (e.g. CancelledError), session_lock is non-None but unacquired and
        # release() on it would raise RuntimeError, masking the original exc.
        session_lock = None
        lock_held = False

        try:
            # Q14-F3 (amendment): router-path entry point mirrors handle_task
            # — catch-all keeps the planner soft-fail contract for plan_and_execute,
            # try widened to cover pre-inner range (logger.info with
            # len(user_request), per-session-lock setup + acquire).
            logger.info(
                "Task received (router path)",
                extra={
                    "event": "orchestrator.task_received",
                    "task_id": task_id,
                    "source": source,
                    "source_channel": source_key.split(":", 1)[0]
                    if source_key and ":" in source_key
                    else None,
                    "source_key_hash": log_hash(source_key),
                    "source_key_len": len(source_key or ""),
                    "request_len": len(user_request),
                    "router_path": True,
                    "user_request_data_id": user_request_data_id,
                },
            )

            # Per-session lock (same as handle_task)
            if source_key is not None and self._session_store is not None:
                session_lock = self._session_store.get_lock(source_key)
            if session_lock is not None:
                await session_lock.acquire()
                lock_held = True

            return await self._handle_task_inner(
                user_request,
                source,
                approval_mode,
                source_key,
                task_id,
                task_t0,
                auto_approved,
                input_pre_scanned=input_pre_scanned,
                user_request_data_id=user_request_data_id,
            )
        except Exception as exc:
            # Q14-F3: catch-all mirrors handle_task. Deliberate wire-contract
            # consistency between the two public entry points (same reason
            # string, same event name). CancelledError is BaseException and
            # still propagates.
            logger.error(
                "Task handling failed unexpectedly",
                extra={
                    "event": "orchestrator.task_failed",
                    "task_id": task_id,
                    "source": source,
                    "router_path": True,
                    "error": str(exc),
                },
                exc_info=True,
            )
            await self._emit(
                task_id,
                "error",
                {"reason": "Request processing failed"},
            )
            return TaskResult(status="error", reason="Request processing failed")
        finally:
            current_task_id.reset(task_id_token)
            if lock_held:
                session_lock.release()

    async def handle_task(
        self,
        user_request: str,
        source: str = "api",
        approval_mode: str = "auto",
        source_key: str | None = None,
        task_id: str | None = None,
        user_request_data_id: str | None = None,
    ) -> TaskResult:
        """Full CaMeL pipeline: conversation check → scan → plan → execute → return.

        ``user_request_data_id`` is the Q8.fix.a ingress-time provenance id:
        the adapter at the channel/API boundary mints a TaggedData wrapping
        ``user_request`` as UNTRUSTED, and threads the id through so downstream
        S3 checks (``is_trust_safe_for_execution``) resolve to the ingress-time
        record. None when no adapter wrapped (e.g. legacy callers) — downstream
        code treats absence as "not yet tagged" rather than TRUSTED.
        """
        if self._shutting_down:
            return TaskResult(
                status="error",
                reason="Server is shutting down — not accepting new tasks",
            )

        # SYS-6/U2: Evict stale worker contexts (older than 1 hour)
        self._evict_stale_contexts()

        task_id = task_id or str(uuid.uuid4())
        self._register_task_owner(task_id, current_user_id.get())
        task_id_token = current_task_id.set(task_id)
        task_t0 = time.monotonic()
        auto_approved = False
        # Q14-F3 (amendment): declared before the try so `finally` always has
        # a defined name to consult, even if setup raises before acquire.
        # `lock_held` gates release — Q14a-r2 round-2 fix: if acquire() raises
        # (e.g. CancelledError), session_lock is non-None but unacquired and
        # release() on it would raise RuntimeError, masking the original exc.
        session_lock = None
        lock_held = False

        try:
            # Q14-F3 (amendment): try widened to cover the pre-inner range
            # (logger.info with len(user_request), per-session-lock setup +
            # acquire) so an unexpected exception here still becomes a
            # structured TaskResult and the token is reset via finally.
            logger.info(
                "Task received",
                extra={
                    "event": "orchestrator.task_received",
                    "task_id": task_id,
                    "source": source,
                    "source_channel": source_key.split(":", 1)[0]
                    if source_key and ":" in source_key
                    else None,
                    "source_key_hash": log_hash(source_key),
                    "source_key_len": len(source_key or ""),
                    "request_len": len(user_request),
                    "user_request_data_id": user_request_data_id,
                },
            )

            # SYS-4: Per-session lock — serialises concurrent requests for
            # the same session while allowing different sessions to proceed
            # in parallel. Acquired before any session operations and held
            # through the entire task.
            if source_key is not None and self._session_store is not None:
                session_lock = self._session_store.get_lock(source_key)
            if session_lock is not None:
                await session_lock.acquire()
                lock_held = True

            return await self._handle_task_inner(
                user_request,
                source,
                approval_mode,
                source_key,
                task_id,
                task_t0,
                auto_approved,
                user_request_data_id=user_request_data_id,
            )
        except Exception as exc:
            # Q14-F3: catch-all keeps the planner soft-fail contract — unexpected
            # exceptions from any stage become a structured TaskResult instead of
            # escaping to the channel / API caller. CancelledError is BaseException
            # and still propagates. Mirrors execute_approved_plan's pattern.
            logger.error(
                "Task handling failed unexpectedly",
                extra={
                    "event": "orchestrator.task_failed",
                    "task_id": task_id,
                    "source": source,
                    "error": str(exc),
                },
                exc_info=True,
            )
            await self._emit(
                task_id,
                "error",
                {"reason": "Request processing failed"},
            )
            return TaskResult(status="error", reason="Request processing failed")
        finally:
            current_task_id.reset(task_id_token)
            if lock_held:
                session_lock.release()

    async def _handle_task_inner(
        self,
        user_request: str,
        source: str,
        approval_mode: str,
        source_key: str | None,
        task_id: str,
        task_t0: float,
        auto_approved: bool,
        input_pre_scanned: bool = False,
        user_request_data_id: str | None = None,
    ) -> TaskResult:
        """Inner body of handle_task, called under the per-session lock.

        Thin orchestrator that delegates to stage methods:
          A: _preprocess_task — trust, session, scan, contacts
          B: _prepare_planner_context — tools, history, memory
          C: _create_plan — planner invocation
          D: _check_approval — approval gate
          E: _execute_and_verify — execute + judge loop
          Post: _post_process_task — episodic + turn recording
          Finally: _cleanup_task — clear task-in-progress flag

        ``input_pre_scanned`` — D42 (FL-C79-a2): scalar signal that the
        router already ran S1 input scan and the orchestrator should
        skip the duplicate scan.  Replaces the prior
        ``pre_scanned_session: Session | None`` carrier; the orchestrator
        now always reloads the ``Session`` object from the store inside
        the per-session lock via ``bind_session``, so router-side stale
        snapshots can no longer wash concurrent intra-lock writes.

        ``user_request_data_id`` — Q8.fix.a ingress-time TaggedData id. Threaded
        into TaskContext so downstream stages (S3 provenance gate, audit
        emission) can resolve back to the UNTRUSTED ingress record.
        """
        ctx = TaskContext(
            user_request=user_request,
            source=source,
            approval_mode=approval_mode,
            source_key=source_key,
            task_id=task_id,
            task_t0=task_t0,
            auto_approved=auto_approved,
            input_pre_scanned=input_pre_scanned,
            user_request_data_id=user_request_data_id,
        )

        # try/finally wraps the entire pipeline so _cleanup_task always
        # runs after _preprocess_task sets session.task_in_progress = True.
        # _cleanup_task is safe to call even when no session was bound.
        try:
            # Stage A: Pre-processing (trust, session, scan, contacts)
            blocked = await self._preprocess_task(ctx)
            if blocked:
                return blocked

            # Stage B: Prepare planner context (tools, history, memory)
            await self._prepare_planner_context(ctx)

            # Stage C: Create plan
            plan_result = await self._create_plan(ctx)
            if plan_result:  # early return (timeout, refusal, error)
                return plan_result

            # Stage D: Approval gate
            approval_result = await self._check_approval(ctx)
            if approval_result:  # waiting for approval
                return approval_result

            # Stage E: Execute + judge + verify
            await self._execute_and_verify(ctx)

            # Post-processing: episodic + turn recording
            await self._post_process_task(ctx)

            return ctx.result
        finally:
            await self._cleanup_task(ctx)

    # ── Stage methods moved to mixins ─────────────────────────────
    # Stage A: IntakeProcessingMixin (_preprocess_task, _bind_and_validate_session)
    # Stage B+C: PlanCreationMixin (_prepare_planner_context, _create_plan)
    # Stage D: ApprovalGateMixin (_check_approval, _validate_approval)
    # Post: PostProcessingMixin (_post_process_task, _cleanup_task)

    # ── Stage E: stays on Orchestrator (coordinates all mixins) ─────

    async def _execute_and_verify(self, ctx: TaskContext) -> None:
        """Stage E: Execute plan with judge-driven replan loop.

        Runs the plan, evaluates assertions, invokes the judge (Tier 2),
        and retries if the judge says the goal was not met.  Populates
        ctx.result and ctx.task_elapsed.
        """
        judge_replan_count = 0

        logger.debug(
            "Stage E: execution loop starting",
            extra={
                "event": "orchestrator.stage_e_start",
                "task_id": ctx.task_id,
                "self.MAX_JUDGE_REPLANS": self.MAX_JUDGE_REPLANS,
            },
        )

        while True:
            loop_label = (
                f"attempt_{judge_replan_count}" if judge_replan_count > 0 else "initial"
            )
            logger.debug(
                "Execution loop: starting %s (judge_replan_count=%d/%d)",
                loop_label,
                judge_replan_count,
                self.MAX_JUDGE_REPLANS,
                extra={
                    "event": "orchestrator.exec_loop_start",
                    "task_id": ctx.task_id,
                    "attempt": loop_label,
                    "judge_replan_count": judge_replan_count,
                    "self.MAX_JUDGE_REPLANS": self.MAX_JUDGE_REPLANS,
                },
            )

            # Per-task execution context — scoped to this plan execution,
            # replaces singleton state on ToolExecutor (H10).
            from sentinel.tools._handlers._task_exec_context import TaskExecutionContext

            ctx.task_exec_context = TaskExecutionContext()

            # Execute the plan
            ctx.result = await self._execute_plan(
                ctx.plan,
                user_input=ctx.user_request,
                task_id=ctx.task_id,
                session_id=ctx.session_id,
                user_id=ctx.contact_result.user_id,
                effective_tl=ctx.effective_tl,
                available_tools=ctx.available_tools,
                task_exec_context=ctx.task_exec_context,
            )
            ctx.result.task_id = ctx.task_id
            ctx.result.conversation = ctx.conv_info
            ctx.result.planner_usage = ctx.planner_usage

            ctx.task_elapsed = time.monotonic() - ctx.task_t0
            logger.info(
                "Task execution completed (%s)",
                loop_label,
                extra={
                    "event": "orchestrator.task_completed",
                    "task_id": ctx.task_id,
                    "status": ctx.result.status,
                    "plan_summary_len": (
                        len(ctx.plan.plan_summary) if ctx.plan.plan_summary else 0
                    ),
                    "plan_step_count": len(ctx.plan.steps),
                    "elapsed_s": round(ctx.task_elapsed, 2),
                    "attempt": loop_label,
                },
            )

            # Event: task completed
            await self._emit(
                ctx.task_id,
                "completed",
                {
                    "status": ctx.result.status,
                    "plan_summary": ctx.result.plan_summary,
                    "elapsed_s": round(ctx.task_elapsed, 2),
                    "response": ctx.result.response,
                    "step_results": [
                        {
                            "step_id": sr.step_id,
                            "status": sr.status,
                            "content": sr.content,
                            "error": sr.error,
                        }
                        for sr in ctx.result.step_results
                    ],
                },
            )

            # Auto-memory: store a brief summary of successful tasks
            if (
                ctx.result.status == "success"
                and settings.auto_memory
                and self._memory_store is not None
            ):
                await auto_store_memory(
                    user_request=ctx.user_request,
                    plan_summary=ctx.plan.plan_summary,
                    memory_store=self._memory_store,
                    embedding_client=self._embedding_client,
                )

            # Tier 2: evaluate assertions, invoke judge, decide retry
            should_retry, judge_replan_count = await self._evaluate_and_decide_retry(
                ctx, loop_label, judge_replan_count
            )
            if not should_retry:
                break

        logger.debug(
            "Stage E: execution loop complete",
            extra={
                "event": "orchestrator.stage_e_complete",
                "task_id": ctx.task_id,
                "status": ctx.result.status,
                "completion": ctx.result.completion,
                "judge_replans": judge_replan_count,
            },
        )

        # Extension point: post-execution enrichers would run here

    async def _evaluate_and_decide_retry(
        self,
        ctx: TaskContext,
        loop_label: str,
        judge_replan_count: int,
    ) -> tuple[bool, int]:
        """Evaluate execution result and decide whether to retry.

        Logs Tier 1 signals, runs assertion evaluation, invokes the
        planner-as-judge (Tier 2), and attempts a judge-driven replan
        if the judge says the goal was not met.

        Returns (should_retry, updated_judge_replan_count).
        should_retry=True means the caller should loop; False means break.
        """
        # Tier 1 signal logging
        logger.debug(
            "Post-execution: Tier 1 signals — status=%s, completion=%s, "
            "goal_actions=%s, mutations=%d, warnings=%d",
            ctx.result.status,
            ctx.result.completion,
            ctx.result.goal_actions_executed,
            len(ctx.result.file_mutations) if ctx.result.file_mutations else 0,
            len(ctx.result.tool_output_warnings)
            if ctx.result.tool_output_warnings
            else 0,
            extra={
                "event": "orchestrator.post_exec_tier1_signals",
                "task_id": ctx.task_id,
                "attempt": loop_label,
            },
        )

        # Evaluate assertions and invoke judge
        await self._evaluate_task_assertions(ctx, loop_label)

        judge_says_retry = await self._invoke_judge(ctx, loop_label)

        # Judge-driven replan
        if judge_says_retry:
            judge_replan_count += 1
            replan_ok = await self._attempt_judge_replan(
                ctx, judge_replan_count, loop_label
            )
            if replan_ok:
                return True, judge_replan_count

        return False, judge_replan_count

    async def execute_approved_plan(self, approval_id: str) -> TaskResult:
        """Execute a plan that has been approved via the approval flow."""
        validation = await self._validate_approval(approval_id)
        if isinstance(validation, TaskResult):
            return validation
        pending, plan = validation

        t0 = time.monotonic()

        # SYS-4: Resolve session_id for the approval flow so worker context
        # (F3) works correctly during approved plan execution.
        source_key = pending.get("source_key", "")
        session_id: str | None = None
        session = None

        # Resolve user_id from ContextVar — approval manager now stores and
        # filters by user_id, so the caller's context is already correct.
        # Resolve per-user trust level for approved plan execution
        uid = current_user_id.get()
        _user_tl = None
        if self._contact_store is not None:
            _user_tl = await self._contact_store.get_user_trust_level(uid)
        _eff_tl = resolve_trust_level(_user_tl, settings.trust_level)

        # SYS-4: Per-session lock — same pattern as handle_task/plan_and_execute.
        # Without this, a concurrent request via handle_task can interleave with
        # approved plan execution, corrupting session turn history.
        # C79: `lock_held` gates release per Q14a-r2 round-2 discipline; the
        # acquire moves inside the widened `try:` so cancellation between
        # acquire and the body cannot leak the lock. `task_in_progress_set`
        # gates F2-flag cleanup so an acquire-phase failure cannot erase a
        # stale crash flag that C48 reconciliation must detect on the next
        # approved-plan entry.
        session_lock = None
        lock_held = False
        task_in_progress_set = False
        if source_key and self._session_store is not None:
            session_lock = self._session_store.get_lock(source_key)

        try:
            if session_lock is not None:
                await session_lock.acquire()
                lock_held = True

            if source_key and self._session_store is not None:
                session = await self._session_store.get(source_key)
                if session is not None:
                    session_id = session.session_id

            # C48: Crash-reconciliation audit (Property-D-honest) — runs
            # BEFORE F2 set_task_in_progress(True) so the helper's
            # `WHERE task_in_progress = TRUE` predicate detects the stale
            # crash flag (not the new-task flag we are about to set).
            # In-memory short-circuit avoids a DB roundtrip on the clean-
            # session common case.
            if (
                session is not None
                and session.task_in_progress
                and self._session_store is not None
                and uid
            ):
                await _maybe_emit_session_crash_reconciliation(
                    self._session_store,
                    getattr(self._pipeline, "_audit_emitter", None),
                    session_id=session.session_id,
                    user_id=uid,
                )

            # F2: Set task_in_progress flag (mirrors handle_task pattern).
            # `task_in_progress_set` flips only after both the in-memory
            # and store flags are set — gates the matching cleanup in
            # `finally` against acquire-phase failures clearing a flag
            # the path never set.
            if session is not None:
                session.set_task_in_progress(True)
                if self._session_store is not None:
                    await self._session_store.set_task_in_progress(
                        session.session_id, True
                    )
                task_in_progress_set = True

            result = await self._execute_plan(
                plan,
                user_input=pending.get("user_request") or None,
                session_id=session_id,
                user_id=uid,
                effective_tl=_eff_tl,
            )
            elapsed = round(time.monotonic() - t0, 2)

            # Record the turn in the session so conversation history builds up.
            # In full approval mode, handle_task returns before execution, so
            # we must record the turn here after the plan completes.
            if session is not None:
                turn = ConversationTurn(
                    request_text=pending.get("user_request", ""),
                    result_status=result.status,
                    plan_summary=plan.plan_summary,
                    elapsed_s=elapsed,
                    step_outcomes=result.step_outcomes or None,
                    mtm_turn_score=pending.get("mtm_turn_score", 0.0),
                    mtm_signal_categories=pending.get("mtm_signal_categories", []),
                )
                session.add_turn(turn)
                if self._session_store is not None:
                    await self._session_store.add_turn(
                        session.session_id, turn, session=session
                    )

            return result
        except Exception as exc:
            logger.error(
                "Approved plan execution failed",
                extra={
                    "event": "orchestrator.approved_plan_failed",
                    "approval_id": approval_id,
                    "error": str(exc),
                },
                exc_info=True,
            )
            return TaskResult(
                status="error", reason="Plan execution failed unexpectedly"
            )
        finally:
            # C79: nested finally — `session_lock.release()` MUST run even
            # if the awaited cleanup raises CancelledError. Unlike
            # handle_task / plan_and_execute (which release the lock in
            # the OUTER entry-point finally after _handle_task_inner
            # unwinds), execute_approved_plan owns both the awaited
            # cleanup AND the lock release in the same finally. Without
            # the nested wrap, cancellation inside set_task_in_progress
            # skips release and orphans the lock. CancelledError is
            # BaseException and escapes the inner except.
            try:
                # C79: clear the in-progress flag only if this path actually
                # set it. An acquire-phase failure or cancellation must not
                # erase a stale crash flag that C48 reconciliation needs to
                # detect on the next approved-plan entry.
                if task_in_progress_set and session is not None:
                    session.set_task_in_progress(False)
                    if self._session_store is not None:
                        try:
                            await self._session_store.set_task_in_progress(
                                session.session_id, False
                            )
                        except Exception:  # catch-all: flag clear best-effort
                            logger.warning(
                                "Failed to clear task_in_progress flag — will be stale until next task",
                                extra={
                                    "event": "orchestrator.task_in_progress_clear_failed"
                                },
                                exc_info=True,
                            )
            finally:
                # C79: `lock_held` gates release per Q14a-r2 round-2
                # discipline. Wrapped in nested finally so cancellation
                # inside the awaited cleanup above cannot orphan the lock.
                if lock_held:
                    session_lock.release()

    async def execute_prebuilt_plan(
        self,
        plan: Plan,
        trust_level: int,
        task_id: str | None = None,
        user_id: int | None = None,
    ) -> TaskResult:
        """Execute a pre-built Plan, bypassing planner and approval.

        Used by the B2 red team test endpoint. Runs the full execution path
        (constraint validator, PolicyEngine, scanners, executor) but does NOT
        call the planner, conversation analyser, or approval gate.

        The caller-supplied `trust_level` is threaded into `_execute_plan`
        as `effective_tl`, so TL-gated controls (e.g. S4 constraint
        validation at `_tool_constraints.py:72`) fire at the requested tier.
        The red team endpoint is rate-limited to 1 req/sec which prevents
        overlap between concurrent requests.

        Q9-FL1 absorbed-into-Q6.fix.a — defence-in-depth. Route registration
        at `sentinel/api/init/orchestrator.py:522-540` already gates the
        /api/test/execute-plan route behind `settings.red_team_mode=True`,
        so there is no production caller. This assert hardens against a future route
        misregistration / new callers wiring into this function without the
        same guard.
        """
        assert settings.red_team_mode, (
            "execute_prebuilt_plan must only be reachable when "
            "settings.red_team_mode is True — route guard at "
            "api/init/orchestrator.py:522-540 is the primary enforcement; "
            "this assert is defence-in-depth (Q9-FL1)."
        )
        user_id = require_user_id(user_id, "Orchestrator.execute_prebuilt_plan")
        # Q6.fix.a — Q6-F3. `require_user_id` resolves from param or
        # ContextVar but does not pin. Under the single production caller
        # (a single in-process caller behind UserContextMiddleware) the param and
        # the ContextVar agree by coincidence; under any future caller that
        # passes `user_id=42` while `current_user_id=1` is set (legitimate
        # cross-user admin pattern), downstream audit emits would read the
        # ambient ContextVar and attribute to user 1, not the nominal
        # principal 42. Pin the ContextVar to the resolved user for the
        # duration of the execute_plan await so all downstream emits agree
        # with the declared principal. Reset in finally so the caller's
        # outer scope is restored even on raise.
        user_token = current_user_id.set(user_id)
        try:
            logger.debug(
                "execute_prebuilt_plan called",
                extra={
                    "event": "orchestrator.execute_prebuilt_plan",
                    "step_count": len(plan.steps) if plan else 0,
                    "trust_level": trust_level,
                    "task_id": task_id,
                },
            )
            task_id = task_id or str(uuid.uuid4())
            session_key = f"red_team_{task_id}"
            self._worker_contexts[session_key] = WorkerContext(
                session_id=session_key,
            )
            self._worker_context_accessed[session_key] = time.monotonic()
            try:
                result = await self._execute_plan(
                    plan,
                    user_input=None,
                    task_id=task_id,
                    session_id=session_key,
                    user_id=user_id,
                    effective_tl=trust_level,
                )
            finally:
                self._worker_contexts.pop(session_key, None)
                self._worker_context_accessed.pop(session_key, None)

            result.task_id = task_id
            return result
        finally:
            current_user_id.reset(user_token)
