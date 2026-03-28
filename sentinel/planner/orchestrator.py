import asyncio
import hashlib
import html as html_module
import json
import logging
import re
import time
import uuid

from sentinel.core.bus import EventBus
from sentinel.core.context import current_task_id, current_user_id, resolve_trust_level, spawn_task
# Variable reference pattern: matches $lowercase_with_underscores_and_digits.
# Shared across resolve_text, resolve_text_safe, and get_referenced_data_ids
# to ensure consistent behaviour. Broad \w+ would match $HOME/$PATH which
# causes false-positive provenance blocks.
_VAR_RE = r"\$[a-z_][a-z0-9_]*"
from sentinel.core.models import (
    DataSource,
    OutputDestination,
    Plan,
    PlanStep,
    StepResult,
    TaggedData,
    TaskResult,
    TrustLevel,
)
from sentinel.core.config import settings
from sentinel.planner.verification import (
    check_goal_actions_executed,
    extract_file_mutations,
    scan_tool_output,
    check_stagnation,
    detect_idempotent_calls,
)
from sentinel.security import semgrep_scanner
from sentinel.security.code_extractor import (
    close_unclosed_fences,
    extract_code_blocks,
    strip_emoji_from_code_blocks,
)
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.security.quality_gate import check_code_quality
from sentinel.security.pipeline import ScanPipeline, SecurityViolation, _generate_marker
from sentinel.memory.episodic import EpisodicStore, classify_task_domain, extract_episodic_facts
from sentinel.worker.base import EmbeddingBase, PlannerBase
from sentinel.worker.context import WorkerContext, WorkerTurn
from .builders import (
    CHAIN_REMINDER,
    FORMAT_INSTRUCTIONS,
    auto_store_memory,
    build_cross_session_context,
    build_interrupted_task_warning,
    build_session_files_context,
    build_step_outcome,
    compute_execution_vars,
    enforce_tagged_format,
    flush_pruned_turns,
    genericise_error,
    get_destination,
    is_auto_approvable,
)
from .intake import (
    ContactResolutionResult,
    InputScanResult,
    IntakeResult,
    analyze_conversation,
    bind_session,
    resolve_contacts,
    scan_input,
)
from .planner import ClaudePlanner, PlannerError, PlannerRefusalError
from .safe_tools import SafeToolHandlers
from .tool_dispatch import CONTENT_CREATION_TOOLS, check_provenance, dispatch_tool, validate_constraints
from .trust_router import classify_operation, TrustTier
from sentinel.security.provenance import (
    create_tagged_data,
    update_content as update_provenance_content,
)
from sentinel.session.store import ConversationTurn, SessionStore
from sentinel.security.spotlighting import apply_datamarking
from sentinel.analysis.metadata_extractor import (
    compute_token_usage_ratio,
    extract_code_symbols,
    extract_complexity,
    extract_diff_stats,
    extract_stderr_preview,
)

logger = logging.getLogger("sentinel.audit")


def _extract_prior_error(step_outcomes: list[dict]) -> str | None:
    """Extract a compact error summary from a failed turn's step_outcomes.

    Returns a one-line string like "exit 1; stderr: ModuleNotFoundError: No
    module named 'requests'" — enough for the planner to understand what went
    wrong without revealing internal scanner details.
    """
    for o in step_outcomes:
        status = o.get("status", "")
        if status not in ("failed", "error", "blocked", "soft_failed"):
            continue
        parts: list[str] = []
        exit_code = o.get("exit_code")
        if exit_code is not None:
            parts.append(f"exit {exit_code}")
        stderr = o.get("stderr_preview", "")
        if stderr:
            # Reuse the same extraction logic as episodic text
            from sentinel.memory.episodic import _extract_key_stderr_line
            line = _extract_key_stderr_line(stderr)
            if line:
                parts.append(f"stderr: {line}")
        elif o.get("error_detail"):
            # error_detail is already genericised (no scanner names)
            parts.append(o["error_detail"][:80])
        if status == "blocked":
            parts.append("blocked by security policy")
        if o.get("sandbox_timed_out"):
            parts.append("sandbox_timeout")
        if o.get("sandbox_oom_killed"):
            parts.append("sandbox_oom")
        if parts:
            return "; ".join(parts)
    return None


def _categorise_error(
    error_detail: str,
    scanner_result: str | None = None,
    exit_code: int | None = None,
    sandbox_timed_out: bool = False,
    sandbox_oom_killed: bool = False,
    constraint_result: str | None = None,
) -> str:
    """Map step failure details to a generic error category.

    Categories are intentionally coarse — the goal is fingerprinting
    repeated identical failures, not detailed diagnostics. Priority
    order ensures the most specific signal wins (e.g. scanner block
    over generic exit code).
    """
    if scanner_result == "blocked":
        return "scanner_block"
    if sandbox_timed_out:
        return "timeout"
    if sandbox_oom_killed:
        return "oom"
    if constraint_result in ("violation", "denylist_block"):
        return "constraint_violation"
    if exit_code is not None and exit_code != 0:
        return "exit_nonzero"
    return "unknown"


def _failure_fingerprint(step: PlanStep, error_category: str) -> str:
    """Deterministic hash identifying a repeated failure pattern.

    Hashes (tool_name, sorted arg keys, error category) so the planner
    can spot "I've tried this exact approach multiple times and it keeps
    failing" — the circuit breaker signal from PentAGI Finding #6.
    """
    tool_name = step.tool or step.type
    key = f"{tool_name}:{sorted(step.args.keys())}:{error_category}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _truncate_plan_prompts(plan_dict: dict, max_prompt_len: int = 200) -> dict:
    """Truncate worker prompts in a serialised plan dict for storage.

    Real worker prompts can be 500+ chars. Storing full prompts in every
    phase of plan_json bloats storage. Truncating to 200 chars at capture
    time preserves the instruction intent without the bulk.

    Mutates and returns the dict (not a deep copy — caller owns the dict).
    """
    for step in plan_dict.get("steps", []):
        prompt = step.get("prompt")
        if prompt and len(prompt) > max_prompt_len:
            step["prompt"] = prompt[:max_prompt_len] + "..."
    return plan_dict


def _build_replan_summary(
    executed_steps: list[PlanStep],
    step_outcomes: list[dict],
    failure_trigger: bool = False,
) -> str:
    """Build a condensed replan context summary from structured data.

    Unlike _build_replan_context() which produces verbose text for the
    planner's continuation call (~4000 chars), this produces a compact
    summary (~200-300 chars) for storage in plan_json. Built directly
    from structured data — no string round-trip through rendered text.
    """
    if not executed_steps:
        return ""

    parts: list[str] = []

    # Error diagnostic for failure-triggered replans
    if failure_trigger and step_outcomes:
        last = step_outcomes[-1]
        error = last.get("error_detail") or last.get("stderr_preview") or ""
        if error:
            parts.append(f"Error: {error[:120]}")

    # Step status lines
    for step, outcome in zip(executed_steps, step_outcomes):
        status = outcome.get("status", "unknown")
        tool_label = step.tool or step.type
        var_suffix = f" → {step.output_var}" if step.output_var else ""
        meta_parts: list[str] = []
        if outcome.get("output_size"):
            meta_parts.append(f"{outcome['output_size']}B")
        if outcome.get("exit_code") is not None and outcome["exit_code"] != 0:
            meta_parts.append(f"exit={outcome['exit_code']}")
        meta = f" ({', '.join(meta_parts)})" if meta_parts else ""
        parts.append(f"{step.id} [{tool_label}]{var_suffix}: {status}{meta}")

    if not parts:
        return ""

    result = "; ".join(parts)

    # Hard cap at 500 chars — truncate cleanly at last semicolon boundary
    if len(result) > 500:
        truncated = result[:497]
        last_semi = truncated.rfind(";")
        if last_semi > 0:
            result = truncated[:last_semi] + "..."
        else:
            result = truncated + "..."

    return result


class ExecutionContext:
    """Tracks variable bindings during plan execution."""

    def __init__(self):
        self._vars: dict[str, TaggedData] = {}

    def set(self, var_name: str, data: TaggedData) -> None:
        self._vars[var_name] = data
        logger.debug(
            "Variable stored in execution context",
            extra={
                "event": "var_store",
                "var_name": var_name,
                "data_id": data.id,
                "content_length": len(data.content) if data.content else 0,
                "content_preview": (data.content[:300] if data.content else ""),
                "has_entities": ("&lt;" in (data.content or "") or "&gt;" in (data.content or "")),
            },
        )

    def get(self, var_name: str) -> TaggedData | None:
        return self._vars.get(var_name)

    def resolve_text(self, text: str) -> str:
        """Replace $var_name references with their content."""
        if not text:
            return text

        def replacer(match: re.Match) -> str:
            var_name = match.group(0)
            data = self._vars.get(var_name)
            if data is not None:
                logger.debug(
                    "Variable resolved",
                    extra={
                        "event": "var_resolve",
                        "var_name": var_name,
                        "data_id": data.id,
                        "content_length": len(data.content) if data.content else 0,
                        "content_preview": (data.content[:300] if data.content else ""),
                        "has_entities": ("&lt;" in (data.content or "") or "&gt;" in (data.content or "")),
                    },
                )
                return data.content
            return var_name  # leave unresolved refs as-is

        resolved = re.sub(_VAR_RE, replacer, text)

        # D-001: Warn on unresolved variable references (likely planner typos)
        unresolved = [
            m.group(0) for m in re.finditer(_VAR_RE, resolved)
            if m.group(0) not in self._vars and self._vars  # only warn if vars exist
        ]
        if unresolved:
            logger.warning(
                "Unresolved variable references: %s",
                unresolved,
                extra={"event": "unresolved_vars", "vars": unresolved},
            )

        return resolved

    def resolve_args(self, args: dict) -> dict:
        """Replace $var_name references in dict values (recurses into nested dicts and lists)."""
        resolved = {}
        for key, value in args.items():
            if isinstance(value, str):
                resolved[key] = self.resolve_text(value)
            elif isinstance(value, dict):
                resolved[key] = self.resolve_args(value)
            elif isinstance(value, list):
                resolved[key] = [
                    self.resolve_text(item) if isinstance(item, str)
                    else self.resolve_args(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                resolved[key] = value
        return resolved

    def get_referenced_data_ids(self, text: str) -> list[str]:
        """Return data IDs from all $var_name references found in text."""
        if not text:
            return []
        data_ids = []
        for match in re.finditer(_VAR_RE, text):
            var_name = match.group(0)
            data = self._vars.get(var_name)
            if data is not None:
                data_ids.append(data.id)
        return data_ids

    def get_referenced_data_ids_from_args(self, args: dict) -> list[str]:
        """Return data IDs from all $var_name references in dict values (recurses into nested dicts and lists)."""
        data_ids = []
        for value in args.values():
            if isinstance(value, str):
                data_ids.extend(self.get_referenced_data_ids(value))
            elif isinstance(value, dict):
                data_ids.extend(self.get_referenced_data_ids_from_args(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        data_ids.extend(self.get_referenced_data_ids(item))
        return data_ids

    def resolve_text_safe(self, text: str, marker: str) -> str:
        """Replace $var_name references with tagged, datamarked content.

        Unlike resolve_text(), this wraps substituted content in
        <UNTRUSTED_DATA> tags with spotlighting markers, treating
        prior step output as untrusted data (which it is).
        """
        if not text:
            return text

        has_substitution = False

        def replacer(match: re.Match) -> str:
            nonlocal has_substitution
            var_name = match.group(0)
            data = self._vars.get(var_name)
            if data is not None:
                has_substitution = True
                if marker:
                    marked = apply_datamarking(data.content, marker=marker)
                else:
                    marked = data.content
                return (
                    f"\n<UNTRUSTED_DATA>\n{marked}\n</UNTRUSTED_DATA>\n"
                )
            return var_name  # leave unresolved refs as-is

        resolved = re.sub(_VAR_RE, replacer, text)

        if has_substitution:
            resolved += f"\n\n{CHAIN_REMINDER}"

        return resolved


def _should_invoke_judge(
    result: TaskResult, task_category: str, assertions_defined: int = 0,
) -> bool:
    """Decide whether to invoke the planner-as-judge (Tier 2).

    Decision matrix:
    - Any Tier 1 RED signal (partial/abandoned) → skip (conclusive)
    - Deterministic + assertions defined & pass → skip
    - Structural + assertions defined & pass → skip
    - Semantic → always invoke
    - Structural + assertions fail → invoke (judge arbitrates)
    - No assertions defined + not deterministic → invoke (no evidence)
    - Tool output warnings present → invoke (something looked off)
    """
    # Tier 1 RED: conclusive, no judge needed
    if result.completion in ("partial", "abandoned"):
        logger.debug(
            "Judge gate: SKIP — Tier 1 RED (completion=%s)",
            result.completion,
            extra={"event": "judge_gate_skip", "reason": "tier1_red", "completion": result.completion},
        )
        return False
    if result.status != "success":
        logger.debug(
            "Judge gate: SKIP — non-success status (%s)",
            result.status,
            extra={"event": "judge_gate_skip", "reason": "non_success", "status": result.status},
        )
        return False

    # Semantic tasks always need the judge
    if task_category == "semantic":
        logger.debug(
            "Judge gate: INVOKE — semantic task always needs judge",
            extra={"event": "judge_gate_invoke", "reason": "semantic_always"},
        )
        return True

    # Tool output warnings present — something looked off, invoke judge
    if result.tool_output_warnings:
        logger.debug(
            "Judge gate: INVOKE — %d tool output warning(s) detected",
            len(result.tool_output_warnings),
            extra={
                "event": "judge_gate_invoke",
                "reason": "tool_output_warnings",
                "warning_count": len(result.tool_output_warnings),
            },
        )
        return True

    # Structural with failed assertions: judge arbitrates
    if task_category == "structural" and result.assertion_failures:
        logger.debug(
            "Judge gate: INVOKE — structural task with %d assertion failure(s)",
            len(result.assertion_failures),
            extra={"event": "judge_gate_invoke", "reason": "structural_assertion_fail"},
        )
        return True

    # No assertions defined → no evidence of success beyond Tier 1 signals.
    # Deterministic tasks can skip (specific values are verifiable by assertions
    # if the planner generated them; if not, the task is simple enough).
    # Structural/other tasks without assertions need the judge.
    if assertions_defined == 0:
        if task_category == "deterministic":
            logger.debug(
                "Judge gate: SKIP — deterministic task, no assertions needed",
                extra={"event": "judge_gate_skip", "reason": "deterministic_no_assertions"},
            )
            return False
        else:
            logger.debug(
                "Judge gate: INVOKE — %s task with no assertions defined (no evidence)",
                task_category,
                extra={
                    "event": "judge_gate_invoke",
                    "reason": "no_assertions_defined",
                    "category": task_category,
                },
            )
            return True

    # Assertions were defined and none failed → confident
    if not result.assertion_failures:
        logger.debug(
            "Judge gate: SKIP — %d assertion(s) defined, all passed",
            assertions_defined,
            extra={
                "event": "judge_gate_skip",
                "reason": "assertions_passed",
                "assertions_defined": assertions_defined,
            },
        )
        return False

    # Default: invoke
    logger.debug(
        "Judge gate: INVOKE — default fallthrough",
        extra={"event": "judge_gate_invoke", "reason": "default"},
    )
    return True


class Orchestrator:
    """Main CaMeL execution loop: plan → execute → scan → return."""

    def __init__(
        self,
        planner: PlannerBase,
        pipeline: ScanPipeline,
        tool_executor=None,
        approval_manager=None,
        session_store: SessionStore | None = None,
        conversation_analyzer: ConversationAnalyzer | None = None,
        memory_store=None,
        embedding_client: EmbeddingBase | None = None,
        event_bus: EventBus | None = None,
        routine_store=None,
        routine_engine=None,
        contact_store=None,
        domain_summary_store=None,
        reranker=None,
    ):
        self._planner = planner
        self._pipeline = pipeline
        self._tool_executor = tool_executor
        self._approval_manager = approval_manager
        self._session_store = session_store
        self._conversation_analyzer = conversation_analyzer
        self._memory_store = memory_store
        self._embedding_client = embedding_client
        self._event_bus = event_bus
        self._routine_store = routine_store
        self._routine_engine = routine_engine
        self._contact_store = contact_store
        self._domain_summary_store = domain_summary_store
        self._reranker = reranker
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
        # SYS-5b: Track background tasks for graceful cancellation on shutdown
        self._background_tasks: set[asyncio.Task] = set()
        # Cross-user isolation: map task_id → user_id for ownership checks
        self._task_owners: dict[str, int] = {}

    def set_routine_engine(self, engine) -> None:
        """Set routine engine after construction (breaks circular dep)."""
        self._routine_engine = engine
        self._safe_tool_handlers.set_routine_engine(engine)

    def set_episodic_store(self, store: EpisodicStore | None) -> None:
        """Set episodic store after construction (breaks circular dep)."""
        self._episodic_store = store
        self._safe_tool_handlers.set_episodic_store(store)

    def set_domain_summary_store(self, store) -> None:
        """Set domain summary store after construction (breaks circular dep)."""
        self._domain_summary_store = store

    def set_reranker(self, reranker) -> None:
        """Set reranker after construction (loaded during lifespan)."""
        self._reranker = reranker

    def get_task_owner(self, task_id: str) -> int | None:
        """Return the user_id that owns a task, or None if unknown."""
        return self._task_owners.get(task_id)

    def _register_task_owner(self, task_id: str, user_id: int) -> None:
        """Record task ownership for cross-user isolation checks."""
        self._task_owners[task_id] = user_id

    def set_strategy_store(self, store) -> None:
        """Set strategy pattern store after construction (loaded during lifespan)."""
        self._strategy_store = store

    def _evict_stale_contexts(self) -> None:
        """Remove worker contexts older than 1 hour.

        Safe without a lock: asyncio is single-threaded and there is no
        await in this loop, so no other coroutine can interleave.
        """
        _CONTEXT_TTL = 3600  # seconds
        now_mono = time.monotonic()
        stale = [
            sid for sid, ts in self._worker_context_accessed.items()
            if now_mono - ts > _CONTEXT_TTL
        ]
        for sid in stale:
            self._worker_contexts.pop(sid, None)
            self._worker_context_accessed.pop(sid, None)

    @property
    def approval_manager(self):
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
    ) -> bool:
        """Submit an approval decision. Returns False if no manager."""
        if self._approval_manager is None:
            return False
        return await self._approval_manager.submit_approval(
            approval_id=approval_id,
            granted=granted,
            reason=reason,
            approved_by=approved_by,
        )

    def set_tool_channels(self, **kwargs) -> None:
        """Forward messaging channels to the tool executor."""
        if self._tool_executor is not None:
            self._tool_executor.set_channels(**kwargs)

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
            extra={"event": "orchestrator_shutdown", "cancelled_bg_tasks": len(self._background_tasks)},
        )

    async def _emit(self, task_id: str, event: str, data: dict | None = None) -> None:
        """Fire-and-forget event publish. No-op if event bus not configured."""
        if self._event_bus is not None and task_id:
            try:
                await self._event_bus.publish(f"task.{task_id}.{event}", data or {})
            except Exception as exc:
                logger.warning(
                    "Event publish failed (non-fatal)",
                    exc_info=True,
                    extra={"event": "event_publish_failed", "topic": event, "error": str(exc)},
                )

    async def plan_and_execute(
        self,
        user_request: str,
        source: str = "api",
        approval_mode: str = "auto",
        source_key: str | None = None,
        task_id: str | None = None,
        session=None,
    ) -> TaskResult:
        """Plan and execute a task — input already scanned by router.

        Called by MessageRouter after session binding and input scanning.
        Skips session creation and input scan, goes straight to conversation
        analysis, F2 interrupted task detection, Claude planning, and execution.
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
        logger.info(
            "Task received (router path)",
            extra={
                "event": "task_received",
                "task_id": task_id,
                "source": source,
                "source_key": source_key,
                "request_length": len(user_request),
                "request_preview": user_request[:200],
                "router_path": True,
            },
        )

        # Per-session lock (same as handle_task)
        session_lock = None
        if (
            source_key is not None
            and self._session_store is not None
        ):
            session_lock = self._session_store.get_lock(source_key)
        if session_lock is not None:
            await session_lock.acquire()

        try:
            return await self._handle_task_inner(
                user_request, source, approval_mode, source_key,
                task_id, task_t0, auto_approved,
                pre_scanned_session=session,
            )
        finally:
            current_task_id.reset(task_id_token)
            if session_lock is not None:
                session_lock.release()

    async def handle_task(
        self,
        user_request: str,
        source: str = "api",
        approval_mode: str = "auto",
        source_key: str | None = None,
        task_id: str | None = None,
    ) -> TaskResult:
        """Full CaMeL pipeline: conversation check → scan → plan → execute → return."""
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
        logger.info(
            "Task received",
            extra={
                "event": "task_received",
                "task_id": task_id,
                "source": source,
                "source_key": source_key,
                "request_length": len(user_request),
                "request_preview": user_request[:200],
            },
        )

        # SYS-4: Per-session lock — serialises concurrent requests for the same
        # session while allowing different sessions to proceed in parallel.
        # Acquired before any session operations and held through the entire task.
        session_lock = None
        if (
            source_key is not None
            and self._session_store is not None
        ):
            session_lock = self._session_store.get_lock(source_key)
        if session_lock is not None:
            await session_lock.acquire()

        try:
            return await self._handle_task_inner(
                user_request, source, approval_mode, source_key, task_id,
                task_t0, auto_approved,
            )
        finally:
            current_task_id.reset(task_id_token)
            if session_lock is not None:
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
        pre_scanned_session: "Session | None" = None,
    ) -> TaskResult:
        """Inner body of handle_task, called under the per-session lock.

        When pre_scanned_session is provided (via plan_and_execute), the router
        has already bound the session and scanned input. We skip session creation
        and input scanning, but still run conversation analysis (multi-turn
        attack detection) and everything downstream.
        """
        # Resolve per-user trust level (Phase 1: multi-user).
        # User's trust_level overrides system default if set.
        user_tl = None
        if self._contact_store is not None:
            user_tl = await self._contact_store.get_user_trust_level(current_user_id.get())
        effective_tl = resolve_trust_level(user_tl, settings.trust_level)

        # 0. Session binding — acquire session and reject if locked.
        # bind_session handles both pre-scanned (router) and standard paths.
        # Gate: only bind a session when conversations are enabled or router
        # already provided one.
        _use_sessions = (
            pre_scanned_session is not None
            or (
                settings.conversation_enabled
                and self._session_store is not None
                and self._conversation_analyzer is not None
            )
        )
        intake = await bind_session(
            source_key, source,
            self._session_store if _use_sessions else None,
            pre_scanned_session,
        )
        if intake.blocked:
            return intake.task_result

        session = intake.session
        conv_info = intake.conv_info

        # 0b. Conversation analysis (multi-turn attack detection).
        # Runs on the bound session regardless of how it was acquired.
        if session is not None:
            conv_result = await analyze_conversation(
                user_request, session,
                self._conversation_analyzer, self._session_store,
            )
            if conv_result.blocked:
                return conv_result.task_result
            conv_info = conv_result.conv_info

        # F2: Interrupted task detection + flag management
        interrupted_context = ""
        # SYS-4: session_id as local variable — never stored on self, eliminates
        # race where a second concurrent request overwrites the instance field.
        session_id: str | None = None
        if session is not None:
            session_id = session.session_id
            if session.task_in_progress:
                interrupted_context = build_interrupted_task_warning(session)
            session.set_task_in_progress(True)
            if self._session_store is not None:
                await self._session_store.set_task_in_progress(session.session_id, True)

            # F3: Get or create worker turn buffer for this session
            if session_id not in self._worker_contexts:
                self._worker_contexts[session_id] = WorkerContext(
                    session_id=session_id,
                )
            self._worker_context_accessed[session_id] = time.monotonic()

        try:
            # 1. Scan user input (skipped when router already scanned).
            # intake.input_pre_scanned is set by bind_session when a
            # pre_scanned_session was provided — S1 skip decision is visible here.
            if not intake.input_pre_scanned:
                input_scan_result = await scan_input(
                    user_request, self._pipeline,
                    session, self._session_store, conv_info,
                )
                if input_scan_result.blocked:
                    return input_scan_result.task_result

            # 1b. Contact resolution — resolve sender, rewrite names to opaque IDs.
            # Runs AFTER S1 scan (scanner sees raw text). Rewritten text goes to planner.
            contact_result = await resolve_contacts(
                self._contact_store, source_key, user_request,
            )
            if contact_result.rejected:
                return TaskResult(
                    status="rejected",
                    reason=contact_result.error or "Unknown sender",
                )
            user_request = contact_result.rewritten_text
            if contact_result.audit_log:
                logger.info(
                    "Contact resolution applied",
                    extra={
                        "event": "contact_resolution",
                        "user_id": contact_result.user_id,
                        "rewrites": len(contact_result.audit_log),
                    },
                )

            # Event: task started (input scan passed)
            await self._emit(task_id, "started", {
                "source": source,
                "request_preview": user_request[:200],
            })

            # 2. Get tool descriptions — SAFE internal tools + system/external tools
            available_tools = self._safe_tool_handlers.get_descriptions()
            if self._tool_executor is not None:
                available_tools.extend(self._tool_executor.get_tool_descriptions())

            # 3. Create plan via Claude — include conversation history for
            # multi-turn context and chain-level adversarial assessment.
            conversation_history = None
            if session is not None and len(session.turns) > 0:
                conversation_history = []
                for i, turn in enumerate(session.turns, 1):
                    conversation_history.append({
                        "turn": i,
                        "request": turn.request_text[:1000],
                        "outcome": turn.result_status or "unknown",
                        "summary": turn.plan_summary,
                        "step_outcomes": turn.step_outcomes,
                    })

            # F2: Pre-pruning memory flush — persist pruned turns before they leave planner view.
            # After flushing, replace conversation_history with the kept portion so
            # the planner's _format_conversation_history doesn't re-prune redundantly.
            if conversation_history and len(conversation_history) > settings.session_max_history_turns:
                kept_turns, pruned_turns = ClaudePlanner.prune_history(
                    conversation_history, max_turns=settings.session_max_history_turns,
                )
                if pruned_turns:
                    await flush_pruned_turns(
                        session_id=session.session_id,
                        pruned_turns=pruned_turns,
                        memory_store=self._memory_store,
                    )
                conversation_history = kept_turns

            # F2: Cross-session context injection on every planner call
            cross_session_context = ""
            if session is not None:
                cross_session_context = await build_cross_session_context(
                    user_request=user_request,
                    memory_store=self._memory_store,
                    embedding_client=self._embedding_client,
                    cross_session_token_budget=settings.cross_session_token_budget,
                    domain_summary_store=self._domain_summary_store,
                    reranker=self._reranker,
                    episodic_store=self._episodic_store,
                )

            # F3: Session workspace tracking — planner sees which files this session modified
            session_files_context = ""
            if session is not None and len(session.turns) > 0:
                session_files_context = build_session_files_context(session.turns)

            try:
                plan = await asyncio.wait_for(
                    self._planner.create_plan(
                        user_request=user_request,
                        available_tools=available_tools,
                        conversation_history=conversation_history,
                        cross_session_context=cross_session_context,
                        interrupted_context=interrupted_context,
                        max_history_turns=settings.session_max_history_turns,
                        session_files_context=session_files_context,
                    ),
                    timeout=settings.planner_timeout,
                )
            except asyncio.TimeoutError:
                logger.error(
                    "Planner timed out",
                    extra={
                        "event": "planner_timeout",
                        "timeout_s": settings.planner_timeout,
                    },
                )
                return TaskResult(
                    status="error",
                    reason=f"Planning timed out after {settings.planner_timeout}s",
                    conversation=conv_info,
                )
            except PlannerRefusalError as exc:
                logger.info(
                    "Planner refused request",
                    extra={"event": "planner_refusal", "reason": str(exc)},
                )
                if session is not None:
                    turn = ConversationTurn(
                        request_text=user_request,
                        result_status="refused",
                        blocked_by=["planner"],
                        risk_score=conv_info.risk_score if conv_info else 0.0,
                    )
                    session.add_turn(turn)
                    if self._session_store is not None:
                        await self._session_store.add_turn(session.session_id, turn, session=session)
                return TaskResult(
                    status="refused",
                    reason=str(exc),
                    conversation=conv_info,
                )
            except PlannerError as exc:
                logger.error(
                    "Planning failed",
                    extra={"event": "planner_error", "error": str(exc)},
                )
                return TaskResult(
                    status="error",
                    reason="Request processing failed",
                    conversation=conv_info,
                )

            # Capture planner token usage for the task result
            planner_usage = getattr(self._planner, "_last_usage", None)

            # Event: plan created
            await self._emit(task_id, "planned", {
                "plan_summary": plan.plan_summary,
                "steps": [{"id": s.id, "type": s.type, "description": s.description} for s in plan.steps],
            })

            # 4. Check if approval is needed
            if approval_mode == "full" and self._approval_manager is not None:
                # D2/D3: Auto-approve safe plans at TL1+ (trust-level-aware)
                if effective_tl >= 1 and is_auto_approvable(plan, effective_tl):
                    logger.info(
                        "Plan auto-approved (all steps SAFE at TL%d)",
                        effective_tl,
                        extra={
                            "event": "plan_auto_approved",
                            "task_id": task_id,
                            "trust_level": effective_tl,
                            "plan_summary": plan.plan_summary,
                            "step_count": len(plan.steps),
                        },
                    )
                    await self._emit(task_id, "auto_approved", {
                        "plan_summary": plan.plan_summary,
                        "trust_level": effective_tl,
                    })
                    auto_approved = True
                    # Fall through to step 5 (execute plan)
                else:
                    approval_id = await self._approval_manager.request_plan_approval(
                        plan, source_key=source_key or "", user_request=user_request,
                    )
                    # Event: approval requested
                    await self._emit(task_id, "approval_requested", {
                        "approval_id": approval_id,
                        "plan_summary": plan.plan_summary,
                        "steps": [{"id": s.id, "type": s.type, "description": s.description} for s in plan.steps],
                    })
                    return TaskResult(
                        task_id=task_id,
                        status="awaiting_approval",
                        plan_summary=plan.plan_summary,
                        approval_id=approval_id,
                        conversation=conv_info,
                    )

            # 5. Execute plan (with judge-driven replan loop)
            # The judge can trigger at most 1 replan attempt if it determines the
            # goal was not met. This is the outer "autonomous loop" gate — the judge
            # verdict feeds GAP context back into a new plan-execute cycle.
            max_judge_replans = 1
            judge_replan_count = 0

            from sentinel.planner.verification import (
                classify_task_category,
                build_judge_payload,
                process_judge_verdict,
                evaluate_assertions,
            )

            while True:
                loop_label = f"attempt_{judge_replan_count}" if judge_replan_count > 0 else "initial"
                logger.debug(
                    "Execution loop: starting %s (judge_replan_count=%d/%d)",
                    loop_label, judge_replan_count, max_judge_replans,
                    extra={
                        "event": "exec_loop_start",
                        "task_id": task_id,
                        "attempt": loop_label,
                        "judge_replan_count": judge_replan_count,
                        "max_judge_replans": max_judge_replans,
                    },
                )

                result = await self._execute_plan(
                    plan, user_input=user_request, task_id=task_id, session_id=session_id,
                    user_id=contact_result.user_id, effective_tl=effective_tl,
                    available_tools=available_tools,
                )
                result.task_id = task_id
                result.conversation = conv_info
                result.planner_usage = planner_usage

                task_elapsed = time.monotonic() - task_t0
                logger.info(
                    "Task execution completed (%s)",
                    loop_label,
                    extra={
                        "event": "task_completed",
                        "task_id": task_id,
                        "status": result.status,
                        "plan_summary": plan.plan_summary,
                        "step_count": len(plan.steps),
                        "elapsed_s": round(task_elapsed, 2),
                        "attempt": loop_label,
                    },
                )

                # Event: task completed
                await self._emit(task_id, "completed", {
                    "status": result.status,
                    "plan_summary": result.plan_summary,
                    "elapsed_s": round(task_elapsed, 2),
                    "response": result.response,
                    "step_results": [
                        {
                            "step_id": sr.step_id,
                            "status": sr.status,
                            "content": sr.content,
                            "error": sr.error,
                        }
                        for sr in result.step_results
                    ],
                })

                # Auto-memory: store a brief summary of successful tasks
                if (
                    result.status == "success"
                    and settings.auto_memory
                    and self._memory_store is not None
                ):
                    await auto_store_memory(
                        user_request=user_request,
                        plan_summary=plan.plan_summary,
                        memory_store=self._memory_store,
                        embedding_client=self._embedding_client,
                    )

                # ── Tier 2: Planner-as-judge (conditional) ──
                logger.debug(
                    "Post-execution: Tier 1 signals — status=%s, completion=%s, goal_actions=%s, mutations=%d, warnings=%d",
                    result.status, result.completion,
                    result.goal_actions_executed,
                    len(result.file_mutations) if result.file_mutations else 0,
                    len(result.tool_output_warnings) if result.tool_output_warnings else 0,
                    extra={"event": "post_exec_tier1_signals", "task_id": task_id, "attempt": loop_label},
                )

                # Evaluate plan-level assertions if any
                all_assertions = []
                for pstep in plan.steps:
                    all_assertions.extend(pstep.assertions)
                all_assertions.extend(plan.assertions)

                if all_assertions:
                    logger.debug(
                        "Assertions: %d defined (step-level: %d, plan-level: %d)",
                        len(all_assertions),
                        sum(len(ps.assertions) for ps in plan.steps),
                        len(plan.assertions),
                        extra={
                            "event": "assertions_defined",
                            "task_id": task_id,
                            "total": len(all_assertions),
                            "step_level": sum(len(ps.assertions) for ps in plan.steps),
                            "plan_level": len(plan.assertions),
                            "attempt": loop_label,
                        },
                    )
                else:
                    logger.debug(
                        "Assertions: NONE defined by planner — judge may be needed for non-deterministic tasks",
                        extra={
                            "event": "no_assertions_defined",
                            "task_id": task_id,
                            "task_category_hint": "will classify next",
                            "attempt": loop_label,
                        },
                    )

                if all_assertions and result.completion == "full":
                    # Use user-scoped workspace path for assertion evaluation
                    from sentinel.core.workspace import get_user_workspace
                    try:
                        ws_root = str(get_user_workspace())
                    except ValueError:
                        ws_root = "/workspace"  # Fallback if no user context
                    assertion_results = evaluate_assertions(
                        all_assertions,
                        step_outcomes=result.step_outcomes,
                        workspace_root=ws_root,
                    )
                    result.assertion_failures = [
                        {"type": r.assertion_type, "path": r.path, "passed": r.passed, "message": r.message, "recovery": r.recovery}
                        for r in assertion_results if not r.passed
                    ]
                    # Assertion failure is conclusive → mark partial
                    if result.assertion_failures and result.completion == "full":
                        result.completion = "partial"
                        result.status = "partial"
                        logger.info(
                            "Assertion failure(s) detected — marking partial",
                            extra={
                                "event": "assertion_failure",
                                "failures": len(result.assertion_failures),
                                "task_id": task_id,
                                "attempt": loop_label,
                            },
                        )

                # Classify task and decide if judge is needed
                task_category = classify_task_category(
                    user_request,
                    assertions_count=len(all_assertions),
                )

                should_judge = _should_invoke_judge(
                    result, task_category, assertions_defined=len(all_assertions),
                )
                logger.debug(
                    "Post-execution: judge decision — category=%s, should_invoke=%s, "
                    "assertions_defined=%d, assertion_failures=%d, warnings=%d",
                    task_category, should_judge, len(all_assertions),
                    len(result.assertion_failures) if result.assertion_failures else 0,
                    len(result.tool_output_warnings) if result.tool_output_warnings else 0,
                    extra={
                        "event": "post_exec_judge_decision",
                        "task_id": task_id,
                        "category": task_category,
                        "invoke_judge": should_judge,
                        "assertions_defined": len(all_assertions),
                        "assertion_failures": len(result.assertion_failures) if result.assertion_failures else 0,
                        "tool_output_warnings": len(result.tool_output_warnings) if result.tool_output_warnings else 0,
                        "attempt": loop_label,
                    },
                )

                judge_says_retry = False  # Will be set if judge wants a replan

                if should_judge:
                    try:
                        judge_prompt = build_judge_payload(
                            original_request=user_request,
                            plan_summary=plan.plan_summary,
                            step_outcomes=result.step_outcomes,
                            file_mutations=result.file_mutations,
                            completion=result.completion,
                            goal_actions_executed=result.goal_actions_executed or False,
                            assertion_results=result.assertion_failures,
                            tool_output_warnings=result.tool_output_warnings,
                        )
                        verdict = await self._planner.verify_goal(judge_prompt)
                        result.judge_verdict = verdict
                        processed = process_judge_verdict(verdict, result.completion)

                        logger.debug(
                            "Judge verdict: GOAL_MET=%s, CONFIDENCE=%s, acted_on=%s, completion=%s, GAP=%s",
                            verdict.get("GOAL_MET"), verdict.get("CONFIDENCE"),
                            processed["acted_on"], processed.get("completion"),
                            verdict.get("GAP", "none"),
                            extra={
                                "event": "judge_verdict_detail",
                                "task_id": task_id,
                                "goal_met": verdict.get("GOAL_MET"),
                                "confidence": verdict.get("CONFIDENCE"),
                                "acted_on": processed["acted_on"],
                                "new_completion": processed.get("completion"),
                                "gap": verdict.get("GAP"),
                                "attempt": loop_label,
                            },
                        )

                        if processed["acted_on"]:
                            result.completion = processed["completion"]
                            if processed["completion"] in ("partial", "failed"):
                                result.status = processed["completion"]
                                # Judge says goal not met — should we retry?
                                gap = verdict.get("GAP") or ""
                                if (
                                    judge_replan_count < max_judge_replans
                                    and gap  # Only retry if judge gave actionable feedback
                                    and result.status != "error"  # Don't retry hard errors
                                ):
                                    judge_says_retry = True
                                    logger.info(
                                        "Judge-driven replan: goal not met (GOAL_MET=%s, CONFIDENCE=%s) — "
                                        "requesting new plan with GAP context (attempt %d/%d)",
                                        verdict.get("GOAL_MET"), verdict.get("CONFIDENCE"),
                                        judge_replan_count + 1, max_judge_replans,
                                        extra={
                                            "event": "judge_replan_triggered",
                                            "task_id": task_id,
                                            "goal_met": verdict.get("GOAL_MET"),
                                            "confidence": verdict.get("CONFIDENCE"),
                                            "gap": gap,
                                            "judge_replan_count": judge_replan_count,
                                        },
                                    )
                                elif judge_replan_count >= max_judge_replans:
                                    logger.warning(
                                        "Judge-driven replan budget exhausted — accepting %s verdict",
                                        processed["completion"],
                                        extra={
                                            "event": "judge_replan_budget_exhausted",
                                            "task_id": task_id,
                                            "judge_replan_count": judge_replan_count,
                                            "max_judge_replans": max_judge_replans,
                                        },
                                    )
                                else:
                                    logger.debug(
                                        "Judge says incomplete but no GAP context for replan — accepting verdict",
                                        extra={
                                            "event": "judge_no_gap_for_replan",
                                            "task_id": task_id,
                                            "gap": gap,
                                        },
                                    )
                    except Exception as exc:
                        logger.warning(
                            "Judge invocation failed — using Tier 1 verdict",
                            exc_info=True,
                            extra={"event": "judge_failed", "error": str(exc), "task_id": task_id},
                        )

                # ── Judge-driven replan: request a new plan with GAP context ──
                if judge_says_retry:
                    judge_replan_count += 1
                    gap_context = result.judge_verdict.get("GAP", "") if result.judge_verdict else ""

                    # Emit event so UI can show what's happening
                    await self._emit(task_id, "judge_replan", {
                        "judge_replan_number": judge_replan_count,
                        "gap": gap_context,
                        "previous_completion": result.completion,
                        "goal_met": result.judge_verdict.get("GOAL_MET") if result.judge_verdict else None,
                    })

                    # Store the failed attempt's episodic record before retrying
                    # (so we have a record of what went wrong)
                    logger.debug(
                        "Judge replan: storing episodic record for failed attempt before retry",
                        extra={"event": "judge_replan_episodic_pre_store", "task_id": task_id},
                    )

                    try:
                        # Request a new plan with GAP context injected
                        replan_request = (
                            f"{user_request}\n\n"
                            f"[PREVIOUS ATTEMPT FAILED — Judge feedback: {gap_context}]\n"
                            f"[Previous plan summary: {plan.plan_summary}]\n"
                            f"[Address the gap identified above. Do not repeat the same approach.]"
                        )
                        logger.debug(
                            "Judge replan: requesting new plan with GAP context — %s",
                            gap_context[:200],
                            extra={
                                "event": "judge_replan_plan_request",
                                "task_id": task_id,
                                "gap_context": gap_context[:500],
                            },
                        )
                        plan = await asyncio.wait_for(
                            self._planner.create_plan(
                                user_request=replan_request,
                                available_tools=available_tools,
                            ),
                            timeout=settings.planner_timeout,
                        )
                        # Capture updated planner usage (overwrites — latest call only)
                        planner_usage = getattr(self._planner, "_last_usage", None)
                        logger.info(
                            "Judge replan: new plan received — %d steps, summary: %s",
                            len(plan.steps), plan.plan_summary[:100],
                            extra={
                                "event": "judge_replan_plan_received",
                                "task_id": task_id,
                                "new_step_count": len(plan.steps),
                                "new_summary": plan.plan_summary[:200],
                            },
                        )
                        continue  # Go back to top of while loop for re-execution

                    except (PlannerError, PlannerRefusalError, asyncio.TimeoutError) as exc:
                        logger.error(
                            "Judge-driven replan failed — accepting original verdict",
                            exc_info=True,
                            extra={
                                "event": "judge_replan_failed",
                                "task_id": task_id,
                                "error": str(exc),
                            },
                        )
                        # Fall through to return the original result

                # No retry needed — break out of the execution loop
                break

            # F4: Store episodic record (best-effort, alongside auto-memory)
            # For fix-cycle turns (session has prior turns), include the
            # original scenario request so the episodic record is searchable
            # by scenario content rather than the generic retry prompt.
            original_request: str | None = None
            prior_error_summary: str | None = None
            if session is not None and session.turns:
                first_turn = session.turns[0]
                if first_turn.request_text != user_request:
                    original_request = first_turn.request_text
                # Extract error context from the most recent failed turn
                for prev_turn in reversed(session.turns):
                    if prev_turn.result_status not in ("success", "completed") and prev_turn.step_outcomes:
                        prior_error_summary = _extract_prior_error(prev_turn.step_outcomes)
                        break

            logger.debug(
                "Post-execution: storing episodic record — status=%s, completion=%s, fix_cycle=%s",
                result.status, result.completion, original_request is not None,
                extra={
                    "event": "post_exec_episodic_store",
                    "task_id": task_id,
                    "status": result.status,
                    "completion": result.completion,
                    "has_original_request": original_request is not None,
                    "has_prior_error": prior_error_summary is not None,
                    "judge_verdict": result.judge_verdict is not None,
                },
            )

            await self._store_episodic_record(
                session_id=session.session_id if session else "",
                task_id=task_id,
                user_request=user_request,
                task_status=result.status,
                plan_summary=plan.plan_summary,
                step_outcomes=result.step_outcomes or [],
                original_request=original_request,
                prior_error_summary=prior_error_summary,
                plan_phases=result.plan_phases,
                completion=result.completion,
                goal_actions_executed=result.goal_actions_executed,
                file_mutations=result.file_mutations,
                assertion_failures=result.assertion_failures,
                tool_output_warnings=result.tool_output_warnings,
                judge_verdict=result.judge_verdict,
            )

            # Record turn with plan summary for conversation history
            if session is not None:
                turn = ConversationTurn(
                    request_text=user_request,
                    result_status=result.status,
                    risk_score=conv_info.risk_score if conv_info else 0.0,
                    plan_summary=plan.plan_summary,
                    auto_approved=auto_approved,
                    elapsed_s=round(task_elapsed, 2),
                    step_outcomes=result.step_outcomes if result.step_outcomes else None,
                )
                session.add_turn(turn)
                if self._session_store is not None:
                    await self._session_store.add_turn(session.session_id, turn, session=session)
                logger.debug(
                    "Post-execution: session turn recorded — turn_count=%d, status=%s",
                    len(session.turns), result.status,
                    extra={"event": "post_exec_turn_recorded", "task_id": task_id, "turn_count": len(session.turns)},
                )

            logger.debug(
                "Post-execution: complete — returning result (status=%s, completion=%s)",
                result.status, result.completion,
                extra={"event": "post_exec_complete", "task_id": task_id, "status": result.status, "completion": result.completion},
            )
            return result
        finally:
            if session is not None:
                session.set_task_in_progress(False)
                if self._session_store is not None:
                    await self._session_store.set_task_in_progress(session.session_id, False)

    async def execute_approved_plan(self, approval_id: str) -> TaskResult:
        """Execute a plan that has been approved via the approval flow."""
        if self._approval_manager is None:
            return TaskResult(status="error", reason="Approval manager not configured")

        is_approved = await self._approval_manager.is_approved(approval_id)
        if is_approved is None:
            return TaskResult(status="error", reason="Approval not found or still pending")
        if not is_approved:
            return TaskResult(status="denied", reason="Plan was denied")

        pending = await self._approval_manager.get_pending(approval_id)
        if pending is None or pending.get("plan") is None:
            return TaskResult(status="error", reason="Plan not found for approval")

        plan = pending["plan"]
        t0 = time.monotonic()

        # SYS-4: Resolve session_id for the approval flow so worker context
        # (F3) works correctly during approved plan execution.
        source_key = pending.get("source_key", "")
        session_id: str | None = None
        session = None
        if source_key and self._session_store is not None:
            session = await self._session_store.get(source_key)
            if session is not None:
                session_id = session.session_id

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
        session_lock = None
        if source_key and self._session_store is not None:
            session_lock = self._session_store.get_lock(source_key)
        if session_lock is not None:
            await session_lock.acquire()

        # F2: Set task_in_progress flag (mirrors handle_task pattern)
        if session is not None:
            session.set_task_in_progress(True)
            if self._session_store is not None:
                await self._session_store.set_task_in_progress(session.session_id, True)

        try:
            result = await self._execute_plan(
                plan, user_input=pending.get("user_request") or None,
                session_id=session_id, user_id=uid, effective_tl=_eff_tl,
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
                    step_outcomes=result.step_outcomes if result.step_outcomes else None,
                )
                session.add_turn(turn)
                if self._session_store is not None:
                    await self._session_store.add_turn(session.session_id, turn, session=session)

            return result
        except Exception as exc:
            logger.error(
                "Approved plan execution failed",
                extra={"event": "approved_plan_failed", "approval_id": approval_id, "error": str(exc)},
            )
            return TaskResult(status="error", reason="Plan execution failed unexpectedly")
        finally:
            if session is not None:
                session.set_task_in_progress(False)
                if self._session_store is not None:
                    try:
                        await self._session_store.set_task_in_progress(session.session_id, False)
                    except Exception:
                        logger.warning("Failed to clear task_in_progress flag — will be stale until next task")
            if session_lock is not None:
                session_lock.release()

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
        # Verification signals (from TaskResult)
        completion: str = "full",
        goal_actions_executed: bool | None = None,
        file_mutations: list[dict] | None = None,
        assertion_failures: list[dict] | None = None,
        tool_output_warnings: list[dict] | None = None,
        judge_verdict: dict | None = None,
    ) -> None:
        """Store a structured episodic record after task completion.

        Best-effort — failures are logged, never block the task. Creates:
        1. Episodic record with structured fields
        2. Memory_chunks shadow entry (for full-text/vec search)
        3. Extracted facts with tsvector index

        All data is TRUSTED by construction — F1 metadata only.
        """
        if self._episodic_store is None or self._memory_store is None:
            return

        try:
            # Extract file paths from step_outcomes
            file_paths = []
            error_patterns = []
            all_symbols = []
            for outcome in step_outcomes:
                fp = outcome.get("file_path")
                if fp and fp not in file_paths:
                    file_paths.append(fp)
                if outcome.get("scanner_result") == "blocked":
                    generic_err = outcome.get("error_detail", "blocked")
                    error_patterns.append(generic_err)
                if outcome.get("exit_code") and outcome["exit_code"] != 0:
                    stderr = outcome.get("stderr_preview", "")
                    error_patterns.append(
                        f"exit {outcome['exit_code']}: {stderr[:80]}" if stderr
                        else f"exit {outcome['exit_code']}"
                    )
                symbols = outcome.get("defined_symbols", [])
                if symbols:
                    all_symbols.extend(symbols)

            success_count = sum(
                1 for o in step_outcomes if o.get("status") == "success"
            )

            # Classify task domain from tool usage patterns
            task_domain = classify_task_domain(step_outcomes)

            # Build plan_json for plan-outcome memory (before embedding so
            # the compact plan line is included in the vector embedding)
            plan_json_data = None
            if plan_phases:
                plan_json_data = {
                    "phases": plan_phases,
                    "user_request_full": user_request[:2000],
                }
                # Inject verification signals
                plan_json_data["completion"] = completion
                if goal_actions_executed is not None:
                    plan_json_data["goal_actions_executed"] = goal_actions_executed
                if file_mutations:
                    plan_json_data["file_mutations"] = file_mutations
                if assertion_failures:
                    plan_json_data["assertion_failures"] = assertion_failures
                if tool_output_warnings:
                    plan_json_data["tool_output_warnings"] = tool_output_warnings
                if judge_verdict:
                    plan_json_data["judge_verdict"] = judge_verdict

                plan_json_size = len(json.dumps(plan_json_data))
                if plan_json_size > 50_000:
                    logger.warning(
                        "plan_history: plan_json %d bytes for task %s, consider review",
                        plan_json_size, task_id,
                        extra={
                            "event": "plan_history_large",
                            "size_bytes": plan_json_size,
                            "task_id": task_id,
                        },
                    )

            # Try to get embedding for shadow entry.
            # For fix-cycles, use original_request so the vector embedding
            # matches on scenario content, not the generic retry prompt.
            embedding = None
            if self._embedding_client is not None:
                try:
                    from sentinel.memory.episodic import render_episodic_text
                    text = render_episodic_text(
                        user_request=user_request,
                        task_status=task_status,
                        step_count=len(step_outcomes),
                        success_count=success_count,
                        file_paths=file_paths,
                        plan_summary=plan_summary,
                        error_patterns=error_patterns,
                        step_outcomes=step_outcomes,
                        task_domain=task_domain,
                        original_request=original_request,
                        prior_error_summary=prior_error_summary,
                        plan_json=plan_json_data,
                    )
                    embedding = await self._embedding_client.embed(text, prefix="search_document: ")
                except Exception as exc:
                    logger.debug(
                        "Episodic embedding failed",
                        extra={
                            "event": "episodic_embedding_failed",
                            "error": str(exc),
                        },
                    )

            record_id = await self._episodic_store.create_with_shadow(
                memory_store=self._memory_store,
                session_id=session_id,
                task_id=task_id,
                user_request=user_request[:2000],
                task_status=task_status,
                plan_summary=plan_summary,
                step_count=len(step_outcomes),
                success_count=success_count,
                file_paths=file_paths,
                error_patterns=error_patterns,
                defined_symbols=all_symbols,
                step_outcomes=step_outcomes,
                embedding=embedding,
                task_domain=task_domain,
                original_request=original_request,
                prior_error_summary=prior_error_summary,
                plan_json=plan_json_data,
            )

            # Extract and store facts
            facts = extract_episodic_facts(step_outcomes, user_request, task_status)
            if facts:
                await self._episodic_store.store_facts(record_id, facts)

            logger.info(
                "Episodic record stored",
                extra={
                    "event": "episodic_stored",
                    "record_id": record_id,
                    "fact_count": len(facts),
                    "file_count": len(file_paths),
                    "plan_phases": len(plan_phases) if plan_phases else 0,
                },
            )

            # Record strategy pattern for this task
            if task_domain and self._strategy_store is not None:
                try:
                    from sentinel.memory.episodic import _categorise_strategy
                    strategy = _categorise_strategy(step_outcomes)
                    total_duration = sum(
                        o.get("duration_s", 0) or 0 for o in step_outcomes
                    )
                    await self._strategy_store.upsert(
                        domain=task_domain,
                        strategy_name=strategy,
                        step_sequence=[
                            o.get("tool") or o.get("step_type", "")
                            for o in step_outcomes if o.get("step_type")
                        ],
                        success=task_status in ("success", "completed"),
                        duration_s=total_duration if total_duration > 0 else None,
                    )
                except Exception as exc:
                    logger.debug(
                        "Strategy pattern recording failed (non-fatal)",
                        extra={"event": "strategy_record_failed", "error": str(exc)},
                    )

            # Check domain summary staleness and refresh if needed
            if task_domain and self._domain_summary_store is not None:
                try:
                    new_count = await self._domain_summary_store.increment_task_count(
                        task_domain
                    )
                    if new_count >= 10:
                        await self._domain_summary_store.reset_task_count(task_domain)
                        _uid = current_user_id.get()
                        task = spawn_task(
                            self._refresh_domain_summary(task_domain, user_id=_uid)
                        )
                        self._background_tasks.add(task)
                        task.add_done_callback(self._background_tasks.discard)
                except Exception as exc:
                    logger.debug(
                        "Domain summary check failed (non-fatal)",
                        extra={"event": "domain_summary_check_failed", "error": str(exc)},
                    )

        except Exception as exc:
            logger.warning(
                "Episodic record storage failed (best-effort)",
                extra={"event": "episodic_store_failed", "error": str(exc)},
            )

    async def _refresh_domain_summary(self, domain: str, user_id: int = 1) -> None:
        """Background refresh of a domain summary. Best-effort.

        user_id is threaded explicitly because asyncio.create_task does not
        propagate ContextVars reliably to background tasks.
        """
        try:
            from sentinel.memory.domain_summary import generate_domain_summary
            summary = await generate_domain_summary(
                domain=domain,
                episodic_store=self._episodic_store,
            )
            await self._domain_summary_store.upsert(summary)
            logger.info(
                "Domain summary refreshed",
                extra={
                    "event": "domain_summary_refreshed",
                    "domain": domain,
                    "total_tasks": summary.total_tasks,
                },
            )
        except Exception as exc:
            logger.warning(
                "Domain summary refresh failed (non-fatal)",
                extra={"event": "domain_summary_refresh_failed", "error": str(exc)},
            )

        # Piggyback canonical trajectory refresh on domain summary refresh
        if self._strategy_store is not None and self._memory_store is not None:
            try:
                from sentinel.memory.canonical import refresh_canonical_trajectories
                await refresh_canonical_trajectories(
                    user_id=user_id,
                    strategy_store=self._strategy_store,
                    episodic_store=self._episodic_store,
                    memory_store=self._memory_store,
                    embedding_client=self._embedding_client,
                    domain_summary_store=self._domain_summary_store,
                )
            except Exception as exc:
                logger.debug(
                    "Canonical refresh failed (non-fatal)",
                    extra={"event": "canonical_refresh_failed", "error": str(exc)},
                )

    async def execute_prebuilt_plan(
        self,
        plan: Plan,
        trust_level: int,
        task_id: str | None = None,
        user_id: int = 1,
    ) -> TaskResult:
        """Execute a pre-built Plan, bypassing planner and approval.

        Used by the B2 red team test endpoint. Runs the full execution path
        (constraint validator, PolicyEngine, scanners, executor) but does NOT
        call the planner, conversation analyser, or approval gate.

        Trust level comes from settings (set by env var at container start).
        The red team endpoint is rate-limited to 1 req/sec which prevents
        overlap between concurrent requests.
        """
        task_id = task_id or str(uuid.uuid4())
        session_key = f"red_team_{task_id}"
        self._worker_contexts[session_key] = WorkerContext(
            session_id=session_key,
        )
        self._worker_context_accessed[session_key] = time.monotonic()
        try:
            result = await self._execute_plan(
                plan, user_input=None, task_id=task_id,
                session_id=session_key, user_id=user_id,
            )
        finally:
            self._worker_contexts.pop(session_key, None)
            self._worker_context_accessed.pop(session_key, None)

        result.task_id = task_id
        return result

    # ── Dynamic replanning helpers ──────────────────────────────────

    # Tools whose output is controller-generated (TRUSTED) and safe to
    # show the planner during replan. Filesystem/OS output, not Qwen text.
    _TRUSTED_OUTPUT_TOOLS = frozenset({
        "shell", "shell_exec", "file_read", "list_dir", "find_file",
    })

    @staticmethod
    def _build_replan_context(
        user_request: str,
        plan_summary: str,
        step_results: list[StepResult],
        step_outcomes: list[dict],
        executed_steps: list[PlanStep],
        failure_trigger: bool = False,
    ) -> str:
        """Build context for a continuation planner call.

        Includes F1 metadata for all completed steps, plus actual output for
        trusted tool steps (shell, file_read). Worker (llm_task) output is
        never included — only F1 metadata (status, size, symbols).

        When failure_trigger=True, prepends a FAILURE DIAGNOSTIC header so the
        planner knows to diagnose the error and plan corrective steps.
        """
        lines = []
        if failure_trigger:
            # _extract_prior_error already handles soft_failed (Task 2)
            error_summary = _extract_prior_error(step_outcomes) or "unknown error"
            lines.extend([
                "FAILURE DIAGNOSTIC:",
                f"  {error_summary}",
                "",
                "  The command ran but produced an error. The full output is included below.",
                "  Diagnose the issue, plan corrective steps (fix the code, adjust the",
                "  command, etc.), then retry.",
                "",
            ])
        lines.extend([
            f"REPLAN CONTEXT — continuing plan: {plan_summary}",
            f"Original request: {user_request}",
            "",
            "Completed steps:",
        ])

        for step, result, outcome in zip(executed_steps, step_results, step_outcomes):
            # Include output_var so the continuation plan references the correct
            # variable names. Without this, the planner guesses variable names
            # (e.g. $step_1_result) instead of using the actual names from the
            # initial plan (e.g. $weather_search, $current_html).
            var_suffix = f" → {step.output_var}" if step.output_var else ""
            lines.append(f"  {step.id} [{step.type}]{var_suffix}: {outcome.get('status', 'unknown')}")

            # F1 metadata (always included — privacy-safe)
            meta_parts = []
            if outcome.get("output_size"):
                meta_parts.append(f"output={outcome['output_size']}B")
            if outcome.get("exit_code") is not None:
                meta_parts.append(f"exit={outcome['exit_code']}")
            if outcome.get("stderr_preview"):
                meta_parts.append(f"stderr: {outcome['stderr_preview']}")
            if outcome.get("file_path"):
                meta_parts.append(f"file={outcome['file_path']}")
            if outcome.get("diff_stats"):
                meta_parts.append(f"diff={outcome['diff_stats']}")
            if meta_parts:
                lines.append(f"    metadata: {' | '.join(meta_parts)}")

            # Actual output for trusted tools — lets the planner see
            # directory listings, file contents, shell errors, etc.
            if (
                step.type == "tool_call"
                and step.tool in Orchestrator._TRUSTED_OUTPUT_TOOLS
                and result.status in ("success", "soft_failed")
                and result.content
            ):
                content = result.content[:4000]
                if len(result.content) > 4000:
                    content += f"\n... (truncated, {len(result.content)} chars total)"
                indent = "      "
                indented = "\n".join(indent + ln for ln in content.splitlines())
                lines.append(f"    output:\n{indented}")

            # Worker steps: F1 metadata only (no raw content — privacy boundary)
            elif step.type == "llm_task" and result.status == "success":
                if outcome.get("output_language"):
                    lines.append(f"    language: {outcome['output_language']}")
                if outcome.get("syntax_valid") is not None:
                    lines.append(f"    syntax: {'valid' if outcome['syntax_valid'] else 'ERROR'}")
                if outcome.get("defined_symbols"):
                    lines.append(f"    symbols: {outcome['defined_symbols']}")

        lines.append("")
        if failure_trigger:
            lines.append(
                "The previous step failed. Diagnose the error using the output above, "
                "then plan corrective steps to fix the issue and retry. "
                'Set "continuation": true in your response.'
            )
        else:
            lines.append(
                "Continue the plan from the next step. Use the results above to determine "
                "correct file paths, commands, and approach for remaining steps. "
                'Set "continuation": true in your response.'
            )
        return "\n".join(lines)

    async def _request_continuation(
        self,
        user_request: str,
        plan_summary: str,
        step_results: list[StepResult],
        step_outcomes: list[dict],
        executed_steps: list[PlanStep],
        available_tools: list[dict] | None = None,
        failure_trigger: bool = False,
    ) -> Plan:
        """Request continuation steps from the planner after a replan checkpoint."""
        replan_context = self._build_replan_context(
            user_request=user_request,
            plan_summary=plan_summary,
            step_results=step_results,
            step_outcomes=step_outcomes,
            executed_steps=executed_steps,
            failure_trigger=failure_trigger,
        )

        # --- Inject anchor maps for files read in this task ---
        _anchor_maps = getattr(self, '_active_anchor_maps', {})
        if _anchor_maps:
            replan_context += "\n\n" + "\n\n".join(_anchor_maps.values())

        # Collect output_var names from executed steps so the continuation
        # plan validator accepts references to them. Without this, the validator
        # rejects $weather_search etc. as "undefined variable" because it only
        # sees the continuation plan's steps, not the initial plan's.
        prior_vars = {
            s.output_var for s in executed_steps
            if s.output_var
        }

        continuation = await asyncio.wait_for(
            self._planner.create_plan(
                user_request=replan_context,
                available_tools=available_tools,
                prior_vars=prior_vars,
            ),
            timeout=settings.planner_timeout,
        )

        # Validate continuation step IDs don't conflict with executed steps
        executed_ids = {s.id for s in executed_steps}
        for step in continuation.steps:
            if step.id in executed_ids:
                raise PlannerError(
                    f"Continuation step ID '{step.id}' conflicts with "
                    f"already-executed step. IDs must be unique across phases."
                )

        return continuation

    # ── Plan execution ───────────────────────────────────────────────

    async def _execute_plan(
        self, plan: Plan, user_input: str | None = None,
        task_id: str = "",
        session_id: str | None = None,
        user_id: int = 1,
        effective_tl: int | None = None,
        available_tools: list[dict] | None = None,
    ) -> TaskResult:
        """Execute all steps in a plan sequentially, with dynamic replanning."""
        context = ExecutionContext()
        step_results: list[StepResult] = []
        step_outcomes: list[dict] = []
        execution_vars = compute_execution_vars(plan)
        enforce_tagged_format(plan, execution_vars)
        plan_t0 = time.monotonic()
        replan_count = 0
        max_replans = 3
        failure_replan_count = 0
        max_failure_replans = 3
        budget_exhausted = False  # Set when replan budget is hit
        consecutive_no_mutation_replans = 0  # Stagnation: no-mutation replan counter
        stagnation_aborted = False  # Set when stagnation abort threshold is hit
        pre_replan_mutation_count = 0  # File mutations before last replan (for stagnation diff)

        # Mutable list so continuation steps can be appended dynamically
        remaining_steps = list(plan.steps)
        executed_steps: list[PlanStep] = []

        # Plan-outcome memory: capture plan evolution for episodic storage.
        plan_phases: list[dict] = []
        current_phase: dict = {
            "phase": "initial",
            "trigger": None,
            "trigger_step": None,
            "plan": _truncate_plan_prompts(plan.model_dump(exclude_none=True)),
            "step_outcomes_summary": {},
            "replan_context_summary": None,
        }
        logger.debug(
            "plan_history: initial phase captured",
            extra={"event": "plan_history_init", "step_count": len(plan.steps)},
        )

        while remaining_steps:
            step = remaining_steps.pop(0)
            # SYS-5a: Abort plan if the process is shutting down
            if self._shutting_down:
                logger.info(
                    "Plan aborted — orchestrator shutting down",
                    extra={
                        "event": "plan_aborted_shutdown",
                        "steps_completed": len(step_results),
                        "steps_total": len(plan.steps),
                    },
                )
                return TaskResult(
                    status="error",
                    plan_summary=plan.plan_summary,
                    step_results=step_results,
                    step_outcomes=step_outcomes,
                    reason=(
                        f"Plan aborted — server shutting down "
                        f"({len(step_results)}/{len(plan.steps)} steps completed)"
                    ),
                    replan_count=replan_count,
                    plan_phases=plan_phases + [current_phase],
                )

            # Overall plan execution timeout — guard against plans with many steps
            # accumulating beyond the budget. Per-step timeouts (worker, tool) handle
            # individual hangs; this catches the aggregate.
            plan_elapsed = time.monotonic() - plan_t0
            if plan_elapsed > settings.plan_execution_timeout:
                logger.error(
                    "Plan execution timed out",
                    extra={
                        "event": "plan_execution_timeout",
                        "timeout_s": settings.plan_execution_timeout,
                        "elapsed_s": round(plan_elapsed, 2),
                        "steps_completed": len(step_results),
                        "steps_total": len(plan.steps),
                    },
                )
                return TaskResult(
                    status="error",
                    plan_summary=plan.plan_summary,
                    step_results=step_results,
                    step_outcomes=step_outcomes,
                    reason=(
                        f"Plan execution timed out after {settings.plan_execution_timeout}s "
                        f"({len(step_results)}/{len(plan.steps)} steps completed)"
                    ),
                    replan_count=replan_count,
                    plan_phases=plan_phases + [current_phase],
                )
            destination = get_destination(step, execution_vars)
            step_t0 = time.monotonic()
            logger.info(
                "Executing step",
                extra={
                    "event": "step_start",
                    "step_id": step.id,
                    "step_type": step.type,
                    "description": step.description,
                    "output_destination": destination.value,
                },
            )

            result, exec_meta = await self._execute_step(
                step, context, user_input=user_input, destination=destination,
                session_id=session_id, user_id=user_id, effective_tl=effective_tl,
            )
            step_results.append(result)
            executed_steps.append(step)
            step_elapsed = time.monotonic() - step_t0

            # F1: Build structured step outcome metadata
            step_outcomes.append(build_step_outcome(
                step=step, result=result, elapsed_s=step_elapsed,
                destination=destination, exec_meta=exec_meta,
            ))

            # Plan-outcome memory: record condensed outcome for this step
            outcome_entry: dict = {
                "status": result.status,
                "output_size": len(result.content) if result.content else 0,
            }
            # Conditionally include non-None diagnostic fields
            step_outcome = step_outcomes[-1]  # just appended above
            if step_outcome.get("error_detail"):
                outcome_entry["error"] = step_outcome["error_detail"]
            if step_outcome.get("file_path"):
                outcome_entry["file_path"] = step_outcome["file_path"]
            if step_outcome.get("file_size_before") is not None:
                outcome_entry["file_size_before"] = step_outcome["file_size_before"]
            if step_outcome.get("file_size_after") is not None:
                outcome_entry["file_size_after"] = step_outcome["file_size_after"]
            if step_outcome.get("scanner_result"):
                outcome_entry["scanner_result"] = step_outcome["scanner_result"]
            if step_outcome.get("exit_code") is not None:
                outcome_entry["exit_code"] = step_outcome["exit_code"]
            # Failure fingerprint for non-success steps (PentAGI Finding #6)
            if result.status not in ("success",):
                error_cat = _categorise_error(
                    step_outcome.get("error_detail", ""),
                    scanner_result=step_outcome.get("scanner_result"),
                    exit_code=step_outcome.get("exit_code"),
                    sandbox_timed_out=step_outcome.get("sandbox_timed_out", False),
                    sandbox_oom_killed=step_outcome.get("sandbox_oom_killed", False),
                    constraint_result=step_outcome.get("constraint_result"),
                )
                outcome_entry["failure_fingerprint"] = _failure_fingerprint(step, error_cat)
                logger.info(
                    "plan_history: failure fingerprint %s for %s (%s)",
                    outcome_entry["failure_fingerprint"], step.id, error_cat,
                    extra={
                        "event": "plan_history_fingerprint",
                        "step_id": step.id,
                        "fingerprint": outcome_entry["failure_fingerprint"],
                        "error_category": error_cat,
                    },
                )
            current_phase["step_outcomes_summary"][step.id] = outcome_entry
            logger.debug(
                "plan_history: %s -> %s", step.id, result.status,
                extra={"event": "plan_history_step", "step_id": step.id, "status": result.status},
            )

            # F3: Update worker turn buffer after successful llm_task steps
            if (
                step.type == "llm_task"
                and result.status == "success"
                and session_id
            ):
                worker_ctx = self._worker_contexts.get(session_id)
                if worker_ctx:
                    self._worker_context_accessed[session_id] = time.monotonic()
                    worker_ctx.add_turn(WorkerTurn(
                        turn_number=len(worker_ctx.turns) + 1,
                        prompt_summary=(step.prompt or "")[:200],
                        response_summary=(result.content or "")[:500],
                        step_outcome=step_outcomes[-1],
                        timestamp=time.time(),
                    ))

            logger.info(
                "Step completed",
                extra={
                    "event": "step_complete",
                    "step_id": step.id,
                    "status": result.status,
                    "elapsed_s": round(step_elapsed, 2),
                },
            )

            # Event: step completed
            await self._emit(task_id, "step_completed", {
                "step_id": step.id,
                "status": result.status,
                "content_preview": result.content[:200] if result.content else "",
                "error": result.error,
            })

            # Store result in context if step has output_var
            # TODO: output_var intentionally not stored for soft_failed steps — the replan
            # replaces remaining steps anyway, so downstream $var references won't exist.
            if result.status == "success" and step.output_var and result.data_id:
                data = await self._get_tagged_data(result.data_id)
                if data:
                    context.set(step.output_var, data)
                    logger.debug(
                        "Variable stored in context",
                        extra={
                            "event": "context_var_set",
                            "var_name": step.output_var,
                            "data_id": result.data_id,
                            "trust_level": data.trust_level.value,
                        },
                    )

            # Stop on blocking errors.
            # NOTE (U2/RETRY-1): This aborts the entire plan on first step
            # failure. For llm_task steps, a retry on transient errors (Ollama
            # timeout, connection reset) could improve resilience. Left as
            # abort-on-error: safety-over-resilience is the design intent, and
            # tool_call steps may have side effects that make retries unsafe.
            if result.status in ("blocked", "error", "failed"):
                return TaskResult(
                    status=result.status,
                    plan_summary=plan.plan_summary,
                    step_results=step_results,
                    step_outcomes=step_outcomes,
                    reason=result.error,
                    replan_count=replan_count,
                    plan_phases=plan_phases + [current_phase],
                    completion="abandoned",
                    goal_actions_executed=check_goal_actions_executed(step_outcomes),
                    file_mutations=extract_file_mutations(step_outcomes),
                )

            # ── Dynamic replanning checkpoint ──
            # When a step has replan_after=True and succeeded, call the planner
            # again with execution results to get continuation steps.
            if step.replan_after and result.status == "success":
                # Stagnation detection: count file mutations since last replan
                current_mutations = len(extract_file_mutations(step_outcomes))
                mutations_this_cycle = current_mutations - pre_replan_mutation_count
                if mutations_this_cycle == 0:
                    consecutive_no_mutation_replans += 1
                    logger.debug(
                        "Stagnation tracking: no new file mutations this replan cycle — counter=%d",
                        consecutive_no_mutation_replans,
                        extra={
                            "event": "stagnation_no_mutations",
                            "consecutive_no_mutation_replans": consecutive_no_mutation_replans,
                            "total_mutations": current_mutations,
                            "step_id": step.id,
                        },
                    )
                else:
                    if consecutive_no_mutation_replans > 0:
                        logger.debug(
                            "Stagnation tracking: %d new mutation(s) — resetting counter (was %d)",
                            mutations_this_cycle, consecutive_no_mutation_replans,
                            extra={
                                "event": "stagnation_reset",
                                "mutations_this_cycle": mutations_this_cycle,
                                "previous_counter": consecutive_no_mutation_replans,
                            },
                        )
                    consecutive_no_mutation_replans = 0
                pre_replan_mutation_count = current_mutations

                stagnation_result = check_stagnation(consecutive_no_mutation_replans)
                if stagnation_result == "abort":
                    stagnation_aborted = True
                    logger.warning(
                        "Stagnation abort: %d consecutive no-mutation replans — forcing partial",
                        consecutive_no_mutation_replans,
                        extra={
                            "event": "stagnation_abort",
                            "consecutive_no_mutation_replans": consecutive_no_mutation_replans,
                            "steps_completed": len(step_results),
                        },
                    )
                    return TaskResult(
                        status="partial",
                        plan_summary=plan.plan_summary,
                        step_results=step_results,
                        step_outcomes=step_outcomes,
                        reason=f"Stagnation detected: {consecutive_no_mutation_replans} consecutive replan cycles with no file mutations",
                        replan_count=replan_count,
                        plan_phases=plan_phases + [current_phase],
                        completion="partial",
                        goal_actions_executed=check_goal_actions_executed(step_outcomes),
                        file_mutations=extract_file_mutations(step_outcomes),
                    )
                elif stagnation_result == "warn":
                    logger.warning(
                        "Stagnation warning: %d consecutive no-mutation replans — continuing but at risk",
                        consecutive_no_mutation_replans,
                        extra={
                            "event": "stagnation_warn",
                            "consecutive_no_mutation_replans": consecutive_no_mutation_replans,
                        },
                    )

                if replan_count >= max_replans:
                    budget_exhausted = True
                    logger.warning(
                        "Replan budget exhausted — executing remaining steps as-is",
                        extra={
                            "event": "replan_budget_exhausted",
                            "replan_count": replan_count,
                            "remaining_steps": len(remaining_steps),
                        },
                    )
                else:
                    replan_count += 1
                    logger.info(
                        "Replan checkpoint reached — requesting continuation",
                        extra={
                            "event": "replan_checkpoint",
                            "step_id": step.id,
                            "replan_number": replan_count,
                            "steps_completed": len(executed_steps),
                        },
                    )

                    # --- Accumulate anchor maps for file_read steps ---
                    if step.tool == "file_read" and step.args:
                        _file_path = step.args.get("path", "")
                        if _file_path and hasattr(self, '_episodic_store') and self._episodic_store:
                            try:
                                import json as _json
                                from sentinel.tools.anchor_allocator._memory import read_anchor_map
                                from sentinel.tools.anchor_allocator._core import content_hash
                                _file_content = result.content if result and result.content else ""
                                _anchor_list = await read_anchor_map(
                                    path=_file_path,
                                    current_hash=content_hash(_file_content),
                                    episodic_store=self._episodic_store,
                                    user_id=user_id,
                                )
                                if _anchor_list:
                                    _lines = [f"[ANCHOR MAP: {_file_path}]"]
                                    for _a in _anchor_list:
                                        _end = f" (pair: {_a['name']}-end)" if _a.get("has_end") else ""
                                        _lines.append(f"  {_a['name']} — {_a['description']}{_end}")
                                    _lines.append("[END ANCHOR MAP]")
                                    if not hasattr(self, '_active_anchor_maps'):
                                        self._active_anchor_maps = {}
                                    self._active_anchor_maps[_file_path] = "\n".join(_lines)
                                    logger.info(
                                        "Anchor map injected for replan",
                                        extra={
                                            "event": "anchor_map_injected",
                                            "path": _file_path,
                                            "anchor_count": len(_anchor_list),
                                        },
                                    )
                            except Exception:
                                pass  # Non-fatal

                    try:
                        continuation = await self._request_continuation(
                            user_request=user_input or "",
                            plan_summary=plan.plan_summary,
                            step_results=step_results,
                            step_outcomes=step_outcomes,
                            executed_steps=executed_steps,
                            available_tools=available_tools,
                        )

                        # Plan-outcome memory: close current phase, start new one
                        plan_phases.append(current_phase)
                        current_phase = {
                            "phase": f"continuation_{len(plan_phases)}",
                            "trigger": "replan_after",
                            "trigger_step": step.id,
                            "plan": _truncate_plan_prompts(continuation.model_dump(exclude_none=True)),
                            "step_outcomes_summary": {},
                            "replan_context_summary": _build_replan_summary(
                                executed_steps=executed_steps,
                                step_outcomes=step_outcomes,
                            ),
                        }
                        logger.info(
                            "plan_history: %s closed, continuation triggered by %s (replan_after)",
                            plan_phases[-1]["phase"], step.id,
                            extra={
                                "event": "plan_history_phase_close",
                                "closed_phase": plan_phases[-1]["phase"],
                                "trigger_step": step.id,
                                "trigger": "replan_after",
                            },
                        )

                        # Replace remaining steps with continuation steps
                        remaining_steps = list(continuation.steps)

                        # Recompute execution_vars for the extended plan
                        extended_plan = Plan(
                            plan_summary=plan.plan_summary,
                            steps=list(executed_steps) + remaining_steps,
                        )
                        execution_vars = compute_execution_vars(extended_plan)
                        enforce_tagged_format(extended_plan, execution_vars)

                        # Log if continuation introduces new tool types
                        original_tools = {s.tool for s in plan.steps if s.tool}
                        continuation_tools = {s.tool for s in continuation.steps if s.tool}
                        new_tools = continuation_tools - original_tools
                        if new_tools:
                            logger.info(
                                "Continuation introduces new tool types",
                                extra={
                                    "event": "replan_new_tools",
                                    "new_tools": sorted(new_tools),
                                    "original_tools": sorted(original_tools),
                                },
                            )

                        await self._emit(task_id, "plan_continued", {
                            "replan_number": replan_count,
                            "new_steps": len(continuation.steps),
                            "continuation_summary": continuation.plan_summary,
                        })

                    except (PlannerError, PlannerRefusalError, asyncio.TimeoutError) as exc:
                        logger.error(
                            "Replan failed — executing remaining steps as-is",
                            extra={
                                "event": "replan_failed",
                                "error": str(exc),
                                "remaining_steps": len(remaining_steps),
                            },
                        )
                        # Fall through to execute any remaining original steps.
                        # If there are none (discovery-only plan), the loop ends.

            # ── Failure replan checkpoint ──
            # When a step soft-fails (non-zero exit code), call the planner
            # with diagnostic context to let it diagnose and fix.
            # NOTE: failure budget check comes FIRST — soft_failed steps are
            # actively erroring, so the failure budget is the primary control.
            # Stagnation is logged as a secondary signal but doesn't override.
            elif result.status == "soft_failed":
                # Stagnation: track mutations (logging/signal only — failure budget takes priority)
                current_mutations = len(extract_file_mutations(step_outcomes))
                mutations_this_cycle = current_mutations - pre_replan_mutation_count
                if mutations_this_cycle == 0:
                    consecutive_no_mutation_replans += 1
                else:
                    consecutive_no_mutation_replans = 0
                pre_replan_mutation_count = current_mutations

                stagnation_result = check_stagnation(consecutive_no_mutation_replans)
                if stagnation_result == "abort":
                    logger.warning(
                        "Stagnation detected during failure replan (%d cycles) — "
                        "deferring to failure budget (%d/%d)",
                        consecutive_no_mutation_replans,
                        failure_replan_count, max_failure_replans,
                        extra={
                            "event": "stagnation_during_failure_replan",
                            "consecutive_no_mutation_replans": consecutive_no_mutation_replans,
                            "failure_replan_count": failure_replan_count,
                            "step_id": step.id,
                        },
                    )
                elif stagnation_result == "warn":
                    logger.warning(
                        "Stagnation warning during failure replan: %d consecutive no-mutation cycles",
                        consecutive_no_mutation_replans,
                        extra={
                            "event": "stagnation_warn_failure_replan",
                            "consecutive_no_mutation_replans": consecutive_no_mutation_replans,
                        },
                    )

                if failure_replan_count >= max_failure_replans:
                    logger.warning(
                        "Failure replan budget exhausted — aborting",
                        extra={
                            "event": "failure_replan_budget_exhausted",
                            "failure_replan_count": failure_replan_count,
                            "step_id": step.id,
                        },
                    )
                    return TaskResult(
                        status="failed",
                        plan_summary=plan.plan_summary,
                        step_results=step_results,
                        step_outcomes=step_outcomes,
                        reason=f"Failure replan budget exhausted ({max_failure_replans} attempts)",
                        replan_count=replan_count,
                        plan_phases=plan_phases + [current_phase],
                        completion="abandoned",
                        goal_actions_executed=check_goal_actions_executed(step_outcomes),
                        file_mutations=extract_file_mutations(step_outcomes),
                    )

                failure_replan_count += 1
                replan_count += 1
                logger.info(
                    "Failure replan triggered — requesting fix from planner",
                    extra={
                        "event": "failure_replan_triggered",
                        "step_id": step.id,
                        "failure_replan_number": failure_replan_count,
                        "exit_code": (exec_meta or {}).get("exit_code"),
                    },
                )

                try:
                    continuation = await self._request_continuation(
                        user_request=user_input or "",
                        plan_summary=plan.plan_summary,
                        step_results=step_results,
                        step_outcomes=step_outcomes,
                        executed_steps=executed_steps,
                        available_tools=available_tools,
                        failure_trigger=True,
                    )

                    # Plan-outcome memory: close current phase, start new one
                    plan_phases.append(current_phase)
                    current_phase = {
                        "phase": f"continuation_{len(plan_phases)}",
                        "trigger": "soft_failed",
                        "trigger_step": step.id,
                        "plan": _truncate_plan_prompts(continuation.model_dump(exclude_none=True)),
                        "step_outcomes_summary": {},
                        "replan_context_summary": _build_replan_summary(
                            executed_steps=executed_steps,
                            step_outcomes=step_outcomes,
                            failure_trigger=True,
                        ),
                    }
                    logger.info(
                        "plan_history: %s closed, continuation triggered by %s (soft_failed)",
                        plan_phases[-1]["phase"], step.id,
                        extra={
                            "event": "plan_history_phase_close",
                            "closed_phase": plan_phases[-1]["phase"],
                            "trigger_step": step.id,
                            "trigger": "soft_failed",
                        },
                    )

                    # Replace remaining steps with continuation steps
                    remaining_steps = list(continuation.steps)

                    # Recompute execution_vars for the extended plan
                    extended_plan = Plan(
                        plan_summary=plan.plan_summary,
                        steps=list(executed_steps) + remaining_steps,
                    )
                    execution_vars = compute_execution_vars(extended_plan)
                    enforce_tagged_format(extended_plan, execution_vars)

                    await self._emit(task_id, "failure_replan", {
                        "failure_replan_number": failure_replan_count,
                        "new_steps": len(continuation.steps),
                        "trigger_step": step.id,
                        "exit_code": (exec_meta or {}).get("exit_code"),
                    })

                except (PlannerError, PlannerRefusalError, asyncio.TimeoutError) as exc:
                    logger.error(
                        "Failure replan request failed — aborting",
                        extra={
                            "event": "failure_replan_request_failed",
                            "error": str(exc),
                        },
                    )
                    return TaskResult(
                        status="failed",
                        plan_summary=plan.plan_summary,
                        step_results=step_results,
                        step_outcomes=step_outcomes,
                        reason=genericise_error(f"Failure replan failed: {exc}") or "Failure replan failed",
                        replan_count=replan_count,
                        plan_phases=plan_phases + [current_phase],
                        completion="abandoned",
                        goal_actions_executed=check_goal_actions_executed(step_outcomes),
                        file_mutations=extract_file_mutations(step_outcomes),
                    )

        # Extract response text from the last llm_task step for response
        # verification in test harness and API consumers. Fast-path sets
        # this directly; planner path extracts from step results.
        response_text = ""
        for sr in reversed(step_results):
            if sr.step_id.startswith("llm_task") and sr.content:
                response_text = sr.content
                break

        # Plan-outcome memory: close final phase
        plan_phases.append(current_phase)

        # ── Tier 1: Deterministic verification signals ──
        goal_actions = check_goal_actions_executed(step_outcomes)
        file_muts = extract_file_mutations(step_outcomes)

        # Collect tool output warnings from step results
        all_warnings: list[dict] = []
        for sr in step_results:
            if sr.content:
                for w in scan_tool_output(sr.content):
                    all_warnings.append({"step_id": sr.step_id, "pattern": w.pattern, "severity": w.severity})

        # Idempotency detection: flag duplicate tool calls with identical output
        idempotent_calls = detect_idempotent_calls(step_outcomes)
        if idempotent_calls:
            logger.warning(
                "Idempotent calls detected: %d duplicate group(s) — %s",
                len(idempotent_calls), ", ".join(idempotent_calls),
                extra={
                    "event": "idempotent_calls_detected",
                    "duplicate_groups": len(idempotent_calls),
                    "descriptions": idempotent_calls,
                },
            )
            # Append as tool_output_warnings so they're visible in episodic records
            for desc in idempotent_calls:
                all_warnings.append({
                    "step_id": "plan_level",
                    "pattern": f"idempotent_call: {desc}",
                    "severity": "MEDIUM",
                })

        # Determine completion status
        if budget_exhausted or stagnation_aborted:
            completion = "partial"
        else:
            completion = "full"

        # Override status: budget exhaustion / stagnation = "partial" not "success"
        final_status = "success"
        if budget_exhausted:
            final_status = "partial"
            logger.warning(
                "Task completed with partial status — replan budget exhausted",
                extra={
                    "event": "verification_partial",
                    "reason": "budget_exhausted",
                    "goal_actions_executed": goal_actions,
                    "file_mutations_count": len(file_muts),
                },
            )

        logger.debug(
            "Tier 1 signals computed — goal_actions=%s, mutations=%d, warnings=%d, "
            "idempotent_groups=%d, stagnation_counter=%d, budget_exhausted=%s",
            goal_actions, len(file_muts), len(all_warnings),
            len(idempotent_calls), consecutive_no_mutation_replans, budget_exhausted,
            extra={
                "event": "tier1_signals_summary",
                "goal_actions_executed": goal_actions,
                "file_mutations_count": len(file_muts),
                "tool_output_warnings_count": len(all_warnings),
                "idempotent_call_groups": len(idempotent_calls),
                "consecutive_no_mutation_replans": consecutive_no_mutation_replans,
                "budget_exhausted": budget_exhausted,
                "stagnation_aborted": stagnation_aborted,
            },
        )

        return TaskResult(
            status=final_status,
            plan_summary=plan.plan_summary,
            step_results=step_results,
            step_outcomes=step_outcomes,
            response=response_text,
            replan_count=replan_count,
            plan_phases=plan_phases,
            completion=completion,
            goal_actions_executed=goal_actions,
            file_mutations=file_muts,
            tool_output_warnings=all_warnings,
        )

    async def _execute_step(
        self, step: PlanStep, context: ExecutionContext,
        user_input: str | None = None,
        destination: OutputDestination = OutputDestination.EXECUTION,
        session_id: str | None = None,
        user_id: int = 1,
        effective_tl: int | None = None,
    ) -> tuple[StepResult, dict | None]:
        """Execute a single plan step.

        Returns (step_result, exec_meta) where exec_meta contains tool-specific
        metadata from the executor (exit_code, stderr, file sizes) or None.
        """
        if step.type == "llm_task":
            result = await self._execute_llm_task(
                step, context, user_input=user_input, destination=destination,
                session_id=session_id,
            )
            return result, None
        elif step.type == "tool_call":
            return await self._execute_tool_call(
                step, context, destination=destination, session_id=session_id,
                user_id=user_id, effective_tl=effective_tl,
            )
        else:
            return StepResult(
                step_id=step.id,
                status="error",
                error=f"Unknown step type: {step.type}",
            ), None

    async def _execute_llm_task(
        self, step: PlanStep, context: ExecutionContext,
        user_input: str | None = None,
        destination: OutputDestination = OutputDestination.EXECUTION,
        session_id: str | None = None,
    ) -> StepResult:
        """Send a prompt to Qwen via the scan pipeline."""
        if not step.prompt:
            return StepResult(
                step_id=step.id,
                status="error",
                error="LLM task step has no prompt",
            )

        # Chain-safe: if step references prior output, apply structural marking.
        # Defence-in-depth: also check for actual $var references in the prompt
        # even if input_vars is empty — catches planner omissions that would
        # otherwise cause UNTRUSTED worker output to resolve without wrapping.
        actual_refs = set(re.findall(_VAR_RE, step.prompt or ""))
        declared_refs = set(step.input_vars or [])
        has_undeclared = bool(actual_refs - declared_refs) and any(
            context.get(ref) is not None for ref in (actual_refs - declared_refs)
        )
        if has_undeclared:
            logger.warning(
                "Undeclared variable references in prompt — using safe resolver",
                extra={
                    "event": "input_vars_mismatch",
                    "step_id": step.id,
                    "declared": sorted(declared_refs),
                    "actual": sorted(actual_refs),
                    "undeclared": sorted(actual_refs - declared_refs),
                },
            )
        if step.input_vars or has_undeclared:
            marker = _generate_marker() if settings.spotlighting_enabled else ""
            resolved_prompt = context.resolve_text_safe(step.prompt, marker=marker)
        else:
            marker = ""
            resolved_prompt = context.resolve_text(step.prompt)

        # Append format instruction if output_format is set (P8)
        if step.output_format and step.output_format in FORMAT_INSTRUCTIONS:
            resolved_prompt += FORMAT_INSTRUCTIONS[step.output_format]

        # F3: Inject worker turn buffer if planner requested it
        if step.include_worker_history and session_id:
            worker_ctx = self._worker_contexts.get(session_id)
            if worker_ctx:
                self._worker_context_accessed[session_id] = time.monotonic()
                context_block = worker_ctx.format_context()
                if context_block:
                    resolved_prompt = context_block + "\n\n[Current task:]\n" + resolved_prompt

        # Verbose logging — capture prompts/responses for stress test analysis.
        # Only populated when SENTINEL_VERBOSE_RESULTS=true (never in production).
        verbose = settings.verbose_results
        _v: dict = {}
        if verbose:
            _v["planner_prompt"] = step.prompt
            _v["resolved_prompt"] = resolved_prompt

        try:
            tagged, worker_stats = await asyncio.wait_for(
                self._pipeline.process_with_qwen(
                    prompt=resolved_prompt,
                    marker=marker or None,
                    skip_input_scan=bool(step.input_vars) or destination == OutputDestination.DISPLAY,
                    user_input=user_input,
                    destination=destination,
                ),
                timeout=settings.worker_timeout,
            )

            # Type-check to avoid MagicMock leaking into Pydantic models in tests.
            worker_usage = worker_stats if isinstance(worker_stats, dict) else None

            # Capture Qwen's raw response before any post-processing
            logger.debug(
                "Raw Qwen output received (before any processing)",
                extra={
                    "event": "qwen_raw_output",
                    "step_id": step.id,
                    "content_length": len(tagged.content) if tagged.content else 0,
                    "content_full": tagged.content,
                    "has_entities": ("&lt;" in (tagged.content or "") or "&gt;" in (tagged.content or "")),
                    "has_response_tags": ("<RESPONSE>" in (tagged.content or "")),
                    "data_id": tagged.id,
                },
            )
            if verbose:
                _v["worker_response"] = tagged.content

            # Fail-closed: if Semgrep is required but unavailable, block
            if settings.require_semgrep and not semgrep_scanner.is_loaded():
                logger.warning(
                    "Semgrep required but not loaded — blocking step",
                    extra={
                        "event": "semgrep_unavailable",
                        "step_id": step.id,
                    },
                )
                return StepResult(
                    step_id=step.id,
                    status="blocked",
                    error="Semgrep required but not loaded",
                    **_v,
                )

            # D-005: Strip emoji BEFORE scanning — prevents emoji injection bypass
            # where emoji causes Semgrep parse failure, then stripping produces
            # clean malicious code that was never successfully scanned.
            pre_emoji = tagged.content
            tagged.content = strip_emoji_from_code_blocks(tagged.content)
            if tagged.content != pre_emoji:
                logger.debug(
                    "Emoji stripped from code blocks",
                    extra={
                        "event": "emoji_strip",
                        "step_id": step.id,
                        "chars_removed": len(pre_emoji) - len(tagged.content),
                    },
                )

            # Qwen3 thinking mode produces <think>...</think> blocks even in
            # non-thinking prompts (architecture leakage). <RESPONSE> tags are
            # from the tagged output format instruction. Strip both defensively
            # before code block extraction — the B-006 fallback puts the entire
            # text into a single CodeBlock, so surviving tags would re-appear
            # when the EXECUTION destination unwraps the block.
            stripped = tagged.content.strip()
            stripped = re.sub(
                r"<think>.*?</think>\s*", "", stripped, flags=re.DOTALL
            ).strip()
            if "<RESPONSE>" in stripped and "</RESPONSE>" in stripped:
                start = stripped.index("<RESPONSE>") + len("<RESPONSE>")
                end = stripped.rindex("</RESPONSE>")
                extracted = stripped[start:end].strip()
                logger.debug(
                    "RESPONSE tag extraction",
                    extra={
                        "event": "response_tag_extract",
                        "step_id": step.id,
                        "pre_extract_length": len(stripped),
                        "post_extract_length": len(extracted),
                        "pre_extract_preview": stripped[:500],
                        "post_extract_preview": extracted[:500],
                        "has_entities_before": ("&lt;" in stripped),
                        "has_entities_after": ("&lt;" in extracted),
                    },
                )
                # Qwen sometimes entity-encodes HTML content inside
                # RESPONSE tags (treating them as XML). Unescape to
                # restore raw HTML. Safe: html.unescape on non-encoded
                # content is a no-op.
                if "&lt;" in extracted or "&gt;" in extracted or "&amp;" in extracted:
                    extracted = html_module.unescape(extracted)
                    logger.info(
                        "Unescaped HTML entities from RESPONSE tag content",
                        extra={
                            "event": "response_entity_unescape",
                            "step_id": step.id,
                        },
                    )
                tagged.content = extracted
                if step.output_format != "tagged":
                    logger.info(
                        "Defensive strip — removed unsolicited RESPONSE tags "
                        "from worker output",
                        extra={
                            "event": "defensive_response_tag_strip",
                            "step_id": step.id,
                            "output_format": step.output_format,
                        },
                    )
            elif "<RESPONSE>" in stripped:
                start = stripped.index("<RESPONSE>") + len("<RESPONSE>")
                tagged.content = stripped[start:].strip()
                logger.info(
                    "Stripped truncated RESPONSE tag (no closing tag — "
                    "likely output cap hit)",
                    extra={
                        "event": "truncated_response_tag_strip",
                        "step_id": step.id,
                    },
                )
            else:
                tagged.content = stripped
                logger.debug(
                    "No RESPONSE tags found — content used as-is",
                    extra={
                        "event": "no_response_tags",
                        "step_id": step.id,
                        "content_preview": stripped[:500],
                        "has_entities": ("&lt;" in stripped),
                    },
                )

            # R9: Close unclosed code fences.
            pre_fence = tagged.content
            tagged.content = close_unclosed_fences(tagged.content)
            if tagged.content != pre_fence:
                logger.debug(
                    "Closed unclosed code fences",
                    extra={"event": "fence_close", "step_id": step.id},
                )

            # Extract code blocks once
            code_blocks = extract_code_blocks(tagged.content)
            logger.debug(
                "Code blocks extracted",
                extra={
                    "event": "code_blocks_extracted",
                    "step_id": step.id,
                    "block_count": len(code_blocks),
                    "block_languages": [b.language for b in code_blocks],
                    "block_previews": [b.code[:300] for b in code_blocks],
                    "blocks_have_entities": [("&lt;" in b.code) for b in code_blocks],
                },
            )

            # R7: Post-generation quality gate — warns, never blocks.
            # Runs BEFORE Semgrep so warnings are available even on blocked
            # steps (e.g. truncation signal on Semgrep-blocked output helps
            # F1 enriched planner history diagnose the failure mode).
            quality_warnings = check_code_quality(code_blocks, worker_usage)
            if quality_warnings:
                logger.warning(
                    "Quality gate warnings",
                    extra={
                        "event": "quality_gate_warnings",
                        "step_id": step.id,
                        "warnings": quality_warnings,
                    },
                )

            # Semgrep scan on ALL Qwen output (not just expects_code steps).
            if semgrep_scanner.is_loaded():
                sg_result = await semgrep_scanner.scan_blocks(
                    [(b.code, b.language) for b in code_blocks]
                )
                if sg_result.found:
                    logger.warning(
                        "Semgrep blocked generated code",
                        extra={
                            "event": "semgrep_blocked",
                            "step_id": step.id,
                            "matches": len(sg_result.matches),
                        },
                    )
                    return StepResult(
                        step_id=step.id,
                        status="blocked",
                        error=f"Semgrep: insecure code detected ({len(sg_result.matches)} issues)",
                        quality_warnings=quality_warnings,
                        **_v,
                    )

            # Validate output format if specified (P8)
            content = tagged.content
            if step.output_format == "json":
                try:
                    json.loads(content)
                except (json.JSONDecodeError, ValueError):
                    return StepResult(
                        step_id=step.id,
                        status="error",
                        error="Output format violation: response is not valid JSON",
                        **_v,
                    )

            # When the output feeds a downstream tool_call (EXECUTION destination),
            # unwrap markdown code fences. Qwen frequently wraps code in
            # ```python...``` even for execution-destined output. A single code
            # block means the entire response IS the code — safe to unwrap.
            # Multiple blocks or DISPLAY-destined output are left as-is.
            if (
                destination == OutputDestination.EXECUTION
                and len(code_blocks) == 1
                and code_blocks[0].code.strip()
            ):
                content = code_blocks[0].code
                logger.debug(
                    "Unwrapped single code block for execution-destined output",
                    extra={
                        "event": "execution_fence_unwrap",
                        "step_id": step.id,
                        "language": code_blocks[0].language,
                        "content_preview": content[:500],
                        "has_entities": ("&lt;" in content),
                    },
                )
            else:
                logger.debug(
                    "No fence unwrap (multi-block or display destination)",
                    extra={
                        "event": "no_fence_unwrap",
                        "step_id": step.id,
                        "destination": str(destination),
                        "block_count": len(code_blocks),
                        "content_preview": content[:500],
                        "has_entities": ("&lt;" in content),
                    },
                )

            tagged.content = content
            # Persist the cleaned content back to the provenance store
            logger.debug(
                "Final content before provenance store",
                extra={
                    "event": "pre_provenance_store",
                    "step_id": step.id,
                    "data_id": tagged.id,
                    "content_length": len(content),
                    "content_full": content,
                    "has_entities": ("&lt;" in content),
                },
            )
            await update_provenance_content(tagged.id, content)

            return StepResult(
                step_id=step.id,
                status="success",
                data_id=tagged.id,
                content=content,
                worker_usage=worker_usage,
                quality_warnings=quality_warnings,
                **_v,
            )
        except asyncio.TimeoutError:
            logger.error(
                "Worker inference timed out",
                extra={
                    "event": "worker_timeout",
                    "step_id": step.id,
                    "timeout_s": settings.worker_timeout,
                },
            )
            return StepResult(
                step_id=step.id,
                status="error",
                error=f"Worker inference timed out after {settings.worker_timeout}s",
                **_v,
            )
        except SecurityViolation as exc:
            # Capture Qwen's raw response from the exception (post-Qwen violations
            # like output scan or echo scan include it; pre-Qwen violations don't)
            if verbose and exc.raw_response is not None:
                _v["worker_response"] = exc.raw_response
            # Build specific block reason from scan results
            details = []
            for scanner_name, sr in exc.scan_results.items():
                patterns = [m.pattern_name for m in sr.matches]
                details.append(f"{scanner_name}: {', '.join(patterns)}")
            specific = "; ".join(details) if details else str(exc)
            return StepResult(
                step_id=step.id,
                status="blocked",
                error=f"Output blocked — {specific}",
                **_v,
            )
        except Exception as exc:
            logger.error(
                "LLM task failed",
                extra={"event": "llm_task_error", "step_id": step.id, "error": str(exc)},
            )
            return StepResult(
                step_id=step.id,
                status="error",
                error=genericise_error(f"LLM task failed: {exc}") or "LLM task failed",
                **_v,
            )

    async def _execute_tool_call(
        self, step: PlanStep, context: ExecutionContext,
        destination: OutputDestination = OutputDestination.EXECUTION,
        session_id: str | None = None,
        user_id: int = 1,
        effective_tl: int | None = None,
    ) -> tuple[StepResult, dict | None]:
        """Execute a tool call step with security chain enforcement.

        Security chain (visible in sequence):
          S3: check_provenance()   — BEFORE argument resolution
              context.resolve_args — argument resolution
          S4: validate_constraints — on RESOLVED args
          S5: dispatch_tool        — output scanned BEFORE return
        """
        # Resolve trust level: parameter > system default
        if effective_tl is None:
            effective_tl = settings.trust_level

        if not step.tool:
            return StepResult(
                step_id=step.id,
                status="error",
                error="Tool call step has no tool specified",
            ), None

        # S3: Provenance gate BEFORE argument resolution
        provenance_block = await check_provenance(step, context, effective_tl)
        if provenance_block:
            return provenance_block, None

        # resolve_args uses the UNSAFE resolver (resolve_text, not resolve_text_safe)
        # intentionally — tools need raw content, not UNTRUSTED_DATA-wrapped content.
        # Trust is enforced by the S3/S4/S5 gate chain, not by data marking.
        resolved_args = context.resolve_args(step.args)

        # Log resolved args for debugging — shows what content the tool receives
        _resolved_preview = {}
        for k, v in resolved_args.items():
            if isinstance(v, str):
                _resolved_preview[k] = {
                    "length": len(v),
                    "preview": v[:300],
                    "has_entities": ("&lt;" in v or "&gt;" in v),
                }
            elif isinstance(v, dict):
                _resolved_preview[k] = {}
                for dk, dv in v.items():
                    if isinstance(dv, str):
                        _resolved_preview[k][dk] = {
                            "length": len(dv),
                            "preview": dv[:300],
                            "has_entities": ("&lt;" in dv or "&gt;" in dv),
                        }
                    else:
                        _resolved_preview[k][dk] = str(dv)
            else:
                _resolved_preview[k] = str(v)
        logger.debug(
            "Tool step — resolved args",
            extra={
                "event": "tool_resolved_args",
                "step_id": step.id,
                "tool": step.tool,
                "resolved_args_detail": _resolved_preview,
            },
        )

        # S4: Constraint validation on resolved args (TL4+)
        constraint_block = await validate_constraints(step, resolved_args, effective_tl)
        if constraint_block:
            return constraint_block, None

        # Recipient resolution — convert "user {N}" to real channel identifiers.
        # Runs AFTER S3→resolve→S4 (security operates on opaque IDs) and
        # BEFORE tool dispatch (handler needs real identifiers).
        from sentinel.contacts.resolver import resolve_tool_recipient
        try:
            resolved_args = await resolve_tool_recipient(
                self._contact_store, step.tool, resolved_args,
            )
        except ValueError as exc:
            return StepResult(
                step_id=step.id,
                status="error",
                error=str(exc),
            ), None

        # S5: Dispatch and scan output before returning
        return await dispatch_tool(
            step=step,
            resolved_args=resolved_args,
            destination=destination,
            session_id=session_id,
            safe_tool_handlers=self._safe_tool_handlers,
            tool_executor=self._tool_executor,
            pipeline=self._pipeline,
            tool_timeout=settings.tool_timeout,
            user_id=user_id,
        )

    @staticmethod
    async def _get_tagged_data(data_id: str) -> TaggedData | None:
        from sentinel.security.provenance import get_tagged_data
        return await get_tagged_data(data_id)
