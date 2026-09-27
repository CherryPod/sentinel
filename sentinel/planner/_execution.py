"""Execution mixin for the Orchestrator.

Contains the ExecutionMixin class with plan/step execution loop, worker
output processing, and delegation to extracted helper modules.

Sub-modules (extracted during planner modularisation Phase 4):
  _execution_context.py  — ExecutionContext (variable bindings)
  _error_tracking.py     — error categorisation, fingerprinting, history
  _output_processing.py  — artifact stripping, security scans, validation
  _execution_state.py    — PlanExecState init, replan summary
  _step_executors.py     — per-step-type execution (llm_task, tool_call)
"""

import hashlib
import logging
import time
from typing import TYPE_CHECKING

from sentinel.crypto.blind_index import log_hash

from sentinel.core.config import settings
from sentinel.core.context import require_user_id
from sentinel.core.models import (
    OutputDestination,
    Plan,
    PlanStep,
    StepResult,
    TaggedData,
    TaskResult,
)
from sentinel.planner.verification import (
    check_goal_actions_executed,
    extract_file_mutations,
)
from sentinel.security import semgrep_scanner
from sentinel.security.provenance import (
    update_content as update_provenance_content,
)
from sentinel.worker.context import WorkerTurn

from ._error_tracking import (
    _record_step_in_plan_history,
    _track_code_fixer_errors,
)
from ._execution_context import ExecutionContext
from ._execution_state import _collect_tier1_signals, _init_plan_exec_state
from ._output_processing import (
    _run_security_scans,
    _strip_worker_artifacts,
    _validate_and_unwrap,
)
from ._response_select import _select_response_text
from ._step_executors import execute_llm_task, execute_tool_call
from ._task_context import PlanExecState

if TYPE_CHECKING:
    from sentinel.tools._handlers._task_exec_context import TaskExecutionContext
# ── Backward-compatibility re-exports ────────────────────────────────
# orchestrator.py and _replan.py import these from _execution.
from ._error_tracking import (  # noqa: F401
    _categorise_error,
    _extract_prior_error,
    _failure_fingerprint,
)
from ._execution_state import (  # noqa: F401
    _build_replan_summary,
    _truncate_plan_prompts,
)
from .builders import (
    build_step_outcome,
    compute_execution_vars,
    enforce_tagged_format,
    get_destination,
)

logger = logging.getLogger(__name__)

# Tools whose output is controller-generated (TRUSTED) and safe to
# show the planner during replan. Filesystem/OS output, not Qwen text.
_TRUSTED_OUTPUT_TOOLS = frozenset(
    {
        "shell",
        "shell_exec",
        "file_read",
        "list_dir",
        "find_file",
    }
)


class ExecutionMixin:
    """Mixin providing plan/step execution methods for the Orchestrator."""

    def _build_execution_result(self, state: PlanExecState) -> TaskResult:
        """Assemble the final TaskResult after plan execution loop completes.

        Extracts response text, computes Tier 1 verification signals
        (goal actions, file mutations, tool output warnings, idempotency),
        determines completion status, and constructs the final TaskResult.
        """
        logger.debug(
            "Building execution result",
            extra={
                "event": "execution.build_execution_result_enter",
                "step_count": len(state.step_results),
                "replan_count": state.replan_count,
                "budget_exhausted": state.budget_exhausted,
                "stagnation_aborted": state.stagnation_aborted,
            },
        )

        # Extract response text from the last llm_task step (by type, not id prefix)
        response_text = _select_response_text(state.step_results, state.executed_steps)

        # Plan-outcome memory: close final phase
        state.plan_phases.append(state.current_phase)

        # ── Tier 1: Deterministic verification signals ──
        goal_actions, file_muts, all_warnings, idempotent_calls = (
            _collect_tier1_signals(state.step_results, state.step_outcomes)
        )

        # Determine completion status
        if state.budget_exhausted or state.stagnation_aborted:
            completion = "partial"
        else:
            completion = "full"

        # Override status: budget exhaustion / stagnation = "partial" not "success"
        final_status = "success"
        if state.budget_exhausted:
            final_status = "partial"
            logger.warning(
                "Task completed with partial status — replan budget exhausted",
                extra={
                    "event": "execution.verification_partial",
                    "reason": "budget_exhausted",
                    "goal_actions_executed": goal_actions,
                    "file_mutations_count": len(file_muts),
                },
            )

        logger.debug(
            "Tier 1 signals computed — goal_actions=%s, mutations=%d, warnings=%d, "
            "idempotent_groups=%d, stagnation_counter=%d, budget_exhausted=%s",
            goal_actions,
            len(file_muts),
            len(all_warnings),
            len(idempotent_calls),
            state.consecutive_no_mutation_replans,
            state.budget_exhausted,
            extra={
                "event": "execution.tier1_signals_summary",
                "goal_actions_executed": goal_actions,
                "file_mutations_count": len(file_muts),
                "tool_output_warnings_count": len(all_warnings),
                "idempotent_call_groups": len(idempotent_calls),
                "consecutive_no_mutation_replans": state.consecutive_no_mutation_replans,
                "budget_exhausted": state.budget_exhausted,
                "stagnation_aborted": state.stagnation_aborted,
            },
        )

        logger.debug(
            "_execute_plan returning TaskResult — status=%s, completion=%s, "
            "goal_actions=%s, file_mutations=%d, "
            "step_count=%d, replan_count=%d, "
            "tool_output_warnings=%d, plan_phases=%d, "
            "has_response=%s, "
            "step_statuses=%s",
            final_status,
            completion,
            goal_actions,
            len(file_muts),
            len(state.step_results),
            state.replan_count,
            len(all_warnings),
            len(state.plan_phases),
            bool(response_text),
            [
                {"id": sr.step_id, "status": sr.status, "tool": sr.tool}
                for sr in state.step_results
            ],
            extra={
                "event": "execution.execute_plan_return",
                "status": final_status,
                "completion": completion,
                "goal_actions_executed": goal_actions,
                "file_mutations_count": len(file_muts),
                "file_mutation_path_lens": [
                    len(m.get("path") or m.get("file_path") or "")
                    for m in file_muts
                ],
                "file_mutation_path_hashes": [
                    log_hash(m.get("path") or m.get("file_path") or None)
                    for m in file_muts
                ],
                "step_count": len(state.step_results),
                "replan_count": state.replan_count,
                "tool_output_warnings_count": len(all_warnings),
                "plan_phases_count": len(state.plan_phases),
                "has_response": bool(response_text),
                "budget_exhausted": state.budget_exhausted,
                "stagnation_aborted": state.stagnation_aborted,
                "step_statuses": [
                    {"id": sr.step_id, "status": sr.status, "tool": sr.tool}
                    for sr in state.step_results
                ],
            },
        )

        return TaskResult(
            status=final_status,
            plan_summary=state.plan.plan_summary,
            step_results=state.step_results,
            step_outcomes=state.step_outcomes,
            response=response_text,
            replan_count=state.replan_count,
            plan_phases=state.plan_phases,
            completion=completion,
            goal_actions_executed=goal_actions,
            file_mutations=file_muts,
            tool_output_warnings=all_warnings,
        )

    # ── Plan execution ───────────────────────────────────────────────

    async def _execute_plan(
        self,
        plan: Plan,
        user_input: str | None = None,
        task_id: str = "",
        session_id: str | None = None,
        user_id: int | None = None,
        effective_tl: int | None = None,
        available_tools: list[dict] | None = None,
        task_exec_context: "TaskExecutionContext | None" = None,
    ) -> TaskResult:
        """Execute all steps in a plan sequentially, with dynamic replanning."""
        user_id = require_user_id(user_id, "Orchestrator._execute_plan")
        execution_vars = compute_execution_vars(plan)
        enforce_tagged_format(plan, execution_vars)

        state = _init_plan_exec_state(
            plan,
            user_input,
            task_id,
            session_id,
            user_id,
            effective_tl,
            available_tools,
            execution_vars,
        )

        while state.remaining_steps:
            step = state.remaining_steps.pop(0)

            # SYS-5a / timeout: abort plan on shutdown or timeout
            abort_result = self._check_plan_abort_conditions(state)
            if abort_result:
                return abort_result

            destination = get_destination(step, state.execution_vars)
            step_t0 = time.monotonic()
            logger.info(
                "Executing step",
                extra={
                    "event": "execution.step_start",
                    "step_id": step.id,
                    "step_type": step.type,
                    "description": step.description,
                    "output_destination": destination.value,
                },
            )

            result, exec_meta = await self._execute_step(
                step,
                state.context,
                user_input=user_input,
                destination=destination,
                session_id=session_id,
                user_id=user_id,
                effective_tl=effective_tl,
                task_exec_context=task_exec_context,
            )
            state.step_results.append(result)
            state.executed_steps.append(step)
            step_elapsed = time.monotonic() - step_t0

            # F1: Build structured step outcome metadata
            state.step_outcomes.append(
                build_step_outcome(
                    step=step,
                    result=result,
                    elapsed_s=step_elapsed,
                    destination=destination,
                    exec_meta=exec_meta,
                )
            )

            # Plan-outcome memory: record condensed outcome for this step
            _record_step_in_plan_history(step, result, state)

            # Track code fixer errors across iterations for degradation detection
            _track_code_fixer_errors(step, exec_meta, state)

            # Post-step bookkeeping: worker context, event emission, output_var
            await self._handle_step_post_processing(
                step, result, state, step_elapsed, task_id, session_id
            )

            # Stop on blocking errors (safety-over-resilience — see U2/RETRY-1)
            abort_result = self._check_blocking_failure(result, state)
            if abort_result:
                return abort_result

            # ── Dynamic replanning checkpoint ──
            if step.replan_after and result.status == "success":
                early_return = await self._handle_continuation_replan(
                    state, step, result
                )
                if early_return:
                    return early_return

            # ── Failure replan checkpoint ──
            elif result.status == "soft_failed":
                early_return = await self._handle_failure_replan(
                    state, step, result, exec_meta
                )
                if early_return:
                    return early_return

        return self._build_execution_result(state)

    # ── _execute_plan helpers ──────────────────────────────────────────

    def _check_plan_abort_conditions(self, state: PlanExecState) -> TaskResult | None:
        """Check whether plan execution should abort (shutdown or timeout).

        Returns a TaskResult if the plan should stop, None to continue.
        """
        # SYS-5a: Abort plan if the process is shutting down
        if self._shutting_down:
            logger.info(
                "Plan aborted — orchestrator shutting down",
                extra={
                    "event": "execution.plan_aborted_shutdown",
                    "steps_completed": len(state.step_results),
                    "steps_total": len(state.plan.steps),
                },
            )
            return TaskResult(
                status="error",
                plan_summary=state.plan.plan_summary,
                step_results=state.step_results,
                step_outcomes=state.step_outcomes,
                reason=(
                    f"Plan aborted — server shutting down "
                    f"({len(state.step_results)}/{len(state.plan.steps)} steps completed)"
                ),
                replan_count=state.replan_count,
                plan_phases=state.plan_phases + [state.current_phase],
            )
        logger.debug(
            "_check_plan_abort_conditions: shutting_down_passed",
            extra={
                "event": "execution.plan_aborted_shutdown.passed",
                "reason": "shutting_down_passed",
            },
        )  # auto:neg

        # Overall plan execution timeout — guard against plans with many steps
        # accumulating beyond the budget.  Per-step timeouts (worker, tool) handle
        # individual hangs; this catches the aggregate.
        plan_elapsed = time.monotonic() - state.plan_t0
        if plan_elapsed > settings.plan_execution_timeout:
            logger.error(
                "Plan execution timed out",
                extra={
                    "event": "execution.plan_execution_timeout",
                    "timeout_s": settings.plan_execution_timeout,
                    "elapsed_s": round(plan_elapsed, 2),
                    "steps_completed": len(state.step_results),
                    "steps_total": len(state.plan.steps),
                },
            )
            return TaskResult(
                status="error",
                plan_summary=state.plan.plan_summary,
                step_results=state.step_results,
                step_outcomes=state.step_outcomes,
                reason=(
                    f"Plan execution timed out after {settings.plan_execution_timeout}s "
                    f"({len(state.step_results)}/{len(state.plan.steps)} steps completed)"
                ),
                replan_count=state.replan_count,
                plan_phases=state.plan_phases + [state.current_phase],
            )

        logger.debug(
            "Abort conditions clear",
            extra={
                "event": "execution.abort_check_passed",
                "shutting_down": False,
                "elapsed_s": round(plan_elapsed, 2),
            },
        )
        return None

    def _check_blocking_failure(
        self, result: StepResult, state: PlanExecState
    ) -> TaskResult | None:
        """Return an abort TaskResult if the step hit a blocking error.

        NOTE (U2/RETRY-1): This aborts the entire plan on first step failure.
        For llm_task steps, a retry on transient errors (Ollama timeout,
        connection reset) could improve resilience.  Left as abort-on-error:
        safety-over-resilience is the design intent, and tool_call steps may
        have side effects that make retries unsafe.
        """
        if result.status not in ("blocked", "error", "failed"):
            return None

        logger.info(
            "Plan aborted — blocking step failure",
            extra={
                "event": "execution.plan_aborted_blocking_failure",
                "step_status": result.status,
                "step_error": result.error,
                "steps_completed": len(state.step_results),
                "steps_total": len(state.plan.steps),
            },
        )
        return TaskResult(
            status=result.status,
            plan_summary=state.plan.plan_summary,
            step_results=state.step_results,
            step_outcomes=state.step_outcomes,
            reason=result.error,
            replan_count=state.replan_count,
            plan_phases=state.plan_phases + [state.current_phase],
            completion="abandoned",
            goal_actions_executed=check_goal_actions_executed(state.step_outcomes),
            file_mutations=extract_file_mutations(state.step_outcomes),
        )

    async def _handle_step_post_processing(
        self,
        step: PlanStep,
        result: StepResult,
        state: PlanExecState,
        step_elapsed: float,
        task_id: str,
        session_id: str | None,
    ) -> None:
        """Post-step bookkeeping: worker context, event emission, output_var storage."""
        logger.debug(
            "Step post-processing started",
            extra={
                "event": "execution.postprocessing.entry",
                "task_id": task_id,
                "step_id": step.id,
                "step_status": result.status,
                "step_elapsed": round(step_elapsed, 3),
            },
        )
        # F3: Update worker turn buffer after successful llm_task steps
        if step.type == "llm_task" and result.status == "success" and session_id:
            worker_ctx = self._worker_contexts.get(session_id)
            if worker_ctx:
                self._worker_context_accessed[session_id] = time.monotonic()
                worker_ctx.add_turn(
                    WorkerTurn(
                        turn_number=len(worker_ctx.turns) + 1,
                        prompt_summary=(step.prompt or "")[:200],
                        response_summary=(result.content or "")[:500],
                        step_outcome=state.step_outcomes[-1],
                        timestamp=time.time(),
                    )
                )
                logger.debug(
                    "Worker turn buffer updated",
                    extra={
                        "event": "execution.worker_turn_added",
                        "step_id": step.id,
                        "session_id": session_id,
                        "turn_count": len(worker_ctx.turns),
                    },
                )

        logger.info(
            "Step completed",
            extra={
                "event": "execution.step_complete",
                "step_id": step.id,
                "status": result.status,
                "elapsed_s": round(step_elapsed, 2),
            },
        )

        # Event: step completed (SSE to UI)
        await self._emit(
            task_id,
            "step_completed",
            {
                "step_id": step.id,
                "status": result.status,
                "content_preview": result.content[:200] if result.content else "",
                "error": result.error,
            },
        )

        # Store result in context if step has output_var
        # NOTE: output_var intentionally not stored for soft_failed steps — the replan
        # replaces remaining steps anyway, so downstream $var references won't exist.
        if result.status == "success" and step.output_var and result.data_id:
            data = await self._get_tagged_data(result.data_id)
            if data:
                state.context.set(step.output_var, data)
                logger.debug(
                    "Variable stored in context",
                    extra={
                        "event": "execution.context_var_set",
                        "var_name": step.output_var,
                        "data_id": result.data_id,
                        "trust_level": data.trust_level.value,
                    },
                )

    async def _execute_step(
        self,
        step: PlanStep,
        context: ExecutionContext,
        user_input: str | None = None,
        destination: OutputDestination = OutputDestination.EXECUTION,
        session_id: str | None = None,
        user_id: int | None = None,
        effective_tl: int | None = None,
        task_exec_context: "TaskExecutionContext | None" = None,
    ) -> tuple[StepResult, dict | None]:
        """Execute a single plan step.

        Dispatches to module-level functions in _step_executors.py.
        Returns (step_result, exec_meta) where exec_meta contains tool-specific
        metadata from the executor (exit_code, stderr, file sizes) or None.
        """
        user_id = require_user_id(user_id, "Orchestrator._execute_step")
        if step.type == "llm_task":
            result = await execute_llm_task(
                step=step,
                context=context,
                pipeline=self._pipeline,
                worker_contexts=self._worker_contexts,
                worker_context_accessed=self._worker_context_accessed,
                process_worker_output=self._process_worker_output,
                user_input=user_input,
                destination=destination,
                session_id=session_id,
            )
            return result, None
        if step.type == "tool_call":
            return await execute_tool_call(
                step=step,
                context=context,
                pipeline=self._pipeline,
                contact_store=self._contact_store,
                safe_tool_handlers=self._safe_tool_handlers,
                tool_executor=self._tool_executor,
                destination=destination,
                session_id=session_id,
                user_id=user_id,
                effective_tl=effective_tl,
                task_exec_context=task_exec_context,
            )
        return StepResult(
            step_id=step.id,
            status="error",
            error=f"Unknown step type: {step.type}",
        ), None

    # ── Thin wrappers for backward compatibility ────────────────────────
    # Tests call orch._execute_llm_task() and orch._execute_tool_call()
    # directly. These delegate to the module functions in _step_executors.py.

    async def _execute_llm_task(
        self,
        step: PlanStep,
        context: ExecutionContext,
        user_input: str | None = None,
        destination: OutputDestination = OutputDestination.EXECUTION,
        session_id: str | None = None,
    ) -> StepResult:
        """Delegate to module function. See _step_executors.execute_llm_task."""
        return await execute_llm_task(
            step=step,
            context=context,
            pipeline=self._pipeline,
            worker_contexts=self._worker_contexts,
            worker_context_accessed=self._worker_context_accessed,
            process_worker_output=self._process_worker_output,
            user_input=user_input,
            destination=destination,
            session_id=session_id,
        )

    async def _execute_tool_call(
        self,
        step: PlanStep,
        context: ExecutionContext,
        destination: OutputDestination = OutputDestination.EXECUTION,
        session_id: str | None = None,
        user_id: int | None = None,
        effective_tl: int | None = None,
        task_exec_context: "TaskExecutionContext | None" = None,
    ) -> tuple[StepResult, dict | None]:
        """Delegate to module function. See _step_executors.execute_tool_call."""
        user_id = require_user_id(user_id, "Orchestrator._execute_tool_call")
        return await execute_tool_call(
            step=step,
            context=context,
            pipeline=self._pipeline,
            contact_store=self._contact_store,
            safe_tool_handlers=self._safe_tool_handlers,
            tool_executor=self._tool_executor,
            destination=destination,
            session_id=session_id,
            user_id=user_id,
            effective_tl=effective_tl,
            task_exec_context=task_exec_context,
        )

    async def _process_worker_output(
        self,
        tagged: TaggedData,
        step: PlanStep,
        destination: OutputDestination,
        worker_usage: dict | None,
        verbose_extra: dict,
    ) -> StepResult:
        """Process raw worker output through the post-generation pipeline.

        Sequential pipeline: semgrep fail-closed check → emoji strip →
        think/RESPONSE tag extraction → fence close → code block extraction →
        quality gate → semgrep scan → format validation → execution unwrap →
        provenance store.

        Always returns a StepResult (blocked, error, or success).
        """
        logger.debug(
            "Worker output processing pipeline entered",
            extra={
                "event": "execution.process_worker_output_enter",
                "step_id": step.id,
                "content_length": len(tagged.content) if tagged.content else 0,
                "destination": destination.value,
            },
        )

        # Fail-closed: if Semgrep is required but unavailable, block
        if settings.require_semgrep and not semgrep_scanner.is_loaded():
            logger.warning(
                "Semgrep required but not loaded — blocking step",
                extra={
                    "event": "execution.semgrep_unavailable",
                    "step_id": step.id,
                },
            )
            return StepResult(
                step_id=step.id,
                status="blocked",
                error="Semgrep required but not loaded",
                **verbose_extra,
            )

        tagged.content = _strip_worker_artifacts(
            tagged.content, step.id, step.output_format
        )

        scan_result = await _run_security_scans(tagged.content, step.id, worker_usage)
        if isinstance(scan_result, StepResult):
            # Semgrep blocked — inject verbose_extra and return
            return StepResult(
                step_id=scan_result.step_id,
                status=scan_result.status,
                error=scan_result.error,
                quality_warnings=scan_result.quality_warnings,
                **verbose_extra,
            )
        code_blocks, quality_warnings = scan_result

        unwrap_result = _validate_and_unwrap(
            tagged.content,
            step.id,
            step.output_format,
            destination,
            code_blocks,
        )
        if isinstance(unwrap_result, StepResult):
            # Format validation failed — inject verbose_extra and return
            return StepResult(
                step_id=unwrap_result.step_id,
                status=unwrap_result.status,
                error=unwrap_result.error,
                **verbose_extra,
            )
        content = unwrap_result
        tagged.content = content
        # Persist the cleaned content back to the provenance store
        logger.debug(
            "Final content before provenance store",
            extra={
                "event": "execution.pre_provenance_store",
                "step_id": step.id,
                "data_id": tagged.id,
                "content_length": len(content),
                "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
                "has_entities": ("&lt;" in content),
            },
        )
        await update_provenance_content(tagged.id, content)

        # Extension point: post-processing enrichers would run here

        logger.debug(
            "Worker output processing pipeline completed",
            extra={
                "event": "execution.process_worker_output_exit",
                "step_id": step.id,
                "content_length": len(content),
            },
        )

        return StepResult(
            step_id=step.id,
            status="success",
            data_id=tagged.id,
            content=content,
            worker_usage=worker_usage,
            quality_warnings=quality_warnings,
            **verbose_extra,
        )

    @staticmethod
    async def _get_tagged_data(data_id: str) -> TaggedData | None:
        from sentinel.security.provenance import get_tagged_data

        return await get_tagged_data(data_id)
