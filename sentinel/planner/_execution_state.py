"""Plan execution state initialisation, result assembly helpers, and replan summary.

Contains _init_plan_exec_state (initial PlanExecState construction),
_truncate_plan_prompts (storage-safe plan serialisation),
_collect_tier1_signals (deterministic verification signal aggregation),
and _build_replan_summary (compact context for plan_json storage).

Extracted from _execution.py during planner modularisation Phase 4.
"""

import logging
import time

from sentinel.core.models import Plan, PlanStep, StepResult
from sentinel.planner.verification import (
    check_goal_actions_executed,
    detect_idempotent_calls,
    extract_file_mutations,
    scan_tool_output,
)

from ._execution_context import ExecutionContext
from ._task_context import PlanExecState

logger = logging.getLogger(__name__)


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


def _init_plan_exec_state(
    plan: Plan,
    user_input: str | None,
    task_id: str,
    session_id: str | None,
    user_id: int,
    effective_tl: int | None,
    available_tools: list[dict] | None,
    execution_vars: dict,
) -> PlanExecState:
    """Build the initial PlanExecState for a plan execution run."""
    state = PlanExecState(
        plan=plan,
        user_input=user_input,
        task_id=task_id,
        session_id=session_id,
        user_id=user_id,
        effective_tl=effective_tl,
        available_tools=available_tools,
        plan_t0=time.monotonic(),
        context=ExecutionContext(),
        remaining_steps=list(plan.steps),
        execution_vars=execution_vars,
        current_phase={
            "phase": "initial",
            "trigger": None,
            "trigger_step": None,
            "plan": _truncate_plan_prompts(plan.model_dump(exclude_none=True)),
            "step_outcomes_summary": {},
            "replan_context_summary": None,
        },
    )
    logger.debug(
        "plan_history: initial phase captured",
        extra={"event": "execution.plan_history_init", "step_count": len(plan.steps)},
    )
    return state


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
    logger.debug(
        "_build_replan_summary called",
        extra={
            "event": "execution.build_replan_summary",
            "step_count": len(executed_steps),
            "outcome_count": len(step_outcomes),
            "failure_trigger": failure_trigger,
        },
    )
    if not executed_steps:
        return ""

    parts: list[str] = []

    # Error diagnostic for failure-triggered replans
    if failure_trigger and step_outcomes:
        logger.debug(
            "_build_replan_summary: failure_trigger",
            extra={
                "event": "execution_state.build_replan_summary.match",
                "reason": "failure_trigger",
            },
        )  # auto:neg
        last = step_outcomes[-1]
        error = last.get("error_detail") or last.get("stderr_preview") or ""
        if error:
            logger.debug(
                "_build_replan_summary: error",
                extra={
                    "event": "execution_state.build_replan_summary.match",
                    "reason": "error",
                },
            )  # auto:neg
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
        logger.debug(
            "_build_replan_summary: condition_match",
            extra={
                "event": "execution_state.build_replan_summary.match",
                "reason": "condition_match",
            },
        )  # auto:neg
        truncated = result[:497]
        last_semi = truncated.rfind(";")
        if last_semi > 0:
            logger.debug(
                "_build_replan_summary: last_semi_gt_0",
                extra={
                    "event": "execution_state.build_replan_summary.match",
                    "reason": "last_semi_gt_0",
                },
            )  # auto:neg
            result = truncated[:last_semi] + "..."
        else:
            logger.debug(
                "_build_replan_summary: last_semi_gt_0",
                extra={
                    "event": "execution_state.build_replan_summary.clean",
                    "reason": "last_semi_gt_0",
                },
            )  # auto:neg
            result = truncated + "..."

    return result


def _collect_tier1_signals(
    step_results: list[StepResult],
    step_outcomes: list[dict],
) -> tuple[bool, list[dict], list[dict], list[str]]:
    """Compute Tier 1 deterministic verification signals from execution data.

    Returns (goal_actions_executed, file_mutations, all_warnings, idempotent_calls).
    """
    goal_actions = check_goal_actions_executed(step_outcomes)
    file_muts = extract_file_mutations(step_outcomes)

    # Collect tool output warnings from step results
    all_warnings: list[dict] = []
    for sr in step_results:
        if sr.content:
            for w in scan_tool_output(sr.content):
                all_warnings.append(
                    {
                        "step_id": sr.step_id,
                        "pattern": w.pattern,
                        "severity": w.severity,
                    }
                )

    # Idempotency detection: flag duplicate tool calls with identical output
    idempotent_calls = detect_idempotent_calls(step_outcomes)
    if idempotent_calls:
        logger.warning(
            "Idempotent calls detected: %d duplicate group(s) — %s",
            len(idempotent_calls),
            ", ".join(idempotent_calls),
            extra={
                "event": "execution.idempotent_calls_detected",
                "duplicate_groups": len(idempotent_calls),
                "descriptions": idempotent_calls,
            },
        )
        # Append as tool_output_warnings so they're visible in episodic records
        for desc in idempotent_calls:
            all_warnings.append(
                {
                    "step_id": "plan_level",
                    "pattern": f"idempotent_call: {desc}",
                    "severity": "MEDIUM",
                }
            )

    return goal_actions, file_muts, all_warnings, idempotent_calls
