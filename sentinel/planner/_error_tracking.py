"""Error categorisation and failure tracking for plan execution.

Provides error fingerprinting (PentAGI Finding #6), step-outcome
history recording, and code fixer degradation tracking. All functions
are module-level (no mixin/self references).

Extracted from _execution.py during planner modularisation Phase 4.
"""

import hashlib
import logging

from sentinel.core.models import PlanStep, StepResult
from sentinel.memory.episodic import _sanitise_for_planner

from ._task_context import PlanExecState

logger = logging.getLogger(__name__)


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
            # Redact absolute paths — mirrors render_episodic_text's handling
            # of live stderr (sentinel/memory/episodic.py:498). Prior-error
            # summaries are persisted and replayed to the planner on every
            # subsequent turn, so a path leaked once leaks forever without
            # this.
            from sentinel.memory.episodic import (
                _extract_key_stderr_line,
                _redact_paths,
            )

            stderr = _sanitise_for_planner(stderr)
            line = _extract_key_stderr_line(stderr)
            if line:
                parts.append(f"stderr: {_redact_paths(line)}")
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
            # F-02 DiD: SP the full assembled string — error_detail and status
            # flags are controlled vocabulary, but SP here ensures function-
            # boundary safety regardless of caller context.
            return _sanitise_for_planner("; ".join(parts))
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
        logger.debug(
            "Error categorised",
            extra={"event": "execution.categorise", "category": "scanner_block"},
        )
        return "scanner_block"
    logger.debug(
        "_categorise_error: scanner_result_eq_blocked_passed",
        extra={
            "event": "execution.categorise.passed",
            "reason": "scanner_result_eq_blocked_passed",
        },
    )  # auto:neg
    if sandbox_timed_out:
        logger.debug(
            "Error categorised",
            extra={"event": "execution.categorise", "category": "timeout"},
        )
        return "timeout"
    logger.debug(
        "_categorise_error: sandbox_timed_out_passed",
        extra={
            "event": "execution.categorise.passed",
            "reason": "sandbox_timed_out_passed",
        },
    )  # auto:neg
    if sandbox_oom_killed:
        logger.debug(
            "Error categorised",
            extra={"event": "execution.categorise", "category": "oom"},
        )
        return "oom"
    logger.debug(
        "_categorise_error: sandbox_oom_killed_passed",
        extra={
            "event": "execution.categorise.passed",
            "reason": "sandbox_oom_killed_passed",
        },
    )  # auto:neg
    if constraint_result in ("violation", "denylist_block"):
        logger.debug(
            "Error categorised",
            extra={"event": "execution.categorise", "category": "constraint_violation"},
        )
        return "constraint_violation"
    logger.debug(
        "_categorise_error: constraint_result_in_passed",
        extra={
            "event": "execution.categorise.passed",
            "reason": "constraint_result_in_passed",
        },
    )  # auto:neg
    if exit_code is not None and exit_code != 0:
        logger.debug(
            "Error categorised",
            extra={
                "event": "execution.categorise",
                "category": "exit_nonzero",
                "exit_code": exit_code,
            },
        )
        return "exit_nonzero"
    logger.debug(
        "Error categorised",
        extra={"event": "execution.categorise", "category": "unknown"},
    )
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


def _record_step_in_plan_history(
    step: PlanStep, result: StepResult, state: PlanExecState
) -> None:
    """Build a condensed outcome entry and record it in the current plan phase.

    Includes optional diagnostic fields (file sizes, exit codes, scanner results)
    and a failure fingerprint for non-success steps (PentAGI Finding #6).
    """
    step_outcome = state.step_outcomes[-1]  # caller appends before calling

    outcome_entry: dict = {
        "status": result.status,
        "output_size": len(result.content) if result.content else 0,
    }

    # Conditionally include non-None diagnostic fields
    _optional_fields = [
        ("error_detail", "error"),
        ("file_path", "file_path"),
        ("scanner_result", "scanner_result"),
    ]
    for src_key, dst_key in _optional_fields:
        val = step_outcome.get(src_key)
        if val:
            outcome_entry[dst_key] = val

    # Size fields use `is not None` — zero is a valid size
    if step_outcome.get("file_size_before") is not None:
        outcome_entry["file_size_before"] = step_outcome["file_size_before"]
    if step_outcome.get("file_size_after") is not None:
        outcome_entry["file_size_after"] = step_outcome["file_size_after"]
    if step_outcome.get("exit_code") is not None:
        outcome_entry["exit_code"] = step_outcome["exit_code"]

    # Failure fingerprint for non-success steps (PentAGI Finding #6)
    if result.status != "success":
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
            outcome_entry["failure_fingerprint"],
            step.id,
            error_cat,
            extra={
                "event": "execution.plan_history_fingerprint",
                "step_id": step.id,
                "fingerprint": outcome_entry["failure_fingerprint"],
                "error_category": error_cat,
            },
        )

    state.current_phase["step_outcomes_summary"][step.id] = outcome_entry
    logger.debug(
        "plan_history: %s -> %s",
        step.id,
        result.status,
        extra={
            "event": "execution.plan_history_step",
            "step_id": step.id,
            "status": result.status,
        },
    )


def _track_code_fixer_errors(
    step: PlanStep, exec_meta: dict | None, state: PlanExecState
) -> None:
    """Update code fixer degradation counters after a step executes.

    File-writing tools populate code_fixer_errors in exec_meta.  If errors
    persist across consecutive steps the task is degrading, not improving.
    Resets the counter when a file-writing step succeeds without errors.
    """
    meta = exec_meta or {}
    fixer_errors = meta.get("code_fixer_errors", [])
    full_fixer_errors = meta.get("full_file_fixer_errors", [])

    if fixer_errors or full_fixer_errors:
        state.consecutive_fixer_error_iterations += 1
        logger.warning(
            "Code fixer errors detected after step %s (%d consecutive)",
            step.id,
            state.consecutive_fixer_error_iterations,
            extra={
                "event": "execution.fixer_errors_in_step",
                "step_id": step.id,
                "fixer_errors": fixer_errors,
                "full_fixer_errors": full_fixer_errors,
                "consecutive_fixer_error_iterations": state.consecutive_fixer_error_iterations,
            },
        )
    elif step.tool in ("file_write", "file_patch", "website"):
        # Only reset on file-writing steps that succeeded without fixer errors
        if state.consecutive_fixer_error_iterations > 0:
            logger.info(
                "Code fixer errors cleared after step %s (was %d consecutive)",
                step.id,
                state.consecutive_fixer_error_iterations,
                extra={
                    "event": "execution.fixer_errors_cleared",
                    "step_id": step.id,
                    "previous_consecutive": state.consecutive_fixer_error_iterations,
                },
            )
        state.consecutive_fixer_error_iterations = 0
        state.fixer_degradation_applied = False  # Reset penalty for next episode
    else:
        logger.debug(
            "Code fixer tracking: no-op for step %s (tool=%s)",
            step.id,
            step.tool,
            extra={
                "event": "execution.fixer_tracking_noop",
                "step_id": step.id,
                "step_tool": step.tool,
            },
        )
