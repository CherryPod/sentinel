"""Gap synthesis — security-opaque gap detection and enriched request building.

Analyses TaskResult to produce short, actionable gap summaries that guide
the loop controller's retry logic. Defence-in-depth: gap text never leaks
scanner names, rule IDs, or security mechanism details.

Used by loop_controller.py — all functions are module-level (no class state).
"""

from __future__ import annotations

import logging
import re

from sentinel.core.models import TaskResult
from sentinel.crypto.blind_index import log_hash

logger = logging.getLogger(__name__)

# Allowlist of error patterns safe to surface to the planner.
# Only matches pass through; everything else is redacted to a generic
# message. This is fail-safe: a missing pattern just hides the detail,
# whereas a blocklist miss would leak security internals.
_SAFE_ERROR_PATTERNS = re.compile(
    r"|".join(
        [
            r"not found",  # file/selector/anchor not found
            r"matched \d+ rules?",  # ambiguous CSS/HTML selector
            r"no such file",  # filesystem errors
            r"already exists",  # file already exists
            r"syntax",  # syntax errors from code fixer / validators
            r"timed?\s*out",  # timeouts
            r"empty",  # empty content/output
            r"too large",  # size limits
            r"exceeds",  # size limits
            r"Use a more specific",  # tool guidance (from ToolError messages)
            r"Re-read the file",  # tool guidance
            r"unknown tool",  # bad tool name
            r"is disabled",  # tool disabled
            r"is required",  # missing required arg
            r"must be a valid",  # bad arg format
            r"failed:",  # tool-level failures (e.g. "Web search failed: ...")
            r"could not (?:find|parse|read|resolve)",  # resolution failures
            r"invalid",  # invalid input
            r"path.*outside",  # workspace boundary errors
        ]
    ),
    re.IGNORECASE,
)

# Generic message used when error doesn't match any safe pattern
_REDACTED_ERROR = "Operation was not permitted."

# Defence-in-depth: terms that must never reach the planner from ANY
# source, including judge verdicts. The judge shouldn't see these,
# but step outcomes could echo them and the judge could parrot them.
_CRITICAL_LEAK_RE = re.compile(
    r"|".join(
        re.escape(t)
        for t in [
            "semgrep",
            "yara",
            "clamav",
            "codeshield",
            "prompt.?guard",
            "scanner",
            "scan.?pipeline",
            "innerHTML-xss",
            "no-new-privileges",
            "securityopt",
            "rule_id",
        ]
    ),
    re.IGNORECASE,
)


def _scrub_critical_terms(text: str) -> str:
    """Remove critical security terms from any planner-facing text.

    Defence-in-depth backstop applied to judge gaps and any other
    free-text that reaches the planner. Replaces matches with a
    generic phrase.
    """
    return _CRITICAL_LEAK_RE.sub("a security check", text)


def _sanitise_error(error: str) -> str:
    """Return the error text if it matches a safe pattern, else redact.

    Allowlist approach: only known-safe error descriptions pass through
    to the planner. Anything that might reveal security stack internals
    (scanner names, rule IDs, policy details, trust levels) is replaced
    with a generic message.
    """
    logger.debug(
        "_sanitise_error called",
        extra={"event": "sanitise.error", "error_len": len(error) if error else 0},
    )
    if not error:
        logger.debug(
            "_sanitise_error: exit — empty error",
            extra={"event": "sanitise.error_exit", "reason": "empty_input"},
        )
        return ""
    logger.debug(
        "_sanitise_error: not_error_passed",
        extra={"event": "sanitise.error_exit.passed", "reason": "not_error_passed"},
    )  # auto:neg
    if _SAFE_ERROR_PATTERNS.search(error):
        logger.debug(
            "_sanitise_error: exit — safe pattern matched",
            extra={
                "event": "sanitise.error_exit",
                "reason": "safe_match",
                "truncated_len": min(len(error), 150),
            },
        )
        return error[:150]
    logger.debug(
        "_sanitise_error: search_error_passed",
        extra={"event": "sanitise.error_exit.passed", "reason": "search_error_passed"},
    )  # auto:neg
    return _REDACTED_ERROR


def _check_judge_gap(result: TaskResult) -> str | None:
    """Check if the judge provided a gap assessment (highest quality signal).

    Judge gap is Claude's assessment — it doesn't see security internals
    (only step outcomes), so pass through with truncation. Defence-in-depth
    scrub in case step outcomes echo security terms.
    """
    logger.debug(
        "_check_judge_gap: entry",
        extra={
            "event": "check.judge_gap_entry",
            "has_judge_verdict": bool(result.judge_verdict),
            "has_gap": bool(result.judge_verdict and result.judge_verdict.get("gap")),
        },
    )
    if not (result.judge_verdict and result.judge_verdict.get("gap")):
        logger.debug(
            "_check_judge_gap: no gap detected",
            extra={"event": "check.judge_gap_none"},
        )
        return None
    gap = _scrub_critical_terms(result.judge_verdict["gap"][:200])
    logger.debug(
        "synthesise_gap: using judge GAP — '%s'",
        gap,
        extra={
            "event": "synthesise.gap_chosen",
            "source": "judge_verdict",
            "gap": gap,
        },
    )
    return gap


def _check_blocked_step(result: TaskResult) -> str | None:
    """Check for blocked/rejected steps from the security pipeline.

    Always redacts the detail — never surfaces scanner/policy info.
    """
    logger.debug(
        "_check_blocked_step: entry",
        extra={
            "event": "check.blocked_step_entry",
            "step_count": len(result.step_results) if result.step_results else 0,
        },
    )
    for sr in result.step_results:
        if sr.status in ("blocked", "rejected"):
            gap = (
                f"Step {sr.step_id} {sr.tool or 'llm_task'} was rejected. "
                f"{_REDACTED_ERROR} Try a different approach."
            )
            logger.debug(
                "synthesise_gap: step blocked/rejected — step_id=%s, tool=%s, gap='%s'",
                sr.step_id,
                sr.tool,
                gap,
                extra={
                    "event": "synthesise.gap_chosen",
                    "source": "step_blocked_rejected",
                    "step_id": sr.step_id,
                    "step_status": sr.status,
                    "gap": gap,
                    "original_error_redacted": bool(sr.error),
                },
            )
            return gap
    logger.debug(
        "_check_blocked_step: no gap detected",
        extra={"event": "check.blocked_step_none"},
    )
    return None


def _check_no_mutations(result: TaskResult) -> str | None:
    """Check for goal actions executed but no file mutations produced."""
    _entry_muts = result.file_mutations or []
    logger.debug(
        "_check_no_mutations: entry",
        extra={
            "event": "check.no_mutations_entry",
            "goal_actions_executed": result.goal_actions_executed,
            "file_mutations_count": len(_entry_muts),
            "file_mutation_path_lens": [
                len(m.get("path") or m.get("file_path") or "") for m in _entry_muts
            ],
            "file_mutation_path_hashes": [
                log_hash(m.get("path") or m.get("file_path") or None)
                for m in _entry_muts
            ],
        },
    )
    if not (result.goal_actions_executed and not result.file_mutations):
        logger.debug(
            "_check_no_mutations: no gap detected",
            extra={"event": "check.no_mutations_none"},
        )
        return None
    gap = "Plan ran but no files were changed. Check that modifications are being applied."
    _gap_muts = result.file_mutations or []
    logger.debug(
        "synthesise_gap: goal actions executed but no file mutations — "
        "goal_actions=%s, file_mutations_count=%d, gap='%s'",
        result.goal_actions_executed,
        len(_gap_muts),
        gap,
        extra={
            "event": "synthesise.gap_chosen",
            "source": "no_file_mutations",
            "goal_actions_executed": result.goal_actions_executed,
            "file_mutations_count": len(_gap_muts),
            "file_mutation_path_lens": [
                len(m.get("path") or m.get("file_path") or "") for m in _gap_muts
            ],
            "file_mutation_path_hashes": [
                log_hash(m.get("path") or m.get("file_path") or None)
                for m in _gap_muts
            ],
            "gap": gap,
        },
    )
    return gap


def _check_empty_output(result: TaskResult) -> str | None:
    """Check for steps that succeeded but produced empty output."""
    logger.debug(
        "_check_empty_output: entry",
        extra={
            "event": "check.empty_output_entry",
            "step_count": len(result.step_results) if result.step_results else 0,
        },
    )
    for sr in result.step_results:
        if getattr(sr, "output_size", None) == 0 and sr.status == "success":
            total = len(result.step_results)
            success = sum(1 for s in result.step_results if s.status == "success")
            gap = (
                f"{success}/{total} steps succeeded. "
                f"Step {sr.step_id} produced empty output."
            )
            logger.debug(
                "synthesise_gap: empty llm_task output — step_id=%s, gap='%s'",
                sr.step_id,
                gap,
                extra={
                    "event": "synthesise.gap_chosen",
                    "source": "empty_output",
                    "step_id": sr.step_id,
                    "gap": gap,
                },
            )
            return gap
    logger.debug(
        "_check_empty_output: no gap detected",
        extra={"event": "check.empty_output_none"},
    )
    return None


def _check_partial_completion(result: TaskResult) -> str | None:
    """Check for partial completion — all steps ran but task incomplete."""
    logger.debug(
        "_check_partial_completion: entry",
        extra={
            "event": "check.partial_completion_entry",
            "result_completion": result.completion,
            "result_status": result.status,
        },
    )
    if result.completion != "partial":
        logger.debug(
            "_check_partial_completion: no gap detected",
            extra={"event": "check.partial_completion_none"},
        )
        return None
    assertion_failures = result.assertion_failures or []
    gap = "All steps ran but the task is incomplete. Additional steps may be needed."
    logger.debug(
        "synthesise_gap: completion is partial — status=%s, "
        "assertion_failures=%d, gap='%s'. "
        "NOTE: partial completion is often caused by assertion failures "
        "marking the task as partial even when steps succeeded.",
        result.status,
        len(assertion_failures),
        gap,
        extra={
            "event": "synthesise.gap_chosen",
            "source": "completion_partial",
            "result_status": result.status,
            "result_completion": result.completion,
            "assertion_failure_count": len(assertion_failures),
            "assertion_failure_types": [
                f.get("type", "unknown") if isinstance(f, dict) else "unknown"
                for f in assertion_failures
            ],
            "gap": gap,
        },
    )
    return gap


def _check_step_failure(result: TaskResult) -> str | None:
    """Check for failed/error/soft_failed steps with sanitised error detail.

    Includes sanitised error detail so the planner can understand WHY and
    adapt, not just "try again".
    """
    logger.debug(
        "_check_step_failure: entry",
        extra={
            "event": "check.step_failure_entry",
            "step_count": len(result.step_results) if result.step_results else 0,
        },
    )
    for sr in result.step_results:
        if sr.status in ("failed", "error", "soft_failed"):
            safe_detail = _sanitise_error(sr.error) if sr.error else ""
            if safe_detail and safe_detail != _REDACTED_ERROR:
                gap = (
                    f"Step {sr.step_id} {sr.tool or 'llm_task'} failed: "
                    f"{safe_detail}. Try a different approach."
                )
            else:
                gap = (
                    f"Step {sr.step_id} {sr.tool or 'llm_task'} failed. "
                    f"Try a different approach."
                )
            logger.debug(
                "synthesise_gap: step failed — step_id=%s, status=%s, "
                "tool=%s, gap='%s'",
                sr.step_id,
                sr.status,
                sr.tool,
                gap,
                extra={
                    "event": "synthesise.gap_chosen",
                    "source": "step_failed",
                    "step_id": sr.step_id,
                    "step_status": sr.status,
                    "step_tool": sr.tool,
                    "gap": gap,
                    "error_sanitised": safe_detail != sr.error if sr.error else False,
                },
            )
            return gap
    logger.debug(
        "_check_step_failure: no gap detected",
        extra={"event": "check.step_failure_none"},
    )
    return None


# Ordered priority cascade for gap detection — first match wins.
# Each detector returns a gap string or None.
_GAP_DETECTORS = [
    _check_judge_gap,
    _check_blocked_step,
    _check_no_mutations,
    _check_empty_output,
    _check_partial_completion,
    _check_step_failure,
]


def synthesise_gap(result: TaskResult) -> str:
    """Produce a short, actionable, security-opaque gap summary.

    Runs detectors in priority order (judge > blocked > no-mutations >
    empty-output > partial > step-failure). First match wins.
    Returns max ~200 chars of behavioural guidance.
    """
    step_statuses = (
        [
            {"step_id": sr.step_id, "status": sr.status, "tool": sr.tool}
            for sr in result.step_results
        ]
        if result.step_results
        else []
    )
    assertion_failures = result.assertion_failures or []
    _start_muts = result.file_mutations or []
    logger.debug(
        "synthesise_gap: starting — status=%s, completion=%s, "
        "goal_actions=%s, file_mutations_count=%d, "
        "step_count=%d, step_statuses=%s, "
        "judge_verdict=%s, assertion_failures=%d",
        result.status,
        result.completion,
        result.goal_actions_executed,
        len(_start_muts),
        len(result.step_results) if result.step_results else 0,
        step_statuses,
        bool(result.judge_verdict),
        len(assertion_failures),
        extra={
            "event": "synthesise.gap_start",
            "result_status": result.status,
            "result_completion": result.completion,
            "goal_actions_executed": result.goal_actions_executed,
            "file_mutations_count": len(_start_muts),
            "file_mutation_path_lens": [
                len(m.get("path") or m.get("file_path") or "") for m in _start_muts
            ],
            "file_mutation_path_hashes": [
                log_hash(m.get("path") or m.get("file_path") or None)
                for m in _start_muts
            ],
            "step_count": len(result.step_results) if result.step_results else 0,
            "step_statuses": step_statuses,
            "has_judge_verdict": bool(result.judge_verdict),
            "judge_verdict_goal_met": result.judge_verdict.get("GOAL_MET")
            if result.judge_verdict
            else None,
            "judge_verdict_gap_len": len(result.judge_verdict.get("gap", ""))
            if result.judge_verdict
            else 0,
            "assertion_failure_count": len(assertion_failures),
            "assertion_failure_types": [
                f.get("type", "unknown") if isinstance(f, dict) else "unknown"
                for f in assertion_failures
            ],
            "assertion_failure_message_lens": [
                len(f.get("message", "")) if isinstance(f, dict) else 0
                for f in assertion_failures
            ],
        },
    )

    # Run detectors in priority order — first match wins
    for detector in _GAP_DETECTORS:
        gap = detector(result)
        if gap is not None:
            return gap

    # Catch-all — no detector matched
    gap = "Task did not fully succeed. Try a fundamentally different approach."
    logger.debug(
        "synthesise_gap: catch-all — no specific pattern matched. "
        "status=%s, completion=%s, step_count=%d, gap='%s'",
        result.status,
        result.completion,
        len(result.step_results) if result.step_results else 0,
        gap,
        extra={
            "event": "synthesise.gap_chosen",
            "source": "catch_all",
            "result_status": result.status,
            "result_completion": result.completion,
            "gap": gap,
        },
    )
    return gap


def build_enriched_request(
    original: str,
    gap: str,
    history: list[dict],
) -> str:
    """Build the enriched request for the next iteration.

    Most recent 2 attempts at full detail, older ones compressed
    to a single line each.
    """
    logger.debug(
        "build_enriched_request: original_len=%d, gap='%s', "
        "history_count=%d, history_gaps=%s",
        len(original),
        gap,
        len(history),
        [h.get("gap_summary", "unknown")[:60] for h in history],
        extra={
            "event": "build.enriched_request",
            "original_length": len(original),
            "gap": gap,
            "history_count": len(history),
            "history_gaps": [h.get("gap_summary", "unknown") for h in history],
            "history_statuses": [h.get("task_status", "unknown") for h in history],
        },
    )
    lines = [original, "", "PRIOR ATTEMPTS:"]

    all_attempts = [*history, {"iteration": len(history) + 1, "gap_summary": gap}]

    for attempt in all_attempts:
        iteration = attempt["iteration"]
        attempt_gap = attempt.get("gap_summary", "unknown")

        # Compress older attempts (all except the most recent 2)
        if iteration <= len(all_attempts) - 2:
            # Truncate to ~60 chars for compressed line
            short = attempt_gap[:60].rstrip()
            if len(attempt_gap) > 60:
                short += "..."
            lines.append(f"- Attempt {iteration}: {short}")
        else:
            lines.append(f"- Attempt {iteration}: {attempt_gap}")

    lines.append("")
    lines.append("Use a different approach from previous attempts.")

    result = "\n".join(lines)
    logger.debug(
        "build_enriched_request: built — length=%d, attempt_count=%d, preview='%s'",
        len(result),
        len(all_attempts),
        result[:300],
        extra={
            "event": "build.enriched_request_result",
            "result_length": len(result),
            "attempt_count": len(all_attempts),
        },
    )
    return result
