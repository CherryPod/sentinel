"""Plan history rendering — detailed plan evolution for episodic context.

Renders the tier-2 detailed plan history block for the top episodic
match in learning context. All data is planner-generated or F1 metadata
(privacy-safe).
"""

from __future__ import annotations

import logging
from collections import Counter

from sentinel.memory.episodic import _redact_paths, _sanitise_for_planner

logger = logging.getLogger(__name__)


def _render_step_line(
    step: dict,
    outcome: dict,
) -> tuple[list[str], str | None]:
    """Format a single step with tool hints, prompt excerpts, and error details.

    Returns a tuple of (lines, fingerprint_or_none).  The caller collects
    fingerprints for the summary block.
    """
    logger.debug(
        "_render_step_line called",
        extra={
            "event": "builders._render_step_line",
            "step_len": len(step) if hasattr(step, "__len__") else 0,
            "outcome_len": len(outcome) if hasattr(outcome, "__len__") else 0,
        },
    )  # auto:entry
    step_id = step.get("id", "?")
    step_type = step.get("type", "?")
    tool = step.get("tool", "")
    prompt = step.get("prompt", "")
    output_var = step.get("output_var", "")
    args = step.get("args", {})

    status = outcome.get("status", "?").upper()
    output_size = outcome.get("output_size")

    # Tool label with optional args hint
    tool_label = tool or step_type
    args_hint = ""
    if tool in ("file_patch", "file_write", "file_read") and args.get("anchor"):
        args_hint = f" {args['anchor']}"
    elif tool == "file_patch" and args.get("operation"):
        args_hint = f" {args['operation']}"

    var_str = f" -> {output_var}" if output_var else ""
    size_str = f" ({output_size} bytes)" if output_size else ""

    # File size delta for file operations
    fs_before = outcome.get("file_size_before")
    fs_after = outcome.get("file_size_after")
    if fs_before is not None and fs_after is not None:
        size_str = f" ({fs_before}->{fs_after} bytes)"

    # Worker prompt excerpt for llm_task steps (truncated to ~80 chars)
    if step_type == "llm_task" and prompt:
        prompt_excerpt = prompt[:80].replace("\n", " ")
        if len(prompt) > 80:
            prompt_excerpt += "..."
        step_line = f'  {step_id} [{tool_label}] "{prompt_excerpt}"{var_str}: {status}{size_str}'
    else:
        step_line = (
            f"  {step_id} [{tool_label}{args_hint}]{var_str}: {status}{size_str}"
        )

    result_lines: list[str] = [step_line]

    # Error detail and fingerprint for failures
    error = outcome.get("error")
    if error:
        result_lines.append(f"    Error: {error[:120]}")

    fp = outcome.get("failure_fingerprint")
    if fp:
        result_lines.append(f"    Failure fingerprint: {fp}")

    return result_lines, fp


def _render_phase_block(
    phase: dict,
    phase_index: int,
) -> tuple[list[str], list[str]]:
    """Render a single phase: header, context, summary, and per-step lines.

    Returns (lines, fingerprints) so the caller can aggregate fingerprints
    across all phases.
    """
    logger.debug(
        "_render_phase_block called",
        extra={
            "event": "render.phase_block",
            "phase_index": phase_index,
            "phase_keys": len(phase),
        },
    )
    lines: list[str] = [""]
    fingerprints: list[str] = []

    phase_name = phase.get("phase", f"phase_{phase_index}")
    trigger = phase.get("trigger")
    trigger_step = phase.get("trigger_step")

    if trigger:
        logger.debug(
            "_render_phase_block: trigger",
            extra={"event": "builders._render_phase_block.match", "reason": "trigger"},
        )  # auto:neg
        lines.append(
            f"Phase {phase_index} ({phase_name} -- triggered by {trigger_step} {trigger}):"
        )
    else:
        logger.debug(
            "_render_phase_block: trigger",
            extra={"event": "builders._render_phase_block.clean", "reason": "trigger"},
        )  # auto:neg
        lines.append(f"Phase {phase_index} ({phase_name}):")

    # Replan context summary (for continuations)
    ctx = phase.get("replan_context_summary")
    if ctx:
        logger.debug(
            "_render_phase_block: ctx",
            extra={"event": "builders._render_phase_block.match", "reason": "ctx"},
        )  # auto:neg
        # Q7-F7: stored replan_context_summary aggregates raw stderr fragments
        # (via _execution_state.py:119). Apply SP+RP scrub before rendering into
        # planner prompt: marker-scrub first, then path-redact.
        lines.append(f"  Context: {_redact_paths(_sanitise_for_planner(ctx))[:300]}")

    # Plan summary
    plan_data = phase.get("plan", {})
    summary = plan_data.get("summary", "")
    if summary:
        logger.debug(
            "_render_phase_block: summary",
            extra={"event": "builders._render_phase_block.match", "reason": "summary"},
        )  # auto:neg
        lines.append(f"  Summary: {summary[:150]}")

    # Steps with outcomes
    outcomes = phase.get("step_outcomes_summary", {})
    for step in plan_data.get("steps", []):
        step_id = step.get("id", "?")
        outcome = outcomes.get(step_id, {})
        step_lines, fp = _render_step_line(step, outcome)
        lines.extend(step_lines)
        if fp:
            fingerprints.append(fp)

    logger.debug(
        "phase block rendered",
        extra={
            "event": "render.phase_block",
            "phase_index": phase_index,
            "phase_name": phase_name,
            "step_count": len(plan_data.get("steps", [])),
            "fingerprint_count": len(fingerprints),
        },
    )
    return lines, fingerprints


def _render_fingerprint_summary(all_fingerprints: list[str]) -> list[str]:
    """Aggregate repeated failure fingerprints into a summary block."""
    logger.debug(
        "_render_fingerprint_summary called",
        extra={
            "event": "builders._render_fingerprint_summary",
            "all_fingerprints_len": len(all_fingerprints)
            if hasattr(all_fingerprints, "__len__")
            else 0,
        },
    )  # auto:entry
    lines: list[str] = [""]
    fp_counts = Counter(all_fingerprints)
    repeated = {fp: count for fp, count in fp_counts.items() if count >= 2}
    if repeated:
        logger.debug(
            "_render_fingerprint_summary: repeated",
            extra={
                "event": "builders._render_fingerprint_summary.match",
                "reason": "repeated",
            },
        )  # auto:neg
        repeated_str = ", ".join(f"{fp} ({count}x)" for fp, count in repeated.items())
        lines.append(f"Repeated failure fingerprints: {repeated_str}")
    else:
        logger.debug(
            "_render_fingerprint_summary: repeated",
            extra={
                "event": "builders._render_fingerprint_summary.clean",
                "reason": "repeated",
            },
        )  # auto:neg
        lines.append("Repeated failure fingerprints: none")
    return lines


def render_plan_history(
    plan_json: dict | None,
    task_status: str = "",
    step_count: int = 0,
    success_count: int = 0,
    task_domain: str | None = None,
) -> str:
    """Render detailed plan evolution for the top episodic match (tier-2).

    Produces a structured block showing each plan phase with step-by-step
    outcomes, worker prompt excerpts, failure fingerprints, and file size
    deltas. Only called for the highest-scoring episodic match.

    All data is planner-generated or F1 metadata (privacy-safe).
    """
    logger.debug(
        "render_plan_history called",
        extra={
            "event": "render.plan_history",
            "plan_json_len": len(plan_json) if plan_json else 0,
            "task_status": task_status,
            "step_count": step_count,
        },
    )
    if not plan_json or not plan_json.get("phases"):
        return ""

    phases = plan_json["phases"]
    user_req = plan_json.get("user_request_full", "")

    lines: list[str] = ["[DETAILED PLAN HISTORY -- most relevant past task]"]

    # Header
    domain_str = f" | Domain: {task_domain}" if task_domain else ""
    # Q7-F2: stored user_request_full is replayed into planner prompt here
    # without scrub. Apply SP (marker scrub) BEFORE truncate, so we never split
    # a [REDACTED] token. Paths in a legitimate request are task-relevance
    # signal — RP is not stacked on the request body per design §4.3.
    lines.append(f'Request: "{_sanitise_for_planner(user_req)[:200]}"')
    lines.append(
        f"Overall: {task_status.upper()} ({success_count}/{step_count} steps){domain_str}"
    )

    # Render each phase and collect fingerprints
    all_fingerprints: list[str] = []
    for i, phase in enumerate(phases, 1):
        phase_lines, phase_fps = _render_phase_block(phase, i)
        lines.extend(phase_lines)
        all_fingerprints.extend(phase_fps)

    # Fingerprint summary
    lines.extend(_render_fingerprint_summary(all_fingerprints))
    lines.append("[END DETAILED PLAN HISTORY]")

    logger.debug(
        "render_plan_history complete",
        extra={
            "event": "render.plan_history_done",
            "phase_count": len(phases),
            "total_lines": len(lines),
            "fingerprint_count": len(all_fingerprints),
        },
    )
    return "\n".join(lines)
