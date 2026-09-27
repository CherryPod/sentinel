"""Judge payload construction — builds the planner-as-judge prompt.

Eight section builders plus the main build_judge_payload assembler.
Imports tier1 consensus check and tool scanning types.

Extracted from verification.py during planner modularisation (Phase 3).
"""

from __future__ import annotations

import logging

from sentinel.crypto.blind_index import log_hash
from sentinel.memory.episodic import _redact_paths, _sanitise_for_planner
from sentinel.planner._evaluators import AssertionResult
from sentinel.planner._tier1_consensus import (
    TIER1_CONSENSUS_INSTRUCTION,
    check_tier1_consensus,
)
from sentinel.planner._tool_scanning import ToolOutputWarning

logger = logging.getLogger(__name__)

_JUDGE_PROMPT_TEMPLATE = """\
You are evaluating whether a task was completed successfully.
You are a VERIFICATION judge — your job is to find failures, not confirm success.
Apply scepticism: assume the task failed unless evidence proves otherwise.
{tier1_consensus_instruction}
USER REQUEST: "{original_request}"
PLAN SUMMARY: "{plan_summary}"

EXECUTION TRACE:
{execution_trace}

FILE CHANGES:
{file_changes}
{code_fixer_section}\
{structural_section}\
{manifest_section}\
DETERMINISTIC SIGNALS:
- Completion: {completion}
- Goal actions executed: {goal_actions_executed}
- Assertion results: {assertion_summary}
- Tool output warnings: {warning_summary}

Evaluate each sub-question independently:
1. CORRECT_TARGET: Were the right file(s) / resource(s) modified? (true / false)
2. CORRECT_CONTENT: Does the modification match what was requested? (true / false)
3. SIDE_EFFECTS: Were there unintended changes? (true / false)
4. COMPLETENESS: Is anything from the original request unaddressed? (true / false)

Then synthesise:
5. GOAL_MET: Based on the above (yes / partial / no)
6. CONFIDENCE: How certain are you? (high / medium / low)
7. GAP: If not yes, what specifically is missing or wrong? (one line)

Respond in JSON only. No explanation outside the JSON."""


# ── Section Builders ─────────────────────────────────────────────


def _format_manifest(file_path: str, manifest: dict) -> list[str]:
    """Format a content manifest dict into judge-readable lines."""
    lines = [
        f"  {_redact_paths(_sanitise_for_planner(file_path))} "
        f"({manifest.get('language', '?')}):"
    ]
    lang = manifest.get("language", "")
    logger.debug(
        "Formatting manifest",
        extra={
            "event": "verification.formatmanifest",
            "language": lang,
            "file_path_hash": log_hash(file_path),
            "file_path_len": len(file_path) if file_path else 0,
        },
    )

    if lang == "html":
        if manifest.get("body_styles"):
            styles = ", ".join(
                f"{k}: {_redact_paths(_sanitise_for_planner(v))}"
                for k, v in manifest["body_styles"].items()
            )
            lines.append(f"    body: {styles}")
        for el in manifest.get("elements", []):
            parts = [
                f"id={_sanitise_for_planner(el['id'])}",
                f"tag={el.get('tag', '?')}",
            ]
            if el.get("text_content"):
                parts.append(f"text={_sanitise_for_planner(el['text_content'])[:80]!r}")
            all_styles = {
                **el.get("computed_styles", {}),
                **el.get("inline_styles", {}),
            }
            if all_styles:
                style_str = ", ".join(
                    f"{k}: {_redact_paths(_sanitise_for_planner(v))}"
                    for k, v in all_styles.items()
                )
                parts.append(f"styles=[{style_str}]")
            if el.get("layout"):
                layout_str = ", ".join(
                    f"{k}: {_sanitise_for_planner(v)}" for k, v in el["layout"].items()
                )
                parts.append(f"layout=[{layout_str}]")
            lines.append(f"    element: {', '.join(parts)}")
        if manifest.get("panel_count", 0) > 0:
            lines.append(f"    panels: {manifest['panel_count']}")
        for ref in manifest.get("script_refs", []):
            lines.append(f"    script: {_redact_paths(_sanitise_for_planner(ref))}")

    elif lang == "javascript":
        for b in manifest.get("behaviours", []):
            if b["type"] == "timer":
                lines.append(
                    f"    timer: {b.get('function', '?')} every {b['interval_ms']}ms"
                )
            elif b["type"] == "fetch":
                lines.append(
                    f"    fetch: {_redact_paths(_sanitise_for_planner(b.get('url', '?')))}"
                )
            elif b["type"] == "date_usage":
                lines.append("    behaviour: uses Date()")
        for dom_id in manifest.get("dom_updates", []):
            lines.append(f"    updates: #{_sanitise_for_planner(dom_id)}")

    elif lang == "css":
        for el_id, props in manifest.get("element_styles", {}).items():
            style_str = ", ".join(
                f"{k}: {_redact_paths(_sanitise_for_planner(v))}"
                for k, v in props.items()
            )
            lines.append(f"    #{_sanitise_for_planner(el_id)}: {style_str}")
        if manifest.get("colour_palette"):
            lines.append(f"    colours: {', '.join(manifest['colour_palette'])}")
        for rule in manifest.get("layout_rules", []):
            sel = _sanitise_for_planner(rule.get("selector", "?"))
            props = ", ".join(
                f"{k}: {_sanitise_for_planner(v)}"
                for k, v in rule.items()
                if k != "selector"
            )
            lines.append(f"    layout {sel}: {props}")

    elif lang == "python":
        for ep in manifest.get("entry_points", []):
            args = ", ".join(ep.get("args", []))
            prefix = "async " if ep.get("is_async") else ""
            lines.append(f"    {prefix}def {ep['name']}({args})")
        for cls in manifest.get("class_signatures", []):
            methods = ", ".join(cls.get("methods", []))
            lines.append(f"    class {cls['name']}: [{methods}]")
        if manifest.get("cli_args"):
            lines.append("    cli_args: yes")

    logger.debug(
        "content_manifest: formatted %d lines for judge payload",
        len(lines),
        extra={
            "event": "content.manifest_format",
            "line_count": len(lines),
            "file_path_hash": log_hash(file_path),
            "file_path_len": len(file_path) if file_path else 0,
        },
    )

    return lines


def _build_execution_trace(step_outcomes: list[dict]) -> str:
    """Build the execution trace section — tool + status + output_size per step.

    Each line: step_id | tool | status | output_size bytes.
    """
    logger.debug(
        "Building execution trace",
        extra={"event": "build.execution_trace", "step_count": len(step_outcomes)},
    )
    trace_lines = []
    for outcome in step_outcomes:
        step_id = outcome.get("step_id", outcome.get("description", "?"))
        tool = outcome.get("tool", outcome.get("step_type", "?"))
        status = outcome.get("status", "?")
        out_size = outcome.get("output_size", 0)
        trace_lines.append(f"  {step_id} | {tool} | {status} | {out_size} bytes")
    return "\n".join(trace_lines) if trace_lines else "  (no steps executed)"


def _build_file_changes(file_mutations: list[dict]) -> str:
    """Build the file changes section — path, size delta, line counts per mutation."""
    logger.debug(
        "Building file changes",
        extra={"event": "build.file_changes", "mutation_count": len(file_mutations)},
    )
    change_lines = []
    for m in file_mutations:
        sb = m.get("size_before", "new")
        sa = m.get("size_after", "?")
        la = m.get("lines_added", 0)
        ld = m.get("lines_deleted", 0)
        nop = " [NO-OP]" if m.get("no_op") else ""
        change_lines.append(
            f"  {_redact_paths(_sanitise_for_planner(m.get('path', '?')))} | "
            f"{sb}→{sa} bytes | +{la}/-{ld} lines{nop}"
        )
    return "\n".join(change_lines) if change_lines else "  (no file changes)"


def _build_assertion_summary(
    assertion_results: list[AssertionResult | dict],
) -> str:
    """Build assertion summary — type: PASS/FAIL per assertion result."""
    logger.debug(
        "Building assertion summary",
        extra={
            "event": "build.assertion_summary",
            "assertion_count": len(assertion_results),
        },
    )
    if not assertion_results:
        return "none defined"
    parts = []
    for r in assertion_results:
        if isinstance(r, AssertionResult):
            status = "PASS" if r.passed else "FAIL"
            parts.append(f"{r.assertion_type}: {status}")
        elif isinstance(r, dict):
            status = "PASS" if r.get("passed") else "FAIL"
            parts.append(f"{r.get('type', '?')}: {status}")
    return ", ".join(parts)


def _build_warning_summary(
    tool_output_warnings: list[ToolOutputWarning | dict],
) -> str:
    """Build warning summary — [severity] pattern per warning."""
    logger.debug(
        "Building warning summary",
        extra={
            "event": "build.warning_summary",
            "warning_count": len(tool_output_warnings),
        },
    )
    if not tool_output_warnings:
        return "none"
    parts = []
    for w in tool_output_warnings:
        if isinstance(w, ToolOutputWarning):
            parts.append(f"[{w.severity}] {w.pattern}")
        elif isinstance(w, dict):
            parts.append(f"[{w.get('severity', '?')}] {w.get('pattern', '?')}")
    return ", ".join(parts)


def _build_code_fixer_section(step_outcomes: list[dict]) -> str:
    """Build the code fixer errors section.

    Reports structural problems the fixer detected but couldn't repair.
    The fixer's successes are noise; the fixer's failures are signals.
    Returns empty string if no errors found.
    """
    logger.debug(
        "Building code fixer section",
        extra={"event": "build.code_fixer_section", "step_count": len(step_outcomes)},
    )
    cfe_lines = []
    for outcome in step_outcomes:
        errors = outcome.get("code_fixer_errors", [])
        if errors:
            step_id = outcome.get("step_id", outcome.get("description", "?"))
            for err in errors:
                cfe_lines.append(
                    f"  {step_id}: {_redact_paths(_sanitise_for_planner(err))}"
                )
    if not cfe_lines:
        logger.debug(
            "No code fixer errors",
            extra={"event": "build.code_fixer_section_empty"},
        )
        return ""
    logger.info(
        "Judge payload: %d unfixable code fixer errors",
        len(cfe_lines),
        extra={"event": "judge.code_fixer_errors", "error_count": len(cfe_lines)},
    )
    return (
        "\nCODE FIXER ERRORS (unfixable structural defects):\n"
        + "\n".join(cfe_lines)
        + "\n"
    )


def _build_structural_section(
    step_outcomes: list[dict],
    cross_ref_warnings: list[dict] | None,
) -> str:
    """Build the structural analysis section — digests, cross-refs, survival warnings.

    Combines structural digest data from step outcomes with cross-reference
    warnings into a single section. Returns empty string if neither is present.
    """
    logger.debug(
        "Building structural section",
        extra={
            "event": "build.structural_section",
            "step_count": len(step_outcomes),
            "cross_ref_count": len(cross_ref_warnings) if cross_ref_warnings else 0,
        },
    )
    structural_lines = []
    for outcome in step_outcomes:
        digest = outcome.get("structural_digest")
        removed = outcome.get("structural_elements_removed")
        file_path = outcome.get("file_path", "?")
        if digest or removed:
            structural_lines.append(
                f"  {_redact_paths(_sanitise_for_planner(file_path))}:"
            )
            if digest:
                for key, val in digest.items():
                    if val and val != [] and val is not None:
                        if (
                            isinstance(val, list)
                            or isinstance(val, bool)
                            or (isinstance(val, int) and val > 0)
                        ):
                            structural_lines.append(
                                f"    {key}: "
                                f"{_redact_paths(_sanitise_for_planner(str(val)))}"
                            )
            if removed:
                structural_lines.append(
                    "    ELEMENTS REMOVED BY PATCH: "
                    f"{_sanitise_for_planner(str(removed))}"
                )

    cross_ref_lines = []
    if cross_ref_warnings:
        for w in cross_ref_warnings:
            cross_ref_lines.append(
                f"  [{w.get('severity', '?')}] "
                f"{_redact_paths(_sanitise_for_planner(w.get('detail', '?')))}"
            )

    section = ""
    if structural_lines:
        section += "\nSTRUCTURAL ANALYSIS:\n" + "\n".join(structural_lines) + "\n"
    if cross_ref_lines:
        section += "\nCROSS-REFERENCE WARNINGS:\n" + "\n".join(cross_ref_lines) + "\n"

    logger.debug(
        "Structural section built",
        extra={
            "event": "build.structural_section_done",
            "structural_line_count": len(structural_lines),
            "cross_ref_line_count": len(cross_ref_lines),
            "has_content": bool(section),
        },
    )
    return section


def _build_manifest_section(step_outcomes: list[dict]) -> str:
    """Build the content manifest section — deterministic observable properties per file.

    Collects single-file manifests (file_write, file_patch) and multi-file
    manifests (website tool) from step outcomes. Returns empty string if none.
    """
    logger.debug(
        "Building manifest section",
        extra={"event": "build.manifest_section", "step_count": len(step_outcomes)},
    )
    manifest_lines: list[str] = []
    for outcome in step_outcomes:
        # Single-file manifest (file_write, file_patch)
        manifest = outcome.get("content_manifest")
        file_path = outcome.get("file_path", "?")
        if manifest:
            manifest_lines.extend(_format_manifest(file_path, manifest))
        # Multi-file manifests (website tool)
        manifests = outcome.get("content_manifests", {})
        for fname, m in manifests.items():
            manifest_lines.extend(_format_manifest(fname, m))

    if not manifest_lines:
        logger.debug(
            "No manifest content",
            extra={"event": "build.manifest_section_empty"},
        )
        return ""
    logger.debug(
        "Judge payload: content manifest section — %d lines",
        len(manifest_lines),
        extra={
            "event": "judge.manifest_section",
            "line_count": len(manifest_lines),
        },
    )
    return (
        "\nCONTENT MANIFEST (deterministic observable properties):\n"
        + "\n".join(manifest_lines)
        + "\n"
    )


# ── Main Assembler ───────────────────────────────────────────────


def build_judge_payload(
    original_request: str,
    plan_summary: str,
    step_outcomes: list[dict],
    file_mutations: list[dict],
    completion: str,
    goal_actions_executed: bool,
    assertion_results: list[AssertionResult | dict],
    tool_output_warnings: list[ToolOutputWarning | dict],
    cross_ref_warnings: list[dict] | None = None,
) -> str:
    """Build the judge prompt from trusted metadata only.

    Privacy boundary: NO raw Qwen output, NO raw file content.
    Only tool names, statuses, sizes, and metadata from the orchestrator.

    Delegates section building to focused helpers, then assembles the
    final prompt via the template.
    """
    logger.debug(
        "Building judge payload",
        extra={
            "event": "build.judge_payload_start",
            "step_count": len(step_outcomes),
            "mutation_count": len(file_mutations),
            "assertion_count": len(assertion_results),
            "warning_count": len(tool_output_warnings),
        },
    )

    # Build each section via dedicated helpers
    execution_trace = _build_execution_trace(step_outcomes)
    file_changes = _build_file_changes(file_mutations)
    assertion_summary = _build_assertion_summary(assertion_results)
    warning_summary = _build_warning_summary(tool_output_warnings)
    code_fixer_section = _build_code_fixer_section(step_outcomes)
    structural_section = _build_structural_section(step_outcomes, cross_ref_warnings)
    manifest_section = _build_manifest_section(step_outcomes)

    # Tier 1 consensus gate — when all deterministic signals agree on success,
    # inject an instruction raising the evidence bar for judge override.
    tier1_consensus = check_tier1_consensus(
        completion,
        goal_actions_executed,
        file_mutations,
        assertion_results,
        tool_output_warnings,
    )
    tier1_consensus_instruction = TIER1_CONSENSUS_INSTRUCTION if tier1_consensus else ""

    logger.debug(
        "Tier 1 consensus gate: %s",
        "ACTIVE — all signals green" if tier1_consensus else "inactive",
        extra={
            "event": "tier1.consensus_check",
            "consensus": tier1_consensus,
            "completion": completion,
            "goal_actions": goal_actions_executed,
            "mutation_count": len(file_mutations),
            "assertion_count": len(assertion_results),
            "warning_count": len(tool_output_warnings),
        },
    )

    payload = _JUDGE_PROMPT_TEMPLATE.format(
        original_request=original_request[:500],
        plan_summary=plan_summary[:300],
        execution_trace=execution_trace,
        file_changes=file_changes,
        code_fixer_section=code_fixer_section,
        structural_section=structural_section,
        manifest_section=manifest_section,
        tier1_consensus_instruction=tier1_consensus_instruction,
        completion=completion,
        goal_actions_executed=goal_actions_executed,
        assertion_summary=assertion_summary,
        warning_summary=warning_summary,
    )
    logger.debug(
        "Judge payload built: %d chars, %d steps, %d file changes, %d assertions, %d warnings",
        len(payload),
        len(step_outcomes),
        len(file_mutations),
        len(assertion_results),
        len(tool_output_warnings),
        extra={
            "event": "judge.payload_built",
            "payload_chars": len(payload),
            "step_count": len(step_outcomes),
            "mutation_count": len(file_mutations),
            "assertion_count": len(assertion_results),
            "warning_count": len(tool_output_warnings),
            "completion": completion,
        },
    )
    return payload
