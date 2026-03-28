"""Task success verification — deterministic checks and planner-as-judge.

Tier 1: Deterministic signals computed after every plan execution (zero cost).
Tier 2: Planner-as-judge invoked when Tier 1 is ambiguous (one API call).

Design doc: docs/design/tasksuccessful-confirmations-20260326.md
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass

logger = logging.getLogger("sentinel.audit")

# ── Helpers ───────────────────────────────────────────────────────

_DIFF_STATS_RE = re.compile(r"\+(\d+)/-(\d+)\s+lines")


def _parse_diff_stats(raw: str | dict) -> tuple[int, int]:
    """Parse diff_stats into (lines_added, lines_deleted).

    diff_stats comes from extract_diff_stats() which returns a compact string
    like "+5/-2 lines".  Handles both string and dict forms defensively.
    """
    if isinstance(raw, dict):
        return raw.get("lines_added", 0), raw.get("lines_deleted", 0)
    if isinstance(raw, str):
        m = _DIFF_STATS_RE.search(raw)
        if m:
            return int(m.group(1)), int(m.group(2))
    return 0, 0


# ── Constants ──────────────────────────────────────────────────────

# Tools that only observe state — never change it.
_DISCOVERY_ONLY_TOOLS = frozenset({
    "file_read", "list_dir", "find_file", "web_search", "brave_search",
})

# Tools that mutate state (files, external services).
_EFFECT_TOOLS = frozenset({
    "file_write", "file_patch", "website",
    "shell", "shell_exec",
    "signal_send", "email_send", "telegram_send",
})

# Tools that write to files (subset of effect tools).
_FILE_MUTATION_TOOLS = frozenset({
    "file_write", "file_patch", "website",
})


# ── Tool Output Scanner ───────────────────────────────────────────

@dataclass
class ToolOutputWarning:
    pattern: str
    severity: str  # "HIGH", "MEDIUM", "LOW"

# Patterns checked in order; first match wins per category.
_OUTPUT_FAILURE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"No such file or directory", re.IGNORECASE), "No such file or directory", "HIGH"),
    (re.compile(r"Permission denied", re.IGNORECASE), "Permission denied", "HIGH"),
    (re.compile(r"patch rejected|anchor not found", re.IGNORECASE), "patch rejected", "HIGH"),
    (re.compile(r"no changes made", re.IGNORECASE), "no changes made", "HIGH"),
    (re.compile(r"Traceback \(most recent call last\)"), "Traceback", "HIGH"),
    (re.compile(r"^error:", re.IGNORECASE | re.MULTILINE), "error:", "HIGH"),
    (re.compile(r"\bfailed\b", re.IGNORECASE), "failed", "HIGH"),
    (re.compile(r"already exists|unchanged", re.IGNORECASE), "already exists / unchanged", "MEDIUM"),
    (re.compile(r"^warning:|deprecated", re.IGNORECASE | re.MULTILINE), "warning / deprecated", "LOW"),
]


def scan_tool_output(output: str) -> list[ToolOutputWarning]:
    """Scan tool output text for known failure patterns.

    Returns a list of warnings sorted by severity (HIGH first).
    Empty output is itself a HIGH warning (silent failure).
    """
    if not output or not output.strip():
        logger.debug(
            "Tool output scanner: empty output detected (silent failure)",
            extra={"event": "tool_output_scan", "result": "empty_output"},
        )
        return [ToolOutputWarning(pattern="Empty output (silent failure)", severity="HIGH")]

    warnings: list[ToolOutputWarning] = []
    seen_patterns: set[str] = set()
    for regex, label, severity in _OUTPUT_FAILURE_PATTERNS:
        if regex.search(output) and label not in seen_patterns:
            warnings.append(ToolOutputWarning(pattern=label, severity=severity))
            seen_patterns.add(label)
    if warnings:
        logger.debug(
            "Tool output scanner: %d warning(s) found",
            len(warnings),
            extra={
                "event": "tool_output_scan",
                "warning_count": len(warnings),
                "patterns": [w.pattern for w in warnings],
                "severities": [w.severity for w in warnings],
                "output_length": len(output),
            },
        )
    else:
        logger.debug(
            "Tool output scanner: clean (no warnings)",
            extra={"event": "tool_output_scan", "result": "clean", "output_length": len(output)},
        )
    return warnings


# ── Goal Action Check ─────────────────────────────────────────────

def check_goal_actions_executed(step_outcomes: list[dict]) -> bool:
    """Check if any effect tool ran successfully during execution.

    An "effect" tool is one that changes state (writes files, sends messages).
    A blocked/failed effect tool does NOT count — the effect never happened.
    Discovery-only tools (file_read, web_search) don't count.
    llm_task steps without a tool name don't count.

    Returns True if at least one effect tool executed successfully.
    """
    effect_tools_seen: list[str] = []
    for outcome in step_outcomes:
        tool = outcome.get("tool", "")
        status = outcome.get("status", "")
        if tool in _EFFECT_TOOLS:
            effect_tools_seen.append(f"{tool}={status}")
            if status == "success":
                logger.debug(
                    "Goal action check: effect tool executed — %s (success)",
                    tool,
                    extra={
                        "event": "goal_action_check",
                        "result": True,
                        "tool": tool,
                        "total_steps": len(step_outcomes),
                        "effect_tools": effect_tools_seen,
                    },
                )
                return True
    logger.debug(
        "Goal action check: no successful effect tool found",
        extra={
            "event": "goal_action_check",
            "result": False,
            "total_steps": len(step_outcomes),
            "effect_tools": effect_tools_seen or ["none"],
        },
    )
    return False


# ── File Mutation Extraction ──────────────────────────────────────

def extract_file_mutations(step_outcomes: list[dict]) -> list[dict]:
    """Extract file mutation summaries from step outcomes.

    Only includes steps that actually wrote to files (file_write, file_patch,
    website). Flags no-op patches where size_before == size_after.
    """
    mutations: list[dict] = []
    for outcome in step_outcomes:
        tool = outcome.get("tool", "")
        if tool not in _FILE_MUTATION_TOOLS:
            continue
        file_path = outcome.get("file_path")
        size_before = outcome.get("file_size_before")
        size_after = outcome.get("file_size_after")
        # Skip if we have no size data at all (e.g. website tool without file tracking)
        if size_before is None and size_after is None:
            logger.debug(
                "File mutation: skipping %s (no size data)",
                tool,
                extra={"event": "file_mutation_skip", "tool": tool, "file_path": file_path},
            )
            continue

        # diff_stats is a compact string like "+5/-2 lines" from extract_diff_stats(),
        # NOT a dict — parse it to extract numeric values.
        diff_stats_raw = outcome.get("diff_stats") or ""
        lines_added, lines_deleted = _parse_diff_stats(diff_stats_raw)

        # Detect no-op: file_patch "succeeded" but content is identical
        no_op = (
            size_before is not None
            and size_after is not None
            and size_before == size_after
            and lines_added == 0
            and lines_deleted == 0
        )

        logger.debug(
            "File mutation: %s %s — %s→%s bytes, +%d/-%d lines%s",
            tool, file_path, size_before, size_after,
            lines_added, lines_deleted, " [NO-OP]" if no_op else "",
            extra={
                "event": "file_mutation_extracted",
                "tool": tool,
                "file_path": file_path,
                "size_before": size_before,
                "size_after": size_after,
                "lines_added": lines_added,
                "lines_deleted": lines_deleted,
                "no_op": no_op,
                "diff_stats_raw": str(diff_stats_raw),
            },
        )
        mutations.append({
            "path": file_path,
            "size_before": size_before,
            "size_after": size_after,
            "lines_added": lines_added,
            "lines_deleted": lines_deleted,
            "no_op": no_op,
        })

    logger.debug(
        "File mutation extraction complete: %d mutation(s) from %d outcomes",
        len(mutations), len(step_outcomes),
        extra={"event": "file_mutations_complete", "mutation_count": len(mutations), "outcome_count": len(step_outcomes)},
    )
    return mutations


# ── Stagnation Detection ──────────────────────────────────────────

def check_stagnation(
    consecutive_no_mutation_replans: int,
    warn_threshold: int = 2,
    abort_threshold: int = 3,
) -> str | None:
    """Check if execution is stagnating (no file mutations across replans).

    Returns:
        None — no stagnation detected
        "warn" — hit warn threshold, log warning
        "abort" — hit abort threshold, force partial
    """
    if consecutive_no_mutation_replans >= abort_threshold:
        logger.debug(
            "Stagnation check: ABORT — %d consecutive no-mutation replans (threshold %d)",
            consecutive_no_mutation_replans, abort_threshold,
            extra={"event": "stagnation_check", "result": "abort", "replans": consecutive_no_mutation_replans},
        )
        return "abort"
    if consecutive_no_mutation_replans >= warn_threshold:
        logger.debug(
            "Stagnation check: WARN — %d consecutive no-mutation replans (threshold %d)",
            consecutive_no_mutation_replans, warn_threshold,
            extra={"event": "stagnation_check", "result": "warn", "replans": consecutive_no_mutation_replans},
        )
        return "warn"
    logger.debug(
        "Stagnation check: OK — %d consecutive no-mutation replans",
        consecutive_no_mutation_replans,
        extra={"event": "stagnation_check", "result": "ok", "replans": consecutive_no_mutation_replans},
    )
    return None


# ── Idempotency Detection ────────────────────────────────────────

def detect_idempotent_calls(step_outcomes: list[dict]) -> list[str]:
    """Detect duplicate (tool, args) calls that produced identical output.

    Returns list of step descriptions that appear idempotent.
    """
    seen: dict[str, list[str]] = {}  # fingerprint -> [step descriptions]
    for outcome in step_outcomes:
        tool = outcome.get("tool", "")
        if not tool:
            continue
        # Hash (tool, status, output_size) as a cheap fingerprint
        fp = f"{tool}:{outcome.get('status', '')}:{outcome.get('output_size', 0)}"
        desc = outcome.get("description", tool)
        if fp in seen:
            seen[fp].append(desc)
        else:
            seen[fp] = [desc]

    duplicates: list[str] = []
    for fp, descriptions in seen.items():
        if len(descriptions) >= 2:
            duplicates.append(f"{descriptions[0]} (x{len(descriptions)})")
    if duplicates:
        logger.debug(
            "Idempotent call detection: %d duplicate group(s) found",
            len(duplicates),
            extra={"event": "idempotent_detection", "duplicates": duplicates},
        )
    else:
        logger.debug(
            "Idempotent call detection: no duplicates",
            extra={"event": "idempotent_detection", "unique_fingerprints": len(seen)},
        )
    return duplicates


# ── Assertion Evaluators ──────────────────────────────────────────

@dataclass
class AssertionResult:
    assertion_type: str
    path: str | None
    passed: bool
    message: str
    recovery: str | None = None


def _check_path_in_workspace(path: str, workspace_root: str) -> str | None:
    """Return error message if path is outside workspace, else None."""
    try:
        resolved = os.path.realpath(path)
        ws_resolved = os.path.realpath(workspace_root)
        if not resolved.startswith(ws_resolved):
            return f"Path outside workspace: {path}"
    except (OSError, ValueError) as exc:
        return f"Invalid path: {exc}"
    return None


def _eval_file_exists(assertion: dict, workspace_root: str, **_kwargs) -> AssertionResult:
    path = assertion["path"]
    path_err = _check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult("file_exists", path, False, path_err, assertion.get("recovery"))
    exists = os.path.isfile(path)
    return AssertionResult(
        "file_exists", path, exists,
        "file exists" if exists else f"file not found: {path}",
        assertion.get("recovery"),
    )


def _eval_file_not_empty(assertion: dict, workspace_root: str, **_kwargs) -> AssertionResult:
    path = assertion["path"]
    path_err = _check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult("file_not_empty", path, False, path_err, assertion.get("recovery"))
    try:
        size = os.path.getsize(path)
        passed = size > 0
        msg = f"file size: {size} bytes" if passed else "file is empty"
    except OSError as exc:
        passed = False
        msg = f"cannot read file: {exc}"
    return AssertionResult("file_not_empty", path, passed, msg, assertion.get("recovery"))


def _eval_file_contains(assertion: dict, workspace_root: str, **_kwargs) -> AssertionResult:
    path = assertion["path"]
    pattern = assertion.get("pattern", "")
    path_err = _check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult("file_contains", path, False, path_err, assertion.get("recovery"))
    try:
        regex = re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        return AssertionResult("file_contains", path, False, f"Invalid regex: {exc}", assertion.get("recovery"))
    try:
        content = open(path, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        return AssertionResult("file_contains", path, False, f"Cannot read file: {exc}", assertion.get("recovery"))
    if regex.search(content):
        return AssertionResult("file_contains", path, True, f"pattern found in {path}", assertion.get("recovery"))
    return AssertionResult(
        "file_contains", path, False,
        f"pattern '{pattern}' not found in {path}",
        assertion.get("recovery"),
    )


def _eval_file_not_contains(assertion: dict, workspace_root: str, **_kwargs) -> AssertionResult:
    path = assertion["path"]
    pattern = assertion.get("pattern", "")
    path_err = _check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult("file_not_contains", path, False, path_err, assertion.get("recovery"))
    try:
        regex = re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        return AssertionResult("file_not_contains", path, False, f"Invalid regex: {exc}", assertion.get("recovery"))
    try:
        content = open(path, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        return AssertionResult("file_not_contains", path, False, f"Cannot read file: {exc}", assertion.get("recovery"))
    if regex.search(content):
        return AssertionResult(
            "file_not_contains", path, False,
            f"unwanted pattern '{pattern}' found in {path}",
            assertion.get("recovery"),
        )
    return AssertionResult("file_not_contains", path, True, f"pattern absent from {path}", assertion.get("recovery"))


def _eval_content_changed(
    assertion: dict, workspace_root: str,
    before_hashes: dict[str, str] | None = None, **_kwargs,
) -> AssertionResult:
    path = assertion["path"]
    path_err = _check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult("content_changed", path, False, path_err, assertion.get("recovery"))
    if not before_hashes or path not in before_hashes:
        return AssertionResult("content_changed", path, False, "no before-hash available", assertion.get("recovery"))
    try:
        current = open(path, "rb").read()
        current_hash = hashlib.sha256(current).hexdigest()
    except OSError as exc:
        return AssertionResult("content_changed", path, False, f"Cannot read file: {exc}", assertion.get("recovery"))
    changed = current_hash != before_hashes[path]
    msg = "content changed" if changed else "content unchanged (hash match)"
    return AssertionResult("content_changed", path, changed, msg, assertion.get("recovery"))


def _eval_response_contains(
    assertion: dict, step_outcomes: list[dict], **_kwargs,
) -> AssertionResult:
    step_id = assertion.get("step_id", "")
    pattern = assertion.get("pattern", "")
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return AssertionResult("response_contains", None, False, f"Invalid regex: {exc}", assertion.get("recovery"))
    for outcome in step_outcomes:
        if outcome.get("step_id") == step_id:
            preview = outcome.get("output_preview", "")
            if regex.search(preview):
                return AssertionResult("response_contains", None, True, f"pattern found in {step_id} output", assertion.get("recovery"))
            return AssertionResult(
                "response_contains", None, False,
                f"pattern '{pattern}' not found in {step_id} output",
                assertion.get("recovery"),
            )
    return AssertionResult("response_contains", None, False, f"step {step_id} not found in outcomes", assertion.get("recovery"))


_EVALUATORS: dict[str, callable] = {
    "file_exists": _eval_file_exists,
    "file_not_empty": _eval_file_not_empty,
    "file_contains": _eval_file_contains,
    "file_not_contains": _eval_file_not_contains,
    "content_changed": _eval_content_changed,
    "response_contains": _eval_response_contains,
}


def evaluate_assertions(
    assertions: list[dict],
    step_outcomes: list[dict],
    workspace_root: str,
    before_hashes: dict[str, str] | None = None,
) -> list[AssertionResult]:
    """Evaluate a list of assertions against the current state.

    Each assertion is a dict with at least an "assert" key naming the type.
    Returns one AssertionResult per assertion.

    Design principle (asymmetric trust):
    - A FAILING assertion is conclusive evidence of a problem
    - A PASSING assertion is one positive signal, not conclusive proof of success
    """
    logger.debug(
        "Assertion evaluation: %d assertion(s) to evaluate",
        len(assertions),
        extra={"event": "assertion_eval_start", "count": len(assertions), "workspace_root": workspace_root},
    )
    results: list[AssertionResult] = []
    for assertion in assertions:
        atype = assertion.get("assert", "unknown")
        evaluator = _EVALUATORS.get(atype)
        if evaluator is None:
            results.append(AssertionResult(atype, assertion.get("path"), False, f"Unknown assertion type: {atype}", assertion.get("recovery")))
            continue
        try:
            result = evaluator(
                assertion,
                workspace_root=workspace_root,
                step_outcomes=step_outcomes,
                before_hashes=before_hashes,
            )
            logger.debug(
                "Assertion %s on %s: %s — %s",
                atype, assertion.get("path", "N/A"),
                "PASS" if result.passed else "FAIL", result.message,
                extra={"event": "assertion_eval_result", "type": atype, "passed": result.passed, "path": assertion.get("path")},
            )
            results.append(result)
        except Exception as exc:
            logger.warning("Assertion evaluator crashed: %s", exc, extra={"event": "assertion_eval_error", "type": atype})
            results.append(AssertionResult(atype, assertion.get("path"), False, f"Evaluator error: {exc}", assertion.get("recovery")))
    passed = sum(1 for r in results if r.passed)
    logger.debug(
        "Assertion evaluation complete: %d/%d passed",
        passed, len(results),
        extra={"event": "assertion_eval_complete", "passed": passed, "total": len(results)},
    )
    return results


# ── Task Category Classification ──────────────────────────────────

# Patterns suggesting deterministic verifiability (specific values/targets)
_DETERMINISTIC_PATTERNS = [
    re.compile(r"(change|set|update|modify).*(to|=)\s*\S+", re.IGNORECASE),
    re.compile(r"(send|email|message)\s+.*(to)\s+\S+", re.IGNORECASE),
    re.compile(r"(port|colour|color|font|size|width|height)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"#[0-9a-fA-F]{3,8}\b"),  # hex colour
    re.compile(r"\b\d+px\b|\b\d+rem\b|\b\d+em\b"),  # CSS units
]

# Patterns suggesting structural expectations (concrete elements, not specific values)
_STRUCTURAL_PATTERNS = [
    re.compile(r"\b(add|create|build|insert)\s+(a\s+)?(\w+\s+)*(form|table|list|menu|nav|header|footer|sidebar|button|input|modal|card)\b", re.IGNORECASE),
    re.compile(r"\b(add|create)\s+(a\s+)?(\w+\s+)*(page|section|component)\b", re.IGNORECASE),
]

# Patterns suggesting irreducibly semantic tasks
_SEMANTIC_PATTERNS = [
    re.compile(r"\b(better|improve|enhance|professional|clean|modern|nice|good)\b", re.IGNORECASE),
    re.compile(r"\b(fix the tone|refactor for clarity|make it look)\b", re.IGNORECASE),
]


def classify_task_category(
    user_request: str,
    assertions_count: int = 0,
) -> str:
    """Classify a task as deterministic, structural, or semantic.

    Uses two signals:
    1. Request text patterns
    2. Assertion coverage (strong assertions push toward deterministic)

    Returns: "deterministic", "structural", or "semantic"
    """
    # Strong assertion coverage overrides text analysis
    if assertions_count >= 2:
        logger.debug(
            "Task classification: deterministic (>= 2 assertions)",
            extra={"event": "task_classify", "category": "deterministic", "reason": "assertion_count", "assertions": assertions_count},
        )
        return "deterministic"

    # Check patterns in priority order
    for pattern in _DETERMINISTIC_PATTERNS:
        if pattern.search(user_request):
            logger.debug(
                "Task classification: deterministic (pattern match: %s)",
                pattern.pattern[:60],
                extra={"event": "task_classify", "category": "deterministic", "reason": "pattern", "pattern": pattern.pattern[:60]},
            )
            return "deterministic"

    for pattern in _SEMANTIC_PATTERNS:
        if pattern.search(user_request):
            logger.debug(
                "Task classification: semantic (pattern match: %s)",
                pattern.pattern[:60],
                extra={"event": "task_classify", "category": "semantic", "reason": "pattern", "pattern": pattern.pattern[:60]},
            )
            return "semantic"

    for pattern in _STRUCTURAL_PATTERNS:
        if pattern.search(user_request):
            logger.debug(
                "Task classification: structural (pattern match: %s)",
                pattern.pattern[:60],
                extra={"event": "task_classify", "category": "structural", "reason": "pattern", "pattern": pattern.pattern[:60]},
            )
            return "structural"

    # Default: if we have at least one assertion, treat as deterministic
    if assertions_count >= 1:
        logger.debug(
            "Task classification: deterministic (1 assertion, no pattern match)",
            extra={"event": "task_classify", "category": "deterministic", "reason": "single_assertion"},
        )
        return "deterministic"

    # No patterns matched, no assertions — assume semantic (safer to verify)
    logger.debug(
        "Task classification: semantic (default — no patterns, no assertions)",
        extra={"event": "task_classify", "category": "semantic", "reason": "default"},
    )
    return "semantic"


# ── Planner-as-Judge ──────────────────────────────────────────────

_JUDGE_PROMPT_TEMPLATE = """\
You are evaluating whether a task was completed successfully.
You are a VERIFICATION judge — your job is to find failures, not confirm success.
Apply scepticism: assume the task failed unless evidence proves otherwise.

USER REQUEST: "{original_request}"
PLAN SUMMARY: "{plan_summary}"

EXECUTION TRACE:
{execution_trace}

FILE CHANGES:
{file_changes}

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


def build_judge_payload(
    original_request: str,
    plan_summary: str,
    step_outcomes: list[dict],
    file_mutations: list[dict],
    completion: str,
    goal_actions_executed: bool,
    assertion_results: list[AssertionResult | dict],
    tool_output_warnings: list[ToolOutputWarning | dict],
) -> str:
    """Build the judge prompt from trusted metadata only.

    Privacy boundary: NO raw Qwen output, NO raw file content.
    Only tool names, statuses, sizes, and metadata from the orchestrator.
    """
    # Execution trace — tool + status + output_size per step
    trace_lines = []
    for outcome in step_outcomes:
        step_id = outcome.get("step_id", outcome.get("description", "?"))
        tool = outcome.get("tool", outcome.get("step_type", "?"))
        status = outcome.get("status", "?")
        out_size = outcome.get("output_size", 0)
        trace_lines.append(f"  {step_id} | {tool} | {status} | {out_size} bytes")
    execution_trace = "\n".join(trace_lines) if trace_lines else "  (no steps executed)"

    # File changes
    change_lines = []
    for m in file_mutations:
        sb = m.get("size_before", "new")
        sa = m.get("size_after", "?")
        la = m.get("lines_added", 0)
        ld = m.get("lines_deleted", 0)
        nop = " [NO-OP]" if m.get("no_op") else ""
        change_lines.append(f"  {m.get('path', '?')} | {sb}→{sa} bytes | +{la}/-{ld} lines{nop}")
    file_changes = "\n".join(change_lines) if change_lines else "  (no file changes)"

    # Assertion summary
    if assertion_results:
        parts = []
        for r in assertion_results:
            if isinstance(r, AssertionResult):
                status = "PASS" if r.passed else "FAIL"
                parts.append(f"{r.assertion_type}: {status}")
            elif isinstance(r, dict):
                status = "PASS" if r.get("passed") else "FAIL"
                parts.append(f"{r.get('type', '?')}: {status}")
        assertion_summary = ", ".join(parts)
    else:
        assertion_summary = "none defined"

    # Warning summary
    if tool_output_warnings:
        parts = []
        for w in tool_output_warnings:
            if isinstance(w, ToolOutputWarning):
                parts.append(f"[{w.severity}] {w.pattern}")
            elif isinstance(w, dict):
                parts.append(f"[{w.get('severity', '?')}] {w.get('pattern', '?')}")
        warning_summary = ", ".join(parts)
    else:
        warning_summary = "none"

    payload = _JUDGE_PROMPT_TEMPLATE.format(
        original_request=original_request[:500],
        plan_summary=plan_summary[:300],
        execution_trace=execution_trace,
        file_changes=file_changes,
        completion=completion,
        goal_actions_executed=goal_actions_executed,
        assertion_summary=assertion_summary,
        warning_summary=warning_summary,
    )
    logger.debug(
        "Judge payload built: %d chars, %d steps, %d file changes, %d assertions, %d warnings",
        len(payload), len(step_outcomes), len(file_mutations),
        len(assertion_results), len(tool_output_warnings),
        extra={
            "event": "judge_payload_built",
            "payload_chars": len(payload),
            "step_count": len(step_outcomes),
            "mutation_count": len(file_mutations),
            "assertion_count": len(assertion_results),
            "warning_count": len(tool_output_warnings),
            "completion": completion,
        },
    )
    return payload


def process_judge_verdict(
    verdict: dict,
    current_completion: str,
) -> dict:
    """Process the judge's verdict according to confidence gating rules.

    Confidence gating:
    - high: verdict overrides Tier 1 (completion changes)
    - medium: advisory only (stored in episodic, no status change)
    - low: discarded entirely (no effect)

    Returns dict with: completion, acted_on, gap
    """
    confidence = verdict.get("CONFIDENCE", "low")
    goal_met = verdict.get("GOAL_MET", "yes")
    gap = verdict.get("GAP")

    if confidence == "high":
        if goal_met == "yes":
            result = {"completion": "full", "acted_on": True, "gap": gap}
        elif goal_met == "partial":
            result = {"completion": "partial", "acted_on": True, "gap": gap}
        else:  # "no"
            result = {"completion": "failed", "acted_on": True, "gap": gap}
    else:
        # medium or low — advisory only, don't change completion
        result = {"completion": current_completion, "acted_on": False, "gap": gap}

    logger.debug(
        "Judge verdict processed: goal_met=%s, confidence=%s, acted_on=%s, completion=%s→%s",
        goal_met, confidence, result["acted_on"], current_completion, result["completion"],
        extra={
            "event": "judge_verdict_processed",
            "goal_met": goal_met,
            "confidence": confidence,
            "acted_on": result["acted_on"],
            "completion_before": current_completion,
            "completion_after": result["completion"],
            "gap": gap,
        },
    )
    return result
