"""F4: Episodic memory store — PostgreSQL backend with in-memory fallback.

Provides long-term memory for the planner across sessions: what tasks were
completed, which files were affected, what errors occurred, and what facts
were extracted. All data is TRUSTED by construction — orchestrator-generated
metadata from F1 step_outcomes, never raw Qwen output.

PostgreSQL implementation notes:
- tsvector with plainto_tsquery and ts_rank_cd for full-text search
- search_vector is GENERATED ALWAYS AS STORED — no manual sync
- EXTRACT(EPOCH FROM ...) / 86400.0 for age calculation
- INSERT ... ON CONFLICT DO NOTHING for dedup
- JSON fields are JSONB — asyncpg returns native Python types
- FK ON DELETE CASCADE handles file_index + facts cleanup

When pool is None, falls back to in-memory dict (useful for tests).
"""

from __future__ import annotations

import json
import logging
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sentinel.core.context import current_user_id, get_task_id, require_user_id
from sentinel.core.decorators import no_audit_log
from sentinel.security.homoglyph import _CONFUSABLE_TABLE

logger = logging.getLogger(__name__)

# Finding #6: Module-level constant for render budget (was hardcoded inside function)
RENDER_MAX_CHARS = 800

# Truncation limit for stderr/error lines in episodic text rendering
_STDERR_TRUNCATE_CHARS = 120

# Truncation limit for compact plan lines in episodic text rendering
_PLAN_LINE_MAX_CHARS = 220

# Finding #1: Regex patterns for sanitising user_request before planner injection.
# Defence-in-depth against stored injection: strip XML/HTML-like tags and common
# injection markers. The planner needs the gist, not the exact user phrasing.
#
# Q7.fix.a broadening (design §250-264, Codex rounds 1-4 on thread
# 019da7e3-3ab9-7a01-9c02-30a683232dfb): extend the marker set beyond the four
# patterns the Finding-#1 helper originally covered to include USER:,
# <|system|>/<|user|>/<|assistant|>, [INST]/[/INST], "### Instruction",
# "You are now", "New instructions:", and fence breakouts. Single compiled
# alternation keeps each sub() call O(n) over the input.
_TAG_PATTERN = re.compile(r"<[^>]{1,100}>")
_INJECTION_MARKERS = re.compile(
    r"(?:"
    r"IGNORE\s+(?:ALL\s+)?PREVIOUS"
    r"|SYSTEM\s*:"
    r"|ASSISTANT\s*:"
    r"|USER\s*:"
    r"|Human\s*:"
    r"|<\|(?:im_start|im_end|system|user|assistant)\|>"
    r"|\[/?INST\]"
    r"|###\s*Instruction"
    r"|You\s+are\s+now"
    r"|New\s+instructions\s*:"
    r"|```[a-z]*\s*\n?(?=(?:IGNORE|SYSTEM|ASSISTANT|\[INST))"
    r")",
    re.IGNORECASE,
)


def _build_normalised_shadow(text: str) -> tuple[str, list[int]]:
    """Build a Unicode-normalised shadow of ``text`` with an index map.

    The shadow strips combining marks (Mn) and invisible format chars (Cf),
    NFKD-decomposes precomposed forms, and folds Cyrillic confusables to
    Latin via ``_CONFUSABLE_TABLE``. ``origin_of[j]`` is the index in the
    *original* ``text`` that produced shadow char ``j``.

    Used by ``_sanitise_for_planner`` (Q7-FL2 / cleanup-pass C37) to detect
    injection markers in a confusable-resistant view while redacting spans
    in the original text — preserving identifier fidelity for non-marker
    values like ``ѕource.py`` (Cyrillic ѕ U+0455).
    """
    shadow_chars: list[str] = []
    origin_of: list[int] = []
    for i, ch in enumerate(text):
        for dch in unicodedata.normalize("NFKD", ch):
            if unicodedata.category(dch) in ("Mn", "Cf"):
                continue
            mapped = dch.translate(_CONFUSABLE_TABLE)
            for out_ch in mapped:
                shadow_chars.append(out_ch)
                origin_of.append(i)
    return "".join(shadow_chars), origin_of


def _sanitise_for_planner(text: str) -> str:
    """Strip injection-prone patterns from user_request before planner replay.

    Finding #1: user_request is user-supplied text that passed S1 scanning at
    intake, but is replayed verbatim to the planner via render_episodic_text().
    If S1 has a gap, a stored payload is replayed indefinitely. This sanitisation
    is defence-in-depth — it strips common injection markers without losing the
    semantic content the planner needs for task relevance.

    Two-pass detection (Q7-FL2 / cleanup-pass C37, Option F):

    1. ``_TAG_PATTERN`` runs on the ORIGINAL text. Tag-shaped sequences like
       ``<foo>`` are deleted. Tag-strip stays on the original — NOT on the
       shadow — because shadow's NFKD fold of fullwidth angle brackets
       (``＜`` U+FF1C → ``<``, ``＞`` U+FF1E → ``>``) would cause
       ``<[^>]{1,100}>`` to match shadow segments that aren't actual tags
       in the original. Running tag-strip on the original means non-ASCII-
       bracketed sequences like ``＜|system|＞`` pass through to shadow
       detection where they get caught by the chat-token arm of
       ``_INJECTION_MARKERS``.
    2. ``_INJECTION_MARKERS`` runs on a Unicode-NORMALISED SHADOW of the
       post-tag-strip text, with redaction applied to spans of the ORIGINAL
       post-tag-strip text. This catches confusable variants (zero-width
       joiners, lowercase Cyrillic homoglyphs, RTL/LTR controls,
       NFKD-decomposable forms, fullwidth, math-bold) without corrupting
       benign identifiers — ``ѕource.py`` (Cyrillic ѕ in filename) is left
       untouched if it doesn't contain a marker.

    Two-step lazy optimisation: build the shadow without origin tracking
    first; if no marker matches, return early. Only build the ``origin_of``
    index map (allocates ``~len(shadow)`` ints) when a match is found.
    Common path (benign content) avoids the origin-map allocation.

    Residual gap (post-C78): Greek, Armenian, and Latin small-caps
    confusables fall outside the current ``_CONFUSABLE_TABLE``. The
    uppercase Cyrillic siblings (Ѕ U+0405, І U+0406, Ј U+0408, Һ U+04BA,
    Ԁ U+0500) were closed by cleanup-pass row C78. Broader closure of
    Greek / Armenian / small-caps tracked under FL-C78-a1 (canonical
    confusable source-list selection) / Q7-U1 umbrella scope.
    """
    logger.debug(
        "_sanitise_for_planner called",
        extra={
            "event": "memory.episodic._sanitise_for_planner",
            "text_len": len(text) if hasattr(text, "__len__") else 0,
        },
    )  # auto:entry
    text = _TAG_PATTERN.sub("", text)

    shadow_quick = "".join(
        out_ch
        for ch in text
        for dch in unicodedata.normalize("NFKD", ch)
        if unicodedata.category(dch) not in ("Mn", "Cf")
        for out_ch in dch.translate(_CONFUSABLE_TABLE)
    )
    if not _INJECTION_MARKERS.search(shadow_quick):
        return text

    shadow, origin_of = _build_normalised_shadow(text)
    out: list[str] = []
    cursor = 0
    for m in _INJECTION_MARKERS.finditer(shadow):
        s, e = m.span()
        if s == e:
            continue
        orig_start = origin_of[s]
        orig_end = origin_of[e - 1] + 1
        if orig_start < cursor:
            continue
        out.append(text[cursor:orig_start])
        out.append("[REDACTED]")
        cursor = orig_end
    out.append(text[cursor:])
    return "".join(out)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class EpisodicRecord:
    """A structured outcome record for a completed task."""

    record_id: str
    session_id: str
    task_id: str
    user_id: int
    user_request: str
    task_status: str
    plan_summary: str
    step_count: int
    success_count: int
    file_paths: list[str]
    error_patterns: list[str]
    defined_symbols: list[str]
    step_outcomes: list[dict] | None
    linked_records: list[dict]
    relevance_score: float
    access_count: int
    last_accessed: str | None
    task_domain: str | None = None
    plan_json: dict | None = None  # Full plan evolution (phases + outcomes)
    memory_chunk_id: str | None = None
    created_at: str = ""


@dataclass
class EpisodicFact:
    """A short, keyword-rich extracted fact linked to an episodic record."""

    fact_id: str
    record_id: str
    fact_type: str
    content: str
    file_path: str | None
    created_at: str
    user_id: int = 0  # Finding #2: 0 = unset; callers should pass explicit user_id


# Tool name → domain mapping for task classification
TOOL_TO_DOMAIN: dict[str, str] = {
    # Code generation / file creation
    "file_write": "code_generation",
    "file_read": "file_ops",
    "mkdir": "file_ops",
    # Execution
    "shell": "code_generation",
    "shell_exec": "code_generation",
    # Messaging (static — email tools only; channel tools registered dynamically)
    "email_send": "messaging",
    "email_draft": "messaging",
    # Search
    "web_search": "search",
    "http_fetch": "search",
    "email_search": "search",
    "email_read": "search",
    "memory_search": "search",
    # Calendar
    "calendar_list_events": "calendar",
    "calendar_create_event": "calendar",
    "calendar_update_event": "calendar",
    "calendar_delete_event": "calendar",
    # File patching
    "file_patch": "file_ops",
    # X/Twitter search
    "x_search": "search",
    # System / internal
    "health_check": "system",
    "session_info": "system",
    "memory_store": "system",
    "memory_list": "system",
    "memory_recall_file": "system",
    "memory_recall_session": "system",
    "routine_list": "system",
    "routine_get": "system",
    "routine_history": "system",
    # Website
    "website": "code_generation",
}


def register_channel_domains(channel_registry) -> None:
    """Merge channel tool-to-domain mappings from the registry.

    Called once at startup after channel initialization. Adds entries
    like {"signal_send": "messaging", "telegram_send": "messaging"} from
    each channel's descriptor.
    """
    TOOL_TO_DOMAIN.update(channel_registry.tool_to_domain_map())


# Valid domain values
TASK_DOMAINS = frozenset(
    {
        "code_generation",
        "code_debugging",
        "messaging",
        "search",
        "file_ops",
        "system",
        "calendar",
        "composite",
    }
)


def classify_task_domain(step_outcomes: list[dict]) -> str | None:
    """Classify a task into a domain based on the tools used in step_outcomes.

    Uses dominant-tool heuristic: if one domain accounts for >50% of tool_call
    steps, that's the domain. Otherwise "composite". Returns None if no
    tool_call steps exist (pure llm_task plans).
    """
    logger.debug(
        "classify_task_domain called",
        extra={
            "event": "episodic.classify_task_domain",
            "step_outcomes_len": len(step_outcomes)
            if hasattr(step_outcomes, "__len__")
            else 0,
        },
    )  # auto:entry
    if not step_outcomes:
        return None

    domain_counts: dict[str, int] = {}
    tool_steps = 0

    for outcome in step_outcomes:
        if outcome.get("step_type") != "tool_call":
            continue
        tool = outcome.get("tool", "")
        if not tool:
            continue
        tool_steps += 1
        domain = TOOL_TO_DOMAIN.get(tool, "system")
        domain_counts[domain] = domain_counts.get(domain, 0) + 1

    if tool_steps == 0:
        return None

    # Dominant domain: >50% of tool steps (checked first — Finding #4)
    for domain, count in sorted(
        domain_counts.items(), key=lambda x: x[1], reverse=True
    ):
        if count > tool_steps / 2:
            return domain

    # Finding #4: Debug pattern heuristic moved AFTER dominant-domain check.
    # Previously this fired before the dominant check, misclassifying tasks
    # with a dominant domain (e.g. 5 web_search + 1 file_read + 1 file_write
    # + 1 llm_task would wrongly get "code_debugging" instead of "search").
    has_file_read = any(
        o.get("tool") == "file_read"
        for o in step_outcomes
        if o.get("step_type") == "tool_call"
    )
    has_file_write = any(
        o.get("tool") == "file_write"
        for o in step_outcomes
        if o.get("step_type") == "tool_call"
    )
    has_llm_task = any(o.get("step_type") == "llm_task" for o in step_outcomes)
    if has_file_read and has_file_write and has_llm_task:
        return "code_debugging"

    return "composite"


def compute_relevance(age_days: float, access_count: int = 0) -> float:
    """Compute effective relevance score.

    Base: 1.0 / (1 + age_days * 0.1) — decays with time.
    Boost: 0.1 * access_count — active records stay alive.
    """
    base = 1.0 / (1.0 + age_days * 0.1)
    boost = 0.1 * access_count
    return round(base + boost, 4)


def _format_bytes(size: int) -> str:
    """Format byte count as human-readable string."""
    if size < 1024:
        return f"{size}B"
    return f"{size / 1024:.1f}K"


@no_audit_log
def _categorise_strategy(step_outcomes: list[dict]) -> str:
    """Categorise step sequence into a strategy pattern."""
    if not step_outcomes:
        return "empty"

    steps = []
    for o in step_outcomes:
        st = o.get("step_type", "")
        tool = o.get("tool", "")
        if st == "tool_call" and tool:
            steps.append(tool)
        elif st == "llm_task":
            steps.append("llm")

    if not steps:
        return "unknown"
    if len(steps) == 1:
        return "single-shot"

    # Simplify repeated tools into readable labels
    simplified = []
    for s in steps:
        label = s
        if s == "file_read":
            label = "read"
        elif s == "file_write":
            label = "write"
        elif s in ("shell", "shell_exec"):
            label = "exec"
        elif s == "llm":
            label = "generate"
        elif s in ("web_search", "email_search", "memory_search"):
            label = "search"
        elif s in ("signal_send", "telegram_send", "matrix_send", "email_send"):
            label = "send"
        if not simplified or simplified[-1] != label:
            simplified.append(label)

    result = " → ".join(simplified)
    logger.debug(
        "Strategy categorised",
        extra={
            "event": "episodic.categorise_strategy.result",
            "strategy": result,
            "step_count": len(steps),
        },
    )
    return result


@no_audit_log
def _render_compact_plan_line(plan_json: dict) -> str:
    """Render a one-line plan chain with outcome annotations for compact display.

    Produces: file_read($page):OK -> llm_task($widget):OK -> file_patch(BLOCKED:innerHTML)
    Walks all phases in order so the chain includes continuation steps.
    Budget: ~200 chars — truncates with '...' if needed.
    """
    parts: list[str] = []
    for phase in plan_json.get("phases", []):
        # Mark phase transitions with [replan] marker
        if phase.get("trigger"):
            parts.append("[replan]")

        plan_data = phase.get("plan", {})
        outcomes = phase.get("step_outcomes_summary", {})

        for step in plan_data.get("steps", []):
            step_id = step.get("id", "?")
            tool = step.get("tool") or step.get("type", "?")
            var = step.get("output_var", "")

            # Outcome annotation
            outcome = outcomes.get(step_id, {})
            status = outcome.get("status", "?")
            if status == "success":
                annotation = "OK"
            elif status == "blocked":
                error = outcome.get("error", "")
                short_err = error.split()[0] if error else "blocked"
                annotation = f"BLOCKED:{short_err}"
            elif status in ("failed", "soft_failed", "error"):
                annotation = status.upper()
            else:
                annotation = status.upper()

            if var:
                parts.append(f"{tool}({var}):{annotation}")
            else:
                parts.append(f"{tool}({annotation})")

    result = " -> ".join(parts)

    # Append completion marker for non-full completions
    completion = plan_json.get("completion", "full")
    if completion == "partial":
        result += " [PARTIAL]"
    elif completion == "abandoned":
        result += " [ABANDONED]"

    if (
        len(result) > _PLAN_LINE_MAX_CHARS
    ):  # Slightly larger budget to accommodate markers
        truncated = result[: _PLAN_LINE_MAX_CHARS - 20]
        last_arrow = truncated.rfind(" -> ")
        if last_arrow > 0:
            result = truncated[:last_arrow] + " -> ..."
        else:
            result = truncated[: _PLAN_LINE_MAX_CHARS - 23] + "..."
        # Re-append marker after truncation
        if completion == "partial":
            result += " [PARTIAL]"
        elif completion == "abandoned":
            result += " [ABANDONED]"
    return result


def render_episodic_text(
    user_request: str,
    task_status: str,
    step_count: int = 0,
    success_count: int = 0,
    file_paths: list[str] | None = None,
    plan_summary: str = "",
    error_patterns: list[str] | None = None,
    step_outcomes: list[dict] | None = None,
    task_domain: str | None = None,
    original_request: str | None = None,
    prior_error_summary: str | None = None,
    plan_json: dict | None = None,
) -> str:
    """Render outcome-aware text for embedding + planner context.

    Includes diagnostic detail so the planner can learn from past
    successes and failures: stderr output, exit codes, file sizes,
    diff stats, step-by-step outcomes. All data is F1 metadata
    (trusted by construction) — no raw Qwen output.

    For fix-cycle turns (retry after failure), ``original_request``
    carries the initial scenario prompt so the record is searchable
    by scenario content rather than the generic retry text.

    Scanner blocks are reported as "blocked" with no scanner names
    or internal details — the planner should not know which specific
    scanners exist.

    Budget: ~800 chars. nomic-embed-text handles up to 8192 tokens;
    the real constraint is the planner's token budget for episodic
    context (~2K tokens shared across multiple records).
    """
    # Line 1: [domain] request — use original scenario for fix-cycles
    # so the embedding/search key reflects the actual task, not the
    # generic "previous task failed" retry prompt.
    # Finding #1: Sanitise user_request and original_request before planner replay
    logger.debug(
        "render_episodic_text called",
        extra={
            "event": "episodic.render_episodic_text",
            "user_request": user_request,
            "task_status": task_status,
            "step_count": step_count,
        },
    )  # auto:entry
    display_request = _sanitise_for_planner(user_request)
    is_fix_cycle = original_request is not None and original_request != user_request
    if is_fix_cycle:
        display_request = _sanitise_for_planner(original_request)

    if task_domain:
        header = f"[{task_domain}] {display_request[:140]}"
    else:
        header = display_request[:150]
    if is_fix_cycle:
        header += " (fix-cycle)"
    lines = [header]

    # Line 2: Result with duration
    total_duration = 0.0
    if step_outcomes:
        for o in step_outcomes:
            d = o.get("duration_s")
            if d is not None:
                total_duration += d
    duration_part = f", {total_duration:.0f}s" if total_duration > 0 else ""
    lines.append(
        f"Result: {task_status.upper()} ({success_count}/{step_count} steps{duration_part})"
    )

    # Line 3: Strategy pattern
    strategy = _categorise_strategy(step_outcomes or [])
    lines.append(f"Strategy: {strategy}")

    # Line 4: File types involved — extensions only, not full filenames.
    # Full filenames cause the planner to over-fit to specific names from
    # past tasks (e.g. "clock.js") instead of discovering current state.
    # Extensions preserve useful type info (.html, .css, .js) without
    # the specifics that poison future plans.
    # Finding #5: import os moved to module level
    if file_paths:
        seen_exts: set[str] = set()
        ext_labels: list[str] = []
        for fp in file_paths:
            _, ext = os.path.splitext(os.path.basename(fp))
            ext = ext.lower() if ext else "(no ext)"
            if ext not in seen_exts:
                seen_exts.add(ext)
                ext_labels.append(ext)
            if len(ext_labels) >= 6:
                break
        if ext_labels:
            lines.append(f"File types: {', '.join(ext_labels)}")

    # Lines 5+: Per-step outcomes — show ALL steps so the planner
    # can learn the full execution trajectory, not just failures.
    # Scanner blocks say "blocked" only — no scanner names or details.
    if step_outcomes:
        for i, o in enumerate(step_outcomes, 1):
            step_status = o.get("status", "unknown")
            tool = o.get("tool") or o.get("step_type", "?")
            desc = o.get("description", "")[:50]
            exit_code = o.get("exit_code")

            # Build compact step summary
            status_label = step_status.upper()
            step_parts = [f"S{i}({tool}): {status_label}"]
            if desc:
                step_parts.append(desc)
            if exit_code is not None and exit_code != 0:
                step_parts.append(f"exit={exit_code}")

            # For failures: stderr is the most valuable diagnostic
            # Finding #7: Redact internal paths from stderr before planner injection
            if step_status in ("failed", "error", "soft_failed"):
                stderr = o.get("stderr_preview", "")
                if stderr:
                    stderr = _sanitise_for_planner(stderr)
                    stderr_line = _extract_key_stderr_line(stderr)
                    if stderr_line:
                        stderr_line = _redact_paths(stderr_line)
                        step_parts.append(f"stderr: {stderr_line}")
                elif o.get("error_detail"):
                    step_parts.append(o["error_detail"][:60])
                if o.get("sandbox_timed_out"):
                    step_parts.append("sandbox_timeout")
                if o.get("sandbox_oom_killed"):
                    step_parts.append("sandbox_oom")

            # For blocks: say "blocked" only — no scanner internals
            elif step_status == "blocked":
                step_parts.append("blocked by security policy")

            # For success with exit code 0: note verification passed
            elif (
                step_status == "success"
                and exit_code == 0
                and tool in ("shell", "shell_exec")
            ):
                step_parts.append("verified")

            line = "; ".join(step_parts)
            # Stop adding steps if we'd bust the budget
            current_len = sum(len(l) + 1 for l in lines) + len(line)
            if (
                current_len > RENDER_MAX_CHARS - 100
            ):  # reserve 100 chars for remaining fields
                lines.append(f"... +{len(step_outcomes) - i} more steps")
                break
            lines.append(line)

    # Prior error context — what failed in the previous turn that
    # prompted this fix-cycle. Gives the planner the error to learn from.
    if prior_error_summary:
        scrubbed_prior = _sanitise_for_planner(prior_error_summary)
        lines.append(f"Prior error: {scrubbed_prior[:_STDERR_TRUNCATE_CHARS]}")

    # Plan line — if plan_json is available, render compact tool chain with
    # outcome annotations. Otherwise fall back to plain plan_summary.
    if plan_json and plan_json.get("phases"):
        plan_line = _render_compact_plan_line(plan_json)
        if plan_line:
            lines.append(f"Plan: {plan_line}")
    elif plan_summary:
        lines.append(f"Plan: {plan_summary[:100]}")

    result = "\n".join(lines)
    if len(result) > RENDER_MAX_CHARS:
        result = result[: RENDER_MAX_CHARS - 3] + "..."
    return result


_ABS_PATH_PATTERN = re.compile(r"(?:/[a-zA-Z0-9._-]+){3,}")


def _redact_paths(text: str) -> str:
    """Finding #7: Redact absolute paths from text to avoid leaking internal structure.

    Replaces paths like /opt/sentinel/internal/foo.py with just the basename.
    The planner needs the error message, not the full filesystem layout.
    """

    def _replace_path(m: re.Match) -> str:
        return os.path.basename(m.group(0))

    return _ABS_PATH_PATTERN.sub(_replace_path, text)


def _extract_key_stderr_line(stderr: str) -> str:
    """Extract the most informative line from stderr output.

    Looks for error class names (ImportError, SyntaxError, etc.),
    assertion failures, or the last non-empty line as fallback.
    Returns a single line, max 120 chars.
    """
    logger.debug(
        "_extract_key_stderr_line called",
        extra={
            "event": "episodic._extract_key_stderr_line",
            "stderr_len": len(stderr) if hasattr(stderr, "__len__") else 0,
        },
    )  # auto:entry
    if not stderr:
        return ""
    lines = stderr.strip().splitlines()
    # Priority 1: lines starting with a Python error class
    for line in reversed(lines):
        stripped = line.strip()
        if any(
            stripped.startswith(e)
            for e in (
                "ImportError",
                "SyntaxError",
                "IndentationError",
                "TypeError",
                "NameError",
                "AttributeError",
                "ValueError",
                "KeyError",
                "ModuleNotFoundError",
                "FileNotFoundError",
                "OSError",
                "RuntimeError",
                "AssertionError",
                "ZeroDivisionError",
                "IndexError",
                "StopIteration",
                "RecursionError",
                "PermissionError",
                "ConnectionError",
                "TimeoutError",
            )
        ):
            return stripped[:_STDERR_TRUNCATE_CHARS]
    # Priority 2: lines containing 'Error:' or 'FAILED' or 'assert'
    for line in reversed(lines):
        stripped = line.strip()
        low = stripped.lower()
        if "error:" in low or "failed" in low or "assert" in low:
            return stripped[:_STDERR_TRUNCATE_CHARS]
    # Fallback: last non-empty line
    for line in reversed(lines):
        stripped = line.strip()
        if stripped:
            return stripped[:_STDERR_TRUNCATE_CHARS]
    return ""


def extract_episodic_facts(
    step_outcomes: list[dict],
    user_request: str,
    task_status: str,
) -> list[EpisodicFact]:
    """Extract notable facts from F1 step_outcomes — deterministic, no LLM.

    Examines each step outcome for notable patterns:
    - File creation (file_write where file_size_before is None)
    - File modification (file_write where file_size_before is not None)
    - Scanner blocks (scanner_result == "blocked")
    - Execution errors (non-zero exit_code)
    - Symbol definitions (non-empty defined_symbols)
    - Truncation warnings (token_usage_ratio >= 0.95)

    All extracted data comes from F1 metadata (TRUSTED, orchestrator-generated).
    No raw Qwen output crosses into facts.
    """
    facts: list[EpisodicFact] = []
    now = ""  # DB default handles timestamp

    for outcome in step_outcomes:
        file_path = outcome.get("file_path")

        # File creation: file_write with no prior file
        if (
            outcome.get("step_type") == "tool_call"
            and file_path
            and outcome.get("file_size_before") is None
            and outcome.get("file_size_after") is not None
        ):
            size = outcome["file_size_after"]
            lang = outcome.get("output_language", "")
            lang_part = f", {lang}" if lang else ""
            facts.append(
                EpisodicFact(
                    fact_id=str(uuid.uuid4()),
                    record_id="",  # linked at store time
                    fact_type="file_create",
                    content=f"{file_path} created ({size} bytes{lang_part})",
                    file_path=file_path,
                    created_at=now,
                )
            )
            continue  # don't also match as modification

        # File modification: file_write with prior file
        if (
            outcome.get("step_type") == "tool_call"
            and file_path
            and outcome.get("file_size_before") is not None
            and outcome.get("file_size_after") is not None
        ):
            before = outcome["file_size_before"]
            after = outcome["file_size_after"]
            diff = outcome.get("diff_stats", "")
            diff_part = f", {diff}" if diff else ""
            facts.append(
                EpisodicFact(
                    fact_id=str(uuid.uuid4()),
                    record_id="",
                    fact_type="file_modify",
                    content=f"{file_path} modified ({before}\u2192{after} bytes{diff_part})",
                    file_path=file_path,
                    created_at=now,
                )
            )

        # Scanner block — uses genericised error_detail (scanner_details redacted)
        if outcome.get("scanner_result") == "blocked":
            generic_err = outcome.get("error_detail", "blocked")
            facts.append(
                EpisodicFact(
                    fact_id=str(uuid.uuid4()),
                    record_id="",
                    fact_type="scanner_block",
                    content=f"Scanner block: {generic_err}",
                    file_path=file_path,
                    created_at=now,
                )
            )

        # Execution error
        exit_code = outcome.get("exit_code")
        if exit_code is not None and exit_code != 0:
            stderr = outcome.get("stderr_preview", "")
            stderr_part = f", {stderr[:100]}" if stderr else ""
            path_part = file_path or "shell"
            facts.append(
                EpisodicFact(
                    fact_id=str(uuid.uuid4()),
                    record_id="",
                    fact_type="exec_error",
                    content=f"{path_part}: exit {exit_code}{stderr_part}",
                    file_path=file_path,
                    created_at=now,
                )
            )

        # Symbol definitions
        symbols = outcome.get("defined_symbols")
        if symbols and isinstance(symbols, list) and len(symbols) > 0:
            symbol_list = ", ".join(symbols[:10])
            path_part = file_path or "code"
            facts.append(
                EpisodicFact(
                    fact_id=str(uuid.uuid4()),
                    record_id="",
                    fact_type="symbol_def",
                    content=f"{path_part} defines: [{symbol_list}]",
                    file_path=file_path,
                    created_at=now,
                )
            )

        # Truncation warning
        ratio = outcome.get("token_usage_ratio")
        if ratio is not None and ratio >= 0.95:
            size = outcome.get("output_size", "unknown")
            facts.append(
                EpisodicFact(
                    fact_id=str(uuid.uuid4()),
                    record_id="",
                    fact_type="truncation",
                    content=f"Truncation: output at {ratio * 100:.0f}% token cap ({size} chars, likely incomplete)",
                    file_path=file_path,
                    created_at=now,
                )
            )

    return facts


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row_to_record(row: Any) -> EpisodicRecord:
    """Convert an asyncpg Record to an EpisodicRecord dataclass."""
    # JSONB fields come back as native Python types from asyncpg
    logger.debug(
        "_row_to_record called",
        extra={"event": "episodic._row_to_record", "row_type": type(row).__name__},
    )  # auto:entry
    file_paths = row["file_paths"]
    if isinstance(file_paths, str):
        file_paths = json.loads(file_paths)

    error_patterns = row["error_patterns"]
    if isinstance(error_patterns, str):
        error_patterns = json.loads(error_patterns)

    defined_symbols = row["defined_symbols"]
    if isinstance(defined_symbols, str):
        defined_symbols = json.loads(defined_symbols)

    step_outcomes = row["step_outcomes"]
    if isinstance(step_outcomes, str):
        step_outcomes = json.loads(step_outcomes)

    linked_records = row["linked_records"]
    if isinstance(linked_records, str):
        linked_records = json.loads(linked_records)

    # plan_json may not exist on older databases — graceful fallback
    plan_json = row.get("plan_json") if hasattr(row, "get") else None
    if isinstance(plan_json, str):
        plan_json = json.loads(plan_json)

    return EpisodicRecord(
        record_id=row["record_id"],
        session_id=row["session_id"],
        task_id=row["task_id"],
        user_id=row["user_id"],
        user_request=row["user_request"],
        task_status=row["task_status"],
        plan_summary=row["plan_summary"],
        step_count=row["step_count"],
        success_count=row["success_count"],
        file_paths=file_paths,
        error_patterns=error_patterns,
        defined_symbols=defined_symbols,
        step_outcomes=step_outcomes,
        linked_records=linked_records,
        relevance_score=row["relevance_score"],
        access_count=row["access_count"],
        last_accessed=_dt_to_iso(row["last_accessed"]),
        task_domain=row.get("task_domain")
        if hasattr(row, "get")
        else row["task_domain"],
        plan_json=plan_json,
        memory_chunk_id=row["memory_chunk_id"],
        created_at=_dt_to_iso(row["created_at"]) or "",
    )


def _row_to_fact(row: Any) -> EpisodicFact:
    """Convert an asyncpg Record to an EpisodicFact dataclass."""
    return EpisodicFact(
        fact_id=row["fact_id"],
        record_id=row["record_id"],
        fact_type=row["fact_type"],
        content=row["content"],
        file_path=row["file_path"],
        created_at=_dt_to_iso(row["created_at"]) or "",
        # Q4-F13: defensive default flipped from 1 → 0 to match the
        # ContextVar unset-sentinel convention. Both call paths' SELECTs
        # always project user_id; the default only fires on schema drift.
        user_id=row.get("user_id", 0) if hasattr(row, "get") else 0,
    )


_RECORD_COLUMNS = (
    "record_id, session_id, task_id, user_id, user_request, "
    "task_status, plan_summary, step_count, success_count, "
    "file_paths, error_patterns, defined_symbols, step_outcomes, "
    "linked_records, relevance_score, access_count, last_accessed, "
    "task_domain, plan_json, memory_chunk_id, created_at"
)


class EpisodicStore:
    """PostgreSQL episodic memory store with in-memory fallback for tests."""

    def __init__(self, pool: Any = None):
        self._pool = pool
        # In-memory fallback state
        self._mem: dict[str, EpisodicRecord] = {}
        self._file_index: dict[str, set[str]] = {}  # file_path → set of record_ids
        self._facts: dict[str, list[EpisodicFact]] = {}  # record_id → facts

        # Extracted subsystems — share _facts dict for in-memory coherence
        from sentinel.memory.anchor_maps import AnchorMapStore
        from sentinel.memory.episodic_facts import EpisodicFactIndex

        self._fact_index = EpisodicFactIndex(pool=pool, facts_dict=self._facts)
        self._anchor_maps = AnchorMapStore(pool=pool, facts_dict=self._facts)

    @property
    def pool(self) -> Any:
        """Expose pool for cross-store access (e.g. InsightExtractor)."""
        return self._pool

    async def create(
        self,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: int | None = None,  # Finding #9: fallback to current_user_id
        task_domain: str | None = None,
        plan_json: dict | None = None,
    ) -> str:
        """Create an episodic record + file index entries. Returns record_id."""
        # Q4-F1: resolve via helper — None resolves from current_user_id; raises on 0.
        if user_id is None:
            logger.debug("create: match", extra={"event": "episodic.create.match"})
        user_id = require_user_id(user_id, "EpisodicStore.create")
        record_id = str(uuid.uuid4())
        file_paths = file_paths or []
        error_patterns = error_patterns or []
        defined_symbols = defined_symbols or []

        if self._pool is not None:
            logger.debug("create: clean", extra={"event": "episodic.create.db.clean"})
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        "INSERT INTO episodic_records "
                        "(record_id, session_id, task_id, user_id, user_request, "
                        "task_status, plan_summary, step_count, success_count, "
                        "file_paths, error_patterns, defined_symbols, step_outcomes, "
                        "task_domain, plan_json) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, "
                        "$10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb, $14, $15::jsonb)",
                        record_id,
                        session_id,
                        task_id,
                        user_id,
                        user_request,
                        task_status,
                        plan_summary,
                        step_count,
                        success_count,
                        json.dumps(file_paths),
                        json.dumps(error_patterns),
                        json.dumps(defined_symbols),
                        json.dumps(step_outcomes) if step_outcomes else None,
                        task_domain,
                        json.dumps(plan_json) if plan_json else None,
                    )

                    # Populate file index
                    for path in file_paths:
                        await conn.execute(
                            "INSERT INTO episodic_file_index (file_path, record_id, action, user_id) "
                            "VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                            path,
                            record_id,
                            "modified",
                            user_id,
                        )
        else:
            logger.debug("create: clean", extra={"event": "episodic.create.db.clean"})
            now = _now_iso()
            self._mem[record_id] = EpisodicRecord(
                record_id=record_id,
                session_id=session_id,
                task_id=task_id,
                user_id=user_id,
                user_request=user_request,
                task_status=task_status,
                plan_summary=plan_summary,
                step_count=step_count,
                success_count=success_count,
                file_paths=file_paths,
                error_patterns=error_patterns,
                defined_symbols=defined_symbols,
                step_outcomes=step_outcomes,
                linked_records=[],
                relevance_score=1.0,
                access_count=0,
                last_accessed=None,
                task_domain=task_domain,
                plan_json=plan_json,
                memory_chunk_id=None,
                created_at=now,
            )
            # Populate file index
            for path in file_paths:
                if path not in self._file_index:
                    logger.debug(
                        "create: match", extra={"event": "episodic.create.match"}
                    )
                    self._file_index[path] = set()
                self._file_index[path].add(record_id)

        logger.debug(
            "Episodic record created",
            extra={
                "event": "episodic.record_created",
                "record_id": record_id,
                "session_id": session_id,
                "task_status": task_status,
                "file_count": len(file_paths),
                "task_id": get_task_id(),
            },
        )
        return record_id

    async def get(
        self, record_id: str, user_id: int | None = None
    ) -> EpisodicRecord | None:
        """Fetch a single episodic record by ID."""
        logger.debug(
            "get called",
            extra={"event": "episodic.get", "record_id": record_id, "user_id": user_id},
        )  # auto:entry
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    f"SELECT {_RECORD_COLUMNS} "  # nosec B608 — _RECORD_COLUMNS is a module constant; values parameterised via asyncpg
                    "FROM episodic_records WHERE record_id = $1 AND user_id = $2",
                    record_id,
                    resolved_user_id,
                )
                if row is None:
                    return None
                return _row_to_record(row)

        record = self._mem.get(record_id)
        if record is not None and record.user_id != resolved_user_id:
            return None
        return record

    async def list_by_session(
        self,
        session_id: str,
        user_id: int | None = None,
        limit: int = 50,
    ) -> list[EpisodicRecord]:
        """List records for a session, newest first."""
        logger.debug(
            "list_by_session called",
            extra={
                "event": "episodic.list_by_session",
                "session_id": session_id,
                "user_id": user_id,
                "limit": limit,
            },
        )  # auto:entry
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    f"SELECT {_RECORD_COLUMNS} "  # nosec B608 — _RECORD_COLUMNS is a module constant; values parameterised via asyncpg
                    "FROM episodic_records WHERE session_id = $1 "
                    "AND user_id = $2 "
                    "ORDER BY created_at DESC LIMIT $3",
                    session_id,
                    resolved_user_id,
                    limit,
                )
                return [_row_to_record(r) for r in rows]

        records = [
            r
            for r in self._mem.values()
            if r.session_id == session_id and r.user_id == resolved_user_id
        ]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit]

    async def list_by_file(
        self,
        file_path: str,
        user_id: int | None = None,
        limit: int = 50,
    ) -> list[EpisodicRecord]:
        """List records that affected a given file path, newest first."""
        # Finding #10: Consistent with other methods — fallback to contextvar
        logger.debug(
            "list_by_file called",
            extra={
                "event": "episodic.list_by_file",
                "file_path": file_path,
                "user_id": user_id,
                "limit": limit,
            },
        )  # auto:entry
        # Q4-F2: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicStore.list_by_file")
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    f"SELECT er.{', er.'.join(_RECORD_COLUMNS.split(', '))} "  # nosec B608 — _RECORD_COLUMNS is a module constant; values parameterised via asyncpg
                    "FROM episodic_records er "
                    "JOIN episodic_file_index efi ON er.record_id = efi.record_id "
                    "WHERE efi.file_path = $1 AND er.user_id = $2 "
                    "ORDER BY er.created_at DESC LIMIT $3",
                    file_path,
                    user_id,
                    limit,
                )
                return [_row_to_record(r) for r in rows]

        record_ids = self._file_index.get(file_path, set())
        records = [
            self._mem[rid]
            for rid in record_ids
            if rid in self._mem and self._mem[rid].user_id == user_id
        ]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit]

    async def list_by_domain(
        self,
        domain: str,
        user_id: int | None = None,
        limit: int = 100,
    ) -> list[EpisodicRecord]:
        """List episodic records for a specific task domain, newest first."""
        logger.debug(
            "list_by_domain called",
            extra={
                "event": "episodic.list_by_domain",
                "domain": domain,
                "user_id": user_id,
                "limit": limit,
            },
        )  # auto:entry
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    f"SELECT {_RECORD_COLUMNS} "  # nosec B608 — _RECORD_COLUMNS is a module constant; values parameterised via asyncpg
                    "FROM episodic_records "
                    "WHERE task_domain = $1 AND user_id = $2 "
                    "ORDER BY created_at DESC LIMIT $3",
                    domain,
                    resolved_uid,
                    limit,
                )
                return [_row_to_record(row) for row in rows]

        # In-memory fallback
        records = [
            r
            for r in self._mem.values()
            if r.user_id == resolved_uid and r.task_domain == domain
        ]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit]

    async def delete(self, record_id: str, user_id: int | None = None) -> bool:
        """Delete an episodic record. FK CASCADE handles file_index + facts."""
        logger.debug(
            "delete called",
            extra={
                "event": "episodic.delete",
                "record_id": record_id,
                "user_id": user_id,
            },
        )  # auto:entry
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM episodic_records WHERE record_id = $1 AND user_id = $2",
                    record_id,
                    resolved_user_id,
                )
                return result == "DELETE 1"

        record = self._mem.get(record_id)
        if record is None or record.user_id != resolved_user_id:
            return False
        # Clean up file index
        for path in record.file_paths:
            ids = self._file_index.get(path)
            if ids:
                ids.discard(record_id)
                if not ids:
                    del self._file_index[path]
        # Clean up facts
        self._facts.pop(record_id, None)
        del self._mem[record_id]
        return True

    async def find_linked_records(
        self,
        file_paths: list[str],
        user_id: int | None = None,
        exclude_record_id: str = "",
    ) -> list[str]:
        """Find existing record IDs that share any file paths."""
        # Q4-F5: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicStore.find_linked_records")
        logger.debug(
            "find_linked_records called",
            extra={
                "event": "episodic.find_linked_records",
                "file_paths_len": len(file_paths)
                if hasattr(file_paths, "__len__")
                else 0,
                "user_id": user_id,
                "exclude_record_id": exclude_record_id,
            },
        )  # auto:entry
        if not file_paths:
            return []

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT DISTINCT record_id FROM episodic_file_index "
                    "WHERE file_path = ANY($1) AND record_id != $2 "
                    "AND user_id = $3",
                    file_paths,
                    exclude_record_id,
                    user_id,
                )
                return [r["record_id"] for r in rows]

        # In-memory path: filter by user_id via the parent record
        result_ids: set[str] = set()
        for path in file_paths:
            for rid in self._file_index.get(path, set()):
                if rid != exclude_record_id:
                    rec = self._mem.get(rid)
                    if rec is not None and rec.user_id == user_id:
                        result_ids.add(rid)
        return list(result_ids)

    async def _add_link(
        self,
        conn: Any,
        record_id: str,
        linked_id: str,
        link_type: str = "file",
        user_id: int | None = None,
    ) -> None:
        """Add a link entry to a record's linked_records JSONB array."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            logger.debug(
                "_add_link: clean", extra={"event": "episodic._add_link.db.clean"}
            )
            row = await conn.fetchrow(
                "SELECT linked_records FROM episodic_records "
                "WHERE record_id = $1 AND user_id = $2",
                record_id,
                resolved_user_id,
            )
            if row is None:
                return

            links = row["linked_records"]
            if isinstance(links, str):
                logger.debug(
                    "_add_link: match", extra={"event": "episodic._add_link.match"}
                )
                links = json.loads(links)

            # Avoid duplicates
            if not any(l["record_id"] == linked_id for l in links):
                logger.debug(
                    "_add_link: match", extra={"event": "episodic._add_link.match"}
                )
                links.append({"record_id": linked_id, "link_type": link_type})
                await conn.execute(
                    "UPDATE episodic_records SET linked_records = $1::jsonb "
                    "WHERE record_id = $2 AND user_id = $3",
                    json.dumps(links),
                    record_id,
                    resolved_user_id,
                )
        else:
            logger.debug(
                "_add_link: clean", extra={"event": "episodic._add_link.db.clean"}
            )
            record = self._mem.get(record_id)
            if record is None or record.user_id != resolved_user_id:
                return
            if not any(l["record_id"] == linked_id for l in record.linked_records):
                logger.debug(
                    "_add_link: match", extra={"event": "episodic._add_link.match"}
                )
                record.linked_records.append(
                    {"record_id": linked_id, "link_type": link_type}
                )

    async def prune_stale(
        self,
        threshold: float = 0.05,
        min_age_days: int = 30,
        user_id: int | None = None,
        *,
        admin: bool = False,
    ) -> int:
        """Remove old, unaccessed episodic records below relevance threshold.

        Finding #11: Cross-user pruning requires explicit ``admin=True``.
        When user_id is None and admin is False, falls back to current_user_id.
        When user_id is None and admin is True, prunes across ALL users.
        When user_id is an int, only that user's records are considered.
        """
        if user_id is None and not admin:
            # Q4-F3: resolve via helper — None resolves from current_user_id; raises on 0.
            # Admin path (admin=True) is intentionally cross-user and stays unchanged.
            user_id = require_user_id(user_id, "EpisodicStore.prune_stale")
            logger.debug(
                "prune_stale: no user_id provided, using current_user_id=%d",
                user_id,
                extra={
                    "event": "episodic.prune_stale_user_fallback",
                    "user_id": user_id,
                },
            )
        elif user_id is None and admin:
            logger.warning(
                "prune_stale: admin mode — pruning across ALL users",
                extra={"event": "episodic.prune_stale_admin"},
            )
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if user_id is not None:
                    rows = await conn.fetch(
                        "SELECT record_id, "
                        "EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 AS age_days, "
                        "access_count, memory_chunk_id "
                        "FROM episodic_records "
                        "WHERE EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 > $1 "
                        "AND user_id = $2",
                        float(min_age_days),
                        user_id,
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT record_id, "
                        "EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 AS age_days, "
                        "access_count, memory_chunk_id "
                        "FROM episodic_records "
                        "WHERE EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 > $1",
                        float(min_age_days),
                    )

                # Collect IDs of records and shadow chunks to prune
                record_ids_to_prune: list[str] = []
                chunk_ids_to_prune: list[str] = []
                for row in rows:
                    effective = compute_relevance(row["age_days"], row["access_count"])
                    if effective < threshold:
                        record_ids_to_prune.append(row["record_id"])
                        chunk_id = row["memory_chunk_id"]
                        if chunk_id:
                            chunk_ids_to_prune.append(chunk_id)

                if not record_ids_to_prune:
                    return 0

                # Batch delete shadow chunks (best-effort — don't fail the prune)
                if chunk_ids_to_prune:
                    try:
                        await conn.execute(
                            "DELETE FROM memory_chunks WHERE chunk_id = ANY($1)",
                            chunk_ids_to_prune,
                        )
                    except (
                        Exception
                    ) as exc:  # catch-all: shadow chunk prune best-effort
                        logger.warning(
                            "Shadow chunk batch deletion failed",
                            extra={
                                "event": "episodic.prune_shadow_failed",
                                "chunk_count": len(chunk_ids_to_prune),
                                "error": str(exc),
                            },
                            exc_info=True,
                        )

                # Batch delete episodic records — FK CASCADE handles file_index + facts
                # Finding #13: Re-verify user_id in the DELETE for defence-in-depth.
                # The candidate list was already filtered, but this prevents
                # cross-user deletion if the filter query is ever corrupted.
                if user_id is not None:
                    await conn.execute(
                        "DELETE FROM episodic_records WHERE record_id = ANY($1) AND user_id = $2",
                        record_ids_to_prune,
                        user_id,
                    )
                else:
                    await conn.execute(
                        "DELETE FROM episodic_records WHERE record_id = ANY($1)",
                        record_ids_to_prune,
                    )

                pruned = len(record_ids_to_prune)
                if pruned > 0:
                    logger.info(
                        "Episodic memory pruned",
                        extra={"event": "episodic.pruned", "count": pruned},
                    )

                return pruned

        # In-memory path
        now = datetime.now(UTC)
        to_prune = []
        for record in self._mem.values():
            if user_id is not None and record.user_id != user_id:
                continue
            try:
                created = datetime.fromisoformat(record.created_at)
                age_days = (now - created).total_seconds() / 86400.0
            except (ValueError, AttributeError):
                continue
            if age_days <= min_age_days:
                continue
            effective = compute_relevance(age_days, record.access_count)
            if effective < threshold:
                to_prune.append(record.record_id)

        for rid in to_prune:
            # Pass user_id through so the delete's user_id filter matches.
            # When user_id is None (admin/cross-user prune), use the record's
            # own user_id so the filter doesn't reject it.
            record = self._mem.get(rid)
            delete_uid = (
                user_id if user_id is not None else (record.user_id if record else 0)
            )
            await self.delete(rid, user_id=delete_uid)

        if to_prune:
            logger.info(
                "Episodic memory pruned",
                extra={"event": "episodic.pruned", "count": len(to_prune)},
            )
        return len(to_prune)

    async def update_access(self, record_id: str, user_id: int | None = None) -> None:
        """Bump access_count and last_accessed timestamp."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            logger.debug(
                "update_access: clean",
                extra={"event": "episodic.update_access.db.clean"},
            )
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE episodic_records SET "
                    "access_count = access_count + 1, last_accessed = NOW() "
                    "WHERE record_id = $1 AND user_id = $2",
                    record_id,
                    resolved_user_id,
                )
        else:
            logger.debug(
                "update_access: clean",
                extra={"event": "episodic.update_access.db.clean"},
            )
            record = self._mem.get(record_id)
            if record is not None and record.user_id == resolved_user_id:
                logger.debug(
                    "update_access: match",
                    extra={"event": "episodic.update_access.match"},
                )
                record.access_count += 1
                record.last_accessed = _now_iso()

    async def batch_update_access(
        self, record_ids: list[str], user_id: int | None = None
    ) -> None:
        """Bump access_count for multiple records in a single query."""
        if not record_ids:
            return

        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            logger.debug(
                "batch_update_access: clean",
                extra={"event": "episodic.batch_update_access.db.clean"},
            )
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE episodic_records SET "
                    "access_count = access_count + 1, last_accessed = NOW() "
                    "WHERE record_id = ANY($1) AND user_id = $2",
                    record_ids,
                    resolved_user_id,
                )
        else:
            logger.debug(
                "batch_update_access: clean",
                extra={"event": "episodic.batch_update_access.db.clean"},
            )
            now = _now_iso()
            for rid in record_ids:
                record = self._mem.get(rid)
                if record is not None and record.user_id == resolved_user_id:
                    logger.debug(
                        "batch_update_access: match",
                        extra={"event": "episodic.batch_update_access.match"},
                    )
                    record.access_count += 1
                    record.last_accessed = now

    async def set_memory_chunk_id(
        self, record_id: str, chunk_id: str, user_id: int | None = None
    ) -> None:
        """Set the memory_chunks shadow entry ID for search integration."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            logger.debug(
                "set_memory_chunk_id: clean",
                extra={"event": "episodic.set_memory_chunk_id.db.clean"},
            )
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE episodic_records SET memory_chunk_id = $1 "
                    "WHERE record_id = $2 AND user_id = $3",
                    chunk_id,
                    record_id,
                    resolved_user_id,
                )
        else:
            logger.debug(
                "set_memory_chunk_id: clean",
                extra={"event": "episodic.set_memory_chunk_id.db.clean"},
            )
            record = self._mem.get(record_id)
            if record is not None and record.user_id == resolved_user_id:
                logger.debug(
                    "set_memory_chunk_id: match",
                    extra={"event": "episodic.set_memory_chunk_id.match"},
                )
                record.memory_chunk_id = chunk_id

    async def create_with_shadow(
        self,
        memory_store,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: int | None = None,
        embedding: list[float] | None = None,
        task_domain: str | None = None,
        original_request: str | None = None,
        prior_error_summary: str | None = None,
        plan_json: dict | None = None,
    ) -> str:
        """Create episodic record + memory_chunks shadow entry."""
        # Q4-F4: resolve via helper — None resolves from current_user_id; raises on 0.
        # Resolved value is then threaded through every downstream call below.
        user_id = require_user_id(user_id, "EpisodicStore.create_with_shadow")
        logger.debug(
            "create_with_shadow called",
            extra={
                "event": "episodic.create_with_shadow",
                "memory_store_type": type(memory_store).__name__,
                "session_id": session_id,
                "task_id": task_id,
            },
        )  # auto:entry
        record_id = await self.create(
            session_id=session_id,
            task_id=task_id,
            user_request=user_request,
            task_status=task_status,
            plan_summary=plan_summary,
            step_count=step_count,
            success_count=success_count,
            file_paths=file_paths,
            error_patterns=error_patterns,
            defined_symbols=defined_symbols,
            step_outcomes=step_outcomes,
            user_id=user_id,
            task_domain=task_domain,
            plan_json=plan_json,
        )

        # Render text for shadow entry (include step_outcomes for enriched FTS/vector search)
        text = render_episodic_text(
            user_request=user_request,
            task_status=task_status,
            step_count=step_count,
            success_count=success_count,
            file_paths=file_paths,
            plan_summary=plan_summary,
            error_patterns=error_patterns,
            step_outcomes=step_outcomes,
            task_domain=task_domain,
            original_request=original_request,
            prior_error_summary=prior_error_summary,
            plan_json=plan_json,
        )

        metadata = {
            "record_id": record_id,
            "session_id": session_id,
            "task_status": task_status,
        }
        if task_domain:
            metadata["task_domain"] = task_domain

        # Store shadow with or without embedding
        if embedding is not None:
            chunk_id = await memory_store.store_with_embedding(
                content=text,
                embedding=embedding,
                source="system:episodic",
                metadata=metadata,
                user_id=user_id,
                task_domain=task_domain,
            )
        else:
            chunk_id = await memory_store.store(
                content=text,
                source="system:episodic",
                metadata=metadata,
                user_id=user_id,
                task_domain=task_domain,
            )

        await self.set_memory_chunk_id(record_id, chunk_id)

        # Cross-task file-path linking — bidirectional
        file_paths = file_paths or []
        linked_ids = await self.find_linked_records(
            file_paths,
            user_id=user_id,
            exclude_record_id=record_id,
        )
        if linked_ids:
            if self._pool is not None:
                async with self._pool.acquire() as conn:
                    for linked_id in linked_ids:
                        await self._add_link(
                            conn, record_id, linked_id, "file", user_id=user_id
                        )
                        await self._add_link(
                            conn, linked_id, record_id, "file", user_id=user_id
                        )
            else:
                for linked_id in linked_ids:
                    await self._add_link(
                        None, record_id, linked_id, "file", user_id=user_id
                    )
                    await self._add_link(
                        None, linked_id, record_id, "file", user_id=user_id
                    )

        return record_id

    async def store_facts(
        self,
        record_id: str,
        facts: list[EpisodicFact],
        user_id: int | None = None,
    ) -> None:
        """Store extracted facts for a record. Delegates to EpisodicFactIndex."""
        # Q4-F6: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicStore.store_facts")
        await self._fact_index.store_facts(record_id, facts, user_id)

    async def upsert_anchor_map(
        self,
        fact_id: str,
        record_id: str,
        content: str,
        file_path: str,
        user_id: int | None = None,
    ) -> None:
        """Atomically insert or update an anchor map fact. Delegates to AnchorMapStore."""
        # Q4-F6: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicStore.upsert_anchor_map")
        await self._anchor_maps.upsert_anchor_map(
            fact_id, record_id, content, file_path, user_id
        )

    async def get_anchor_map(
        self,
        file_path: str,
        user_id: int | None = None,
    ) -> EpisodicFact | None:
        """Retrieve anchor map by exact file_path. Delegates to AnchorMapStore."""
        # Q4-F6: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicStore.get_anchor_map")
        return await self._anchor_maps.get_anchor_map(file_path, user_id)

    async def delete_anchor_map(
        self,
        file_path: str,
        user_id: int | None = None,
    ) -> bool:
        """Delete anchor map by exact file_path. Delegates to AnchorMapStore."""
        # Q4-F6: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicStore.delete_anchor_map")
        return await self._anchor_maps.delete_anchor_map(file_path, user_id)

    async def search_facts(
        self,
        query: str,
        fact_type: str | None = None,
        user_id: int | None = None,
        limit: int = 20,
    ) -> list[EpisodicFact]:
        """Search facts via full-text search. Delegates to EpisodicFactIndex."""
        # Q4-F6: resolve via helper — None resolves from current_user_id; raises on 0.
        user_id = require_user_id(user_id, "EpisodicStore.search_facts")
        return await self._fact_index.search_facts(query, fact_type, user_id, limit)
