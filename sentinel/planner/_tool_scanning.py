"""Tool output scanning, goal action checks, file mutation extraction,
stagnation detection, and idempotent call detection.

Extracted from verification.py during planner modularisation (Phase 3).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sentinel.crypto.blind_index import log_hash

logger = logging.getLogger(__name__)

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
_DISCOVERY_ONLY_TOOLS = frozenset(
    {
        "file_read",
        "list_dir",
        "find_file",
        "web_search",
        "brave_search",
    }
)

# Tools that mutate state (files, external services).
_EFFECT_TOOLS = frozenset(
    {
        "file_write",
        "file_patch",
        "website",
        "shell",
        "shell_exec",
        "signal_send",
        "email_send",
        "telegram_send",
    }
)

# Tools that write to files (subset of effect tools).
_FILE_MUTATION_TOOLS = frozenset(
    {
        "file_write",
        "file_patch",
        "website",
    }
)

# ── Tool Output Scanner ───────────────────────────────────────────


@dataclass
class ToolOutputWarning:
    pattern: str
    severity: str  # "HIGH", "MEDIUM", "LOW"


# Patterns checked in order; first match wins per category.
_OUTPUT_FAILURE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"No such file or directory", re.IGNORECASE),
        "No such file or directory",
        "HIGH",
    ),
    (re.compile(r"Permission denied", re.IGNORECASE), "Permission denied", "HIGH"),
    (
        re.compile(r"patch rejected|anchor not found", re.IGNORECASE),
        "patch rejected",
        "HIGH",
    ),
    (re.compile(r"no changes made", re.IGNORECASE), "no changes made", "HIGH"),
    (re.compile(r"Traceback \(most recent call last\)"), "Traceback", "HIGH"),
    (re.compile(r"^error:", re.IGNORECASE | re.MULTILINE), "error:", "HIGH"),
    (re.compile(r"\bfailed\b", re.IGNORECASE), "failed", "HIGH"),
    (
        re.compile(r"already exists|unchanged", re.IGNORECASE),
        "already exists / unchanged",
        "MEDIUM",
    ),
    (
        re.compile(r"^warning:|deprecated", re.IGNORECASE | re.MULTILINE),
        "warning / deprecated",
        "LOW",
    ),
]


def scan_tool_output(output: str) -> list[ToolOutputWarning]:
    """Scan tool output text for known failure patterns.

    Returns a list of warnings sorted by severity (HIGH first).
    Empty output is itself a HIGH warning (silent failure).
    """
    if not output or not output.strip():
        logger.debug(
            "Tool output scanner: empty output detected (silent failure)",
            extra={"event": "tool.output_scan", "result": "empty_output"},
        )
        return [
            ToolOutputWarning(pattern="Empty output (silent failure)", severity="HIGH")
        ]

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
                "event": "tool.output_scan",
                "warning_count": len(warnings),
                "patterns": [w.pattern for w in warnings],
                "severities": [w.severity for w in warnings],
                "output_length": len(output),
            },
        )
    else:
        logger.debug(
            "Tool output scanner: clean (no warnings)",
            extra={
                "event": "tool.output_scan",
                "result": "clean",
                "output_length": len(output),
            },
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
                        "event": "goal.action_check",
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
            "event": "goal.action_check",
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

        # Website tool: no per-file size tracking, but site_files lists deployed files.
        # Record as a mutation so the loop controller knows files were written.
        if tool == "website" and size_before is None and size_after is None:
            site_files = outcome.get("site_files") or []
            site_id = outcome.get("site_id", "")
            if site_files or site_id:
                mutations.append(
                    {
                        "tool": tool,
                        "file_path": f"sites/{site_id}/" if site_id else None,
                        "size_before": None,
                        "size_after": None,
                        "lines_added": 0,
                        "lines_deleted": 0,
                        "no_op": False,
                        "site_files": site_files,
                    }
                )
                logger.debug(
                    "File mutation: website %s — %d files deployed",
                    site_id,
                    len(site_files),
                    extra={
                        "event": "file.mutation_website",
                        "site_id": site_id,
                        "file_count": len(site_files),
                    },
                )
            continue

        # Skip if we have no size data at all
        if size_before is None and size_after is None:
            logger.debug(
                "File mutation: skipping %s (no size data)",
                tool,
                extra={
                    "event": "file.mutation_skip",
                    "tool": tool,
                    "file_path_hash": log_hash(file_path),
                    "file_path_len": len(file_path) if file_path else 0,
                },
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
            tool,
            log_hash(file_path),
            size_before,
            size_after,
            lines_added,
            lines_deleted,
            " [NO-OP]" if no_op else "",
            extra={
                "event": "file.mutation_extracted",
                "tool": tool,
                "file_path_hash": log_hash(file_path),
                "file_path_len": len(file_path) if file_path else 0,
                "size_before": size_before,
                "size_after": size_after,
                "lines_added": lines_added,
                "lines_deleted": lines_deleted,
                "no_op": no_op,
                "diff_stats_raw": str(diff_stats_raw),
            },
        )
        mutations.append(
            {
                "path": file_path,
                "size_before": size_before,
                "size_after": size_after,
                "lines_added": lines_added,
                "lines_deleted": lines_deleted,
                "no_op": no_op,
            }
        )

    logger.debug(
        "File mutation extraction complete: %d mutation(s) from %d outcomes",
        len(mutations),
        len(step_outcomes),
        extra={
            "event": "file.mutations_complete",
            "mutation_count": len(mutations),
            "outcome_count": len(step_outcomes),
        },
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
            consecutive_no_mutation_replans,
            abort_threshold,
            extra={
                "event": "stagnation.check",
                "result": "abort",
                "replans": consecutive_no_mutation_replans,
            },
        )
        return "abort"
    logger.debug(
        "check_stagnation: consecutive_no_mutation_replans_gte_abort_threshold_passed",
        extra={
            "event": "stagnation.check.passed",
            "reason": "consecutive_no_mutation_replans_gte_abort_threshold_passed",
        },
    )  # auto:neg
    if consecutive_no_mutation_replans >= warn_threshold:
        logger.debug(
            "Stagnation check: WARN — %d consecutive no-mutation replans (threshold %d)",
            consecutive_no_mutation_replans,
            warn_threshold,
            extra={
                "event": "stagnation.check",
                "result": "warn",
                "replans": consecutive_no_mutation_replans,
            },
        )
        return "warn"
    logger.debug(
        "Stagnation check: OK — %d consecutive no-mutation replans",
        consecutive_no_mutation_replans,
        extra={
            "event": "stagnation.check",
            "result": "ok",
            "replans": consecutive_no_mutation_replans,
        },
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
    for _fp, descriptions in seen.items():
        if len(descriptions) >= 2:
            duplicates.append(f"{descriptions[0]} (x{len(descriptions)})")
    if duplicates:
        logger.debug(
            "Idempotent call detection: %d duplicate group(s) found",
            len(duplicates),
            extra={"event": "idempotent.detection", "duplicates": duplicates},
        )
    else:
        logger.debug(
            "Idempotent call detection: no duplicates",
            extra={"event": "idempotent.detection", "unique_fingerprints": len(seen)},
        )
    return duplicates
