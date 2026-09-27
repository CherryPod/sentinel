"""Error context builders — genericise errors, interrupted-task warnings, session file context.

Constructs the error-related context blocks that the planner needs to
understand what went wrong and what state files are in. All functions
are pure — no external state.
"""

from __future__ import annotations

import logging
import re

from sentinel.core.decorators import no_audit_log
from sentinel.memory.episodic import _redact_paths, _sanitise_for_planner

logger = logging.getLogger(__name__)


@no_audit_log
def genericise_error(error: str | None) -> str | None:
    """Map specific error messages to generic categories.

    The planner needs to know *that* something failed and the broad
    category (blocked, scan, constraint) so it can replan — but NOT
    the specific scanner name, blocked command, or file path. Exposing
    implementation details helps an adversary learn defence rules.
    """
    if not error:
        return None
    low = error.lower()
    # Shell / command blocks
    if "command not in allowed list" in low or "shell blocked" in low:
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "shell_command_blocked"},
        )
        return "shell command blocked"
    # File operation blocks — word-boundary check avoids matching
    # "empathy", "xpath", "psychopath" etc.
    if re.search(r"\bpath\b", low) and any(
        w in low for w in ("blocked", "denied", "not allowed", "forbidden")
    ):
        logger.debug(
            "Error genericised",
            extra={
                "event": "builders.genericise",
                "category": "file_operation_blocked",
            },
        )
        return "file operation blocked"
    # Scanner blocks — match actual scanner_name values, not bare
    # substrings like "encoding" or "credential" that appear in
    # legitimate text.
    #
    # 4 broad categories (NOT 7) — a bijection from scanner→category
    # would let an adversary enumerate the full pipeline by probing
    # each bucket. Collapsing injection, evasion, and command patterns
    # into one "dangerous pattern" bucket closes that side-channel.
    if "credential_scanner" in low:
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "credential_detected"},
        )
        return "credential/secret detected"
    if any(
        name in low
        for name in (
            "command_pattern_scanner",
            "prompt_guard",
            "encoding_normalization_scanner",
            "vulnerability_echo_scanner",
            "ascii_prompt_gate",
            "prompt_length_gate",
            "script_gate",
        )
    ):
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "dangerous_pattern"},
        )
        return "dangerous pattern detected"
    if "semgrep" in low:
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "code_vulnerability"},
        )
        return "code vulnerability detected"
    if "sensitive_path_scanner" in low:
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "sensitive_path"},
        )
        return "sensitive path reference"
    # Constraint / denylist violations — use "denylist" (specific) and
    # word-boundary "constraint" to avoid matching "unconstrained" etc.
    if "denylist" in low or re.search(r"\bconstraint\s+violat", low):
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "constraint_violation"},
        )
        return "constraint violation"
    # Execution errors — specific patterns only to avoid over-matching
    if (
        "tool execution failed" in low
        or "execution error" in low
        or "execution timeout" in low
    ):
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "execution_error"},
        )
        return "execution error"
    # Non-zero exit codes — debuggable command failure, not a security block
    if re.match(r"command exited with code \d+", low):
        logger.debug(
            "Error genericised",
            extra={"event": "builders.genericise", "category": "non_zero_exit"},
        )
        return "non-zero exit"
    # Fallback — still generic
    logger.debug(
        "Error genericised",
        extra={"event": "builders.genericise", "category": "operation_blocked"},
    )
    return "operation blocked"


def build_interrupted_task_warning(session) -> str:
    """Build a warning message about an interrupted previous task.

    Extracts context from the last turn's step_outcomes (F1 metadata).
    """
    logger.debug(
        "build_interrupted_task_warning called",
        extra={
            "event": "build.interrupted_task_warning",
            "turn_count": len(session.turns) if session.turns else 0,
        },
    )
    if not session.turns:
        logger.debug(
            "build_interrupted_task_warning skipped ��� no turns",
            extra={
                "event": "build.interrupted_task_warning_skip",
                "reason": "no_turns",
            },
        )
        return ""
    logger.debug(
        "build_interrupted_task_warning: not_turns_passed",
        extra={
            "event": "build.interrupted_task_warning_skip.passed",
            "reason": "not_turns_passed",
        },
    )  # auto:neg

    last_turn = session.turns[-1]
    # Q7-F3 (`_error_context.py:159`): scrub stored request_text replay.
    # Scrub-then-truncate so a marker spanning the 200-char boundary still
    # matches (same ordering as F2 at `_history_rendering.py:245`).
    warning_parts = [
        "[WARNING: Previous task was interrupted before completion.]",
        f'Last attempted: "{_sanitise_for_planner(last_turn.request_text)[:200]}"',
    ]

    # Extract completion status from step_outcomes
    step_outcomes = last_turn.step_outcomes or []
    total = len(step_outcomes)
    completed = sum(1 for so in step_outcomes if so.get("status") == "success")
    if total > 0:
        warning_parts.append(
            f"Last known status: {completed} of {total} steps completed"
        )

    # Extract file paths from step_outcomes.
    # Q7-F3 (`_error_context.py:172-176`): scrub + redact each path BEFORE
    # the join — adversarial filenames must be neutralised per-element so
    # the join boundary doesn't dilute the marker (e.g. ``", "`` between
    # two halves of a marker would defeat a post-join SP pass).
    file_paths = [so["file_path"] for so in step_outcomes if so.get("file_path")]
    if file_paths:
        warning_parts.append(
            "Files possibly in partial state: "
            + ", ".join(_redact_paths(_sanitise_for_planner(p)) for p in file_paths)
        )

    warning_parts.append("[Verify file state before proceeding.]")
    return "\n".join(warning_parts)


def build_session_files_context(turns) -> str:
    """Build SESSION FILES block from F1 step_outcomes across session turns.

    Shows per-file, per-turn metadata including what's working and what
    failed — enables the planner to do elimination-style debugging.
    """
    # Collect per-file timeline: {path -> [(turn_num, outcome_dict), ...]}
    logger.debug(
        "build_session_files_context called",
        extra={
            "event": "build.session_files_context",
            "turn_count": len(turns) if turns else 0,
        },
    )
    file_timeline: dict[str, list[tuple[int, dict]]] = {}
    for turn_idx, turn in enumerate(turns, 1):
        for outcome in turn.step_outcomes or []:
            path = outcome.get("file_path")
            if not path:
                continue
            if path not in file_timeline:
                file_timeline[path] = []
            file_timeline[path].append((turn_idx, outcome))

    if not file_timeline:
        logger.debug(
            "build_session_files_context skipped — no file_timeline",
            extra={
                "event": "build.session_files_context_skip",
                "reason": "no_file_timeline",
            },
        )
        return ""
    logger.debug(
        "build_session_files_context: not_file_timeline_passed",
        extra={
            "event": "build.session_files_context_skip.passed",
            "reason": "not_file_timeline_passed",
        },
    )  # auto:neg

    lines = ["SESSION FILES:"]
    for path, events in file_timeline.items():
        # Q7-F3 (`_error_context.py:225`): scrub + redact tool result file
        # path before emission as the SESSION FILES header line. Path is
        # the sink itself (not content), so SP+RP per design §4.3.
        lines.append(f"  {_redact_paths(_sanitise_for_planner(path))}")
        for turn_num, outcome in events:
            parts = []
            # Created vs modified
            is_first = events[0][0] == turn_num
            parts.append("created" if is_first else "modified")

            # Size
            size = outcome.get("file_size_after")
            if size is not None:
                parts.append(f"{size}B")

            # Language
            lang = outcome.get("output_language")
            if lang:
                parts.append(lang)

            # Syntax
            syn = outcome.get("syntax_valid")
            if syn is not None:
                parts.append("syntax valid" if syn else "SYNTAX ERROR")

            # Scanner
            scanner = outcome.get("scanner_result")
            if scanner:
                parts.append(f"scanner: {scanner}")

            # Diff
            diff = outcome.get("diff_stats")
            if diff:
                parts.append(f"diff: {diff}")

            # Symbols
            symbols = outcome.get("defined_symbols")
            if symbols:
                parts.append(f"symbols: {', '.join(symbols[:5])}")

            # Exit code
            exit_code = outcome.get("exit_code")
            if exit_code is not None:
                parts.append(f"exit={exit_code}")

            # Stderr
            # Q7-F3 (`_error_context.py:268-270`): scrub + redact stderr
            # before truncation. Scrub-then-truncate per F2 ordering rule
            # so a marker spanning the 80-char boundary still matches.
            stderr = outcome.get("stderr_preview")
            if stderr:
                parts.append(
                    f"stderr: {_redact_paths(_sanitise_for_planner(stderr))[:80]}"
                )

            lines.append(f"    turn {turn_num}: {' | '.join(parts)}")

    return "\n".join(lines)
