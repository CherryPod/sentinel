"""D5: Plan-policy constraint validation.

Validates resolved shell commands and file paths against planner-generated
constraints. The planner (Claude, trusted) generates per-step argument
constraints; this module enforces them deterministically at TL4+.

Three-tier scanning model:
  1. Static denylist (_ALWAYS_BLOCKED) — constitutional, never overridden
  2. Plan-constraint validation — this module
  3. Fallback to legacy scanning — when constraints are None

Pure functions, no state, no side effects. Fully testable in isolation.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from dataclasses import dataclass

from sentinel.security.homoglyph import normalise_homoglyphs

# ── Static denylist (constitutional — never overridden) ───────────

# CommandPatternScanner pattern names that are ALWAYS blocked regardless
# of plan constraints. These represent operations that are never legitimate
# in autonomous operation. Even if the planner approves one (planner
# compromise), the denylist catches it.
_ALWAYS_BLOCKED: frozenset[str] = frozenset({
    "reverse_shell_tcp",
    "reverse_shell_bash",
    "netcat_shell",
    "scripting_reverse_shell",
    "mkfifo_shell",
    "pipe_to_shell",
    "base64_exec",
    "encoded_payload",
})

# Shell metacharacters that must never appear in constraint definitions.
# Prevents constraint injection via compromised planner.
_METACHAR_RE = re.compile(r"[|;&`$()]")

# Chaining operators for multi-command extraction.
# Includes bare pipe (|) — each segment must independently satisfy a constraint.
# Order matters: || must be tried before | to avoid partial matching.
_CHAIN_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||[|;])\s*")


# ── Result types ──────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class ConstraintResult:
    """Result of a constraint validation check."""
    allowed: bool = False
    skipped: bool = False       # True when constraints are None (legacy mode)
    reason: str = ""
    matched_constraint: str = ""


@dataclass(frozen=True, slots=True)
class DenylistMatch:
    """A match against the constitutional denylist."""
    pattern_name: str
    matched_text: str


# ── Path normalisation ────────────────────────────────────────────

def _normalise_path(path: str) -> str:
    """Normalise a path for secure matching."""
    cleaned = path.strip()
    cleaned = normalise_homoglyphs(cleaned)
    cleaned = cleaned.replace("\x00", "")
    cleaned = posixpath.normpath(cleaned)
    if path.rstrip().endswith("/") and not cleaned.endswith("/"):
        cleaned += "/"
    return cleaned


# ── Command parsing ───────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class _ParsedCommand:
    """A parsed shell command broken into components."""
    base: str
    flags: frozenset[str]
    target: str
    raw: str


def _parse_command(command: str) -> _ParsedCommand | None:
    """Parse a shell command into base, flags, and target."""
    normalised = normalise_homoglyphs(command.strip())
    normalised = normalised.replace("\x00", "")

    try:
        parts = shlex.split(normalised)
    except ValueError:
        return None

    if not parts:
        return None

    base = parts[0]
    flags: set[str] = set()
    targets: list[str] = []

    for part in parts[1:]:
        if part.startswith("-"):
            flags.add(part)
        else:
            targets.append(part)

    # Join all non-flag arguments as the target path.
    # Handles both quoted paths ('rm -rf "/workspace/my dir/"') and
    # unquoted constraint definitions ('rm -rf /workspace/my dir/*').
    target = " ".join(targets) if targets else ""

    return _ParsedCommand(
        base=base,
        flags=frozenset(flags),
        target=target,
        raw=normalised,
    )


def _expand_combined_flags(flags: frozenset[str]) -> frozenset[str]:
    """Expand combined short flags like -rf into individual flags -r, -f."""
    expanded: set[str] = set()
    for flag in flags:
        expanded.add(flag)
        if re.match(r"^-[a-zA-Z]{2,}$", flag):
            for ch in flag[1:]:
                expanded.add(f"-{ch}")
    return frozenset(expanded)


def _flags_subset(actual_flags: frozenset[str], allowed_flags: frozenset[str]) -> bool:
    """Check if actual flags are a subset of allowed flags."""
    actual_expanded = _expand_combined_flags(actual_flags)
    allowed_expanded = _expand_combined_flags(allowed_flags)
    return actual_expanded.issubset(allowed_expanded)


def _matches_single_constraint(
    parsed: _ParsedCommand, constraint: str
) -> bool:
    """Check if a parsed command matches a single constraint string."""
    constraint_parsed = _parse_command(constraint)
    if constraint_parsed is None:
        return False

    if parsed.base.lower() != constraint_parsed.base.lower():
        return False

    # Base-command-only constraint: no flags, no target = allow any usage
    # of this command.  The planner generates these when it trusts the base
    # command but can't predict the exact flags/targets (e.g. ["find", "wc"]).
    if not constraint_parsed.flags and not constraint_parsed.target:
        return True

    # Full-spec constraint: check flag subset and target matching.
    if not _flags_subset(parsed.flags, constraint_parsed.flags):
        return False

    actual_target = _normalise_path(parsed.target) if parsed.target else ""
    constraint_target = _normalise_path(constraint_parsed.target) if constraint_parsed.target else ""

    if not constraint_target and not actual_target:
        return True

    if not constraint_target or not actual_target:
        return constraint_target == "" and actual_target == ""

    return fnmatch.fnmatch(actual_target, constraint_target)


# ── Denylist check ────────────────────────────────────────────────

# Lazy-initialised module global. No lock required: asyncio is single-threaded
# and cooperative — there's no preemption between the None check and the
# assignment, so concurrent coroutines can't race on this.
_denylist_scanner = None


def check_denylist(command: str) -> DenylistMatch | None:
    """Check a command against the constitutional static denylist.

    Uses the CommandPatternScanner's regex patterns but only checks
    the _ALWAYS_BLOCKED subset. Returns the first matching pattern
    or None if no denylist match.
    """
    global _denylist_scanner
    if _denylist_scanner is None:
        from sentinel.security.scanner import CommandPatternScanner
        _denylist_scanner = CommandPatternScanner()

    scanner = _denylist_scanner
    normalised = normalise_homoglyphs(command.strip())

    for pattern_name, regex in scanner._patterns:
        if pattern_name not in _ALWAYS_BLOCKED:
            continue
        match = regex.search(normalised)
        if match:
            return DenylistMatch(
                pattern_name=pattern_name,
                matched_text=match.group(0),
            )
    return None


# ── Public API ────────────────────────────────────────────────────

def validate_command_constraints(
    resolved_command: str,
    allowed_commands: list[str] | None,
) -> ConstraintResult:
    """Validate a resolved shell command against plan-approved constraints."""
    if allowed_commands is None:
        return ConstraintResult(skipped=True, reason="no constraints (legacy mode)")

    command = resolved_command.strip()
    if not command:
        return ConstraintResult(reason="empty command")

    if not allowed_commands:
        return ConstraintResult(reason="empty constraint list blocks all commands")

    sub_commands = _CHAIN_SPLIT_RE.split(command)
    sub_commands = [c.strip() for c in sub_commands if c.strip()]

    if not sub_commands:
        return ConstraintResult(reason="no commands after splitting")

    for sub_cmd in sub_commands:
        parsed = _parse_command(sub_cmd)
        if parsed is None:
            return ConstraintResult(
                reason=f"cannot parse command: {sub_cmd[:80]}"
            )

        matched = False
        for constraint in allowed_commands:
            if _matches_single_constraint(parsed, constraint):
                matched = True
                break

        if not matched:
            return ConstraintResult(
                reason=f"command not in approved scope: {sub_cmd[:80]}"
            )

    first_parsed = _parse_command(sub_commands[0])
    first_match = ""
    if first_parsed:
        for constraint in allowed_commands:
            if _matches_single_constraint(first_parsed, constraint):
                first_match = constraint
                break

    return ConstraintResult(
        allowed=True,
        matched_constraint=first_match,
    )


def validate_path_constraints(
    resolved_path: str,
    allowed_paths: list[str] | None,
) -> ConstraintResult:
    """Validate a resolved file path against plan-approved path constraints."""
    if allowed_paths is None:
        return ConstraintResult(skipped=True, reason="no path constraints (legacy mode)")

    path = resolved_path.strip()
    if not path:
        return ConstraintResult(reason="empty path")

    if not allowed_paths:
        return ConstraintResult(reason="empty path constraint list blocks all paths")

    normalised_actual = _normalise_path(path)

    for constraint_path in allowed_paths:
        normalised_constraint = _normalise_path(constraint_path)
        if fnmatch.fnmatch(normalised_actual, normalised_constraint):
            return ConstraintResult(
                allowed=True,
                matched_constraint=constraint_path,
            )

    return ConstraintResult(
        reason=f"path not in approved scope: {normalised_actual}"
    )


def validate_constraint_definitions(
    allowed_commands: list[str] | None,
    allowed_paths: list[str] | None,
) -> list[str]:
    """Validate constraint definitions at plan validation time."""
    errors: list[str] = []

    if allowed_commands is not None:
        for cmd in allowed_commands:
            if _METACHAR_RE.search(cmd):
                errors.append(
                    f"allowed_commands contains shell metacharacter: {cmd[:80]}"
                )

    if allowed_paths is not None:
        for p in allowed_paths:
            if _METACHAR_RE.search(p):
                errors.append(
                    f"allowed_paths contains shell metacharacter: {p[:80]}"
                )
            normalised = _normalise_path(p)
            if not normalised.startswith("/workspace"):
                errors.append(
                    f"allowed_paths must be within /workspace/: {p}"
                )

    return errors
