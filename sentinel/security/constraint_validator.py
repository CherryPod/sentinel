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
import logging
import posixpath
import re
import shlex
from dataclasses import dataclass

from sentinel.crypto.blind_index import log_hash
from sentinel.security._log_shape import command_shape, path_shape
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)

# ── Static denylist (constitutional — never overridden) ───────────

# CommandPatternScanner pattern names that are ALWAYS blocked regardless
# of plan constraints. These represent operations that are never legitimate
# in autonomous operation. Even if the planner approves one (planner
# compromise), the denylist catches it.
_ALWAYS_BLOCKED: frozenset[str] = frozenset(
    {
        "reverse_shell_tcp",
        "reverse_shell_bash",
        "netcat_shell",
        "scripting_reverse_shell",
        "mkfifo_shell",
        "pipe_to_shell",
        "base64_exec",
        "encoded_payload",
    }
)

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
    skipped: bool = False  # True when constraints are None (legacy mode)
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
    logger.debug(
        "_normalise_path called",
        extra={
            "event": "constraint_validator._normalise_path",
            "path_len": len(path) if isinstance(path, str) else 0,
            "path_hash": log_hash(path) if isinstance(path, str) else "nokey",
        },
    )  # auto:entry
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
    targets: tuple[str, ...]
    raw: str


def _parse_command(command: str) -> _ParsedCommand | None:
    """Parse a shell command into base, flags, and target."""
    normalised = normalise_homoglyphs(command.strip())
    normalised = normalised.replace("\x00", "")

    try:
        parts = shlex.split(normalised)
    except ValueError:
        logger.debug("constraint_validator.parse_command_error", exc_info=True)
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

    # Each non-flag argument is a separate target. Constraints with
    # spaces in paths must use shell quoting (D3 contract).

    return _ParsedCommand(
        base=base,
        flags=frozenset(flags),
        targets=tuple(targets),
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


def _matches_single_constraint(parsed: _ParsedCommand, constraint: str) -> bool:
    """Check if a parsed command matches a single constraint string."""
    logger.debug(
        "_matches_single_constraint called",
        extra={
            "event": "constraint_validator._matches_single_constraint",
            "parsed_type": type(parsed).__name__,
            "constraint_len": len(constraint) if isinstance(constraint, str) else 0,
            "constraint_hash": log_hash(constraint)
            if isinstance(constraint, str)
            else "nokey",
        },
    )  # auto:entry
    constraint_parsed = _parse_command(constraint)
    if constraint_parsed is None:
        return False

    if parsed.base.lower() != constraint_parsed.base.lower():
        return False

    # Base-command-only constraint: no flags, no targets = allow any usage
    # of this command.  The planner generates these when it trusts the base
    # command but can't predict the exact flags/targets (e.g. ["find", "wc"]).
    if not constraint_parsed.flags and not constraint_parsed.targets:
        return True

    # Full-spec constraint: check flag subset and per-target matching.
    if not _flags_subset(parsed.flags, constraint_parsed.flags):
        return False

    actual_targets = parsed.targets
    constraint_targets = constraint_parsed.targets

    if not constraint_targets:
        # Flags-only constraint (flags but no targets): match only when
        # actual also has no targets. Preserves fail-closed behavior.
        return not actual_targets

    if not actual_targets:
        return False

    if len(constraint_targets) == 1:
        # Single-pattern constraint: every actual target must match this one pattern.
        # Allows 'cp /workspace/*' to cover any number of in-scope targets.
        pattern = _normalise_path(constraint_targets[0])
        for actual_t in actual_targets:
            if not fnmatch.fnmatch(_normalise_path(actual_t), pattern):
                return False
    else:
        # Multi-pattern constraint: positional matching.
        # actual[i] must match constraint[i]; lengths must be equal.
        # Prevents a broader sibling pattern from authorizing a target
        # that only a narrower pattern should restrict (codex-F1 fix).
        if len(actual_targets) != len(constraint_targets):
            return False
        normalised_constraints = [_normalise_path(ct) for ct in constraint_targets]
        for actual_t, nc in zip(actual_targets, normalised_constraints):
            if not fnmatch.fnmatch(_normalise_path(actual_t), nc):
                return False
    return True


# ── Denylist check ────────────────────────────────────────────────

# YAML command rule ids are prefixed `cmd.` (e.g. `cmd.pipe_to_shell`);
# _ALWAYS_BLOCKED uses the short legacy names so stripped rule ids can
# match directly. Keeping the short names preserves the observable
# DenylistMatch.pattern_name in logs and audit trails.
_DENYLIST_ID_PREFIX = "cmd."


class DenylistLoadError(RuntimeError):
    """Raised when the constitutional denylist fails to load or validate.

    Fail-closed: if the loaded pattern set does not exactly cover
    _ALWAYS_BLOCKED, or if two rules strip to the same short name, the
    denylist is unsafe to use and the process must refuse to start.
    """


# Lazy-initialised module global. Safe for concurrent coroutines on the
# same event-loop thread only: the None check and assignment happen without
# preemption. If _load_denylist_patterns were ever called from a background
# thread (asyncio.to_thread) a duplicate load could occur — idempotent, but
# wasteful.
_denylist_patterns: dict[str, re.Pattern[str]] | None = None


def _load_denylist_patterns() -> dict[str, re.Pattern[str]]:
    """Load constitutional denylist patterns from rules/commands.yaml.

    Returns a mapping of short pattern name → compiled regex for the
    _ALWAYS_BLOCKED subset only.  Source of truth is the YAML rule file
    (command_pattern scanner) loaded via the shared rule loader.

    Fail-closed on:
      - any rule whose id lacks the `cmd.` prefix (would silently
        collide with a prefixed rule after stripping);
      - two rules stripping to the same short name (silent shadow);
      - loaded pattern set not exactly equal to _ALWAYS_BLOCKED (YAML
        lost a constitutional pattern, or added an unexpected one).
    """
    logger.debug(
        "_load_denylist_patterns called",
        extra={"event": "security.constraint_validator._load_denylist_patterns"},
    )  # auto:entry
    from pathlib import Path

    from sentinel.security._rule_loader import load_rules

    rules_dir = Path(__file__).parent / "rules"
    command_rules = load_rules(rules_dir).get("command_pattern", [])

    patterns: dict[str, re.Pattern[str]] = {}
    for rule in command_rules:
        if not rule.id.startswith(_DENYLIST_ID_PREFIX):
            msg = (
                f"Command rule id {rule.id!r} lacks required "
                f"{_DENYLIST_ID_PREFIX!r} prefix — denylist parity would break"
            )
            raise DenylistLoadError(msg)
        short_name = rule.id.removeprefix(_DENYLIST_ID_PREFIX)
        if short_name not in _ALWAYS_BLOCKED:
            continue
        if short_name in patterns:
            msg = f"Duplicate denylist pattern name {short_name!r} from id {rule.id!r}"
            raise DenylistLoadError(msg)
        patterns[short_name] = re.compile(rule.pattern)

    missing = _ALWAYS_BLOCKED - patterns.keys()
    if missing:
        msg = f"Denylist YAML missing constitutional patterns: {sorted(missing)}"
        raise DenylistLoadError(msg)

    return patterns


def check_denylist(command: str) -> DenylistMatch | None:
    """Check a command against the constitutional static denylist.

    Loads the _ALWAYS_BLOCKED regex subset from rules/commands.yaml
    (shared rule loader).  Returns the first matching pattern or None
    if no denylist match.
    """
    global _denylist_patterns
    if _denylist_patterns is None:
        _denylist_patterns = _load_denylist_patterns()

    normalised = normalise_homoglyphs(command.strip())

    for pattern_name, regex in _denylist_patterns.items():
        match = regex.search(normalised)
        if match:
            logger.warning(
                "Denylist match found",
                extra={
                    "event": "constraint_validator.denylist_match",
                    "pattern_name": pattern_name,
                },
            )
            return DenylistMatch(
                pattern_name=pattern_name,
                matched_text=match.group(0),
            )
    logger.debug(
        "Denylist check clean",
        extra={"event": "constraint_validator.denylist_clean"},
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
            logger.warning(
                "Command constraint validation parse failure",
                extra={
                    "event": "constraint_validator.command_parse_failure",
                    "sub_cmd_len": len(sub_cmd),
                    "sub_cmd_hash": log_hash(sub_cmd),
                },
            )
            # FL-C25-a3: fixed-template user-facing reason. Server-side log
            # above keeps sub_cmd_len + sub_cmd_hash for incident correlation.
            return ConstraintResult(reason="cannot parse command")

        matched = False
        for constraint in allowed_commands:
            if _matches_single_constraint(parsed, constraint):
                matched = True
                break

        if not matched:
            logger.warning(
                "Command constraint validation blocked",
                extra={
                    "event": "constraint_validator.command_blocked",
                    "sub_cmd_len": len(sub_cmd),
                    "sub_cmd_hash": log_hash(sub_cmd),
                },
            )
            # FL-C25-a3: fixed-template user-facing reason. Server-side log
            # above keeps sub_cmd_len + sub_cmd_hash for incident correlation.
            return ConstraintResult(reason="command not in approved scope")

    first_parsed = _parse_command(sub_commands[0])
    first_match = ""
    if first_parsed:
        for constraint in allowed_commands:
            if _matches_single_constraint(first_parsed, constraint):
                first_match = constraint
                break

    logger.info(
        "Command constraint validation passed",
        extra={
            "event": "constraint_validator.command_allowed",
            "matched_constraint_shape": command_shape(first_match),
            "matched_constraint_hash": log_hash(first_match),
            "matched_constraint_len": len(first_match) if first_match else 0,
        },
    )
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
        return ConstraintResult(
            skipped=True, reason="no path constraints (legacy mode)"
        )

    path = resolved_path.strip()
    if not path:
        return ConstraintResult(reason="empty path")

    if not allowed_paths:
        return ConstraintResult(reason="empty path constraint list blocks all paths")

    normalised_actual = _normalise_path(path)

    for constraint_path in allowed_paths:
        normalised_constraint = _normalise_path(constraint_path)
        if fnmatch.fnmatch(normalised_actual, normalised_constraint):
            logger.info(
                "Path constraint validation passed",
                extra={
                    "event": "constraint_validator.path_allowed",
                    "matched_constraint_shape": path_shape(constraint_path),
                    "matched_constraint_hash": log_hash(constraint_path),
                    "matched_constraint_len": len(constraint_path) if constraint_path else 0,
                },
            )
            return ConstraintResult(
                allowed=True,
                matched_constraint=constraint_path,
            )

    logger.warning(
        "Path constraint validation blocked",
        extra={
            "event": "constraint_validator.path_blocked",
            "path_len": len(normalised_actual),
            "path_hash": log_hash(normalised_actual),
        },
    )
    # FL-C25-a3: fixed-template user-facing reason. Server-side log above
    # keeps path_len + path_hash for incident correlation.
    return ConstraintResult(reason="path not in approved scope")


# FL-C72-a1 / D36: fixed-template error codes — no raw user/planner content.
# Server-side warnings inside validate_constraint_definitions carry
# hash/length extras for forensic correlation.
_E_ALLOWED_COMMANDS_METACHAR = "allowed_commands contains shell metacharacter"
_E_ALLOWED_PATHS_METACHAR = "allowed_paths contains shell metacharacter"
_E_ALLOWED_PATHS_OUTSIDE_WORKSPACE = "allowed_paths must be within /workspace/"

# Closed-world set of all error codes this function may return.
# Consumers (e.g. _raise_plan_validation first_error_code) must validate
# against this set to prevent future regressions from leaking dynamic strings.
CV_CONSTRAINT_ERROR_CODES: frozenset[str] = frozenset(
    {
        _E_ALLOWED_COMMANDS_METACHAR,
        _E_ALLOWED_PATHS_METACHAR,
        _E_ALLOWED_PATHS_OUTSIDE_WORKSPACE,
    }
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
                logger.warning(
                    "Constraint definition validation blocked",
                    extra={
                        "event": "constraint_validator.constraint_definition_blocked",
                        "kind": "allowed_commands_metachar",
                        "cmd_len": len(cmd),
                        "cmd_hash": log_hash(cmd),
                    },
                )
                errors.append(_E_ALLOWED_COMMANDS_METACHAR)

    if allowed_paths is not None:
        for p in allowed_paths:
            if _METACHAR_RE.search(p):
                logger.warning(
                    "Constraint definition validation blocked",
                    extra={
                        "event": "constraint_validator.constraint_definition_blocked",
                        "kind": "allowed_paths_metachar",
                        "path_len": len(p),
                        "path_hash": log_hash(p),
                    },
                )
                errors.append(_E_ALLOWED_PATHS_METACHAR)
            normalised = _normalise_path(p)
            if not normalised.startswith("/workspace"):
                logger.warning(
                    "Constraint definition validation blocked",
                    extra={
                        "event": "constraint_validator.constraint_definition_blocked",
                        "kind": "allowed_paths_outside_workspace",
                        "path_len": len(p),
                        "path_hash": log_hash(p),
                        "normalised_len": len(normalised),
                        "normalised_hash": log_hash(normalised),
                    },
                )
                errors.append(_E_ALLOWED_PATHS_OUTSIDE_WORKSPACE)

    return errors
