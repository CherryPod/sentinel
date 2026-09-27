"""Operator-readable shape categorisation and canonical-set hashing for log extras.

Leaf module — imports nothing from sentinel.planner.* so both planner and
security consumers can import without layering inversion.

Why this layer:
  sentinel/security/constraint_validator.py (D37 fold sites) must consume
  these helpers. Existing layering is planner → security (planner imports
  security validators). A planner-side module would force security → planner
  reverse-direction imports. _log_shape.py belongs at the security layer
  where both planner and security can import without reversal.

Used by:
  sentinel/planner/_command_shape.py  — shim, delegates _cmd_shape (D37-0)
  sentinel/tools/_handlers/_container.py — imports _cmd_shape via shim (D37-0)
  sentinel/planner/_tool_constraints.py — TL4 constraint telemetry (D37-A)
  sentinel/security/constraint_validator.py — matched_constraint cure (D37-B)
  sentinel/planner/tool_dispatch.py   — provenance.bypassed (D37-C)
  sentinel/planner/_plan_validator.py — auto.inferred_constraints (D37-C)
  sentinel/planner/_evaluator_fns.py  — eval_command_returns (D38)
"""
from __future__ import annotations

import re
from collections.abc import Callable

from sentinel.core.decorators import no_audit_log

# log_hash is imported lazily inside canonical_set_hash to avoid triggering
# sentinel.crypto.__init__ (which requires pythonjsonlogger) at module load
# time. This keeps _log_shape importable in lightweight test environments
# where only command_shape / path_shape / shape_counts are needed.

# Hardcoded set of executable basenames operators care to distinguish in
# rejected-cmd forensics. These are policy labels, not user data.
# Adding values here requires explicit security review.
_KNOWN_DENIED_BINARIES = frozenset({
    "python3", "python", "python2",
    "node", "deno",
    "bash", "sh", "zsh", "dash",
    "curl", "wget",
    "jq", "yq",
    "git", "ssh", "scp", "rsync",
})

_PATH_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f`$;|&<>]")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._+\-]{1,32}$")
_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:[\\/]")
# URI scheme per RFC 3986: anchored at start so embedded :// inside a path
# component (e.g. /workspace/file://name) is not misclassified as uri_like.
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+\-.]*://")


# @no_audit_log: redaction primitives used INSIDE log calls. An auto-injected
# entry log would emit one extra event per cured site, multiplying log volume
# and violating the no-I/O contract (§3 of the D37 design doc).
@no_audit_log
def command_shape(cmd: str | None, allowed_prefixes: tuple[str, ...] = ()) -> str:
    """Operator-readable shape category for a shell command.

    Returns one of:
    - "empty"                 — None / empty / whitespace-only
    - "allowed:<prefix>"      — full hardcoded allowlist match
    - "denied:<known_binary>" — first token in _KNOWN_DENIED_BINARIES
    - "denied:path_token"     — first token contains path separators (/ or \\)
    - "denied:safe_token"     — alphanumeric-shape, not in known set
    - "denied:unsafe_token"   — metachars/control/Unicode/length>32

    "denied:*" labels mean "outside the allowlist," not "rejected by this site."
    Callers add outcome via separate field (event_name + outcome flag).
    NO raw user data flows through.

    Prefix-match convention (IMP-06): if a prefix ends with '"' it is an
    exact-match entry — cmd must equal the prefix exactly (no trailing content).
    All other prefixes are path-taking (end with ' '): cmd must start with the
    prefix AND the suffix must be a single workspace path (no extra argv)
    classifying as ``workspace_rooted`` via path_shape.  ``len(suffix.split()) == 1``
    closes the extra-argv injection gap using Python's Unicode-aware split: all
    standard whitespace separators (ASCII space 0x20, tab, CR, LF, NBSP U+00A0,
    em-space U+2003, …) are treated uniformly.  Control characters (\\x00-\\x1f)
    are additionally caught by path_shape returning "unsafe_chars".
    """
    if not cmd or not cmd.strip():
        return "empty"
    for prefix in allowed_prefixes:
        if prefix.endswith('"'):
            if cmd == prefix:
                return f"allowed:{prefix.rstrip()}"
        elif cmd.startswith(prefix):
            suffix = cmd[len(prefix):]
            if len(suffix.split()) == 1 and path_shape(suffix) == "workspace_rooted":
                return f"allowed:{prefix.rstrip()}"
    # cmd is guaranteed non-empty here; split always yields ≥1 token.
    first = cmd.split(maxsplit=1)[0]
    if "/" in first or "\\" in first:
        return "denied:path_token"
    if first in _KNOWN_DENIED_BINARIES:
        return f"denied:{first}"
    if _SAFE_TOKEN_RE.match(first):
        return "denied:safe_token"
    return "denied:unsafe_token"


@no_audit_log
def path_shape(path: str | None) -> str:
    """Operator-readable shape category for a filesystem path.

    Returns one of (first-match wins, declaration order):
    - "empty"                  — None / empty / whitespace-only
    - "non_string"             — defensive: non-str input
    - "unsafe_chars"           — control chars, metachars, NUL
    - "uri_like"               — scheme:// prefix
    - "windows_drive_like"     — Windows drive-letter prefix (C:\\, D:/, …)
    - "mixed_separator"        — contains both / and \\ separators
    - "workspace_escape"       — /workspace/ prefix AND contains ..
    - "workspace_rooted"       — /workspace/ prefix, no parent traversal
    - "absolute_nonworkspace"  — starts with / but not /workspace/
    - "relative_parent"        — relative path with .. components
    - "relative"               — relative path without .. components

    NO basename, NO extension — those would be filename leak paths.
    Normalises both separators before traversal classification so that
    mixed-separator workspace_escape payloads (e.g. /workspace/..\\etc) are
    caught. Revised per adversarial-review F4 (Codex 2026-05-01).
    """
    if path is None:
        return "empty"
    if not isinstance(path, str):
        return "non_string"
    if not path or not path.strip():
        return "empty"
    if _PATH_UNSAFE_CHARS.search(path):
        return "unsafe_chars"
    if _URI_SCHEME_RE.match(path):
        return "uri_like"
    if _DRIVE_LETTER_RE.match(path):
        return "windows_drive_like"
    has_forward = "/" in path
    has_back = "\\" in path
    if has_forward and has_back:
        return "mixed_separator"
    # Normalise back-slashes for traversal classification (workspace_escape
    # must catch parent-traversal regardless of separator).
    parts = path.replace("\\", "/").split("/")
    has_parent = ".." in parts
    if path.startswith("/workspace/"):
        return "workspace_escape" if has_parent else "workspace_rooted"
    if path.startswith("/"):
        return "absolute_nonworkspace"
    return "relative_parent" if has_parent else "relative"


@no_audit_log
def canonical_set_hash(items: list[str] | tuple[str, ...] | None) -> str:
    """Collision-resistant keyed hash of a sorted-deduplicated list.

    Use for allowed_commands / allowed_paths redaction. Sort-and-dedupe
    canonicalises the list so the same policy emits the same hash regardless
    of source ordering. Empty / None → "empty".

    Encoding: each item is length-prefixed as "<len>:<item>", items joined
    with "|". Cannot collide via separator-injection because each item's
    delimiter is its own declared length. Adversarial NUL-based collisions
    are impossible under this encoding — see design doc §canonical_set_hash
    for threat-model rationale (revised per adversarial-review F5).
    """
    if not items:
        return "empty"
    canonical = sorted({str(item) for item in items})
    if not canonical:
        return "empty"
    joined = "|".join(f"{len(item)}:{item}" for item in canonical)
    from sentinel.crypto.blind_index import log_hash  # lazy — see module note
    return log_hash(joined)


@no_audit_log
def shape_counts(
    items: list[str] | tuple[str, ...] | None,
    shape_fn: Callable[[str], str],
) -> dict[str, int]:
    """Count of items in each shape category.

    Use for allowed_command_shape_counts / allowed_path_shape_counts extras.
    Pass functools.partial(command_shape, allowed_prefixes=...) to bind
    the allowlist when categorising command constraints.

    Returns dict mapping shape-category → count. Empty input → {}.
    """
    if not items:
        return {}
    counts: dict[str, int] = {}
    for item in items:
        shape = shape_fn(item)
        counts[shape] = counts.get(shape, 0) + 1
    return counts
