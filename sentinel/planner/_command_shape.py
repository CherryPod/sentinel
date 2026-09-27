"""Backwards-compat shim — D37-0.

D37-0 promotes command_shape / path_shape / canonical_set_hash / shape_counts
to sentinel.security._log_shape (leaf module importable by both planner and
security layers without layering inversion).

This file retains:
- _ALLOWED_COMMAND_PREFIXES — policy constant; imported by _evaluator_fns.py
  and _container.py; stays here as the planner-layer source of truth.
- _cmd_shape — thin wrapper around command_shape(cmd, _ALLOWED_COMMAND_PREFIXES);
  existing callers (_evaluator_fns.py, _plan_validator.py, _container.py,
  tests/planner/test_cmd_shape.py) continue to work unchanged.
- _cmd_in_allowlist — boolean gate delegating to _cmd_shape; used by
  eval_command_returns as the allowlist security check. Lives here (not in
  _evaluator_fns.py) so tests can import it without pulling the heavy
  audit/crypto import chain.
- _KNOWN_DENIED_BINARIES — re-exported from _log_shape for back-compat with
  tests/planner/test_cmd_shape.py which imports it directly from this module.

Callers migrate to sentinel.security._log_shape directly in D37-A/B/C.
"""
from __future__ import annotations

from sentinel.core.decorators import no_audit_log
from sentinel.security._log_shape import (
    _KNOWN_DENIED_BINARIES,  # noqa: F401 — re-exported for back-compat
    command_shape,
)

# Hardcoded allowlist of commands that command_returns / eval_command_returns
# can execute. Defence-in-depth measure (network-isolated sandbox enforces
# containment at the container level; allowlist guards against planner
# influence). Callers pass this as command_shape(cmd, _ALLOWED_COMMAND_PREFIXES).
#
# Two prefix kinds (convention enforced by command_shape and _cmd_in_allowlist):
#   Ends with '"'  — exact-match: cmd must equal the prefix exactly (no trailing
#                    content). Used for -c one-liners that must not carry extra
#                    Python statements (IMP-06 fix).
#   Ends with ' '  — path-taking: cmd must startswith the prefix; a trailing
#                    workspace path argument is allowed.
_ALLOWED_COMMAND_PREFIXES = (
    "python3 -m py_compile ",    # Python syntax check        (path-taking)
    'python3 -c "import json"',  # JSON validation            (exact-match)
    'python3 -c "import csv"',   # CSV validation             (exact-match)
    'python3 -c "import ast"',   # Python AST validation      (exact-match)
    'python3 -c "import xml"',   # XML validation             (exact-match)
    'python3 -c "import html"',  # HTML validation            (exact-match)
    "node --check ",             # JS syntax check            (path-taking)
    "jq . ",                     # JSON validation via jq     (path-taking)
    "python3 -m json.tool ",     # JSON pretty-print/validate (path-taking)
)


# @no_audit_log: redaction primitive used INSIDE log calls; see _log_shape.py.
@no_audit_log
def _cmd_shape(cmd: str | None) -> str:
    """Operator-readable shape token — thin shim over command_shape.

    D37-0: delegates to command_shape(cmd, _ALLOWED_COMMAND_PREFIXES) from
    sentinel.security._log_shape. Behaviour is identical to the pre-D37-0
    implementation; existing callers require no changes.
    """
    return command_shape(cmd, _ALLOWED_COMMAND_PREFIXES)


def _cmd_in_allowlist(cmd: str) -> bool:
    """Return True iff cmd is classified as allowed by the prefix allowlist.

    Delegates to _cmd_shape so the allowlist gate and the log-shape classifier
    always agree — single source for the exact-match vs startswith convention.
    IMP-06: closed-quote prefixes require exact match; path-taking prefixes
    allow a trailing workspace path argument.
    """
    return _cmd_shape(cmd).startswith("allowed:")
