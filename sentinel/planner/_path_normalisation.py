"""Path normalisation for assertion evaluation.

Rewrites virtual /workspace/ paths to user-scoped workspace roots,
normalises command paths, and validates workspace containment.

Extracted from verification.py during planner modularisation (Phase 3).
"""

from __future__ import annotations

import logging
import os
import re

from sentinel.crypto.blind_index import log_hash

logger = logging.getLogger(__name__)


def normalise_assertion_path(path: str, workspace_root: str) -> str:
    """Rewrite virtual /workspace/ paths to the user's actual workspace root.

    The planner uses /workspace/ as a virtual root (matching executor's
    _rewrite_workspace_paths design). Assertion paths need the same
    translation so file checks hit the real per-user directory.
    """
    original_path = path
    if not path:
        logger.debug(
            "assertion_path_normalise: empty path — returning unchanged",
            extra={
                "event": "assertion.path_normalise",
                "original_hash": log_hash(original_path),
                "original_len": len(original_path) if original_path else 0,
                "result_hash": log_hash(path),
                "result_len": len(path) if path else 0,
                "action": "empty_passthrough",
                "workspace_root_hash": log_hash(workspace_root),
                "workspace_root_len": len(workspace_root) if workspace_root else 0,
            },
        )
        return path
    logger.debug(
        "_normalise_assertion_path: not_path_passed",
        extra={"event": "assertion.path_normalise.passed", "reason": "not_path_passed"},
    )  # auto:neg
    # Already under the user workspace? No rewrite needed.
    ws = workspace_root.rstrip("/") + "/"
    if path.startswith(ws):
        logger.debug(
            "assertion_path_normalise: already under workspace — no rewrite "
            "(path_hash=%s, workspace_hash=%s)",
            log_hash(path),
            log_hash(ws),
            extra={
                "event": "assertion.path_normalise",
                "original_hash": log_hash(original_path),
                "original_len": len(original_path) if original_path else 0,
                "result_hash": log_hash(path),
                "result_len": len(path) if path else 0,
                "action": "already_under_workspace",
                "workspace_root_hash": log_hash(workspace_root),
                "workspace_root_len": len(workspace_root) if workspace_root else 0,
            },
        )
        return path
    # Virtual /workspace/ prefix → rewrite to user workspace
    base = "/workspace/"
    if path.startswith(base):
        # Don't rewrite if already user-scoped (e.g. /workspace/2/sites/)
        remainder = path[len(base) :]
        if remainder and remainder.split("/", 1)[0].isdigit():
            logger.debug(
                "assertion_path_normalise: already user-scoped (numeric prefix) — "
                "no rewrite (path_hash=%s, remainder_len=%d)",
                log_hash(path),
                len(remainder) if remainder else 0,
                extra={
                    "event": "assertion.path_normalise",
                    "original_hash": log_hash(original_path),
                    "original_len": len(original_path) if original_path else 0,
                    "result_hash": log_hash(path),
                    "result_len": len(path) if path else 0,
                    "action": "already_user_scoped",
                    "workspace_root_hash": log_hash(workspace_root),
                    "workspace_root_len": len(workspace_root) if workspace_root else 0,
                    "remainder_hash": log_hash(remainder),
                    "remainder_len": len(remainder) if remainder else 0,
                },
            )
            return path
        rewritten = ws + remainder
        logger.debug(
            "assertion_path_normalise: rewriting virtual path — "
            "path_hash=%s → rewritten_hash=%s (workspace_hash=%s)",
            log_hash(path),
            log_hash(rewritten),
            log_hash(ws),
            extra={
                "event": "assertion.path_normalise",
                "original_hash": log_hash(original_path),
                "original_len": len(original_path) if original_path else 0,
                "result_hash": log_hash(rewritten),
                "result_len": len(rewritten) if rewritten else 0,
                "action": "rewrite_virtual",
                "workspace_root_hash": log_hash(workspace_root),
                "workspace_root_len": len(workspace_root) if workspace_root else 0,
                "remainder_hash": log_hash(remainder),
                "remainder_len": len(remainder) if remainder else 0,
            },
        )
        return rewritten
    logger.debug(
        "assertion_path_normalise: no /workspace/ prefix — returning unchanged "
        "(path_hash=%s, workspace_hash=%s)",
        log_hash(path),
        log_hash(ws),
        extra={
            "event": "assertion.path_normalise",
            "original_hash": log_hash(original_path),
            "original_len": len(original_path) if original_path else 0,
            "result_hash": log_hash(path),
            "result_len": len(path) if path else 0,
            "action": "no_prefix_passthrough",
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
        },
    )
    return path


def normalise_cmd_paths(cmd: str, workspace_root: str) -> str:
    """Rewrite /workspace/ paths inside shell commands to user workspace."""
    ws = workspace_root.rstrip("/") + "/"
    base = "/workspace/"
    # Don't rewrite if already user-scoped
    result = re.sub(
        rf"{re.escape(base)}(?!\d+/)",
        ws,
        cmd,
    )
    if result != cmd:
        logger.debug(
            "_normalise_cmd_paths: rewrote paths in command",
            extra={
                "event": "normalise.cmd_paths",
                "workspace_root_hash": log_hash(workspace_root),
                "workspace_root_len": len(workspace_root) if workspace_root else 0,
            },
        )
    return result


def check_path_in_workspace(path: str, workspace_root: str) -> str | None:
    """Return error message if path is outside workspace, else None."""
    try:
        resolved = os.path.realpath(path)
        ws_resolved = os.path.realpath(workspace_root)
        if resolved != ws_resolved and not resolved.startswith(ws_resolved + os.sep):
            return f"Path outside workspace: {path}"
    except (OSError, ValueError) as exc:
        # Explicit exc_info=False: OSError stringification embeds the raw path
        # (e.g. "[Errno 2] No such file or directory: '/workspace/2/sites/...'");
        # Python's traceback formatter renders that string in the exc_info dump,
        # leaking the path into operator logs even with redacted extras.
        # Explicit False also blocks audit_fix v6's automatic exc_info=True
        # re-injection per `scripts/audit_fix/fixers/exc_info.py:62`.
        logger.warning(
            "_check_path_in_workspace: OSError | ValueError",
            extra={
                "event": "path_normalisation.check_path_in_workspace_error",
                "path_hash": log_hash(path),
                "path_len": len(path) if path else 0,
                "workspace_root_hash": log_hash(workspace_root),
                "workspace_root_len": len(workspace_root) if workspace_root else 0,
                "error_category": type(exc).__name__,
            },
            exc_info=False,
        )
        # AssertionResult.message is user-facing; preserve the raw path here
        # per the C76 boundary (redact at log emission, not at construction).
        return f"Invalid path: {exc}"
    return None
