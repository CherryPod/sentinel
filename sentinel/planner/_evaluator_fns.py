"""Assertion evaluator functions — the actual checks.

Nine evaluators: file_exists, file_not_empty, file_contains,
file_not_contains, content_changed, response_contains, command_returns,
symbol_exists, symbol_count.

Adding a new assertion type: add a function here, then register it in
_evaluators.py EVALUATORS dict. This file grows; _evaluators.py stays small.

Extracted from _evaluators.py during Phase 3 cleanup.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass

from sentinel.crypto.blind_index import log_hash

# _command_shape is a leaf module (no sentinel.planner.* imports) so this
# package can import it without widening the existing
# _evaluator_fns ↔ _evaluators cycle. Re-exports _ALLOWED_COMMAND_PREFIXES
# and _cmd_in_allowlist (the allowlist gate) so this file's eval_command_returns
# uses the same logic and constant as the _cmd_shape log classifier.
from sentinel.planner._command_shape import (
    _ALLOWED_COMMAND_PREFIXES,
    _cmd_in_allowlist,
    _cmd_shape,
)
from sentinel.planner._evaluators import AssertionResult
from sentinel.planner._path_normalisation import check_path_in_workspace

logger = logging.getLogger(__name__)

# ── Digest Resolution ───────────────────────────────────────────

_EXT_TO_LANGUAGE: dict[str, str] = {
    ".html": "html",
    ".htm": "html",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".css": "css",
}


@dataclass(frozen=True, slots=True)
class DigestResult:
    """Resolved structural digest for a file path."""

    digest: dict | None
    error: str | None
    language: str | None
    basename: str


def _resolve_digest(
    assertion_path: str,
    step_outcomes: list[dict],
) -> DigestResult:
    """Find the structural digest for a file path from step outcomes.

    Returns a DigestResult with digest, error, language, and basename.
    If digest is None, error explains why. Language is detected from
    file extension. Both evaluators use all four fields.
    """
    basename = assertion_path.rsplit("/", 1)[-1]
    ext = os.path.splitext(basename)[1].lower()
    language = _EXT_TO_LANGUAGE.get(ext)

    outcome_paths = []

    # Full-path match first (last write wins — iterate in reverse)
    for outcome in reversed(step_outcomes):
        fpath = outcome.get("file_path")
        if fpath:
            outcome_paths.append(fpath)
        if fpath == assertion_path:
            digest = outcome.get("structural_digest")
            if digest:
                logger.debug(
                    "resolve_digest: full-path match for assertion_path_hash=%s",
                    log_hash(assertion_path),
                    extra={
                        "event": "evaluator.resolve_digest",
                        "strategy": "full_path",
                        "assertion_path_hash": log_hash(assertion_path),
                        "assertion_path_len": len(assertion_path)
                        if assertion_path
                        else 0,
                        "language": language,
                    },
                )
                return DigestResult(
                    digest=digest, error=None, language=language, basename=basename
                )
            logger.debug(
                "resolve_digest: full-path match but no digest for assertion_path_hash=%s",
                log_hash(assertion_path),
                extra={
                    "event": "evaluator.resolve_digest_no_digest",
                    "strategy": "full_path",
                    "assertion_path_hash": log_hash(assertion_path),
                    "assertion_path_len": len(assertion_path) if assertion_path else 0,
                },
            )
            # AssertionResult.error is user-facing; preserve raw assertion_path
            # per the C76 boundary (redact at log emission, not at construction).
            return DigestResult(
                digest=None,
                error=f"No structural digest available for {assertion_path}",
                language=language,
                basename=basename,
            )

    # Basename fallback — check both outcome file_path basenames and
    # structural_digests dict keys (website tool bundles by basename)
    for outcome in reversed(step_outcomes):
        fpath = outcome.get("file_path", "")
        outcome_basename = fpath.rsplit("/", 1)[-1] if fpath else ""

        # Direct basename match on outcome file_path
        if outcome_basename == basename:
            digest = outcome.get("structural_digest")
            if digest:
                logger.debug(
                    "resolve_digest: basename fallback match for "
                    "assertion_path_hash=%s via matched_path_hash=%s",
                    log_hash(assertion_path),
                    log_hash(fpath),
                    extra={
                        "event": "evaluator.resolve_digest",
                        "strategy": "basename_fallback",
                        "assertion_path_hash": log_hash(assertion_path),
                        "assertion_path_len": len(assertion_path)
                        if assertion_path
                        else 0,
                        "matched_path_hash": log_hash(fpath),
                        "matched_path_len": len(fpath) if fpath else 0,
                        "language": language,
                    },
                )
                return DigestResult(
                    digest=digest, error=None, language=language, basename=basename
                )

        # Check structural_digests dict (website tool bundle format)
        digests_dict = outcome.get("structural_digests", {})
        if basename in digests_dict:
            logger.debug(
                "resolve_digest: basename match in structural_digests dict "
                "for assertion_path_hash=%s",
                log_hash(assertion_path),
                extra={
                    "event": "evaluator.resolve_digest",
                    "strategy": "structural_digests_dict",
                    "assertion_path_hash": log_hash(assertion_path),
                    "assertion_path_len": len(assertion_path) if assertion_path else 0,
                    "language": language,
                },
            )
            return DigestResult(
                digest=digests_dict[basename],
                error=None,
                language=language,
                basename=basename,
            )

    # No match at all
    logger.debug(
        "resolve_digest: no match for assertion_path_hash=%s. "
        "Available outcome paths count=%d",
        log_hash(assertion_path),
        len(outcome_paths),
        extra={
            "event": "evaluator.resolve_digest_not_found",
            "assertion_path_hash": log_hash(assertion_path),
            "assertion_path_len": len(assertion_path) if assertion_path else 0,
            "available_path_hashes": [log_hash(p) for p in outcome_paths[:10]],
            "available_count": len(outcome_paths),
        },
    )
    # DigestResult.error is user-facing; preserve raw assertion_path + outcome_paths
    # per the C76 boundary (redact at log emission, not at construction).
    return DigestResult(
        digest=None,
        error=(
            f"No step outcome found for path '{assertion_path}'. "
            f"Available paths ({len(outcome_paths)}): "
            f"{outcome_paths[:10]}"
        ),
        language=language,
        basename=basename,
    )


# ── Sync Evaluators ──────────────────────────────────────────────


def eval_file_exists(
    assertion: dict, workspace_root: str, **_kwargs
) -> AssertionResult:
    logger.debug(
        "_eval_file_exists called",
        extra={
            "event": "verification._eval_file_exists",
            "assertion_len": len(assertion) if hasattr(assertion, "__len__") else 0,
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
        },
    )  # auto:entry
    path = assertion["path"]
    path_err = check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult(
            "file_exists", path, False, path_err, assertion.get("recovery")
        )
    exists = os.path.isfile(path)
    return AssertionResult(
        "file_exists",
        path,
        exists,
        "file exists" if exists else f"file not found: {path}",
        assertion.get("recovery"),
    )


def eval_file_not_empty(
    assertion: dict, workspace_root: str, **_kwargs
) -> AssertionResult:
    logger.debug(
        "_eval_file_not_empty called",
        extra={
            "event": "verification._eval_file_not_empty",
            "assertion_len": len(assertion) if hasattr(assertion, "__len__") else 0,
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
        },
    )  # auto:entry
    path = assertion["path"]
    path_err = check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult(
            "file_not_empty", path, False, path_err, assertion.get("recovery")
        )
    try:
        size = os.path.getsize(path)
        passed = size > 0
        msg = f"file size: {size} bytes" if passed else "file is empty"
    except OSError as exc:
        # Explicit exc_info=False: OSError stringification embeds the raw path
        # via the formatted-traceback dump, which would leak even with
        # redacted extras. Explicit False also blocks audit_fix v6's automatic
        # exc_info=True re-injection. Surface error_class via extras instead.
        logger.warning(
            "_eval_file_not_empty: OSError on path_hash=%s",
            log_hash(path),
            extra={
                "event": "verification._eval_file_not_empty_oserror",
                "path_hash": log_hash(path),
                "path_len": len(path) if path else 0,
                "error_class": type(exc).__name__,
                "error_str_len": len(str(exc)) if exc else 0,
            },
            exc_info=False,
        )  # auto:except
        passed = False
        # AssertionResult.message is user-facing; preserve raw exc per C76 boundary.
        msg = f"cannot read file: {exc}"
    return AssertionResult(
        "file_not_empty", path, passed, msg, assertion.get("recovery")
    )


def eval_file_contains(
    assertion: dict, workspace_root: str, **_kwargs
) -> AssertionResult:
    logger.debug(
        "_eval_file_contains called",
        extra={
            "event": "verification._eval_file_contains",
            "assertion_len": len(assertion) if hasattr(assertion, "__len__") else 0,
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
        },
    )  # auto:entry
    path = assertion["path"]
    pattern = assertion.get("pattern", "")
    path_err = check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult(
            "file_contains", path, False, path_err, assertion.get("recovery")
        )
    try:
        regex = re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        logger.exception(
            "_eval_file_contains: re.error",
            extra={"event": "verification._eval_file_contains_error"},
        )  # auto:except
        return AssertionResult(
            "file_contains",
            path,
            False,
            f"Invalid regex: {exc}",
            assertion.get("recovery"),
        )
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        # Explicit exc_info=False: OSError stringification embeds the raw path
        # via the formatted-traceback dump; same path-leak class as
        # _eval_file_not_empty's :243 cure. Surface error_class via extras.
        logger.warning(
            "_eval_file_contains: OSError on path_hash=%s",
            log_hash(path),
            extra={
                "event": "verification._eval_file_contains_oserror",
                "path_hash": log_hash(path),
                "path_len": len(path) if path else 0,
                "error_class": type(exc).__name__,
                "error_str_len": len(str(exc)) if exc else 0,
            },
            exc_info=False,
        )  # auto:except
        return AssertionResult(
            "file_contains",
            path,
            False,
            f"Cannot read file: {exc}",
            assertion.get("recovery"),
        )
    if regex.search(content):
        return AssertionResult(
            "file_contains",
            path,
            True,
            f"pattern found in {path}",
            assertion.get("recovery"),
        )
    return AssertionResult(
        "file_contains",
        path,
        False,
        f"pattern '{pattern}' not found in {path}",
        assertion.get("recovery"),
    )


def eval_file_not_contains(
    assertion: dict, workspace_root: str, **_kwargs
) -> AssertionResult:
    logger.debug(
        "_eval_file_not_contains called",
        extra={
            "event": "verification._eval_file_not_contains",
            "assertion_len": len(assertion) if hasattr(assertion, "__len__") else 0,
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
        },
    )  # auto:entry
    path = assertion["path"]
    pattern = assertion.get("pattern", "")
    path_err = check_path_in_workspace(path, workspace_root)
    if path_err:
        return AssertionResult(
            "file_not_contains", path, False, path_err, assertion.get("recovery")
        )
    try:
        regex = re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        logger.exception(
            "_eval_file_not_contains: re.error",
            extra={"event": "verification._eval_file_not_contains_error"},
        )  # auto:except
        return AssertionResult(
            "file_not_contains",
            path,
            False,
            f"Invalid regex: {exc}",
            assertion.get("recovery"),
        )
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        # Explicit exc_info=False: OSError stringification embeds the raw path
        # via the formatted-traceback dump; same path-leak class as
        # _eval_file_not_empty's :243 cure. Surface error_class via extras.
        logger.warning(
            "_eval_file_not_contains: OSError on path_hash=%s",
            log_hash(path),
            extra={
                "event": "verification._eval_file_not_contains_oserror",
                "path_hash": log_hash(path),
                "path_len": len(path) if path else 0,
                "error_class": type(exc).__name__,
                "error_str_len": len(str(exc)) if exc else 0,
            },
            exc_info=False,
        )  # auto:except
        return AssertionResult(
            "file_not_contains",
            path,
            False,
            f"Cannot read file: {exc}",
            assertion.get("recovery"),
        )
    if regex.search(content):
        return AssertionResult(
            "file_not_contains",
            path,
            False,
            f"unwanted pattern '{pattern}' found in {path}",
            assertion.get("recovery"),
        )
    return AssertionResult(
        "file_not_contains",
        path,
        True,
        f"pattern absent from {path}",
        assertion.get("recovery"),
    )


def eval_content_changed(
    assertion: dict,
    workspace_root: str,
    before_hashes: dict[str, str] | None = None,
    **_kwargs,
) -> AssertionResult:
    path = assertion["path"]
    before_hashes_key_hashes = (
        [log_hash(k) for k in before_hashes.keys()] if before_hashes else []
    )
    logger.debug(
        "content_changed: evaluating — path_hash=%s, workspace_root_hash=%s, "
        "before_hashes_is_none=%s, before_hashes_count=%d",
        log_hash(path),
        log_hash(workspace_root),
        before_hashes is None,
        len(before_hashes) if before_hashes else 0,
        extra={
            "event": "content.changed_eval_start",
            "path_hash": log_hash(path),
            "path_len": len(path) if path else 0,
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
            "before_hashes_is_none": before_hashes is None,
            "before_hashes_count": len(before_hashes) if before_hashes else 0,
            "before_hashes_key_hashes": before_hashes_key_hashes,
            "assertion_recovery": assertion.get("recovery"),
        },
    )
    path_err = check_path_in_workspace(path, workspace_root)
    if path_err:
        logger.debug(
            "content_changed: FAIL — path not in workspace "
            "(path_hash=%s, workspace_hash=%s, error_len=%d)",
            log_hash(path),
            log_hash(workspace_root),
            len(path_err) if path_err else 0,
            extra={
                "event": "content.changed_path_error",
                "path_hash": log_hash(path),
                "path_len": len(path) if path else 0,
                "workspace_root_hash": log_hash(workspace_root),
                "workspace_root_len": len(workspace_root) if workspace_root else 0,
                "error_len": len(path_err) if path_err else 0,
            },
        )
        return AssertionResult(
            "content_changed", path, False, path_err, assertion.get("recovery")
        )
    logger.debug(
        "_eval_content_changed: path_err_passed",
        extra={
            "event": "content.changed_path_error.passed",
            "reason": "path_err_passed",
        },
    )  # auto:neg
    if not before_hashes or path not in before_hashes:
        # Distinguish between "no hashes dict at all" vs "dict exists but
        # this path isn't in it" — these are very different failure modes.
        # Use a category code (no path leakage) for the log; structured
        # forensic info goes to extras.
        if before_hashes is None:
            reason_code = "before_hashes_is_none"
        elif len(before_hashes) == 0:
            reason_code = "before_hashes_empty"
        else:
            reason_code = "path_not_in_before_hashes"
        logger.debug(
            "content_changed: SKIP — no before-hash available (fail-open). "
            "reason_code=%s. "
            "Returning PASS to avoid false-positive retry loops.",
            reason_code,
            extra={
                "event": "content.changed_no_before_hash",
                "reason_code": reason_code,
                "path_hash": log_hash(path),
                "path_len": len(path) if path else 0,
                "before_hashes_is_none": before_hashes is None,
                "before_hashes_count": len(before_hashes) if before_hashes else 0,
                "before_hashes_key_hashes": (
                    [log_hash(k) for k in before_hashes.keys()] if before_hashes else []
                ),
                "file_exists_on_disk": os.path.exists(path),
            },
        )
        return AssertionResult(
            "content_changed",
            path,
            True,
            "no before-hash available — skipped (cannot verify)",
            assertion.get("recovery"),
        )
    try:
        with open(path, "rb") as fh:
            current = fh.read()
        current_hash = hashlib.sha256(current).hexdigest()
    except OSError as exc:
        # Drop raw exc from message-string positional: OSError stringification
        # embeds the raw path. Surface error_class via extras.
        logger.debug(
            "content_changed: FAIL — cannot read file path_hash=%s (error_class=%s)",
            log_hash(path),
            type(exc).__name__,
            extra={
                "event": "content.changed_read_error",
                "path_hash": log_hash(path),
                "path_len": len(path) if path else 0,
                "error_class": type(exc).__name__,
                "error_str_len": len(str(exc)) if exc else 0,
            },
        )
        return AssertionResult(
            "content_changed",
            path,
            False,
            f"Cannot read file: {exc}",
            assertion.get("recovery"),
        )
    changed = current_hash != before_hashes[path]
    msg = "content changed" if changed else "content unchanged (hash match)"
    logger.debug(
        "content_changed: %s — path_hash=%s, before_hash=%s, current_hash=%s",
        "PASS (content changed)" if changed else "FAIL (content unchanged)",
        log_hash(path),
        before_hashes[path][:16] + "...",
        current_hash[:16] + "...",
        extra={
            "event": "content.changed_hash_compare",
            "path_hash": log_hash(path),
            "path_len": len(path) if path else 0,
            "passed": changed,
            "before_hash": before_hashes[path],
            "current_hash": current_hash,
        },
    )
    return AssertionResult(
        "content_changed", path, changed, msg, assertion.get("recovery")
    )


def eval_response_contains(
    assertion: dict,
    step_outcomes: list[dict],
    **_kwargs,
) -> AssertionResult:
    logger.debug(
        "_eval_response_contains called",
        extra={
            "event": "verification._eval_response_contains",
            "assertion_len": len(assertion) if hasattr(assertion, "__len__") else 0,
            "step_outcomes_len": len(step_outcomes)
            if hasattr(step_outcomes, "__len__")
            else 0,
        },
    )  # auto:entry
    step_id = assertion.get("step_id", "")
    pattern = assertion.get("pattern", "")
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        logger.exception(
            "_eval_response_contains: re.error",
            extra={"event": "verification._eval_response_contains_error"},
        )  # auto:except
        return AssertionResult(
            "response_contains",
            None,
            False,
            f"Invalid regex: {exc}",
            assertion.get("recovery"),
        )
    for outcome in step_outcomes:
        if outcome.get("step_id") == step_id:
            preview = outcome.get("output_preview", "")
            if regex.search(preview):
                return AssertionResult(
                    "response_contains",
                    None,
                    True,
                    f"pattern found in {step_id} output",
                    assertion.get("recovery"),
                )
            return AssertionResult(
                "response_contains",
                None,
                False,
                f"pattern '{pattern}' not found in {step_id} output",
                assertion.get("recovery"),
            )
    return AssertionResult(
        "response_contains",
        None,
        False,
        f"step {step_id} not found in outcomes",
        assertion.get("recovery"),
    )


# ── Symbol Evaluators ───────────────────────────────────────────

# Mapping from (language, symbol_type) to the digest keys to search.
# symbol_exists checks all identity lists for the language; symbol_count
# uses the specific type key.
_SYMBOL_KEYS: dict[str, list[str]] = {
    "html": ["element_ids"],
    "python": ["functions_defined", "classes_defined"],
    "javascript": ["functions_defined"],
    "css": ["selectors"],
}


def eval_symbol_exists(
    assertion: dict,
    step_outcomes: list[dict] | None = None,
    **_kwargs,
) -> AssertionResult:
    """Check whether a named symbol exists in the structural digest."""
    path = assertion.get("path", "")
    symbol = assertion.get("symbol", "")

    result = _resolve_digest(path, step_outcomes or [])
    if result.error:
        # result.error contains raw path via DigestResult construction (user-facing
        # API); strip it from the log message + extras and use length-only.
        logger.debug(
            "symbol_exists: FAIL — digest error for path_hash=%s (error_len=%d)",
            log_hash(path),
            len(result.error) if result.error else 0,
            extra={
                "event": "evaluator.symbol_exists_digest_error",
                "assertion_path_hash": log_hash(path),
                "assertion_path_len": len(path) if path else 0,
                "symbol": symbol,
                "error_len": len(result.error) if result.error else 0,
            },
        )
        return AssertionResult(
            "symbol_exists", path, False, result.error, assertion.get("recovery")
        )
    logger.debug(
        "eval_symbol_exists: error_passed",
        extra={
            "event": "evaluator.symbol_exists_digest_error.passed",
            "reason": "error_passed",
        },
    )  # auto:neg

    if result.language is None:
        ext = os.path.splitext(result.basename)[1]
        logger.debug(
            "symbol_exists: FAIL — unsupported file type '%s' for path_hash=%s",
            ext,
            log_hash(path),
            extra={
                "event": "evaluator.symbol_exists_unsupported_type",
                "assertion_path_hash": log_hash(path),
                "assertion_path_len": len(path) if path else 0,
                "symbol": symbol,
                "extension": ext,
            },
        )
        return AssertionResult(
            "symbol_exists",
            path,
            False,
            f"Cannot check symbols for file type '{ext}'",
            assertion.get("recovery"),
        )

    # Collect all symbols from the relevant digest keys
    digest_keys = _SYMBOL_KEYS.get(result.language, [])
    all_symbols: list[str] = []
    for key in digest_keys:
        all_symbols.extend(result.digest.get(key, []))

    if symbol in all_symbols:
        logger.debug(
            "symbol_exists: PASS — '%s' found in %s (%s)",
            symbol,
            result.basename,
            result.language,
            extra={
                "event": "evaluator.symbol_exists_pass",
                "symbol": symbol,
                "basename": result.basename,
                "language": result.language,
                "assertion_path_hash": log_hash(path),
                "assertion_path_len": len(path) if path else 0,
            },
        )
        return AssertionResult(
            "symbol_exists",
            path,
            True,
            f"symbol '{symbol}' found in {result.basename}",
            assertion.get("recovery"),
        )

    logger.debug(
        "symbol_exists: FAIL — '%s' not found in %s (%s). Present symbols (%d): %s",
        symbol,
        result.basename,
        result.language,
        len(all_symbols),
        all_symbols[:20],
        extra={
            "event": "evaluator.symbol_exists_fail",
            "symbol": symbol,
            "basename": result.basename,
            "language": result.language,
            "assertion_path_hash": log_hash(path),
            "assertion_path_len": len(path) if path else 0,
            "present_symbols": all_symbols[:20],
            "present_count": len(all_symbols),
        },
    )
    return AssertionResult(
        "symbol_exists",
        path,
        False,
        (
            f"symbol '{symbol}' not found in {result.basename}. "
            f"Present symbols: {all_symbols[:20]} ({len(all_symbols)} total)"
        ),
        assertion.get("recovery"),
    )


_COUNT_OPS: dict[str, tuple[str, Callable[[int, int], bool]]] = {
    "eq": ("==", lambda a, e: a == e),
    "gte": (">=", lambda a, e: a >= e),
    "lte": ("<=", lambda a, e: a <= e),
}


def eval_symbol_count(
    assertion: dict,
    step_outcomes: list[dict] | None = None,
    **_kwargs,
) -> AssertionResult:
    """Check the count of structural elements in a digest."""
    path = assertion.get("path", "")
    class_name = assertion.get("class")
    type_name = assertion.get("type")
    expected = assertion.get("expected")
    op_name = assertion.get("op", "eq")

    # Validation
    if class_name and type_name:
        logger.debug(
            "eval_symbol_count: class_name",
            extra={
                "event": "evaluator_fns.eval_symbol_count.match",
                "reason": "class_name",
            },
        )  # auto:neg
        return AssertionResult(
            "symbol_count",
            path,
            False,
            "Cannot specify both 'class' and 'type' — use one or the other",
            assertion.get("recovery"),
        )
    logger.debug(
        "eval_symbol_count: class_name_passed",
        extra={
            "event": "planner.evaluator_fns.eval_symbol_count.passed",
            "reason": "class_name_passed",
        },
    )  # auto:neg
    if not class_name and not type_name:
        logger.debug(
            "eval_symbol_count: not_class_name",
            extra={
                "event": "evaluator_fns.eval_symbol_count.match",
                "reason": "not_class_name",
            },
        )  # auto:neg
        return AssertionResult(
            "symbol_count",
            path,
            False,
            "Must specify either 'class' or 'type'",
            assertion.get("recovery"),
        )
    logger.debug(
        "eval_symbol_count: not_class_name_passed",
        extra={
            "event": "planner.evaluator_fns.eval_symbol_count.passed",
            "reason": "not_class_name_passed",
        },
    )  # auto:neg
    if not isinstance(expected, int):
        return AssertionResult(
            "symbol_count",
            path,
            False,
            f"'expected' must be an integer, got {type(expected).__name__}",
            assertion.get("recovery"),
        )

    op_entry = _COUNT_OPS.get(op_name)
    if not op_entry:
        logger.debug(
            "eval_symbol_count: not_op_entry",
            extra={
                "event": "evaluator_fns.eval_symbol_count.match",
                "reason": "not_op_entry",
            },
        )  # auto:neg
        return AssertionResult(
            "symbol_count",
            path,
            False,
            f"Unknown operator '{op_name}'. Valid: eq, gte, lte",
            assertion.get("recovery"),
        )
    logger.debug(
        "eval_symbol_count: not_op_entry_passed",
        extra={
            "event": "planner.evaluator_fns.eval_symbol_count.passed",
            "reason": "not_op_entry_passed",
        },
    )  # auto:neg
    op_symbol, op_fn = op_entry

    result = _resolve_digest(path, step_outcomes or [])
    if result.error:
        # result.error contains raw path via DigestResult construction (user-facing
        # API); strip it from the log message + extras and use length-only.
        logger.debug(
            "symbol_count: FAIL — digest error for path_hash=%s (error_len=%d)",
            log_hash(path),
            len(result.error) if result.error else 0,
            extra={
                "event": "evaluator.symbol_count_digest_error",
                "assertion_path_hash": log_hash(path),
                "assertion_path_len": len(path) if path else 0,
                "error_len": len(result.error) if result.error else 0,
            },
        )
        return AssertionResult(
            "symbol_count", path, False, result.error, assertion.get("recovery")
        )

    # Resolve the actual count and the items list (for failure messages)
    actual: int = 0
    items: list[str] | None = None

    if class_name:
        # HTML class count from class_counts dict
        actual = result.digest.get("class_counts", {}).get(class_name, 0)
        thing = f"elements with class '{class_name}'"
    elif result.language == "html" and type_name == "element":
        items = result.digest.get("element_ids", [])
        actual = len(items)
        thing = "element IDs"
    elif result.language == "python" and type_name == "function":
        items = result.digest.get("functions_defined", [])
        actual = len(items)
        thing = "functions"
    elif result.language == "python" and type_name == "class":
        items = result.digest.get("classes_defined", [])
        actual = len(items)
        thing = "classes"
    elif result.language == "javascript" and type_name == "function":
        items = result.digest.get("functions_defined", [])
        actual = len(items)
        thing = "functions"
    elif result.language == "css" and type_name == "selector":
        items = result.digest.get("selectors", [])
        actual = len(items)
        thing = "selectors"
    else:
        lang_label = result.language or "unknown"
        logger.debug(
            "symbol_count: FAIL — unsupported type '%s' for language '%s' "
            "in path_hash=%s",
            type_name,
            lang_label,
            log_hash(path),
            extra={
                "event": "evaluator.symbol_count_unsupported",
                "type_name": type_name,
                "language": lang_label,
                "assertion_path_hash": log_hash(path),
                "assertion_path_len": len(path) if path else 0,
            },
        )
        return AssertionResult(
            "symbol_count",
            path,
            False,
            f"Unsupported type '{type_name}' for language '{lang_label}'",
            assertion.get("recovery"),
        )

    passed = op_fn(actual, expected)
    if passed:
        logger.debug(
            "symbol_count: PASS — %d %s %s %d in %s",
            actual,
            op_symbol,
            thing,
            expected,
            result.basename,
            extra={
                "event": "evaluator.symbol_count_pass",
                "actual": actual,
                "expected": expected,
                "op": op_name,
                "thing": thing,
                "basename": result.basename,
                "assertion_path_hash": log_hash(path),
                "assertion_path_len": len(path) if path else 0,
            },
        )
        return AssertionResult(
            "symbol_count",
            path,
            True,
            f"symbol_count: {actual} matches expected {op_symbol} {expected} in {result.basename}",
            assertion.get("recovery"),
        )

    # Build failure message — include items if available
    fail_msg = (
        f"symbol_count: expected {op_symbol} {expected} {thing} in "
        f"{result.basename}, found {actual}"
    )
    if items is not None:
        fail_msg += f". Present: {items[:10]}"

    logger.debug(
        "symbol_count: FAIL — expected %s %d %s in %s, found %d. Present: %s",
        op_symbol,
        expected,
        thing,
        result.basename,
        actual,
        (items[:10] if items is not None else "N/A (class count)"),
        extra={
            "event": "evaluator.symbol_count_fail",
            "actual": actual,
            "expected": expected,
            "op": op_name,
            "thing": thing,
            "basename": result.basename,
            "assertion_path_hash": log_hash(path),
            "assertion_path_len": len(path) if path else 0,
            "present_items": (items[:10] if items is not None else []),
        },
    )
    return AssertionResult(
        "symbol_count", path, False, fail_msg, assertion.get("recovery")
    )


# ── Async Evaluator ──────────────────────────────────────────────

_COMMAND_TIMEOUT = 10  # seconds

# _ALLOWED_COMMAND_PREFIXES and _cmd_in_allowlist live in
# sentinel.planner._command_shape (leaf module — broke the cross-module
# circular import surfaced by Codex peer-consult `019de56c`). Re-imported
# above so the allowlist gate and _cmd_shape log classifier share the same
# implementation (single source for the exact-match vs startswith convention).

# Shell metacharacters that could chain commands or inject subshells.
# Defence-in-depth: the sandbox has NetworkMode: none and CapDrop: ALL,
# but we reject these to prevent local filesystem abuse even within the
# container. Assertions come from the planner (trusted), but the planner
# consumes untrusted user input that could influence command generation.
_SHELL_METACHAR_RE = re.compile(r"[;|&`$\n\r]|\$\(|\)\s*\{|\|\||\&\&")


async def eval_command_returns(
    assertion: dict,
    workspace_root: str,
    sandbox=None,
    timeout: int = _COMMAND_TIMEOUT,
    **_kwargs,
) -> AssertionResult:
    """Run a validation command in the sandbox and check its exit code.

    Security model:
    1. Command must match _ALLOWED_COMMAND_PREFIXES (defence-in-depth)
    2. Execution via PodmanSandbox (NetworkMode: none, ReadonlyRootfs,
       CapDrop: ALL, runs as nobody)
    3. Timeout enforced (default 10s)
    """
    # Site 1 (entry log): treat assertion["cmd"] as adversarial pre-gate input.
    # Logged BEFORE empty/sandbox/metachar/allowlist gates fire — must redact.
    _cmd_value = assertion.get("cmd", "")
    logger.debug(
        "_eval_command_returns called",
        extra={
            "event": "eval.command_returns",
            "cmd_shape": _cmd_shape(_cmd_value),
            "cmd_hash": log_hash(_cmd_value),
            "cmd_len": len(_cmd_value),
        },
    )

    cmd = assertion.get("cmd", "")
    expected_exit = assertion.get("exit_code", 0)

    if not cmd:
        return AssertionResult(
            "command_returns",
            "",
            False,
            "No command specified",
            assertion.get("recovery"),
        )

    if sandbox is None:
        return AssertionResult(
            "command_returns",
            cmd,
            False,
            "Sandbox not available — command_returns requires sandbox execution",
            assertion.get("recovery"),
        )

    # Shell metacharacter check — reject before allowlist to prevent chaining
    if _SHELL_METACHAR_RE.search(cmd):
        # Site 2 (metachar reject): log-rendering-hostile content possible
        # (backtick / $ / control chars). Shape categories collapse to
        # known-safe labels so raw adversarial bytes never reach the log line.
        logger.warning(
            "command_returns: rejected command with shell metacharacters: shape=%s hash=%s",
            _cmd_shape(cmd),
            log_hash(cmd),
            extra={
                "event": "command.returns_metachar_rejected",
                "cmd_shape": _cmd_shape(cmd),
                "cmd_hash": log_hash(cmd),
                "cmd_len": len(cmd),
            },
        )
        return AssertionResult(
            "command_returns",
            cmd,
            False,
            f"Command contains disallowed control characters or shell metacharacters: '{cmd[:60]}'",
            assertion.get("recovery"),
        )
    logger.debug(
        "_eval_command_returns: search_cmd_passed",
        extra={
            "event": "command.returns_metachar_rejected.passed",
            "reason": "search_cmd_passed",
        },
    )  # auto:neg

    # Allowlist check — command must match a known validation prefix.
    # IMP-06: closed-quote prefixes (ending with '"') require exact match;
    # no trailing content is permitted after the -c one-liner closing quote.
    # Path-taking prefixes (ending with ' ') allow a trailing path argument.
    # Same convention as command_shape in sentinel.security._log_shape.
    if not _cmd_in_allowlist(cmd):
        # Site 3 (allowlist reject): clean-syntax but arbitrary non-allowlist
        # command. Same redaction shape as Site 2 — shape category preserves
        # operator-readable distinction (denied:curl vs denied:python3) without
        # leaking workspace paths or user-authored filenames.
        logger.warning(
            "command_returns: rejected command not in allowlist: shape=%s hash=%s",
            _cmd_shape(cmd),
            log_hash(cmd),
            extra={
                "event": "command.returns_rejected",
                "cmd_shape": _cmd_shape(cmd),
                "cmd_hash": log_hash(cmd),
                "cmd_len": len(cmd),
            },
        )
        return AssertionResult(
            "command_returns",
            cmd,
            False,
            f"Command not in allowlist: '{cmd[:60]}'. Only validation "
            f"commands are permitted (python3 -m py_compile, node --check, etc.)",
            assertion.get("recovery"),
        )

    try:
        sandbox_result = await sandbox.run(cmd, timeout=timeout)

        if sandbox_result.timed_out:
            return AssertionResult(
                "command_returns",
                cmd,
                False,
                f"Command timed out after {timeout}s",
                assertion.get("recovery"),
            )

        if sandbox_result.exit_code == expected_exit:
            return AssertionResult(
                "command_returns",
                cmd,
                True,
                f"Command exited with expected code {expected_exit}",
                assertion.get("recovery"),
            )
        stderr_preview = (sandbox_result.stderr or "")[:200]
        return AssertionResult(
            "command_returns",
            cmd,
            False,
            f"Command exited with code {sandbox_result.exit_code} "
            f"(expected {expected_exit}). stderr: {stderr_preview}",
            assertion.get("recovery"),
        )
    except Exception as exc:  # catch-all: sandbox execution isolation
        # Site 4 (sandbox failure): three deliberate changes vs pre-cure:
        #  (a) drop %s exc positional — exception repr embeds wrapped subprocess
        #      argv (e.g. PodmanError "Command 'python3 -m py_compile
        #      /workspace/2/...' failed") which would re-leak the path.
        #  (b) explicit exc_info=False — REQUIRED to block audit_fix v6
        #      re-injection of exc_info=True at the next merge gate (see
        #      scripts/audit_fix/fixers/exc_info.py auto-fix logic). Mirrors
        #      C76's OSError sites at _evaluator_fns.py:243/305/370.
        #  (c) replace exc forensic info with error_class + error_str_len +
        #      error_hash — parity with C76's OSError treatment at
        #      _evaluation.py:154-170. error_hash preserves clustering.
        logger.warning(
            "command_returns: sandbox execution failed: shape=%s hash=%s error_category=sandbox_execution",
            _cmd_shape(cmd),
            log_hash(cmd),
            extra={
                "event": "command.returns_error",
                "cmd_shape": _cmd_shape(cmd),
                "cmd_hash": log_hash(cmd),
                "cmd_len": len(cmd),
                "error_category": "sandbox_execution",
                "error_class": type(exc).__name__,
                "error_str_len": len(str(exc)) if exc else 0,
                "error_hash": log_hash(str(exc)) if exc else "",
            },
            exc_info=False,
        )
        return AssertionResult(
            "command_returns",
            cmd,
            False,
            f"Sandbox execution failed: {exc}",
            assertion.get("recovery"),
        )
