"""Assertion evaluation orchestration — sync and async paths.

Coordinates running evaluators from _evaluators.py against assertions,
handling path normalisation and async evaluator dispatch.

Extracted from verification.py during planner modularisation (Phase 3).
"""

from __future__ import annotations

import logging

from sentinel.crypto.blind_index import log_hash
from sentinel.planner._evaluators import (
    EVALUATORS,
    AssertionResult,
    is_async_evaluator,
)
from sentinel.planner._path_normalisation import (
    normalise_assertion_path,
    normalise_cmd_paths,
)

logger = logging.getLogger(__name__)


async def _evaluate_single_async(
    assertion: dict,
    idx: int,
    total: int,
    workspace_root: str,
    step_outcomes: list[dict],
    before_hashes: dict[str, str] | None,
    sandbox,
) -> AssertionResult:
    """Evaluate a single assertion — normalise paths, dispatch, log result.

    Handles both sync and async evaluators. Called from
    evaluate_assertions_async for each assertion in the list.
    """
    # Normalise virtual /workspace/ paths to the user's real workspace root
    assertion = dict(assertion)  # shallow copy to avoid mutating input
    original_path = assertion.get("path")
    if assertion.get("path"):
        logger.debug(
            "_evaluate_single_async: get_path",
            extra={
                "event": "_evaluation._evaluate_single_async.match",
                "reason": "get_path",
            },
        )  # auto:neg
        assertion["path"] = normalise_assertion_path(assertion["path"], workspace_root)
    if assertion.get("cmd"):
        logger.debug(
            "_evaluate_single_async: get_cmd",
            extra={
                "event": "_evaluation._evaluate_single_async.match",
                "reason": "get_cmd",
            },
        )  # auto:neg
        assertion["cmd"] = normalise_cmd_paths(assertion["cmd"], workspace_root)

    atype = assertion.get("assert", "unknown")
    normalised_path = assertion.get("path")

    logger.debug(
        "Evaluating assertion %d/%d: type=%s, "
        "original_path_hash=%s, normalised_path_hash=%s, "
        "recovery=%s",
        idx + 1,
        total,
        atype,
        log_hash(original_path),
        log_hash(normalised_path),
        assertion.get("recovery", "none")[:100],
        extra={
            "event": "assertion.eval_item_start",
            "index": idx,
            "assertion_type": atype,
            "original_path_hash": log_hash(original_path),
            "original_path_len": len(original_path) if original_path else 0,
            "normalised_path_hash": log_hash(normalised_path),
            "normalised_path_len": len(normalised_path) if normalised_path else 0,
            "path_changed": original_path != normalised_path,
            "has_recovery": assertion.get("recovery") is not None,
        },
    )

    evaluator = EVALUATORS.get(atype)
    if evaluator is None:
        logger.debug(
            "Assertion %d/%d: unknown type '%s' — marking FAIL",
            idx + 1,
            total,
            atype,
            extra={
                "event": "assertion.eval_unknown_type",
                "assertion_type": atype,
            },
        )
        return AssertionResult(
            atype,
            assertion.get("path"),
            False,
            f"Unknown assertion type: {atype}",
            assertion.get("recovery"),
        )
    try:
        if is_async_evaluator(evaluator):
            logger.debug(
                "_evaluate_single_async: is_async_evaluator_evaluator",
                extra={
                    "event": "_evaluation._evaluate_single_async.match",
                    "reason": "is_async_evaluator_evaluator",
                },
            )  # auto:neg
            result = await evaluator(
                assertion,
                workspace_root=workspace_root,
                step_outcomes=step_outcomes,
                before_hashes=before_hashes,
                sandbox=sandbox,
            )
        else:
            logger.debug(
                "_evaluate_single_async: is_async_evaluator_evaluator",
                extra={
                    "event": "_evaluation._evaluate_single_async.clean",
                    "reason": "is_async_evaluator_evaluator",
                },
            )  # auto:neg
            result = evaluator(
                assertion,
                workspace_root=workspace_root,
                step_outcomes=step_outcomes,
                before_hashes=before_hashes,
            )
        _path_value = assertion.get("path")
        logger.debug(
            "Assertion %d/%d %s on path_hash=%s: %s",
            idx + 1,
            total,
            atype,
            log_hash(_path_value) or "N/A",
            "PASS" if result.passed else "FAIL",
            extra={
                "event": "assertion.eval_result",
                "index": idx,
                "type": atype,
                "passed": result.passed,
                "path_hash": log_hash(_path_value),
                "path_len": len(_path_value) if _path_value else 0,
                "result_message_len": len(result.message) if result.message else 0,
            },
        )
        return result
    except Exception as exc:  # catch-all: assertion evaluator isolation
        # Explicit exc_info=False: OSError / FileNotFoundError stringification
        # can embed the raw path; the traceback formatter would leak it even
        # with redacted extras. Explicit False also blocks audit_fix v6's
        # automatic exc_info=True re-injection. error_class + error_str_len
        # carry the forensic signal without the leak.
        _path_value = assertion.get("path")
        logger.warning(
            "Assertion %d/%d evaluator crashed: type=%s, path_hash=%s, error_category=%s",
            idx + 1,
            total,
            atype,
            log_hash(_path_value),
            type(exc).__name__,
            extra={
                "event": "assertion.eval_error",
                "index": idx,
                "type": atype,
                "path_hash": log_hash(_path_value),
                "path_len": len(_path_value) if _path_value else 0,
                "error_class": type(exc).__name__,
                "error_str_len": len(str(exc)) if exc else 0,
                "error_category": "evaluator_crash",
            },
            exc_info=False,
        )
        return AssertionResult(
            atype,
            assertion.get("path"),
            False,
            f"Evaluator error: {exc}",
            assertion.get("recovery"),
        )


def evaluate_assertions(
    assertions: list[dict],
    step_outcomes: list[dict],
    workspace_root: str,
    before_hashes: dict[str, str] | None = None,
    sandbox=None,
) -> list[AssertionResult]:
    """Evaluate a list of assertions against the current state (sync).

    Handles all sync evaluators. For command_returns (async), use
    evaluate_assertions_async() which awaits the sandbox call.
    When called with command_returns assertions and no running event loop,
    command_returns evaluations are skipped with an error result.

    Design principle (asymmetric trust):
    - A FAILING assertion is conclusive evidence of a problem
    - A PASSING assertion is one positive signal, not conclusive proof of success
    """
    logger.debug(
        "Assertion evaluation: %d assertion(s) to evaluate",
        len(assertions),
        extra={
            "event": "assertion.eval_start",
            "count": len(assertions),
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
        },
    )
    results: list[AssertionResult] = []
    for assertion in assertions:
        # Normalise virtual /workspace/ paths to the user's real workspace root
        assertion = dict(assertion)  # shallow copy to avoid mutating input
        if assertion.get("path"):
            assertion["path"] = normalise_assertion_path(
                assertion["path"], workspace_root
            )
        if assertion.get("cmd"):
            assertion["cmd"] = normalise_cmd_paths(assertion["cmd"], workspace_root)

        atype = assertion.get("assert", "unknown")
        evaluator = EVALUATORS.get(atype)
        if evaluator is None:
            results.append(
                AssertionResult(
                    atype,
                    assertion.get("path"),
                    False,
                    f"Unknown assertion type: {atype}",
                    assertion.get("recovery"),
                )
            )
            continue
        try:
            if is_async_evaluator(evaluator):
                # Async evaluator (command_returns) — skip in sync path
                results.append(
                    AssertionResult(
                        atype,
                        assertion.get("path"),
                        False,
                        f"Async evaluator '{atype}' requires evaluate_assertions_async()",
                        assertion.get("recovery"),
                    )
                )
                continue
            result = evaluator(
                assertion,
                workspace_root=workspace_root,
                step_outcomes=step_outcomes,
                before_hashes=before_hashes,
            )
            _path_value = assertion.get("path")
            logger.debug(
                "Assertion %s on path_hash=%s: %s",
                atype,
                log_hash(_path_value) or "N/A",
                "PASS" if result.passed else "FAIL",
                extra={
                    "event": "assertion.eval_result",
                    "type": atype,
                    "passed": result.passed,
                    "path_hash": log_hash(_path_value),
                    "path_len": len(_path_value) if _path_value else 0,
                    "result_message_len": len(result.message) if result.message else 0,
                },
            )
            results.append(result)
        except Exception as exc:  # catch-all: assertion evaluator isolation
            # Explicit exc_info=False: see _evaluate_single_async equivalent
            # above for path-leak rationale + audit_fix re-injection block.
            _path_value = assertion.get("path")
            logger.warning(
                "Assertion evaluator crashed: type=%s, path_hash=%s, error_class=%s",
                atype,
                log_hash(_path_value),
                type(exc).__name__,
                extra={
                    "event": "assertion.eval_error",
                    "type": atype,
                    "path_hash": log_hash(_path_value),
                    "path_len": len(_path_value) if _path_value else 0,
                    "error_class": type(exc).__name__,
                    "error_str_len": len(str(exc)) if exc else 0,
                    "error_category": "evaluator_crash",
                },
                exc_info=False,
            )
            results.append(
                AssertionResult(
                    atype,
                    assertion.get("path"),
                    False,
                    f"Evaluator error: {exc}",
                    assertion.get("recovery"),
                )
            )
    passed = sum(1 for r in results if r.passed)
    logger.debug(
        "Assertion evaluation complete: %d/%d passed",
        passed,
        len(results),
        extra={
            "event": "assertion.eval_complete",
            "passed": passed,
            "total": len(results),
        },
    )
    return results


async def evaluate_assertions_async(
    assertions: list[dict],
    step_outcomes: list[dict],
    workspace_root: str,
    before_hashes: dict[str, str] | None = None,
    sandbox=None,
) -> list[AssertionResult]:
    """Evaluate assertions including async evaluators (command_returns).

    Use this from async contexts (orchestrator) when command_returns
    assertions may be present.
    """
    assertion_types = [a.get("assert", "unknown") for a in assertions]
    assertion_paths = [a.get("path", "N/A") for a in assertions]
    assertion_path_hashes = [log_hash(p) for p in assertion_paths]
    before_hashes_key_hashes = (
        [log_hash(k) for k in before_hashes.keys()] if before_hashes else []
    )
    logger.debug(
        "Async assertion evaluation: %d assertion(s) to evaluate — "
        "types=%s, paths_count=%d, workspace_root_hash=%s, "
        "before_hashes_passed=%s, before_hashes_len=%d, "
        "sandbox_available=%s, step_outcomes_count=%d",
        len(assertions),
        assertion_types,
        len(assertion_paths),
        log_hash(workspace_root),
        before_hashes is not None,
        len(before_hashes) if before_hashes else 0,
        sandbox is not None,
        len(step_outcomes) if step_outcomes else 0,
        extra={
            "event": "assertion.eval_async_start",
            "count": len(assertions),
            "assertion_types": assertion_types,
            "assertion_path_hashes": assertion_path_hashes,
            "assertion_paths_count": len(assertion_paths),
            "workspace_root_hash": log_hash(workspace_root),
            "workspace_root_len": len(workspace_root) if workspace_root else 0,
            "before_hashes_passed": before_hashes is not None,
            "before_hashes_len": len(before_hashes) if before_hashes else 0,
            "before_hashes_key_hashes": before_hashes_key_hashes,
            "before_hashes_count": len(before_hashes) if before_hashes else 0,
            "sandbox_available": sandbox is not None,
            "step_outcomes_count": len(step_outcomes) if step_outcomes else 0,
        },
    )
    results: list[AssertionResult] = []
    total = len(assertions)
    for idx, assertion in enumerate(assertions):
        result = await _evaluate_single_async(
            assertion,
            idx,
            total,
            workspace_root=workspace_root,
            step_outcomes=step_outcomes,
            before_hashes=before_hashes,
            sandbox=sandbox,
        )
        results.append(result)

    passed = sum(1 for r in results if r.passed)
    failed = [r for r in results if not r.passed]
    logger.debug(
        "Async assertion evaluation complete: %d/%d passed, %d failed — "
        "failed_types=%s, failed_count=%d",
        passed,
        len(results),
        len(failed),
        [r.assertion_type for r in failed],
        len(failed),
        extra={
            "event": "assertion.eval_async_complete",
            "passed": passed,
            "total": len(results),
            "failed": len(failed),
            "failed_details": [
                {
                    "type": r.assertion_type,
                    "path_hash": log_hash(r.path),
                    "path_len": len(r.path) if r.path else 0,
                    "message_len": len(r.message) if r.message else 0,
                }
                for r in failed
            ],
        },
    )
    return results
