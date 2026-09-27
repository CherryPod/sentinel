"""Tier 1 consensus check — all deterministic signals agree on success.

Extracted from verification.py during planner modularisation (Phase 3).
"""

from __future__ import annotations

import logging

from sentinel.planner._evaluators import AssertionResult
from sentinel.planner._tool_scanning import ToolOutputWarning

logger = logging.getLogger(__name__)

# Injected into the judge prompt when all Tier 1 deterministic signals agree
# on success. Raises the evidence bar — the judge can still override, but
# must cite a specific, concrete gap rather than speculative incompleteness.
TIER1_CONSENSUS_INSTRUCTION = """
IMPORTANT: All deterministic signals indicate success (completion=full, goal actions \
executed, files mutated, no assertion failures, no warnings). Only override with \
GOAL_MET=no or GOAL_MET=partial if you can identify a specific, concrete requirement \
from the original request that is demonstrably unmet. "Might be incomplete" or \
"cannot verify content" is not sufficient — cite exactly what is missing."""


def check_tier1_consensus(
    completion: str,
    goal_actions_executed: bool,
    file_mutations: list[dict],
    assertion_results: list[AssertionResult | dict],
    tool_output_warnings: list[ToolOutputWarning | dict],
) -> bool:
    """Check if all 5 Tier 1 deterministic signals agree on success.

    All five must be green:
    1. completion == "full"
    2. goal_actions_executed == True
    3. mutations >= 1 (at least one file was changed)
    4. assertion_failures == 0 (no assertion failed, or none defined)
    5. no HIGH-severity tool output warnings
    """
    if completion != "full":
        logger.debug(
            "Tier1 consensus failed",
            extra={
                "event": "verification.tier1consensus",
                "reason": "completion_not_full",
                "completion": completion,
            },
        )
        return False
    logger.debug(
        "_check_tier1_consensus: completion_noteq_full_passed",
        extra={
            "event": "verification.tier1consensus.passed",
            "reason": "completion_noteq_full_passed",
        },
    )  # auto:neg
    if not goal_actions_executed:
        logger.debug(
            "Tier1 consensus failed",
            extra={
                "event": "verification.tier1consensus",
                "reason": "goal_actions_not_executed",
            },
        )
        return False
    logger.debug(
        "_check_tier1_consensus: not_goal_actions_executed_passed",
        extra={
            "event": "verification.tier1consensus.passed",
            "reason": "not_goal_actions_executed_passed",
        },
    )  # auto:neg

    # At least one real file mutation (exclude no-ops)
    real_mutations = [m for m in file_mutations if not m.get("no_op")]
    if not real_mutations:
        logger.debug(
            "Tier1 consensus failed",
            extra={
                "event": "verification.tier1consensus",
                "reason": "no_real_mutations",
            },
        )
        return False

    # No assertion failures (passing or none defined both count as green)
    for r in assertion_results:
        if isinstance(r, AssertionResult):
            if not r.passed:
                logger.debug(
                    "Tier1 consensus failed",
                    extra={
                        "event": "verification.tier1consensus",
                        "reason": "assertion_failed",
                    },
                )
                return False
        elif isinstance(r, dict):
            if not r.get("passed"):
                logger.debug(
                    "Tier1 consensus failed",
                    extra={
                        "event": "verification.tier1consensus",
                        "reason": "assertion_failed",
                    },
                )
                return False

    # No HIGH-severity warnings
    for w in tool_output_warnings:
        if isinstance(w, ToolOutputWarning):
            if w.severity == "HIGH":
                logger.debug(
                    "Tier1 consensus failed",
                    extra={
                        "event": "verification.tier1consensus",
                        "reason": "high_severity_warning",
                    },
                )
                return False
        elif isinstance(w, dict):
            if w.get("severity") == "HIGH":
                logger.debug(
                    "Tier1 consensus failed",
                    extra={
                        "event": "verification.tier1consensus",
                        "reason": "high_severity_warning",
                    },
                )
                return False

    logger.debug(
        "Tier1 consensus passed",
        extra={"event": "verification.tier1consensus", "reason": "all_signals_green"},
    )
    return True
