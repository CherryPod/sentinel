"""Judge verdict processing — confidence gating and false-positive filtering.

Extracted from verification.py during planner modularisation (Phase 3).
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Known false-positive GAP patterns from the judge. These are metadata
# artefacts (e.g. the judge seeing "(no file changes)" in the prompt when
# changes DID happen but size data wasn't propagated) rather than real gaps.
# When the GAP matches one of these, the verdict is downgraded to advisory.
_FALSE_POSITIVE_GAP_PATTERNS = [
    re.compile(r"no file changes", re.IGNORECASE),
    re.compile(r"cannot verify .*(content|file|changes)", re.IGNORECASE),
    re.compile(r"no evidence of .*(file|changes|modification)", re.IGNORECASE),
    re.compile(r"file changes shows .*(no|empty)", re.IGNORECASE),
]


def _is_false_positive_gap(gap: str | None) -> bool:
    """Check if a judge GAP string matches known false-positive patterns."""
    if not gap:
        return False
    return any(p.search(gap) for p in _FALSE_POSITIVE_GAP_PATTERNS)


def process_judge_verdict(
    verdict: dict,
    current_completion: str,
) -> dict:
    """Process the judge's verdict according to confidence gating rules.

    Confidence gating:
    - high: verdict overrides Tier 1 (completion changes)
    - medium: advisory only (stored in episodic, no status change)
    - low: discarded entirely (no effect)

    False-positive filter: when GOAL_MET is "no" or "partial" with high
    confidence but the GAP matches a known metadata false-positive pattern,
    the verdict is downgraded to advisory (not acted on).

    Returns dict with: completion, acted_on, gap
    """
    confidence = verdict.get("CONFIDENCE", "low")
    goal_met = verdict.get("GOAL_MET", "yes")
    gap = verdict.get("GAP")

    if confidence == "high":
        # False-positive filter: if the GAP is a known metadata artefact,
        # downgrade to advisory rather than overriding Tier 1 success.
        if goal_met != "yes" and _is_false_positive_gap(gap):
            logger.info(
                "Judge verdict downgraded: GAP matches false-positive pattern — %s",
                gap,
                extra={
                    "event": "judge.false_positive_filter",
                    "goal_met": goal_met,
                    "gap": gap,
                },
            )
            result = {"completion": current_completion, "acted_on": False, "gap": gap}
        elif goal_met == "yes":
            result = {"completion": "full", "acted_on": True, "gap": gap}
        elif goal_met == "partial":
            result = {"completion": "partial", "acted_on": True, "gap": gap}
        else:  # "no"
            result = {"completion": "failed", "acted_on": True, "gap": gap}
    else:
        # medium or low — advisory only, don't change completion
        logger.debug(
            "process_judge_verdict: confidence_not_high",
            extra={
                "event": "judge.false_positive_filter.clean",
                "reason": "confidence_not_high",
            },
        )  # auto:neg
        result = {"completion": current_completion, "acted_on": False, "gap": gap}

    logger.debug(
        "Judge verdict processed: goal_met=%s, confidence=%s, acted_on=%s, completion=%s→%s",
        goal_met,
        confidence,
        result["acted_on"],
        current_completion,
        result["completion"],
        extra={
            "event": "judge.verdict_processed",
            "goal_met": goal_met,
            "confidence": confidence,
            "acted_on": result["acted_on"],
            "completion_before": current_completion,
            "completion_after": result["completion"],
            "gap": gap,
        },
    )
    return result
