"""S8: Violation accumulation signal extractor.

Scores based on prior violations, weighted by category (security vs policy).
Extracted from ConversationAnalyzer._check_violation_accumulation().

No changes from legacy — benefits from new aggregator without rule modification.
"""

from __future__ import annotations

import logging

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import (
    PIPELINE_SECURITY_SCANNER_NAMES,
    SignalResult,
)
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Block category classification ────────────────────────────────

_PIPELINE_SECURITY_SCANNERS = PIPELINE_SECURITY_SCANNER_NAMES

_EXTERNAL_SECURITY_SCANNERS = frozenset(
    {
        "prompt_guard",
        "semgrep",
        "provenance",
        "constraint",
        "constraint_validator",
        "conversation_analyzer",
        "ascii_prompt_gate",
        "scanner_crash",
    }
)

_SECURITY_SCANNERS = _PIPELINE_SECURITY_SCANNERS | _EXTERNAL_SECURITY_SCANNERS

# Score weights
_SECURITY_WEIGHT = 1.5
_POLICY_WEIGHT = 0.5
_MAX_SCORE = 5.0


def check_violation_accumulation(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S8: Score based on prior violations, weighted by category.

    Security blocks: 1.5 per violation. Policy blocks: 0.5.
    Planner refusals: 0.0. Success forgiveness reduces security count.
    Capped at 5.0.

    Returns SignalResult with category 'violation'.
    """
    logger.debug(
        "check_violation_accumulation called",
        extra={
            "event": "signals.violation_accumulation.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    if session.violation_count == 0:
        return SignalResult(score=0.0, categories=frozenset(), details=())

    security_count, policy_count = _count_violations(session)

    # Apply success forgiveness
    security_count = _apply_forgiveness(session, security_count)

    score = min(
        security_count * _SECURITY_WEIGHT + policy_count * _POLICY_WEIGHT, _MAX_SCORE
    )

    details: list[str] = []
    if security_count:
        details.append(f"{security_count} security violation(s)")
    if policy_count:
        details.append(f"{policy_count} policy block(s)")

    if not details:
        return SignalResult(score=0.0, categories=frozenset(), details=())

    logger.info(
        "Violation accumulation scored",
        extra={
            "event": "signals.violation_accumulation.detected",
            "session_id": session.session_id,
            "score": score,
            "security_count": security_count,
            "policy_count": policy_count,
        },
    )

    return SignalResult(
        score=score,
        categories=frozenset({"violation"}),
        details=(f"Session has {'; '.join(details)}",),
    )


def _classify_block_category(blocked_by: list[str]) -> str:
    """Classify a block as security, policy, or planner."""
    if not blocked_by:
        logger.debug(
            "Block category: no attribution, fail-closed to security",
            extra={"event": "signals.violation_accumulation.classify.no_attribution"},
        )
        return "security"
    logger.debug(
        "_classify_block_category: not_blocked_by_passed",
        extra={
            "event": "signals.violation_accumulation.classify.no_attribution.passed",
            "reason": "not_blocked_by_passed",
        },
    )  # auto:neg
    if blocked_by == ["planner"]:
        logger.debug(
            "Block category: planner refusal",
            extra={"event": "signals.violation_accumulation.classify.planner"},
        )
        return "planner"
    logger.debug(
        "_classify_block_category: blocked_by_eq_passed",
        extra={
            "event": "signals.violation_accumulation.classify.planner.passed",
            "reason": "blocked_by_eq_passed",
        },
    )  # auto:neg
    if any(name in _SECURITY_SCANNERS for name in blocked_by):
        logger.debug(
            "Block category: security scanner",
            extra={"event": "signals.violation_accumulation.classify.security"},
        )
        return "security"
    logger.debug(
        "Block category: policy",
        extra={"event": "signals.violation_accumulation.classify.policy"},
    )
    return "policy"


def _count_violations(session: Session) -> tuple[int, int]:
    """Count security and policy violations in the session."""
    security_count = 0
    policy_count = 0
    for turn in session.turns:
        if turn.result_status != "blocked":
            continue
        cat = _classify_block_category(turn.blocked_by)
        if cat == "security":
            security_count += 1
        elif cat == "policy":
            policy_count += 1
    return security_count, policy_count


def _apply_forgiveness(session: Session, security_count: int) -> int:
    """Apply success-after-block forgiveness to reduce security count.

    A successful step after scanner blocks indicates a legitimate retry
    workflow. Forgive one security block per success-after-block pattern.
    """
    logger.debug(
        "_apply_forgiveness called",
        extra={
            "event": "violation_accumulation._apply_forgiveness",
            "session_type": type(session).__name__,
            "security_count": security_count,
        },
    )  # auto:entry
    from sentinel.core.config import settings

    max_forgives = settings.max_success_forgives
    success_forgives_used = session.success_forgives_used

    if security_count <= 0 or success_forgives_used >= max_forgives:
        logger.debug(
            "_apply_forgiveness: security_count_lte_0",
            extra={
                "event": "violation_accumulation._apply_forgiveness.match",
                "reason": "security_count_lte_0",
            },
        )  # auto:neg
        return security_count

    # Count successes that follow at least one prior block
    seen_block = False
    forgive_eligible = 0
    for turn in session.turns:
        if (
            turn.result_status == "blocked"
            and _classify_block_category(turn.blocked_by) == "security"
        ):
            seen_block = True
        elif turn.result_status == "success" and seen_block:
            forgive_eligible += 1
            seen_block = False

    new_forgives = min(
        forgive_eligible - success_forgives_used,
        max_forgives - success_forgives_used,
        security_count,
    )
    if new_forgives > 0:
        logger.debug(
            "_apply_forgiveness: new_forgives_gt_0",
            extra={
                "event": "violation_accumulation._apply_forgiveness.match",
                "reason": "new_forgives_gt_0",
            },
        )  # auto:neg
        security_count -= new_forgives

    return security_count
