"""MTM false-positive management — suppression and forgiveness mechanisms.

Three strategies to reduce false positives without weakening detection:
  1. Benign-anchor suppression (design doc Section 6.1)
  2. Benign session floor (design doc Section 5.4)
  3. Success forgiveness (design doc Section 6.2)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sentinel.security.conversation.types import SignalResult

if TYPE_CHECKING:
    from sentinel.security.conversation.config import MTMConfig
    from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# Design doc Section 6.1: score multiplier when benign anchor present
_BENIGN_ANCHOR_SUPPRESSION_FACTOR = 0.5


def apply_benign_anchor_suppression(
    signal_result: SignalResult,
    request: str,
    config: MTMConfig,
) -> SignalResult:
    """Reduce signal scores when only benign dev keywords are present.

    When the request contains a benign anchor keyword (e.g. "write", "build")
    and NO dangerous keyword (e.g. "eval", "sudo"), the signal score is
    halved. Phase 8 benchmark replay showed that restricting this to only
    escalation-category signals allowed topic_shift and sensitive_topic to
    cause FPs on genuine learning sessions. The dangerous-keyword guard
    prevents suppression on actually dangerous requests.

    Args:
        signal_result: The signal result to potentially suppress.
        request: The current user request text (already homoglyph-normalised).
        config: MTM config with benign_anchors and dangerous_keywords lists.

    Returns:
        Original or suppressed SignalResult.
    """
    logger.debug(
        "fp_management.benign_anchor: evaluating",
        extra={
            "event": "conversation.fp.benign_anchor.evaluate",
            "score": signal_result.score,
            "categories": list(signal_result.categories),
        },
    )

    # Zero scores need no suppression
    if signal_result.score == 0.0:
        return signal_result

    request_lower = request.lower()

    # Check for dangerous keywords — if present, never suppress
    for kw in config.dangerous_keywords:
        if kw.lower() in request_lower:
            logger.debug(
                "fp_management.benign_anchor: dangerous keyword found, no suppression",
                extra={
                    "event": "conversation.fp.benign_anchor.dangerous",
                    "keyword_len": len(kw),
                },
            )
            return signal_result

    # Check for benign anchors — if present, suppress
    for anchor in config.benign_anchors:
        if anchor.lower() in request_lower:
            suppressed_score = signal_result.score * _BENIGN_ANCHOR_SUPPRESSION_FACTOR
            logger.info(
                "fp_management.benign_anchor: suppressing escalation",
                extra={
                    "event": "conversation.fp.benign_anchor.suppressed",
                    "original_score": signal_result.score,
                    "suppressed_score": suppressed_score,
                    "anchor_len": len(anchor),
                },
            )
            return SignalResult(
                score=suppressed_score,
                categories=signal_result.categories,
                details=(
                    *signal_result.details,
                    "benign-anchor suppression applied (0.5x)",
                ),
            )

    # No benign anchor found — pass through unchanged
    logger.debug(
        "fp_management.benign_anchor: no anchor match",
        extra={"event": "conversation.fp.benign_anchor.no_match"},
    )
    return signal_result


def check_benign_floor(
    turn_scores: list,
    config: MTMConfig,
) -> bool:
    """Check if the benign session floor is active.

    The floor is active when:
      1. At least benign_floor_turns turns have been scored
      2. The first benign_floor_turns turns ALL scored exactly 0.0
      3. No turn in the entire history exceeds warn_threshold

    Args:
        turn_scores: All TurnScore objects in session history (chronological).
        config: MTM config with benign_floor_turns and warn_threshold.

    Returns:
        True if benign floor is active, False otherwise.
    """
    logger.debug(
        "fp_management.benign_floor: checking",
        extra={
            "event": "conversation.fp.benign_floor.check",
            "turn_count": len(turn_scores),
            "required_turns": config.benign_floor_turns,
        },
    )

    # Not enough turns yet
    if len(turn_scores) < config.benign_floor_turns:
        logger.debug(
            "fp_management.benign_floor: not enough turns",
            extra={
                "event": "conversation.fp.benign_floor.inactive",
                "reason": "insufficient_turns",
            },
        )
        return False

    # Check first N turns are all 0.0
    for i in range(config.benign_floor_turns):
        if turn_scores[i].score != 0.0:
            logger.debug(
                "fp_management.benign_floor: non-zero early turn",
                extra={
                    "event": "conversation.fp.benign_floor.inactive",
                    "reason": "nonzero_early_turn",
                    "turn_index": i,
                },
            )
            return False

    # Revoke if any turn exceeds warn_threshold (design doc Section 5.4)
    for i, ts in enumerate(turn_scores):
        if ts.score >= config.warn_threshold:
            logger.debug(
                "fp_management.benign_floor: revoked by high score",
                extra={
                    "event": "conversation.fp.benign_floor.revoked",
                    "turn_index": i,
                    "score": ts.score,
                },
            )
            return False

    logger.debug(
        "fp_management.benign_floor: active",
        extra={"event": "conversation.fp.benign_floor.active"},
    )
    return True


def apply_success_forgiveness(
    persistence_count: int,
    session: Session,
) -> int:
    """Reduce persistence count by successful turns after blocked/warned turns.

    Each success-after-block pattern reduces persistence by 1 (minimum 0).
    This prevents legitimate fix-retry cycles from accumulating false persistence.

    Args:
        persistence_count: Current persistence count from aggregation.
        session: Session with turn history.

    Returns:
        Adjusted persistence count (>= 0).
    """
    logger.debug(
        "fp_management.success_forgiveness: evaluating",
        extra={
            "event": "conversation.fp.success_forgiveness.evaluate",
            "persistence_count": persistence_count,
            "turn_count": len(session.turns),
        },
    )

    if persistence_count <= 0:
        return 0

    # Count success-after-block patterns in turn history.
    # Note: design doc Section 6.2 says "warned turn" but session turns
    # have no "warned" status — only "success", "blocked", "error".
    # Warns are advisory and don't change result_status, so forgiveness
    # triggers on block→success patterns (matching violation_accumulation.py).
    forgive_count = 0
    seen_block = False
    for turn in session.turns:
        if turn.result_status == "blocked":
            seen_block = True
        elif turn.result_status == "success" and seen_block:
            forgive_count += 1
            seen_block = False

    if forgive_count == 0:
        logger.debug(
            "fp_management.success_forgiveness: no forgiveness patterns",
            extra={
                "event": "conversation.fp.success_forgiveness.none",
            },
        )
        return persistence_count

    adjusted = max(0, persistence_count - forgive_count)
    logger.info(
        "fp_management.success_forgiveness: reducing persistence",
        extra={
            "event": "conversation.fp.success_forgiveness.applied",
            "original": persistence_count,
            "forgive_count": forgive_count,
            "adjusted": adjusted,
        },
    )
    return adjusted
