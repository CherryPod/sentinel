"""S2: Sensitive topic acceleration signal extractor.

Detects first mention of sensitive topic categories after benign turns.
Extracted from ConversationAnalyzer._check_sensitive_topic_acceleration().

Design doc fix: score 1.0 on first introduction (was 0.0).
"""

from __future__ import annotations

import logging

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.signals._patterns import (
    get_sensitive_categories as _get_sensitive_categories,
)
from sentinel.security.conversation.types import SignalResult
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# Score thresholds for benign turn counts
_SCORE_AFTER_FOUR_BENIGN = 3.0
_SCORE_AFTER_ONE_BENIGN = 2.0
_SCORE_FIRST_INTRODUCTION = 1.0
_BENIGN_HIGH_THRESHOLD = 4
_BENIGN_LOW_THRESHOLD = 1


def check_sensitive_topic(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S2: Sensitive topic acceleration with first-introduction scoring.

    Detects first mention of a NEW sensitive topic category. Scores based on
    how many benign turns preceded the introduction:
      - 0 benign turns (first message): 1.0 (design doc fix)
      - 1+ benign turns: 2.0
      - 4+ benign turns: 3.0

    Returns SignalResult with category 'sensitive_topic'.
    """
    logger.debug(
        "check_sensitive_topic called",
        extra={
            "event": "signals.sensitive_topic.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    current_categories = _get_sensitive_categories(request)
    if not current_categories:
        logger.debug(
            "check_sensitive_topic: not_current_categories",
            extra={
                "event": "sensitive_topic.check_sensitive_topic.match",
                "reason": "not_current_categories",
            },
        )  # auto:neg
        return SignalResult(score=0.0, categories=frozenset(), details=())
    logger.debug(
        "check_sensitive_topic: not_current_categories_passed",
        extra={
            "event": "sensitive_topic.check_sensitive_topic.passed",
            "reason": "not_current_categories_passed",
        },
    )  # auto:neg

    # Collect categories seen in prior turns
    prior_categories: set[str] = set()
    for turn in session.turns:
        prior_categories |= _get_sensitive_categories(
            normalise_homoglyphs(turn.request_text)
        )

    # Check for NEW categories not seen before
    new_categories = current_categories - prior_categories
    if not new_categories:
        logger.debug(
            "check_sensitive_topic: not_new_categories",
            extra={
                "event": "sensitive_topic.check_sensitive_topic.match",
                "reason": "not_new_categories",
            },
        )  # auto:neg
        return SignalResult(score=0.0, categories=frozenset(), details=())

    # Count benign turns (not blocked)
    benign_count = sum(1 for t in session.turns if t.result_status != "blocked")

    sorted_cats = ", ".join(sorted(new_categories))

    if benign_count >= _BENIGN_HIGH_THRESHOLD:
        score = _SCORE_AFTER_FOUR_BENIGN
        detail = f"New sensitive topic category ({sorted_cats}) after {benign_count} benign turns"
    elif benign_count >= _BENIGN_LOW_THRESHOLD:
        score = _SCORE_AFTER_ONE_BENIGN
        detail = f"New sensitive topic category ({sorted_cats}) after {benign_count} benign turns"
    else:
        # Design doc fix: first introduction scores 1.0 (was 0.0)
        score = _SCORE_FIRST_INTRODUCTION
        detail = f"First introduction of sensitive topic ({sorted_cats})"

    logger.info(
        "Sensitive topic detected",
        extra={
            "event": "signals.sensitive_topic.detected",
            "session_id": session.session_id,
            "score": score,
            "new_categories_count": len(new_categories),
            "benign_count": benign_count,
        },
    )

    return SignalResult(
        score=score,
        categories=frozenset({"sensitive_topic"}),
        details=(detail,),
    )
