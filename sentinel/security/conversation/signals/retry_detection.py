"""S5: Retry detection signal extractor.

Detects rephrased retries of previously blocked requests.
Extracted from ConversationAnalyzer._check_retry_after_block().

No changes from legacy — SequenceMatcher > 0.45 preserved.
"""

from __future__ import annotations

import logging
from difflib import SequenceMatcher

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import SignalResult
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# SequenceMatcher ratio threshold for detecting retries
_SIMILARITY_THRESHOLD = 0.45

# Per-match score and cap
_SCORE_PER_MATCH = 3.0
_MAX_SCORE = 5.0

# Truncation length for SequenceMatcher (O(n^2) complexity)
_TRUNCATE_LEN = 1000


def check_retry_detection(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S5: Detect rephrased retries of previously blocked requests.

    Score: 3.0 per similar blocked request, max 5.0.
    Trigger: SequenceMatcher ratio > 0.45 against any blocked turn.

    Returns SignalResult with category 'retry'.
    """
    logger.debug(
        "check_retry_detection called",
        extra={
            "event": "signals.retry_detection.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    score = 0.0
    details: list[str] = []
    current_lower = request.lower()[:_TRUNCATE_LEN]

    for turn in session.turns:
        if turn.result_status != "blocked":
            continue
        turn_text = normalise_homoglyphs(turn.request_text).lower()[:_TRUNCATE_LEN]
        ratio = SequenceMatcher(None, current_lower, turn_text).ratio()
        if ratio > _SIMILARITY_THRESHOLD:
            score += _SCORE_PER_MATCH
            details.append(
                f"Request similar to previously blocked request (similarity: {ratio:.0%})"
            )

    score = min(score, _MAX_SCORE)

    if score > 0.0:
        logger.info(
            "Retry after block detected",
            extra={
                "event": "signals.retry_detection.detected",
                "session_id": session.session_id,
                "score": score,
                "match_count": len(details),
            },
        )
        return SignalResult(
            score=score,
            categories=frozenset({"retry"}),
            details=tuple(details),
        )
    logger.debug(
        "check_retry_detection: score_gt_0_0_passed",
        extra={
            "event": "signals.retry_detection.detected.passed",
            "reason": "score_gt_0_0_passed",
        },
    )  # auto:neg

    return SignalResult(score=0.0, categories=frozenset(), details=())
