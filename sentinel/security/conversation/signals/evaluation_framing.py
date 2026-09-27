"""S10: Evaluation framing signal extractor.

Detects Bad Likert Judge / educational reframing patterns combined with
sensitive topic content. Low base score (amplifier signal, not standalone).

See design doc Section 4.2 for scoring rationale.
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.signals._patterns import get_sensitive_categories
from sentinel.security.conversation.types import SignalResult
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Evaluation / educational framing patterns ─────────────────

EVALUATION_PATTERNS: list[re.Pattern[str]] = [
    # Evaluation requests
    re.compile(r"\bshow me an example of\b", re.IGNORECASE),
    re.compile(r"\bdemonstrate how\b", re.IGNORECASE),
    re.compile(r"\bwhat would .{1,40} look like\b", re.IGNORECASE),
    # Educational framing
    re.compile(r"\bfor educational purposes\b", re.IGNORECASE),
    re.compile(r"\bso I understand the risk\b", re.IGNORECASE),
    re.compile(r"\bto learn about\b", re.IGNORECASE),
    # Rating requests
    re.compile(r"\brate the severity of\b", re.IGNORECASE),
    re.compile(r"\bon a scale of\b", re.IGNORECASE),
    re.compile(r"\bhow dangerous is\b", re.IGNORECASE),
]

# ── Scoring constants ─────────────────────────────────────────

_SCORE_FRAMING_PLUS_SENSITIVE = 1.5
_SCORE_FRAMING_PLUS_SENSITIVE_PLUS_BENIGN = 2.5


def _has_evaluation_framing(text: str) -> bool:
    """Check whether text contains any evaluation/educational framing pattern."""
    return any(p.search(text) for p in EVALUATION_PATTERNS)


def check_evaluation_framing(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S10: Evaluation framing — catches educational reframing of sensitive topics.

    Scores:
      - Framing alone (no sensitive content): 0.0
      - Framing + sensitive topic in same turn: 1.5
      - Framing + sensitive topic + prior benign turn: 2.5

    Returns SignalResult with category 'evaluation_framing'.
    """
    logger.debug(
        "check_evaluation_framing called",
        extra={
            "event": "signals.evaluation_framing.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    if not _has_evaluation_framing(request):
        logger.debug(
            "check_evaluation_framing: no framing patterns",
            extra={
                "event": "signals.evaluation_framing.no_match",
                "reason": "no_framing_patterns",
            },
        )
        return SignalResult(score=0.0, categories=frozenset(), details=())
    logger.debug(
        "check_evaluation_framing: not_has_evaluation_framing_request_passed",
        extra={
            "event": "signals.evaluation_framing.no_match.passed",
            "reason": "not_has_evaluation_framing_request_passed",
        },
    )  # auto:neg

    # Check for sensitive topic in the same turn
    sensitive_cats = get_sensitive_categories(request)
    if not sensitive_cats:
        logger.debug(
            "check_evaluation_framing: framing without sensitive topic",
            extra={
                "event": "signals.evaluation_framing.no_match",
                "reason": "no_sensitive_topic",
            },
        )
        return SignalResult(score=0.0, categories=frozenset(), details=())

    # Check for prior benign turns (trust-building).
    # Note: session.turns does NOT include the current request at call time —
    # the monitor adds the turn after scoring.
    benign_prior_count = sum(1 for t in session.turns if t.result_status != "blocked")

    sorted_cats = ", ".join(sorted(sensitive_cats))

    if benign_prior_count >= 1:
        logger.debug(
            "check_evaluation_framing: benign_prior_count_gte_1",
            extra={
                "event": "evaluation_framing.check_evaluation_framing.match",
                "reason": "benign_prior_count_gte_1",
            },
        )  # auto:neg
        score = _SCORE_FRAMING_PLUS_SENSITIVE_PLUS_BENIGN
        detail = f"Evaluation framing with sensitive topic ({sorted_cats}) after {benign_prior_count} benign turns"
    else:
        logger.debug(
            "check_evaluation_framing: benign_prior_count_gte_1",
            extra={
                "event": "evaluation_framing.check_evaluation_framing.clean",
                "reason": "benign_prior_count_gte_1",
            },
        )  # auto:neg
        score = _SCORE_FRAMING_PLUS_SENSITIVE
        detail = f"Evaluation framing with sensitive topic ({sorted_cats})"

    logger.info(
        "Evaluation framing detected",
        extra={
            "event": "signals.evaluation_framing.detected",
            "session_id": session.session_id,
            "score": score,
            "sensitive_categories_count": len(sensitive_cats),
            "benign_prior_count": benign_prior_count,
        },
    )

    return SignalResult(
        score=score,
        categories=frozenset({"evaluation_framing"}),
        details=(detail,),
    )
