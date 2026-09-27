"""S4: Context reference signal extractor.

Detects context-reference phrases combined with sensitive content or
escalation language. Extracted from ConversationAnalyzer._check_context_building().

Design doc fix: add phrases "same approach", "like before", "again but",
"instead of", "adapt it".
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.signals._patterns import get_sensitive_categories
from sentinel.security.conversation.types import SignalResult
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Context reference phrases (legacy + design doc additions) ───

CONTEXT_REFERENCE_PHRASES: list[re.Pattern[str]] = [
    # Legacy phrases
    re.compile(r"\bas (?:I|we) (?:mentioned|discussed|said|noted)\b", re.IGNORECASE),
    re.compile(
        r"\byou (?:already|previously) (?:said|confirmed|agreed|told me)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bremember (?:when|that|earlier)\b", re.IGNORECASE),
    re.compile(
        r"\bbased on (?:our|the) (?:earlier|previous|prior) (?:conversation|discussion)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bcontinuing (?:from|where|what)\b", re.IGNORECASE),
    re.compile(r"\bso (?:now|next|then) (?:can you|let's|we can)\b", re.IGNORECASE),
    # Design doc additions
    re.compile(r"\bsame approach\b", re.IGNORECASE),
    re.compile(r"\blike before\b", re.IGNORECASE),
    re.compile(r"\bagain but\b", re.IGNORECASE),
    re.compile(r"\binstead of\b", re.IGNORECASE),
    re.compile(r"\badapt it\b", re.IGNORECASE),
]

# Escalation language (from legacy)
ESCALATION_LANGUAGE: list[str] = [
    "now that we have",
    "next step",
    "final step",
    "the real task",
    "what i actually need",
    "the important part",
]

# Sensitive topic patterns (reused from sensitive_topic module)
# Import at function call time to avoid circular imports
_SENSITIVE_SCORE = 2.0
_ESCALATION_SCORE = 2.0
_MAX_SCORE = 4.0


def check_context_reference(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S4: Context reference combined with sensitive content or escalation.

    Score: 2.0 for context ref + sensitive topic, up to 4.0 with escalation.
    Session is accepted but not used (stateless check on current request).

    Returns SignalResult with category 'context_building'.
    """
    logger.debug(
        "check_context_reference called",
        extra={
            "event": "signals.context_reference.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    has_context_ref = any(p.search(request) for p in CONTEXT_REFERENCE_PHRASES)
    if not has_context_ref:
        return SignalResult(score=0.0, categories=frozenset(), details=())

    request_lower = request.lower()

    # Check for sensitive content
    has_sensitive = bool(get_sensitive_categories(request))

    # Check for escalation language
    has_escalation = any(phrase in request_lower for phrase in ESCALATION_LANGUAGE)

    score = 0.0
    details: list[str] = []

    if has_sensitive:
        score = _SENSITIVE_SCORE
        details.append("Context reference combined with sensitive topic")
    if has_escalation:
        score += _ESCALATION_SCORE
        details.append("Context reference combined with escalation language")

    score = min(score, _MAX_SCORE)

    if score > 0.0:
        logger.info(
            "Context reference detected",
            extra={
                "event": "signals.context_reference.detected",
                "session_id": session.session_id,
                "score": score,
            },
        )
        return SignalResult(
            score=score,
            categories=frozenset({"context_building"}),
            details=tuple(details),
        )
    logger.debug(
        "check_context_reference: score_gt_0_0_passed",
        extra={
            "event": "signals.context_reference.detected.passed",
            "reason": "score_gt_0_0_passed",
        },
    )  # auto:neg

    return SignalResult(score=0.0, categories=frozenset(), details=())
