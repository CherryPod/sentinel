"""S3: Instruction override signal extractor.

Detects attempts to override system instructions via known patterns.
Extracted from ConversationAnalyzer._check_instruction_override().

Design doc fix: add soft patterns scoring 1.5 instead of 3.0.
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import SignalResult
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Hard override patterns (3.0 each, from legacy) ─────────────

HARD_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bfrom now on\b", re.IGNORECASE),
    re.compile(r"\byou are now\b", re.IGNORECASE),
    re.compile(r"\bas we discussed\b", re.IGNORECASE),
    re.compile(
        r"\bforget (?:(?:your |all |previous |the )*)?(?:instructions|rules|constraints)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bignore (?:(?:your |all |previous |the )*)?(?:instructions|rules|constraints|policies)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\byour new (?:role|persona|identity|instructions)\b", re.IGNORECASE),
    re.compile(r"\byou (?:must|should|will) now\b", re.IGNORECASE),
    re.compile(r"\bact as (?:if you are|a|an|my)\b", re.IGNORECASE),
    re.compile(r"\bpretend (?:you are|to be|that)\b", re.IGNORECASE),
    re.compile(r"\bswitch to (?:\w+ )?mode\b", re.IGNORECASE),
    re.compile(
        r"\benable (?:developer|debug|admin|god|unrestricted) mode\b", re.IGNORECASE
    ),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bDAN\b"),  # "Do Anything Now" — case-sensitive acronym
    re.compile(r"\bsystem\s+override\b", re.IGNORECASE),
    re.compile(r"\bsafety\s+mode\s+(?:is\s+)?off\b", re.IGNORECASE),
    re.compile(
        r"\ball\s+restrictions?\s+(?:are\s+)?(?:now\s+)?(?:lifted|removed|disabled)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\byour\s+(?:programming|rules|constraints)\s+(?:ha(?:ve|s)\s+been)\s+(?:revised|updated|changed|removed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bbypass\s+(?:all\s+)?(?:filters?|security|restrictions?|constraints?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:new|updated)\s+directive\b", re.IGNORECASE),
    re.compile(r"\bdisable\s+(?:content\s+)?filter(?:ing|s)?\b", re.IGNORECASE),
]

# ── Soft override patterns (1.5 each, design doc addition) ──────

SOFT_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bhas been revised\b", re.IGNORECASE),
    re.compile(r"\bhas been updated\b", re.IGNORECASE),
    re.compile(r"\bmode has changed\b", re.IGNORECASE),
    re.compile(r"\bguidelines have changed\b", re.IGNORECASE),
    re.compile(r"\brestrictions have been lifted\b", re.IGNORECASE),
    re.compile(r"\byou can now\b", re.IGNORECASE),
]

_HARD_SCORE = 3.0
_SOFT_SCORE = 1.5
_MAX_SCORE = 5.0


def check_instruction_override(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S3: Instruction override with soft pattern support.

    Hard patterns score 3.0 each, soft patterns 1.5 each, capped at 5.0.
    Session is accepted but not used (stateless rule).

    Returns SignalResult with category 'instruction_override'.
    """
    logger.debug(
        "check_instruction_override called",
        extra={
            "event": "signals.instruction_override.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    score = 0.0
    details: list[str] = []

    for pattern in HARD_OVERRIDE_PATTERNS:
        if pattern.search(request):
            score += _HARD_SCORE
            details.append("Instruction override phrase detected")

    for pattern in SOFT_OVERRIDE_PATTERNS:
        if pattern.search(request):
            score += _SOFT_SCORE
            details.append("Soft instruction override phrase detected")

    score = min(score, _MAX_SCORE)

    if score > 0.0:
        logger.info(
            "Instruction override detected",
            extra={
                "event": "signals.instruction_override.detected",
                "session_id": session.session_id,
                "score": score,
                "detail_count": len(details),
            },
        )
        return SignalResult(
            score=score,
            categories=frozenset({"instruction_override"}),
            details=tuple(details),
        )
    logger.debug(
        "check_instruction_override: score_gt_0_0_passed",
        extra={
            "event": "signals.instruction_override.detected.passed",
            "reason": "score_gt_0_0_passed",
        },
    )  # auto:neg

    return SignalResult(score=0.0, categories=frozenset(), details=())
