"""S6: Reconnaissance signal extractor.

Detects systematic directory/file exploration across turns.
Extracted from ConversationAnalyzer._check_reconnaissance().

Design doc fix: add patterns "what commands are available",
"what tools do you have", "what can you access", "what files exist".
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import SignalResult
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Recon patterns (legacy + design doc additions) ──────────────

RECON_PATTERNS: list[re.Pattern[str]] = [
    # Legacy patterns
    re.compile(r"\b(?:ls|list|dir)\s+", re.IGNORECASE),
    re.compile(r"\blist\s+(?:files|directories|folders)\b", re.IGNORECASE),
    re.compile(r"\bwhat(?:'s| is)\s+in\b", re.IGNORECASE),
    re.compile(
        r"\bshow\s+(?:me\s+)?(?:the\s+)?(?:files|contents|directory|folder)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bcontents?\s+of\b", re.IGNORECASE),
    re.compile(r"\btree\s+", re.IGNORECASE),
    re.compile(r"\bfind\s+.*(?:/\w+)", re.IGNORECASE),
    # Design doc additions
    re.compile(r"\bwhat commands are available\b", re.IGNORECASE),
    re.compile(r"\bwhat tools do you have\b", re.IGNORECASE),
    re.compile(r"\bwhat can you access\b", re.IGNORECASE),
    re.compile(r"\bwhat files exist\b", re.IGNORECASE),
]

# Score thresholds
_SCORE_TWO_TURNS = 2.0
_SCORE_THREE_PLUS = 3.5
_MAX_SCORE = 5.0
_MIN_TURNS_TWO = 2
_MIN_TURNS_THREE = 3


def check_reconnaissance(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S6: Detect systematic directory/file exploration across turns.

    Score: 2.0 for 2 recon turns, 3.5 for 3+, max 5.0.

    Returns SignalResult with category 'reconnaissance'.
    """
    logger.debug(
        "check_reconnaissance called",
        extra={
            "event": "signals.reconnaissance.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    # Count prior turns that match recon patterns
    recon_count = 0
    for turn in session.turns:
        normalised = normalise_homoglyphs(turn.request_text)
        if any(p.search(normalised) for p in RECON_PATTERNS):
            recon_count += 1

    # Check if current request is also recon
    if any(p.search(request) for p in RECON_PATTERNS):
        logger.debug(
            "check_reconnaissance: any",
            extra={
                "event": "reconnaissance.check_reconnaissance.match",
                "reason": "any",
            },
        )  # auto:neg
        recon_count += 1

    if recon_count >= _MIN_TURNS_THREE:
        score = min(_SCORE_THREE_PLUS, _MAX_SCORE)
        detail = f"Systematic reconnaissance: {recon_count} exploration turns"
    elif recon_count >= _MIN_TURNS_TWO:
        score = _SCORE_TWO_TURNS
        detail = f"Reconnaissance pattern: {recon_count} exploration turns"
    else:
        logger.debug(
            "reconnaissance.check_reconnaissance.clean",
            extra={
                "event": "signals.reconnaissance.clean",
                "session_id": session.session_id,
                "request_len": len(request),
                "recon_count": recon_count,
            },
        )
        return SignalResult(score=0.0, categories=frozenset(), details=())

    logger.info(
        "Reconnaissance detected",
        extra={
            "event": "signals.reconnaissance.detected",
            "session_id": session.session_id,
            "score": score,
            "recon_count": recon_count,
        },
    )
    return SignalResult(
        score=score,
        categories=frozenset({"reconnaissance"}),
        details=(detail,),
    )
