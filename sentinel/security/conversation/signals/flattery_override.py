"""S11: Flattery-to-override signal extractor.

Detects a two-turn social engineering pattern: flattery in turn N
followed by instruction override or capability escalation in turn N+1.

See design doc Section 4.2 for scoring rationale.
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.signals.escalation import TIER_KEYWORDS
from sentinel.security.conversation.signals.instruction_override import (
    HARD_OVERRIDE_PATTERNS,
    SOFT_OVERRIDE_PATTERNS,
)
from sentinel.security.conversation.types import SignalResult
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Flattery patterns ─────────────────────────────────────────

FLATTERY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bgreat job\b", re.IGNORECASE),
    re.compile(r"\bso helpful\b", re.IGNORECASE),
    re.compile(r"\bso capable\b", re.IGNORECASE),
    re.compile(r"\bimpressive\b", re.IGNORECASE),
    re.compile(r"\byou'?re amazing\b", re.IGNORECASE),
    re.compile(r"\bwell done\b", re.IGNORECASE),
    re.compile(r"\breally helpful\b", re.IGNORECASE),
    re.compile(r"\breally impressive\b", re.IGNORECASE),
]

# ── Execute+ tier names from S1 (for escalation detection) ────

_EXECUTE_PLUS_TIERS = frozenset({"execute", "persist", "exfiltrate"})

# ── Scoring constants ─────────────────────────────────────────

_SCORE_FLATTERY_THEN_OVERRIDE = 2.5


def _has_flattery(text: str) -> bool:
    """Check whether text contains flattery patterns."""
    return any(p.search(text) for p in FLATTERY_PATTERNS)


def _has_override_or_escalation(text: str) -> bool:
    """Check whether text contains S3 override patterns or S1 execute+ keywords."""
    # Check S3 instruction override patterns (hard + soft)
    if any(p.search(text) for p in HARD_OVERRIDE_PATTERNS):
        return True
    if any(p.search(text) for p in SOFT_OVERRIDE_PATTERNS):
        return True

    # Check S1 execute+ tier keywords
    for tier_name in _EXECUTE_PLUS_TIERS:
        tier_patterns = TIER_KEYWORDS.get(tier_name, [])
        if any(p.search(text) for p in tier_patterns):
            return True

    return False


def check_flattery_override(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S11: Flattery-to-override — catches role erosion / social engineering.

    Detects flattery in the immediately preceding turn followed by
    override or capability escalation in the current turn.

    Scores:
      - Flattery alone: 0.0
      - Flattery → override in next turn: 2.5

    Returns SignalResult with category 'social_engineering'.
    """
    logger.debug(
        "check_flattery_override called",
        extra={
            "event": "signals.flattery_override.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    # Need at least one prior turn for the flattery → override pattern
    if not session.turns:
        logger.debug(
            "check_flattery_override: no prior turns",
            extra={
                "event": "signals.flattery_override.no_match",
                "reason": "no_prior_turns",
            },
        )
        return SignalResult(score=0.0, categories=frozenset(), details=())
    logger.debug(
        "check_flattery_override: not_turns_passed",
        extra={
            "event": "signals.flattery_override.no_match.passed",
            "reason": "not_turns_passed",
        },
    )  # auto:neg

    # Check the immediately preceding turn for flattery
    last_turn = session.turns[-1]
    if not _has_flattery(last_turn.request_text):
        logger.debug(
            "check_flattery_override: no flattery in previous turn",
            extra={
                "event": "signals.flattery_override.no_match",
                "reason": "no_prior_flattery",
            },
        )
        return SignalResult(score=0.0, categories=frozenset(), details=())
    logger.debug(
        "check_flattery_override: not_has_flattery_request_text_passed",
        extra={
            "event": "signals.flattery_override.no_match.passed",
            "reason": "not_has_flattery_request_text_passed",
        },
    )  # auto:neg

    # Check current request for override or escalation
    if not _has_override_or_escalation(request):
        logger.debug(
            "check_flattery_override: flattery without override follow-up",
            extra={
                "event": "signals.flattery_override.no_match",
                "reason": "no_override_followup",
            },
        )
        return SignalResult(score=0.0, categories=frozenset(), details=())

    # Flattery → override detected
    logger.info(
        "Flattery-to-override detected",
        extra={
            "event": "signals.flattery_override.detected",
            "session_id": session.session_id,
            "score": _SCORE_FLATTERY_THEN_OVERRIDE,
        },
    )

    return SignalResult(
        score=_SCORE_FLATTERY_THEN_OVERRIDE,
        categories=frozenset({"social_engineering"}),
        details=("Flattery in previous turn followed by override/escalation attempt",),
    )
