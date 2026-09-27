"""S1: Keyword escalation signal extractor.

Detects rapid capability tier escalation across conversation turns.
Extracted from ConversationAnalyzer._check_escalation() with design doc fixes:
  - Cumulative tier tracking (gradual boiling-frog detection)
  - New execute-tier keywords: subprocess, eval, exec, os.system, shell=True
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import SignalResult
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Capability tiers (ordered by severity) ──────────────────────

CAPABILITY_TIERS: dict[str, int] = {
    "observe": 0,
    "read": 1,
    "write": 2,
    "execute": 3,
    "persist": 4,
    "exfiltrate": 5,
}

# Keywords that map to capability tiers (pre-compiled word-boundary patterns).
# New execute-tier keywords added per design doc Section 4.1.
TIER_KEYWORDS: dict[str, list[re.Pattern[str]]] = {
    "observe": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "list",
            "show",
            "display",
            "status",
            "check",
            "info",
            "describe",
            "what is",
        ]
    ],
    "read": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "read",
            "cat",
            "view",
            "open",
            "get contents",
            "print file",
            "head",
            "tail",
            "less",
        ]
    ],
    "write": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "write",
            "create",
            "edit",
            "modify",
            "append",
            "save",
            "update file",
            "overwrite",
        ]
    ],
    "execute": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "run",
            "execute",
            "bash",
            "shell",
            "script",
            "command",
            "invoke",
            "launch",
            # Design doc additions
            "subprocess",
            "eval",
            "exec",
        ]
    ]
    + [
        # os.system and shell=True need non-word-boundary patterns
        re.compile(r"os\.system", re.IGNORECASE),
        re.compile(r"shell\s*=\s*True", re.IGNORECASE),
    ],
    "persist": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "cron",
            "crontab",
            "systemd",
            "service",
            "startup",
            "autostart",
            "schedule",
            "daemon",
            "boot",
            "init.d",
            "rc.local",
            "persist",
            "backdoor",
        ]
    ],
    "exfiltrate": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "curl",
            "wget",
            "upload",
            "send to",
            "post to",
            "exfil",
            "transfer out",
            "base64 encode",
            "dns tunnel",
            "reverse shell",
            "nc -e",
            "netcat",
        ]
    ],
}

# High-risk tiers that always flag even without a 2-tier jump
_HIGH_RISK_TIERS = frozenset({"persist", "exfiltrate"})

# Minimum single-step jump to trigger escalation scoring
_MIN_JUMP_TIERS = 2

# Cumulative tracking thresholds (design doc Section 4.1)
_CUMULATIVE_MIN_TIER = 3  # Cumulative max tier must reach this
_CUMULATIVE_MIN_STEPS = 3  # Need this many advancing steps
_CUMULATIVE_SCORE = 2.0  # Score for cumulative escalation


def check_keyword_escalation(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S1: Keyword escalation with cumulative tier tracking.

    Detects:
    - Single-step: 2+ tier jump in one step (score = jump amount, max 5.0)
    - High-risk: reaching persist/exfiltrate tier (score 3.0)
    - Cumulative: tier reached 3+ across 3+ advancing steps (score 2.0)

    Returns SignalResult with category 'escalation'.
    """
    logger.debug(
        "check_keyword_escalation called",
        extra={
            "event": "signals.escalation.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    current_tier = _classify_tier(request)
    if current_tier is None:
        return SignalResult(score=0.0, categories=frozenset(), details=())

    current_value = CAPABILITY_TIERS[current_tier]

    # Build per-turn tier history from session
    turn_tiers = _get_per_turn_tiers(session)
    prev_max_tier = _max_tier_from_values(turn_tiers)

    score = 0.0
    details: list[str] = []

    # Check single-step jump (legacy behaviour)
    if prev_max_tier is not None:
        prev_value = CAPABILITY_TIERS[prev_max_tier]
        jump = current_value - prev_value
        if jump >= _MIN_JUMP_TIERS:
            score = min(float(jump), 5.0)
            details.append(
                f"Capability escalation: {prev_max_tier} \u2192 {current_tier} (+{jump} tiers)"
            )

    # Check high-risk tier (always flags if not already scored)
    if current_tier in _HIGH_RISK_TIERS and score == 0.0:
        score = 3.0
        details.append(f"High-risk capability tier: {current_tier}")

    # Check cumulative escalation (design doc fix)
    if score == 0.0:
        cumulative_score, cumulative_detail = _check_cumulative(
            turn_tiers, current_tier
        )
        if cumulative_score > 0.0:
            score = cumulative_score
            details.append(cumulative_detail)

    if score > 0.0:
        logger.info(
            "Keyword escalation detected",
            extra={
                "event": "signals.escalation.detected",
                "session_id": session.session_id,
                "score": score,
                "current_tier": current_tier,
                "prev_max_tier": prev_max_tier,
            },
        )
        return SignalResult(
            score=score,
            categories=frozenset({"escalation"}),
            details=tuple(details),
        )
    logger.debug(
        "check_keyword_escalation: score_gt_0_0_passed",
        extra={
            "event": "signals.escalation.detected.passed",
            "reason": "score_gt_0_0_passed",
        },
    )  # auto:neg

    return SignalResult(score=0.0, categories=frozenset(), details=())


def _classify_tier(text: str) -> str | None:
    """Classify text into the highest matching capability tier."""
    logger.debug(
        "_classify_tier called",
        extra={
            "event": "escalation._classify_tier",
            "text_len": len(text) if hasattr(text, "__len__") else 0,
        },
    )  # auto:entry
    text_lower = text.lower()
    best_tier: str | None = None
    best_value = -1

    for tier, patterns in TIER_KEYWORDS.items():
        for pattern in patterns:
            if pattern.search(text_lower):
                tier_value = CAPABILITY_TIERS[tier]
                if tier_value > best_value:
                    best_tier = tier
                    best_value = tier_value

    return best_tier


def _get_per_turn_tiers(session: Session) -> list[str | None]:
    """Get the tier classification for each prior turn in the session."""
    tiers: list[str | None] = []
    for turn in session.turns:
        normalised = normalise_homoglyphs(turn.request_text)
        tiers.append(_classify_tier(normalised))
    return tiers


def _max_tier_from_values(turn_tiers: list[str | None]) -> str | None:
    """Get the highest tier from a list of per-turn tier classifications."""
    max_tier: str | None = None
    max_value = -1
    for tier in turn_tiers:
        if tier is not None:
            value = CAPABILITY_TIERS[tier]
            if value > max_value:
                max_tier = tier
                max_value = value
    return max_tier


def _check_cumulative(
    turn_tiers: list[str | None], current_tier: str
) -> tuple[float, str]:
    """Check for cumulative tier escalation across multiple steps.

    Fires when: cumulative max tier >= 3, AND there were 3+ steps where
    each step advanced beyond the previous maximum.

    Returns (score, detail_string). Score is 0.0 if cumulative doesn't fire.
    """
    logger.debug(
        "_check_cumulative called",
        extra={
            "event": "escalation._check_cumulative",
            "turn_tiers_len": len(turn_tiers) if hasattr(turn_tiers, "__len__") else 0,
            "current_tier": current_tier,
        },
    )  # auto:entry
    current_value = CAPABILITY_TIERS[current_tier]

    # Build sequence of advancing tiers: each step must exceed prior max
    advancing_steps = 0
    running_max = -1

    for tier in turn_tiers:
        if tier is not None:
            value = CAPABILITY_TIERS[tier]
            if value > running_max:
                advancing_steps += 1
                running_max = value

    # Include current request in the advancing chain
    if current_value > running_max:
        advancing_steps += 1
        running_max = current_value

    if running_max >= _CUMULATIVE_MIN_TIER and advancing_steps >= _CUMULATIVE_MIN_STEPS:
        return _CUMULATIVE_SCORE, (
            f"Cumulative escalation: tier {running_max} reached across "
            f"{advancing_steps} advancing steps"
        )

    return 0.0, ""
