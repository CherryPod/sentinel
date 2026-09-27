"""S7: Topic shift signal extractor.

Detects shifts from benign topics (code/text/question) to system/file operations.
Extracted from ConversationAnalyzer._check_topic_shift().

Design doc fix: increase max score from 1.5 to 2.5.
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import SignalResult
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Topic categories (from legacy) ─────────────────────────────

TOPIC_CATEGORIES: dict[str, list[re.Pattern[str]]] = {
    "code": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "write code",
            "function",
            "class",
            "implement",
            "refactor",
            "debug",
            "algorithm",
            "variable",
        ]
    ],
    "text": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "write",
            "essay",
            "summarize",
            "translate",
            "explain",
            "describe",
            "poem",
            "story",
        ]
    ],
    "file": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "file",
            "directory",
            "path",
            "read file",
            "list files",
            "contents of",
        ]
    ],
    "system": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "execute",
            "run",
            "bash",
            "shell",
            "command",
            "sudo",
            "process",
            "kill",
            "service",
        ]
    ],
    "question": [
        re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
        for kw in [
            "what is",
            "how does",
            "why",
            "can you explain",
            "tell me about",
            "help me understand",
        ]
    ],
}

# Benign starting categories that trigger shift detection
_BENIGN_CATEGORIES = frozenset({"code", "text", "question"})

# Target categories that represent a concerning shift
_TARGET_CATEGORIES = frozenset({"system", "file"})

# Design doc fix: increased from 1.5 to 2.5
_SHIFT_SCORE = 2.5

# Minimum prior turns needed
_MIN_PRIOR_TURNS = 2

# How many early turns to inspect for starting topic
_EARLY_TURN_WINDOW = 3


def check_topic_shift(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S7: Detect shifts from benign topics to system/file operations.

    Score: 2.5 if session started with code/text/question and shifts
    to system/file requests. Requires at least 2 prior turns.

    Returns SignalResult with category 'topic_shift'.
    """
    logger.debug(
        "check_topic_shift called",
        extra={
            "event": "signals.topic_shift.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    if len(session.turns) < _MIN_PRIOR_TURNS:
        return SignalResult(score=0.0, categories=frozenset(), details=())

    current_cat = _classify_topic(request)
    if current_cat not in _TARGET_CATEGORIES:
        return SignalResult(score=0.0, categories=frozenset(), details=())

    # Check if earlier turns were in benign categories
    early_categories: set[str] = set()
    for turn in session.turns[:_EARLY_TURN_WINDOW]:
        cat = _classify_topic(normalise_homoglyphs(turn.request_text))
        if cat:
            early_categories.add(cat)

    benign_start = bool(early_categories) and early_categories.issubset(
        _BENIGN_CATEGORIES
    )
    if benign_start:
        logger.info(
            "Topic shift detected",
            extra={
                "event": "signals.topic_shift.detected",
                "session_id": session.session_id,
                "from_categories": sorted(early_categories),
                "to_category": current_cat,
            },
        )
        return SignalResult(
            score=_SHIFT_SCORE,
            categories=frozenset({"topic_shift"}),
            details=(f"Topic shift from {early_categories} to {current_cat}",),
        )
    logger.debug(
        "check_topic_shift: benign_start_passed",
        extra={
            "event": "signals.topic_shift.detected.passed",
            "reason": "benign_start_passed",
        },
    )  # auto:neg

    return SignalResult(score=0.0, categories=frozenset(), details=())


def _classify_topic(text: str) -> str | None:
    """Classify text into a topic category. Returns highest-risk match.

    Priority order: system > file > code > text > question.
    """
    logger.debug(
        "_classify_topic called",
        extra={
            "event": "signals.topic_shift._classify_topic",
            "text_len": len(text),
        },
    )
    text_lower = text.lower()
    priority = ["system", "file", "code", "text", "question"]
    for cat in priority:
        patterns = TOPIC_CATEGORIES[cat]
        for pattern in patterns:
            if pattern.search(text_lower):
                return cat
    return None
