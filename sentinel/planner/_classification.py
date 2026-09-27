"""Task category classification — deterministic vs structural vs semantic.

Extracted from verification.py during planner modularisation (Phase 3).
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Patterns suggesting deterministic verifiability (specific values/targets)
_DETERMINISTIC_PATTERNS = [
    re.compile(r"(change|set|update|modify).*(to|=)\s*\S+", re.IGNORECASE),
    re.compile(r"(send|email|message)\s+.*(to)\s+\S+", re.IGNORECASE),
    re.compile(
        r"(port|colour|color|font|size|width|height)\s*[:=]\s*\S+", re.IGNORECASE
    ),
    re.compile(r"#[0-9a-fA-F]{3,8}\b"),  # hex colour
    re.compile(r"\b\d+px\b|\b\d+rem\b|\b\d+em\b"),  # CSS units
]

# Patterns suggesting structural expectations (concrete elements, not specific values)
_STRUCTURAL_PATTERNS = [
    re.compile(
        r"\b(add|create|build|insert)\s+(a\s+)?(\w+\s+)*(form|table|list|menu|nav|header|footer|sidebar|button|input|modal|card)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(add|create)\s+(a\s+)?(\w+\s+)*(page|section|component)\b", re.IGNORECASE
    ),
]

# Patterns suggesting irreducibly semantic tasks
_SEMANTIC_PATTERNS = [
    re.compile(
        r"\b(better|improve|enhance|professional|clean|modern|nice|good)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(fix the tone|refactor for clarity|make it look)\b", re.IGNORECASE),
]


WEAK_TYPES = frozenset({"file_exists", "file_not_empty"})


def classify_task_category(
    user_request: str,
    assertions: list[dict] | None = None,
) -> str:
    """Classify a task as deterministic, structural, or semantic.

    Uses two signals:
    1. Request text patterns
    2. Assertion diversity (>= 2 strong assertion types push toward deterministic)

    Returns: "deterministic", "structural", or "semantic"
    """
    # Diversity gate: only override to deterministic when assertions span
    # >= 2 strong types (excluding weak types like file_exists/file_not_empty)
    if assertions:
        all_types = {a["assert"] for a in assertions}
        strong_types = all_types - WEAK_TYPES
        weak_present = sorted(all_types & WEAK_TYPES)
        if len(strong_types) >= 2:
            logger.debug(
                "Diversity gate: PASS — %d strong types (%s), threshold=2. "
                "Weak excluded: %s",
                len(strong_types),
                sorted(strong_types),
                weak_present,
                extra={
                    "event": "task.classify.diversity_pass",
                    "category": "deterministic",
                    "strong_types": sorted(strong_types),
                    "strong_count": len(strong_types),
                    "weak_excluded": weak_present,
                    "total_assertions": len(assertions),
                },
            )
            return "deterministic"
        logger.debug(
            "Diversity gate: FAIL — %d strong type(s) (%s), threshold=2. "
            "Total assertions: %d, weak-only: %s. "
            "Falling through to text patterns",
            len(strong_types),
            sorted(strong_types),
            len(assertions),
            weak_present,
            extra={
                "event": "task.classify.diversity_fail",
                "strong_types": sorted(strong_types),
                "strong_count": len(strong_types),
                "weak_excluded": weak_present,
                "total_assertions": len(assertions),
            },
        )

    # Check patterns in priority order
    for pattern in _DETERMINISTIC_PATTERNS:
        if pattern.search(user_request):
            logger.debug(
                "Task classification: deterministic (pattern match: %s)",
                pattern.pattern[:60],
                extra={
                    "event": "task.classify",
                    "category": "deterministic",
                    "reason": "pattern",
                    "pattern": pattern.pattern[:60],
                },
            )
            return "deterministic"

    for pattern in _SEMANTIC_PATTERNS:
        if pattern.search(user_request):
            logger.debug(
                "Task classification: semantic (pattern match: %s)",
                pattern.pattern[:60],
                extra={
                    "event": "task.classify",
                    "category": "semantic",
                    "reason": "pattern",
                    "pattern": pattern.pattern[:60],
                },
            )
            return "semantic"

    for pattern in _STRUCTURAL_PATTERNS:
        if pattern.search(user_request):
            logger.debug(
                "Task classification: structural (pattern match: %s)",
                pattern.pattern[:60],
                extra={
                    "event": "task.classify",
                    "category": "structural",
                    "reason": "pattern",
                    "pattern": pattern.pattern[:60],
                },
            )
            return "structural"

    # Default: if we have at least one assertion, treat as deterministic
    if assertions and len(assertions) >= 1:
        logger.debug(
            "Task classification: deterministic (assertions present, no pattern match)",
            extra={
                "event": "task.classify",
                "category": "deterministic",
                "reason": "assertions_present",
                "assertion_count": len(assertions),
            },
        )
        return "deterministic"

    # No patterns matched, no assertions — assume semantic (safer to verify)
    logger.debug(
        "Task classification: semantic (default — no patterns, no assertions)",
        extra={"event": "task.classify", "category": "semantic", "reason": "default"},
    )
    return "semantic"
