"""Suppression handler: placeholder values.

Suppresses credential matches where the matched value is a known
placeholder (e.g. "changeme", "AKIAIOSFODNN7EXAMPLE", "password123").
Tutorials, ``.env.example`` files, and documentation use these.

Extracted from ``CredentialScanner.scan`` placeholder logic
(scanner.py:279-303).
"""

from __future__ import annotations

import logging
import re

from sentinel.security._scan_context import ScanContext, ScanMatch

logger = logging.getLogger(__name__)

# Values (case-insensitive) that indicate a placeholder via starts-with.
# "changeme" matches "changeme" and "changeme123" but NOT
# "realpasswordchangeme".
_PLACEHOLDER_PREFIXES = (
    "changeme",
    "replace",
    "placeholder",
    "example",
    "todo",
    "xxxxxxxx",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "fakekey",
    "dummy",
    "sample",
    "your-",
    "your_",
    "<replace",
    "<your",
    "insert-",
    "insert_",
    "put-your",
    "put_your",
    "fill-in",
)

# Suffix matching uses a restricted set to minimise false negatives.
_PLACEHOLDER_SUFFIXES = (
    "examplekey",
    "placeholder",
    "replace_me",
    "change_me",
)

# Values that suppress ONLY as exact matches (case-insensitive).
_PLACEHOLDER_EXACT = frozenset(
    {
        "password",
        "password123",
        "secret12",
        "12345678",
        "test1234",
    }
)


class PlaceholderValuesHandler:
    """Suppress matches where the credential value is a placeholder."""

    handler_id: str = "placeholder_values"

    def evaluate(
        self,
        match: ScanMatch,
        context: ScanContext,
        params: dict | None = None,
    ) -> bool:
        """Return True if the match should be suppressed.

        Extracts the value portion (after = or :), checks against
        prefix/suffix/exact lists and any rule-specific known_examples.
        """
        logger.debug(
            "Evaluating placeholder values",
            extra={
                "event": "security.suppression.placeholder_values.evaluate",
                "rule_id": match.rule_id,
                "offset": match.offset,
            },
        )

        matched_text = match.matched_text

        # Extract the value portion (after = or :)
        value_part = re.split(r"[=:]+", matched_text, maxsplit=1)[-1]
        value_lower = value_part.strip().strip("'\"").lower()

        if not value_lower:
            return False

        # Check exact matches
        if value_lower in _PLACEHOLDER_EXACT:
            logger.debug(
                "Placeholder: exact match",
                extra={
                    "event": "security.suppression.placeholder_values.suppressed",
                    "reason": "exact_match",
                },
            )
            return True
        logger.debug(
            "Placeholder: exact match not found",
            extra={
                "event": "security.suppression.placeholder_values.not_suppressed",
                "reason": "no_exact_match",
            },
        )  # auto:neg

        # Check prefix matches
        if value_lower.startswith(_PLACEHOLDER_PREFIXES):
            logger.debug(
                "Placeholder: prefix match",
                extra={
                    "event": "security.suppression.placeholder_values.suppressed",
                    "reason": "prefix_match",
                },
            )
            return True
        logger.debug(
            "Placeholder: prefix match not found",
            extra={
                "event": "security.suppression.placeholder_values.not_suppressed",
                "reason": "no_prefix_match",
            },
        )  # auto:neg

        # Check suffix matches
        if value_lower.endswith(_PLACEHOLDER_SUFFIXES):
            logger.debug(
                "Placeholder: suffix match",
                extra={
                    "event": "security.suppression.placeholder_values.suppressed",
                    "reason": "suffix_match",
                },
            )
            return True

        # Check rule-specific known examples (e.g. AKIAIOSFODNN7EXAMPLE)
        if params and "known_examples" in params:
            known = params["known_examples"]
            if isinstance(known, list) and matched_text in known:
                logger.debug(
                    "Placeholder: known example",
                    extra={
                        "event": "security.suppression.placeholder_values.suppressed",
                        "reason": "known_example",
                    },
                )
                return True

        return False
