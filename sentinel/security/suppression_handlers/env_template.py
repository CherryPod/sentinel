"""Suppression handler: env template files.

Suppresses ``.env`` matches that are actually ``.env.example``,
``.env.sample``, or ``.env.template`` — placeholder files without
real secrets.

Extracted from ``SensitivePathScanner._is_env_template``
(scanner.py:583-602).
"""

from __future__ import annotations

import logging

from sentinel.security._scan_context import (
    ScanContext,
    ScanMatch,
    decoded_variant_encoding_matches,
)
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)

_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template")
# Lookahead window after ".env" — longest suffix is ".template" (9 chars),
# rounded up for safety.
_MAX_SUFFIX_LOOKAHEAD = 12


class EnvTemplateHandler:
    """Suppress .env matches that are template files."""

    handler_id: str = "env_template"

    def evaluate(
        self,
        match: ScanMatch,
        context: ScanContext,
        params: dict | None = None,
    ) -> bool:
        """Return True if the match should be suppressed.

        Checks if the text after the match starts with a template suffix.
        """
        logger.debug(
            "Evaluating env template",
            extra={
                "event": "security.suppression.env_template.evaluate",
                "rule_id": match.rule_id,
                "offset": match.offset,
            },
        )

        # Only applies to .env pattern matches
        if match.matched_text != ".env":
            return False

        # For encoded matches, match.offset is in decoded-variant coordinate
        # space — check the decoded variant text, not normalised_text.
        if match.rule_id.startswith("encoded:"):
            end = match.offset + match.length
            for variant in context.decoded_variants:
                if not decoded_variant_encoding_matches(variant, match.rule_id):
                    continue
                normalised = normalise_homoglyphs(variant.decoded_text)
                if end <= len(normalised) and normalised[match.offset:end] == match.matched_text:
                    remaining = normalised[end : end + _MAX_SUFFIX_LOOKAHEAD]
                    for suffix in _ENV_TEMPLATE_SUFFIXES:
                        if remaining.startswith(suffix):
                            logger.debug(
                                "Env template: suppressed (encoded match)",
                                extra={
                                    "event": "security.suppression.env_template.suppressed",
                                    "suffix": suffix,
                                },
                            )
                            return True
                    return False
            if context.decoded_variants:
                logger.warning(
                    "Encoded match: no decoded variant found for env template lookup",
                    extra={
                        "event": "security.suppression.env_template.encoded_no_variant",
                        "rule_id": match.rule_id,
                        "offset": match.offset,
                    },
                )
            return False

        # Use normalised_text so that match.offset indexes the same string
        # that the scanner searched.  Fall back to raw_text for synthetic
        # contexts created without the preprocessor.
        text = context.normalised_text if context.normalised_text is not None else context.raw_text
        end = match.offset + match.length
        remaining = text[end : end + _MAX_SUFFIX_LOOKAHEAD]

        for suffix in _ENV_TEMPLATE_SUFFIXES:
            if remaining.startswith(suffix):
                logger.debug(
                    "Env template: suppressed",
                    extra={
                        "event": "security.suppression.env_template.suppressed",
                        "suffix": suffix,
                    },
                )
                return True

        return False
