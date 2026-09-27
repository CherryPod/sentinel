"""Suppression handler: educational context.

Suppresses sensitive-path matches that appear in genuine educational
questions (e.g. "What's the format of /etc/passwd?") when the
surrounding text does NOT contain file-operation commands or
access-intent phrases.

Extracted from ``SensitivePathScanner._is_educational_input``
(scanner.py:620-682).
"""

from __future__ import annotations

import logging
import re

from sentinel.security._scan_context import (
    ScanContext,
    ScanMatch,
    decoded_variant_encoding_matches,
)
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)

# Educational question indicators — genuine questions about paths.
# "Can you..." / "Could you..." are excluded because they frame
# ACTION requests, not knowledge questions.
_QUESTION_RE = re.compile(
    r"(?:"
    r"(?:^|\n)\s*(?:what|how|why|where|when)[\s']"
    r"|(?:^|\n)\s*(?:explain|describe)\s"
    r"|(?:^|\n)\s*i\s+(?:need|want)\s+to\s+(?:understand|learn|know)\b"
    r"|\bwhat[\s']+(?:is|does|are|do|s\b)"
    r"|\bhow[\s']+(?:do|does|is|are|can|should|s\b)"
    r"|\bformat\s+of\b|\bstructure\s+of\b|\bfield\s+(?:structure|format)\b"
    r"|\bdifference\s+between\b"
    r")",
    re.IGNORECASE,
)

# Operational verbs/phrases NEAR a sensitive path — indicate the path
# is a target of action, not a topic of discussion.
_FILE_OP_CMD_RE = re.compile(
    r"\b(?:"
    r"cat|less|more|head|tail|nano|vi|vim|"
    r"rm|chmod|chown|cp|mv|mkdir|touch|scp|rsync|"
    r"curl|wget|nc\b|ncat|netcat|socat|telnet|"
    r"base64|xxd|strings|"
    r"read(?:ing)?|access(?:ing)?|send(?:ing)?|steal(?:ing)?|"
    r"dump(?:ing)?|extract(?:ing)?|exfil(?:trat(?:e|ing))?|"
    r"download(?:ing)?|upload(?:ing)?|writ(?:e|ing)|"
    r"append(?:ing)?|delet(?:e|ing)|"
    r"show(?:ing)?|display(?:ing)?|print(?:ing)?|"
    r"output(?:ting)?|check(?:ing)?|retriev(?:e|ing)|fetch(?:ing)?"
    r")\b",
    re.IGNORECASE,
)

# Phrases that indicate path access intent even without a single-word
# command verb.
_ACCESS_PHRASE_RE = re.compile(
    r"\bcontents?\s+of\b"
    r"|\bexists?\b.*\bshow\b"
    r"|\bwhat(?:'s|s| is)\s+in\s+[/~.]"
    r"|\bshow\s+me\b"
    r"|\bhelp\s+me\s+(?:with\s+)?(?:read|access|check|show)",
    re.IGNORECASE,
)


def _text_for_match(match: ScanMatch, context: ScanContext) -> str:
    """Return the text whose coordinate space contains match.offset.

    Plain matches carry offsets into normalised_text (homoglyph-normalised
    main text).  Encoded matches (rule_id prefixed ``encoded:<enc>:``) carry
    offsets into the normalised decoded-variant text produced by the scanner,
    NOT into normalised_text.  Find the variant whose text contains the
    matched content at the declared offset; fall back to the main text when
    no variant is found (e.g. synthetic test contexts with empty decoded_variants).
    """
    if match.rule_id.startswith("encoded:"):
        end = match.offset + match.length
        for variant in context.decoded_variants:
            if not decoded_variant_encoding_matches(variant, match.rule_id):
                continue
            normalised = normalise_homoglyphs(variant.decoded_text)
            if end <= len(normalised) and normalised[match.offset:end] == match.matched_text:
                return normalised
        if context.decoded_variants:
            logger.warning(
                "Encoded match: no decoded variant found for offset — falling back to main text",
                extra={
                    "event": "security.suppression.educational_context.encoded_fallback",
                    "rule_id": match.rule_id,
                    "offset": match.offset,
                },
            )
    return context.normalised_text if context.normalised_text is not None else context.raw_text


class EducationalContextHandler:
    """Suppress matches in genuine educational/question contexts."""

    handler_id: str = "educational_context"

    def evaluate(
        self,
        match: ScanMatch,
        context: ScanContext,
        params: dict | None = None,
    ) -> bool:
        """Return True if the match should be suppressed.

        Checks: full text has question indicator + match line has no
        file operation verbs + no access phrases.
        """
        logger.debug(
            "Evaluating educational context",
            extra={
                "event": "security.suppression.educational_context.evaluate",
                "rule_id": match.rule_id,
                "offset": match.offset,
            },
        )

        # Use the text whose coordinate space contains match.offset.
        # Encoded matches carry offsets into the decoded-variant text, not
        # normalised_text; _text_for_match resolves the right string.
        text = _text_for_match(match, context)
        pos = match.offset

        # Step 1: full text must contain an educational question indicator
        if not _QUESTION_RE.search(text):
            return False

        # Step 2: extract the line containing the path match
        line_start = text.rfind("\n", 0, pos) + 1
        line_end = text.find("\n", pos)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]

        # Step 3: the path's line must NOT contain file-operation commands
        if _FILE_OP_CMD_RE.search(line):
            logger.debug(
                "Educational context: operational command on path line",
                extra={
                    "event": "security.suppression.educational_context.operational_cmd",
                    "reason": "file_op_on_path_line",
                },
            )
            return False
        logger.debug(
            "Educational context: no file-op command on match line",
            extra={
                "event": "security.suppression.educational_context.no_file_op",
                "reason": "line_clean",
            },
        )  # auto:neg

        # Step 4: check for access-intent phrases in the full text
        if _ACCESS_PHRASE_RE.search(text):
            logger.debug(
                "Educational context: access-intent phrase in text",
                extra={
                    "event": "security.suppression.educational_context.access_phrase",
                    "reason": "access_intent_phrase",
                },
            )
            return False

        logger.debug(
            "Educational context: suppressed (question context, no operational commands)",
            extra={
                "event": "security.suppression.educational_context.suppressed",
                "reason": "educational_question_context",
            },
        )
        return True
