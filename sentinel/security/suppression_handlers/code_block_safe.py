"""Suppression handler: code-block-safe paths.

Suppresses known-safe paths inside non-shell code blocks.  Paths like
``/etc/passwd`` commonly appear in legitimate infrastructure code
(Terraform, Ansible, Containerfiles) and should not be flagged inside
code blocks unless the block is tagged as a shell language.

Extracted from ``SensitivePathScanner._CODE_BLOCK_SAFE`` and
``_SHELL_LANG_TAGS`` (scanner.py:542-576).
"""

from __future__ import annotations

import logging

from sentinel.security._enums import RegionType
from sentinel.security._scan_context import (
    ContextRegion,
    ScanContext,
    ScanMatch,
    decoded_variant_encoding_matches,
)
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)

# Paths safe to skip inside fenced code blocks (non-shell).
# These commonly appear in infrastructure/monitoring code.
_CODE_BLOCK_SAFE: frozenset[str] = frozenset(
    {
        "/etc/passwd",
        "/proc/",
        "/sys/",
        ".config/",
        ".local/share/",
    }
)

# Language tags treated as shell — ALL lines in these blocks are
# operational context.  Matches in shell-tagged blocks are NOT
# suppressed (they remain flagged).
_SHELL_LANG_TAGS: frozenset[str] = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "shell",
        "console",
        "terminal",
        "powershell",
        "ps1",
        "pwsh",
        "bat",
        "cmd",
    }
)


class CodeBlockSafeHandler:
    """Suppress known-safe paths inside non-shell code blocks."""

    handler_id: str = "code_block_safe"

    def evaluate(
        self,
        match: ScanMatch,
        context: ScanContext,
        params: dict | None = None,
    ) -> bool:
        """Return True if the match should be suppressed.

        Checks: match is in a CODE_BLOCK region AND (path in
        _CODE_BLOCK_SAFE OR language tag NOT in _SHELL_LANG_TAGS).
        """
        logger.debug(
            "Evaluating code block safe",
            extra={
                "event": "security.suppression.code_block_safe.evaluate",
                "rule_id": match.rule_id,
                "offset": match.offset,
            },
        )

        # Find enclosing region for this match
        region = _find_enclosing_region(match, context)
        if region is None:
            return False

        # Must be in a code block
        if region.region_type != RegionType.CODE_BLOCK:
            return False

        # Shell-tagged code blocks are NOT suppressed — they're operational
        lang = (region.language_tag or "").lower()
        if lang in _SHELL_LANG_TAGS:
            return False

        # Check if the matched path is in the safe set
        matched = match.matched_text
        matching_safe_key = next(
            (safe for safe in _CODE_BLOCK_SAFE if safe in matched), None
        )
        if matching_safe_key is not None:
            logger.debug(
                "Code block safe: suppressed (safe path in non-shell block)",
                extra={
                    "event": "security.suppression.code_block_safe.suppressed",
                    "safe_key": matching_safe_key,
                    "lang": lang,
                },
            )
            return True

        return False


def _find_enclosing_region(
    match: ScanMatch, context: ScanContext
) -> ContextRegion | None:
    """Find the ContextRegion enclosing the match offset.

    Uses the match's own ``region`` field first (set by scanner).  For
    encoded matches (rule_id prefixed ``encoded:<enc>:``) match.offset is
    in decoded-variant space — find the variant and use
    ``variant.original_span[0]`` as a proxy for the blob's position in
    normalised_text space to look up the enclosing region.
    """
    if match.region is not None:
        return match.region

    if match.rule_id.startswith("encoded:"):
        end = match.offset + match.length
        for variant in context.decoded_variants:
            if not decoded_variant_encoding_matches(variant, match.rule_id):
                continue
            normalised_variant = normalise_homoglyphs(variant.decoded_text)
            if end <= len(normalised_variant) and normalised_variant[match.offset:end] == match.matched_text:
                blob_start = variant.original_span[0]
                for region in context.regions:
                    if region.start <= blob_start < region.end:
                        return region
                return None
        if context.decoded_variants:
            logger.warning(
                "Encoded match: no decoded variant found for enclosing region lookup",
                extra={
                    "event": "security.suppression.code_block_safe.encoded_no_variant",
                    "rule_id": match.rule_id,
                    "offset": match.offset,
                },
            )
        return None

    for region in context.regions:
        if region.start <= match.offset < region.end:
            return region

    return None
