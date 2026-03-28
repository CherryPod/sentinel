"""Shell/Bash anchor parser using regex-based detection."""

from __future__ import annotations

import logging
import re

from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier

logger = logging.getLogger(__name__)

_SHEBANG_RE = re.compile(r'^#!.+\n', re.MULTILINE)
_FUNC_RE = re.compile(r'^(\w+)\s*\(\)\s*\{', re.MULTILINE)
_SECTION_COMMENT_RE = re.compile(r'^##?\s*[-=]{3,}\s*(.+)?', re.MULTILINE)


def parse_shell_anchors(content: str) -> list[AnchorEntry]:
    """Parse Shell/Bash and return anchor candidates at all tiers.

    Returns an empty list on parse failure (fail-safe).
    """
    if not content.strip():
        return []

    anchors: list[AnchorEntry] = []

    try:
        # Shebang (SECTION tier)
        if _SHEBANG_RE.match(content):
            anchors.append(AnchorEntry(
                name="shebang",
                line=1,
                tier=AnchorTier.SECTION,
                description="After shebang line",
                has_end=False,
            ))

        # Function definitions (BLOCK tier)
        for match in _FUNC_RE.finditer(content):
            func_name = match.group(1)
            anchors.append(AnchorEntry(
                name=f"func-{func_name}",
                line=content[:match.start()].count("\n") + 1,
                tier=AnchorTier.BLOCK,
                description=f"Shell function {func_name}()",
                has_end=True,
            ))

        # Comment-delimited sections (SECTION tier)
        for match in _SECTION_COMMENT_RE.finditer(content):
            label = match.group(1)
            if label:
                label = label.strip().lower()
                label = re.sub(r'[^a-z0-9]+', '-', label).strip('-')
                if label:
                    anchors.append(AnchorEntry(
                        name=f"section-{label}",
                        line=content[:match.start()].count("\n") + 1,
                        tier=AnchorTier.SECTION,
                        description=f"Shell section: {match.group(1).strip()}",
                        has_end=False,
                    ))

    except Exception as exc:
        logger.warning("shell_anchor_parse_failed", exc_info=exc)
        return []

    return anchors
