"""CSS anchor parser using regex-based rule detection."""

from __future__ import annotations

import logging
import re

from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier

logger = logging.getLogger(__name__)

_MEDIA_RE = re.compile(r'@media\s*\(([^)]+)\)\s*\{', re.MULTILINE)
_KEYFRAMES_RE = re.compile(r'@keyframes\s+(\w+)\s*\{', re.MULTILINE)
_ID_SELECTOR_RE = re.compile(r'#([\w-]+)\s*[,{]')
_COMMENT_SECTION_RE = re.compile(r'/\*\s*(.+?)\s*\*/', re.DOTALL)


def parse_css_anchors(content: str) -> list[AnchorEntry]:
    """Parse CSS and return anchor candidates at all tiers.

    Returns an empty list on parse failure (fail-safe).
    """
    if not content.strip():
        return []

    anchors: list[AnchorEntry] = []
    seen_names: set[str] = set()

    try:
        # @keyframes blocks (BLOCK tier)
        for match in _KEYFRAMES_RE.finditer(content):
            name = f"keyframes-{match.group(1)}"
            if name not in seen_names:
                seen_names.add(name)
                anchors.append(AnchorEntry(
                    name=name,
                    line=content[:match.start()].count("\n") + 1,
                    tier=AnchorTier.BLOCK,
                    description=f"@keyframes {match.group(1)} animation",
                    has_end=True,
                ))

        # @media blocks (BLOCK tier)
        for match in _MEDIA_RE.finditer(content):
            condition = match.group(1).strip()
            # Simplify condition for name
            simple = re.sub(r'[^a-zA-Z0-9]+', '-', condition).strip('-').lower()
            name = f"media-{simple}"
            if name not in seen_names:
                seen_names.add(name)
                anchors.append(AnchorEntry(
                    name=name,
                    line=content[:match.start()].count("\n") + 1,
                    tier=AnchorTier.BLOCK,
                    description=f"@media ({condition})",
                    has_end=True,
                ))

        # ID selector rules (BLOCK tier)
        for match in _ID_SELECTOR_RE.finditer(content):
            selector_id = match.group(1)
            name = f"styles-{selector_id}"
            if name not in seen_names:
                seen_names.add(name)
                anchors.append(AnchorEntry(
                    name=name,
                    line=content[:match.start()].count("\n") + 1,
                    tier=AnchorTier.BLOCK,
                    description=f"CSS rules for #{selector_id}",
                    has_end=False,
                ))

        # Comment-delimited sections (SECTION tier)
        # Split by blank lines, check if a section starts with a comment
        sections = re.split(r'\n\s*\n', content)
        section_num = 0
        for section in sections:
            section = section.strip()
            if not section:
                continue
            section_num += 1
            comment_match = _COMMENT_SECTION_RE.match(section)
            if comment_match:
                label = comment_match.group(1).strip().lower()
                label = re.sub(r'[^a-z0-9]+', '-', label).strip('-')
                if label and label not in seen_names:
                    seen_names.add(label)
                    anchors.append(AnchorEntry(
                        name=label,
                        line=0,
                        tier=AnchorTier.SECTION,
                        description=f"CSS section: {comment_match.group(1).strip()}",
                        has_end=False,
                    ))

    except Exception as exc:
        logger.warning("css_anchor_parse_failed", exc_info=exc)
        return []

    return anchors
