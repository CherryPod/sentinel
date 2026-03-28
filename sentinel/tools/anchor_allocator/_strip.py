"""Strip existing anchor markers from file content for idempotent re-allocation."""

from __future__ import annotations

import re

# Patterns match anchor markers that are the ONLY content on their line
# (after optional leading whitespace). This avoids stripping anchors
# inside string literals like: x = "# anchor: fake"
_STRIP_PATTERNS = [
    re.compile(r'^[ \t]*<!--[ \t]*anchor:[ \t]*[\w.-]+[ \t]*-->[ \t]*\n?', re.MULTILINE),
    re.compile(r'^[ \t]*#[ \t]*anchor:[ \t]*[\w.-]+[ \t]*\n?', re.MULTILINE),
    re.compile(r'^[ \t]*//[ \t]*anchor:[ \t]*[\w.-]+[ \t]*\n?', re.MULTILINE),
    re.compile(r'^[ \t]*/\*[ \t]*anchor:[ \t]*[\w.-]+[ \t]*\*/[ \t]*\n?', re.MULTILINE),
]

# Collapse triple+ blank lines left after stripping to double blank lines
_MULTI_BLANK = re.compile(r'\n{3,}')


def strip_anchors(content: str) -> tuple[str, int]:
    """Remove all anchor markers from content.

    Returns:
        (stripped_content, count_removed)
    """
    total_removed = 0
    for pattern in _STRIP_PATTERNS:
        content, n = pattern.subn("", content)
        total_removed += n

    # Clean up blank lines left by removal
    if total_removed > 0:
        content = _MULTI_BLANK.sub("\n\n", content)

    return content, total_removed
