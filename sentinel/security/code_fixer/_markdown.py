"""Markdown fixer.

Fixes common LLM mistakes in Markdown:
- Unclosed code fences (``` without matching ```)
- Unbalanced link syntax: [text](url  -> [text](url)
- Unbalanced image syntax: ![alt](src  -> ![alt](src)

Conservative: only fix clearly broken syntax. Don't touch inline backticks.
"""

import logging
import re

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)


def fix_markdown(content: str) -> FixResult:
    """Markdown fixes: unclosed code fences, unbalanced links/images."""
    result = FixResult(content=content)
    original = content
    fname = _current_filename.get()

    logger.debug(
        "Markdown fixer starting",
        extra={
            "event": "markdown.fixer_start",
            "file": fname,
            "content_length": len(content),
        },
    )

    # Finding #17 fix: close unclosed code fences, matching the backtick
    # count of the opening fence. We find all fence markers and pair them
    # by count: if there's an odd number, the last unpaired fence gets a
    # matching closer appended at EOF (the safest default for truncated
    # LLM output).
    #
    # Known limitation: even counts with mismatched positions (e.g. 4 opens,
    # 0 closes) are treated as 2 valid pairs and won't be fixed. Properly
    # distinguishing opener vs closer requires tracking language annotations
    # and indentation context, which isn't worth the complexity for LLM output.
    fence_pattern = re.compile(r"^(`{3,})", re.MULTILINE)
    fence_matches = list(fence_pattern.finditer(content))

    if len(fence_matches) % 2 != 0:
        # The last fence is the unclosed one. Match its backtick count
        # for the closing fence.
        last_opener = fence_matches[-1]
        backtick_count = len(last_opener.group(1))
        closing_fence = "`" * backtick_count

        content = content.rstrip("\n") + "\n" + closing_fence + "\n"
        result.fixes_applied.append("Closed unclosed code fence")

    # Image regex runs FIRST — it is more specific (![) and would otherwise
    # be consumed by the link regex (which matches [, a superset).
    # Finding #57 fix: simplified regex to prevent catastrophic backtracking.
    pre_image = content
    content = re.sub(
        r"!\[([^\]]*)\]\(([^)]+)\s*$",
        lambda m: m.group(0) + ")",
        content,
        flags=re.MULTILINE,
    )
    if content != pre_image:
        if "Closed unbalanced image syntax" not in result.fixes_applied:
            result.fixes_applied.append("Closed unbalanced image syntax")

    # Unbalanced link syntax: [text](url  -> [text](url)
    # Negative lookbehind (?<!!) prevents matching image links already
    # handled above.
    # Finding #27 fix: removed dead endswith(")") check.
    pre_link = content
    content = re.sub(
        r"(?<!!)\[([^\]]*)\]\(([^)]+)\s*$",
        lambda m: m.group(0) + ")",
        content,
        flags=re.MULTILINE,
    )
    if (
        content != pre_link
        and "Closed unbalanced link/image syntax" not in result.fixes_applied
    ):
        result.fixes_applied.append("Closed unbalanced link/image syntax")

    result.content = content
    result.changed = content != original

    if result.changed:
        logger.debug(
            "Markdown fixer applied changes",
            extra={
                "event": "markdown.fixer_done",
                "file": fname,
                "fix_description": ", ".join(result.fixes_applied),
            },
        )

    return result
