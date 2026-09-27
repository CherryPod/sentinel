"""CSS fixer module.

Handles: unclosed braces, missing semicolons before closing brace.

Moved from monolith lines 1546-1577. Finding fixes applied:
  #12: brace counting uses count_in_code("css") instead of naive count()
  #23: tracks brace depth to avoid inserting ; after nested block closers
"""

import logging

from ._core import (
    FixResult,
    _current_filename,
    count_in_code,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def fix_css(content: str) -> FixResult:
    """CSS fixes: unclosed braces, missing semicolons before closing brace."""
    result = FixResult(content=content)
    original = content
    fname = _current_filename.get()

    logger.debug(
        "CSS fixer starting",
        extra={
            "event": "css.fixer_start",
            "file": fname,
            "content_length": len(content),
        },
    )

    # Finding #12: use count_in_code to skip braces inside comments
    open_count = count_in_code(content, "css", "{")
    close_count = count_in_code(content, "css", "}")
    if open_count > close_count:
        diff = open_count - close_count
        content = content.rstrip("\n") + "\n" + ("}\n" * diff)
        result.fixes_applied.append(f"Closed {diff} unclosed brace(s)")
        logger.debug(
            "Closed unclosed CSS braces",
            extra={
                "event": "css.brace_fix",
                "fixer": "fix_css",
                "file": fname,
                "count": diff,
            },
        )
    else:
        logger.debug(
            "CSS braces balanced",
            extra={"event": "css.braces_balanced", "file": fname},
        )

    # Finding #23: Track brace depth to avoid inserting ; after nested block closers.
    # A line like "}" that closes a nested rule (e.g. @media inner rule) should
    # not get a semicolon. We track depth: if the line before } reduces depth
    # from > 1, it's a nested block closer, not a property line.
    lines = content.split("\n")
    fixed_lines = []
    depth = 0
    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track brace depth for this line — use count_in_code to skip
        # braces inside comments, consistent with the initial brace count above
        line_opens = count_in_code(stripped, "css", "{")
        line_closes = count_in_code(stripped, "css", "}")

        if stripped == "}":
            # This is a block closer — check previous non-empty line
            prev_idx = i - 1
            while prev_idx >= 0 and not fixed_lines[prev_idx].strip():
                prev_idx -= 1

            if prev_idx >= 0:
                prev_line = fixed_lines[prev_idx].rstrip()
                prev_stripped = prev_line.strip()
                # Only add ; if the previous line looks like a property
                # (not another block closer, not a block opener, and not
                # already ending with ; or {)
                if (
                    prev_stripped
                    and prev_stripped[-1] not in (";", "{", "}")
                    and depth <= 1
                ):
                    # This is a top-level block closer after a property line
                    fixed_lines[prev_idx] = prev_line + ";"

        fixed_lines.append(line)
        depth += line_opens - line_closes

    content = "\n".join(fixed_lines)
    if content != original and "semicolon" not in str(result.fixes_applied):
        result.fixes_applied.append("Added missing semicolons before }")
        logger.debug(
            "Added missing CSS semicolons",
            extra={
                "event": "css.semicolon_fix",
                "fixer": "fix_css",
                "file": fname,
            },
        )

    result.content = content
    result.changed = content != original
    return result
