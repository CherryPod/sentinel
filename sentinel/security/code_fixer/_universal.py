"""Universal normalisation and prose stripping.

fix_universal: BOM removal, CRLF, trailing whitespace, trailing newline.
strip_prose: Remove conversational prose LLMs prepend to code output.
"""
import logging
import re

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prose detection patterns — match LLM conversational preamble
# ---------------------------------------------------------------------------

# IMPORTANT: These only match at the START of lines and must be full-line
# matches. A pattern like "Here's" would false-positive on code containing
# that word in a string — the anchored patterns below prevent this.
_PROSE_PATTERNS = [
    re.compile(r"^Here(?:'s| is) (?:the|a|an|your) .+:?\s*$", re.IGNORECASE),
    re.compile(r"^Sure[,!].+:?\s*$", re.IGNORECASE),
    re.compile(r"^I(?:'ve| have) (?:created|written|made|updated).+:?\s*$", re.IGNORECASE),
    re.compile(r"^This (?:code|script|file|function|program|module).+:?\s*$", re.IGNORECASE),
    re.compile(r"^Let me .+:?\s*$", re.IGNORECASE),
    re.compile(r"^The (?:following|above|below).+:?\s*$", re.IGNORECASE),
    re.compile(r"^Updated (?:code|file|version).+:?\s*$", re.IGNORECASE),
    re.compile(r"^(?:Here you go|Certainly|Of course)[.!,].+$", re.IGNORECASE),
    re.compile(r"^I'll .+:?\s*$", re.IGNORECASE),
    re.compile(r"^Below is .+:?\s*$", re.IGNORECASE),
]

# How many leading lines to check for prose. LLMs put preamble at the top,
# not scattered through the file. Limiting this prevents false positives on
# code that happens to contain prose-like comments deep in the file.
_PROSE_SCAN_LIMIT = 5


# ---------------------------------------------------------------------------
# Layer 1: Universal normalisation (all file types)
# ---------------------------------------------------------------------------

def fix_universal(content: str) -> FixResult:
    """BOM removal, CRLF, trailing whitespace, trailing newline.

    These are safe for ALL text file types. They never change meaning.
    """
    result = FixResult(content=content)
    original = content

    # BOM removal (UTF-8 BOM is unnecessary and causes issues with shebangs,
    # JSON parsers, and many other tools)
    if content.startswith("\ufeff"):
        content = content[1:]
        result.fixes_applied.append("Removed BOM")

    # CRLF -> LF (normalise to Unix line endings — container is Linux)
    if "\r\n" in content:
        content = content.replace("\r\n", "\n")
        result.fixes_applied.append("CRLF -> LF")

    # Trailing whitespace per line (never meaningful in any language)
    lines = content.split("\n")
    stripped = [line.rstrip() for line in lines]
    if lines != stripped:
        content = "\n".join(stripped)
        result.fixes_applied.append("Stripped trailing whitespace")

    # Trailing newline (POSIX: text files end with newline)
    if content and not content.endswith("\n"):
        content += "\n"
        result.fixes_applied.append("Added trailing newline")

    result.content = content
    result.changed = content != original

    if result.changed:
        logger.debug(
            "Universal fixes applied",
            extra={
                "event": "fixer_applied",
                "fixer": "fix_universal",
                "file": _current_filename.get(),
                "fix_description": ", ".join(result.fixes_applied),
                "len_before": len(original),
                "len_after": len(content),
            },
        )

    return result


# ---------------------------------------------------------------------------
# Layer 2: Prose stripping (code files only)
# ---------------------------------------------------------------------------

def strip_prose(content: str) -> FixResult:
    """Remove conversational prose that LLMs prepend to code output.

    Only scans the first few lines. Only removes lines that match known
    prose patterns AND are not indented (indented lines are code).

    Finding #44: removed unused ``language`` parameter — the function
    never used it.
    """
    result = FixResult(content=content)
    lines = content.split("\n")
    removed = []
    clean_lines = []
    prose_zone = True  # only strip consecutive prose at the start

    for i, line in enumerate(lines):
        if prose_zone and i < _PROSE_SCAN_LIMIT:
            stripped = line.strip()
            # Skip blank lines at the start (they're between prose and code)
            if not stripped:
                clean_lines.append(line)
                continue
            # Only match non-indented lines (indented = code)
            if line == stripped and any(p.match(stripped) for p in _PROSE_PATTERNS):
                removed.append(stripped)
                continue
            else:
                prose_zone = False  # first non-prose line ends the zone
        clean_lines.append(line)

    if removed:
        # Strip any blank lines that were between prose and code
        while clean_lines and not clean_lines[0].strip():
            clean_lines.pop(0)
        content = "\n".join(clean_lines)
        result.fixes_applied.append(f"Stripped {len(removed)} prose line(s)")
        result.content = content
        result.changed = True

        logger.debug(
            "Prose lines stripped",
            extra={
                "event": "fixer_applied",
                "fixer": "strip_prose",
                "file": _current_filename.get(),
                "lines_removed": len(removed),
                "removed_text": removed,
            },
        )

    return result
