"""Shared context classification for scanner output text.

Determines the context type (code block, shell line, prose, etc.) for a
given position in scanner output text.  Used by SensitivePathScanner and
CommandPatternScanner to make consistent classification decisions.

The classifier answers "what context is this?" — the scanner decides
"should I flag or skip?" based on its own exemption rules.

Also provides ``classify_regions()`` which segments entire text into
non-overlapping ``ContextRegion`` objects (from ``_scan_context.py``)
for the new ``ScanContext``-based pipeline.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass

from sentinel.security._enums import RegionType
from sentinel.security._scan_context import ContextRegion as PipelineContextRegion
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)

# ── Shared constants (canonical definitions) ──────────────────────────

# Fenced code blocks: ```lang\n...\n```
# Group 1 = language tag (may be empty), Group 2 = block content.
CODE_FENCE_RE = re.compile(r"```(\w*)\s*\n(.*?)```", re.DOTALL)

# Language tags treated as shell — ALL lines in these blocks are
# operational context, not educational.
SHELL_LANG_TAGS = frozenset(
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

# Shell command prefixes that indicate operational context on a line.
SHELL_PREFIXES = re.compile(
    r"^\s*(?:\$|#|sudo|"
    r"cat|rm|chmod|chown|ls|cp|mv|mkdir|touch|head|tail|less|more|nano|vi|vim|"
    r"source|scp|grep|curl|wget|tar|ssh|bash|sh|zsh|"
    r"python[23]?|perl|ruby|node|"
    r"powershell|pwsh|php|"
    r"find|xargs|sed|awk|sort|uniq|tee|"
    r"socat|telnet|openssl|nc|ncat|netcat"
    r")\s",
    re.IGNORECASE,
)

# Command-line prefixes (broader set for CommandPatternScanner).
CMD_LINE_PREFIX = re.compile(
    r"^\s*(?:"
    r"\$\s|#!\s*|"
    r"sudo\s|curl\s|wget\s|echo\s|printf\s|"
    r"nc\s|ncat\s|netcat\s|bash\s|sh\s|zsh\s|"
    r"nohup\s|crontab\s|"
    r"cat\s|rm\s|chmod\s|chown\s|cp\s|mv\s|"
    r"mkdir\s|touch\s|head\s|tail\s|"
    r"python[23]?\s|perl\s|ruby\s|"
    r"eval\s|exec\s|mkfifo\s|"
    r"powershell(?:\.exe)?\s|pwsh\s|"
    r"socat\s|telnet\s|openssl\s|php\s"
    r")",
    re.IGNORECASE,
)

# 4-space or tab indented lines (markdown code blocks without fences).
INDENTED_LINE_RE = re.compile(r"^(?:    |\t).+", re.MULTILINE)


# ── Data classes ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class CodeBlockInfo:
    """Metadata for a fenced code block."""

    fence_start: int  # position of opening ```
    content_start: int  # position of first content char (after ```lang\n)
    content_end: int  # position just before closing ```
    fence_end: int  # position just after closing ``` (== regex match end)
    language: str  # lowercased language tag ("python", "bash", "")


@dataclass(frozen=True)
class ContextRegion:
    """Classification result for a position in text."""

    kind: str  # "fenced_code", "indented_code", "cmd_line", "prose"
    language: str  # fence language tag (empty if not in fenced block)
    is_shell: bool  # True if operational shell context
    line: str  # the full line containing the position
    line_start: int  # offset of line start in text
    block_content: str  # code block content text (empty if not in a block)
    block_info: CodeBlockInfo | None  # full block metadata (None if not in block)


# ── Preparation ───────────────────────────────────────────────────────


def prepare_text(text: str, strip_outer_fence: Callable[[str], str]) -> str:
    """Strip outer fence wrapper and normalise homoglyphs.

    Both scanners do this as their first step.  Centralising here
    ensures consistent preprocessing.
    """
    text = strip_outer_fence(text)
    text = normalise_homoglyphs(text)
    return text


# ── Building blocks ───────────────────────────────────────────────────


def build_code_blocks(text: str) -> list[CodeBlockInfo]:
    """Extract all fenced code blocks with metadata."""
    blocks = []
    for m in CODE_FENCE_RE.finditer(text):
        blocks.append(
            CodeBlockInfo(
                fence_start=m.start(),
                content_start=m.start(2),
                content_end=m.end(2),
                fence_end=m.end(),
                language=m.group(1).lower(),
            )
        )
    return blocks


def build_indented_ranges(text: str) -> list[tuple[int, int]]:
    """Extract ranges of indented (4-space/tab) code lines."""
    return [(m.start(), m.end()) for m in INDENTED_LINE_RE.finditer(text)]


# ── Classification ────────────────────────────────────────────────────


def classify(
    text: str,
    pos: int,
    code_blocks: list[CodeBlockInfo],
    indented_ranges: list[tuple[int, int]],
) -> ContextRegion:
    """Classify the context at a given position in text.

    Determines whether the position falls inside a fenced code block,
    an indented code block, a command-line-prefixed line, or prose.
    The fence line itself (```python) is considered part of its block
    so that language-anchored patterns can see the keyword.

    Args:
        text: The full scanner text (already preprocessed).
        pos: Character position of the match to classify.
        code_blocks: Pre-built list from build_code_blocks().
        indented_ranges: Pre-built list from build_indented_ranges().

    Returns:
        ContextRegion with kind, language, is_shell, line info, and
        block content (if applicable).
    """
    # Extract the line containing this position
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]

    # Check 1: inside a fenced code block (including fence line)
    for block in code_blocks:
        if block.fence_start <= pos < block.content_end:
            is_shell = (
                block.language in SHELL_LANG_TAGS
                or SHELL_PREFIXES.match(line) is not None
            )
            logger.info(
                "context=classify pos=%d kind=fenced_code lang=%s is_shell=%s",
                pos,
                block.language,
                is_shell,
            )
            return ContextRegion(
                kind="fenced_code",
                language=block.language,
                is_shell=is_shell,
                line=line,
                line_start=line_start,
                block_content=text[block.content_start : block.content_end],
                block_info=block,
            )

    # Check 2: inside an indented code block
    for start, end in indented_ranges:
        if start <= pos < end:
            is_shell = SHELL_PREFIXES.match(line) is not None
            logger.info(
                "context=classify pos=%d kind=indented_code is_shell=%s",
                pos,
                is_shell,
            )
            return ContextRegion(
                kind="indented_code",
                language="",
                is_shell=is_shell,
                line=line,
                line_start=line_start,
                block_content=line,
                block_info=None,
            )

    # Check 3: command-line prefix (shell prompt, shebang, command name)
    if CMD_LINE_PREFIX.match(line):
        logger.info("context=classify pos=%d kind=cmd_line", pos)
        return ContextRegion(
            kind="cmd_line",
            language="",
            is_shell=True,
            line=line,
            line_start=line_start,
            block_content="",
            block_info=None,
        )

    # Check 4: prose context (default fallthrough)
    logger.info("context=classify pos=%d kind=prose", pos)
    return ContextRegion(
        kind="prose",
        language="",
        is_shell=False,
        line=line,
        line_start=line_start,
        block_content="",
        block_info=None,
    )


# ── Region-based classification (new pipeline) ──────────────────────


def classify_regions(text: str) -> tuple[PipelineContextRegion, ...]:
    """Segment text into non-overlapping ``ContextRegion`` objects.

    Wraps existing ``build_code_blocks()`` and ``build_indented_ranges()``
    logic, maps to ``RegionType`` enums, and fills gaps with PROSE or
    SHELL regions (lines with command prefixes).

    Returns frozen ``PipelineContextRegion`` objects sorted by start offset,
    covering the entire text with no gaps or overlaps.
    """
    logger.debug(
        "classify_regions called",
        extra={
            "event": "security.context_classifier.classify_regions",
            "text_len": len(text),
        },
    )
    if not text:
        logger.debug(
            "classify_regions: not_text",
            extra={
                "event": "context_classifier.classify_regions.match",
                "reason": "not_text",
            },
        )  # auto:neg
        return ()

    # Collect classified spans: (start, end, region_type, language_tag)
    classified: list[tuple[int, int, RegionType, str | None]] = []

    # Fenced code blocks
    code_blocks = build_code_blocks(text)
    for block in code_blocks:
        lang = block.language
        if lang in SHELL_LANG_TAGS:
            region_type = RegionType.SHELL
        else:
            region_type = RegionType.CODE_BLOCK
        classified.append(
            (block.fence_start, block.fence_end, region_type, lang or None)
        )

    # Indented code blocks
    indented_ranges = build_indented_ranges(text)
    for start, end in indented_ranges:
        # Skip if overlaps with a fenced block
        if any(cs <= start < ce for cs, ce, _, _ in classified):
            continue
        classified.append((start, end, RegionType.INDENTED_CODE, None))

    # Sort by start offset
    classified.sort(key=lambda x: x[0])

    # Fill gaps with prose/shell line-by-line classification
    regions: list[PipelineContextRegion] = []
    cursor = 0

    for span_start, span_end, region_type, lang_tag in classified:
        # Fill gap before this classified span
        if cursor < span_start:
            gap_regions = _classify_gap(text, cursor, span_start)
            regions.extend(gap_regions)
        regions.append(
            PipelineContextRegion(
                start=span_start,
                end=span_end,
                region_type=region_type,
                language_tag=lang_tag,
            )
        )
        cursor = span_end

    # Fill trailing gap
    if cursor < len(text):
        gap_regions = _classify_gap(text, cursor, len(text))
        regions.extend(gap_regions)

    return tuple(regions)


def _classify_gap(text: str, start: int, end: int) -> list[PipelineContextRegion]:
    """Classify unclassified text between code blocks.

    Lines with command prefixes become SHELL regions, everything else
    is PROSE. Adjacent lines of the same type are merged into one region.
    """
    logger.debug(
        "_classify_gap called",
        extra={
            "event": "security.context_classifier.classify_gap",
            "start": start,
            "end": end,
            "gap_len": end - start,
        },
    )
    gap_text = text[start:end]
    lines = gap_text.split("\n")
    regions: list[PipelineContextRegion] = []

    line_offset = start
    current_type: RegionType | None = None
    current_start = start

    for i, line in enumerate(lines):
        # Determine line type
        if CMD_LINE_PREFIX.match(line):
            line_type = RegionType.SHELL
        else:
            line_type = RegionType.PROSE

        if current_type is None:
            current_type = line_type
            current_start = line_offset
        elif line_type != current_type:
            # Flush previous region
            regions.append(
                PipelineContextRegion(
                    start=current_start,
                    end=line_offset,
                    region_type=current_type,
                    language_tag=None,
                )
            )
            current_type = line_type
            current_start = line_offset

        # Move past this line (+1 for newline, except last line)
        line_offset += len(line)
        if i < len(lines) - 1:
            line_offset += 1  # newline character

    # Flush final region (skip zero-width trailing regions)
    if current_type is not None and current_start < end:
        regions.append(
            PipelineContextRegion(
                start=current_start,
                end=end,
                region_type=current_type,
                language_tag=None,
            )
        )

    return regions
