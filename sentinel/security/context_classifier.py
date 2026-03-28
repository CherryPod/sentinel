"""Shared context classification for scanner output text.

Determines the context type (code block, shell line, prose, etc.) for a
given position in scanner output text.  Used by SensitivePathScanner and
CommandPatternScanner to make consistent classification decisions.

The classifier answers "what context is this?" — the scanner decides
"should I flag or skip?" based on its own exemption rules.
"""

import logging
import re
from dataclasses import dataclass

from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)

# ── Shared constants (canonical definitions) ──────────────────────────

# Fenced code blocks: ```lang\n...\n```
# Group 1 = language tag (may be empty), Group 2 = block content.
CODE_FENCE_RE = re.compile(r"```(\w*)\s*\n(.*?)```", re.DOTALL)

# Language tags treated as shell — ALL lines in these blocks are
# operational context, not educational.
SHELL_LANG_TAGS = frozenset({
    "bash", "sh", "zsh", "shell", "console", "terminal",
    "powershell", "ps1", "pwsh", "bat", "cmd",
})

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
    fence_start: int     # position of opening ```
    content_start: int   # position of first content char (after ```lang\n)
    content_end: int     # position just before closing ```
    language: str        # lowercased language tag ("python", "bash", "")


@dataclass(frozen=True)
class ContextRegion:
    """Classification result for a position in text."""
    kind: str            # "fenced_code", "indented_code", "cmd_line", "prose"
    language: str        # fence language tag (empty if not in fenced block)
    is_shell: bool       # True if operational shell context
    line: str            # the full line containing the position
    line_start: int      # offset of line start in text
    block_content: str   # code block content text (empty if not in a block)
    block_info: CodeBlockInfo | None  # full block metadata (None if not in block)


# ── Preparation ───────────────────────────────────────────────────────

def prepare_text(text: str, strip_outer_fence: callable) -> str:
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
        blocks.append(CodeBlockInfo(
            fence_start=m.start(),
            content_start=m.start(2),
            content_end=m.end(2),
            language=m.group(1).lower(),
        ))
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
            logger.debug(
                "context=classify pos=%d kind=fenced_code lang=%s is_shell=%s",
                pos, block.language, is_shell,
            )
            return ContextRegion(
                kind="fenced_code",
                language=block.language,
                is_shell=is_shell,
                line=line,
                line_start=line_start,
                block_content=text[block.content_start:block.content_end],
                block_info=block,
            )

    # Check 2: inside an indented code block
    for start, end in indented_ranges:
        if start <= pos < end:
            is_shell = SHELL_PREFIXES.match(line) is not None
            logger.debug(
                "context=classify pos=%d kind=indented_code is_shell=%s",
                pos, is_shell,
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
        logger.debug("context=classify pos=%d kind=cmd_line", pos)
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
    logger.debug("context=classify pos=%d kind=prose", pos)
    return ContextRegion(
        kind="prose",
        language="",
        is_shell=False,
        line=line,
        line_start=line_start,
        block_content="",
        block_info=None,
    )
