"""Extract fenced code blocks from markdown-formatted text.

Used by the Semgrep scanner to scan only actual code blocks
rather than mixed prose+code, which Semgrep can't parse reliably.
"""

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Fenced code block: ``` with optional language tag, content, closing ```
_FENCED_BLOCK_RE = re.compile(
    r"```(\w+)?\s*\n(.*?)```",
    re.DOTALL,
)

# Language tag → canonical language name (for Semgrep file extension mapping)
_LANGUAGE_MAP: dict[str, str] = {
    "python": "python",
    "py": "python",
    "python3": "python",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "javascript",
    "ts": "javascript",
    "rust": "rust",
    "rs": "rust",
    "java": "java",
    "c": "c",
    "cpp": "cpp",
    "cxx": "cpp",
    "csharp": "csharp",
    "cs": "csharp",
    "php": "php",
}

# Heuristics for language detection when no tag is provided
_PYTHON_HINTS = re.compile(
    r"^\s*(?:import |from \w+ import |def |class )", re.MULTILINE
)
_JS_HINTS = re.compile(
    r"^\s*(?:const |let |var |function |=>|require\(|import \{)", re.MULTILINE
)
_RUST_HINTS = re.compile(r"^\s*(?:fn |let mut |pub fn |use \w+::|impl )", re.MULTILINE)
_JAVA_HINTS = re.compile(
    r"^\s*(?:public class |private |protected |System\.)", re.MULTILINE
)
_C_HINTS = re.compile(r"^\s*#include\s+[<\"]", re.MULTILINE)
_PHP_HINTS = re.compile(r"<\?php|\$\w+\s*=", re.MULTILINE)


@dataclass
class CodeBlock:
    """A code block extracted from markdown text."""

    code: str
    language: str | None  # Canonical language name, or None


def _detect_language(code: str) -> str | None:
    """Attempt to detect the programming language from code content."""
    detected: str | None = None
    if _PYTHON_HINTS.search(code):
        detected = "python"
    # Check Rust before JS — "let mut" is more specific than "let "
    elif _RUST_HINTS.search(code):
        logger.debug(
            "_detect_language: clean",
            extra={"event": "code_extractor._detect_language.branch.clean"},
        )
        detected = "rust"
    elif _JS_HINTS.search(code):
        logger.debug(
            "_detect_language: clean",
            extra={"event": "code_extractor._detect_language.branch.clean"},
        )
        detected = "javascript"
    elif _JAVA_HINTS.search(code):
        logger.debug(
            "_detect_language: clean",
            extra={"event": "code_extractor._detect_language.branch.clean"},
        )
        detected = "java"
    elif _C_HINTS.search(code):
        logger.debug(
            "_detect_language: clean",
            extra={"event": "code_extractor._detect_language.branch.clean"},
        )
        detected = "c"
    elif _PHP_HINTS.search(code):
        logger.debug(
            "_detect_language: clean",
            extra={"event": "code_extractor._detect_language.branch.clean"},
        )
        detected = "php"
    logger.debug(
        "Language detection result",
        extra={
            "event": "code_extractor.detect_language_result",
            "detected": detected,
            "code_len": len(code) if code else 0,
        },
    )
    return detected


# Emoji and symbol Unicode ranges that cause syntax errors in code.
# Covers emoticons, dingbats, pictographs, transport symbols, etc.
_EMOJI_RE = re.compile(
    "["
    "\u2600-\u27bf"  # Misc Symbols + Dingbats (✅, ✓, ☀, etc.)
    "\ufe00-\ufe0f"  # Variation Selectors
    "\u200d"  # Zero Width Joiner (composite emoji)
    "\u20e3"  # Combining Enclosing Keycap
    "\U0001f000-\U0001faff"  # Supplemental symbol planes (all emoji)
    "]+",
)


def strip_emoji_from_code_blocks(text: str) -> str:
    """Strip emoji characters from fenced code blocks, preserving prose.

    Only modifies content inside ``` fences — prose, headings, and other
    text outside code blocks is left untouched.
    """

    def _clean_block(match: re.Match) -> str:  # audit_fix:skip (per-iteration callback)
        logger.debug(
            "_clean_block called",
            extra={
                "event": "code_extractor._clean_block",
                "match_type": type(match).__name__,
            },
        )  # auto:entry
        lang_tag = match.group(1) or ""
        code = match.group(2)
        cleaned = _EMOJI_RE.sub("", code)
        prefix = f"```{lang_tag}\n" if lang_tag else "```\n"
        return f"{prefix}{cleaned}```"

    return _FENCED_BLOCK_RE.sub(_clean_block, text)


# Fence delimiter: a line that starts (optionally after whitespace) with
# three or more backticks. This matches both opening fences (```python)
# and closing fences (```).  Used by close_unclosed_fences().
_FENCE_LINE_RE = re.compile(r"^\s*`{3,}", re.MULTILINE)


def close_unclosed_fences(text: str) -> str:
    """Append a closing code fence if the text has an unclosed fence.

    When Qwen hits the num_predict token cap mid-code-block, the response
    ends with an unclosed ``` fence. This causes broken markdown rendering
    and inflates "poor" quality grades. The fix is cosmetic: if the text
    ends with an odd number of fence delimiters (= still inside a code
    block), append a closing ``` so the markdown is structurally valid.

    Only appends — never removes or modifies existing content.
    """
    # Count fence delimiters by scanning line-starts.  Inline backticks
    # (e.g. `some code`) don't match because they don't start at column 0.
    fence_count = len(_FENCE_LINE_RE.findall(text))

    # Even count → all fences are balanced, nothing to do
    if fence_count % 2 == 0:
        return text

    # Odd count → last fence was an opening fence with no closing pair.
    # Append a closing fence, ensuring it starts on its own line.
    if text.endswith("\n"):
        return text + "```\n"
    return text + "\n```\n"


def extract_code_blocks(text: str) -> list[CodeBlock]:
    """Extract fenced code blocks from markdown-formatted text.

    Returns a list of CodeBlock entries with code and optional language hint.
    If no fenced blocks are found, returns the full text as a single entry
    (fallback to current scan-everything behaviour).
    """
    blocks: list[CodeBlock] = []

    for match in _FENCED_BLOCK_RE.finditer(text):
        lang_tag = match.group(1)
        code = match.group(2).strip()

        if not code:
            continue

        # Map the language tag to a canonical language name
        language = None
        if lang_tag:
            language = _LANGUAGE_MAP.get(lang_tag.lower())

        # If no tag or unmapped tag, try heuristic detection
        if language is None:
            language = _detect_language(code)

        blocks.append(CodeBlock(code=code, language=language))

    # B-006: Fallback — no fenced blocks → scan entire text as a single block.
    # This is intentional: Qwen sometimes emits code without fences, and scanning
    # everything is safer than scanning nothing.
    if not blocks:
        language = _detect_language(text)
        blocks.append(CodeBlock(code=text, language=language))

    return blocks
