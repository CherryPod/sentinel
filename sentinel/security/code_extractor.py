"""Extract fenced code blocks from markdown-formatted text.

Used by the CodeShield integration to scan only actual code blocks
rather than mixed prose+code, which Semgrep can't parse reliably.
"""

import re
from dataclasses import dataclass

# Fenced code block: ``` with optional language tag, content, closing ```
_FENCED_BLOCK_RE = re.compile(
    r"```(\w+)?\s*\n(.*?)```",
    re.DOTALL,
)

# Language tag → CodeShield Language enum value (only supported languages)
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
_PYTHON_HINTS = re.compile(r"^\s*(?:import |from \w+ import |def |class )", re.MULTILINE)
_JS_HINTS = re.compile(r"^\s*(?:const |let |var |function |=>|require\(|import \{)", re.MULTILINE)
_RUST_HINTS = re.compile(r"^\s*(?:fn |let mut |pub fn |use \w+::|impl )", re.MULTILINE)
_JAVA_HINTS = re.compile(r"^\s*(?:public class |private |protected |System\.)", re.MULTILINE)
_C_HINTS = re.compile(r"^\s*#include\s+[<\"]", re.MULTILINE)
_PHP_HINTS = re.compile(r"<\?php|\$\w+\s*=", re.MULTILINE)


@dataclass
class CodeBlock:
    """A code block extracted from markdown text."""

    code: str
    language: str | None  # CodeShield language string, or None


def _detect_language(code: str) -> str | None:
    """Attempt to detect the programming language from code content."""
    if _PYTHON_HINTS.search(code):
        return "python"
    # Check Rust before JS — "let mut" is more specific than "let "
    if _RUST_HINTS.search(code):
        return "rust"
    if _JS_HINTS.search(code):
        return "javascript"
    if _JAVA_HINTS.search(code):
        return "java"
    if _C_HINTS.search(code):
        return "c"
    if _PHP_HINTS.search(code):
        return "php"
    return None


# Emoji and symbol Unicode ranges that cause syntax errors in code.
# Covers emoticons, dingbats, pictographs, transport symbols, etc.
_EMOJI_RE = re.compile(
    "["
    "\u2600-\u27BF"          # Misc Symbols + Dingbats (✅, ✓, ☀, etc.)
    "\uFE00-\uFE0F"          # Variation Selectors
    "\u200D"                  # Zero Width Joiner (composite emoji)
    "\u20E3"                  # Combining Enclosing Keycap
    "\U0001F000-\U0001FAFF"  # Supplemental symbol planes (all emoji)
    "]+",
)


def strip_emoji_from_code_blocks(text: str) -> str:
    """Strip emoji characters from fenced code blocks, preserving prose.

    Only modifies content inside ``` fences — prose, headings, and other
    text outside code blocks is left untouched.
    """
    def _clean_block(match: re.Match) -> str:
        lang_tag = match.group(1) or ""
        code = match.group(2)
        cleaned = _EMOJI_RE.sub("", code)
        prefix = f"```{lang_tag}\n" if lang_tag else "```\n"
        return f"{prefix}{cleaned}```"

    return _FENCED_BLOCK_RE.sub(_clean_block, text)


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

        # Map the language tag to a CodeShield-supported language
        language = None
        if lang_tag:
            language = _LANGUAGE_MAP.get(lang_tag.lower())

        # If no tag or unmapped tag, try heuristic detection
        if language is None:
            language = _detect_language(code)

        blocks.append(CodeBlock(code=code, language=language))

    # Fallback: no fenced blocks → scan entire text (preserves current behaviour)
    if not blocks:
        language = _detect_language(text)
        blocks.append(CodeBlock(code=text, language=language))

    return blocks
