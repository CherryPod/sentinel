"""Cross-language detectors for structural issues in code.

These detectors run AFTER the fixer chain completes (Finding #48).
They operate on post-fix content by design — we want to detect issues
that survived the fixing pipeline, not issues the fixers will correct.

Contains:
- _detect_truncation_generic: unclosed braces/comments via _iter_code_chars
- _detect_duplicate_defs_generic: duplicate top-level definitions
"""

import logging
import re

from ._core import CharContext, _iter_code_chars

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extension to _iter_code_chars language mapping
# ---------------------------------------------------------------------------
_EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".rs": "rust",
    ".sh": "shell",
    ".bash": "shell",
    ".css": "css",
    ".html": "html",
    ".htm": "html",
    ".json": "json",
    ".sql": "sql",
    ".go": "javascript",  # C-family: // and /* */ comments, same as JS
    ".java": "javascript",
    ".c": "javascript",
    ".cpp": "javascript",
    ".h": "javascript",
    ".hpp": "javascript",
    ".php": "javascript",
}


def _ext_to_language(ext: str) -> str:
    """Map file extension to _iter_code_chars language string."""
    return _EXT_TO_LANGUAGE.get(ext, "javascript")  # default to C-family syntax


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_C_FAMILY_EXTENSIONS = {
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".rs",
    ".go",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".css",
    ".php",
}

_DEF_PATTERNS = {
    ".js": [
        re.compile(r"^(?:export\s+)?(?:async\s+)?function\s+(\w+)"),
        re.compile(r"^(?:export\s+)?class\s+(\w+)"),
        re.compile(r"^(?:export\s+)?const\s+(\w+)\s*="),
    ],
    ".rs": [
        re.compile(r"^(?:pub\s+)?(?:async\s+)?fn\s+(\w+)"),
        re.compile(r"^(?:pub\s+)?struct\s+(\w+)"),
        re.compile(r"^(?:pub\s+)?enum\s+(\w+)"),
    ],
    ".go": [
        re.compile(r"^func\s+(\w+)"),
        re.compile(r"^type\s+(\w+)\s+struct"),
    ],
}
_DEF_PATTERNS[".ts"] = _DEF_PATTERNS[".js"]
_DEF_PATTERNS[".jsx"] = _DEF_PATTERNS[".js"]
_DEF_PATTERNS[".tsx"] = _DEF_PATTERNS[".js"]


# ---------------------------------------------------------------------------
# Truncation detection
# ---------------------------------------------------------------------------
def _detect_truncation_generic(content: str, ext: str) -> list[str]:
    """Detect truncated code in C-family languages. Returns error messages.

    Finding #38/#39 fix: uses a single pass via _iter_code_chars instead of
    two near-identical hand-rolled character parsers.
    Finding #29: template literal ${expr} handled natively by _iter_code_chars.
    """
    logger.debug(
        "_detect_truncation_generic called",
        extra={
            "event": "detectors.truncation_check",
            "content_len": len(content) if content else 0,
            "ext": ext,
        },
    )
    if ext not in _C_FAMILY_EXTENSIONS:
        logger.debug(
            "Truncation check skipped — not C-family",
            extra={"event": "detectors.truncation_skip", "ext": ext},
        )
        return []

    errors = []
    language = _ext_to_language(ext)

    # Single pass: count braces in CODE context and track last context
    open_braces = 0
    last_ctx = CharContext.CODE
    for _, ch, ctx in _iter_code_chars(content, language):
        last_ctx = ctx
        if ctx == CharContext.CODE:
            if ch == "{":
                open_braces += 1
            elif ch == "}":
                open_braces -= 1

    # If we ended inside a block comment, the file is truncated
    if last_ctx == CharContext.COMMENT:
        logger.debug(
            "_detect_truncation_generic: last_ctx_eq_COMMENT",
            extra={
                "event": "_detectors._detect_truncation_generic.match",
                "reason": "last_ctx_eq_COMMENT",
            },
        )  # auto:neg
        errors.append("File appears truncated — unclosed block comment")

    if open_braces > 0:
        logger.debug(
            "_detect_truncation_generic: open_braces_gt_0",
            extra={
                "event": "_detectors._detect_truncation_generic.match",
                "reason": "open_braces_gt_0",
            },
        )  # auto:neg
        errors.append(f"File appears truncated — {open_braces} unclosed brace(s)")

    if not errors:
        logger.debug(
            "Truncation check clean",
            extra={"event": "detectors.truncation_clean", "ext": ext},
        )

    return errors


# ---------------------------------------------------------------------------
# Duplicate definition detection
# ---------------------------------------------------------------------------
def _detect_duplicate_defs_generic(content: str, ext: str) -> list[str]:
    """Detect duplicate top-level definitions in non-Python languages.
    v2.5 addition.
    """
    logger.debug(
        "_detect_duplicate_defs_generic called",
        extra={
            "event": "detectors.duplicate_defs_check",
            "content_len": len(content) if content else 0,
            "ext": ext,
        },
    )
    patterns = _DEF_PATTERNS.get(ext)
    if not patterns:
        logger.debug(
            "_detect_duplicate_defs_generic: not_patterns",
            extra={
                "event": "_detectors._detect_duplicate_defs_generic.match",
                "reason": "not_patterns",
            },
        )  # auto:neg
        return []
    logger.debug(
        "_detect_duplicate_defs_generic: not_patterns_passed",
        extra={
            "event": "_detectors._detect_duplicate_defs_generic.passed",
            "reason": "not_patterns_passed",
        },
    )  # auto:neg

    errors = []
    seen: dict[str, int] = {}
    for i, line in enumerate(content.split("\n"), 1):
        for pattern in patterns:
            m = pattern.match(line)
            if m:
                name = m.group(1)
                if name in seen:
                    errors.append(
                        f"Duplicate definition: '{name}' at lines {seen[name]} and {i}"
                    )
                else:
                    seen[name] = i
                break

    return errors
