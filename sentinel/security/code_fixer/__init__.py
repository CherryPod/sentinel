"""Sentinel Code Fixer — modular package (v3.0).

Public API:
    fix_code(filename, content) -> FixResult
    FixResult dataclass

Backwards-compatible: existing imports work unchanged.
"""

import logging
from pathlib import Path

from ._core import (
    _MAX_FIX_SIZE,
    FixResult,
    _is_empty_or_whitespace,
    _looks_binary,
    _run_chain,
)
from ._cross_language import fix_cross_language
from ._css import fix_css
from ._detectors import _detect_duplicate_defs_generic, _detect_truncation_generic
from ._dockerfile import fix_dockerfile
from ._html import fix_html
from ._javascript import fix_javascript
from ._json import fix_json
from ._markdown import fix_markdown
from ._python import fix_python
from ._rust import fix_rust
from ._shell import fix_shell
from ._sql import fix_sql
from ._structural import check_structural_integrity
from ._toml import fix_toml
from ._universal import fix_universal, strip_prose
from ._yaml import fix_yaml

__all__ = ["FixResult", "fix_code"]

logger = logging.getLogger(__name__)

# Finding #42: registry pattern replaces identity comparison for fixers
# that need extra arguments beyond content.
FIXER_REGISTRY = {
    fix_html: {"extra_args": lambda ext, name: (0,)},  # _depth=0
}

# Each chain runs in order. Universal normalisation always runs first.
# Prose stripping only runs on code files (not data formats like JSON/YAML).
FIXER_CHAINS = {
    # Code files (prose stripping enabled)
    ".py": [fix_universal, strip_prose, fix_python],
    ".rs": [fix_universal, strip_prose, fix_rust],
    ".html": [fix_universal, strip_prose, fix_html],
    ".htm": [fix_universal, strip_prose, fix_html],
    ".css": [fix_universal, fix_css],
    ".sql": [fix_universal, fix_sql],
    ".sh": [fix_universal, strip_prose, fix_shell],
    ".bash": [fix_universal, strip_prose, fix_shell],
    # Data/config files (no prose stripping — content is the data)
    ".json": [fix_universal, fix_json],
    ".yaml": [fix_universal, fix_yaml],
    ".yml": [fix_universal, fix_yaml],
    ".toml": [fix_universal, fix_toml],
    # Container files (prose stripping enabled)
    "Dockerfile": [fix_universal, strip_prose, fix_dockerfile],
    "Containerfile": [fix_universal, strip_prose, fix_dockerfile],
    ".dockerfile": [fix_universal, strip_prose, fix_dockerfile],
    # JavaScript/TypeScript
    ".js": [fix_universal, strip_prose, fix_javascript],
    ".ts": [fix_universal, strip_prose, fix_javascript],
    ".jsx": [fix_universal, strip_prose, fix_javascript],
    ".tsx": [fix_universal, strip_prose, fix_javascript],
    # Languages we don't have specific fixers for yet — universal only.
    # Listed explicitly so they get universal normalisation (BOM, CRLF,
    # whitespace, newline) rather than being silently skipped.
    ".c": [fix_universal],
    ".cpp": [fix_universal],
    ".h": [fix_universal],
    ".hpp": [fix_universal],
    ".java": [fix_universal],
    ".go": [fix_universal],
    ".rb": [fix_universal],
    ".lua": [fix_universal],
    ".xml": [fix_universal],
    ".ini": [fix_universal],
    ".cfg": [fix_universal],
    ".conf": [fix_universal],
    ".php": [fix_universal],
    ".txt": [fix_universal],
    ".md": [fix_universal, fix_markdown],
    ".csv": [fix_universal],
}


def fix_code(
    filename: str, content: str, surrounding_context: str | None = None
) -> FixResult:
    """Run the appropriate fixer chain for a file.

    Args:
        filename: The file path (used for language detection via extension).
                  This is always available at the integration point in
                  executor.py _file_write().
        content:  The file content to fix (after RESPONSE/fence stripping
                  by executor).
        surrounding_context: Optional surrounding file content (50 lines
                  before/after the anchor position). Individual fixers can
                  use this for integration error detection.

    Returns:
        FixResult with the (possibly fixed) content and audit metadata.
        On any error, returns the original content unchanged.
    """
    # Guard: empty/whitespace content — pass through unchanged
    if _is_empty_or_whitespace(content):
        logger.debug(
            "fix_code: is_empty_or_whitespace_content",
            extra={
                "event": "code_fixer.fix_code.match",
                "reason": "is_empty_or_whitespace_content",
            },
        )  # auto:neg
        return FixResult(
            content=content,
            skipped=True,
            skip_reason="Empty or whitespace-only content",
        )
    logger.debug(
        "fix_code: is_empty_or_whitespace_content_passed",
        extra={
            "event": "code_fixer.fix_code.passed",
            "reason": "is_empty_or_whitespace_content_passed",
        },
    )  # auto:neg

    # Guard: binary content — pass through unchanged
    if _looks_binary(content):
        logger.debug(
            "fix_code: looks_binary_content",
            extra={
                "event": "code_fixer.fix_code.match",
                "reason": "looks_binary_content",
            },
        )  # auto:neg
        return FixResult(
            content=content, skipped=True, skip_reason="Binary content detected"
        )

    logger.debug(
        "fix_code entry",
        extra={
            "event": "core.fix_code_entry",
            "file": filename,
            "ext": Path(filename).suffix.lower(),
            "content_length": len(content),
        },
    )

    path = Path(filename)
    ext = path.suffix.lower()
    name = path.name

    # Guard: oversized content — universal only (BOM/CRLF/whitespace)
    if len(content) > _MAX_FIX_SIZE:
        logger.debug(
            "fix_code: condition_match",
            extra={"event": "code_fixer.fix_code.match", "reason": "condition_match"},
        )  # auto:neg
        result = fix_universal(content)
        # Finding #52 fix: clear size format
        result.warnings.append(
            f"File exceeds {_MAX_FIX_SIZE:,} bytes — only universal fixes applied"
        )
        return result

    # Select fixer chain: match by exact filename first (Dockerfile),
    # then by extension, then fallback to universal-only
    chain = FIXER_CHAINS.get(name) or FIXER_CHAINS.get(ext) or [fix_universal]

    # Log which chain was selected and how it was matched
    if name in FIXER_CHAINS:
        chain_match = "name"
    elif ext in FIXER_CHAINS:
        logger.debug(
            "fix_code: clean", extra={"event": "code_fixer.fix_code.branch.clean"}
        )
        chain_match = "ext"
    else:
        logger.debug(
            "fix_code: clean", extra={"event": "code_fixer.fix_code.branch.clean"}
        )
        chain_match = "fallback"
    logger.debug(
        "Fixer chain selected",
        extra={
            "event": "core.chain_selected",
            "file": filename,
            "match_type": chain_match,
            "chain_length": len(chain),
        },
    )

    # Run chain with error isolation
    combined = _run_chain(
        filename=filename,
        content=content,
        chain=chain,
        fixer_registry=FIXER_REGISTRY,
        ext=ext,
        name=name,
    )

    # Cross-language content detection and repair (post-chain).
    # Catches CSS outside <style>, JS outside <script> in HTML/SVG,
    # and <style>/<script> wrapper tags on standalone CSS/JS files.
    # Fail-safe: crash is caught and logged as a warning.
    try:
        cross_lang = fix_cross_language(combined.content)
        if cross_lang.changed:
            logger.debug(
                "fix_code: changed",
                extra={"event": "code_fixer.fix_code.match", "reason": "changed"},
            )  # auto:neg
            combined.content = cross_lang.content
            combined.changed = True
            combined.fixes_applied.extend(cross_lang.fixes_applied)
        combined.errors_found.extend(cross_lang.errors_found)
        combined.warnings.extend(cross_lang.warnings)
    except Exception as exc:
        combined.warnings.append(
            f"Cross-language detector crashed: {type(exc).__name__}: {exc}"
        )
        logger.error(
            "Cross-language detector crashed",
            extra={
                "event": "core.cross_lang_crash",
                "file": filename,
                "error": str(exc),
            },
            exc_info=True,
        )

    # Cross-language detection (runs after chain — Finding #48)
    truncation_errors = _detect_truncation_generic(combined.content, ext)
    combined.errors_found.extend(truncation_errors)

    # Skip duplicate detection for Python — it has its own detector in fix_python()
    if ext != ".py":
        logger.debug(
            "fix_code: ext_noteq__py",
            extra={"event": "code_fixer.fix_code.match", "reason": "ext_noteq__py"},
        )  # auto:neg
        dup_errors = _detect_duplicate_defs_generic(combined.content, ext)
        combined.errors_found.extend(dup_errors)

    # Structural integrity validation (final step). Checks whether the
    # fixed content is parseable. If not, adds "structural_integrity_failure"
    # to errors_found so downstream consumers (e.g., anchor allocator) know
    # the file is in bad shape. Does NOT block the write.
    try:
        integrity_errors = check_structural_integrity(
            combined.content,
            ext,
            combined.errors_found,
        )
        combined.errors_found.extend(integrity_errors)
    except Exception as exc:
        combined.warnings.append(
            f"Structural integrity check crashed: {type(exc).__name__}: {exc}"
        )
        logger.error(
            "Structural integrity check crashed",
            extra={
                "event": "core.structural_integrity_crash",
                "file": filename,
                "error": str(exc),
            },
            exc_info=True,
        )

    return combined
