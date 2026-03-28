"""Structural integrity validation for the code_fixer package.

Runs AFTER the fixer chain and all detectors complete. Checks whether the
fixed content is structurally valid by attempting to parse it with the
appropriate parser. If parsing fails after all fixes have been applied,
adds "structural_integrity_failure" to FixResult.errors_found.

This is a gate for downstream consumers (e.g., anchor allocator) that need
to know whether the file is safe to parse for structural operations. The
file still gets written — this flag is informational, not blocking.

For languages where the fixer chain already validates (Python via ast.parse,
JSON via json.loads, YAML via yaml.safe_load, TOML via tomllib.loads, JS/CSS
via truncation detection), we check for existing errors in errors_found.
For HTML and Shell, we add new validation.
"""
import logging
import re

from ._core import CharContext, FixResult, _current_filename, _iter_code_chars

logger = logging.getLogger(__name__)

INTEGRITY_FLAG = "structural_integrity_failure"

# Error patterns from existing fixers/detectors that indicate structural failure
_STRUCTURAL_ERROR_PATTERNS = (
    "SyntaxError:",           # Python ast.parse
    "JSONDecodeError",        # JSON json.loads
    "YAMLError:",             # YAML yaml.safe_load
    "TOMLDecodeError:",       # TOML tomllib.loads
    "File appears truncated", # JS/CSS truncation detector
    "unclosed block comment", # JS/CSS truncation detector
)


def _check_shell_balance(content: str) -> str | None:
    """Check shell keyword balance (if/fi, for/done, while/done, case/esac).

    The shell fixer auto-fixes when exactly 1 closer is missing. This check
    catches cases where 2+ are missing (unfixable by the fixer).
    Returns an error message or None if balanced.
    """
    has_heredoc = "<<" in content
    if has_heredoc:
        # Heredoc content can contain keywords — skip balance check
        return None

    lines = content.split("\n")
    if_count = fi_count = 0
    for_while_count = done_count = 0
    case_count = esac_count = 0

    for line in lines:
        # Build code-only version of the line (skip strings/comments)
        code_chars: list[str] = []
        for _, ch, ctx in _iter_code_chars(line, "shell"):
            if ctx == CharContext.CODE:
                code_chars.append(ch)
            else:
                code_chars.append(" ")
        code_line = "".join(code_chars).strip()

        if re.match(r"if\b", code_line):
            if_count += 1
        if re.match(r"fi\b", code_line):
            fi_count += 1
        if re.match(r"(for|while)\b", code_line):
            for_while_count += 1
        if re.match(r"done\b", code_line):
            done_count += 1
        if re.match(r"case\b", code_line):
            case_count += 1
        if re.match(r"esac\b", code_line):
            esac_count += 1

    issues = []
    if if_count > fi_count:
        issues.append(f"{if_count - fi_count} unclosed if block(s)")
    if for_while_count > done_count:
        issues.append(f"{for_while_count - done_count} unclosed for/while loop(s)")
    if case_count > esac_count:
        issues.append(f"{case_count - esac_count} unclosed case block(s)")

    if issues:
        return "Shell keyword imbalance: " + ", ".join(issues)
    return None


def _check_html_structure(content: str) -> str | None:
    """Check HTML structural validity via BeautifulSoup.

    Returns an error message or None if valid.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        logger.debug(
            "structural: BeautifulSoup not available, skipping HTML check",
            extra={"event": "structural_bs4_missing"},
        )
        return None

    try:
        soup = BeautifulSoup(content, "html.parser")
    except Exception as exc:
        return f"HTML parse error: {exc}"

    # Check if BeautifulSoup found any tags at all — if not, this isn't HTML
    if not soup.find():
        return "HTML has no recognisable tags"

    return None


def check_structural_integrity(
    content: str,
    ext: str,
    existing_errors: list[str],
) -> list[str]:
    """Check structural integrity of fixed content.

    Examines existing errors from the fixer chain and detectors, plus
    runs any additional language-specific validation. Returns a list of
    new errors to append (may be empty).

    Args:
        content: The fixed file content.
        ext: File extension (lowercase, with dot).
        existing_errors: Errors already found by fixers/detectors.
    """
    fname = _current_filename.get()
    new_errors: list[str] = []

    # Check if existing fixer/detector errors indicate structural failure
    has_structural_error = any(
        any(pattern in err for pattern in _STRUCTURAL_ERROR_PATTERNS)
        for err in existing_errors
    )

    if has_structural_error:
        # Find the first matching error for the log message
        triggering_error = next(
            err for err in existing_errors
            if any(p in err for p in _STRUCTURAL_ERROR_PATTERNS)
        )
        new_errors.append(f"{INTEGRITY_FLAG}: {triggering_error}")
        logger.warning(
            "Structural integrity check failed (existing error)",
            extra={
                "event": "structural_integrity_check_failed",
                "file": fname,
                "ext": ext,
                "trigger": triggering_error,
            },
        )
        return new_errors

    # Language-specific additional checks
    check_error: str | None = None

    if ext in (".sh", ".bash"):
        check_error = _check_shell_balance(content)
    elif ext in (".html", ".htm"):
        check_error = _check_html_structure(content)
    # Python, JSON, YAML, TOML, JS, CSS — already covered by existing
    # fixer chain validation (ast.parse, json.loads, yaml.safe_load,
    # tomllib.loads, truncation detection). If they found issues,
    # has_structural_error would have caught them above.

    if check_error:
        new_errors.append(f"{INTEGRITY_FLAG}: {check_error}")
        logger.warning(
            "Structural integrity check failed",
            extra={
                "event": "structural_integrity_check_failed",
                "file": fname,
                "ext": ext,
                "language_check": check_error,
            },
        )
    else:
        logger.debug(
            "Structural integrity check passed",
            extra={
                "event": "structural_integrity_check_passed",
                "file": fname,
                "ext": ext,
            },
        )

    return new_errors
