"""SQL fixer.

Fixes common LLM mistakes in SQL:
- Missing trailing semicolon on statements.
- Handles files that start with -- comments before the first statement.
"""
import logging

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)

# SQL keywords that should end with a semicolon
_SQL_KEYWORDS = {
    "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP",
    "ALTER", "GRANT", "REVOKE", "WITH", "EXPLAIN", "TRUNCATE",
}


def fix_sql(content: str) -> FixResult:
    """SQL fixes: missing trailing semicolon on statements."""
    result = FixResult(content=content)
    original = content
    fname = _current_filename.get()

    logger.debug(
        "SQL fixer starting",
        extra={
            "event": "sql_fixer_start",
            "file": fname,
            "content_length": len(content),
        },
    )

    stripped = content.rstrip()
    if stripped and not stripped.endswith(";"):
        # Finding #24 fix: handle files starting with -- comments before
        # the first SQL statement. Skip comment lines to find the actual
        # first SQL keyword.
        first_word = ""
        for line in stripped.split("\n"):
            line_stripped = line.strip()
            # Skip empty lines and SQL single-line comments
            if not line_stripped or line_stripped.startswith("--"):
                continue
            first_word = line_stripped.split()[0].upper() if line_stripped.split() else ""
            break

        if first_word in _SQL_KEYWORDS:
            content = stripped + ";\n"
            result.fixes_applied.append("Added trailing semicolon")

    result.content = content
    result.changed = content != original

    if result.changed:
        logger.debug(
            "SQL fixer applied changes",
            extra={
                "event": "sql_fixer_done",
                "file": fname,
                "fixes": result.fixes_applied,
            },
        )

    return result
