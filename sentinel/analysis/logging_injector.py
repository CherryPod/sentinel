"""Inject debug logging into Qwen-generated scripts.

Adds entry-point logging to functions so the judge can see runtime
execution signals: what ran, what failed, what was called with what.

Privacy constraints:
- NEVER log parameter values (PII risk)
- Only log type(x) or len(x) for params — presence, not content
- Only log function entry, not return values
- Only additive — must not change observable script behaviour

Logs flow to stderr (captured by sandbox) → step_outcomes → judge payload.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Functions shorter than this (in lines) don't get logging injected.
# Short functions are trivially verifiable from the structural digest.
_MIN_FUNCTION_LINES = 4

# Max params to include in the log line
_MAX_LOG_PARAMS = 3

# Default capture limits
_MAX_LOG_LINES = 50
_MAX_LOG_BYTES = 4096

# Params whose value is likely large — log len() instead of type()
_LARGE_PARAM_NAMES = frozenset(
    {
        "content",
        "data",
        "body",
        "text",
        "payload",
        "html",
        "response",
        "result",
        "output",
        "items",
        "records",
        "rows",
        "lines",
    }
)


@dataclass
class InjectionResult:
    """What happened when we tried to inject logging."""

    content: str
    changed: bool = False
    injection_count: int = 0
    errors: list[str] = field(default_factory=list)


def inject_logging(code: str, language: str) -> InjectionResult:
    """Inject debug logging into code. Returns modified code.

    Currently supports Python and JavaScript. Other languages return
    the code unchanged.
    """
    if language in {"python", "py"}:
        result = _inject_python(code)
        if result.changed:
            logger.debug(
                "logging_injector: Python — %d entry points instrumented",
                result.injection_count,
                extra={
                    "event": "logging_injector.inject_python",
                    "count": result.injection_count,
                },
            )
        return result
    logger.debug(
        "inject_logging: language_in_passed",
        extra={
            "event": "logging_injector.inject_python.passed",
            "reason": "language_in_passed",
        },
    )  # auto:neg
    if language in ("javascript", "js", "mjs"):
        result = _inject_js(code)
        if result.changed:
            logger.debug(
                "logging_injector: JS — %d entry points instrumented",
                result.injection_count,
                extra={
                    "event": "logging_injector.inject_js",
                    "count": result.injection_count,
                },
            )
        return result
    logger.debug(
        "logging_injector: unsupported language %r — skipping injection",
        language,
        extra={"event": "logging_injector.inject_skip", "language": language},
    )
    return InjectionResult(content=code)


def truncate_log_capture(
    output: str,
    max_lines: int = _MAX_LOG_LINES,
    max_bytes: int = _MAX_LOG_BYTES,
) -> str:
    """Truncate captured log output to prevent bloated step outcomes.

    Keeps the LAST max_lines (most recent logs are most relevant for
    verification). Then trims to max_bytes if still too large.
    """
    logger.debug(
        "truncate_log_capture called",
        extra={
            "event": "logging_injector.truncate_log_capture",
            "output_len": len(output),
            "max_lines": max_lines,
            "max_bytes": max_bytes,
        },
    )
    if not output:
        return output
    lines = output.split("\n")
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    result = "\n".join(lines)
    if len(result.encode("utf-8", errors="replace")) > max_bytes:
        encoded = result.encode("utf-8", errors="replace")
        truncated = encoded[-max_bytes:]
        # Walk past any leading UTF-8 continuation bytes (0x80-0xBF)
        # to avoid splitting a multi-byte character mid-sequence
        start = 0
        while start < len(truncated) and (truncated[start] & 0xC0) == 0x80:
            start += 1
        result = truncated[start:].decode("utf-8", errors="replace")
    return result


def _inject_python(code: str) -> InjectionResult:
    """Inject logger.debug() at Python function entry points."""
    logger.debug(
        "_inject_python called",
        extra={
            "event": "logging_injector.inject_python_start",
            "code_len": len(code),
        },
    )
    try:
        tree = ast.parse(code)
    except (SyntaxError, MemoryError, RecursionError, ValueError):
        # Pathological code from Qwen — return unchanged, don't crash
        logger.warning(
            "logging_injector: Python parse failed",
            exc_info=True,
            extra={
                "event": "logging_injector.inject_python_error",
                "error_category": "parse_error",
            },
        )
        return InjectionResult(content=code, errors=["parse_error"])

    lines = code.split("\n")
    # Collect injection points (line number → log statement)
    # Process in reverse order so line numbers stay valid after insertion
    injections: list[tuple[int, str, str]] = []  # (line_idx, indent, log_stmt)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Skip short functions
        if not node.body:
            continue
        func_end = max(
            getattr(n, "end_lineno", node.lineno)
            for n in ast.walk(node)
            if hasattr(n, "end_lineno")
        )
        func_lines = func_end - node.lineno + 1
        if func_lines < _MIN_FUNCTION_LINES:
            continue
        # Skip dunder methods
        if node.name.startswith("__") and node.name.endswith("__"):
            continue

        first_stmt = node.body[0]

        # Build param logging (type/len only, never values)
        param_parts = []
        args = node.args
        param_names = [a.arg for a in args.args if a.arg != "self"][:_MAX_LOG_PARAMS]
        for pname in param_names:
            if pname in _LARGE_PARAM_NAMES:
                param_parts.append(f"len({pname})=%s")
            else:
                param_parts.append(f"type({pname})=%s")
        if param_parts:
            format_str = f'"{node.name} called: {", ".join(param_parts)}"'
            format_args = []
            for pname in param_names:
                if pname in _LARGE_PARAM_NAMES:
                    format_args.append(f"len({pname}) if {pname} is not None else None")
                else:
                    format_args.append(f"type({pname}).__name__")
            log_stmt = f"logger.debug({format_str}, {', '.join(format_args)})"
        else:
            log_stmt = f'logger.debug("{node.name} called")'

        # Determine indentation from the insertion target
        if (
            isinstance(first_stmt, ast.Expr)
            and isinstance(first_stmt.value, ast.Constant)
            and isinstance(first_stmt.value.value, str)
        ):
            # After docstring — use indentation of next statement or docstring
            if len(node.body) > 1:
                ref_line = lines[node.body[1].lineno - 1]
            else:
                ref_line = lines[first_stmt.lineno - 1]
            indent = ref_line[: len(ref_line) - len(ref_line.lstrip())]
            insert_idx = first_stmt.end_lineno  # Insert after docstring
        else:
            ref_line = lines[first_stmt.lineno - 1]
            indent = ref_line[: len(ref_line) - len(ref_line.lstrip())]
            insert_idx = first_stmt.lineno - 1  # Insert before first statement

        injections.append((insert_idx, indent, log_stmt))

    if not injections:
        return InjectionResult(content=code)

    # Sort by line number descending so insertions don't shift later indices
    injections.sort(key=lambda x: x[0], reverse=True)
    for insert_idx, indent, log_stmt in injections:
        lines.insert(insert_idx, f"{indent}{log_stmt}")

    # Add logger setup if not already present
    result_code = "\n".join(lines)
    if "import logging" not in result_code:
        result_code = (
            "import logging\n"
            'logger = logging.getLogger("sentinel.sandbox")\n\n' + result_code
        )

    return InjectionResult(
        content=result_code,
        changed=True,
        injection_count=len(injections),
    )


# ── JS function patterns ────────────────────────────────────────────
_JS_FUNC_PATTERN = re.compile(
    r"([ \t]*)((?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{)",
    re.MULTILINE,
)
_JS_ARROW_PATTERN = re.compile(
    r"([ \t]*)(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>\s*\{",
    re.MULTILINE,
)


def _lines_to_closing_brace(text: str) -> int:
    """Count newlines from *text* start to the depth-matched closing brace.

    Walks the string tracking ``{`` / ``}`` depth, starting at depth 1
    (the opening brace has already been consumed by the caller). Returns
    the number of ``\\n`` characters encountered before depth returns to 0.
    Falls back to total newlines if no matching brace is found.

    NOTE: Does not account for braces inside string literals or comments.
    This is acceptable because the result is only used as a threshold check
    (>= _MIN_FUNCTION_LINES), and the fallback over-estimates rather than
    under-estimates, erring on the side of injecting logging.
    """
    depth = 1
    newlines = 0
    for ch in text:
        if ch == "\n":
            newlines += 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return newlines
    # Unmatched — fall back to total newlines (better than 0)
    return newlines


def _inject_js(code: str) -> InjectionResult:
    """Inject console.log() at JS function entry points.

    Captured via sandbox stdout → step_outcomes.
    """
    logger.debug(
        "_inject_js called",
        extra={
            "event": "logging_injector.inject_js_start",
            "code_len": len(code),
        },
    )
    injections = 0
    result = code

    # Named functions — work on original code for match positions
    for match in reversed(list(_JS_FUNC_PATTERN.finditer(code))):
        indent = match.group(1)
        func_name = match.group(3)
        insert_pos = match.end()
        remaining = code[insert_pos:]
        # Count lines until the matching closing brace (depth-aware).
        # The old heuristic split on the first "}" which could be a
        # nested brace, under-counting function length.
        line_count = _lines_to_closing_brace(remaining)
        if line_count < _MIN_FUNCTION_LINES:
            continue
        log_line = f'\n{indent}    console.log("[sentinel] {func_name} called");'
        result = result[:insert_pos] + log_line + result[insert_pos:]
        injections += 1

    # Arrow functions — work on already-modified result
    for match in reversed(list(_JS_ARROW_PATTERN.finditer(result))):
        indent = match.group(1)
        func_name = match.group(2)
        insert_pos = match.end()
        remaining = result[insert_pos:]
        line_count = _lines_to_closing_brace(remaining)
        if line_count < _MIN_FUNCTION_LINES:
            continue
        log_line = f'\n{indent}    console.log("[sentinel] {func_name} called");'
        result = result[:insert_pos] + log_line + result[insert_pos:]
        injections += 1

    if injections == 0:
        return InjectionResult(content=code)

    return InjectionResult(
        content=result,
        changed=True,
        injection_count=injections,
    )
