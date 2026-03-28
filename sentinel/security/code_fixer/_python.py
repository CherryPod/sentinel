"""Python language fixer module.

Handles: mixed indentation, escaped triple quotes, import dedup,
bracket completion, mismatched brackets, indentation errors,
f-string bracket repair, missing stdlib imports, hallucinated imports,
truncation detection, and duplicate definition detection.

Moved from monolith lines 219-921. Finding fixes applied:
  #3 (HIGH): hallucinated import rename uses AST, skips strings/comments
  #6: mismatched bracket counting uses _iter_code_chars (triple-quote aware)
  #47: logger.debug when multi-bracket imbalance is silently skipped
  #49: renamed _fix_with_parso → _fix_with_ast
  #51: extracted retry limit to _MAX_INDENT_RETRIES
"""
import ast
import logging
import re

from ._core import (
    CharContext,
    FixResult,
    _current_filename,
    _iter_code_chars,
)

logger = logging.getLogger(__name__)

# Optional dependency — error-recovering Python parser
try:
    import parso
except ImportError:
    parso = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Finding #51: extracted from inline magic number
_MAX_INDENT_RETRIES = 10

# Allowlist: usage pattern → (module, import_name)
# For "from X import Y" style
_IMPORT_ALLOWLIST_FROM = {
    # dataclasses
    "dataclass": ("dataclasses", "dataclass"),
    "field": ("dataclasses", "field"),  # only if @dataclass present
    # contextlib
    "contextmanager": ("contextlib", "contextmanager"),
    # abc
    "ABC": ("abc", "ABC"),
    "abstractmethod": ("abc", "abstractmethod"),
    # pathlib
    "Path": ("pathlib", "Path"),
    # typing
    "Optional": ("typing", "Optional"),
    "List": ("typing", "List"),
    "Dict": ("typing", "Dict"),
    "Tuple": ("typing", "Tuple"),
    "Union": ("typing", "Union"),
    "Any": ("typing", "Any"),
    # datetime
    "datetime": ("datetime", "datetime"),
    "timedelta": ("datetime", "timedelta"),
    "date": ("datetime", "date"),
    "time": ("datetime", "time"),
    # collections
    "defaultdict": ("collections", "defaultdict"),
    "Counter": ("collections", "Counter"),
    # enum
    "Enum": ("enum", "Enum"),
}

# Module-level imports (triggered by attribute access like re.search)
_IMPORT_ALLOWLIST_MODULE = {
    "re", "json", "os", "sys", "math",
}

# Known-wrong import names that Qwen commonly hallucinates
# (wrong_module, wrong_name, right_module, right_name)
_HALLUCINATED_IMPORTS = [
    ("contextlib", "ContextManager", "contextlib", "contextmanager"),
    ("collections", "DefaultDict", "collections", "defaultdict"),
    ("typing", "TracebackType", "types", "TracebackType"),
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def fix_python(content: str) -> FixResult:
    """Python-specific fixes: syntax validation, import dedup, mixed indent.

    Priority order:
    1. Mixed indentation (tabs -> spaces) — safe, deterministic
    2. Escaped triple quotes (Qwen-specific) — safe, regex-based
    3. Import dedup (module-level only) — AST-based, conservative
    4. Bracket completion (truncation) — verify with ast.parse after fix
    5. Second import dedup pass (if bracket completion made code parseable)
    """
    result = FixResult(content=content)
    original = content
    fname = _current_filename.get()

    # 1. Fix mixed indentation (tabs -> 4 spaces)
    # Only fix leading tabs — tabs in strings/comments are left alone
    if "\t" in content:
        lines = content.split("\n")
        fixed_lines = []
        for line in lines:
            # Replace leading tabs with 4 spaces each
            stripped = line.lstrip("\t")
            tab_count = len(line) - len(stripped)
            if tab_count > 0:
                fixed_lines.append("    " * tab_count + stripped)
            else:
                fixed_lines.append(line)
        content = "\n".join(fixed_lines)
        if content != original:
            result.fixes_applied.append("Tabs -> spaces")
            logger.debug(
                "Fixed mixed indentation",
                extra={
                    "event": "fixer_detail",
                    "fixer": "fix_python",
                    "file": fname,
                    "fix": "tabs_to_spaces",
                },
            )

    # 2. Escaped triple quotes (Qwen-specific: emits \" instead of ")
    # Pattern: \"\"\".....\"\"\" at the start of a line (docstring position)
    # Only fix if the escaped version doesn't parse but unescaped does
    if '\\"\\"\\"' in content:
        candidate = content.replace('\\"\\"\\"', '"""')
        try:
            ast.parse(candidate)
            # Unescaped version parses — the escaping was wrong
            content = candidate
            result.fixes_applied.append("Unescaped triple quotes (Qwen artifact)")
            logger.debug(
                "Fixed escaped triple quotes",
                extra={
                    "event": "fixer_detail",
                    "fixer": "fix_python",
                    "file": fname,
                    "fix": "unescape_triple_quotes",
                },
            )
        except SyntaxError:
            pass  # unescaped version doesn't parse either, leave it alone

    # 3. Duplicate import removal (module-level only)
    content = _dedup_imports(content, result)

    # 4. Unclosed bracket completion (truncation artifact)
    content = _complete_brackets_python(content, original, result)

    # 4b. Mismatched bracket repair (v2.5)
    content = _fix_mismatched_brackets(content, result)

    # 5. Re-run import dedup if bracket completion made the code parseable
    # (first attempt may have failed due to syntax errors)
    content = _dedup_imports(content, result)

    # 6. IndentationError repair (v2) — fix "unexpected indent" and
    # "unindent does not match" by aligning to surrounding context
    content = _fix_indentation_errors(content, result)

    # 7. AST-based bracket repair (v2) — handles unclosed brackets inside
    # f-strings that stdlib ast.parse can't recover from
    # Finding #49: renamed from _fix_with_parso → _fix_with_ast
    content = _fix_with_ast(content, result)

    # 8. Missing stdlib imports (v2.5) — detect undefined names and add
    # imports from a hardcoded allowlist. Runs after all syntax repair
    # so the AST is as clean as possible.
    content = _add_missing_imports(content, result)

    # 9. Fix hallucinated imports (v2.5)
    content = _fix_hallucinated_imports(content, result)

    # 10. Truncation detection (v2.5)
    content = _detect_truncation_python(content, result)

    # 11. Duplicate definition detection (v2.5)
    content = _detect_duplicate_defs_python(content, result)

    # Final syntax check — report but don't block
    try:
        ast.parse(content)
    except SyntaxError as e:
        result.errors_found.append(f"SyntaxError: {e}")
        logger.debug(
            "Python file has residual syntax error",
            extra={
                "event": "fixer_detail",
                "fixer": "fix_python",
                "file": fname,
                "error": str(e),
            },
        )

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fix_indentation_errors(content: str, result: FixResult) -> str:
    """Fix IndentationError by aligning lines to surrounding context.

    Handles two patterns:
    - "unexpected indent": line is indented more than context allows
    - "unindent does not match": line's indentation doesn't match any outer level
    Retries up to _MAX_INDENT_RETRIES times (one fix per iteration) to handle
    cascading errors.
    """
    fname = _current_filename.get()
    # Finding #51: use extracted constant instead of magic number
    for attempt in range(_MAX_INDENT_RETRIES):
        try:
            ast.parse(content)
            return content  # parses clean — done
        except IndentationError as e:
            if e.lineno is None:
                break
            lines = content.split("\n")
            err_idx = e.lineno - 1
            if err_idx < 0 or err_idx >= len(lines):
                break

            # Find the previous non-empty line's indentation
            prev_indent = 0
            for i in range(err_idx - 1, -1, -1):
                if lines[i].strip():
                    prev_indent = len(lines[i]) - len(lines[i].lstrip())
                    # If prev line ends with colon, next line should be indented
                    if lines[i].rstrip().endswith(":"):
                        prev_indent += 4
                    break

            err_line = lines[err_idx]
            cur_indent = len(err_line) - len(err_line.lstrip())
            if cur_indent == prev_indent:
                break  # already at the right level, can't fix
            lines[err_idx] = " " * prev_indent + err_line.lstrip()
            new_content = "\n".join(lines)
            if new_content == content:
                break  # no change — avoid infinite loop
            content = new_content
            result.fixes_applied.append(
                f"Fixed indentation on line {e.lineno}"
            )
            logger.debug(
                "Fixed indentation error",
                extra={
                    "event": "fixer_detail",
                    "fixer": "_fix_indentation_errors",
                    "file": fname,
                    "line": e.lineno,
                    "attempt": attempt + 1,
                },
            )
        except SyntaxError:
            break  # not an indentation error — stop
    return content


def _fix_with_ast(content: str, result: FixResult) -> str:
    """Use parso's error-recovering parser for issues ast.parse can't handle.

    Primarily targets f-string bracket completion — parso can parse partial
    f-string expressions and identify where brackets are missing.

    For f-strings like ``f"text {len(items"``, the closing brackets need to
    go *inside* the string before the closing quote, not appended at the end.
    We try both strategies: insert-before-quote and append-at-end.

    Finding #49: renamed from _fix_with_parso to better reflect the
    ast.parse validation that drives the fix.
    """
    if parso is None:
        return content  # parso not available — skip

    try:
        ast.parse(content)
        return content  # already valid — skip
    except SyntaxError:
        pass

    fname = _current_filename.get()
    closings = [")", "]", "}", ")}", ")]", "})", ")}"]

    # Strategy 1: f-string bracket insertion before closing quote.
    # Find lines with f-strings that have unclosed brackets and try
    # inserting completions before the trailing quote character.
    lines = content.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Match f-string lines ending with a quote (the string is "closed"
        # by the LLM but the expression brackets inside aren't)
        if not re.match(r'.*f["\']', stripped):
            continue
        # Check if line ends with a quote that could be the f-string close
        if not stripped.endswith('"') and not stripped.endswith("'"):
            continue
        quote_char = stripped[-1]
        # Try inserting bracket completions before the final quote
        for closing in closings:
            fixed_line = line.rstrip()
            fixed_line = fixed_line[:-1] + closing + quote_char
            test_lines = lines[:i] + [fixed_line] + lines[i + 1:]
            test = "\n".join(test_lines)
            try:
                ast.parse(test)
                result.fixes_applied.append(
                    f"parso: closed bracket(s) in f-string: {closing}"
                )
                logger.debug(
                    "Closed bracket(s) in f-string",
                    extra={
                        "event": "fixer_detail",
                        "fixer": "_fix_with_ast",
                        "file": fname,
                        "line": i + 1,
                        "closing": closing,
                    },
                )
                return test
            except SyntaxError:
                continue

    # Strategy 2: append closing brackets at end of content.
    try:
        candidate = content.rstrip("\n")
        for closing in closings:
            test = candidate + closing + "\n"
            try:
                ast.parse(test)
                result.fixes_applied.append(
                    f"parso: closed bracket(s): {closing}"
                )
                logger.debug(
                    "Closed bracket(s) at end of file",
                    extra={
                        "event": "fixer_detail",
                        "fixer": "_fix_with_ast",
                        "file": fname,
                        "closing": closing,
                    },
                )
                return test
            except SyntaxError:
                continue
    except Exception:
        pass  # fail-safe

    return content


def _dedup_imports(content: str, result: FixResult) -> str:
    """Remove duplicate module-level imports. Scoped imports are preserved."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return content  # can't dedup if it doesn't parse

    seen_imports = set()
    lines = content.split("\n")
    lines_to_remove = set()

    # Only check top-level imports (direct children of Module)
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                key = f"import:{alias.name}:{alias.asname}"
                if key in seen_imports:
                    lines_to_remove.add(node.lineno - 1)
                else:
                    seen_imports.add(key)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                key = f"from:{node.module}:{alias.name}:{alias.asname}"
                if key in seen_imports:
                    lines_to_remove.add(node.lineno - 1)
                else:
                    seen_imports.add(key)

    if lines_to_remove:
        content = "\n".join(
            line for i, line in enumerate(lines) if i not in lines_to_remove
        )
        result.fixes_applied.append(
            f"Removed {len(lines_to_remove)} duplicate import(s)"
        )
        logger.debug(
            "Removed duplicate imports",
            extra={
                "event": "fixer_detail",
                "fixer": "_dedup_imports",
                "file": _current_filename.get(),
                "removed_count": len(lines_to_remove),
            },
        )
    return content


def _add_missing_imports(content: str, result: FixResult) -> str:
    """Auto-add missing stdlib imports based on name usage in the file.

    Uses ast.walk() (deep walk) to find all name references and all
    definitions. Only adds imports from a hardcoded allowlist — never
    guesses. Skips files with star imports (can't know what they provide).

    v2.5 addition.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return content  # can't analyse unparseable code

    # Bail on star imports — impossible to know what names they provide
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.names:
            if any(alias.name == "*" for alias in node.names):
                return content

    # Collect all defined names (deep walk — covers all scopes)
    defined = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                defined.add(alias.asname or alias.name)
                # For "import os", "os" is defined
                # For "from os import path", "path" is defined
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(node.name)
            # Parameters
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                defined.add(arg.arg)
            if node.args.vararg:
                defined.add(node.args.vararg.arg)
            if node.args.kwarg:
                defined.add(node.args.kwarg.arg)
        elif isinstance(node, ast.ClassDef):
            defined.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            defined.add(node.id)
        elif isinstance(node, ast.Global):
            defined.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            defined.update(node.names)
        # for/with/except targets
        elif isinstance(node, ast.For):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            defined.add(node.name)

    # Collect all referenced names (bare Name nodes + Attribute roots)
    referenced = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            # Walk to the root of the attribute chain (os.path.join → os)
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                referenced.add(root.id)

    # Check if @dataclass is present (needed for field() allowlist gate)
    has_dataclass = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id == "dataclass":
                    has_dataclass = True
                elif isinstance(decorator, ast.Call):
                    func = decorator.func
                    if isinstance(func, ast.Name) and func.id == "dataclass":
                        has_dataclass = True

    # Find missing names that match the allowlist
    # Group by module for clean import statements
    from_imports: dict[str, list[str]] = {}  # module → [names]
    module_imports: list[str] = []

    for name in referenced - defined:
        # Check "from X import Y" allowlist
        if name in _IMPORT_ALLOWLIST_FROM:
            module, import_name = _IMPORT_ALLOWLIST_FROM[name]
            # field() gate: only add if @dataclass is present
            if import_name == "field" and not has_dataclass:
                continue
            from_imports.setdefault(module, []).append(import_name)
        # Check "import X" allowlist (module-level attribute access)
        elif name in _IMPORT_ALLOWLIST_MODULE:
            module_imports.append(name)

    if not from_imports and not module_imports:
        return content

    # Build import lines
    new_lines = []
    for module in sorted(module_imports):
        new_lines.append(f"import {module}")
    for module in sorted(from_imports):
        names = sorted(set(from_imports[module]))
        new_lines.append(f"from {module} import {', '.join(names)}")

    # Find insertion point: after last existing import, or after docstring
    lines = content.split("\n")
    insert_idx = 0
    in_docstring = False
    docstring_quote = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Track docstrings
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                docstring_quote = stripped[:3]
                if stripped.count(docstring_quote) >= 2:
                    # Single-line docstring
                    insert_idx = i + 1
                else:
                    in_docstring = True
                continue
        else:
            if docstring_quote and docstring_quote in stripped:
                in_docstring = False
                insert_idx = i + 1
            continue

        # Track imports
        if stripped.startswith("import ") or stripped.startswith("from "):
            insert_idx = i + 1
        # Stop at first non-import, non-blank, non-comment line after imports
        elif stripped and not stripped.startswith("#") and insert_idx > 0:
            break

    # Insert new imports
    for j, imp_line in enumerate(new_lines):
        lines.insert(insert_idx + j, imp_line)

    content = "\n".join(lines)
    result.fixes_applied.append(
        f"Added missing import(s): {', '.join(new_lines)}"
    )
    logger.debug(
        "Added missing imports",
        extra={
            "event": "fixer_detail",
            "fixer": "_add_missing_imports",
            "file": _current_filename.get(),
            "imports": new_lines,
        },
    )
    return content


def _fix_hallucinated_imports(content: str, result: FixResult) -> str:
    """Fix known-wrong import names that Qwen commonly hallucinates.

    Corrects both the import statement and all usages of the wrong name.
    Only fires on exact matches from a hardcoded mapping.

    Finding #3 (HIGH): uses AST node visitor for rename instead of blind
    regex, so strings and comments are never modified.

    v2.5 addition.
    """
    fname = _current_filename.get()
    for wrong_mod, wrong_name, right_mod, right_name in _HALLUCINATED_IMPORTS:
        wrong_import = f"from {wrong_mod} import {wrong_name}"
        if wrong_import not in content:
            continue

        right_import = f"from {right_mod} import {right_name}"
        content = content.replace(wrong_import, right_import, 1)

        # Finding #3: Only rename in CODE context — skip strings and comments
        if wrong_name != right_name:
            try:
                tree = ast.parse(content)
            except SyntaxError:
                # Can't parse — fall back to conservative no-rename
                continue

            # Find all Name nodes that reference the wrong name
            # and replace at exact AST positions
            lines = content.split("\n")
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == wrong_name:
                    line_idx = node.lineno - 1
                    col = node.col_offset
                    line = lines[line_idx]
                    # Replace at exact position
                    lines[line_idx] = (
                        line[:col] + right_name + line[col + len(wrong_name):]
                    )
            content = "\n".join(lines)

        result.fixes_applied.append(
            f"Fixed hallucinated import: {wrong_import} → {right_import}"
        )
        logger.debug(
            "Fixed hallucinated import",
            extra={
                "event": "fixer_detail",
                "fixer": "_fix_hallucinated_imports",
                "file": fname,
                "fix_description": f"{wrong_import} → {right_import}",
            },
        )
    return content


def _detect_truncation_python(content: str, result: FixResult) -> str:
    """Detect truncated Python code. Report only — don't modify.
    v2.5 addition.
    """
    lines = [l for l in content.split("\n") if l.strip()]
    if not lines:
        return content

    last_line = lines[-1].strip()

    # Decorator with nothing after it
    if last_line.startswith("@"):
        result.errors_found.append(
            "Code appears truncated — ends with decorator, no function/class follows"
        )
        logger.debug(
            "Detected truncation: trailing decorator",
            extra={
                "event": "fixer_detail",
                "fixer": "_detect_truncation_python",
                "file": _current_filename.get(),
            },
        )
        return content

    # Ends at indentation > 0 (mid-block) — but only if the file doesn't parse
    try:
        ast.parse(content)
    except SyntaxError:
        indent = len(lines[-1]) - len(lines[-1].lstrip())
        if indent > 0:
            result.errors_found.append(
                f"Code appears truncated — ends mid-block at indentation level {indent}"
            )
            logger.debug(
                "Detected truncation: mid-block",
                extra={
                    "event": "fixer_detail",
                    "fixer": "_detect_truncation_python",
                    "file": _current_filename.get(),
                    "indent_level": indent,
                },
            )

    return content


def _detect_duplicate_defs_python(content: str, result: FixResult) -> str:
    """Detect duplicate function/class definitions at module level.
    v2.5 addition.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return content

    seen: dict[str, int] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
            if name in seen:
                result.errors_found.append(
                    f"Duplicate definition: '{name}' defined at lines "
                    f"{seen[name]} and {node.lineno}"
                )
                logger.debug(
                    "Detected duplicate definition",
                    extra={
                        "event": "fixer_detail",
                        "fixer": "_detect_duplicate_defs_python",
                        "file": _current_filename.get(),
                        "name": name,
                        "first_line": seen[name],
                        "second_line": node.lineno,
                    },
                )
            else:
                seen[name] = node.lineno

    return content


def _complete_brackets_python(content: str, original: str, result: FixResult) -> str:
    """Close unclosed brackets in truncated Python code.

    Uses a string-aware bracket counter that skips brackets inside:
    - Single-quoted strings
    - Double-quoted strings
    - Triple-quoted strings
    - Comments (# to end of line)

    After closing brackets, verifies the fix with ast.parse().
    If the fix doesn't help, reverts to the original content.
    """
    try:
        ast.parse(content)
        return content  # already valid — nothing to do
    except SyntaxError as e:
        err_msg = str(e)
        if not ("unexpected EOF" in err_msg or "was never closed" in err_msg
                or "unterminated" in err_msg):
            return content  # not a truncation error — leave it

    fname = _current_filename.get()

    # Count unmatched brackets, skipping strings and comments
    open_chars = {"(": ")", "[": "]", "{": "}"}
    close_chars = {v: k for k, v in open_chars.items()}
    stack = []
    in_str = None  # None, or the quote char(s)
    i = 0
    while i < len(content):
        ch = content[i]
        triple = content[i:i + 3]
        if in_str is None:
            if triple in ('"""', "'''"):
                in_str = triple
                i += 3
                continue
            elif ch in ('"', "'"):
                in_str = ch
                i += 1
                continue
            elif ch == "#":
                nl = content.find("\n", i)
                i = nl + 1 if nl != -1 else len(content)
                continue
            elif ch in open_chars:
                stack.append(open_chars[ch])
            elif ch in close_chars:
                if stack and stack[-1] == ch:
                    stack.pop()
        else:
            if ch == "\\" and i + 1 < len(content):
                i += 2
                continue
            if in_str in ('"""', "'''"):
                if content[i:i + 3] == in_str:
                    in_str = None
                    i += 3
                    continue
            elif ch == in_str:
                in_str = None
        i += 1

    if not stack:
        return content

    closing = "".join(reversed(stack))
    candidate = content.rstrip("\n") + closing + "\n"
    try:
        ast.parse(candidate)
        result.fixes_applied.append(
            f"Closed {len(stack)} unclosed bracket(s): {closing}"
        )
        logger.debug(
            "Closed unclosed brackets",
            extra={
                "event": "fixer_detail",
                "fixer": "_complete_brackets_python",
                "file": fname,
                "closing": closing,
                "count": len(stack),
            },
        )
        return candidate
    except SyntaxError:
        return content  # revert — our fix didn't help


def _fix_mismatched_brackets(content: str, result: FixResult) -> str:
    """Fix single-character bracket mismatches on the SyntaxError line.

    Two operations, tried in order:
    1. Swap: extra closer of type A, missing closer of type B -> swap
    2. Remove: extra closer with no missing counterpart -> remove

    Only operates on the error line. Verifies with ast.parse() before accepting.

    Finding #6: uses _iter_code_chars("python") for triple-quote-aware counting.
    v2.5 addition.
    """
    try:
        ast.parse(content)
        return content
    except SyntaxError as e:
        if e.lineno is None:
            return content
        err_lineno = e.lineno  # save before Python 3 deletes e

    fname = _current_filename.get()
    lines = content.split("\n")
    err_idx = err_lineno - 1
    if err_idx < 0 or err_idx >= len(lines):
        return content

    err_line = lines[err_idx]

    # Finding #6: count brackets using _iter_code_chars for triple-quote awareness
    open_counts = {"(": 0, "[": 0, "{": 0}
    close_counts = {")": 0, "]": 0, "}": 0}
    pairs = {"(": ")", "[": "]", "{": "}"}

    for _, ch, ctx in _iter_code_chars(err_line, "python"):
        if ctx != CharContext.CODE:
            continue
        if ch in open_counts:
            open_counts[ch] += 1
        elif ch in close_counts:
            close_counts[ch] += 1

    # Find imbalances on this line
    for opener, closer in pairs.items():
        opens = open_counts[opener]
        closes = close_counts[closer]

        if closes > opens:
            extra_count = closes - opens
            if extra_count != 1:
                # Finding #47: log when multi-bracket imbalance is silently skipped
                logger.debug(
                    "Multi-bracket imbalance skipped",
                    extra={
                        "event": "fixer_detail",
                        "fixer": "_fix_mismatched_brackets",
                        "file": fname,
                        "line": err_lineno,
                        "bracket": closer,
                        "extra_count": extra_count,
                    },
                )
                continue

            # Strategy 1: Swap — extra closer of one type, missing closer of another
            for other_opener, other_closer in pairs.items():
                if other_opener == opener:
                    continue
                other_opens = open_counts[other_opener]
                other_closes = close_counts[other_closer]
                if other_opens > other_closes:
                    last_pos = err_line.rfind(closer)
                    if last_pos >= 0:
                        candidate_line = err_line[:last_pos] + other_closer + err_line[last_pos + 1:]
                        candidate_lines = lines[:err_idx] + [candidate_line] + lines[err_idx + 1:]
                        candidate = "\n".join(candidate_lines)
                        try:
                            ast.parse(candidate)
                            result.fixes_applied.append(
                                f"Fixed bracket mismatch on line {err_lineno}: "
                                f"'{closer}' -> '{other_closer}'"
                            )
                            logger.debug(
                                "Fixed bracket mismatch (swap)",
                                extra={
                                    "event": "fixer_detail",
                                    "fixer": "_fix_mismatched_brackets",
                                    "file": fname,
                                    "line": err_lineno,
                                    "from": closer,
                                    "to": other_closer,
                                },
                            )
                            return candidate
                        except SyntaxError:
                            continue

            # Strategy 2: Remove — extra closer with no missing counterpart
            last_pos = err_line.rfind(closer)
            if last_pos >= 0:
                candidate_line = err_line[:last_pos] + err_line[last_pos + 1:]
                candidate_lines = lines[:err_idx] + [candidate_line] + lines[err_idx + 1:]
                candidate = "\n".join(candidate_lines)
                try:
                    ast.parse(candidate)
                    result.fixes_applied.append(
                        f"Removed extra '{closer}' on line {err_lineno}"
                    )
                    logger.debug(
                        "Removed extra bracket",
                        extra={
                            "event": "fixer_detail",
                            "fixer": "_fix_mismatched_brackets",
                            "file": fname,
                            "line": err_lineno,
                            "bracket": closer,
                        },
                    )
                    return candidate
                except SyntaxError:
                    continue

    return content
