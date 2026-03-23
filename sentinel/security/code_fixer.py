"""
Sentinel Code Fixer — v2.6

Deterministic, multi-language code fixer for LLM output. Runs inside the
sentinel container between security scanning and file write.

DESIGN PRINCIPLES:
  1. CONSERVATIVE — never change content unless we're confident it's wrong.
     When in doubt, report the issue but don't modify the content.
  2. PATH-BASED — language detection uses the file path (always available
     at the integration point in executor.py). Never guess from content.
  3. IDEMPOTENT — running the fixer twice produces identical output.
  4. FAIL-SAFE — if any fixer crashes, the original content passes through
     unchanged. A broken fixer must never block a file write.
  5. AUDITABLE — every change is recorded in fixes_applied with enough
     detail to understand what happened and why.

WHAT THIS IS NOT:
  - Not a linter (use Ruff/Semgrep for that)
  - Not a formatter (use Ruff format for that)
  - Not a security scanner (Semgrep runs before us)
  - Not a general-purpose code repair tool — it fixes specific, well-documented
    LLM output errors that are deterministically identifiable

INTEGRATION POINT:
  executor.py _file_write(), after fence/tag stripping, before open(path, "w").
  The fixer receives: path (str) and content (str). Path is always a real
  filesystem path under /workspace/.

DEPENDENCIES: Python stdlib + PyYAML + parso (error-recovering Python parser) +
  json-repair (robust JSON fixer). All pure Python, MIT licensed, ~26KB total.

v2.6 ADDITIONS:
  JavaScript: Multi-pass fixer — object literal semicolons → commas, double
  semicolon removal, Python-style comment conversion, unclosed string literal
  repair, innerHTML → textContent defence-in-depth. Semicolon insertion
  retained from v2.

v2.5 ADDITIONS:
  Python: Missing stdlib import auto-add (allowlist), hallucinated import
  correction, bracket mismatch swap/remove, truncation detection, duplicate
  definition detection.
  HTML: Attribute quote normalisation, bare entity encoding.
  Shell: Shebang typo repair, missing fi/done block closers, unsafe pattern
  detection.
  Cross-language: Block comment / brace truncation detection (C-family),
  duplicate top-level definition detection (JS/TS/Rust/Go).
"""

import ast
import json
import logging
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import yaml  # already a project dep

try:
    import parso  # error-recovering Python parser (v2)
except ImportError:
    parso = None  # type: ignore[assignment]

try:
    from json_repair import repair_json as _json_repair  # robust JSON fixer (v2)
except ImportError:
    _json_repair = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class FixResult:
    """What happened when we tried to fix the code."""
    content: str
    changed: bool = False
    fixes_applied: list[str] = field(default_factory=list)
    errors_found: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped: bool = False  # True if content was not processed (e.g. binary, empty)
    skip_reason: str = ""


# ---------------------------------------------------------------------------
# Safety: content guards
# ---------------------------------------------------------------------------

# Maximum file size we'll process. Anything larger is likely not LLM-generated
# single-file output. Pass it through with universal-only treatment.
_MAX_FIX_SIZE = 100_000  # 100KB — generous for LLM output

# Characters that suggest binary content (not text)
_BINARY_CHARS = frozenset(range(0, 8)) | frozenset(range(14, 32)) - {9, 10, 13}


def _looks_binary(content: str) -> bool:
    """Check if content contains binary characters (null bytes, control chars)."""
    # Only check first 512 bytes — enough to detect binary headers
    sample = content[:512]
    return any(ord(ch) in _BINARY_CHARS for ch in sample)


def _is_empty_or_whitespace(content: str) -> bool:
    """Check if content is empty or whitespace-only."""
    return not content or not content.strip()


# ---------------------------------------------------------------------------
# Layer 1: Universal normalisation (all file types)
# ---------------------------------------------------------------------------

def fix_universal(content: str) -> FixResult:
    """BOM removal, CRLF, trailing whitespace, trailing newline.

    These are safe for ALL text file types. They never change meaning.
    """
    result = FixResult(content=content)
    original = content

    # BOM removal (UTF-8 BOM is unnecessary and causes issues with shebangs,
    # JSON parsers, and many other tools)
    if content.startswith("\ufeff"):
        content = content[1:]
        result.fixes_applied.append("Removed BOM")

    # CRLF -> LF (normalise to Unix line endings — container is Linux)
    if "\r\n" in content:
        content = content.replace("\r\n", "\n")
        result.fixes_applied.append("CRLF -> LF")

    # Trailing whitespace per line (never meaningful in any language)
    lines = content.split("\n")
    stripped = [line.rstrip() for line in lines]
    if lines != stripped:
        content = "\n".join(stripped)
        result.fixes_applied.append("Stripped trailing whitespace")

    # Trailing newline (POSIX: text files end with newline)
    if content and not content.endswith("\n"):
        content += "\n"
        result.fixes_applied.append("Added trailing newline")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 2: Prose stripping (code files only)
# ---------------------------------------------------------------------------

# Patterns that match LLM conversational preamble.
# IMPORTANT: These only match at the START of lines and must be full-line
# matches. A pattern like "Here's" would false-positive on code containing
# that word in a string — the anchored patterns below prevent this.
_PROSE_PATTERNS = [
    re.compile(r"^Here(?:'s| is) (?:the|a|an|your) .+:?\s*$", re.IGNORECASE),
    re.compile(r"^Sure[,!].+:?\s*$", re.IGNORECASE),
    re.compile(r"^I(?:'ve| have) (?:created|written|made|updated).+:?\s*$", re.IGNORECASE),
    re.compile(r"^This (?:code|script|file|function|program|module).+:?\s*$", re.IGNORECASE),
    re.compile(r"^Let me .+:?\s*$", re.IGNORECASE),
    re.compile(r"^The (?:following|above|below).+:?\s*$", re.IGNORECASE),
    re.compile(r"^Updated (?:code|file|version).+:?\s*$", re.IGNORECASE),
    re.compile(r"^(?:Here you go|Certainly|Of course)[.!,].+$", re.IGNORECASE),
    re.compile(r"^I'll .+:?\s*$", re.IGNORECASE),
    re.compile(r"^Below is .+:?\s*$", re.IGNORECASE),
]

# How many leading lines to check for prose. LLMs put preamble at the top,
# not scattered through the file. Limiting this prevents false positives on
# code that happens to contain prose-like comments deep in the file.
_PROSE_SCAN_LIMIT = 5


def strip_prose(content: str, language: str) -> FixResult:
    """Remove conversational prose that LLMs prepend to code output.

    Only scans the first few lines. Only removes lines that match known
    prose patterns AND are not indented (indented lines are code).
    """
    result = FixResult(content=content)
    lines = content.split("\n")
    removed = []
    clean_lines = []
    prose_zone = True  # only strip consecutive prose at the start

    for i, line in enumerate(lines):
        if prose_zone and i < _PROSE_SCAN_LIMIT:
            stripped = line.strip()
            # Skip blank lines at the start (they're between prose and code)
            if not stripped:
                clean_lines.append(line)
                continue
            # Only match non-indented lines (indented = code)
            if line == stripped and any(p.match(stripped) for p in _PROSE_PATTERNS):
                removed.append(stripped)
                continue
            else:
                prose_zone = False  # first non-prose line ends the zone
        clean_lines.append(line)

    if removed:
        # Strip any blank lines that were between prose and code
        while clean_lines and not clean_lines[0].strip():
            clean_lines.pop(0)
        content = "\n".join(clean_lines)
        result.fixes_applied.append(f"Stripped {len(removed)} prose line(s)")
        result.content = content
        result.changed = True

    return result


# ---------------------------------------------------------------------------
# Layer 3: Python syntax repair
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

    # 7. parso f-string repair (v2) — handles unclosed brackets inside
    # f-strings that stdlib ast.parse can't recover from
    content = _fix_with_parso(content, result)

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

    result.content = content
    result.changed = content != original
    return result


def _fix_indentation_errors(content: str, result: FixResult) -> str:
    """Fix IndentationError by aligning lines to surrounding context.

    Handles two patterns:
    - "unexpected indent": line is indented more than context allows
    - "unindent does not match": line's indentation doesn't match any outer level
    Retries up to 10 times (one fix per iteration) to handle cascading errors.
    """
    for _ in range(10):
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
        except SyntaxError:
            break  # not an indentation error — stop
    return content


def _fix_with_parso(content: str, result: FixResult) -> str:
    """Use parso's error-recovering parser for issues ast.parse can't handle.

    Primarily targets f-string bracket completion — parso can parse partial
    f-string expressions and identify where brackets are missing.

    For f-strings like ``f"text {len(items"``, the closing brackets need to
    go *inside* the string before the closing quote, not appended at the end.
    We try both strategies: insert-before-quote and append-at-end.
    """
    if parso is None:
        return content  # parso not available — skip

    try:
        ast.parse(content)
        return content  # already valid — skip
    except SyntaxError:
        pass

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
    return content


# ---------------------------------------------------------------------------
# Missing stdlib import detection and auto-add (v2.5)
# ---------------------------------------------------------------------------

# Allowlist: usage pattern → (import_statement, is_from_import)
# For "from X import Y" style: maps name → (module, name)
# For "import X" style: maps name → (module, None)
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

_IMPORT_ALLOWLIST_MODULE = {
    # Module-level imports (triggered by attribute access like re.search)
    "re", "json", "os", "sys", "math",
}


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
    return content


_HALLUCINATED_IMPORTS = [
    # (wrong_module, wrong_name, right_module, right_name)
    ("contextlib", "ContextManager", "contextlib", "contextmanager"),
    ("collections", "DefaultDict", "collections", "defaultdict"),
    ("typing", "TracebackType", "types", "TracebackType"),
]


def _fix_hallucinated_imports(content: str, result: FixResult) -> str:
    """Fix known-wrong import names that Qwen commonly hallucinates.

    Corrects both the import statement and all usages of the wrong name.
    Only fires on exact matches from a hardcoded mapping.

    v2.5 addition.
    """
    original = content
    for wrong_mod, wrong_name, right_mod, right_name in _HALLUCINATED_IMPORTS:
        wrong_import = f"from {wrong_mod} import {wrong_name}"
        if wrong_import not in content:
            continue

        right_import = f"from {right_mod} import {right_name}"
        content = content.replace(wrong_import, right_import, 1)

        # Also rename usages if the name changed — use word-boundary regex
        if wrong_name != right_name:
            content = re.sub(r'\b' + re.escape(wrong_name) + r'\b',
                             right_name, content)

        result.fixes_applied.append(
            f"Fixed hallucinated import: {wrong_import} → {right_import}"
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
        return candidate
    except SyntaxError:
        return content  # revert — our fix didn't help


def _fix_mismatched_brackets(content: str, result: FixResult) -> str:
    """Fix single-character bracket mismatches on the SyntaxError line.

    Two operations, tried in order:
    1. Swap: extra closer of type A, missing closer of type B -> swap
    2. Remove: extra closer with no missing counterpart -> remove

    Only operates on the error line. Verifies with ast.parse() before accepting.
    v2.5 addition.
    """
    try:
        ast.parse(content)
        return content
    except SyntaxError as e:
        if e.lineno is None:
            return content
        err_lineno = e.lineno  # save before Python 3 deletes e

    lines = content.split("\n")
    err_idx = err_lineno - 1
    if err_idx < 0 or err_idx >= len(lines):
        return content

    err_line = lines[err_idx]

    # Count brackets on the error line (string/comment-aware)
    open_counts = {"(": 0, "[": 0, "{": 0}
    close_counts = {")": 0, "]": 0, "}": 0}
    pairs = {"(": ")", "[": "]", "{": "}"}
    in_str = None
    i = 0
    while i < len(err_line):
        ch = err_line[i]
        if in_str is None:
            if ch in ('"', "'"):
                in_str = ch
            elif ch == "#":
                break
            elif ch in open_counts:
                open_counts[ch] += 1
            elif ch in close_counts:
                close_counts[ch] += 1
        else:
            if ch == "\\" and i + 1 < len(err_line):
                i += 2
                continue
            if ch == in_str:
                in_str = None
        i += 1

    # Find imbalances on this line
    for opener, closer in pairs.items():
        opens = open_counts[opener]
        closes = close_counts[closer]

        if closes > opens:
            extra_count = closes - opens
            if extra_count != 1:
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
                    return candidate
                except SyntaxError:
                    continue

    return content


# ---------------------------------------------------------------------------
# Layer 3: JSON repair (stdlib only — basic fixes)
# ---------------------------------------------------------------------------

def fix_json(content: str) -> FixResult:
    """Fix common LLM JSON errors using json-repair (v2) with regex fallback.

    Conservative approach:
    - Try parsing first — if valid, return immediately
    - Try json-repair library if available (handles nested brackets, NaN, etc.)
    - Fall back to regex-based fixes (Python bools, single quotes, trailing commas)
    """
    result = FixResult(content=content)
    original = content

    # Check for non-standard tokens Python json accepts but JSON spec forbids.
    # NaN/Infinity pass json.loads() but aren't valid JSON — fix them.
    _has_nonstandard = bool(re.search(r'\bNaN\b|\bInfinity\b', content))

    # Already valid strict JSON? Skip entirely.
    if not _has_nonstandard:
        try:
            json.loads(content)
            return result
        except json.JSONDecodeError:
            pass

    # Python booleans -> JSON booleans. Only runs when json.loads() failed
    # above, so we won't corrupt "True" inside valid string values.
    # json-repair doesn't know Python's True/False/None — it treats None
    # as a string "None". Do this substitution before json-repair.
    content = re.sub(r'\bTrue\b', 'true', content)
    content = re.sub(r'\bFalse\b', 'false', content)
    content = re.sub(r'\bNone\b', 'null', content)
    # NaN / Infinity are valid JavaScript but not valid JSON
    content = re.sub(r'\bNaN\b', 'null', content)
    content = re.sub(r'\bInfinity\b', 'null', content)
    content = re.sub(r'\b-Infinity\b', 'null', content)
    if content != original:
        result.fixes_applied.append("Python bools/None/NaN -> JSON")

    # Valid after bool fix? Return early.
    try:
        json.loads(content)
        result.content = content
        result.changed = content != original
        return result
    except json.JSONDecodeError:
        pass

    # v2: Try json-repair library (handles nested brackets, NaN, etc.)
    if _json_repair is not None:
        try:
            repaired = _json_repair(content)
            if isinstance(repaired, str) and repaired != content:
                # json-repair may strip trailing newline — preserve it
                if original.endswith("\n") and not repaired.endswith("\n"):
                    repaired += "\n"
                try:
                    json.loads(repaired.rstrip())
                    content = repaired
                    result.fixes_applied.append("json-repair: fixed malformed JSON")
                    result.content = content
                    result.changed = True
                    return result
                except json.JSONDecodeError:
                    pass  # json-repair output still invalid — fall through to regex
        except Exception:
            pass  # json-repair crashed — fall through to regex

    # Regex fallback (v1 approach) — Python bools already handled above.
    # Single quotes -> double quotes
    # ONLY if there are zero double quotes (avoids mangling mixed strings)
    if "'" in content and '"' not in content:
        content = content.replace("'", '"')
        result.fixes_applied.append("Single quotes -> double quotes")

    # Trailing commas before } or ]
    before_comma = content
    content = re.sub(r',\s*([}\]])', r'\1', content)
    if content != before_comma:
        result.fixes_applied.append("Removed trailing commas")

    # Validate after fixes
    try:
        json.loads(content)
    except json.JSONDecodeError as e:
        result.errors_found.append(f"JSONDecodeError after repair: {e}")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: YAML repair
# ---------------------------------------------------------------------------

def fix_yaml(content: str) -> FixResult:
    """Fix YAML indentation issues and validate.

    v1: Tab -> 2 spaces (YAML spec forbids tabs for indentation)
    v2: Normalize inconsistent indentation (mixed 2/4 space) to 2 spaces
    """
    result = FixResult(content=content)
    original = content

    # Tab -> 2 spaces (safe — YAML spec forbids tabs)
    if "\t" in content:
        content = content.replace("\t", "  ")
        result.fixes_applied.append("Tabs -> spaces in YAML")

    # v2: Normalize 4-space indentation to 2-space (YAML convention).
    # Detect the indent unit: if the smallest non-zero indent is 4 spaces,
    # the file uses 4-space indentation. If it's 2, leave it alone.
    lines = content.split("\n")
    indent_sizes = set()
    for line in lines:
        if line.strip() and line != line.lstrip():
            leading = len(line) - len(line.lstrip())
            indent_sizes.add(leading)
    min_indent = min(indent_sizes) if indent_sizes else 0
    has_4_space = min_indent >= 4 and min_indent % 4 == 0
    if has_4_space:
        normalized_lines = []
        for line in lines:
            if line and not line.lstrip().startswith("#"):
                leading = len(line) - len(line.lstrip())
                if leading > 0 and leading % 2 == 0:
                    normalized_lines.append(
                        " " * (leading // 2) + line.lstrip()
                    )
                else:
                    normalized_lines.append(line)
            else:
                normalized_lines.append(line)
        candidate = "\n".join(normalized_lines)
        try:
            yaml.safe_load(candidate)
            content = candidate
            result.fixes_applied.append(
                "Normalized 4-space indent -> 2-space (YAML convention)"
            )
        except yaml.YAMLError:
            pass  # normalization broke it — revert

    # Final validation
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        result.errors_found.append(f"YAMLError: {e}")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: TOML validation
# ---------------------------------------------------------------------------

def fix_toml(content: str) -> FixResult:
    """Validate TOML. No common deterministic fixes — just detection."""
    result = FixResult(content=content)
    try:
        tomllib.loads(content)
    except tomllib.TOMLDecodeError as e:
        result.errors_found.append(f"TOMLDecodeError: {e}")
    return result


# ---------------------------------------------------------------------------
# Layer 3: Shell script fixes
# ---------------------------------------------------------------------------

_SHEBANG_FIXES = {
    "#!bin/bash": "#!/bin/bash",
    "#!bin/sh": "#!/bin/sh",
    "#!/usr/bash": "#!/usr/bin/bash",
    "#!/usr/sh": "#!/usr/bin/sh",
    "#!/bin/env bash": "#!/usr/bin/env bash",
    "#!/bin/env sh": "#!/usr/bin/env sh",
    "#!/bin/env python3": "#!/usr/bin/env python3",
}

_UNSAFE_SHELL_PATTERNS = [
    (re.compile(r'rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\s*$',
                re.MULTILINE),
     "Dangerous command: rm -rf / (recursive delete of root)"),
    (re.compile(r'rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\*',
                re.MULTILINE),
     "Dangerous command: rm -rf /* (recursive delete of all files)"),
    (re.compile(r'chmod\s+777\b'),
     "chmod 777 sets world-writable permissions"),
    (re.compile(r'eval\s+"?\$'),
     "eval with variable input — potential code injection"),
    (re.compile(r':\(\)\s*\{.*\|.*&\s*\}\s*;'),
     "Fork bomb detected"),
]


def fix_shell(content: str) -> FixResult:
    """Shell script fixes: shebang, unclosed quotes, block closers, unsafe patterns.

    v1: Add missing shebang
    v2: Detect unclosed double quotes per line
    v2.5: Shebang typo repair, missing fi/done, unsafe pattern detection
    """
    result = FixResult(content=content)
    original = content

    # Missing shebang
    if not content.startswith("#!"):
        content = "#!/bin/bash\n" + content
        result.fixes_applied.append("Added shebang (#!/bin/bash)")

    # v2: Detect unclosed double quotes on individual lines
    # (odd number of unescaped " on a line suggests a missing closing quote)
    lines = content.split("\n")
    fixed_count = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Count unescaped double quotes
        count = 0
        j = 0
        while j < len(stripped):
            if stripped[j] == "\\" and j + 1 < len(stripped):
                j += 2  # skip escaped char
                continue
            if stripped[j] == '"':
                count += 1
            j += 1
        if count % 2 != 0:
            # Odd number of quotes — close the last one
            lines[i] = line.rstrip() + '"'
            fixed_count += 1

    if fixed_count:
        content = "\n".join(lines)
        result.fixes_applied.append(
            f"Closed {fixed_count} unclosed double quote(s)"
        )

    # v2: Warn about $VAR inside single quotes (don't auto-fix — semantics change)
    for i, line in enumerate(lines):
        # Find single-quoted sections and check for $
        in_single = False
        for j, ch in enumerate(line):
            if ch == "'" and (j == 0 or line[j - 1] != "\\"):
                in_single = not in_single
            elif ch == "$" and in_single:
                result.warnings.append(
                    f"Line {i + 1}: $variable inside single quotes won't expand"
                )
                break  # one warning per line is enough

    # v2.5: Shebang typo repair
    first_line = content.split("\n", 1)[0]
    if first_line.startswith("#!"):
        for wrong, right in _SHEBANG_FIXES.items():
            if first_line.strip() == wrong:
                content = right + content[len(first_line):]
                result.fixes_applied.append(f"Fixed shebang: {wrong} → {right}")
                break

    # v2.5: Missing block closers (if/fi, for/done, while/done)
    # Skip files with heredocs — they contain unmatched keywords
    if "<<" not in content:
        lines = content.split("\n")
        if_count = sum(1 for l in lines if re.match(r'\s*if\b', l))
        fi_count = sum(1 for l in lines if re.match(r'\s*fi\b', l))
        then_count = sum(1 for l in lines
                         if re.match(r'\s*then\b', l) or '; then' in l.split('#')[0])
        for_count = sum(1 for l in lines if re.match(r'\s*(for|while)\b', l))
        done_count = sum(1 for l in lines if re.match(r'\s*done\b', l))
        do_count = sum(1 for l in lines
                       if re.match(r'\s*do\b', l) or '; do' in l.split('#')[0])

        if (if_count > 0 and then_count > 0
                and fi_count == if_count - 1 and if_count - fi_count == 1):
            content = content.rstrip("\n") + "\nfi\n"
            result.fixes_applied.append("Added missing 'fi' (unclosed if block)")
        elif (for_count > 0 and do_count > 0
                and done_count == for_count - 1 and for_count - done_count == 1):
            content = content.rstrip("\n") + "\ndone\n"
            result.fixes_applied.append("Added missing 'done' (unclosed for/while block)")

    # v2.5: Unsafe pattern detection (detect only — don't modify content)
    for pattern, message in _UNSAFE_SHELL_PATTERNS:
        if pattern.search(content):
            result.errors_found.append(message)

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: Rust structural repair
# ---------------------------------------------------------------------------

def fix_rust(content: str) -> FixResult:
    """Rust-specific fixes: bracket completion, missing semicolons.

    Bracket counting is string/comment-aware (handles //, /* */, "...", '.')
    Semicolons are only added to lines that start with known Rust statement
    keywords (let, return, println!, etc.) and are followed by a closing
    brace or end of file.
    """
    result = FixResult(content=content)
    original = content

    # Bracket/brace completion (string/comment-aware)
    content = _complete_brackets_rust(content, result)

    # Missing semicolons on statement lines
    content = _fix_rust_semicolons(content, result)

    result.content = content
    result.changed = content != original
    return result


def _complete_brackets_rust(content: str, result: FixResult) -> str:
    """Close unclosed brackets in truncated Rust code."""
    open_chars = {"(": ")", "[": "]", "{": "}"}
    close_chars = {v: k for k, v in open_chars.items()}
    stack = []
    in_string = False
    in_line_comment = False
    in_block_comment = False
    i = 0
    while i < len(content):
        ch = content[i]
        next_ch = content[i + 1] if i + 1 < len(content) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and next_ch == "/":
                in_block_comment = False
                i += 1
        elif in_string:
            if ch == "\\" and next_ch:
                i += 1
            elif ch == '"':
                in_string = False
        else:
            if ch == "/" and next_ch == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and next_ch == "*":
                in_block_comment = True
                i += 1
            elif ch == '"':
                in_string = True
            elif ch in open_chars:
                stack.append(open_chars[ch])
            elif ch in close_chars:
                if stack and stack[-1] == ch:
                    stack.pop()
        i += 1

    if stack:
        closing = "".join(reversed(stack))
        content = content.rstrip("\n") + "\n" + closing + "\n"
        result.fixes_applied.append(
            f"Closed {len(stack)} unclosed bracket(s): {closing}"
        )
    return content


_RUST_SEMI_KEYWORDS = (
    "let ", "return ", "println!", "eprintln!", "print!",
    "assert", "panic!", "todo!", "unimplemented!", "vec!",
    "dbg!", "write!", "writeln!", "format!",
)


def _fix_rust_semicolons(content: str, result: FixResult) -> str:
    """Add missing semicolons to Rust statement lines."""
    lines = content.rstrip("\n").split("\n")
    fixed_count = 0
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if (not stripped.endswith(";")
                and not stripped.endswith("{")
                and not stripped.endswith("}")
                and not stripped.endswith(",")
                and not stripped.endswith("(")
                and not stripped.startswith("//")
                and not stripped.startswith("/*")
                and not stripped.startswith("*")
                and any(stripped.startswith(kw) for kw in _RUST_SEMI_KEYWORDS)):
            # Only add if the next non-blank line suggests this line is complete
            next_stripped = ""
            for nxt in lines[idx + 1:]:
                ns = nxt.strip()
                if ns:
                    next_stripped = ns
                    break
            if (next_stripped.startswith("}")
                    or next_stripped.startswith("let ")
                    or not next_stripped
                    or idx == len(lines) - 1):
                lines[idx] = line.rstrip() + ";"
                fixed_count += 1

    if fixed_count:
        content = "\n".join(lines) + "\n"
        result.fixes_applied.append(f"Added {fixed_count} missing semicolon(s)")
    return content


# ---------------------------------------------------------------------------
# Layer 3: HTML structural repair
# ---------------------------------------------------------------------------

_HTML_VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})

# Recursion limit for misnested tag repair (prevents infinite loops
# on pathological input)
_HTML_MAX_RECURSION = 10


def fix_html(content: str, _depth: int = 0) -> FixResult:
    """HTML fixes: unclosed tags, missing doctype, common LLM HTML errors.

    Uses stack-based tag tracking:
    - Void elements (br, img, input, etc.) are never pushed to the stack
    - Self-closing tags (/>) are ignored
    - Misnested tags trigger insertion of closing tags at the correct position
    - Unclosed tags at EOF get closing tags appended
    """
    result = FixResult(content=content)
    original = content

    # Recursion guard for pathological input
    if _depth > _HTML_MAX_RECURSION:
        result.warnings.append("HTML tag repair hit recursion limit")
        return result

    # Add missing DOCTYPE (only if <html> tag present)
    stripped = content.lstrip()
    if ("<html" in stripped.lower()
            and not stripped.lower().startswith("<!doctype")):
        content = "<!DOCTYPE html>\n" + content
        result.fixes_applied.append("Added <!DOCTYPE html>")

    # Track and fix unclosed/misnested tags
    tag_pattern = re.compile(r"<(/?)(\w+)([^>]*?)(/?)>")
    stack = []  # list of (tag_name, match_end_position)
    for m in tag_pattern.finditer(content):
        is_closing = m.group(1) == "/"
        tag_name = m.group(2).lower()
        is_self_closing = m.group(4) == "/"

        if tag_name in _HTML_VOID_ELEMENTS or is_self_closing:
            continue

        if is_closing:
            if stack and stack[-1][0] == tag_name:
                stack.pop()
            elif any(t[0] == tag_name for t in stack):
                # Misnested: close intermediate tags before this closer
                unclosed = []
                while stack and stack[-1][0] != tag_name:
                    unclosed.append(stack.pop()[0])
                if stack:
                    stack.pop()
                if unclosed:
                    insert_pos = m.start()
                    closing_str = "".join(f"</{t}>" for t in unclosed)
                    content = content[:insert_pos] + closing_str + content[insert_pos:]
                    result.fixes_applied.append(
                        f"Auto-closed {len(unclosed)} misnested tag(s): {', '.join(unclosed)}"
                    )
                    # Positions shifted — re-run
                    inner = fix_html(content, _depth + 1)
                    inner.changed = True
                    inner.fixes_applied = result.fixes_applied + inner.fixes_applied
                    return inner
        else:
            stack.append((tag_name, m.end()))

    # Close remaining unclosed tags at end of document
    if stack:
        tag_names = [t[0] for t in stack]
        closing_tags = "".join(f"</{tag}>" for tag in reversed(tag_names))
        content = content.rstrip("\n") + "\n" + closing_tags + "\n"
        result.fixes_applied.append(
            f"Closed {len(stack)} unclosed tag(s): {', '.join(reversed(tag_names))}"
        )

    # v2.5: Attribute quote normalisation
    # Skip template files (Jinja2, Django, ERB) — template syntax looks like
    # unquoted attributes and would be corrupted by quoting
    has_templates = "{{" in content or "{%" in content or "<%" in content
    if not has_templates:
        pre_attr = content

        def _quote_attr(m):
            """Wrap bare attribute values in double quotes."""
            attr_name = m.group(1)
            value = m.group(2)
            return f'{attr_name}="{value}"'

        def _fix_tag_attrs(tag_match):
            """Find unquoted attribute values within a single tag.

            Splits the tag into quoted and unquoted segments first,
            then only applies the quoting fix to unquoted segments.
            This prevents corrupting values inside already-quoted
            attributes (e.g. content="width=device-width, ...").
            """
            tag_content = tag_match.group(0)
            # Split into segments: quoted strings vs everything else
            # This preserves content="width=device-width" as-is
            segments = re.split(r'''("[^"]*"|'[^']*')''', tag_content)
            result_parts = []
            for i, seg in enumerate(segments):
                if i % 2 == 1:
                    # Quoted segment — leave untouched
                    result_parts.append(seg)
                else:
                    # Unquoted segment — fix bare attribute values
                    result_parts.append(
                        re.sub(
                            r'(\w+)=([^\s"\'<>=]+)(?=[\s>/>])',
                            _quote_attr,
                            seg,
                        )
                    )
            return "".join(result_parts)

        content = re.sub(r'<[a-zA-Z][^>]*>', _fix_tag_attrs, content)

        def _fix_tag_mixed_quotes(tag_match):
            """Fix mismatched quote pairs (opening single, closing double or vice versa)."""
            tag_content = tag_match.group(0)
            return re.sub(
                r"""(\w+)='([^']*?)"|(\w+)="([^"]*?)'""",
                lambda m: f'{m.group(1) or m.group(3)}="{m.group(2) or m.group(4)}"',
                tag_content,
            )

        content = re.sub(r'<[a-zA-Z][^>]*>', _fix_tag_mixed_quotes, content)

        if content != pre_attr:
            result.fixes_applied.append("Normalised attribute quotes to double-quoted")

    # v2.5: Entity encoding in text content
    # Only encodes bare & and < in text nodes — skips tags, attributes,
    # and content inside script/style/pre/code/textarea blocks
    _SKIP_ENTITY_TAGS = {"script", "style", "pre", "code", "textarea"}
    in_skip_tag = None
    entity_lines = content.split("\n")
    entity_fixed = False
    for i, line in enumerate(entity_lines):
        line_lower = line.lower()
        for tag in _SKIP_ENTITY_TAGS:
            # Check close before open — handles same-line open+close correctly
            if f"</{tag}" in line_lower:
                in_skip_tag = None
            if f"<{tag}" in line_lower and f"</{tag}" not in line_lower:
                # Only enter skip mode if the tag opens but doesn't close on this line
                in_skip_tag = tag

        if in_skip_tag:
            continue

        # Split line into tag and non-tag segments, only fix non-tag segments
        # Use [a-zA-Z/] after < to only match real HTML tags, not bare < in text
        parts = re.split(r'(<[a-zA-Z/][^>]*>)', line)
        line_changed = False
        # Track skip-tag state within a single line (handles inline <script>...</script>)
        inline_skip = False
        for j, part in enumerate(parts):
            if part.startswith("<"):
                part_lower = part.lower()
                for tag in _SKIP_ENTITY_TAGS:
                    if part_lower.startswith(f"<{tag}"):
                        inline_skip = True
                    elif part_lower == f"</{tag}>":
                        inline_skip = False
                continue
            if inline_skip:
                continue
            original_part = part
            # Encode bare ampersands (not already part of an entity reference)
            part = re.sub(r'&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[\da-fA-F]+);)', '&amp;', part)
            # Encode < that isn't a tag start (followed by space, digit, or =)
            part = re.sub(r'<(?=[\s\d=])', '&lt;', part)
            if part != original_part:
                parts[j] = part
                line_changed = True
        if line_changed:
            entity_lines[i] = "".join(parts)
            entity_fixed = True

    if entity_fixed:
        content = "\n".join(entity_lines)
        result.fixes_applied.append("Encoded bare HTML entities in text content")

    # Warnings (non-blocking)
    if re.search(r"<html\s*>", content, re.IGNORECASE):
        result.warnings.append('<html> missing lang attribute (e.g. <html lang="en">)')
    if "<head" in content.lower() and "charset" not in content.lower():
        result.warnings.append("Missing charset meta tag in <head>")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: CSS structural repair
# ---------------------------------------------------------------------------

def fix_css(content: str) -> FixResult:
    """CSS fixes: unclosed braces, missing semicolons before closing brace."""
    result = FixResult(content=content)
    original = content

    # Unclosed braces
    open_count = content.count("{")
    close_count = content.count("}")
    if open_count > close_count:
        diff = open_count - close_count
        content = content.rstrip("\n") + "\n" + ("}\n" * diff)
        result.fixes_applied.append(f"Closed {diff} unclosed brace(s)")

    # Missing semicolons on last property before }
    content = re.sub(
        r'(\S)\s*\n(\s*\})',
        lambda m: m.group(0) if m.group(1) in (";", "{", "}") else m.group(1) + ";\n" + m.group(2),
        content,
    )
    if content != original and "semicolon" not in str(result.fixes_applied):
        result.fixes_applied.append("Added missing semicolons before }")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: SQL basic repair
# ---------------------------------------------------------------------------

def fix_sql(content: str) -> FixResult:
    """SQL fixes: missing trailing semicolon on statements."""
    result = FixResult(content=content)
    original = content

    stripped = content.rstrip()
    if stripped and not stripped.endswith(";"):
        first_word = stripped.split()[0].upper() if stripped.split() else ""
        sql_keywords = {
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP",
            "ALTER", "GRANT", "REVOKE", "WITH", "EXPLAIN", "TRUNCATE",
        }
        if first_word in sql_keywords:
            content = stripped + ";\n"
            result.fixes_applied.append("Added trailing semicolon")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: Dockerfile fixes
# ---------------------------------------------------------------------------

def fix_dockerfile(content: str) -> FixResult:
    """Fix common LLM Dockerfile mistakes. Both Dockerfile and Containerfile."""
    result = FixResult(content=content)
    original = content

    # Single quotes in CMD/ENTRYPOINT exec form -> double quotes
    # JSON requires double quotes. LLMs often use Python-style single quotes.
    pattern = r"^(CMD|ENTRYPOINT)\s+\[([^\]]*)\]"
    def _fix_exec_form(m):
        instruction = m.group(1)
        args = m.group(2)
        if "'" in args:
            args = args.replace("'", '"')
            return f"{instruction} [{args}]"
        return m.group(0)
    content = re.sub(pattern, _fix_exec_form, content, flags=re.MULTILINE)
    if content != original:
        result.fixes_applied.append("Fixed single quotes in exec form")

    # Check FROM exists and is first instruction
    code_lines = [l.strip() for l in content.split("\n")
                  if l.strip() and not l.strip().startswith("#")]
    if code_lines and not code_lines[0].upper().startswith("FROM"):
        result.errors_found.append("First instruction is not FROM")

    lines = content.split("\n")
    new_lines = []
    has_user = False
    has_apt_update = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        upper = stripped.upper()

        if upper.startswith("USER "):
            has_user = True

        if "apt-get install" in stripped and not has_apt_update:
            result.warnings.append(
                f"Line {i + 1}: apt-get install without prior apt-get update"
            )
        if "apt-get update" in stripped:
            has_apt_update = True

        # ADD -> COPY when source is not a URL or archive
        if upper.startswith("ADD ") and not upper.startswith("ADD --"):
            args = stripped[4:].strip()
            src = args.split()[0] if args.split() else args
            archive_exts = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".gz")
            if (not src.startswith("http")
                    and not any(src.endswith(ext) for ext in archive_exts)):
                new_line = line.replace("ADD ", "COPY ", 1).replace("add ", "COPY ", 1)
                if new_line != line:
                    result.fixes_applied.append(
                        f"Line {i + 1}: ADD -> COPY (not a URL or archive)"
                    )
                    line = new_line

        # Shell operators in exec form
        exec_match = re.match(r'^(CMD|ENTRYPOINT|RUN)\s+\[(.+)\]', stripped)
        if exec_match:
            args_str = exec_match.group(2)
            if "&&" in args_str or "||" in args_str or "|" in args_str:
                result.warnings.append(
                    f"Line {i + 1}: Shell operators in exec form won't work "
                    f"(needs shell form or explicit sh -c)"
                )

        # Detect :latest tag
        if re.match(r"^\s*FROM\s+\S+:latest", line):
            result.warnings.append(f"Using :latest tag: {stripped}")

        new_lines.append(line)

    content = "\n".join(new_lines)

    # Missing USER instruction
    if not has_user and code_lines:
        result.warnings.append("No USER instruction — container runs as root")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: JavaScript/TypeScript fixes (v2.6)
#
# Multi-pass fixer for common LLM-generated JS errors. Each sub-function
# handles one error class. All fixes are HIGH confidence — they correct
# patterns that are always wrong in valid JavaScript.
# ---------------------------------------------------------------------------

# Tokens that indicate a line is a complete statement needing a semicolon
_JS_SEMI_ENDINGS = re.compile(
    r"(?:"
    r"[a-zA-Z_$0-9]"  # identifier char
    r"|['\"`]"         # string ending
    r"|\)"             # closing paren
    r"|\]"             # closing bracket
    r"|true|false|null|undefined"
    r"|\+\+|--"        # postfix operators
    r")$"
)

# Lines ending with these should NOT get a semicolon
_JS_NO_SEMI = re.compile(
    r"(?:"
    r"[{},;]"          # block/comma/already has semi
    r"|//"             # comment
    r"|\*/"            # block comment end
    r"|=>$"            # arrow function
    r")$"
)

# Object property line: key (with optional quotes) followed by colon and value
_JS_OBJ_PROP = re.compile(
    r'^(\s*)'                           # leading whitespace (group 1)
    r'(?:["\'][^"\']+["\']'            # quoted key (any chars inside quotes)
    r'|[\w$]+)'                         # or bare identifier key
    r'\s*:\s*'                          # colon separator
    r'.+?'                              # value (non-greedy)
    r';'                                # trailing semicolon (the error)
    r'\s*$'                             # optional trailing whitespace
)

# Python-style comment: line starting with # (not #! shebang)
_JS_PYTHON_COMMENT = re.compile(r'^(\s*)#(?!!)\s*(.*)')


def _js_fix_object_semicolons(content: str, fixes: list[str]) -> str:
    """Fix semicolons used instead of commas between object properties.

    Detects lines like `name: "test";` inside object literals and replaces
    the trailing semicolon with a comma. Only fixes when the context clearly
    indicates an object literal (next non-blank line is another property or
    a closing brace).
    """
    lines = content.split("\n")
    fixed_count = 0

    # Track brace depth to identify object literal contexts
    brace_depth = 0
    in_string = False
    in_block_comment = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track block comments
        if not in_block_comment and "/*" in stripped:
            if "*/" not in stripped.split("/*", 1)[1]:
                in_block_comment = True
                continue
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue

        # Skip single-line comments
        if stripped.startswith("//"):
            continue

        # Count braces (rough — doesn't handle braces in strings perfectly,
        # but we only use depth > 0 as a signal, not exact scoping)
        brace_depth += stripped.count("{") - stripped.count("}")

        # Only look for the pattern when we're inside braces (object context)
        if brace_depth <= 0:
            continue

        m = _JS_OBJ_PROP.match(line)
        if not m:
            continue

        # Confirm context: next non-blank line should be another property or }
        next_meaningful = ""
        for j in range(i + 1, min(i + 5, len(lines))):
            candidate = lines[j].strip()
            if candidate:
                next_meaningful = candidate
                break

        if not next_meaningful:
            continue

        # Next line is another property or closing brace — safe to fix
        looks_like_obj_context = (
            _JS_OBJ_PROP.match(lines[j] if next_meaningful else "")
            or next_meaningful.startswith("}")
            or re.match(r'^(?:["\'][^"\']+["\']|[\w$]+)\s*:', next_meaningful)
        )

        if looks_like_obj_context:
            # Replace the last semicolon with a comma
            line_rstripped = line.rstrip()
            if line_rstripped.endswith(";"):
                lines[i] = line_rstripped[:-1] + ","
                fixed_count += 1

    if fixed_count:
        content = "\n".join(lines)
        fixes.append(
            f"Replaced {fixed_count} semicolon(s) with commas in object "
            f"literal(s)"
        )

    return content


def _js_fix_double_semicolons(content: str, fixes: list[str]) -> str:
    """Replace `;;` with `;` — always unintentional in LLM output."""
    # Avoid touching `for (;;)` loops — only fix ;; at end of statements
    pattern = re.compile(r'(?<!\()(;;)(?!\s*\))')
    new_content = pattern.sub(";", content)
    if new_content != content:
        count = content.count(";;") - new_content.count(";;")
        fixes.append(f"Removed {count} double semicolon(s)")
    return new_content


def _js_fix_python_comments(content: str, fixes: list[str]) -> str:
    """Convert Python-style `# comment` to JS-style `// comment`.

    Skips shebangs (#!) and lines inside strings/template literals.
    Only converts lines where # is the first non-whitespace character —
    never touches # inside code (e.g. hex colours, URL fragments).
    """
    lines = content.split("\n")
    fixed_count = 0
    in_template = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track template literals
        backtick_count = stripped.count("`")
        if backtick_count % 2 != 0:
            in_template = not in_template
        if in_template:
            continue

        m = _JS_PYTHON_COMMENT.match(line)
        if m:
            indent = m.group(1)
            comment_text = m.group(2)
            lines[i] = f"{indent}// {comment_text}"
            fixed_count += 1

    if fixed_count:
        content = "\n".join(lines)
        fixes.append(
            f"Converted {fixed_count} Python-style comment(s) to JS-style"
        )

    return content


def _js_fix_unclosed_strings(content: str, fixes: list[str]) -> str:
    """Fix unclosed string literals on single lines.

    Detects lines with an odd number of unescaped quotes (same type) that
    end with a semicolon, and adds the closing quote before the semicolon.
    Only fixes simple cases — single-line strings that are clearly missing
    their closing delimiter.
    """
    lines = content.split("\n")
    fixed_count = 0

    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if not stripped or stripped.startswith("//"):
            continue

        for quote in ('"', "'"):
            # Count unescaped quotes of this type
            count = 0
            for j, ch in enumerate(stripped):
                if ch == quote and (j == 0 or stripped[j - 1] != "\\"):
                    count += 1

            # Odd count means unclosed — but only fix if the line ends with ;
            if count % 2 != 0 and count >= 1:
                if stripped.endswith(";"):
                    lines[i] = stripped[:-1] + quote + ";"
                    fixed_count += 1
                    break  # Only fix one quote type per line
                elif not stripped.endswith(quote):
                    # Line doesn't end with ; or the quote — add closing quote
                    # Only if the line looks like a statement (has = or ()
                    if "=" in stripped or "(" in stripped:
                        lines[i] = stripped + quote
                        fixed_count += 1
                        break

    if fixed_count:
        content = "\n".join(lines)
        fixes.append(f"Closed {fixed_count} unclosed string literal(s)")

    return content


def _js_fix_innerhtml(content: str, fixes: list[str]) -> str:
    """Replace .innerHTML with .textContent when RHS has no HTML tags.

    Defence-in-depth: Semgrep blocks innerHTML with dynamic content, but
    if code reaches the fixer it means Semgrep was bypassed or disabled.
    Only replaces when the RHS is clearly not HTML (no < or > characters).
    """
    # Match: something.innerHTML = <value without HTML tags>
    pattern = re.compile(
        r'(\.innerHTML)(\s*=\s*)([^;]+;?)',
        re.MULTILINE,
    )

    fixed_count = 0

    def replace_if_safe(m: re.Match) -> str:
        nonlocal fixed_count
        rhs = m.group(3)
        # Only replace if the RHS contains no HTML tag characters
        if "<" not in rhs and ">" not in rhs:
            fixed_count += 1
            return ".textContent" + m.group(2) + m.group(3)
        return m.group(0)

    new_content = pattern.sub(replace_if_safe, content)

    if fixed_count:
        fixes.append(
            f"Replaced {fixed_count} innerHTML assignment(s) with textContent"
        )

    return new_content


def fix_javascript(content: str) -> FixResult:
    """JavaScript/TypeScript multi-pass fixer.

    Applies fixes in order from most structural to most local:
    1. Python-style comments → JS-style (must run before semicolon logic)
    2. Object literal semicolons → commas
    3. Double semicolons
    4. Missing semicolons (original v2 logic)
    5. Unclosed string literals
    6. innerHTML → textContent (defence-in-depth)
    """
    result = FixResult(content=content)
    original = content

    # --- Pass 1: Python comments → JS comments ---
    content = _js_fix_python_comments(content, result.fixes_applied)

    # --- Pass 2: Object literal semicolons → commas ---
    # Must run BEFORE semicolon insertion so we don't add semicolons to
    # object properties that should have commas
    content = _js_fix_object_semicolons(content, result.fixes_applied)

    # --- Pass 3: Double semicolons ---
    content = _js_fix_double_semicolons(content, result.fixes_applied)

    # --- Pass 4: Missing semicolons (original v2 logic) ---
    lines = content.split("\n")
    in_template = False
    in_block_comment = False
    semi_count = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # Track block comments
        if "/*" in stripped and "*/" not in stripped:
            in_block_comment = True
            continue
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue

        # Skip comments
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Track template literals (backtick strings can span lines)
        backtick_count = stripped.count("`")
        if backtick_count % 2 != 0:
            in_template = not in_template
        if in_template:
            continue

        # Skip lines that shouldn't get semicolons
        if _JS_NO_SEMI.search(stripped):
            continue

        # Skip control flow / declaration keywords without values
        first_word = stripped.split()[0] if stripped.split() else ""
        if first_word in (
            "if", "else", "for", "while", "do", "switch", "case",
            "default:", "try", "catch", "finally", "class", "function",
            "export", "import", "from",
        ):
            continue

        # Add semicolon if line ends with a statement-like token
        if _JS_SEMI_ENDINGS.search(stripped):
            lines[i] = line.rstrip() + ";"
            semi_count += 1

    if semi_count:
        content = "\n".join(lines)
        result.fixes_applied.append(
            f"Added {semi_count} missing semicolon(s)"
        )

    # --- Pass 5: Unclosed string literals ---
    content = _js_fix_unclosed_strings(content, result.fixes_applied)

    # --- Pass 6: innerHTML → textContent ---
    content = _js_fix_innerhtml(content, result.fixes_applied)

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Layer 3: Markdown fence and link repair (v2)
# ---------------------------------------------------------------------------

def fix_markdown(content: str) -> FixResult:
    """Markdown fixes: unclosed code fences, unbalanced links/images.

    Conservative: only fix clearly broken syntax. Don't touch inline backticks.
    """
    result = FixResult(content=content)
    original = content

    # Unclosed code fences (``` without matching ```)
    fence_pattern = re.compile(r"^(`{3,})", re.MULTILINE)
    fences = fence_pattern.findall(content)
    if len(fences) % 2 != 0:
        # Odd number of fences — add a closing fence at the end
        content = content.rstrip("\n") + "\n```\n"
        result.fixes_applied.append("Closed unclosed code fence")

    # Unbalanced link syntax: [text](url  -> [text](url)
    content = re.sub(
        r'\[([^\]]*)\]\(([^)\s]+)(?:\s[^)]*)?\s*$',
        lambda m: m.group(0) if m.group(0).endswith(")") else m.group(0) + ")",
        content,
        flags=re.MULTILINE,
    )
    if content != original and "link" not in str(result.fixes_applied):
        result.fixes_applied.append("Closed unbalanced link/image syntax")

    # Unbalanced image syntax: ![alt](src  -> ![alt](src)
    content = re.sub(
        r'!\[([^\]]*)\]\(([^)\s]+)(?:\s[^)]*)?\s*$',
        lambda m: m.group(0) if m.group(0).endswith(")") else m.group(0) + ")",
        content,
        flags=re.MULTILINE,
    )
    if content != original and "image" not in str(result.fixes_applied):
        if "link" not in str(result.fixes_applied):
            result.fixes_applied.append("Closed unbalanced image syntax")

    result.content = content
    result.changed = content != original
    return result


# ---------------------------------------------------------------------------
# Cross-language detection (v2.5)
# ---------------------------------------------------------------------------

_C_FAMILY_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".rs", ".go", ".java",
                        ".c", ".cpp", ".h", ".hpp", ".css", ".php"}

_DEF_PATTERNS = {
    ".js":  [re.compile(r'^(?:export\s+)?(?:async\s+)?function\s+(\w+)'),
             re.compile(r'^(?:export\s+)?class\s+(\w+)'),
             re.compile(r'^(?:export\s+)?const\s+(\w+)\s*=')],
    ".rs":  [re.compile(r'^(?:pub\s+)?(?:async\s+)?fn\s+(\w+)'),
             re.compile(r'^(?:pub\s+)?struct\s+(\w+)'),
             re.compile(r'^(?:pub\s+)?enum\s+(\w+)')],
    ".go":  [re.compile(r'^func\s+(\w+)'),
             re.compile(r'^type\s+(\w+)\s+struct')],
}
_DEF_PATTERNS[".ts"] = _DEF_PATTERNS[".js"]
_DEF_PATTERNS[".jsx"] = _DEF_PATTERNS[".js"]
_DEF_PATTERNS[".tsx"] = _DEF_PATTERNS[".js"]


def _detect_truncation_generic(content: str, ext: str) -> list[str]:
    """Detect truncated code in C-family languages. Returns error messages.
    v2.5 addition.
    """
    if ext not in _C_FAMILY_EXTENSIONS:
        return []

    errors = []

    # Unclosed block comments
    open_comments = 0
    i = 0
    in_str = None
    in_line_comment = False
    while i < len(content):
        ch = content[i]
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_str:
            if ch == "\\" and i + 1 < len(content):
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        two = content[i:i + 2]
        if two == "//":
            in_line_comment = True
            i += 2
            continue
        if two == "/*":
            open_comments += 1
            i += 2
            continue
        if two == "*/":
            open_comments -= 1
            i += 2
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
        i += 1

    if open_comments > 0:
        errors.append("File appears truncated — unclosed block comment (/* without */)")

    # Unclosed braces
    open_braces = 0
    i = 0
    in_str = None
    in_line_comment = False
    in_block_comment = False
    while i < len(content):
        ch = content[i]
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if content[i:i + 2] == "*/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_str:
            if ch == "\\" and i + 1 < len(content):
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        two = content[i:i + 2]
        if two == "//":
            in_line_comment = True
            i += 2
            continue
        if two == "/*":
            in_block_comment = True
            i += 2
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
        elif ch == "{":
            open_braces += 1
        elif ch == "}":
            open_braces -= 1
        i += 1

    if open_braces > 0:
        errors.append(f"File appears truncated — {open_braces} unclosed brace(s)")

    return errors


def _detect_duplicate_defs_generic(content: str, ext: str) -> list[str]:
    """Detect duplicate top-level definitions in non-Python languages.
    v2.5 addition.
    """
    patterns = _DEF_PATTERNS.get(ext)
    if not patterns:
        return []

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


# ---------------------------------------------------------------------------
# Extension -> fixer chain mapping
# ---------------------------------------------------------------------------

# Each chain runs in order. Universal normalisation always runs first.
# Prose stripping only runs on code files (not data formats like JSON/YAML).
FIXER_CHAINS = {
    # Code files (prose stripping enabled)
    ".py":          [fix_universal, strip_prose, fix_python],
    ".rs":          [fix_universal, strip_prose, fix_rust],
    ".html":        [fix_universal, strip_prose, fix_html],
    ".htm":         [fix_universal, strip_prose, fix_html],
    ".css":         [fix_universal, fix_css],
    ".sql":         [fix_universal, fix_sql],
    ".sh":          [fix_universal, strip_prose, fix_shell],
    ".bash":        [fix_universal, strip_prose, fix_shell],

    # Data/config files (no prose stripping — content is the data)
    ".json":        [fix_universal, fix_json],
    ".yaml":        [fix_universal, fix_yaml],
    ".yml":         [fix_universal, fix_yaml],
    ".toml":        [fix_universal, fix_toml],

    # Container files (prose stripping enabled)
    "Dockerfile":   [fix_universal, strip_prose, fix_dockerfile],
    "Containerfile": [fix_universal, strip_prose, fix_dockerfile],
    ".dockerfile":  [fix_universal, strip_prose, fix_dockerfile],

    # Languages we don't have specific fixers for yet — universal only.
    # Listed explicitly so they get universal normalisation (BOM, CRLF,
    # whitespace, newline) rather than being silently skipped.
    ".js":          [fix_universal, strip_prose, fix_javascript],
    ".ts":          [fix_universal, strip_prose, fix_javascript],
    ".jsx":         [fix_universal, strip_prose, fix_javascript],
    ".tsx":         [fix_universal, strip_prose, fix_javascript],
    ".c":           [fix_universal],
    ".cpp":         [fix_universal],
    ".h":           [fix_universal],
    ".hpp":         [fix_universal],
    ".java":        [fix_universal],
    ".go":          [fix_universal],
    ".rb":          [fix_universal],
    ".lua":         [fix_universal],
    ".xml":         [fix_universal],
    ".ini":         [fix_universal],
    ".cfg":         [fix_universal],
    ".conf":        [fix_universal],
    ".php":         [fix_universal],
    ".txt":         [fix_universal],
    ".md":          [fix_universal, fix_markdown],
    ".csv":         [fix_universal],
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def fix_code(filename: str, content: str) -> FixResult:
    """Run the appropriate fixer chain for a file.

    Args:
        filename: The file path (used for language detection via extension).
                  This is always available at the integration point in
                  executor.py _file_write().
        content:  The file content to fix (after RESPONSE/fence stripping
                  by executor).

    Returns:
        FixResult with the (possibly fixed) content and audit metadata.
        On any error, returns the original content unchanged.
    """
    # Guard: empty/whitespace content — pass through unchanged
    if _is_empty_or_whitespace(content):
        return FixResult(content=content, skipped=True,
                         skip_reason="Empty or whitespace-only content")

    # Guard: binary content — pass through unchanged
    if _looks_binary(content):
        return FixResult(content=content, skipped=True,
                         skip_reason="Binary content detected")

    # Guard: oversized content — universal only (BOM/CRLF/whitespace)
    path = Path(filename)
    ext = path.suffix.lower()
    name = path.name

    if len(content) > _MAX_FIX_SIZE:
        result = fix_universal(content)
        result.warnings.append(
            f"File exceeds {_MAX_FIX_SIZE // 1000}KB — only universal fixes applied"
        )
        return result

    # Select fixer chain: match by exact filename first (Dockerfile),
    # then by extension, then fallback to universal-only
    chain = FIXER_CHAINS.get(name) or FIXER_CHAINS.get(ext) or [fix_universal]
    chain_names = [f.__name__ for f in chain]

    logger.debug(
        "Code fixer starting",
        extra={
            "event": "code_fixer_start",
            "filename": filename,
            "ext": ext,
            "chain": chain_names,
            "content_length": len(content),
            "content_preview": content[:500],
            "has_entities": ("&lt;" in content or "&gt;" in content),
        },
    )

    # Run chain with error isolation — if any fixer crashes, skip it
    # and continue with the remaining fixers
    combined = FixResult(content=content)
    for fixer in chain:
        try:
            pre_fixer = combined.content
            if fixer == strip_prose:
                lang = ext.lstrip(".") or name.lower()
                r = fixer(combined.content, lang)
            elif fixer == fix_html:
                r = fixer(combined.content, 0)
            else:
                r = fixer(combined.content)
            combined.content = r.content
            combined.changed = combined.changed or r.changed
            combined.fixes_applied.extend(r.fixes_applied)
            combined.errors_found.extend(r.errors_found)
            combined.warnings.extend(r.warnings)

            if r.changed:
                logger.debug(
                    "Code fixer layer applied changes",
                    extra={
                        "event": "code_fixer_layer",
                        "filename": filename,
                        "fixer": fixer.__name__,
                        "fixes": r.fixes_applied,
                        "content_length_before": len(pre_fixer),
                        "content_length_after": len(r.content),
                        "content_preview_after": r.content[:500],
                        "had_entities_before": ("&lt;" in pre_fixer),
                        "has_entities_after": ("&lt;" in r.content),
                    },
                )
            else:
                logger.debug(
                    "Code fixer layer — no changes",
                    extra={
                        "event": "code_fixer_layer_noop",
                        "filename": filename,
                        "fixer": fixer.__name__,
                    },
                )
        except Exception as exc:
            # Fail-safe: log the error but don't block the file write
            fixer_name = fixer.__name__
            combined.warnings.append(
                f"Fixer {fixer_name} crashed: {type(exc).__name__}: {exc}"
            )
            logger.error(
                "Code fixer crashed — skipping",
                extra={
                    "event": "code_fixer_crash",
                    "fixer": fixer_name,
                    "filename": filename,
                    "error": str(exc),
                },
                exc_info=True,
            )

    # v2.5: Cross-language detection (runs after language-specific chain)
    truncation_errors = _detect_truncation_generic(combined.content, ext)
    combined.errors_found.extend(truncation_errors)

    # Skip duplicate detection for Python — it has its own detector in fix_python()
    if ext != ".py":
        dup_errors = _detect_duplicate_defs_generic(combined.content, ext)
        combined.errors_found.extend(dup_errors)

    return combined
