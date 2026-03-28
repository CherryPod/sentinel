"""JavaScript/TypeScript structural repair for the code_fixer package.

Contains: fix_javascript and 6 helpers (5 original + 1 extracted).

Finding fixes applied:
  #1  (HIGH): _js_fix_unclosed_strings rewritten with _iter_code_chars
  #15: brace depth counting via count_in_code
  #16: template literal tracking via _iter_code_chars (remove manual backtick counting)
  #26/#43: removed vestigial in_string variable, fixed j scope issue
  #41: extracted Pass 4 to _js_insert_missing_semicolons helper
  #54: split() result assigned once instead of called twice
"""
import logging
import re

from ._core import (
    CharContext,
    FixResult,
    _current_filename,
    _iter_code_chars,
    count_in_code,
    iter_code_lines,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regex constants (moved from monolith)
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


# ---------------------------------------------------------------------------
# Pass 1: Python-style comments -> JS-style
# ---------------------------------------------------------------------------
def _js_fix_python_comments(content: str, fixes: list[str]) -> str:
    """Convert Python-style `# comment` to JS-style `// comment`.

    Skips shebangs (#!) and lines inside strings/template literals.
    Only converts lines where # is the first non-whitespace character —
    never touches # inside code (e.g. hex colours, URL fragments).

    Finding #16: uses _iter_code_chars for template literal tracking
    instead of manual backtick counting.
    """
    lines = content.split("\n")
    fixed_count = 0

    # Finding #16: build a set of line numbers that are inside template
    # literals, using _iter_code_chars for accurate tracking
    template_lines: set[int] = set()
    current_line = 0
    in_template_body = False
    for _idx, ch, ctx in _iter_code_chars(content, "javascript"):
        if ch == "\n":
            current_line += 1
            continue
        # A line is "in template" if it has STRING context chars from a
        # template literal.  We detect this by tracking whether we're in
        # a multi-line string context (backtick strings span lines)
        if ctx == CharContext.STRING and in_template_body:
            template_lines.add(current_line)
        # Heuristic: backtick at STRING boundary toggles template body
        if ch == "`" and ctx == CharContext.STRING:
            in_template_body = not in_template_body

    for i, line in enumerate(lines):
        if i in template_lines:
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
        logger.debug(
            "Converted %d Python-style comments",
            fixed_count,
            extra={
                "event": "js_python_comments_fixed",
                "file": _current_filename.get(),
                "count": fixed_count,
            },
        )

    return content


# ---------------------------------------------------------------------------
# Pass 2: Object literal semicolons -> commas
# ---------------------------------------------------------------------------
def _js_fix_object_semicolons(content: str, fixes: list[str]) -> str:
    """Fix semicolons used instead of commas between object properties.

    Detects lines like `name: "test";` inside object literals and replaces
    the trailing semicolon with a comma. Only fixes when the context clearly
    indicates an object literal (next non-blank line is another property or
    a closing brace).

    Finding #15: uses count_in_code for string/comment-aware brace counting.
    Finding #26/#43: removed vestigial in_string variable, fixed j scope by
    assigning next_line_idx before the inner loop.
    """
    lines = content.split("\n")
    fixed_count = 0

    # Finding #15: use count_in_code for accurate brace depth
    # We track cumulative brace depth line-by-line using code-context chars
    brace_depth = 0
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

        # Finding #15: count braces in code context only for this line
        line_open = count_in_code(line, "javascript", "{")
        line_close = count_in_code(line, "javascript", "}")
        brace_depth += line_open - line_close

        # Only look for the pattern when we're inside braces (object context)
        if brace_depth <= 0:
            continue

        m = _JS_OBJ_PROP.match(line)
        if not m:
            continue

        # Confirm context: next non-blank line should be another property or }
        # Finding #43: assign next_line_idx before the loop to avoid scope issues
        next_meaningful = ""
        next_line_idx = i  # safe default
        for next_line_idx in range(i + 1, min(i + 5, len(lines))):
            candidate = lines[next_line_idx].strip()
            if candidate:
                next_meaningful = candidate
                break

        if not next_meaningful:
            continue

        # Next line is another property or closing brace — safe to fix
        looks_like_obj_context = (
            _JS_OBJ_PROP.match(lines[next_line_idx])
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
        logger.debug(
            "Fixed %d object literal semicolons",
            fixed_count,
            extra={
                "event": "js_object_semicolons_fixed",
                "file": _current_filename.get(),
                "count": fixed_count,
            },
        )

    return content


# ---------------------------------------------------------------------------
# Pass 3: Double semicolons
# ---------------------------------------------------------------------------
def _js_fix_double_semicolons(content: str, fixes: list[str]) -> str:
    """Replace `;;` with `;` — always unintentional in LLM output."""
    # Avoid touching `for (;;)` loops — only fix ;; at end of statements
    pattern = re.compile(r'(?<!\()(;;)(?!\s*\))')
    new_content = pattern.sub(";", content)
    if new_content != content:
        count = content.count(";;") - new_content.count(";;")
        fixes.append(f"Removed {count} double semicolon(s)")
        logger.debug(
            "Removed %d double semicolons",
            count,
            extra={
                "event": "js_double_semicolons_fixed",
                "file": _current_filename.get(),
                "count": count,
            },
        )
    return new_content


# ---------------------------------------------------------------------------
# Pass 4: Missing semicolons (Finding #41: extracted to named helper)
# ---------------------------------------------------------------------------
def _js_insert_missing_semicolons(content: str, fixes: list[str]) -> str:
    """Insert missing semicolons on statement-ending lines.

    Finding #41: extracted from inline code in fix_javascript for clarity.
    Finding #16: uses _iter_code_chars for template literal tracking
    instead of manual backtick counting.
    Finding #54: split() called once and result reused.
    """
    lines = content.split("\n")
    in_block_comment = False
    semi_count = 0

    # Finding #16: identify lines inside template literals using the
    # context-aware parser instead of manual backtick counting
    template_lines: set[int] = set()
    current_line = 0
    in_template_body = False
    for _idx, ch, ctx in _iter_code_chars(content, "javascript"):
        if ch == "\n":
            current_line += 1
            continue
        if ctx == CharContext.STRING and in_template_body:
            template_lines.add(current_line)
        if ch == "`" and ctx == CharContext.STRING:
            in_template_body = not in_template_body

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

        # Finding #16: skip lines inside template literals
        if i in template_lines:
            continue

        # Skip lines that shouldn't get semicolons
        if _JS_NO_SEMI.search(stripped):
            continue

        # Finding #54: assign split() result once
        parts = stripped.split()
        first_word = parts[0] if parts else ""
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
        fixes.append(f"Added {semi_count} missing semicolon(s)")
        logger.debug(
            "Added %d missing JS semicolons",
            semi_count,
            extra={
                "event": "js_semicolons_added",
                "file": _current_filename.get(),
                "count": semi_count,
            },
        )

    return content


# ---------------------------------------------------------------------------
# Pass 5: Unclosed string literals
# (Finding #1 HIGH: rewritten with _iter_code_chars)
# ---------------------------------------------------------------------------
def _js_fix_unclosed_strings(content: str, fixes: list[str]) -> str:
    """Fix unclosed string literals on single lines.

    Finding #1 (HIGH): rewritten to use iter_code_lines("javascript")
    instead of counting quote chars per line.  The old approach counted
    all quote characters which corrupted lines like "it's fine" (the
    apostrophe was counted as an unmatched single quote).

    New approach: uses the context-aware parser to check if a line ends
    in STRING context, which means a string opened but never closed on
    that line.  Only fixes simple cases — single-line strings that are
    clearly missing their closing delimiter.
    """
    lines = content.split("\n")
    fixed_count = 0

    for line_no, line_text, char_ctxs in iter_code_lines(content, "javascript"):
        stripped = line_text.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if not char_ctxs:
            continue

        # Check if the line ends in STRING context — an unclosed string
        last_col, last_ctx = char_ctxs[-1]
        if last_ctx != CharContext.STRING:
            continue

        # Find what quote character opened the string by scanning backwards
        # from the end to find the transition from CODE to STRING
        open_quote = None
        for col_idx in range(len(char_ctxs) - 1):
            col, ctx = char_ctxs[col_idx]
            next_col, next_ctx = char_ctxs[col_idx + 1]
            if ctx == CharContext.CODE and next_ctx == CharContext.STRING:
                # The char at next_col is the string opener
                if next_col < len(line_text) and line_text[next_col] in ('"', "'"):
                    open_quote = line_text[next_col]
                    break

        if open_quote is None:
            # Could be a template literal or continuation — skip
            continue

        # Only fix if the line looks like a statement (has = or ( for assignment/call)
        if stripped.endswith(";"):
            # Insert closing quote before the semicolon
            lines[line_no] = line_text.rstrip()
            rstripped = lines[line_no]
            lines[line_no] = rstripped[:-1] + open_quote + ";"
            fixed_count += 1
        elif "=" in stripped or "(" in stripped:
            # Add closing quote at end
            lines[line_no] = line_text.rstrip() + open_quote
            fixed_count += 1

    if fixed_count:
        content = "\n".join(lines)
        fixes.append(f"Closed {fixed_count} unclosed string literal(s)")
        logger.debug(
            "Closed %d unclosed JS string literals",
            fixed_count,
            extra={
                "event": "js_unclosed_strings_fixed",
                "file": _current_filename.get(),
                "count": fixed_count,
            },
        )

    return content


# ---------------------------------------------------------------------------
# Pass 6: innerHTML -> textContent (defence-in-depth)
# ---------------------------------------------------------------------------
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
        logger.debug(
            "Replaced %d innerHTML assignments",
            fixed_count,
            extra={
                "event": "js_innerhtml_fixed",
                "file": _current_filename.get(),
                "count": fixed_count,
            },
        )

    return new_content


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def fix_javascript(content: str) -> FixResult:
    """JavaScript/TypeScript multi-pass fixer.

    Applies fixes in order from most structural to most local:
    1. Python-style comments -> JS-style (must run before semicolon logic)
    2. Object literal semicolons -> commas
    3. Double semicolons
    4. Missing semicolons (extracted to _js_insert_missing_semicolons)
    5. Unclosed string literals (rewritten with _iter_code_chars)
    6. innerHTML -> textContent (defence-in-depth)
    """
    result = FixResult(content=content)
    original = content

    logger.debug(
        "JavaScript fixer starting",
        extra={
            "event": "js_fixer_start",
            "file": _current_filename.get(),
            "content_length": len(content),
        },
    )

    # --- Pass 1: Python comments -> JS comments ---
    content = _js_fix_python_comments(content, result.fixes_applied)

    # --- Pass 2: Object literal semicolons -> commas ---
    # Must run BEFORE semicolon insertion so we don't add semicolons to
    # object properties that should have commas
    content = _js_fix_object_semicolons(content, result.fixes_applied)

    # --- Pass 3: Double semicolons ---
    content = _js_fix_double_semicolons(content, result.fixes_applied)

    # --- Pass 4: Missing semicolons (Finding #41: extracted to helper) ---
    content = _js_insert_missing_semicolons(content, result.fixes_applied)

    # --- Pass 5: Unclosed string literals ---
    content = _js_fix_unclosed_strings(content, result.fixes_applied)

    # --- Pass 6: innerHTML -> textContent ---
    content = _js_fix_innerhtml(content, result.fixes_applied)

    result.content = content
    result.changed = content != original
    return result
