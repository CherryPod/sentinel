"""Rust structural repair for the code_fixer package.

Contains: fix_rust, _complete_brackets_rust, _fix_rust_semicolons.

Finding fixes applied:
  #19: hand-rolled parser detects r#"..."# raw strings and skips their contents
  #20: semicolon fixer skips method chain continuations (lines starting with .)
  #45: validation gate — reverts bracket completion if net count worsens
"""
import logging

from ._core import (
    FixResult,
    _current_filename,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_RUST_SEMI_KEYWORDS = (
    "let ", "return ", "println!", "eprintln!", "print!",
    "assert", "panic!", "todo!", "unimplemented!", "vec!",
    "dbg!", "write!", "writeln!", "format!",
)


# ---------------------------------------------------------------------------
# Bracket completion (Finding #19: raw-string-aware hand-rolled parser)
# ---------------------------------------------------------------------------
def _complete_brackets_rust(content: str, result: FixResult) -> str:
    """Close unclosed brackets in truncated Rust code.

    Uses a hand-rolled parser rather than _iter_code_chars because the
    generic parser treats ' as a char literal delimiter, which conflicts
    with Rust lifetime syntax ('static, 'a). The hand-rolled version
    tracks " strings, r#"..."# raw strings, and // / /* */ comments.

    Finding #45: after appending closing brackets, a validation gate
    checks that no bracket type has a worse imbalance than before. If
    the fix overclosed (e.g. due to raw strings confusing the counter),
    the original content is returned unchanged.
    """
    original = content
    open_chars = {"(": ")", "[": "]", "{": "}"}
    close_chars = {v: k for k, v in open_chars.items()}
    stack: list[str] = []
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
            # Finding #19: detect Rust raw strings r#"..."#, r##"..."##, etc.
            # Skip their contents so brackets inside don't affect the count.
            elif ch == "r" and i + 1 < len(content):
                hash_count = 0
                j = i + 1
                while j < len(content) and content[j] == "#":
                    hash_count += 1
                    j += 1
                if hash_count > 0 and j < len(content) and content[j] == '"':
                    # This is a raw string — skip to closing "###
                    close_seq = '"' + "#" * hash_count
                    j += 1  # skip the opening "
                    while j < len(content):
                        if content[j : j + len(close_seq)] == close_seq:
                            j += len(close_seq)
                            break
                        j += 1
                    i = j
                    continue
                else:
                    # Not a raw string — treat 'r' as normal character
                    pass
            elif ch == '"':
                in_string = True
            elif ch in open_chars:
                stack.append(open_chars[ch])
            elif ch in close_chars:
                if stack and stack[-1] == ch:
                    stack.pop()
        i += 1

    added = False
    if stack:
        closing = "".join(reversed(stack))
        content = content.rstrip("\n") + "\n" + closing + "\n"
        added = True
        result.fixes_applied.append(
            f"Closed {len(stack)} unclosed bracket(s): {closing}"
        )
        logger.debug(
            "Completed %d unclosed Rust bracket(s)",
            len(stack),
            extra={
                "event": "rust_bracket_complete",
                "file": _current_filename.get(),
                "closing": closing,
            },
        )

    # Finding #45: validation gate — verify fix didn't make things worse
    if added:
        for open_ch, close_ch in [("(", ")"), ("[", "]"), ("{", "}")]:
            orig_net = original.count(open_ch) - original.count(close_ch)
            fixed_net = content.count(open_ch) - content.count(close_ch)
            if abs(fixed_net) > abs(orig_net):
                # Fix made imbalance worse — revert
                logger.info(
                    "Rust bracket completion reverted — made imbalance worse",
                    extra={
                        "event": "validation_rejected",
                        "fixer": "_complete_brackets_rust",
                        "file": _current_filename.get(),
                        "validator": "bracket_count",
                        "error_summary": f"{open_ch}/{close_ch}: {orig_net} -> {fixed_net}",
                    },
                )
                return original

    return content


# ---------------------------------------------------------------------------
# Semicolon insertion (Finding #20: method chain continuation detection)
# ---------------------------------------------------------------------------
def _fix_rust_semicolons(content: str, result: FixResult) -> str:
    """Add missing semicolons to Rust statement lines.

    Finding #20: skips lines starting with . (method chain continuations)
    since those are not complete statements.
    """
    lines = content.rstrip("\n").split("\n")
    fixed_count = 0
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # Finding #20: skip method chain continuations — a line starting
        # with . is a continuation of the previous expression, not a
        # standalone statement that needs a semicolon
        if stripped.startswith("."):
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
        logger.debug(
            "Added %d missing Rust semicolon(s)",
            fixed_count,
            extra={
                "event": "rust_semicolons_added",
                "file": _current_filename.get(),
                "count": fixed_count,
            },
        )
    return content


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def fix_rust(content: str) -> FixResult:
    """Rust-specific fixes: bracket completion, missing semicolons.

    Bracket counting uses a hand-rolled parser that handles //, /* */,
    "..." strings, and r#"..."# raw strings (Finding #19). Char literal
    syntax ('a, 'static) is intentionally not tracked as string delimiters
    to avoid conflicts with Rust lifetimes.
    Semicolons are only added to lines that start with known Rust statement
    keywords (let, return, println!, etc.) and are followed by a closing
    brace or end of file.
    """
    result = FixResult(content=content)
    original = content

    logger.debug(
        "Rust fixer starting",
        extra={
            "event": "rust_fixer_start",
            "file": _current_filename.get(),
            "content_length": len(content),
        },
    )

    # Bracket/brace completion (string/comment-aware)
    content = _complete_brackets_rust(content, result)

    # Missing semicolons on statement lines
    content = _fix_rust_semicolons(content, result)

    result.content = content
    result.changed = content != original
    return result
