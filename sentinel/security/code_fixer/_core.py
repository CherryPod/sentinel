"""Core foundation for the code_fixer package.

Contains: FixResult, content guards, _iter_code_chars() parser,
CharContext enum, _run_chain() chain runner, and context variable
for filename threading.
"""
import contextvars
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Filename context variable — set by chain runner, read by fixers for logging
# ---------------------------------------------------------------------------
_current_filename: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_current_filename", default="<unknown>"
)


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
    skipped: bool = False
    skip_reason: str = ""


# ---------------------------------------------------------------------------
# Safety: content guards
# ---------------------------------------------------------------------------
_MAX_FIX_SIZE = 100_000  # 100KB

# Finding #5 fix: operator precedence — parenthesise before subtraction
_BINARY_CHARS = (frozenset(range(0, 8)) | frozenset(range(14, 32))) - {9, 10, 13}


def _looks_binary(content: str) -> bool:
    """Check if content contains binary characters (null bytes, control chars)."""
    sample = content[:512]
    return any(ord(ch) in _BINARY_CHARS for ch in sample)


def _is_empty_or_whitespace(content: str) -> bool:
    """Check if content is empty or whitespace-only."""
    return not content or not content.strip()


# ---------------------------------------------------------------------------
# Context-aware character parser
# ---------------------------------------------------------------------------
class CharContext(Enum):
    """Context classification for a character in source code."""
    CODE = "code"
    STRING = "string"
    COMMENT = "comment"


def _iter_code_chars(
    content: str, language: str
) -> Iterator[tuple[int, str, CharContext]]:
    """Yield (index, char, context) for every character in content.

    The parser is language-aware: it knows each language's comment syntax
    and string delimiters, so callers can filter to CODE-only characters
    without worrying about brackets/quotes inside strings or comments.

    Supported languages and their syntax:
    - "python": # line comments, ', ", ''', triple-quote strings
    - "javascript": //, /* */ comments, ', ", ` (template literal) strings
    - "rust": //, /* */ comments, ', " strings, r#""# raw strings
    - "shell": # line comments, ', " strings, heredoc bodies
    - "css": /* */ block comments only
    - "html": <!-- --> comments, ', " attribute strings
    - "json": " strings only, no comments
    - "sql": -- line comments, ' strings
    - "dockerfile": # line comments, ', " strings

    Design decisions:
    - JS template literals: ${...} content returns CODE (nesting stack)
    - Shell heredocs: body lines return STRING
    - Rust raw strings: counts # chars after r for termination
    """
    length = len(content)
    i = 0

    # Language-specific configuration
    line_comment_markers: list[str] = []
    block_comment_open = ""
    block_comment_close = ""
    string_delimiters: list[str] = []
    has_triple_quotes = False
    has_template_literals = False
    has_raw_strings = False   # Rust r#"..."#
    has_heredocs = False      # Shell <<EOF...EOF

    if language == "python":
        line_comment_markers = ["#"]
        string_delimiters = ["'", '"']
        has_triple_quotes = True
    elif language == "javascript":
        line_comment_markers = ["//"]
        block_comment_open = "/*"
        block_comment_close = "*/"
        string_delimiters = ["'", '"', "`"]
        has_template_literals = True
    elif language == "rust":
        line_comment_markers = ["//"]
        block_comment_open = "/*"
        block_comment_close = "*/"
        string_delimiters = ["'", '"']
        has_raw_strings = True
    elif language == "shell":
        line_comment_markers = ["#"]
        string_delimiters = ["'", '"']
        has_heredocs = True
    elif language == "css":
        block_comment_open = "/*"
        block_comment_close = "*/"
    elif language == "html":
        block_comment_open = "<!--"
        block_comment_close = "-->"
        string_delimiters = ["'", '"']
    elif language == "json":
        string_delimiters = ['"']
    elif language == "sql":
        line_comment_markers = ["--"]
        string_delimiters = ["'"]
    elif language == "dockerfile":
        line_comment_markers = ["#"]
        string_delimiters = ["'", '"']

    # Template literal nesting stack for JS: tracks brace depth inside ${}
    template_brace_stack: list[int] = []
    # Heredoc state for shell
    heredoc_delimiter: str | None = None

    while i < length:
        ch = content[i]

        # --- Shell heredoc body ---
        if has_heredocs and heredoc_delimiter is not None:
            # Check if this line is the closing delimiter
            line_end = content.find("\n", i)
            if line_end == -1:
                line_end = length
            line_text = content[i:line_end].strip()
            if line_text == heredoc_delimiter:
                # Closing delimiter line — emit as CODE
                while i < line_end:
                    yield (i, content[i], CharContext.CODE)
                    i += 1
                if i < length:
                    yield (i, content[i], CharContext.CODE)  # the \n
                    i += 1
                heredoc_delimiter = None
                continue
            else:
                # Heredoc body — all STRING
                while i < line_end:
                    yield (i, content[i], CharContext.STRING)
                    i += 1
                if i < length:
                    yield (i, content[i], CharContext.STRING)  # the \n
                    i += 1
                continue

        # --- JS template literal: check for ${ and } ---
        if has_template_literals and template_brace_stack:
            if ch == "}" and template_brace_stack:
                if template_brace_stack[-1] == 0:
                    # Exiting ${...} — back to STRING (template literal body)
                    template_brace_stack.pop()
                    yield (i, ch, CharContext.CODE)
                    i += 1
                    continue
                else:
                    template_brace_stack[-1] -= 1
            elif ch == "{":
                template_brace_stack[-1] += 1

        # --- Block comments ---
        if block_comment_open and content[i:i+len(block_comment_open)] == block_comment_open:
            marker_len = len(block_comment_open)
            close_len = len(block_comment_close)
            # Emit the opening marker
            for j in range(marker_len):
                yield (i + j, content[i + j], CharContext.COMMENT)
            i += marker_len
            # Find closing marker
            while i < length:
                if content[i:i+close_len] == block_comment_close:
                    for j in range(close_len):
                        yield (i + j, content[i + j], CharContext.COMMENT)
                    i += close_len
                    break
                yield (i, content[i], CharContext.COMMENT)
                i += 1
            continue

        # --- Line comments ---
        matched_line_comment = False
        for marker in line_comment_markers:
            if content[i:i+len(marker)] == marker:
                # Emit all chars until end of line as COMMENT
                while i < length and content[i] != "\n":
                    yield (i, content[i], CharContext.COMMENT)
                    i += 1
                matched_line_comment = True
                break
        if matched_line_comment:
            continue

        # --- String literals ---
        matched_string = False
        for delim in string_delimiters:
            # Python triple-quoted strings
            if has_triple_quotes and delim in ("'", '"'):
                triple = delim * 3
                if content[i:i+3] == triple:
                    # Emit opening triple quote
                    for j in range(3):
                        yield (i + j, content[i + j], CharContext.STRING)
                    i += 3
                    # Find closing triple quote
                    while i < length:
                        if content[i] == "\\" and i + 1 < length:
                            yield (i, content[i], CharContext.STRING)
                            yield (i + 1, content[i + 1], CharContext.STRING)
                            i += 2
                            continue
                        if content[i:i+3] == triple:
                            for j in range(3):
                                yield (i + j, content[i + j], CharContext.STRING)
                            i += 3
                            break
                        yield (i, content[i], CharContext.STRING)
                        i += 1
                    matched_string = True
                    break

            # Rust raw strings: r#"..."#, r##"..."##, etc.
            if has_raw_strings and ch == "r" and i + 1 < length and content[i + 1] == "#":
                # Count the # characters
                hash_count = 0
                j = i + 1
                while j < length and content[j] == "#":
                    hash_count += 1
                    j += 1
                if j < length and content[j] == '"':
                    # This is a raw string: r###"..."###
                    close_seq = '"' + "#" * hash_count
                    # Emit r + hashes + opening quote
                    start = i
                    end_of_open = j + 1
                    for k in range(start, end_of_open):
                        yield (k, content[k], CharContext.STRING)
                    i = end_of_open
                    # Find closing sequence
                    while i < length:
                        if content[i:i+len(close_seq)] == close_seq:
                            for k in range(len(close_seq)):
                                yield (i + k, content[i + k], CharContext.STRING)
                            i += len(close_seq)
                            break
                        yield (i, content[i], CharContext.STRING)
                        i += 1
                    matched_string = True
                    break

            # JS template literals with ${} nesting
            if has_template_literals and delim == "`":
                if ch == "`":
                    yield (i, ch, CharContext.STRING)
                    i += 1
                    # Inside template literal body
                    while i < length:
                        c = content[i]
                        if c == "\\" and i + 1 < length:
                            yield (i, c, CharContext.STRING)
                            yield (i + 1, content[i + 1], CharContext.STRING)
                            i += 2
                            continue
                        if c == "`":
                            yield (i, c, CharContext.STRING)
                            i += 1
                            break
                        if c == "$" and i + 1 < length and content[i + 1] == "{":
                            # Enter ${} expression — push brace depth 0
                            yield (i, c, CharContext.STRING)      # $
                            yield (i + 1, content[i + 1], CharContext.CODE)  # {
                            template_brace_stack.append(0)
                            i += 2
                            break  # back to main loop to parse CODE
                        yield (i, c, CharContext.STRING)
                        i += 1
                    matched_string = True
                    break

            # Regular single-char delimiter strings
            if ch == delim:
                yield (i, ch, CharContext.STRING)
                i += 1
                while i < length:
                    c = content[i]
                    if c == "\\" and i + 1 < length:
                        yield (i, c, CharContext.STRING)
                        yield (i + 1, content[i + 1], CharContext.STRING)
                        i += 2
                        continue
                    yield (i, c, CharContext.STRING)
                    i += 1
                    if c == delim:
                        break
                matched_string = True
                break

        if matched_string:
            continue

        # --- Shell heredoc detection ---
        if has_heredocs and ch == "<" and content[i:i+2] == "<<":
            # Detect heredoc: <<DELIM or <<'DELIM' or <<"DELIM" or <<-DELIM
            yield (i, ch, CharContext.CODE)
            yield (i + 1, content[i + 1], CharContext.CODE)
            j = i + 2
            # Skip optional -
            if j < length and content[j] == "-":
                yield (j, content[j], CharContext.CODE)
                j += 1
            # Skip whitespace
            while j < length and content[j] in " \t":
                yield (j, content[j], CharContext.CODE)
                j += 1
            # Read delimiter (may be quoted)
            delim_start = j
            quote_char = None
            if j < length and content[j] in ("'", '"'):
                quote_char = content[j]
                yield (j, content[j], CharContext.CODE)
                j += 1
                delim_start = j
            while j < length and content[j] not in ("\n", " ", "\t"):
                if quote_char and content[j] == quote_char:
                    break
                j += 1
            heredoc_delimiter = content[delim_start:j]
            # Emit remaining chars on this line as CODE
            while j < length and content[j] != "\n":
                yield (j, content[j], CharContext.CODE)
                j += 1
            if j < length:
                yield (j, content[j], CharContext.CODE)  # the \n
                j += 1
            i = j
            continue

        # --- Regular code character ---
        yield (i, ch, CharContext.CODE)
        i += 1


# ---------------------------------------------------------------------------
# Convenience helpers built on _iter_code_chars
# ---------------------------------------------------------------------------
def count_in_code(content: str, language: str, char: str) -> int:
    """Count occurrences of char that are in CODE context only."""
    return sum(1 for _, c, ctx in _iter_code_chars(content, language)
               if c == char and ctx == CharContext.CODE)


def iter_code_lines(
    content: str, language: str
) -> Iterator[tuple[int, str, list[tuple[int, CharContext]]]]:
    """Yield (line_number, line_text, char_contexts) per line.

    char_contexts is a list of (column, context) for each character in the line.
    """
    lines = content.split("\n")
    char_contexts: dict[int, CharContext] = {}
    for idx, _, ctx in _iter_code_chars(content, language):
        char_contexts[idx] = ctx

    offset = 0
    for line_no, line_text in enumerate(lines):
        line_ctxs = []
        for col in range(len(line_text)):
            ctx = char_contexts.get(offset + col, CharContext.CODE)
            line_ctxs.append((col, ctx))
        yield (line_no, line_text, line_ctxs)
        offset += len(line_text) + 1  # +1 for the \n


# ---------------------------------------------------------------------------
# Chain runner
# ---------------------------------------------------------------------------
def _run_chain(
    filename: str,
    content: str,
    chain: list,
    fixer_registry: dict | None = None,
    ext: str = "",
    name: str = "",
) -> FixResult:
    """Run a fixer chain with error isolation and rollback.

    Args:
        filename: File path (for logging context).
        content: Content to fix.
        chain: List of fixer callables.
        fixer_registry: Optional dict mapping fixer -> {"extra_args": lambda ext, name: tuple}.
        ext: File extension (for registry lambdas).
        name: File name (for registry lambdas).
    """
    _current_filename.set(filename)
    registry = fixer_registry or {}

    chain_names = [f.__name__ for f in chain]
    logger.debug(
        "Code fixer starting",
        extra={
            "event": "chain_start",
            "file": filename,  # UNTRUSTED — worker output
            "ext": ext,
            "chain": chain_names,
            "content_length": len(content),
            "content_preview": content[:500],  # UNTRUSTED — worker output
        },
    )

    combined = FixResult(content=content)
    for fixer in chain:
        try:
            pre_fixer = combined.content
            # Finding #42 fix: use registry instead of identity comparison
            reg_entry = registry.get(fixer)
            if reg_entry:
                extra_args = reg_entry["extra_args"](ext, name)
                r = fixer(combined.content, *extra_args)
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
                        "event": "fixer_applied",
                        "file": filename,
                        "fixer": fixer.__name__,
                        "fixes": r.fixes_applied,
                        "len_before": len(pre_fixer),
                        "len_after": len(r.content),
                    },
                )
            elif logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Code fixer layer — no changes",
                    extra={
                        "event": "fixer_noop",
                        "file": filename,
                        "fixer": fixer.__name__,
                    },
                )
        except Exception as exc:
            # Finding #35 fix: rollback partial mutations
            combined.content = pre_fixer
            fixer_name = fixer.__name__
            combined.warnings.append(
                f"Fixer {fixer_name} crashed: {type(exc).__name__}: {exc}"
            )
            logger.error(
                "Code fixer crashed — rolling back",
                extra={
                    "event": "fixer_crashed",
                    "fixer": fixer_name,
                    "file": filename,
                    "error": str(exc),
                },
                exc_info=True,
            )

    logger.debug(
        "Code fixer complete",
        extra={
            "event": "chain_complete",
            "file": filename,
            "changed": combined.changed,
            "fixes_count": len(combined.fixes_applied),
            "errors_count": len(combined.errors_found),
        },
    )

    return combined
