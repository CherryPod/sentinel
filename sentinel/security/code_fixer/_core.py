"""Core foundation for the code_fixer package.

Contains: FixResult, content guards, _iter_code_chars() parser,
CharContext enum, _run_chain() chain runner, and context variable
for filename threading.
"""

import contextvars
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum

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
_BINARY_CHARS = (frozenset(range(8)) | frozenset(range(14, 32))) - {9, 10, 13}


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


class _CodeCharParser:
    """State machine for context-aware character iteration.

    Decomposes the parsing of source code into focused methods per
    language construct (comments, strings, heredocs, template literals).
    Each method advances ``self._i`` and yields ``(index, char, context)``
    tuples.
    """

    __slots__ = (
        "_block_comment_close",
        "_block_comment_open",
        "_content",
        "_has_heredocs",
        "_has_raw_strings",
        "_has_template_literals",
        "_has_triple_quotes",
        "_heredoc_delimiter",
        "_i",
        "_length",
        "_line_comment_markers",
        "_string_delimiters",
        "_template_brace_stack",
        "_template_literal_depth",
    )

    def __init__(self, content: str, language: str) -> None:
        self._content = content
        self._length = len(content)
        self._i = 0
        # Mutable parsing state
        self._template_brace_stack: list[int] = []
        self._template_literal_depth: int = 0
        self._heredoc_delimiter: str | None = None
        # Language-specific syntax rules
        self._line_comment_markers: list[str] = []
        self._block_comment_open: str = ""
        self._block_comment_close: str = ""
        self._string_delimiters: list[str] = []
        self._has_triple_quotes: bool = False
        self._has_template_literals: bool = False
        self._has_raw_strings: bool = False
        self._has_heredocs: bool = False
        self._configure(language)

    def _configure(self, language: str) -> None:
        """Set syntax rules for the target language."""
        if language == "python":
            self._line_comment_markers = ["#"]
            self._string_delimiters = ["'", '"']
            self._has_triple_quotes = True
        elif language == "javascript":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._line_comment_markers = ["//"]
            self._block_comment_open = "/*"
            self._block_comment_close = "*/"
            self._string_delimiters = ["'", '"', "`"]
            self._has_template_literals = True
        elif language == "rust":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._line_comment_markers = ["//"]
            self._block_comment_open = "/*"
            self._block_comment_close = "*/"
            self._string_delimiters = ["'", '"']
            self._has_raw_strings = True
        elif language == "shell":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._line_comment_markers = ["#"]
            self._string_delimiters = ["'", '"']
            self._has_heredocs = True
        elif language == "css":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._block_comment_open = "/*"
            self._block_comment_close = "*/"
        elif language == "html":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._block_comment_open = "<!--"
            self._block_comment_close = "-->"
            self._string_delimiters = ["'", '"']
        elif language == "json":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._string_delimiters = ['"']
        elif language == "sql":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._line_comment_markers = ["--"]
            self._string_delimiters = ["'"]
        elif language == "dockerfile":
            logger.debug(
                "_configure: clean", extra={"event": "core._configure.branch.clean"}
            )
            self._line_comment_markers = ["#"]
            self._string_delimiters = ["'", '"']

    # ------------------------------------------------------------------
    # Main dispatch loop
    # ------------------------------------------------------------------
    def parse(self) -> Iterator[tuple[int, str, CharContext]]:
        """Yield ``(index, char, context)`` for every character."""
        content = self._content
        while self._i < self._length:
            ch = content[self._i]

            # Shell heredoc body takes priority — entire lines are STRING
            if self._has_heredocs and self._heredoc_delimiter is not None:
                yield from self._parse_heredoc_body()
                continue

            # JS template ${} brace tracking — may consume or fall through
            if self._has_template_literals and self._template_brace_stack:
                if ch == "}" and self._template_brace_stack[-1] == 0:
                    # Exiting ${...} — emit closing brace, resume body
                    self._template_brace_stack.pop()
                    yield (self._i, ch, CharContext.CODE)
                    self._i += 1
                    yield from self._scan_template_body()
                    continue
                elif ch == "}":
                    logger.debug(
                        "parse: clean", extra={"event": "core.parse.branch.clean"}
                    )
                    self._template_brace_stack[-1] -= 1
                elif ch == "{":
                    logger.debug(
                        "parse: clean", extra={"event": "core.parse.branch.clean"}
                    )
                    self._template_brace_stack[-1] += 1

            # Block comments: /* */, <!-- -->
            if (
                self._block_comment_open
                and content[self._i : self._i + len(self._block_comment_open)]
                == self._block_comment_open
            ):
                yield from self._parse_block_comment()
                continue

            # Line comments: //, #, --
            line_comment_matched = False
            for marker in self._line_comment_markers:
                if content[self._i : self._i + len(marker)] == marker:
                    yield from self._parse_line_comment()
                    line_comment_matched = True
                    break
            if line_comment_matched:
                continue

            # String literals (triple-quoted, raw, template, regular)
            string_gen = self._match_string(ch)
            if string_gen is not None:
                yield from string_gen
                continue

            # Shell heredoc start: <<DELIM
            if (
                self._has_heredocs
                and ch == "<"
                and content[self._i : self._i + 2] == "<<"
            ):
                yield from self._parse_heredoc_start()
                continue

            # Regular code character
            yield (self._i, ch, CharContext.CODE)
            self._i += 1

    # ------------------------------------------------------------------
    # Comment parsers
    # ------------------------------------------------------------------
    def _parse_block_comment(self) -> Iterator[tuple[int, str, CharContext]]:
        """Consume a block comment (``/* */``, ``<!-- -->``)."""
        logger.debug(
            "block comment at offset %d",
            self._i,
            extra={"event": "core.parse_block_comment", "offset": self._i},
        )
        content = self._content
        marker_len = len(self._block_comment_open)
        close_seq = self._block_comment_close
        close_len = len(close_seq)
        # Emit the opening marker
        for j in range(marker_len):
            yield (self._i + j, content[self._i + j], CharContext.COMMENT)
        self._i += marker_len
        # Scan until closing marker
        while self._i < self._length:
            if content[self._i : self._i + close_len] == close_seq:
                for j in range(close_len):
                    yield (self._i + j, content[self._i + j], CharContext.COMMENT)
                self._i += close_len
                return
            yield (self._i, content[self._i], CharContext.COMMENT)
            self._i += 1

    def _parse_line_comment(self) -> Iterator[tuple[int, str, CharContext]]:
        """Consume a line comment until end of line."""
        content = self._content
        while self._i < self._length and content[self._i] != "\n":
            yield (self._i, content[self._i], CharContext.COMMENT)
            self._i += 1

    # ------------------------------------------------------------------
    # String dispatch
    # ------------------------------------------------------------------
    def _match_string(self, ch: str) -> Iterator[tuple[int, str, CharContext]] | None:
        """Match a string literal at current position. Returns generator or None."""
        for delim in self._string_delimiters:
            # Python triple-quoted strings (check before single-char)
            if self._has_triple_quotes and delim in ("'", '"'):
                triple = delim * 3
                if self._content[self._i : self._i + 3] == triple:
                    return self._parse_triple_string(triple)
            # Rust raw strings: r#"..."#
            if (
                self._has_raw_strings
                and ch == "r"
                and self._i + 1 < self._length
                and self._content[self._i + 1] == "#"
            ):
                return self._parse_rust_raw_string()
            # JS template literals
            if self._has_template_literals and delim == "`" and ch == "`":
                return self._parse_template_literal()
            # Regular single-char delimiter strings
            if ch == delim:
                return self._parse_regular_string(delim)
        return None

    def _parse_triple_string(
        self, triple: str
    ) -> Iterator[tuple[int, str, CharContext]]:
        """Consume a Python triple-quoted string."""
        content = self._content
        # Emit opening triple quote
        for j in range(3):
            yield (self._i + j, content[self._i + j], CharContext.STRING)
        self._i += 3
        # Scan until closing triple quote
        while self._i < self._length:
            if content[self._i] == "\\" and self._i + 1 < self._length:
                yield (self._i, content[self._i], CharContext.STRING)
                yield (self._i + 1, content[self._i + 1], CharContext.STRING)
                self._i += 2
                continue
            if content[self._i : self._i + 3] == triple:
                for j in range(3):
                    yield (self._i + j, content[self._i + j], CharContext.STRING)
                self._i += 3
                return
            yield (self._i, content[self._i], CharContext.STRING)
            self._i += 1

    def _parse_rust_raw_string(self) -> Iterator[tuple[int, str, CharContext]]:
        """Consume a Rust raw string ``r#"..."#``."""
        logger.debug(
            "rust raw string at offset %d",
            self._i,
            extra={"event": "core.parse_rust_raw_string", "offset": self._i},
        )
        content = self._content
        # Count the # characters after r
        hash_count = 0
        j = self._i + 1
        while j < self._length and content[j] == "#":
            hash_count += 1
            j += 1
        if j >= self._length or content[j] != '"':
            # Not actually a raw string — emit 'r' as CODE and return
            yield (self._i, content[self._i], CharContext.CODE)
            self._i += 1
            return
        close_seq = '"' + "#" * hash_count
        # Emit r + hashes + opening quote
        end_of_open = j + 1
        for k in range(self._i, end_of_open):
            yield (k, content[k], CharContext.STRING)
        self._i = end_of_open
        # Scan until closing sequence
        while self._i < self._length:
            if content[self._i : self._i + len(close_seq)] == close_seq:
                for k in range(len(close_seq)):
                    yield (self._i + k, content[self._i + k], CharContext.STRING)
                self._i += len(close_seq)
                return
            yield (self._i, content[self._i], CharContext.STRING)
            self._i += 1

    def _parse_template_literal(self) -> Iterator[tuple[int, str, CharContext]]:
        """Consume a JS template literal, pushing ``${}`` contexts."""
        # Emit opening backtick
        yield (self._i, self._content[self._i], CharContext.STRING)
        self._i += 1
        self._template_literal_depth += 1
        yield from self._scan_template_body()

    def _scan_template_body(self) -> Iterator[tuple[int, str, CharContext]]:
        """Scan template literal body — shared by initial entry and ``${}`` resume."""
        content = self._content
        while self._i < self._length:
            c = content[self._i]
            if c == "\\" and self._i + 1 < self._length:
                yield (self._i, c, CharContext.STRING)
                yield (self._i + 1, content[self._i + 1], CharContext.STRING)
                self._i += 2
                continue
            if c == "`":
                # Closing backtick
                yield (self._i, c, CharContext.STRING)
                self._i += 1
                self._template_literal_depth -= 1
                return
            if c == "$" and self._i + 1 < self._length and content[self._i + 1] == "{":
                # Enter ${} expression — push brace depth
                yield (self._i, c, CharContext.STRING)  # $
                yield (self._i + 1, content[self._i + 1], CharContext.CODE)  # {
                self._template_brace_stack.append(0)
                self._i += 2
                return  # back to main loop for CODE inside ${}
            yield (self._i, c, CharContext.STRING)
            self._i += 1

    def _parse_regular_string(
        self, delim: str
    ) -> Iterator[tuple[int, str, CharContext]]:
        """Consume a regular single-delimiter string."""
        content = self._content
        yield (self._i, content[self._i], CharContext.STRING)
        self._i += 1
        while self._i < self._length:
            c = content[self._i]
            if c == "\\" and self._i + 1 < self._length:
                yield (self._i, c, CharContext.STRING)
                yield (self._i + 1, content[self._i + 1], CharContext.STRING)
                self._i += 2
                continue
            yield (self._i, c, CharContext.STRING)
            self._i += 1
            if c == delim:
                return

    # ------------------------------------------------------------------
    # Heredoc parsers
    # ------------------------------------------------------------------
    def _parse_heredoc_body(self) -> Iterator[tuple[int, str, CharContext]]:
        """Process one heredoc body line (STRING) or closing delimiter (CODE)."""
        logger.debug(
            "heredoc body line at offset %d",
            self._i,
            extra={"event": "core.parse_heredoc_body", "offset": self._i},
        )
        content = self._content
        line_end = content.find("\n", self._i)
        if line_end == -1:
            logger.debug(
                "_parse_heredoc_body: line_end_eq",
                extra={
                    "event": "_core._parse_heredoc_body.match",
                    "reason": "line_end_eq",
                },
            )  # auto:neg
            line_end = self._length
        line_text = content[self._i : line_end].strip()

        if line_text == self._heredoc_delimiter:
            # Closing delimiter line — emit as CODE
            logger.debug(
                "_parse_heredoc_body: line_text_eq_heredoc_delimiter",
                extra={
                    "event": "_core._parse_heredoc_body.match",
                    "reason": "line_text_eq_heredoc_delimiter",
                },
            )  # auto:neg
            while self._i < line_end:
                yield (self._i, content[self._i], CharContext.CODE)
                self._i += 1
            if self._i < self._length:
                logger.debug(
                    "_parse_heredoc_body: i_lt_length",
                    extra={
                        "event": "_core._parse_heredoc_body.match",
                        "reason": "i_lt_length",
                    },
                )  # auto:neg
                yield (self._i, content[self._i], CharContext.CODE)  # the \n
                self._i += 1
            self._heredoc_delimiter = None
        else:
            # Heredoc body — all STRING
            logger.debug(
                "_parse_heredoc_body: line_text_eq_heredoc_delimiter",
                extra={
                    "event": "_core._parse_heredoc_body.clean",
                    "reason": "line_text_eq_heredoc_delimiter",
                },
            )  # auto:neg
            while self._i < line_end:
                yield (self._i, content[self._i], CharContext.STRING)
                self._i += 1
            if self._i < self._length:
                logger.debug(
                    "_parse_heredoc_body: i_lt_length",
                    extra={
                        "event": "_core._parse_heredoc_body.match",
                        "reason": "i_lt_length",
                    },
                )  # auto:neg
                yield (self._i, content[self._i], CharContext.STRING)  # the \n
                self._i += 1

    def _parse_heredoc_start(self) -> Iterator[tuple[int, str, CharContext]]:
        """Detect and consume shell heredoc start (``<<DELIM``)."""
        logger.debug(
            "heredoc start at offset %d",
            self._i,
            extra={"event": "core.parse_heredoc_start", "offset": self._i},
        )
        content = self._content
        # Emit <<
        yield (self._i, content[self._i], CharContext.CODE)
        yield (self._i + 1, content[self._i + 1], CharContext.CODE)
        j = self._i + 2
        # Skip optional -
        if j < self._length and content[j] == "-":
            yield (j, content[j], CharContext.CODE)
            j += 1
        # Skip whitespace
        while j < self._length and content[j] in " \t":
            yield (j, content[j], CharContext.CODE)
            j += 1
        # Read delimiter (may be quoted)
        delim_start = j
        quote_char = None
        if j < self._length and content[j] in ("'", '"'):
            quote_char = content[j]
            yield (j, content[j], CharContext.CODE)
            j += 1
            delim_start = j
        while j < self._length and content[j] not in ("\n", " ", "\t"):
            if quote_char and content[j] == quote_char:
                break
            j += 1
        delimiter = content[delim_start:j]
        if not delimiter:
            # Malformed heredoc (e.g. `<<\n`) — no delimiter text.
            # Treat `<<` as regular code to avoid matching every blank line.
            logger.debug(
                "empty heredoc delimiter at offset %d — treating as code",
                self._i,
                extra={"event": "core.empty_heredoc_skip", "offset": self._i},
            )
            self._i = j
            return
        logger.debug(
            "_parse_heredoc_start: not_delimiter_passed",
            extra={
                "event": "core.empty_heredoc_skip.passed",
                "reason": "not_delimiter_passed",
            },
        )  # auto:neg
        self._heredoc_delimiter = delimiter
        # Emit remaining chars on this line as CODE
        while j < self._length and content[j] != "\n":
            yield (j, content[j], CharContext.CODE)
            j += 1
        if j < self._length:
            yield (j, content[j], CharContext.CODE)  # the \n
            j += 1
        self._i = j


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
    logger.debug(
        "_iter_code_chars called",
        extra={
            "event": "core.iter_code_chars",
            "content_len": len(content) if content else 0,
            "language": language,
        },
    )
    yield from _CodeCharParser(content, language).parse()


# ---------------------------------------------------------------------------
# Convenience helpers built on _iter_code_chars
# ---------------------------------------------------------------------------
def count_in_code(content: str, language: str, char: str) -> int:
    """Count occurrences of char that are in CODE context only."""
    return sum(
        1
        for _, c, ctx in _iter_code_chars(content, language)
        if c == char and ctx == CharContext.CODE
    )


def iter_code_lines(
    content: str, language: str
) -> Iterator[tuple[int, str, list[tuple[int, CharContext]]]]:
    """Yield (line_number, line_text, char_contexts) per line.

    char_contexts is a list of (column, context) for each character in the line.
    """
    logger.debug(
        "iter_code_lines called",
        extra={
            "event": "core.iter_code_lines",
            "content_len": len(content) if content else 0,
            "language": language,
        },
    )
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
            "event": "core.chain_start",
            "file": filename,  # UNTRUSTED — worker output
            "ext": ext,
            "chain": chain_names,
            "content_length": len(content),
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
                        "event": "core.fixer_applied",
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
                        "event": "core.fixer_noop",
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
                    "event": "core.fixer_crashed",
                    "fixer": fixer_name,
                    "file": filename,
                    "error": str(exc),
                },
                exc_info=True,
            )

    logger.debug(
        "Code fixer complete",
        extra={
            "event": "core.chain_complete",
            "file": filename,
            "changed": combined.changed,
            "fixes_count": len(combined.fixes_applied),
            "errors_count": len(combined.errors_found),
        },
    )

    return combined
