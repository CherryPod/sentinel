"""Shell script fixer module.

Handles: shebang repair, unclosed quotes, block closers (fi/done),
unsafe pattern detection, $VAR-in-single-quote warnings.

Moved from monolith lines 1094-1220. Finding fixes applied:
  #9: heredoc guard covers quote fixer (not just fi/done)
  #10: if/for counting uses _iter_code_chars("shell") instead of naive regex
  #33: added --recursive --force long-form patterns to unsafe detection
  #34: broadened eval detection pattern
  #46: documented shebang prepend as intentional
  #55: $VAR warning iterates post-fix lines, not pre-fix
"""
import logging
import re

from ._core import (
    CharContext,
    FixResult,
    _current_filename,
    _iter_code_chars,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
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
    # Short-form flags: rm -rf / or rm -rf /*
    (re.compile(r'rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\s*$',
                re.MULTILINE),
     "Dangerous command: rm -rf / (recursive delete of root)"),
    (re.compile(r'rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\*',
                re.MULTILINE),
     "Dangerous command: rm -rf /* (recursive delete of all files)"),
    # Finding #33: long-form flag patterns
    (re.compile(r'rm\s+--recursive\s+--force\s+/\s*$', re.MULTILINE),
     "Dangerous command: rm --recursive --force / (recursive delete of root)"),
    (re.compile(r'rm\s+--recursive\s+--force\s+/\*', re.MULTILINE),
     "Dangerous command: rm --recursive --force /* (recursive delete of all files)"),
    (re.compile(r'rm\s+--force\s+--recursive\s+/\s*$', re.MULTILINE),
     "Dangerous command: rm --force --recursive / (recursive delete of root)"),
    (re.compile(r'rm\s+--force\s+--recursive\s+/\*', re.MULTILINE),
     "Dangerous command: rm --force --recursive /* (recursive delete of all files)"),
    (re.compile(r'chmod\s+777\b'),
     "chmod 777 sets world-writable permissions"),
    # Finding #34: broadened eval detection — matches eval $, eval "$, eval '$
    (re.compile(r'eval\s+["\']?\$'),
     "eval with variable input — potential code injection"),
    (re.compile(r':\(\)\s*\{.*\|.*&\s*\}\s*;'),
     "Fork bomb detected"),
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def fix_shell(content: str) -> FixResult:
    """Shell script fixes: shebang, unclosed quotes, block closers, unsafe patterns.

    v1: Add missing shebang
    v2: Detect unclosed double quotes per line
    v2.5: Shebang typo repair, missing fi/done, unsafe pattern detection
    """
    result = FixResult(content=content)
    original = content
    fname = _current_filename.get()

    # Finding #9: detect heredocs early — skip quote fixing for heredoc files
    has_heredoc = "<<" in content

    # Finding #46: Missing shebang — intentional prepend.
    # Shell scripts without a shebang default to the user's login shell,
    # which may not be bash. Adding #!/bin/bash is the safe default since
    # the fixer is for LLM-generated scripts targeting our container (bash).
    if not content.startswith("#!"):
        content = "#!/bin/bash\n" + content
        result.fixes_applied.append("Added shebang (#!/bin/bash)")
        logger.debug(
            "Added missing shebang",
            extra={
                "event": "fixer_detail",
                "fixer": "fix_shell",
                "file": fname,
            },
        )

    # v2: Detect unclosed double quotes on individual lines
    # (odd number of unescaped " on a line suggests a missing closing quote)
    # Finding #9: skip quote fixing entirely if heredocs are present
    lines = content.split("\n")
    if not has_heredoc:
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
            logger.debug(
                "Closed unclosed double quotes",
                extra={
                    "event": "fixer_detail",
                    "fixer": "fix_shell",
                    "file": fname,
                    "count": fixed_count,
                },
            )

    # Finding #55: $VAR warning should iterate post-fix lines (not pre-fix).
    # Re-split after any quote fixes above.
    lines = content.split("\n")

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
                logger.debug(
                    "Fixed shebang typo",
                    extra={
                        "event": "fixer_detail",
                        "fixer": "fix_shell",
                        "file": fname,
                        "wrong": wrong,
                        "right": right,
                    },
                )
                break

    # v2.5: Missing block closers (if/fi, for/done, while/done)
    # Finding #9: heredoc guard already applied above
    # Finding #10: use _iter_code_chars("shell") for context-aware keyword counting
    if not has_heredoc:
        lines = content.split("\n")

        # Count keywords using context-aware parser so we skip
        # keywords inside strings and comments, and avoid matching
        # prefixed words like 'ifdef' or 'ifconfig'
        if_count = 0
        fi_count = 0
        then_count = 0
        for_while_count = 0
        done_count = 0
        do_count = 0

        for line in lines:
            # Build a "code-only" version of the line for keyword matching
            code_chars: list[str] = []
            for _, ch, ctx in _iter_code_chars(line, "shell"):
                if ctx == CharContext.CODE:
                    code_chars.append(ch)
                else:
                    code_chars.append(" ")  # replace non-code with space
            code_line = "".join(code_chars).strip()

            # Match keywords with word boundaries to avoid 'ifdef', 'ifconfig' etc.
            if re.match(r'if\b', code_line):
                if_count += 1
            if re.match(r'fi\b', code_line):
                fi_count += 1
            if re.match(r'then\b', code_line) or '; then' in code_line:
                then_count += 1
            if re.match(r'(for|while)\b', code_line):
                for_while_count += 1
            if re.match(r'done\b', code_line):
                done_count += 1
            if re.match(r'do\b', code_line) or '; do' in code_line:
                do_count += 1

        if (if_count > 0 and then_count > 0
                and fi_count == if_count - 1 and if_count - fi_count == 1):
            content = content.rstrip("\n") + "\nfi\n"
            result.fixes_applied.append("Added missing 'fi' (unclosed if block)")
            logger.debug(
                "Added missing fi",
                extra={
                    "event": "fixer_detail",
                    "fixer": "fix_shell",
                    "file": fname,
                    "if_count": if_count,
                    "fi_count": fi_count,
                },
            )
        elif (for_while_count > 0 and do_count > 0
                and done_count == for_while_count - 1
                and for_while_count - done_count == 1):
            content = content.rstrip("\n") + "\ndone\n"
            result.fixes_applied.append("Added missing 'done' (unclosed for/while block)")
            logger.debug(
                "Added missing done",
                extra={
                    "event": "fixer_detail",
                    "fixer": "fix_shell",
                    "file": fname,
                    "loop_count": for_while_count,
                    "done_count": done_count,
                },
            )

    # v2.5: Unsafe pattern detection (detect only — don't modify content)
    for pattern, message in _UNSAFE_SHELL_PATTERNS:
        if pattern.search(content):
            result.errors_found.append(message)
            logger.debug(
                "Unsafe shell pattern detected",
                extra={
                    "event": "fixer_detail",
                    "fixer": "fix_shell",
                    "file": fname,
                    "pattern": message,
                },
            )

    result.content = content
    result.changed = content != original
    return result
