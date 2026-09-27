"""Input validation gates — script gate and prompt length constants.

Extracted from pipeline.py (Phase 8). Contains the ASCII/script gate
that blocks non-Latin characters in worker prompts, and the constants
for prompt length/token estimation gates.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from sentinel.core.exceptions import SecurityViolation

from ._audit_builders import build_gate_event
from ._enums import Phase
from ._gate_violations import build_gate_scan_result

if TYPE_CHECKING:
    from .pipeline import ScanPipeline

# Use pipeline's logger name so test caplog filters continue to work.
# Gate modules are logically part of the pipeline — the split is structural only.
logger = logging.getLogger("sentinel.security.pipeline")

# Finding #23: token estimation for prompt length gate.
# Conservative: 3.0 chars/token. Dense ASCII is ~4 chars/token, but
# code with single-char tokens (brackets, operators) can hit 2-3.
# 3.0 provides safety margin for symbol-heavy code.
_CHARS_PER_TOKEN_ESTIMATE = 3.0
_CONTEXT_TOKEN_LIMIT = 24_000  # Qwen 3 14B context window
_MAX_PROMPT_CHARS = 100_000  # Hard limit on combined prompt character count

# Allowed characters in prompts sent to the worker LLM.
# Goal: block non-Latin scripts (CJK, Cyrillic, Arabic, Hangul, etc.)
# that Qwen might interpret as instructions, while allowing the
# typographic Unicode that Claude legitimately uses (smart quotes,
# em-dashes, math symbols, currency, accented Latin, etc.).
_ALLOWED_PROMPT_CHARS = re.compile(
    r"["
    r"\x09\x0a\x0d"  # Tab, newline, carriage return
    r"\x20-\x7e"  # Printable ASCII
    r"\u00a0-\u00ff"  # Latin-1 Supplement (£, ©, ®, ±, accented chars)
    r"\u0100-\u024f"  # Latin Extended-A & B
    r"\u0250-\u02af"  # IPA Extensions
    r"\u02b0-\u02ff"  # Spacing Modifier Letters
    r"\u0300-\u036f"  # Combining Diacritical Marks
    # Greek: restricted to modern letters + math/science variants only.
    # Full \u0370-\u03ff includes archaic letters (Ϙ, Ϛ, Ϝ, Ϟ, Ϡ) and
    # Coptic characters (Ϣ, Ϥ) that could be used for injection via
    # Greek-language prompts that Qwen understands.
    r"\u0391-\u03a9"  # Greek capital Α-Ω
    r"\u03b1-\u03c9"  # Greek small α-ω
    r"\u03d5\u03f5\u03d1"  # phi variant, lunate epsilon, theta variant
    r"\u03f0\u03f1\u03d6"  # kappa variant, rho variant, pi variant
    r"\u2000-\u206f"  # General Punctuation (dashes, quotes, ellipsis, bullets)
    r"\u2070-\u209f"  # Superscripts and Subscripts
    r"\u20a0-\u20cf"  # Currency Symbols (€, ₹, ₽, etc.)
    r"\u2100-\u214f"  # Letterlike Symbols (™, ℃, etc.)
    r"\u2150-\u218f"  # Number Forms (fractions, Roman numerals)
    r"\u2190-\u21ff"  # Arrows
    r"\u2200-\u22ff"  # Mathematical Operators
    r"\u2300-\u23ff"  # Miscellaneous Technical
    r"\u2500-\u257f"  # Box Drawing
    r"\u2580-\u259f"  # Block Elements
    r"\u25a0-\u25ff"  # Geometric Shapes
    r"\u2600-\u26ff"  # Miscellaneous Symbols
    r"\u2700-\u27bf"  # Dingbats
    r"\ufb00-\ufb06"  # Alphabetic Presentation (ligatures: fi, fl)
    r"]*",
    re.DOTALL,
)


def check_prompt_ascii(
    pipeline: ScanPipeline,
    prompt: str,
    pipeline_run_id: str | None = None,
) -> None:
    """Block non-Latin scripts in worker prompts to prevent cross-model injection.

    Allows ASCII + extended Latin + common typographic symbols (smart
    quotes, em-dashes, math, currency, arrows, box drawing, etc.).
    Blocks CJK, Cyrillic, Arabic, Hangul, and other scripts that Qwen
    might interpret as instructions.

    Intentionally checks only the Claude-generated instruction text (prompt),
    not the full_prompt which includes user-provided untrusted_data. User
    content may legitimately contain non-Latin Unicode; the script gate
    validates only the trusted instruction portion.
    """
    logger.debug(
        "check_prompt_ascii called",
        extra={
            "event": "security.input.check_prompt_ascii",
            "prompt_length": len(prompt),
        },
    )
    if _ALLOWED_PROMPT_CHARS.fullmatch(prompt):
        logger.debug(
            "ASCII prompt gate passed",
            extra={"event": "ascii.gate_pass", "prompt_length": len(prompt)},
        )
        return

    # Single-pass extraction of disallowed characters (negated class).
    # Must be the exact complement of _ALLOWED_PROMPT_CHARS.
    bad_chars = re.findall(
        r"[^\x09\x0a\x0d\x20-\x7e"
        r"\u00a0-\u00ff\u0100-\u024f\u0250-\u02af\u02b0-\u02ff"
        r"\u0300-\u036f"
        r"\u0391-\u03a9\u03b1-\u03c9\u03d5\u03f5\u03d1\u03f0\u03f1\u03d6"
        r"\u2000-\u206f\u2070-\u209f\u20a0-\u20cf\u2100-\u214f"
        r"\u2150-\u218f\u2190-\u21ff\u2200-\u22ff\u2300-\u23ff"
        r"\u2500-\u257f\u2580-\u259f\u25a0-\u25ff\u2600-\u26ff"
        r"\u2700-\u27bf\ufb00-\ufb06]",
        prompt,
    )[:5]  # First 5 bad chars to avoid log spam

    # Build a readable summary with positions
    char_desc = ", ".join(
        f"U+{ord(c):04X} '{c}' at pos {prompt.index(c)}" for c in bad_chars
    )

    logger.warning(
        "Non-Latin script in worker prompt blocked",
        extra={
            "event": "prompt.script_violation",
            "bad_char_count": len(bad_chars),
            "samples": char_desc,
        },
    )

    # Emit scan.gate audit event for ASCII gate failure
    if pipeline_run_id and pipeline._audit_emitter:
        pipeline._schedule_audit_events(
            [
                build_gate_event(
                    pipeline_run_id,
                    "ascii",
                    "BLOCKED",
                    severity="MEDIUM",
                    gate_value=len(bad_chars),
                )
            ]
        )

    raise SecurityViolation(
        f"Worker prompt contains blocked script characters: {char_desc}",
        build_gate_scan_result(
            scanner_name="ascii_prompt_gate",
            rule_id="non_latin_script_in_prompt",
            matched_text=char_desc,
            phase=Phase.INPUT,
        ),
    )
