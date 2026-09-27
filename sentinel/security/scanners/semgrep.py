"""Semgrep scanner — ScannerPlugin wrapper.

Wraps the existing ``semgrep_scanner.scan_blocks()`` module-level function
in the unified ScannerPlugin interface.  The underlying subprocess logic,
semaphore limiting, and temp file creation are untouched — this module
only adapts the interface and adds fail-closed timeout handling.

Detection-only: returns raw matches without suppression logic.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING

from sentinel.core.decorators import no_audit_log
from sentinel.security._enums import Phase, Platform, Severity
from sentinel.security._scan_context import MLMatchMeta, ScanMatch
from sentinel.security._scanner_registry import ScannerMeta
from sentinel.security.context_classifier import CODE_FENCE_RE as _CODE_FENCE_RE

if TYPE_CHECKING:
    from sentinel.security._scan_context import ScanContext

logger = logging.getLogger(__name__)

# Default timeout for the outer scan_blocks() call (seconds).
# Higher than the plan-specified 60s because this guards the *entire*
# scan_blocks() call, which runs multiple sequential subprocess scans
# (each with its own 30s per-subprocess timeout from semgrep_scanner).
# A scan with 4 blocks could legitimately take ~120s.
_DEFAULT_TIMEOUT_S = 120

# Confidence assigned to Semgrep static-analysis findings.
_SEMGREP_CONFIDENCE = 0.8

# Maximum characters kept in matched_text (no raw content in logs).
_MAX_MATCH_TEXT_LEN = 500

# Pre-compiled regex for indented code lines (4-space or tab prefix).
# Used by _extract_code_blocks to find code outside fenced blocks.
_INDENTED_LINE_RE = re.compile(r"^(?:    |\t).+", re.MULTILINE)


class SemgrepScanner:
    """ScannerPlugin wrapper for Semgrep static analysis.

    Delegates to ``sentinel.security.semgrep_scanner.scan_blocks()`` for
    the actual subprocess execution.  Handles failure modes:

    1. **Scanner not loaded** — synthetic fail-closed CRITICAL match.
    2. **Scan timeout** — synthetic fail-closed CRITICAL match via
       ``asyncio.wait_for()``.
    3. **Scan error** — synthetic fail-closed CRITICAL match.

    Code blocks are extracted from the scan context's raw text using
    fenced code block and indentation detection, then passed to
    ``scan_blocks()`` with language hints from the context regions.
    """

    def __init__(self, *, timeout_s: float = _DEFAULT_TIMEOUT_S) -> None:
        logger.debug(
            "semgrep scanner init",
            extra={
                "event": "security.scanner.semgrep.init",
                "timeout_s": timeout_s,
            },
        )
        self._timeout_s = timeout_s

    @property
    def scanner_meta(self) -> ScannerMeta:
        return ScannerMeta(
            name="semgrep",
            order=70,
            phases=frozenset({Phase.OUTPUT}),
            platforms=frozenset({Platform.ALL}),
            description="Static analysis via Semgrep CLI",
            expensive=True,
            execution_only=False,
        )

    async def scan(self, context: ScanContext) -> list[ScanMatch]:
        """Run Semgrep analysis on code blocks in the scan context.

        Extracts code blocks from ``context.raw_text``, passes them to
        the legacy ``scan_blocks()`` with language hints, and converts
        the result.  Returns a synthetic fail-closed match if Semgrep
        is unavailable or the scan times out.
        """
        from sentinel.security import semgrep_scanner as _sg

        logger.debug(
            "semgrep scan start",
            extra={
                "event": "security.scanner.semgrep.scan_start",
                "text_length": len(context.raw_text),
                "scanner_loaded": _sg.is_loaded(),
            },
        )

        # Fail-closed: scanner not loaded → synthetic CRITICAL match
        if not _sg.is_loaded():
            logger.warning(
                "semgrep scanner not loaded — fail-closed",
                extra={
                    "event": "security.scanner.fail_closed",
                    "scanner_name": self.scanner_meta.name,
                    "error_type": "scanner_not_loaded",
                },
            )
            return [self._synthetic_match("scanner_not_loaded")]
        logger.debug(
            "semgrep scanner loaded — proceeding",
            extra={
                "event": "security.scanner.semgrep.loaded_check_passed",
            },
        )  # auto:neg

        # Extract code blocks with language hints and raw_text offsets
        blocks = _extract_code_blocks(context.raw_text)
        if not blocks:
            logger.debug(
                "semgrep scan skipped (no code blocks)",
                extra={
                    "event": "security.scanner.semgrep.skipped",
                    "reason": "no_code_blocks",
                },
            )
            return []

        logger.debug(
            "semgrep scanning code blocks",
            extra={
                "event": "security.scanner.semgrep.blocks",
                "block_count": len(blocks),
            },
        )

        # Scan each block individually so we can attribute matches to their
        # originating block and compute correct raw_text offsets.
        # Track elapsed time so the total across all blocks stays within
        # _timeout_s (the outer guard), not _timeout_s per block.
        all_matches: list[ScanMatch] = []
        scan_start = time.monotonic()
        for code_text, lang_hint, content_offset in blocks:
            elapsed = time.monotonic() - scan_start
            remaining = self._timeout_s - elapsed
            if remaining <= 0:
                logger.warning(
                    "semgrep scan budget exhausted after %.1fs — fail-closed",
                    elapsed,
                    extra={
                        "event": "security.scanner.fail_closed",
                        "scanner_name": self.scanner_meta.name,
                        "error_type": "timeout",
                        "error_category": "scanner_failure",
                        "timeout_s": self._timeout_s,
                    },
                )
                return [self._synthetic_match("timeout")]
            try:
                legacy_result = await asyncio.wait_for(
                    _sg.scan_blocks([(code_text, lang_hint)]),
                    timeout=remaining,
                )
            except TimeoutError:
                logger.warning(
                    "semgrep scan timed out after %.1fs — fail-closed",
                    self._timeout_s,
                    extra={
                        "event": "security.scanner.fail_closed",
                        "scanner_name": self.scanner_meta.name,
                        "error_type": "timeout",
                        "error_category": "scanner_failure",
                        "timeout_s": self._timeout_s,
                    },
                    exc_info=True,
                )
                return [self._synthetic_match("timeout")]
            except Exception:
                logger.warning(
                    "semgrep scan failed — fail-closed",
                    extra={
                        "event": "security.scanner.fail_closed",
                        "scanner_name": self.scanner_meta.name,
                        "error_type": "scan_error",
                        "error_category": "scanner_failure",
                    },
                    exc_info=True,
                )
                return [self._synthetic_match("scan_error")]

            block_matches = _convert_legacy_matches(
                legacy_result.matches,
                self.scanner_meta.name,
                code_text,
                content_offset,
            )
            all_matches.extend(block_matches)

        logger.debug(
            "semgrep scan complete",
            extra={
                "event": "security.scanner.semgrep.complete",
                "match_count": len(all_matches),
                "block_count": len(blocks),
            },
        )
        return all_matches

    def _synthetic_match(self, error_type: str) -> ScanMatch:
        """Build a fail-closed synthetic match per design spec."""
        return ScanMatch(
            rule_id=f"ml.timeout.{self.scanner_meta.name}",
            scanner=self.scanner_meta.name,
            severity=Severity.CRITICAL,
            confidence=1.0,
            matched_text="",
            offset=0,
            length=0,
            region=None,
            metadata=MLMatchMeta(
                model_name=self.scanner_meta.name,
                model_confidence=0.0,
            ),
        )


@no_audit_log
def _extract_code_blocks(text: str) -> list[tuple[str, str | None, int]]:
    """Extract code blocks with language hints and raw_text offsets.

    Finds fenced code blocks (```lang ... ```) and indented code blocks.
    Returns list of ``(code_text, language_hint, content_start_offset)``
    tuples.  *content_start_offset* is the char position of the block
    content's first character in *text*, used to map block-local Semgrep
    line numbers back to raw_text positions.
    """
    logger.debug(
        "extracting code blocks",
        extra={
            "event": "security.scanner.semgrep.extract_blocks",
            "text_length": len(text),
        },
    )  # auto:entry
    blocks: list[tuple[str, str | None, int]] = []

    # Fenced code blocks — extract content and language tag
    for m in _CODE_FENCE_RE.finditer(text):
        lang_tag = m.group(1)  # language after opening ```
        content = m.group(2)  # block content
        if content and content.strip():
            lang_hint = (
                lang_tag.strip().lower() if lang_tag and lang_tag.strip() else None
            )
            blocks.append((content, lang_hint, m.start(2)))

    # Indented code blocks — no language hint available
    # Collect consecutive indented lines into blocks.
    # Skip lines that fall inside a fenced block to avoid double-extraction.
    fenced_ranges = [(start, start + len(code)) for code, _lang, start in blocks]
    indented_lines: list[str] = []
    block_start_offset = 0
    prev_end = -2  # track consecutive lines
    for m in _INDENTED_LINE_RE.finditer(text):
        # Skip if this line falls inside any fenced block range
        if any(fs <= m.start() < fe for fs, fe in fenced_ranges):
            # Flush any accumulated indented lines before skipping
            if indented_lines:
                block_text = "\n".join(indented_lines)
                if block_text.strip():
                    blocks.append((block_text, None, block_start_offset))
                indented_lines = []
            prev_end = -2
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        if line_start == prev_end + 1:
            # Consecutive with previous indented line
            indented_lines.append(m.group(0))
        else:
            # Start of a new indented block — flush previous
            if indented_lines:
                block_text = "\n".join(indented_lines)
                if block_text.strip():
                    blocks.append((block_text, None, block_start_offset))
            indented_lines = [m.group(0)]
            block_start_offset = m.start()
        prev_end = m.end()

    # Flush final indented block
    if indented_lines:
        block_text = "\n".join(indented_lines)
        if block_text.strip():
            blocks.append((block_text, None, block_start_offset))

    return blocks


def _line_to_offset(block_text: str, line_1based: int) -> int:
    """Convert a 1-based line number to a char offset within *block_text*.

    Semgrep reports findings as 1-based line numbers relative to the
    scanned block.  This converts to a 0-based char offset at the start
    of that line.
    """
    offset = 0
    for _ in range(line_1based - 1):
        nl = block_text.find("\n", offset)
        if nl == -1:
            break
        offset = nl + 1
    return offset


def _convert_legacy_matches(
    legacy_matches: list,
    scanner_name: str,
    block_text: str = "",
    content_offset: int = 0,
) -> list[ScanMatch]:
    """Convert legacy ``core.models.ScanMatch`` to new ``ScanMatch``.

    The legacy match has ``pattern_name``, ``matched_text``, ``position``
    (1-based line number within the scanned block).

    *block_text* is the code block content that was scanned.
    *content_offset* is the char position of the block content's first
    character in the original ``raw_text``.  Together they map the
    block-local line number to a char offset in ``raw_text``.
    """
    matches: list[ScanMatch] = []
    for lm in legacy_matches:
        # Determine severity from pattern name.
        # Fail-closed synthetic matches (semgrep_timeout, semgrep_scan_error,
        # semgrep_block_error, semgrep_not_found, semgrep_parse_error) are
        # CRITICAL. Regular findings are HIGH.
        is_error = lm.pattern_name in {
            "semgrep_timeout",
            "semgrep_scan_error",
            "semgrep_block_error",
            "semgrep_not_found",
            "semgrep_parse_error",
        }
        severity = Severity.CRITICAL if is_error else Severity.HIGH

        # Map block-local line number to raw_text char offset.
        # When Semgrep source-span metadata is available (start_col,
        # end_line, end_col, or byte offsets), use it for precise offset
        # and length. Otherwise fall back to line-start offset with
        # length=0 (line-anchored finding).
        #
        # Known limitation: Semgrep byte offsets may diverge from Python
        # char offsets on non-ASCII content (multi-byte chars). In our
        # threat model, scanned blocks are LLM output (overwhelmingly
        # ASCII). If non-ASCII scanning becomes relevant, this needs a
        # byte-to-char conversion step. See codex review tracker 2026-04-16.
        line_offset = _line_to_offset(block_text, lm.position)

        # Refine with start column if available (1-based → 0-based)
        if lm.start_col is not None:
            block_local_offset = line_offset + max(0, lm.start_col - 1)
        else:
            block_local_offset = line_offset

        raw_text_offset = content_offset + block_local_offset

        # Compute length from Semgrep span metadata
        if lm.semgrep_start_offset is not None and lm.semgrep_end_offset is not None:
            # Semgrep byte offsets are relative to the scanned file (block)
            match_length = lm.semgrep_end_offset - lm.semgrep_start_offset
        elif (
            lm.end_line is not None
            and lm.end_col is not None
            and lm.start_col is not None
        ):
            # Compute from line/col spans within the block
            end_block_offset = _line_to_offset(block_text, lm.end_line) + max(
                0, lm.end_col - 1
            )
            start_block_offset = _line_to_offset(block_text, lm.position) + max(
                0, lm.start_col - 1
            )
            match_length = max(0, end_block_offset - start_block_offset)
        else:
            # No span info available — line-anchored with zero length
            match_length = 0

        matches.append(
            ScanMatch(
                rule_id=lm.pattern_name,
                scanner=scanner_name,
                severity=severity,
                confidence=_SEMGREP_CONFIDENCE,
                matched_text=lm.matched_text[:_MAX_MATCH_TEXT_LEN]
                if lm.matched_text
                else "",
                offset=raw_text_offset,
                length=match_length,
                region=None,
                metadata=MLMatchMeta(
                    model_name=scanner_name,
                    model_confidence=_SEMGREP_CONFIDENCE,
                ),
            )
        )
    return matches
