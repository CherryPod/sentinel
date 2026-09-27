"""Async scanner dispatch with fail-closed crash/timeout handling.

This module is the sync→async cutover point for scanner execution
(Phase 9b-ii.1). Every scanner implementing the new ``ScannerPlugin``
protocol is driven through ``run_scanner_safe`` or the bulk
``dispatch_scanners`` wrapper — no other call path is permitted into
a scanner's ``scan()`` method from the pipeline.

Design contract (see docs/design/2026-04-13-scanner-refactor-design.md
§Fail-Closed Synthetic Matches):

- If ``await scanner.scan(context)`` raises, or exceeds ``timeout_s``,
  the dispatcher returns a synthetic ``ScanMatch`` carrying
  ``rule_id="ml.timeout.<scanner_name>"`` and ``severity=CRITICAL``.
  The suppression engine never suppresses matches with the
  ``ml.timeout.`` prefix — a failed scanner becomes a hard block, not
  a silent pass.

- ``crashed=True`` is returned on both exception and timeout, so the
  audit layer can mark the scanner as degraded and record the failure.

Pure helpers (no pipeline state) so phase modules compose them with
whatever scanner subset applies at their call site.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass

from sentinel.security._enums import Severity
from sentinel.security._scan_context import (
    MLMatchMeta,
    ScanContext,
    ScanMatch,
    SuppressionVerdict,
)
from sentinel.security._scanner_registry import ScannerPlugin

logger = logging.getLogger("sentinel.security.pipeline")

_ML_TIMEOUT_PREFIX = "ml.timeout."


@dataclass(frozen=True)
class ScannerRun:
    """Outcome of dispatching a single scanner.

    ``matches`` is always a non-empty tuple when ``crashed=True`` —
    fail-closed synthesizes a CRITICAL match so downstream code can
    treat the outcome uniformly without a ``crashed``-special-case
    branch in the suppression / adapter layers.
    """

    scanner: ScannerPlugin
    matches: tuple[ScanMatch, ...]
    crashed: bool
    duration_ms: int


def _synthetic_timeout_match(scanner_name: str) -> ScanMatch:
    """Build the CRITICAL synthetic match emitted on crash or timeout.

    ``rule_id`` uses the ``ml.timeout.`` prefix (enforced upstream by
    ``sentinel.security._suppression`` — those matches bypass the
    suppression engine entirely). ``model_confidence=0.0`` distinguishes
    synthetic timeouts from real ML findings at audit time.
    """
    return ScanMatch(
        rule_id=f"{_ML_TIMEOUT_PREFIX}{scanner_name}",
        scanner=scanner_name,
        severity=Severity.CRITICAL,
        confidence=1.0,
        matched_text="",
        offset=0,
        length=0,
        region=None,
        metadata=MLMatchMeta(
            model_name=scanner_name,
            model_confidence=0.0,
        ),
    )


async def run_scanner_safe(
    scanner: ScannerPlugin,
    context: ScanContext,
    *,
    timeout_s: float | None = None,
) -> ScannerRun:
    """Run one scanner with fail-closed crash/timeout handling.

    Arguments:
        scanner: A scanner implementing the ``ScannerPlugin`` protocol.
        context: Immutable scan context from the preprocessing phase.
        timeout_s: Optional wall-clock budget for the scanner. ``None``
            means no timeout is applied — callers should only omit this
            for Phase 1 (sub-ms regex) scanners.

    Returns:
        A ``ScannerRun`` carrying the matches (real or synthetic) and
        a ``crashed`` flag. Exceptions are logged and swallowed — this
        is the only function in the dispatch chain that may do that.
    """
    logger.debug(
        "scanner dispatch: start",
        extra={
            "event": "security.scanner.dispatch_start",
            "scanner_name": scanner.scanner_meta.name,
            "timeout_s": timeout_s,
        },
    )
    t0 = time.monotonic()
    scanner_name = scanner.scanner_meta.name
    try:
        if timeout_s is None:
            matches = await scanner.scan(context)
        else:
            matches = await asyncio.wait_for(scanner.scan(context), timeout_s)
    except asyncio.CancelledError:
        # Always re-raise cancellation (Python best practice) — a
        # cancelled request is a caller-driven teardown, not a scanner
        # failure.  Swallowing it would either hang the caller (if the
        # outer task is waiting) or silently lose the cancellation
        # signal.  Logged at DEBUG so operators can trace which scanner
        # was in-flight when cancellation arrived.
        logger.debug(
            "scanner dispatch cancelled",
            extra={
                "event": "security.scanner.dispatch_cancelled",
                "scanner_name": scanner_name,
            },
        )
        raise
    except TimeoutError:
        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.warning(
            "scanner timed out — failing closed",
            extra={
                "event": "security.scanner.fail_closed",
                "scanner_name": scanner_name,
                "error_type": "timeout",
                "timeout_s": timeout_s,
                "duration_ms": duration_ms,
            },
            exc_info=True,
        )
        return ScannerRun(
            scanner=scanner,
            matches=(_synthetic_timeout_match(scanner_name),),
            crashed=True,
            duration_ms=duration_ms,
        )
    except Exception:
        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "scanner crashed — failing closed",
            extra={
                "event": "security.scanner.fail_closed",
                "scanner_name": scanner_name,
                "error_type": "crash",
                "duration_ms": duration_ms,
            },
            exc_info=True,
        )
        return ScannerRun(
            scanner=scanner,
            matches=(_synthetic_timeout_match(scanner_name),),
            crashed=True,
            duration_ms=duration_ms,
        )

    duration_ms = int((time.monotonic() - t0) * 1000)
    logger.debug(
        "scanner dispatch: complete",
        extra={
            "event": "security.scanner.complete",
            "scanner_name": scanner_name,
            "match_count": len(matches),
            "duration_ms": duration_ms,
        },
    )
    return ScannerRun(
        scanner=scanner,
        matches=tuple(matches),
        crashed=False,
        duration_ms=duration_ms,
    )


async def dispatch_scanners(
    scanners: Sequence[ScannerPlugin],
    context: ScanContext,
    *,
    concurrent: bool = False,
    timeout_s: float | None = None,
) -> list[ScannerRun]:
    """Dispatch a scanner sequence, preserving registration order.

    Arguments:
        scanners: Ordered scanner sequence — caller has already filtered
            by phase / destination / expensive flag.
        context: Shared immutable scan context.
        concurrent: When ``True``, scanners run via ``asyncio.gather``.
            Use for Phase 2 expensive scanners; sequential dispatch is
            fine for Phase 1 regex scanners (sub-ms each).
        timeout_s: Per-scanner timeout when ``concurrent=True``. Ignored
            in sequential mode (Phase 1 scanners do not need timeouts).

    Returns:
        One ``ScannerRun`` per input scanner, in registration order.
        Result order is independent of completion order — caller-visible
        sequence is stable so audit events remain reproducible.
    """
    logger.debug(
        "dispatch_scanners: start",
        extra={
            "event": "security.dispatch.start",
            "scanner_count": len(scanners),
            "concurrent": concurrent,
            "timeout_s": timeout_s,
        },
    )

    if not scanners:
        return []

    if concurrent:
        coros = [run_scanner_safe(s, context, timeout_s=timeout_s) for s in scanners]
        runs = await asyncio.gather(*coros)
        return list(runs)

    runs: list[ScannerRun] = []
    for scanner in scanners:
        runs.append(await run_scanner_safe(scanner, context, timeout_s=timeout_s))
    return runs


def should_skip_expensive_scanners(
    verdicts: Sequence[SuppressionVerdict],
) -> bool:
    """Return True iff any verdict is unsuppressed AND CRITICAL.

    Early-termination predicate for the pipeline: after Phase 1
    dispatch + suppression evaluation, phase modules call this helper
    to decide whether to run Phase 2 (expensive ML/external scanners).

    Semantics (design doc §Execution Flow):

    - An **unsuppressed CRITICAL** match means a confirmed high-severity
      finding already exists — running Phase 2 is redundant effort and
      its ML timeouts would extend the blocked response. Skip Phase 2
      and set ``ScanResult.skipped_async=True``.
    - A **suppressed CRITICAL** match (handler matched, e.g. build
      context for a ``rm -rf``) means Phase 1's finding is not a real
      threat — continue to Phase 2. Synthetic ``ml.timeout.*`` matches
      bypass the engine entirely so they are always unsuppressed, which
      correctly preserves fail-closed behaviour.
    - A **non-CRITICAL** match never triggers early termination,
      regardless of suppression state. Early termination is reserved
      for the "blocked, done" case; lower severities go through Phase 2
      so ML detection can still corroborate or add context.
    """
    return any(
        not v.suppressed and v.match.severity is Severity.CRITICAL for v in verdicts
    )
