"""Shared helpers between ``_phase_input.py`` and ``_phase_output.py``.

Pure functions only — no hidden state. These helpers were duplicated
across both phase modules before scanner-hardening H2 consolidated
them here.

Logger is reused from the pipeline module so caplog filters in tests
continue to work; phase modules and this shared module are logically
part of the pipeline — the split is structural only.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from sentinel.core.context import get_task_id

from ._enums import Phase
from ._scanner_names import scanner_legacy_name

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sentinel.core.models import OutputDestination

    from ._phase_dispatch import ScannerRun
    from ._scan_context import ScanResult, SuppressionVerdict
    from ._scanner_registry import ScannerPlugin

logger = logging.getLogger("sentinel.security.pipeline")


def _log_scan_results(
    result: ScanResult,
    direction: str,
    text: str,
    elapsed: float,
    *,
    destination: OutputDestination | None = None,
) -> None:
    """Log per-scanner results and scan completion summary.

    Shared between ``run_input_scan`` and ``run_output_scan``.

    Direction-specific event names are preserved bit-for-bit against
    pre-H2 behaviour:

    - Input direction emits ``input.scanner_match`` per per-scanner hit;
      output direction emits ``scanner.match``. The asymmetry predates
      H2 and is retained to avoid perturbing log consumers.
    - The ``destination`` key is added to the completion-summary extras
      only for output scans (input callers pass ``None``, matching the
      pre-H2 shape that had no ``destination`` field at all).
    """
    per_scanner = result.verdicts_by_scanner()
    if result.is_clean:
        logger.debug(
            "All %s scanners clean",
            direction,
            extra={
                "event": "all.scanners_clean",
                "direction": direction,
                "scanner_count": len(per_scanner),
            },
        )

    for scanner_name in result.degraded_scanners:
        logger.warning(
            "Scanner running in degraded mode — results may be incomplete",
            extra={
                "event": "scanner.degraded",
                "scanner": scanner_name,
            },
        )

    match_event = "scanner.match" if direction == "output" else "input.scanner_match"
    for scanner_name, verdicts in per_scanner.items():
        unsuppressed = [v for v in verdicts if not v.suppressed]
        if unsuppressed:
            logger.info(
                "Scanner found matches",
                extra={
                    "event": match_event,
                    "scanner": scanner_name,
                    "match_count": len(verdicts),
                    "patterns": [v.match.rule_id for v in verdicts],
                },
            )

    log_extra: dict = {
        "event": f"scan.{direction}",
        "task_id": get_task_id(),
        "clean": result.is_clean,
        "scanners": list(per_scanner.keys()),
        "violations": list(result.violated_scanners()),
        "text_length": len(text),
        "elapsed_s": round(elapsed, 3),
    }
    if destination is not None:
        log_extra["destination"] = destination.value
    logger.info("%s scan complete", direction.capitalize(), extra=log_extra)


def _get_settings():
    """Resolve settings from pipeline module to honour test patches.

    Tests mock ``sentinel.security.pipeline.settings``. Phase modules
    must read from that namespace so the mock takes effect.
    """
    return sys.modules["sentinel.security.pipeline"].settings


def _partition_verdicts_by_scanner(
    runs: Sequence[ScannerRun],
    verdicts: Sequence[SuppressionVerdict],
) -> tuple[dict[str, tuple[SuppressionVerdict, ...]], set[str]]:
    """Slice the flat verdict list into per-scanner tuples.

    Returns ``(per_scanner_verdicts, degraded_scanners)`` where
    ``degraded_scanners`` captures runs that crashed or exposed the
    ``_degraded_on_last_scan`` side-channel (test fixture hook).
    Verdicts align 1:1 with flattened matches across runs.
    """
    logger.debug(
        "_partition_verdicts_by_scanner called",
        extra={
            "event": "security.phase_shared._partition_verdicts_by_scanner",
            "runs_type": type(runs).__name__,
            "verdicts_len": len(verdicts) if hasattr(verdicts, "__len__") else 0,
        },
    )  # auto:entry
    per_scanner: dict[str, tuple[SuppressionVerdict, ...]] = {}
    degraded: set[str] = set()
    idx = 0
    for run in runs:
        name = scanner_legacy_name(run.scanner)
        count = len(run.matches)
        per_scanner[name] = tuple(verdicts[idx : idx + count])
        idx += count
        if run.crashed or getattr(run.scanner, "_degraded_on_last_scan", False):
            degraded.add(name)
    return per_scanner, degraded


def _scanner_phases(scanner: ScannerPlugin) -> frozenset[Phase]:
    """Return the scanner's declared phases.

    New scanners expose ``scanner_meta.phases``; legacy scanners use
    ``scanner_info.scan_input``/``scan_output`` flags.  Default to
    both phases for unknown shapes (fail-safe — include scanner rather
    than silently skip it).
    """
    logger.debug(
        "_scanner_phases called",
        extra={
            "event": "security.phase_shared._scanner_phases",
            "scanner_type": type(scanner).__name__,
        },
    )  # auto:entry
    meta = getattr(scanner, "scanner_meta", None)
    if meta is not None:
        return meta.phases
    info = getattr(scanner, "scanner_info", None)
    if info is None:
        return frozenset({Phase.INPUT, Phase.OUTPUT})
    phases: set[Phase] = set()
    if info.scan_input:
        phases.add(Phase.INPUT)
    if info.scan_output:
        phases.add(Phase.OUTPUT)
    return frozenset(phases)


def _scanner_expensive(scanner: ScannerPlugin) -> bool:
    """Return True iff the scanner is classified as expensive (Phase 2)."""
    meta = getattr(scanner, "scanner_meta", None)
    if meta is not None:
        return meta.expensive
    # Legacy scanners are all regex (Phase 1) — none are expensive.
    return False


def _scan_mode_for(run: ScannerRun) -> str:
    """Return the audit-event ``scan_mode`` value for a dispatched scanner.

    Every scanner receives the full ``ScanContext``; the only meaningful
    partition is Phase 1 (cheap regex) vs Phase 2 (expensive ML / external).

    - ``"strict"`` for Phase 1 (cheap regex) dispatch.
    - ``"expensive"`` for Phase 2 (ML / external) dispatch.

    DISPLAY-skipped scanners bypass this helper; their events are built
    with ``scan_mode="skipped"`` by the non-dispatched-result builder.
    """
    return "expensive" if _scanner_expensive(run.scanner) else "strict"


def _scanner_execution_only(scanner: ScannerPlugin) -> bool:
    """Return True iff the scanner skips DISPLAY destinations.

    New scanners declare this via ``scanner_meta.execution_only``.
    Legacy scanners use ``scanner_info.output_execution_only``.

    Phase-agnostic helper: input callers don't use it today, but the
    classification is defined on the scanner and not on the phase.
    """
    logger.debug(
        "_scanner_execution_only called",
        extra={
            "event": "security.phase_shared._scanner_execution_only",
            "scanner_type": type(scanner).__name__,
        },
    )  # auto:entry
    meta = getattr(scanner, "scanner_meta", None)
    if meta is not None:
        return meta.execution_only
    info = getattr(scanner, "scanner_info", None)
    if info is None:
        return False
    return info.output_execution_only
