"""Consolidated audit-event builder functions.

Pure — input → event dict, no hidden state.  Callers (``pipeline.py``,
``_phase_input.py``, ``_phase_output.py``) are responsible for ordering,
participation consistency, and passing legacy scanner names (via
``scanner_legacy_name``).

Extracted from the monolithic builder methods scattered across
``pipeline.py`` and both phase modules.  The separation is a structural
one: audit-event *construction* belongs here; audit-event *emission*
(``_schedule_audit_events`` / ``_emit_audit_events``) stays on
``ScanPipeline`` because it owns the emitter handle.

H3 extraction lands builders one-at-a-time as atomic commits; phase
modules and ``pipeline.py`` switch to direct imports as builders move.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import TYPE_CHECKING

from ._phase_shared import _get_settings, _scan_mode_for
from ._scanner_names import scanner_legacy_name

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ._phase_dispatch import ScannerRun
    from ._scan_context import SuppressionVerdict
    from ._scanner_registry import ScannerPlugin

logger = logging.getLogger("sentinel.security.pipeline")


def build_manifest_event(
    scan_path: str,
    pipeline_run_id: str,
    scanners_expected: list[str],
    outcome: str = "CLEAN",
) -> dict:
    """Build a ``scan.manifest`` audit event dict for pipeline entry."""
    return {
        "event_type": "scan.manifest",
        "source_component": "pipeline",
        "outcome": outcome,
        "severity": "INFO",
        "details": {
            "pipeline_run_id": pipeline_run_id,
            "scan_path": scan_path,
            "scanners_expected": scanners_expected,
        },
    }


def build_summary_event(
    scan_path: str,
    pipeline_run_id: str,
    scanners_completed: list[str],
    scanners_skipped: list[str],
    scanners_errored: list[str],
    total_findings: int,
    aggregate_outcome: str,
    duration_ms: int,
) -> dict:
    """Build a ``scan.summary`` audit event dict for pipeline exit."""
    severity = "INFO"
    if scanners_errored:
        severity = "HIGH"
    elif aggregate_outcome == "BLOCKED":
        severity = "MEDIUM"

    return {
        "event_type": "scan.summary",
        "source_component": "pipeline",
        "outcome": aggregate_outcome,
        "severity": severity,
        "duration_ms": duration_ms,
        "details": {
            "pipeline_run_id": pipeline_run_id,
            "scan_path": scan_path,
            "scanners_completed": scanners_completed,
            "scanners_skipped": scanners_skipped,
            "scanners_errored": scanners_errored,
            "total_findings": total_findings,
        },
    }


def build_gate_event(
    pipeline_run_id: str,
    gate_type: str,
    outcome: str,
    severity: str = "INFO",
    gate_value: str | int | None = None,
    degraded: bool = False,
) -> dict:
    """Build a ``scan.gate`` audit event dict for a gate check.

    Q17-F13b: ``degraded`` is always emitted so consumers filtering
    ``event_type=="scan.gate"`` get a stable shape; default False for
    gates that fire pre-scan (length, token) where degraded state is
    meaningless. Callers firing gates after a scan can pass True.

    Q17-F3 (D2, 2026-04-24): correlation id field renamed
    ``gate_run_id`` → ``pipeline_run_id`` so gate events share the same
    correlation key as manifest/summary/result events across the scan
    stream.
    """
    details: dict = {
        "pipeline_run_id": pipeline_run_id,
        "gate_type": gate_type,
        "degraded": degraded,
    }
    if gate_value is not None:
        details["gate_value"] = gate_value

    return {
        "event_type": "scan.gate",
        "source_component": "pipeline",
        "outcome": outcome,
        "severity": severity,
        "details": details,
    }


def build_non_dispatched_result_event(
    scanner_name: str,
    outcome: str,
    scan_path: str,
    pipeline_run_id: str,
    *,
    scan_mode: str,
    reason: str | None = None,
) -> dict:
    """Build a ``scan.result`` event for non-dispatched scanner outcomes.

    Used today for DISPLAY-destination skips (``scan_mode="skipped"``),
    which bypass ``dispatch_scanners`` and therefore don't get
    ``build_scan_result_event`` called automatically.  The pre-H1
    inline-PG path also routed through here; that caller was deleted in
    H1.  This dual purpose is why the H1 excision preserved this
    builder (it was NOT inline-PG-only) and why H3 renamed it.

    ``scan_mode`` is keyword-only and required — the builder no longer
    carries a stale ``"inline"`` default (DC6 cleanup).
    """
    logger.debug(
        "build_non_dispatched_result_event called",
        extra={
            "event": "security.audit_builders.build_non_dispatched_result_event",
            "scanner_name": scanner_name,
            "outcome": outcome,
            "scan_path": scan_path,
        },
    )  # auto:entry
    severity = "INFO"
    if outcome == "BLOCKED":
        severity = "MEDIUM"
    elif outcome == "ERROR":
        severity = "HIGH"

    # Q17-F5: Both scan.result producers (this + build_scan_result_event)
    # carry the same field set, discriminated by scan_mode. A consumer
    # filtering event_type=="scan.result" gets a stable shape regardless of
    # whether the scanner was dispatched or skipped.
    details: dict = {
        "pipeline_run_id": pipeline_run_id,
        "scanner_name": scanner_name,
        "scan_path": scan_path,
        "scan_mode": scan_mode,
        "input_hash": "",
        "input_length": 0,
        "findings_count": 0,
        "suppressions_count": 0,
        "findings": [],
        "degraded": False,
        "scanner_config_hash": None,
    }
    if reason:
        logger.debug(
            "build_non_dispatched_result_event: reason",
            extra={
                "event": "security.audit_builders.build_non_dispatched_result_event.match",
                "reason": "reason",
            },
        )  # auto:neg
        details["reason"] = reason

    # Q17-F5: top-level envelope parity with build_scan_result_event.
    # action_taken=None + duration_ms=0 preserve existing vocabulary
    # (action_taken stays "BLOCKED"|"ALLOWED"|None) and keep top-level key
    # sets identical between the two scan.result producers.
    return {
        "event_type": "scan.result",
        "source_component": "pipeline",
        "outcome": outcome,
        "severity": severity,
        "action_taken": None,
        "duration_ms": 0,
        "details": details,
    }


def build_input_audit_events(
    pipeline_run_id: str,
    input_scanners: Sequence[ScannerPlugin],
    runs: Sequence[ScannerRun],
    per_scanner_verdicts: dict[str, tuple[SuppressionVerdict, ...]],
    degraded_scanners: frozenset[str],
    audit_ctx: dict,
    t0: float,
    *,
    pg_synthetic_verdicts: tuple[SuppressionVerdict, ...] | None = None,
) -> list[dict]:
    """Build input-phase manifest + per-scanner scan.result + summary events.

    Orchestrates the per-phase builders for the input side.  Audit-event
    ordering (manifest first, PG-synthetic result second if applicable,
    then dispatch results, then summary) is pinned by
    ``tests/test_audit_framework/test_e2e_audit_trail.py``.
    """
    logger.debug(
        "build_input_audit_events called",
        extra={
            "event": "security.audit_builders.build_input_audit_events",
            "pipeline_run_id": pipeline_run_id,
            "input_scanners_type": type(input_scanners).__name__,
        },
    )  # auto:entry
    settings = _get_settings()
    scanner_names_expected = [scanner_legacy_name(s) for s in input_scanners]

    # PromptGuard synthetic participation (H1.2a availability helper).
    # When PG is enabled but the model is unavailable, the pipeline-level
    # helper synthesises PG's outcome and filters PG out of dispatch.
    # Make PG visible in the manifest + emit its scan.result so audit
    # reconciliation still accounts for it.
    pg_synthetic = (
        pg_synthetic_verdicts is not None
        and settings.prompt_guard_enabled
        and not any(n == "prompt_guard" for n in scanner_names_expected)
    )
    if pg_synthetic:
        scanner_names_expected.insert(0, "prompt_guard")

    events: list[dict] = [
        build_manifest_event(
            "input",
            pipeline_run_id,
            scanner_names_expected,
        )
    ]

    completed_scanners: list[str] = []
    errored_scanners: list[str] = []

    # Emit scan.result for the PG synthetic FIRST so it appears at the top
    # of completed_scanners (pg-first ordering). PG is an expensive-tier
    # scanner so scan_mode="expensive" regardless of synthetic outcome.
    if pg_synthetic:
        events.append(
            build_scan_result_event(
                "prompt_guard",
                pg_synthetic_verdicts,
                crashed=False,
                duration_ms=0,
                scan_mode="expensive",
                text=audit_ctx["text"],
                scan_path=audit_ctx["scan_path"],
                pipeline_run_id=audit_ctx["pipeline_run_id"],
                scanner_config_hash=audit_ctx["scanner_config_hash"],
                degraded="prompt_guard" in degraded_scanners,
            )
        )
        completed_scanners.append("prompt_guard")

    for run in runs:
        legacy = scanner_legacy_name(run.scanner)
        events.append(
            build_scan_result_event(
                legacy,
                per_scanner_verdicts.get(legacy, ()),
                crashed=run.crashed,
                duration_ms=run.duration_ms,
                scan_mode=_scan_mode_for(run),
                text=audit_ctx["text"],
                scan_path=audit_ctx["scan_path"],
                pipeline_run_id=audit_ctx["pipeline_run_id"],
                scanner_config_hash=audit_ctx["scanner_config_hash"],
                degraded=legacy in degraded_scanners,
            )
        )
        if run.crashed:
            errored_scanners.append(legacy)
        else:
            completed_scanners.append(legacy)

    total_findings = sum(
        sum(1 for v in verdicts if not v.suppressed)
        for verdicts in per_scanner_verdicts.values()
    )
    aggregate_outcome = "CLEAN"
    if errored_scanners:
        aggregate_outcome = "ERROR"
    elif total_findings > 0:
        aggregate_outcome = "BLOCKED"
    total_duration_ms = int((time.monotonic() - t0) * 1000)
    events.append(
        build_summary_event(
            "input",
            pipeline_run_id,
            completed_scanners,
            [],  # no DISPLAY skips on input
            errored_scanners,
            total_findings,
            aggregate_outcome,
            total_duration_ms,
        )
    )
    return events


def build_output_audit_events(
    pipeline_run_id: str,
    output_scanners: Sequence[ScannerPlugin],
    display_skip_scanners: Sequence[ScannerPlugin],
    runs: Sequence[ScannerRun],
    per_scanner_verdicts: dict[str, tuple[SuppressionVerdict, ...]],
    degraded_scanners: frozenset[str],
    audit_ctx: dict,
    t0: float,
    *,
    pg_synthetic_verdicts: tuple[SuppressionVerdict, ...] | None = None,
) -> list[dict]:
    """Build output-phase manifest + per-scanner scan.result + skip events + summary.

    Orchestrates the per-phase builders for the output side.  DISPLAY-
    destination skips flow through ``build_non_dispatched_result_event``
    (scan_mode="skipped") so they appear as scan.result events in the
    stream even though no scanner ran.  Audit-event ordering pinned by
    ``tests/test_audit_framework/test_pipeline_audit.py``.
    """
    logger.debug(
        "build_output_audit_events called",
        extra={
            "event": "security.audit_builders.build_output_audit_events",
            "pipeline_run_id": pipeline_run_id,
            "output_scanners_type": type(output_scanners).__name__,
        },
    )  # auto:entry
    settings = _get_settings()
    scanner_names_expected = [scanner_legacy_name(s) for s in output_scanners]

    # PromptGuard synthetic participation (H1.2a availability helper).
    # When PG is enabled but the model is unavailable, the helper
    # synthesises PG's outcome and PG is filtered out of dispatch; make
    # it visible in the manifest + emit its scan.result so audit
    # reconciliation still accounts for it.
    pg_synthetic = (
        pg_synthetic_verdicts is not None
        and settings.prompt_guard_enabled
        and not any(n == "prompt_guard" for n in scanner_names_expected)
    )
    if pg_synthetic:
        scanner_names_expected.insert(0, "prompt_guard")

    events: list[dict] = [
        build_manifest_event(
            "output",
            pipeline_run_id,
            scanner_names_expected,
        )
    ]

    completed_scanners: list[str] = []
    errored_scanners: list[str] = []

    if pg_synthetic:
        events.append(
            build_scan_result_event(
                "prompt_guard",
                pg_synthetic_verdicts,
                crashed=False,
                duration_ms=0,
                scan_mode="expensive",
                text=audit_ctx["text"],
                scan_path=audit_ctx["scan_path"],
                pipeline_run_id=audit_ctx["pipeline_run_id"],
                scanner_config_hash=audit_ctx["scanner_config_hash"],
                degraded="prompt_guard" in degraded_scanners,
            )
        )
        completed_scanners.append("prompt_guard")

    for run in runs:
        legacy = scanner_legacy_name(run.scanner)
        events.append(
            build_scan_result_event(
                legacy,
                per_scanner_verdicts.get(legacy, ()),
                crashed=run.crashed,
                duration_ms=run.duration_ms,
                scan_mode=_scan_mode_for(run),
                text=audit_ctx["text"],
                scan_path=audit_ctx["scan_path"],
                pipeline_run_id=audit_ctx["pipeline_run_id"],
                scanner_config_hash=audit_ctx["scanner_config_hash"],
                degraded=legacy in degraded_scanners,
            )
        )
        if run.crashed:
            errored_scanners.append(legacy)
        else:
            completed_scanners.append(legacy)

    # DISPLAY-skipped scanners get a scan.result event with SKIPPED outcome.
    scanners_skipped: list[str] = []
    scan_path = audit_ctx["scan_path"]
    for scanner in display_skip_scanners:
        legacy = scanner_legacy_name(scanner)
        events.append(
            build_non_dispatched_result_event(
                legacy,
                "SKIPPED",
                scan_path,
                pipeline_run_id,
                scan_mode="skipped",
                reason="display_destination",
            )
        )
        scanners_skipped.append(legacy)

    total_findings = sum(
        sum(1 for v in verdicts if not v.suppressed)
        for verdicts in per_scanner_verdicts.values()
    )
    aggregate_outcome = "CLEAN"
    if errored_scanners:
        aggregate_outcome = "ERROR"
    elif total_findings > 0:
        aggregate_outcome = "BLOCKED"
    total_duration_ms = int((time.monotonic() - t0) * 1000)
    events.append(
        build_summary_event(
            "output",
            pipeline_run_id,
            completed_scanners,
            scanners_skipped,
            errored_scanners,
            total_findings,
            aggregate_outcome,
            total_duration_ms,
        )
    )
    return events


def build_scan_result_event(
    scanner_name: str,
    verdicts: Sequence[SuppressionVerdict],
    *,
    crashed: bool,
    duration_ms: int,
    scan_mode: str,
    text: str,
    scan_path: str,
    pipeline_run_id: str,
    scanner_config_hash: str,
    degraded: bool = False,
) -> dict:
    """Build a ``scan.result`` audit event dict from per-scanner verdicts.

    Wire format is unchanged from the legacy ScanResult-based builder:
    ``findings`` entries still use ``pattern`` / ``suppressed`` /
    ``reason`` keys, and ``outcome`` / ``action_taken`` follow the
    same rules.  The input is new-shape verdicts, so ``pattern`` is
    sourced from ``verdict.match.rule_id`` and ``reason`` from
    ``verdict.canonical_reason``.
    """
    logger.debug(
        "build_scan_result_event called",
        extra={
            "event": "security.audit_builders.build_scan_result_event",
            "scanner_name": scanner_name,
            "verdict_count": len(verdicts),
            "crashed": crashed,
            "degraded": degraded,
        },
    )  # auto:entry
    unsuppressed_count = sum(1 for v in verdicts if not v.suppressed)
    suppressed_count = sum(1 for v in verdicts if v.suppressed)
    found = unsuppressed_count > 0

    if crashed:
        outcome, severity = "ERROR", "HIGH"
    elif found:
        outcome, severity = "BLOCKED", "MEDIUM"
    else:
        outcome, severity = "CLEAN", "INFO"

    input_hash = "sha256:" + hashlib.sha256(text.encode()).hexdigest() if text else ""

    return {
        "event_type": "scan.result",
        "source_component": "pipeline",
        "outcome": outcome,
        "severity": severity,
        "action_taken": "BLOCKED" if found else "ALLOWED",
        "duration_ms": duration_ms,
        "details": {
            "pipeline_run_id": pipeline_run_id,
            "scanner_name": scanner_name,
            "scan_path": scan_path,
            "scan_mode": scan_mode,
            "input_hash": input_hash,
            "input_length": len(text) if text else 0,
            "findings_count": unsuppressed_count,
            "suppressions_count": suppressed_count,
            "findings": [
                {
                    "pattern": v.match.rule_id,
                    "suppressed": v.suppressed,
                    "reason": v.canonical_reason,
                }
                for v in verdicts
            ],
            "degraded": degraded,
            "scanner_config_hash": scanner_config_hash,
        },
    }
