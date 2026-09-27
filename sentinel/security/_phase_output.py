"""Output scanning phase — extracted from pipeline.py (Phase 8).

Contains the output scan dispatch logic and the post-scan finalization
(pipeline completion logging). All functions receive the ScanPipeline
instance as first argument.

Phase 9d-ii: ``run_output_scan`` returns the new frozen ``ScanResult``
from ``_scan_context`` directly.  No legacy adapter is invoked on the
production path.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING, NamedTuple

from sentinel.core.context import get_task_id
from sentinel.core.exceptions import SecurityViolation, ViolationPhase
from sentinel.core.models import OutputDestination, TaggedData

from ._audit_builders import build_manifest_event, build_output_audit_events
from ._enums import OutputDestination as _OutputDestinationEnum
from ._enums import Phase, Severity
from ._phase_dispatch import (
    ScannerRun,
    dispatch_scanners,
    should_skip_expensive_scanners,
)
from ._phase_shared import (
    _get_settings,
    _log_scan_results,
    _partition_verdicts_by_scanner,
    _scanner_execution_only,
    _scanner_expensive,
    _scanner_phases,
)
from ._scan_context import (
    ScanContext,
    ScanMetadata,
    ScanResult,
    SuppressionVerdict,
)
from ._scanner_names import scanner_legacy_name

if TYPE_CHECKING:
    from ._scanner_registry import ScannerPlugin
    from .pipeline import ScanPipeline

# Use pipeline's logger name so test caplog filters continue to work.
# Phase modules are logically part of the pipeline — the split is structural only.
logger = logging.getLogger("sentinel.security.pipeline")

# Outer per-scanner timeout for Phase 2 (expensive) dispatch — see
# ``_phase_input.py`` for rationale (mirrors that module's constant).
_EXPENSIVE_SCANNER_TIMEOUT_S = 150.0


class _OutputVerdictBundle(NamedTuple):
    """Bundle returned by ``_merge_output_verdicts``.

    Mirror of ``_phase_input._InputVerdictBundle``.  ``result`` is the
    frozen ``ScanResult`` returned to the caller.  ``per_scanner_verdicts``
    and ``degraded_scanners_full`` are consumed downstream by
    ``_emit_output_audit`` — they include the synthetic PromptGuard entry
    when the H1.2a availability helper produced one.
    """

    result: ScanResult
    per_scanner_verdicts: dict[str, tuple[SuppressionVerdict, ...]]
    degraded_scanners_full: frozenset[str]


class _OutputDispatchPlan(NamedTuple):
    """Dispatch plan returned by ``_prepare_output_dispatch``.

    ``output_scanners`` is the full Phase.OUTPUT scanner list (pre-PG-filter,
    pre-DISPLAY-skip filter).  It is passed to the audit builder via
    ``_emit_output_audit``, which filters ``PromptGuardScanner`` out when
    ``pg_availability is not None`` (see DC24) so the builder's synthetic-PG
    guard fires — mirroring the input-side filter in
    ``_prepare_input_dispatch``.  ``display_skip_scanners`` are the
    ``execution_only=True`` scanners (currently only ``command_pattern``)
    that emit ``outcome="SKIPPED"`` non-dispatched-result events when
    ``destination == DISPLAY``.  ``cheap`` and ``expensive`` are the
    post-filter dispatch lists.  ``pg_availability`` mirrors
    ``_InputDispatchPlan`` — the synthetic ``ScanResult`` from the H1.2a
    availability helper, or ``None``.
    """

    output_scanners: list[ScannerPlugin]
    display_skip_scanners: list[ScannerPlugin]
    cheap: list[ScannerPlugin]
    expensive: list[ScannerPlugin]
    pg_availability: ScanResult | None


def _prepare_output_dispatch(
    pipeline: ScanPipeline,
    destination: OutputDestination,
) -> _OutputDispatchPlan:
    """Partition Phase.OUTPUT scanners and resolve PG availability.

    Three filters are applied in order:

    1. Phase.OUTPUT — the full pre-filter list ``output_scanners`` is
       returned in the plan.  ``_emit_output_audit`` later filters PG
       out of this list when the availability helper synthesised PG's
       outcome so the builder's synthetic-PG guard fires (see DC24).
    2. ``execution_only`` ∧ ``destination != EXECUTION`` — pulled out as
       ``display_skip_scanners`` so the dispatch list only contains what
       we actually want to run.  These emit ``outcome="SKIPPED"`` non-
       dispatched-result events at audit time (DISPLAY-skip contract).
    3. PromptGuard pre-dispatch availability (H1.2a) — when PG is enabled
       but the model is not loaded, the helper returns a synthetic
       ``ScanResult`` and ``PromptGuardScanner`` is filtered out of
       dispatch (otherwise its own fail-closed path would produce a
       second, duplicate verdict for the same scan).

    The result is then split by ``_scanner_expensive`` for two-phase
    dispatch.
    """
    logger.debug(
        "_prepare_output_dispatch called",
        extra={
            "event": "security.phase_output._prepare_output_dispatch",
            "scanner_count": len(pipeline._scanners),
            "destination": destination.value,
        },
    )

    output_scanners = [
        s for s in pipeline._scanners if Phase.OUTPUT in _scanner_phases(s)
    ]
    display_skip_scanners: list[ScannerPlugin] = []
    dispatchable: list[ScannerPlugin] = []
    for scanner in output_scanners:
        if (
            _scanner_execution_only(scanner)
            and destination != OutputDestination.EXECUTION
        ):
            display_skip_scanners.append(scanner)
        else:
            dispatchable.append(scanner)

    pg_availability = pipeline._check_prompt_guard_available()
    if pg_availability is not None:
        dispatchable = [
            s for s in dispatchable if scanner_legacy_name(s) != "prompt_guard"
        ]

    cheap = [s for s in dispatchable if not _scanner_expensive(s)]
    expensive = [s for s in dispatchable if _scanner_expensive(s)]

    return _OutputDispatchPlan(
        output_scanners=output_scanners,
        display_skip_scanners=display_skip_scanners,
        cheap=cheap,
        expensive=expensive,
        pg_availability=pg_availability,
    )


async def _run_phase1_output(
    cheap: list[ScannerPlugin],
    context: ScanContext,
) -> list[ScannerRun]:
    """Dispatch Phase 1 (cheap) output scanners sequentially."""
    logger.debug(
        "_run_phase1_output called",
        extra={
            "event": "security.phase_output._run_phase1_output",
            "scanner_count": len(cheap),
        },
    )
    return await dispatch_scanners(cheap, context, concurrent=False)


async def _run_phase2_output(
    expensive: list[ScannerPlugin],
    context: ScanContext,
) -> list[ScannerRun]:
    """Dispatch Phase 2 (expensive) output scanners concurrently.

    Outer per-scanner timeout is ``_EXPENSIVE_SCANNER_TIMEOUT_S`` — a
    defence-in-depth upper bound; each scanner already owns an inner
    timeout (PromptGuard ~5s, Semgrep ~120s).
    """
    logger.debug(
        "_run_phase2_output called",
        extra={
            "event": "security.phase_output._run_phase2_output",
            "scanner_count": len(expensive),
        },
    )
    return await dispatch_scanners(
        expensive,
        context,
        concurrent=True,
        timeout_s=_EXPENSIVE_SCANNER_TIMEOUT_S,
    )


def _evaluate_early_termination_output(
    pipeline: ScanPipeline,
    phase1_runs: list[ScannerRun],
    context: ScanContext,
    *,
    cheap_count: int,
    expensive_count: int,
) -> bool:
    """Decide whether Phase 2 (expensive) output scanners should be skipped.

    Mirrors ``_phase_input._evaluate_early_termination`` — same predicate
    (unsuppressed AND CRITICAL via ``should_skip_expensive_scanners``),
    same suppression configuration (``severity_filter=Severity.CRITICAL``).
    The ``phase`` field on the early-termination log is ``"output"`` to
    distinguish it from the input-side emission in dashboards.
    """
    logger.debug(
        "_evaluate_early_termination_output called",
        extra={
            "event": "security.phase_output._evaluate_early_termination_output",
            "phase1_run_count": len(phase1_runs),
        },
    )
    phase1_matches = [m for run in phase1_runs for m in run.matches]
    rules_dict = dict(pipeline._rules)
    phase1_verdicts = pipeline._suppression.evaluate(
        phase1_matches,
        context,
        rules_dict,
        severity_filter=Severity.CRITICAL,
    )
    skipped = should_skip_expensive_scanners(phase1_verdicts)
    if skipped:
        logger.info(
            "Early termination — skipping expensive scanners",
            extra={
                "event": "security.early_termination",
                "phase": "output",
                "phase1_scanner_count": cheap_count,
                "phase2_scanner_count_skipped": expensive_count,
            },
        )
    else:
        logger.debug(
            "Early termination not triggered",
            extra={
                "event": "security.phase_output._evaluate_early_termination_output.clean",
                "reason": "no_unsuppressed_critical_in_phase1",
            },
        )  # auto:neg
    return skipped


def _merge_output_verdicts(
    pipeline: ScanPipeline,
    all_runs: list[ScannerRun],
    context: ScanContext,
    pg_availability: ScanResult | None,
    *,
    skipped_async: bool,
) -> _OutputVerdictBundle:
    """Combine Phase 1 + Phase 2 verdicts into the output ``ScanResult``.

    Mirror of ``_phase_input._merge_input_verdicts``.  Runs the final
    unfiltered suppression evaluation, partitions verdicts by scanner,
    merges the synthetic PromptGuard result (when the H1.2a availability
    helper produced one), and assembles the frozen ``ScanResult``
    returned to the caller.  Both the ``per_scanner_verdicts`` dict and
    the ``degraded_scanners_full`` set are returned so the audit-emission
    stage can consume them without re-partitioning.
    """
    logger.debug(
        "_merge_output_verdicts called",
        extra={
            "event": "security.phase_output._merge_output_verdicts",
            "run_count": len(all_runs),
            "has_pg_availability": pg_availability is not None,
        },
    )
    all_matches = [m for run in all_runs for m in run.matches]
    rules_dict = dict(pipeline._rules)
    all_verdicts = pipeline._suppression.evaluate(
        all_matches,
        context,
        rules_dict,
    )

    per_scanner_verdicts, degraded_scanners = _partition_verdicts_by_scanner(
        all_runs, all_verdicts
    )
    ran_scanners: set[str] = {scanner_legacy_name(run.scanner) for run in all_runs}

    # Merge synthetic PromptGuard result (H1.2a availability contract).
    combined_verdicts: list[SuppressionVerdict] = list(all_verdicts)
    extra_degraded: set[str] = set()
    if pg_availability is not None:
        pg_verdicts = pg_availability.verdicts
        pg_degraded = set(pg_availability.degraded_scanners)
        combined_verdicts = list(pg_verdicts) + combined_verdicts
        per_scanner_verdicts = {"prompt_guard": pg_verdicts, **per_scanner_verdicts}
        extra_degraded |= pg_degraded
        ran_scanners.add("prompt_guard")

    degraded_scanners_full = frozenset(degraded_scanners | extra_degraded)
    found = any(not v.suppressed for v in combined_verdicts)
    result = ScanResult(
        found=found,
        verdicts=tuple(combined_verdicts),
        context=context,
        skipped_async=skipped_async,
        degraded_scanners=degraded_scanners_full,
        ran_scanners=frozenset(ran_scanners),
    )
    return _OutputVerdictBundle(
        result=result,
        per_scanner_verdicts=per_scanner_verdicts,
        degraded_scanners_full=degraded_scanners_full,
    )


def _handle_baseline_skip_output(
    pipeline: ScanPipeline,
    text: str,
    destination: OutputDestination,
    *,
    pipeline_run_id: str | None = None,
) -> ScanResult | None:
    """Return the baseline-mode empty ``ScanResult``, or ``None`` otherwise.

    Mirror of ``_phase_input._handle_baseline_skip_input``.  When
    ``settings.baseline_mode`` is ``False`` (normal operation), returns
    ``None`` so the caller proceeds with the full scan.  When enabled,
    emits an ``outcome="SKIPPED"`` manifest event (fire-and-forget) if
    an audit emitter is wired and returns the empty ``ScanResult`` the
    caller must surface without further processing.

    Q17-F4 MG-2 (2026-04-24): accepts optional ``pipeline_run_id`` so
    the baseline-skip manifest can share the caller's correlation id
    (threaded from ``_dispatch_external_tool``).  Without this, the
    caller's id was dropped on the baseline-mode path and the
    manifest used a fresh UUID, breaking the ``tool.* ↔ scan.*``
    details-payload join that D3 promises.  When absent, falls back
    to fresh allocation (legacy / non-seam callers).
    """
    logger.debug(
        "_handle_baseline_skip_output called",
        extra={
            "event": "security.phase_output._handle_baseline_skip_output",
            "text_length": len(text),
            "destination": destination.value,
            "caller_supplied_pipeline_run_id": pipeline_run_id is not None,
        },
    )
    settings = _get_settings()
    if not settings.baseline_mode:
        logger.debug(
            "Baseline mode off — running full output scan",
            extra={
                "event": "security.phase_output._handle_baseline_skip_output.clean",
                "reason": "baseline_mode_off",
            },
        )  # auto:neg
        return None
    logger.info(
        "Output scan skipped (baseline mode)",
        extra={"event": "baseline.skip_output_scan"},
    )
    if pipeline._audit_emitter:
        logger.debug(
            "Scheduling baseline-mode manifest event",
            extra={
                "event": "security.phase_output._handle_baseline_skip_output.match",
                "reason": "audit_emitter",
            },
        )  # auto:neg
        if pipeline_run_id is None:
            pipeline_run_id = uuid.uuid4().hex
        scanner_names = [
            scanner_legacy_name(s)
            for s in pipeline._scanners
            if Phase.OUTPUT in _scanner_phases(s)
        ]
        pipeline._schedule_audit_events(
            [
                build_manifest_event(
                    "output",
                    pipeline_run_id,
                    scanner_names,
                    outcome="SKIPPED",
                ),
            ]
        )
    return _empty_output_scan_result(text, destination)


def _emit_output_audit(
    pipeline: ScanPipeline,
    text: str,
    pipeline_run_id: str,
    output_scanners: list[ScannerPlugin],
    display_skip_scanners: list[ScannerPlugin],
    all_runs: list[ScannerRun],
    bundle: _OutputVerdictBundle,
    pg_availability: ScanResult | None,
    t0: float,
) -> None:
    """Build + schedule output-phase audit events if an emitter is wired.

    Mirror of ``_phase_input._emit_input_audit``.  Does nothing when
    ``pipeline._build_audit_ctx`` returns ``None`` — the pipeline has no
    audit emitter configured.  When present, calls
    ``build_output_audit_events`` to produce the manifest + per-scanner
    result + DISPLAY-skip non-dispatched-result + summary events and
    schedules them fire-and-forget via ``pipeline._schedule_audit_events``.

    ``output_scanners`` is the full Phase.OUTPUT list (including
    ``PromptGuardScanner`` when present).  When ``pg_availability`` is
    not ``None`` (the H1.2a helper synthesised PG's outcome), PG is
    filtered out before being passed to the builder so the builder
    re-adds it alongside the synthetic ``scan.result`` event — mirroring
    how ``_prepare_input_dispatch`` filters PG on the input side.
    ``display_skip_scanners`` are the DISPLAY-skipped execution-only
    scanners that emit non-dispatched-result events instead of dispatch
    results.
    """
    logger.debug(
        "_emit_output_audit called",
        extra={
            "event": "security.phase_output._emit_output_audit",
            "pipeline_run_id": pipeline_run_id,
            "run_count": len(all_runs),
            "display_skip_count": len(display_skip_scanners),
            "has_pg_availability": pg_availability is not None,
        },
    )
    audit_ctx = pipeline._build_audit_ctx(text, "output", pipeline_run_id)
    if audit_ctx is None:
        logger.debug(
            "No audit emitter — skipping output audit build",
            extra={
                "event": "security.phase_output._emit_output_audit.clean",
                "reason": "no_audit_emitter",
            },
        )  # auto:neg
        return
    # Filter PG when the availability helper synthesised its outcome so
    # the builder's synthetic-PG guard fires (mirrors input side; DC24).
    scanners_for_manifest = (
        [s for s in output_scanners if scanner_legacy_name(s) != "prompt_guard"]
        if pg_availability is not None
        else output_scanners
    )
    audit_events = build_output_audit_events(
        pipeline_run_id,
        scanners_for_manifest,
        display_skip_scanners,
        all_runs,
        bundle.per_scanner_verdicts,
        bundle.degraded_scanners_full,
        audit_ctx,
        t0,
        pg_synthetic_verdicts=(
            bundle.per_scanner_verdicts.get("prompt_guard", ())
            if pg_availability is not None
            else None
        ),
    )
    pipeline._schedule_audit_events(audit_events)


async def run_output_scan(
    pipeline: ScanPipeline,
    text: str,
    destination: OutputDestination = OutputDestination.EXECUTION,
    *,
    user_input: str | None = None,
    pipeline_run_id: str | None = None,
) -> ScanResult:
    """Run output scanning phase via async ``ScannerPlugin`` dispatch.

    Structure mirrors ``_phase_input.run_input_scan`` plus destination
    awareness:

    - ``execution_only=True`` scanners (only ``command_pattern`` today)
      are filtered out when ``destination == DISPLAY``.  They emit a
      ``scan.result`` event with ``outcome="SKIPPED"`` but produce no
      verdicts.  (Post-9d-ii their presence is signalled through the
      audit trail, not by synthesizing empty match entries.)
    - ``user_input`` is threaded into ``ScanMetadata.input_text`` so
      the echo scanner can compare input vs output inside the dispatch
      loop.  ``scan_output_and_finalize`` passes the raw user request
      through when available.

    Q17-F4 (D3, 2026-04-24): ``pipeline_run_id`` is now an optional
    caller-owned parameter.  When the tool-dispatch seam supplies it,
    the scan's audit events share the same correlation id as the
    surrounding ``tool.*`` envelope so operators can join a
    ``tool.completed`` event to its downstream ``scan.*`` events
    directly via the details payload.  When ``None`` (legacy direct
    callers, ``scan_output_and_finalize``, tests), a fresh id is
    allocated as before.
    """
    logger.debug(
        "run_output_scan called",
        extra={
            "event": "security.output.run_output_scan",
            "text_length": len(text),
            "destination": destination.value,
            "has_user_input": user_input is not None,
            "caller_supplied_pipeline_run_id": pipeline_run_id is not None,
        },
    )

    # Baseline mode: skip all scanning to measure utility without security overhead.
    # Q17-F4 MG-2 (2026-04-24): thread caller's pipeline_run_id through so the
    # baseline-skip manifest event shares the tool-dispatch seam's correlation
    # id (D3 contract holds in baseline mode too).
    baseline_result = _handle_baseline_skip_output(
        pipeline, text, destination, pipeline_run_id=pipeline_run_id
    )
    if baseline_result is not None:
        return baseline_result

    t0 = time.monotonic()
    if pipeline_run_id is None:
        pipeline_run_id = uuid.uuid4().hex

    # Build ScanContext with output destination + carried user_input.
    metadata = ScanMetadata(
        phase=Phase.OUTPUT,
        output_destination=_OutputDestinationEnum(destination.value),
        trust_level=0,
        tool_target=None,
        input_text=user_input,
    )
    context = pipeline._preprocessor.process(text, metadata)

    # Plan dispatch: Phase.OUTPUT filter, DISPLAY execution-only skip,
    # PG pre-dispatch availability resolution, cheap/expensive split.
    plan = _prepare_output_dispatch(pipeline, destination)

    # Phase 1 (sequential) → early-termination check → Phase 2 (concurrent).
    phase1_runs = await _run_phase1_output(plan.cheap, context)
    skipped_async = _evaluate_early_termination_output(
        pipeline,
        phase1_runs,
        context,
        cheap_count=len(plan.cheap),
        expensive_count=len(plan.expensive),
    )
    phase2_runs: list[ScannerRun] = (
        [] if skipped_async else await _run_phase2_output(plan.expensive, context)
    )
    all_runs: list[ScannerRun] = list(phase1_runs) + list(phase2_runs)

    # Final suppression eval + PG-synthetic merge + ScanResult assembly.
    bundle = _merge_output_verdicts(
        pipeline,
        all_runs,
        context,
        plan.pg_availability,
        skipped_async=skipped_async,
    )

    # Emit audit events (no-op when no audit emitter is wired).
    _emit_output_audit(
        pipeline,
        text,
        pipeline_run_id,
        plan.output_scanners,
        plan.display_skip_scanners,
        all_runs,
        bundle,
        plan.pg_availability,
        t0,
    )

    elapsed = time.monotonic() - t0
    _log_scan_results(bundle.result, "output", text, elapsed, destination=destination)
    return bundle.result


def _empty_output_scan_result(
    text: str,
    destination: OutputDestination,
) -> ScanResult:
    """Build an empty ``ScanResult`` for baseline-mode output skips."""
    metadata = ScanMetadata(
        phase=Phase.OUTPUT,
        output_destination=_OutputDestinationEnum(destination.value),
        trust_level=0,
        tool_target=None,
        input_text=None,
    )
    context = ScanContext(
        raw_text=text,
        regions=(),
        decoded_variants=(),
        metadata=metadata,
    )
    return ScanResult(found=False, verdicts=(), context=context)


async def scan_output_and_finalize(
    pipeline: ScanPipeline,
    tagged: TaggedData,
    response_text: str,
    user_input: str | None,
    destination: OutputDestination,
    spotlighting_active: bool,
) -> None:
    """Scan tagged output, run echo scan, log pipeline completion.

    Extracted from ScanPipeline._scan_output_and_finalize. Mutates
    tagged.scan_results in place. Raises SecurityViolation if any
    output scan or echo scan fails.
    """
    logger.debug(
        "scan_output_and_finalize called",
        extra={
            "event": "security.output.scan_output_and_finalize",
            "data_id": tagged.id,
            "destination": destination.value,
            "has_user_input": user_input is not None,
        },
    )

    # Call through the method (not the module function) to preserve
    # the original call chain — tests patch pipeline.scan_output.
    # ``user_input`` is passed through so the echo scanner (now part
    # of the unified dispatch) can compare it against tagged.content
    # inside ``run_output_scan`` via ``ScanMetadata.input_text``.
    output_scan = await pipeline.scan_output(
        tagged.content,
        destination=destination,
        user_input=user_input,
    )
    tagged.scan_result = output_scan

    if not output_scan.is_clean:
        logger.warning(
            "Qwen output blocked by scan pipeline",
            extra={
                "event": "output.blocked",
                "violations": list(output_scan.violated_scanners()),
                "data_id": tagged.id,
            },
        )
        raise SecurityViolation(
            "Qwen output blocked by security scan",
            output_scan,
            raw_response=response_text,
            phase=ViolationPhase.OUTPUT,
        )

    logger.info(
        "Pipeline complete — output clean",
        extra={
            "event": "pipeline.complete",
            "task_id": get_task_id(),
            "data_id": tagged.id,
            "trust_level": tagged.trust_level.value,
            "spotlighting_active": spotlighting_active,
            "echo_scan_ran": user_input is not None,
            "scanner_count": len(output_scan.verdicts_by_scanner()),
            "response_length": len(tagged.content),
        },
    )
