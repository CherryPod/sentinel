"""Input scanning phase — extracted from pipeline.py (Phase 8).

Contains the input scan dispatch logic and pre-flight validation.
All functions receive the ScanPipeline instance as first argument.
Gate constants and the ASCII script gate live in _input_gates.py.

Phase 9d-ii: ``run_input_scan`` returns the new frozen ``ScanResult``
from ``_scan_context`` directly.  No legacy adapter is invoked on the
production path.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING, NamedTuple

from sentinel.core.exceptions import SecurityViolation

from ._audit_builders import (
    build_gate_event,
    build_input_audit_events,
    build_manifest_event,
)
from ._enums import Phase, Severity
from ._gate_violations import build_gate_scan_result
from ._input_gates import (
    _CHARS_PER_TOKEN_ESTIMATE,
    _CONTEXT_TOKEN_LIMIT,
    _MAX_PROMPT_CHARS,
    check_prompt_ascii,
)
from ._phase_dispatch import (
    ScannerRun,
    dispatch_scanners,
    should_skip_expensive_scanners,
)
from ._phase_shared import (
    _get_settings,
    _log_scan_results,
    _partition_verdicts_by_scanner,
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

# Outer per-scanner timeout for Phase 2 (expensive) dispatch.  Each
# expensive scanner already has its own internal timeout
# (PromptGuard ~5s, Semgrep ~120s); this value is a hard upper bound
# in case the inner timeout fails to fire.
_EXPENSIVE_SCANNER_TIMEOUT_S = 150.0


class _InputVerdictBundle(NamedTuple):
    """Bundle returned by ``_merge_input_verdicts``.

    ``result`` is the frozen ``ScanResult`` returned to the caller.
    ``per_scanner_verdicts`` and ``degraded_scanners_full`` are
    consumed downstream by ``_emit_input_audit`` — they include the
    synthetic PromptGuard entry when the H1.2a availability helper
    produced one.
    """

    result: ScanResult
    per_scanner_verdicts: dict[str, tuple[SuppressionVerdict, ...]]
    degraded_scanners_full: frozenset[str]


class _InputDispatchPlan(NamedTuple):
    """Dispatch plan returned by ``_prepare_input_dispatch``.

    ``input_scanners`` is the post-filter list surfaced to the audit
    manifest as ``scanners_expected``.  ``cheap`` feeds Phase 1 sequential
    dispatch, ``expensive`` feeds Phase 2 concurrent dispatch.
    ``pg_availability`` is the synthetic ``ScanResult`` emitted by the
    pipeline-owned PG availability policy (H1.2a) when PG is enabled but
    not loaded; ``None`` when PG is on the AVAILABLE or DISABLED branch
    and participates (or not) through the normal dispatch path.
    """

    input_scanners: list[ScannerPlugin]
    cheap: list[ScannerPlugin]
    expensive: list[ScannerPlugin]
    pg_availability: ScanResult | None


def _prepare_input_dispatch(pipeline: ScanPipeline) -> _InputDispatchPlan:
    """Partition scanners for input dispatch and resolve PG availability.

    Runs the H1.2a PG availability policy *before* dispatch so that when
    PG is enabled-but-not-loaded the helper returns a pre-dispatch
    synthetic ``ScanResult`` and ``PromptGuardScanner`` is filtered out
    of the dispatch list — otherwise its own fail-closed path would
    produce a second, duplicate verdict for the same scan.
    """
    logger.debug(
        "_prepare_input_dispatch called",
        extra={
            "event": "security.phase_input._prepare_input_dispatch",
            "scanner_count": len(pipeline._scanners),
        },
    )

    input_scanners = [
        s for s in pipeline._scanners if Phase.INPUT in _scanner_phases(s)
    ]

    pg_availability = pipeline._check_prompt_guard_available()
    if pg_availability is not None:
        input_scanners = [
            s for s in input_scanners if scanner_legacy_name(s) != "prompt_guard"
        ]

    cheap = [s for s in input_scanners if not _scanner_expensive(s)]
    expensive = [s for s in input_scanners if _scanner_expensive(s)]

    return _InputDispatchPlan(
        input_scanners=input_scanners,
        cheap=cheap,
        expensive=expensive,
        pg_availability=pg_availability,
    )


async def _run_phase1_input(
    cheap: list[ScannerPlugin],
    context: ScanContext,
) -> list[ScannerRun]:
    """Dispatch Phase 1 (cheap) input scanners sequentially."""
    logger.debug(
        "_run_phase1_input called",
        extra={
            "event": "security.phase_input._run_phase1_input",
            "scanner_count": len(cheap),
        },
    )
    return await dispatch_scanners(cheap, context, concurrent=False)


def _merge_input_verdicts(
    pipeline: ScanPipeline,
    all_runs: list[ScannerRun],
    context: ScanContext,
    pg_availability: ScanResult | None,
    *,
    skipped_async: bool,
) -> _InputVerdictBundle:
    """Combine Phase 1 + Phase 2 verdicts into the input ``ScanResult``.

    Runs the final unfiltered suppression evaluation, partitions verdicts
    by scanner, merges the synthetic PromptGuard result (when the H1.2a
    availability helper produced one), and assembles the frozen
    ``ScanResult`` returned to the caller.  Both the ``per_scanner_verdicts``
    dict and the ``degraded_scanners_full`` set are returned so the
    audit-emission stage can consume them without re-partitioning.
    """
    logger.debug(
        "_merge_input_verdicts called",
        extra={
            "event": "security.phase_input._merge_input_verdicts",
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
    return _InputVerdictBundle(
        result=result,
        per_scanner_verdicts=per_scanner_verdicts,
        degraded_scanners_full=degraded_scanners_full,
    )


async def _run_phase2_input(
    expensive: list[ScannerPlugin],
    context: ScanContext,
) -> list[ScannerRun]:
    """Dispatch Phase 2 (expensive) input scanners concurrently.

    Outer per-scanner timeout is ``_EXPENSIVE_SCANNER_TIMEOUT_S`` — a
    defence-in-depth upper bound; each scanner already owns an inner
    timeout (PromptGuard ~5s, Semgrep ~120s).
    """
    logger.debug(
        "_run_phase2_input called",
        extra={
            "event": "security.phase_input._run_phase2_input",
            "scanner_count": len(expensive),
        },
    )
    return await dispatch_scanners(
        expensive,
        context,
        concurrent=True,
        timeout_s=_EXPENSIVE_SCANNER_TIMEOUT_S,
    )


def _evaluate_early_termination(
    pipeline: ScanPipeline,
    phase1_runs: list[ScannerRun],
    context: ScanContext,
    *,
    cheap_count: int,
    expensive_count: int,
) -> bool:
    """Decide whether Phase 2 (expensive) scanners should be skipped.

    Runs the ``SuppressionEngine`` over Phase 1 matches with a
    ``Severity.CRITICAL`` filter and consults
    ``should_skip_expensive_scanners`` — the single source of truth for
    the predicate (unsuppressed AND CRITICAL).  Returns ``True`` when
    early termination applies.
    """
    logger.debug(
        "_evaluate_early_termination called",
        extra={
            "event": "security.phase_input._evaluate_early_termination",
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
                "phase": "input",
                "phase1_scanner_count": cheap_count,
                "phase2_scanner_count_skipped": expensive_count,
            },
        )
    else:
        logger.debug(
            "Early termination not triggered",
            extra={
                "event": "security.phase_input._evaluate_early_termination.clean",
                "reason": "no_unsuppressed_critical_in_phase1",
            },
        )  # auto:neg
    return skipped


def _handle_baseline_skip_input(
    pipeline: ScanPipeline,
    text: str,
) -> ScanResult | None:
    """Return the baseline-mode empty ``ScanResult``, or ``None`` otherwise.

    When ``settings.baseline_mode`` is ``False`` (normal operation), returns
    ``None`` so the caller proceeds with the full scan.  When enabled,
    emits an ``outcome="SKIPPED"`` manifest event (fire-and-forget) if
    an audit emitter is wired and returns the empty ``ScanResult`` the
    caller must surface without further processing.
    """
    logger.debug(
        "_handle_baseline_skip_input called",
        extra={
            "event": "security.phase_input._handle_baseline_skip_input",
            "text_length": len(text),
        },
    )
    settings = _get_settings()
    if not settings.baseline_mode:
        logger.debug(
            "Baseline mode off — running full input scan",
            extra={
                "event": "security.phase_input._handle_baseline_skip_input.clean",
                "reason": "baseline_mode_off",
            },
        )  # auto:neg
        return None
    logger.info(
        "Input scan skipped (baseline mode)",
        extra={"event": "baseline.skip_input_scan"},
    )
    if pipeline._audit_emitter:
        logger.debug(
            "Scheduling baseline-mode manifest event",
            extra={
                "event": "security.phase_input._handle_baseline_skip_input.match",
                "reason": "audit_emitter",
            },
        )  # auto:neg
        pipeline_run_id = uuid.uuid4().hex
        scanner_names = [
            scanner_legacy_name(s)
            for s in pipeline._scanners
            if Phase.INPUT in _scanner_phases(s)
        ]
        pipeline._schedule_audit_events(
            [
                build_manifest_event(
                    "input",
                    pipeline_run_id,
                    scanner_names,
                    outcome="SKIPPED",
                ),
            ]
        )
    return _empty_scan_result(text, Phase.INPUT)


def _emit_input_audit(
    pipeline: ScanPipeline,
    text: str,
    pipeline_run_id: str,
    input_scanners: list[ScannerPlugin],
    all_runs: list[ScannerRun],
    bundle: _InputVerdictBundle,
    pg_availability: ScanResult | None,
    t0: float,
) -> None:
    """Build + schedule input-phase audit events if an emitter is wired.

    Does nothing when ``pipeline._build_audit_ctx`` returns ``None`` —
    the pipeline has no audit emitter configured.  When present, calls
    ``build_input_audit_events`` to produce the manifest + per-scanner
    result + summary events and schedules them fire-and-forget via
    ``pipeline._schedule_audit_events``.
    """
    logger.debug(
        "_emit_input_audit called",
        extra={
            "event": "security.phase_input._emit_input_audit",
            "pipeline_run_id": pipeline_run_id,
            "run_count": len(all_runs),
            "has_pg_availability": pg_availability is not None,
        },
    )
    audit_ctx = pipeline._build_audit_ctx(text, "input", pipeline_run_id)
    if audit_ctx is None:
        logger.debug(
            "No audit emitter — skipping input audit build",
            extra={
                "event": "security.phase_input._emit_input_audit.clean",
                "reason": "no_audit_emitter",
            },
        )  # auto:neg
        return
    audit_events = build_input_audit_events(
        pipeline_run_id,
        input_scanners,
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


async def run_input_scan(
    pipeline: ScanPipeline,
    text: str,
    context_aware_paths: bool = False,
) -> ScanResult:
    """Run input scanning phase via async ``ScannerPlugin`` dispatch.

    Structure:
      1. Baseline-mode early-skip.
      2. Preprocess → ``ScanContext``.
      3. Split scanners by ``expensive`` flag.  Phase 1 (cheap) runs
         sequentially; Phase 2 (expensive) runs concurrently via
         ``asyncio.gather`` with per-scanner timeouts.
      4. Early termination: if Phase 1 produced an unsuppressed CRITICAL
         match, Phase 2 is skipped.
      5. Suppression engine evaluates all matches.
      6. Result is the new frozen ``ScanResult`` from ``_scan_context``
         (9d-ii — adapter removed from the production path).

    ``context_aware_paths`` is a legacy caller parameter kept for
    source-compat (orchestrator passes ``True`` for Claude-generated
    planner prompts).  Under the new protocol every scanner receives
    the full ``ScanContext``; region-aware scanning is intrinsic to
    the plugin, so the flag no longer drives pipeline behaviour.
    """
    logger.debug(
        "run_input_scan called",
        extra={
            "event": "security.input.run_input_scan",
            "text_length": len(text),
            "context_aware_paths": context_aware_paths,
        },
    )

    # Baseline mode: skip all scanning to measure utility without security overhead.
    baseline_result = _handle_baseline_skip_input(pipeline, text)
    if baseline_result is not None:
        return baseline_result

    t0 = time.monotonic()
    pipeline_run_id = uuid.uuid4().hex

    # Preprocess the raw text into an immutable ScanContext.
    metadata = ScanMetadata(
        phase=Phase.INPUT,
        output_destination=None,
        trust_level=0,
        tool_target=None,
        input_text=None,
    )
    context = pipeline._preprocessor.process(text, metadata)

    # Plan dispatch: partition by Phase, filter PG when pre-dispatch
    # availability policy synthesises a result (H1.2a), split cheap /
    # expensive.
    plan = _prepare_input_dispatch(pipeline)

    # Phase 1 (sequential) → early-termination check → Phase 2 (concurrent).
    phase1_runs = await _run_phase1_input(plan.cheap, context)
    skipped_async = _evaluate_early_termination(
        pipeline,
        phase1_runs,
        context,
        cheap_count=len(plan.cheap),
        expensive_count=len(plan.expensive),
    )
    phase2_runs: list[ScannerRun] = (
        [] if skipped_async else await _run_phase2_input(plan.expensive, context)
    )
    all_runs: list[ScannerRun] = list(phase1_runs) + list(phase2_runs)

    # Final suppression eval + PG-synthetic merge + ScanResult assembly.
    bundle = _merge_input_verdicts(
        pipeline,
        all_runs,
        context,
        plan.pg_availability,
        skipped_async=skipped_async,
    )

    # Emit audit events (no-op when no audit emitter is wired).
    _emit_input_audit(
        pipeline,
        text,
        pipeline_run_id,
        plan.input_scanners,
        all_runs,
        bundle,
        plan.pg_availability,
        t0,
    )

    elapsed = time.monotonic() - t0
    _log_scan_results(bundle.result, "input", text, elapsed)
    return bundle.result


def _empty_scan_result(text: str, phase: Phase) -> ScanResult:
    """Build an empty ``ScanResult`` for baseline-mode skips."""
    metadata = ScanMetadata(
        phase=phase,
        output_destination=None,
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


def _emit_gate_audit(
    pipeline: ScanPipeline,
    pipeline_run_id: str | None,
    gate_name: str,
    outcome: str,
    *,
    severity: str = "MEDIUM",
    gate_value: int | str | None = None,
    degraded: bool = False,
) -> None:
    """Emit a ``scan.gate`` audit event if an audit emitter is wired.

    No-op when ``pipeline_run_id`` is ``None`` — signals the pipeline
    has no audit emitter configured.  Normalises the
    ``build_gate_event → _schedule_audit_events`` call shape used by
    the length gate.  The token gate deliberately does NOT route
    through this helper — the token-gate no-audit contract is pinned
    by ``test_pipeline.py::TestPromptLengthTokenEstimate`` and must be
    preserved.  The ASCII script gate emits through
    ``_input_gates.check_prompt_ascii`` and is outside the current
    gate-audit normalisation scope.

    Q17-F3 (D2, 2026-04-24): parameter renamed from ``gate_run_id`` →
    ``pipeline_run_id`` so gate events share the same correlation key
    as the rest of the scan stream.
    """
    logger.debug(
        "_emit_gate_audit called",
        extra={
            "event": "security.phase_input._emit_gate_audit",
            "gate_name": gate_name,
            "outcome": outcome,
            "has_pipeline_run_id": pipeline_run_id is not None,
        },
    )
    if pipeline_run_id is None:
        logger.debug(
            "No audit emitter — skipping gate audit",
            extra={
                "event": "security.phase_input._emit_gate_audit.clean",
                "reason": "pipeline_run_id_none",
                "gate_name": gate_name,
            },
        )  # auto:neg
        return
    logger.debug(
        "_emit_gate_audit scheduling",
        extra={
            "event": "security.phase_input._emit_gate_audit.scheduled",
            "gate_name": gate_name,
            "outcome": outcome,
        },
    )
    pipeline._schedule_audit_events(
        [
            build_gate_event(
                pipeline_run_id,
                gate_name,
                outcome,
                severity=severity,
                gate_value=gate_value,
                degraded=degraded,
            ),
        ]
    )


async def _check_skip_scan(
    pipeline: ScanPipeline,
    prompt: str,
    skip_input_scan: bool,
) -> None:
    """Run the full input scan unless the caller opts out.

    When ``skip_input_scan`` is ``True`` (chained steps where the content
    was already scanned as output from a prior step), logs and returns
    without running the scan.  Otherwise delegates to
    ``pipeline.scan_input`` and raises ``SecurityViolation`` when the
    scan result is not clean.
    """
    logger.debug(
        "_check_skip_scan called",
        extra={
            "event": "security.phase_input._check_skip_scan",
            "skip_input_scan": skip_input_scan,
            "prompt_length": len(prompt),
        },
    )
    if skip_input_scan:
        logger.info(
            "Input scan skipped for internally-constructed prompt",
            extra={
                "event": "input.scan_skipped",
                "prompt_length": len(prompt),
                "reason": "skip_input_scan=True (chained step or DISPLAY)",
            },
        )
        return
    logger.debug(
        "_check_skip_scan: skip_input_scan_passed",
        extra={
            "event": "security.phase_input._check_skip_scan.skip_input_scan_passed",
            "reason": "skip_input_scan_passed",
        },
    )  # auto:neg
    # Call through the method (not the module function) to preserve
    # the original call chain — tests patch pipeline.scan_input.
    input_scan = await pipeline.scan_input(prompt, context_aware_paths=True)
    if not input_scan.is_clean:
        logger.warning(
            "Input blocked by scan pipeline",
            extra={
                "event": "input.blocked",
                "violations": list(input_scan.violated_scanners()),
            },
        )
        raise SecurityViolation(
            "Input blocked by security scan",
            input_scan,
        )


def _check_script_gate(
    pipeline: ScanPipeline,
    prompt: str,
    skip_input_scan: bool,
    baseline_mode: bool,
    pipeline_run_id: str | None,
) -> None:
    """Run the ASCII script gate unless bypassed.

    Bypassed for chained steps (``skip_input_scan=True``, where the prompt
    contains prior Qwen output via ``$variable`` substitution) and in
    baseline mode.  Delegates to ``check_prompt_ascii`` which owns gate
    audit emission and raises ``SecurityViolation`` on failure.

    Q17-F3 (D2, 2026-04-24): parameter renamed from ``gate_run_id`` →
    ``pipeline_run_id``; ``check_prompt_ascii`` already accepts
    ``pipeline_run_id`` so no call-site rename is needed.
    """
    logger.debug(
        "_check_script_gate called",
        extra={
            "event": "security.phase_input._check_script_gate",
            "skip_input_scan": skip_input_scan,
            "baseline_mode": baseline_mode,
        },
    )
    if not skip_input_scan and not baseline_mode:
        logger.debug(
            "Script gate active",
            extra={
                "event": "security.phase_input._check_script_gate.match",
                "reason": "not_skip_input_scan_and_not_baseline",
            },
        )  # auto:neg
        check_prompt_ascii(pipeline, prompt, pipeline_run_id=pipeline_run_id)


def _check_length_gate(
    pipeline: ScanPipeline,
    prompt: str,
    untrusted_data: str | None,
    pipeline_run_id: str | None,
) -> int:
    """Reject oversized prompts (combined prompt + untrusted_data length).

    Emits a ``scan.gate`` audit event and raises ``SecurityViolation``
    when the combined length exceeds ``_MAX_PROMPT_CHARS``.  Returns
    the computed combined length so the downstream token gate can reuse
    it without recomputing.

    Q17-F3 (D2, 2026-04-24): parameter renamed from ``gate_run_id`` →
    ``pipeline_run_id`` — same correlation key as manifest/summary/result.
    """
    combined_length = len(prompt) + (len(untrusted_data) if untrusted_data else 0)
    logger.debug(
        "_check_length_gate called",
        extra={
            "event": "security.phase_input._check_length_gate",
            "combined_length": combined_length,
        },
    )
    if combined_length > _MAX_PROMPT_CHARS:
        logger.warning(
            "Oversized prompt rejected before Qwen",
            extra={
                "event": "prompt.too_long",
                "combined_length": combined_length,
                "prompt_length": len(prompt),
                "untrusted_data_length": len(untrusted_data) if untrusted_data else 0,
            },
        )
        # Emit scan.gate audit event for prompt_length gate failure.
        _emit_gate_audit(
            pipeline,
            pipeline_run_id,
            "prompt_length",
            "BLOCKED",
            severity="MEDIUM",
            gate_value=combined_length,
        )
        raise SecurityViolation(
            f"Prompt too long ({combined_length:,} chars, maximum 100,000)",
            build_gate_scan_result(
                scanner_name="prompt_length_gate",
                rule_id="prompt_too_long",
                matched_text=f"combined length: {combined_length:,} chars",
                phase=Phase.INPUT,
            ),
        )
    logger.debug(
        "Length gate passed (char count under MAX)",
        extra={
            "event": "prompt.too_long.passed",
            "reason": "combined_length_gt_MAX_PROMPT_CHARS_passed",
        },
    )  # auto:neg
    return combined_length


def _check_token_gate(combined_length: int) -> None:
    """Reject prompts estimated to exceed Qwen's context token limit.

    Dense prompts (code, symbols) can overflow Qwen's context window
    even when under the char limit.  Deliberately emits NO audit event —
    the token-gate no-audit contract is pinned by
    ``test_pipeline.py::TestPromptLengthTokenEstimate``.
    """
    estimated_tokens = int(combined_length / _CHARS_PER_TOKEN_ESTIMATE)
    logger.debug(
        "_check_token_gate called",
        extra={
            "event": "security.phase_input._check_token_gate",
            "combined_length": combined_length,
            "estimated_tokens": estimated_tokens,
        },
    )
    if estimated_tokens > _CONTEXT_TOKEN_LIMIT:
        logger.warning(
            "Oversized prompt rejected (estimated token limit)",
            extra={
                "event": "prompt.length_gate_blocked",
                "reason": "token_estimate",
                "combined_length": combined_length,
                "estimated_tokens": estimated_tokens,
                "context_token_limit": _CONTEXT_TOKEN_LIMIT,
                "chars_per_token": _CHARS_PER_TOKEN_ESTIMATE,
            },
        )
        raise SecurityViolation(
            f"Prompt estimated at ~{estimated_tokens:,} tokens "
            f"(Qwen context limit: {_CONTEXT_TOKEN_LIMIT:,})",
            build_gate_scan_result(
                scanner_name="prompt_length_gate",
                rule_id="prompt_token_estimate_exceeded",
                matched_text=f"~{estimated_tokens:,} estimated tokens",
                phase=Phase.INPUT,
            ),
        )
    logger.debug(
        "Prompt length gate passed",
        extra={
            "event": "prompt.length_gate_pass",
            "combined_chars": combined_length,
            "estimated_tokens": estimated_tokens,
        },
    )


async def validate_input(
    pipeline: ScanPipeline,
    prompt: str,
    untrusted_data: str | None,
    skip_input_scan: bool,
) -> None:
    """Pre-flight validation: input scan, script gate, prompt length gates.

    Extracted from ScanPipeline._validate_input. Raises SecurityViolation
    if any gate fails. Skips input scan and script gate for chained steps
    (skip_input_scan=True) where the content was already scanned as output
    from a prior step.
    """
    logger.debug(
        "validate_input called",
        extra={
            "event": "security.input.validate_input",
            "prompt_length": len(prompt),
            "has_untrusted_data": untrusted_data is not None,
            "skip_input_scan": skip_input_scan,
        },
    )

    # Input scan: skip for internally-constructed prompts (chained steps
    # where the orchestrator has already wrapped prior output in
    # UNTRUSTED_DATA tags + spotlighting markers).  The original user
    # request was scanned at task intake and the chained content was
    # scanned as output from the previous step; scanning our own
    # defensive wrapper text causes Prompt Guard false positives (the
    # instruction-like reminders look like injection).
    await _check_skip_scan(pipeline, prompt, skip_input_scan)

    # Gate-phase pipeline_run_id for correlating gate audit events with
    # manifest/summary/result events in the same scan invocation (Q17-F3).
    pipeline_run_id = uuid.uuid4().hex if pipeline._audit_emitter else None

    # Script gate: block non-Latin scripts from reaching Qwen.  Skipped
    # for chained steps (prior Qwen output via ``$variable`` is already
    # scanned) and in baseline mode.
    settings = _get_settings()
    _check_script_gate(
        pipeline,
        prompt,
        skip_input_scan,
        settings.baseline_mode,
        pipeline_run_id,
    )

    # Prompt length gate: reject oversized prompts before they reach Qwen.
    # The per-field limit is 50K chars, but the orchestrator can combine
    # prompt + untrusted_data + spotlighting markers, so we allow 2x here.
    combined_length = _check_length_gate(
        pipeline,
        prompt,
        untrusted_data,
        pipeline_run_id,
    )

    # Token estimation gate: dense prompts (code, symbols) can overflow
    # Qwen's context window even when under the char limit.  Preserves
    # the token-gate no-audit contract pinned by tests.
    _check_token_gate(combined_length)
