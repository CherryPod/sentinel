"""Synthetic ``ScanResult`` constructor for non-scanner gate violations.

Gate checks (ASCII script, prompt length, token estimate) enforce trust
boundaries before the scanner pipeline runs — they don't produce real
``ScannerRun`` entries, so they can't go through the normal suppression
engine.  After Phase 9d-ii the ``SecurityViolation.violations`` field is
typed as a single new-shape ``ScanResult`` rather than the legacy
``dict[str, ScanResult]``; gates previously constructed the dict by hand
and now build a synthetic new-shape result via this helper.

Keeping the synthetic-construction logic in one place avoids the
clutter of hand-building ``ScanContext`` + ``ScanMatch`` +
``SuppressionVerdict`` at every gate raise site.
"""

from __future__ import annotations

from sentinel.security._enums import Phase, Severity
from sentinel.security._scan_context import (
    MLMatchMeta,
    ScanContext,
    ScanMatch,
    ScanMetadata,
    ScanResult,
    SuppressionVerdict,
)


def build_gate_scan_result(
    *,
    scanner_name: str,
    rule_id: str,
    matched_text: str,
    phase: Phase = Phase.INPUT,
) -> ScanResult:
    """Construct a synthetic new-shape ``ScanResult`` for a gate violation.

    The synthetic ``ScanMatch`` carries ``scanner`` set to the gate
    identifier (``ascii_prompt_gate`` / ``prompt_length_gate`` / etc.),
    a ``CRITICAL`` severity, and the gate's chosen ``rule_id`` and
    ``matched_text``.  The wrapping ``SuppressionVerdict`` is always
    unsuppressed — gates block unconditionally.

    The gate's scanner name is recorded in ``degraded_scanners`` as
    well, so downstream audit code that groups by scanner sees the gate
    alongside real scanners.
    """
    context = ScanContext(
        raw_text=matched_text,
        regions=(),
        decoded_variants=(),
        metadata=ScanMetadata(
            phase=phase,
            output_destination=None,
            trust_level=0,
            tool_target=None,
            input_text=None,
        ),
    )
    match = ScanMatch(
        rule_id=rule_id,
        scanner=scanner_name,
        severity=Severity.CRITICAL,
        confidence=1.0,
        matched_text=matched_text,
        offset=0,
        length=len(matched_text),
        region=None,
        metadata=MLMatchMeta(model_name=scanner_name, model_confidence=1.0),
    )
    verdict = SuppressionVerdict(
        match=match,
        suppressed=False,
        canonical_reason=None,
        all_reasons=(),
    )
    return ScanResult(
        found=True,
        verdicts=(verdict,),
        context=context,
    )
