"""Frozen data types for the security scanner pipeline.

All types are immutable (``@dataclass(frozen=True)``) — scanners receive
immutable context and produce immutable matches.  No mutable state flows
through the pipeline.  Collections use ``tuple`` (not ``list``) to preserve
immutability guarantees.
"""

from __future__ import annotations

import logging  # auto:logger
from collections import defaultdict
from dataclasses import dataclass

from sentinel.security._enums import (
    EncodingType,
    OutputDestination,
    Phase,
    Platform,
    RegionType,
    Severity,
)

logger = logging.getLogger(__name__)  # auto:logger


# ---------------------------------------------------------------------------
# Context types (produced by preprocessing, consumed by scanners)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContextRegion:
    """A classified region within the scanned text.

    Produced solely by ``ContextClassifier``.
    """

    start: int
    end: int
    region_type: RegionType
    language_tag: str | None


@dataclass(frozen=True)
class DecodedVariant:
    """A decoded segment found by ``EncodingNormalizer``.

    ``decode_chain`` records encoding layers from outermost to innermost.
    Length > 1 indicates multi-layer encoding (more suspicious).
    """

    encoding: EncodingType
    original_span: tuple[int, int]
    decoded_text: str
    decode_chain: tuple[EncodingType, ...]


def encoded_rule_encoding(rule_id: str) -> str | None:
    """Return ``<enc>`` from ``encoded:<enc>:<rest>`` rule ids, else None."""
    if not rule_id.startswith("encoded:"):
        return None
    rest = rule_id[len("encoded:"):]
    enc, sep, _tail = rest.partition(":")
    if not sep or not enc:
        return None
    return enc


def decoded_variant_encoding_matches(
    variant: DecodedVariant, rule_id: str
) -> bool:
    """True when *variant* is eligible for an encoded match's rule_id.

    Slice-equal decoded texts from a different encoding must not bind.
    Plain (non-encoded) rule ids skip this filter.
    """
    enc = encoded_rule_encoding(rule_id)
    if enc is None:
        return True
    matches = variant.encoding.value == enc
    logger.debug(
        "encoded variant bind: encoding %s",
        "applied" if matches else "rejected",
        extra={
            "event": (
                "security.scan_context.encoded_variant_encoding_applied"
                if matches
                else "security.scan_context.encoded_variant_encoding_rejected"
            ),
            "rule_id": rule_id,
            "rule_encoding": enc,
            "variant_encoding": variant.encoding.value,
        },
    )
    return matches


@dataclass(frozen=True)
class ScanMetadata:
    """Per-scan metadata supplied by the pipeline caller.

    ``output_destination`` is ``None`` during input scanning (no destination
    yet).  ``tool_target`` is only set for ``EXECUTION`` destination.
    ``input_text`` is carried for the echo scanner (needs both input + output).
    """

    phase: Phase
    output_destination: OutputDestination | None
    trust_level: int
    tool_target: str | None
    input_text: str | None


@dataclass(frozen=True)
class ScanContext:
    """Immutable context passed to every scanner.

    Built by the preprocessing phase from raw text, encoding normalisation,
    and context classification.

    ``normalised_text`` is ``raw_text`` after homoglyph normalisation.
    All scanner match offsets and ``regions`` are in ``normalised_text``
    coordinate space.  ``raw_text`` is preserved for callers that need
    the original bytes; do not index ``raw_text`` with a match offset.
    ``normalised_text`` is ``None`` for contexts built outside the
    preprocessor (synthetic stubs, gate violations, test helpers); those
    contexts must fall back to ``raw_text`` when indexing.
    Note: ``encoded:*:`` rule matches carry offsets into the decoded
    variant's text, not into ``normalised_text``.
    """

    raw_text: str
    regions: tuple[ContextRegion, ...]
    decoded_variants: tuple[DecodedVariant, ...]
    metadata: ScanMetadata
    normalised_text: str | None = None


# ---------------------------------------------------------------------------
# Typed match metadata (one per scanner concern)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialMatchMeta:
    """Metadata for a credential scanner match."""

    credential_type: str
    platform_tags: tuple[Platform, ...]


@dataclass(frozen=True)
class PathMatchMeta:
    """Metadata for a sensitive-path scanner match."""

    path_type: str
    platform_tags: tuple[Platform, ...]


@dataclass(frozen=True)
class CommandMatchMeta:
    """Metadata for a command-pattern scanner match."""

    attack_type: str
    platform_tags: tuple[Platform, ...]


@dataclass(frozen=True)
class EchoMatchMeta:
    """Metadata for a vulnerability-echo scanner match."""

    fingerprint_type: str


@dataclass(frozen=True)
class MLMatchMeta:
    """Metadata for an ML/external scanner match."""

    model_name: str
    model_confidence: float


ScannerMatchMeta = (
    CredentialMatchMeta | PathMatchMeta | CommandMatchMeta | EchoMatchMeta | MLMatchMeta
)
"""Union type for type-safe match metadata dispatch."""


# ---------------------------------------------------------------------------
# Match and result types (produced by scanners, consumed by suppression/pipeline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanMatch:
    """A single match produced by a scanner.

    ``offset`` and ``length`` locate the match in ``ScanContext.normalised_text``
    (the homoglyph-normalised text).  Do not use them to index ``raw_text``.
    Exception: matches with ``rule_id`` prefixed ``encoded:<enc>:`` carry
    offsets into the decoded variant's text, not ``normalised_text``.
    ``region`` links to the ``ContextRegion`` containing the match (if any);
    region boundaries are also in ``normalised_text`` coordinate space.
    """

    rule_id: str
    scanner: str
    severity: Severity
    confidence: float
    matched_text: str
    offset: int
    length: int
    region: ContextRegion | None
    metadata: ScannerMatchMeta


@dataclass(frozen=True)
class SuppressionVerdict:
    """Suppression decision for a single match.

    ``canonical_reason`` is the first handler that matched (primary reason).
    ``all_reasons`` records every handler that would have suppressed, for
    FP benchmark traceability.
    """

    match: ScanMatch
    suppressed: bool
    canonical_reason: str | None
    all_reasons: tuple[str, ...]


@dataclass(frozen=True)
class ScanResult:
    """Aggregate result from a complete scan pass.

    ``found`` is ``True`` when any unsuppressed match exists.
    ``skipped_async`` is ``True`` when early termination skipped Phase 2.
    ``degraded_scanners`` lists scanner names that crashed / timed out /
    ran in degraded mode during this scan pass.
    ``ran_scanners`` lists every scanner that participated in dispatch
    (whether or not it produced matches) — callers that need to
    distinguish "scanner ran, found nothing" from "scanner didn't run
    at all" (DISPLAY-skipped, baseline mode) consult this set.
    """

    found: bool
    verdicts: tuple[SuppressionVerdict, ...]
    context: ScanContext
    skipped_async: bool = False
    degraded_scanners: frozenset[str] = frozenset()
    ran_scanners: frozenset[str] = frozenset()

    @property
    def is_clean(self) -> bool:
        """Return True iff no unsuppressed match was recorded."""
        return not self.found

    def unsuppressed_by_scanner(
        self,
    ) -> dict[str, tuple[SuppressionVerdict, ...]]:
        """Group unsuppressed verdicts by scanner name.

        Keys use the legacy ``_scanner``-suffixed name (e.g.
        ``credential_scanner``) to match the audit event contract and
        existing caller expectations; the underlying ``ScanMatch``
        still carries the canonical meta name on ``match.scanner``.

        Returns an empty dict when every verdict is suppressed (or
        there are no verdicts).  Callers that need per-scanner block
        reasons iterate the returned dict; the order of scanner keys
        follows the order each scanner first produced an unsuppressed
        verdict.
        """
        from sentinel.security._scanner_names import legacy_name

        grouped: dict[str, list[SuppressionVerdict]] = defaultdict(list)
        for verdict in self.verdicts:
            if not verdict.suppressed:
                grouped[legacy_name(verdict.match.scanner)].append(verdict)
        return {name: tuple(verdicts) for name, verdicts in grouped.items()}

    def violated_scanners(self) -> tuple[str, ...]:
        """Return ordered scanner names with at least one unsuppressed verdict.

        Convenience for the many call sites that previously wrote
        ``list(result.violations.keys())``.  Preserves first-appearance
        order so downstream logs and blocker messages stay stable.
        Names use the legacy ``_scanner``-suffixed form.
        """
        return tuple(self.unsuppressed_by_scanner())

    def verdicts_by_scanner(
        self,
    ) -> dict[str, tuple[SuppressionVerdict, ...]]:
        """Group every verdict by scanner name (suppressed and unsuppressed).

        Keys use the legacy ``_scanner``-suffixed name.  Used by audit
        emitters and the ``/security/process`` response serialiser —
        both need to list suppressed matches alongside unsuppressed
        ones per scanner.  Scanners that appear in ``ran_scanners`` or
        ``degraded_scanners`` but produced no verdicts are included
        with an empty verdict tuple so callers can distinguish
        "scanner ran, found nothing" from "scanner wasn't dispatched".

        Defensively routes ``ran_scanners`` / ``degraded_scanners``
        through ``legacy_name`` too, so a future external constructor
        that populates those sets with raw meta names can't produce a
        result with two entries for the same scanner (one short, one
        suffixed) — Codex review 9d-ii finding.
        """
        logger.debug(
            "verdicts_by_scanner called",
            extra={"event": "security.scan_context.verdicts_by_scanner"},
        )  # auto:entry
        from sentinel.security._scanner_names import legacy_name

        grouped: dict[str, list[SuppressionVerdict]] = defaultdict(list)
        for verdict in self.verdicts:
            grouped[legacy_name(verdict.match.scanner)].append(verdict)
        view: dict[str, tuple[SuppressionVerdict, ...]] = {
            name: tuple(verdicts) for name, verdicts in grouped.items()
        }
        for scanner_name in self.ran_scanners:
            view.setdefault(legacy_name(scanner_name), ())
        for scanner_name in self.degraded_scanners:
            view.setdefault(legacy_name(scanner_name), ())
        return view


@dataclass(frozen=True)
class AllowlistEntry:
    """Global allowlist entry for a specific rule.

    ``reason`` is mandatory — logged as a warning at startup for every
    active entry so allowlisted rules remain visible.
    """

    rule_id: str
    reason: str
