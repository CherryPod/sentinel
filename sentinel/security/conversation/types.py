"""MTM type definitions — immutable data structures for signal and turn scores.

These types flow through the MTM pipeline:
  Signal extractors produce SignalResult → aggregator combines into TurnScore
"""

from dataclasses import dataclass

# Pipeline scanners whose block reasons classify as security violations
# (as distinct from policy violations) when MTM attributes a prior block.
# These names are the stable `scanner_info.name` values — adding a new
# pipeline security scanner means updating this set.
PIPELINE_SECURITY_SCANNER_NAMES: frozenset[str] = frozenset(
    {
        "credential_scanner",
        "sensitive_path_scanner",
        "command_pattern_scanner",
        "encoding_normalization_scanner",
        "vulnerability_echo_scanner",
    }
)


@dataclass(frozen=True, slots=True)
class SignalResult:
    """Output of a single signal extractor.

    Attributes:
        score: This signal's contribution to the turn score.
        categories: Signal category tags for diversity counting.
        details: Human-readable explanation strings for audit logs.
    """

    score: float
    categories: frozenset[str]
    details: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TurnScore:
    """Aggregated score for one conversation turn.

    Attributes:
        score: Sum of signal scores for this turn.
        categories: Union of all signal categories that fired.
        signal_details: Signal name to result mapping for audit trail.
            Note: dict is mutable by reference but frozen prevents reassignment.
            All producers must treat as read-only after construction.
    """

    score: float
    categories: frozenset[str]
    signal_details: dict[str, SignalResult]
