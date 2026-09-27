"""MTM session aggregator — Peak + Persistence + Diversity formula.

Computes session-level risk by combining five components:
  - Peak: highest single-turn score ever in this session
  - Persistence: fraction of turns scoring above low_threshold
  - Diversity: distinct signal categories triggered across all turns
  - Velocity: escalation from previous turn to current turn
  - Current: the current turn's raw score

Design doc Section 5, research doc Section 6.4.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import TurnScore

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AggregationResult:
    """Output of the session risk aggregation formula.

    All fields are exposed for audit trail and debugging.
    """

    total: float
    peak: float
    persistence_ratio: float
    persistence_count: int
    diversity_count: int
    velocity: float
    benign_floor_active: bool
    action: str  # "allow", "warn", "block"


def aggregate_session_risk(
    turn_scores: list[TurnScore],
    current_turn: TurnScore,
    config: MTMConfig,
    benign_floor_active: bool = False,
    persistence_override: int | None = None,
) -> AggregationResult:
    """Compute session-level risk using Peak + Persistence + Diversity.

    Args:
        turn_scores: All turns in the session including the current turn.
        current_turn: The current (latest) turn being evaluated.
        config: Tuneable constants for the formula.
        benign_floor_active: Whether the benign session floor discount applies.
        persistence_override: If set, use this count instead of computing from
            turn_scores. Used by success forgiveness to reduce persistence.

    Returns:
        AggregationResult with full breakdown for audit.

    Raises:
        ValueError: If turn_scores is empty.
    """
    logger.debug(
        "aggregator.aggregate: computing session risk",
        extra={
            "event": "conversation.aggregator.compute",
            "turn_count": len(turn_scores),
            "benign_floor_active": benign_floor_active,
        },
    )

    if not turn_scores:
        msg = "turn_scores must contain at least the current turn"
        raise ValueError(msg)

    # 1. Peak — highest single-turn score ever
    peak = max(t.score for t in turn_scores)

    # 2. Persistence — fraction of turns above low_threshold (strictly greater)
    if persistence_override is not None:
        persistence_count = persistence_override
    else:
        persistence_count = sum(
            1 for t in turn_scores if t.score > config.low_threshold
        )
    persistence_ratio = persistence_count / len(turn_scores)

    # 3. Diversity — distinct signal categories across all turns
    all_categories: set[str] = set()
    for t in turn_scores:
        all_categories.update(t.categories)
    diversity_count = len(all_categories)

    # 4. Velocity — escalation from previous to current (clamped >= 0)
    #    Assumes turn_scores is in chronological order with current_turn last.
    if len(turn_scores) >= 2:
        prev_score = turn_scores[-2].score
        velocity = max(0.0, current_turn.score - prev_score)
    else:
        velocity = 0.0

    # 5. Composite score
    total = (
        peak
        + (persistence_ratio * config.alpha)
        + (diversity_count * config.delta)
        + (velocity * config.beta_e)
        + current_turn.score
    )

    # Benign floor discount: applied only when active AND below block threshold
    if benign_floor_active and total < config.block_threshold:
        logger.debug(
            "aggregator.aggregate: applying benign floor discount",
            extra={
                "event": "conversation.aggregator.benign_floor",
                "total_before": total,
                "discount": config.benign_floor_discount,
            },
        )
        total *= config.benign_floor_discount

    # Action determination
    if total >= config.block_threshold:
        action = "block"
    elif total >= config.warn_threshold:
        action = "warn"
    else:
        action = "allow"

    logger.debug(
        "aggregator.aggregate: result",
        extra={
            "event": "conversation.aggregator.result",
            "total": total,
            "peak": peak,
            "persistence_ratio": persistence_ratio,
            "diversity_count": diversity_count,
            "velocity": velocity,
            "action": action,
        },
    )

    return AggregationResult(
        total=total,
        peak=peak,
        persistence_ratio=persistence_ratio,
        persistence_count=persistence_count,
        diversity_count=diversity_count,
        velocity=velocity,
        benign_floor_active=benign_floor_active,
        action=action,
    )
