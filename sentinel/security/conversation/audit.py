"""MTM audit event builders — structured SecurityAuditEvent records.

Builds per-turn and session-summary audit events for the unified
security audit framework. All events use the 'conversation' category
(event types: conversation.mtm_turn, conversation.mtm_summary).

No raw user content in audit records — only length + SHA-256 hash.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

from sentinel.audit.events import SecurityAuditEvent

if TYPE_CHECKING:
    from sentinel.security.conversation.aggregator import AggregationResult
    from sentinel.security.conversation.config import MTMConfig
    from sentinel.security.conversation.types import TurnScore
    from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# Outcome and severity mappings — matches intake.py _ACTION_TO_OUTCOME
_ACTION_TO_OUTCOME = {"allow": "ALLOWED", "warn": "WARNED", "block": "BLOCKED"}
_ACTION_TO_SEVERITY = {"allow": "INFO", "warn": "MEDIUM", "block": "HIGH"}


def build_turn_audit_event(
    session_id: str,
    turn_index: int,
    request: str,
    turn_score: TurnScore,
    aggregation: AggregationResult,
    config: MTMConfig,
) -> SecurityAuditEvent:
    """Build a SecurityAuditEvent for one MTM turn analysis.

    Uses event_type='conversation.mtm_turn' under the existing
    'conversation' audit category. Signal breakdown, aggregation
    formula components, and config snapshot go in the details JSONB.

    Args:
        session_id: Current session identifier.
        turn_index: Zero-based turn index in the session.
        request: The user's request text (hashed, never stored raw).
        turn_score: Signal-level scoring for this turn.
        aggregation: Full aggregation result with formula breakdown.
        config: Active MTM configuration at decision time.

    Returns:
        Frozen SecurityAuditEvent ready for AuditEmitter.emit().
    """
    logger.debug(
        "audit.build_turn_audit_event: building",
        extra={
            "event": "conversation.audit.build_turn",
            "session_id": session_id,
            "turn_index": turn_index,
            "action": aggregation.action,
        },
    )

    action = aggregation.action
    request_hash = "sha256:" + hashlib.sha256(request.encode()).hexdigest()

    # Signal breakdown — only non-zero signals
    signals = {}
    for name, result in turn_score.signal_details.items():
        if result.score > 0.0:
            signals[name] = {
                "score": result.score,
                "categories": sorted(result.categories),
                "details": list(result.details),
            }

    details = {
        "session_id": session_id,
        "turn_index": turn_index,
        "request_length": len(request),
        "request_hash": request_hash,
        "signals": signals,
        "turn_score": turn_score.score,
        "categories": sorted(turn_score.categories),
        "aggregation": {
            "peak": aggregation.peak,
            "persistence_ratio": aggregation.persistence_ratio,
            "persistence_count": aggregation.persistence_count,
            "diversity_count": aggregation.diversity_count,
            "velocity": aggregation.velocity,
        },
        "action": action,
        "config_snapshot": {
            "alpha": config.alpha,
            "delta": config.delta,
            "beta_e": config.beta_e,
            "warn_threshold": config.warn_threshold,
            "block_threshold": config.block_threshold,
            "window_size": config.window_size,
        },
        "benign_floor_active": aggregation.benign_floor_active,
    }

    return SecurityAuditEvent(
        event_type="conversation.mtm_turn",
        source_component="mtm",
        outcome=_ACTION_TO_OUTCOME.get(action, "ALLOWED"),
        severity=_ACTION_TO_SEVERITY.get(action, "INFO"),
        details=details,
    )


def build_session_summary_event(
    session: Session,
    final_action: str,
    aggregation: AggregationResult,
) -> SecurityAuditEvent:
    """Build a SecurityAuditEvent for MTM session summary (emitted on lock).

    Summarises the full session: turn count, peak score, all triggered
    categories, and the final aggregation total.

    Args:
        session: The session being summarised.
        final_action: The action that triggered the summary ("block").
        aggregation: Final aggregation result.

    Returns:
        Frozen SecurityAuditEvent ready for AuditEmitter.emit().
    """
    logger.debug(
        "audit.build_session_summary_event: building",
        extra={
            "event": "conversation.audit.build_summary",
            "session_id": session.session_id,
            "final_action": final_action,
        },
    )

    # Collect all triggered categories across all turns
    all_categories: set[str] = set()
    for turn in session.turns:
        all_categories.update(turn.mtm_signal_categories)

    details = {
        "session_id": session.session_id,
        "turn_count": len(session.turns),
        "peak_score": session.mtm_peak_score,
        "aggregation_total": aggregation.total,
        "categories": sorted(all_categories),
        "final_action": final_action,
    }

    return SecurityAuditEvent(
        event_type="conversation.mtm_summary",
        source_component="mtm",
        outcome=_ACTION_TO_OUTCOME.get(final_action, "ALLOWED"),
        severity=_ACTION_TO_SEVERITY.get(final_action, "INFO"),
        details=details,
    )
