"""Conversation analysis gate — multi-turn attack detection and audit.

Extracted from intake.py. Runs the conversation analyzer (legacy or MTM),
emits audit events, and enforces session lock-on-block. Security-critical:
the block/warn/allow decision here controls whether a request proceeds
to the planner.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.config import settings
from sentinel.core.models import ConversationInfo, TaskResult
from sentinel.crypto.blind_index import log_hash
from sentinel.planner._intake_types import IntakeResult
from sentinel.session.store import ConversationTurn, Session, SessionStore

if TYPE_CHECKING:
    from sentinel.audit.emitter import AuditEmitter
    from sentinel.security.conversation import AnalysisResult, ConversationAnalyzer
    from sentinel.security.conversation.monitor import MultiTurnMonitor

logger = logging.getLogger(__name__)


async def _emit_audit_event(
    audit_emitter: AuditEmitter | None,
    event: SecurityAuditEvent,
) -> None:
    """Fire-and-forget audit event emit. Never raises to caller."""
    if audit_emitter is None:
        return
    try:
        await audit_emitter.emit(event)
    except Exception:
        logger.debug(
            "Conversation audit emit failed (non-fatal)",
            extra={
                "event": "conversation.audit_emit_failed",
                "event_type": event.event_type,
            },
        )


_ACTION_TO_OUTCOME = {"allow": "ALLOWED", "warn": "WARNED", "block": "BLOCKED"}
_ACTION_TO_SEVERITY = {"allow": "INFO", "warn": "MEDIUM", "block": "HIGH"}


async def _emit_conversation_audit(
    audit_emitter: AuditEmitter | None,
    session: Session,
    analysis: object,
    user_request: str,
) -> None:
    """Emit conversation.analysis and optionally conversation.override_attempt."""
    if audit_emitter is None:
        return
    if not user_request or not user_request.strip():
        logger.debug(
            "_emit_conversation_audit skipped — empty/whitespace request",
            extra={
                "event": "conversation.audit_skip_empty",
                "session_id": session.session_id,
            },
        )
        return

    action = analysis.action
    # Emit conversation.analysis for every analysis result
    await _emit_audit_event(
        audit_emitter,
        SecurityAuditEvent(
            event_type="conversation.analysis",
            source_component="conversation",
            outcome=_ACTION_TO_OUTCOME.get(action, "ALLOWED"),
            severity=_ACTION_TO_SEVERITY.get(action, "INFO"),
            details={
                "session_id": session.session_id,
                "turn_number": len(session.turns),
                "action": action,
                "total_score": analysis.total_score,
                "rule_scores": dict(analysis.rule_scores),
                "request_length": len(user_request),
                "request_hash": log_hash(user_request),
            },
        ),
    )

    # Emit conversation.override_attempt on first-turn instruction override
    if len(session.turns) == 0 and "instruction_override" in analysis.rule_scores:
        await _emit_audit_event(
            audit_emitter,
            SecurityAuditEvent(
                event_type="conversation.override_attempt",
                source_component="conversation",
                outcome="BLOCKED" if action == "block" else "WARNED",
                severity="HIGH" if action == "block" else "MEDIUM",
                details={
                    "session_id": session.session_id,
                    "score": analysis.rule_scores["instruction_override"],
                },
            ),
        )


# Shadow mode score divergence threshold — differences below this
# are considered agreement and no shadow event is emitted.
_SHADOW_DIVERGENCE_THRESHOLD = 2.0


async def _emit_shadow_comparison(
    audit_emitter: AuditEmitter | None,
    session: Session,
    legacy_analysis: AnalysisResult,
    mtm_analysis: AnalysisResult,
) -> None:
    """Emit conversation.mtm_shadow when MTM and legacy significantly diverge.

    Emits via the unified audit framework (SecurityAuditEvent), making
    shadow results queryable in the security_audit_log table.

    Skips when:
    - No audit_emitter configured
    - Actions match AND score divergence < _SHADOW_DIVERGENCE_THRESHOLD
    """
    if audit_emitter is None:
        logger.debug(
            "shadow comparison skipped — no emitter",
            extra={"event": "analyze.shadow_skip_no_emitter"},
        )
        return

    divergence = abs(legacy_analysis.total_score - mtm_analysis.total_score)
    actions_match = legacy_analysis.action == mtm_analysis.action

    if actions_match and divergence < _SHADOW_DIVERGENCE_THRESHOLD:
        logger.debug(
            "shadow comparison — analyzers agree, no event",
            extra={
                "event": "analyze.shadow_agree",
                "session_id": session.session_id,
                "action": legacy_analysis.action,
                "divergence": divergence,
            },
        )
        return

    logger.info(
        "shadow comparison — divergence detected",
        extra={
            "event": "analyze.shadow_divergence",
            "session_id": session.session_id,
            "legacy_action": legacy_analysis.action,
            "mtm_action": mtm_analysis.action,
            "divergence": divergence,
        },
    )
    await _emit_audit_event(
        audit_emitter,
        SecurityAuditEvent(
            event_type="conversation.mtm_shadow",
            source_component="mtm",
            outcome="ALLOWED",  # shadow mode never enforces
            severity="LOW",
            details={
                "session_id": session.session_id,
                "legacy_action": legacy_analysis.action,
                "legacy_score": legacy_analysis.total_score,
                "mtm_action": mtm_analysis.action,
                "mtm_score": mtm_analysis.total_score,
                "divergence": divergence,
            },
        ),
    )


async def analyze_conversation(
    user_request: str,
    session: Session,
    conversation_analyzer: ConversationAnalyzer | None,
    session_store: SessionStore | None,
    audit_emitter: AuditEmitter | None = None,
    multi_turn_monitor: MultiTurnMonitor | None = None,
) -> IntakeResult:
    """Run multi-turn attack detection. Block/warn/allow.

    Three-position feature flag (settings.mtm_enabled):
    - "true": MTM replaces legacy — MTM emits its own audit events
    - "shadow": both run, legacy enforces — shadow comparison emitted
    - "false" (default): legacy only

    Updates session risk score and lock state. When the analyzer says
    "block", the session is locked and a blocked turn is recorded.
    For "warn", cumulative risk is ratcheted upward (SYS-4/RACE-3).

    Returns IntakeResult with conv_info populated. If blocked,
    `blocked=True` and `task_result` is set.
    """
    mtm_mode = settings.mtm_enabled
    logger.debug(
        "analyze_conversation called",
        extra={
            "event": "analyze.conversation",
            "session_id": session.session_id,
            "has_analyzer": conversation_analyzer is not None,
            "has_mtm": multi_turn_monitor is not None,
            "mtm_mode": mtm_mode,
        },
    )

    # Select which analyzer to use based on feature flag
    use_mtm = mtm_mode == "true" and multi_turn_monitor is not None
    use_shadow = (
        mtm_mode == "shadow"
        and multi_turn_monitor is not None
        and conversation_analyzer is not None
    )

    # Determine the active analyzer (legacy or MTM)
    if use_mtm:
        active_analyzer = multi_turn_monitor
        analyzer_label = "multi_turn_monitor"
    elif conversation_analyzer is not None:
        active_analyzer = conversation_analyzer
        analyzer_label = "conversation_analyzer"
    else:
        logger.debug(
            "analyze_conversation skipped — no analyzer configured",
            extra={
                "event": "analyze.conversation_skip",
                "session_id": session.session_id,
            },
        )
        return IntakeResult(session=session)

    logger.debug(
        "analyze_conversation — analyzer selected",
        extra={
            "event": "analyze.conversation_analyzer_selected",
            "session_id": session.session_id,
            "analyzer": analyzer_label,
            "shadow": use_shadow,
        },
    )

    try:
        analysis = active_analyzer.analyze(session, user_request)

        # Persist fix-cycle forgiveness (Finding #11: moved out of analyzer)
        # Only applies to legacy analyzer — MTM handles forgiveness internally
        if analysis.new_success_forgives is not None:
            session.success_forgives_used = analysis.new_success_forgives

        conv_info = ConversationInfo(
            session_id=session.session_id,
            turn_number=len(session.turns),
            risk_score=analysis.total_score,
            action=analysis.action,
            warnings=analysis.warnings,
            mtm_turn_score=analysis.mtm_turn_score,
            mtm_turn_categories=analysis.mtm_turn_categories,
        )

        # Audit emission: MTM collects coroutines in _emit_audit,
        # flushed here via flush_audit(). Legacy uses _emit_conversation_audit.
        # Shadow mode: legacy audit + shadow comparison + MTM flush.
        if use_mtm:
            await multi_turn_monitor.flush_audit()
        else:
            await _emit_conversation_audit(
                audit_emitter,
                session,
                analysis,
                user_request,
            )

        # Shadow mode: run MTM for comparison (non-enforcing).
        # Wrapped in try/except so a shadow-mode MTM crash never
        # blocks the user — shadow is observational only.
        if use_shadow:
            # use_shadow=True implies use_mtm=False (flag logic at lines 215-220):
            # the enforcing analyzer is legacy and does not mutate mtm_peak_score
            # before this block. If that mutual exclusivity ever changes, extend
            # the snapshot/restore scope to wrap the enforcing analyzer call too.
            saved_peak = session.mtm_peak_score
            try:
                mtm_analysis = multi_turn_monitor.analyze(session, user_request)
                session.mtm_peak_score = saved_peak  # restore — shadow is non-enforcing
                await multi_turn_monitor.flush_audit()
                await _emit_shadow_comparison(
                    audit_emitter,
                    session,
                    analysis,
                    mtm_analysis,
                )
            except Exception:
                session.mtm_peak_score = saved_peak  # restore on exception too
                logger.warning(
                    "shadow MTM comparison failed (non-fatal)",
                    extra={
                        "event": "analyze.shadow_error",
                        "error_category": "shadow_mtm",
                        "session_id": session.session_id,
                    },
                    exc_info=True,
                )

        if analysis.action == "block":
            return await _handle_block(
                session,
                session_store,
                audit_emitter,
                user_request,
                analysis,
                conv_info,
                analyzer_label,
            )

        # For "warn", continue processing but include warnings
        # SYS-4/RACE-3: Atomic DB update — ratchets upward only
        logger.debug(
            "analyze_conversation decision — warn/allow path",
            extra={
                "event": "analyze.conversation_warn",
                "session_id": session.session_id,
                "action": analysis.action,
                "risk_score": analysis.total_score,
                "ratchet_needed": analysis.total_score > session.cumulative_risk,
            },
        )
        if analysis.total_score > session.cumulative_risk:
            session.cumulative_risk = analysis.total_score
            if session_store is not None:
                await session_store.accumulate_risk(
                    session.session_id,
                    analysis.total_score,
                )

        logger.debug(
            "analyze_conversation completed",
            extra={
                "event": "analyze.conversation_exit",
                "session_id": session.session_id,
                "action": analysis.action,
                "risk_score": analysis.total_score,
            },
        )
        return IntakeResult(session=session, conv_info=conv_info)

    except Exception as exc:
        logger.error(
            "Conversation analysis failed",
            extra={
                "event": "conv.analysis_error",
                "session_id": session.session_id,
                "error": str(exc),
                "error_category": "analysis",
            },
            exc_info=True,
        )
        return IntakeResult(
            blocked=True,
            task_result=TaskResult(
                status="error",
                reason="Service temporarily unavailable",
            ),
        )


async def _handle_block(
    session: Session,
    session_store: SessionStore | None,
    audit_emitter: AuditEmitter | None,
    user_request: str,
    analysis: AnalysisResult,
    conv_info: ConversationInfo,
    analyzer_label: str,
) -> IntakeResult:
    """Handle a block decision — lock session, record turn, emit audit."""
    logger.info(
        "analyze_conversation decision — blocking session",
        extra={
            "event": "analyze.conversation_block",
            "session_id": session.session_id,
            "risk_score": analysis.total_score,
            "warning_count": len(analysis.warnings),
            "analyzer": analyzer_label,
        },
    )
    session.cumulative_risk = analysis.total_score
    if session_store is not None:
        await session_store.accumulate_risk(
            session.session_id,
            analysis.total_score,
        )
    session.lock()
    if session_store is not None:
        await session_store.lock_session(session.session_id)
    # Emit session locked event
    await _emit_audit_event(
        audit_emitter,
        SecurityAuditEvent(
            event_type="conversation.locked",
            source_component="conversation",
            outcome="LOCKED",
            severity="HIGH",
            details={
                "session_id": session.session_id,
                "risk_score": analysis.total_score,
                "violation_count": session.violation_count,
            },
        ),
    )
    turn = ConversationTurn(
        request_text=user_request,
        result_status="blocked",
        blocked_by=[analyzer_label],
        risk_score=analysis.total_score,
        mtm_turn_score=analysis.mtm_turn_score,
        mtm_signal_categories=analysis.mtm_turn_categories,
    )
    session.add_turn(turn)
    if session_store is not None:
        await session_store.add_turn(session.session_id, turn, session=session)
    return IntakeResult(
        session=session,
        conv_info=conv_info,
        blocked=True,
        task_result=TaskResult(
            status="blocked",
            reason="Blocked by multi-turn conversation analysis",
            conversation=conv_info,
        ),
    )
