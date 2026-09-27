"""MTM monitor orchestrator — drop-in replacement for ConversationAnalyzer.

Orchestrates signal extraction, aggregation, and FP management.
Same interface: analyze(session, current_request) → AnalysisResult.

Design doc Section 3: component pipeline.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel.security.conversation import AnalysisResult
from sentinel.security.conversation.aggregator import (
    AggregationResult,
    aggregate_session_risk,
)
from sentinel.security.conversation.audit import (
    build_session_summary_event,
    build_turn_audit_event,
)
from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.fp_management import (
    apply_benign_anchor_suppression,
    apply_success_forgiveness,
    check_benign_floor,
)
from sentinel.security.conversation.signals import SIGNAL_REGISTRY
from sentinel.security.conversation.types import SignalResult, TurnScore
from sentinel.security.homoglyph import normalise_homoglyphs

if TYPE_CHECKING:
    from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# Signals that only run on first turn (no history needed)
_FIRST_TURN_SIGNALS = frozenset({"instruction_override"})

# Default weight when signal has no explicit weight override
_DEFAULT_SIGNAL_WEIGHT = 1.0


class MultiTurnMonitor:
    """Multi-Turn Monitor — drop-in replacement for ConversationAnalyzer.

    Uses Peak + Persistence + Diversity aggregation instead of simple
    cumulative scoring. Runs modular signal extractors from SIGNAL_REGISTRY.

    Args:
        config: MTM configuration. Defaults to from_settings() if None.
        audit_emitter: Optional audit emitter for structured event records.
            If provided, per-turn and session-summary events are emitted
            via the unified security audit framework. Audit failures never
            block the security decision.
    """

    def __init__(
        self,
        config: MTMConfig | None = None,
        *,
        audit_emitter: Any | None = None,
    ) -> None:
        if config is None:
            config = MTMConfig.from_settings()
        self._config = config
        self._audit_emitter = audit_emitter
        self._pending_audit_coros: list = []
        logger.debug(
            "monitor.__init__: created",
            extra={
                "event": "conversation.monitor.init",
                "warn_threshold": config.warn_threshold,
                "block_threshold": config.block_threshold,
                "signal_count": len(SIGNAL_REGISTRY),
                "has_audit_emitter": audit_emitter is not None,
            },
        )

    def analyze(self, session: Session, current_request: str) -> AnalysisResult:
        """Run all signal extractors, aggregate, return verdict.

        Same interface as ConversationAnalyzer.analyze() — callers need
        no changes.

        Args:
            session: Current session with turn history.
            current_request: The user's request text for this turn.

        Returns:
            AnalysisResult with action, total_score, rule_scores, warnings.
        """
        logger.debug(
            "monitor.analyze: starting",
            extra={
                "event": "conversation.monitor.analyze",
                "session_id": session.session_id,
                "turn_count": len(session.turns),
                "request_len": len(current_request),
            },
        )

        # Clear pending audit coroutines from any previous call.
        # Each analyze() starts fresh — the caller (intake) flushes
        # after each call, so stale coros indicate a missed flush.
        self._pending_audit_coros = []

        # 1. Homoglyph normalisation (same as legacy analyzer)
        current_request = normalise_homoglyphs(current_request)

        # 2. First-turn special case — only instruction_override
        if len(session.turns) == 0:
            return self._analyze_first_turn(session, current_request)

        # 3. Run all signals, apply FP management, aggregate
        return self._analyze_subsequent_turn(session, current_request)

    def _analyze_first_turn(
        self,
        session: Session,
        request: str,
    ) -> AnalysisResult:
        """Handle first turn — only run instruction_override signal.

        First messages have no history to compare against, so
        history-dependent signals (retry, escalation, etc.) are skipped.
        """
        logger.debug(
            "monitor._analyze_first_turn: evaluating",
            extra={
                "event": "conversation.monitor.first_turn",
                "session_id": session.session_id,
            },
        )

        rule_scores: dict[str, float] = {}
        signal_results: dict[str, SignalResult] = {}
        warnings: list[str] = []

        for name, extractor in SIGNAL_REGISTRY:
            if name not in _FIRST_TURN_SIGNALS:
                continue

            weight = self._get_signal_weight(name)
            if weight == 0.0:
                continue

            result = extractor(request, session, self._config)
            if result.score > 0.0:
                weighted_score = result.score * weight
                if weight != _DEFAULT_SIGNAL_WEIGHT:
                    result = SignalResult(
                        score=weighted_score,
                        categories=result.categories,
                        details=result.details,
                    )
                rule_scores[name] = weighted_score
                signal_results[name] = result
                warnings.extend(result.details)

        total = sum(rule_scores.values())

        if total >= self._config.block_threshold:
            action = "block"
        elif total >= self._config.warn_threshold:
            action = "warn"
        else:
            action = "allow"

        # Update peak score on session (I-3: first turn can have non-zero score)
        if total > session.mtm_peak_score:
            session.mtm_peak_score = total

        if total > 0.0:
            logger.info(
                "monitor._analyze_first_turn: override detected",
                extra={
                    "event": "conversation.monitor.first_turn_override",
                    "session_id": session.session_id,
                    "total": total,
                    "action": action,
                },
            )
        else:
            logger.debug(
                "monitor._analyze_first_turn: clean",
                extra={
                    "event": "conversation.monitor.first_turn_clean",
                    "session_id": session.session_id,
                },
            )

        # Build TurnScore + synthetic aggregation for audit emit
        turn_score = self._build_turn_score(signal_results)
        first_turn_agg = AggregationResult(
            total=total,
            peak=total,
            persistence_ratio=0.0,
            persistence_count=0,
            diversity_count=len(rule_scores),
            velocity=0.0,
            benign_floor_active=False,
            action=action,
        )
        self._emit_audit(session, request, turn_score, first_turn_agg)

        return AnalysisResult(
            action=action,
            total_score=total,
            rule_scores=rule_scores,
            warnings=warnings,
            mtm_turn_score=total,
            mtm_turn_categories=sorted(turn_score.categories),
        )

    def _analyze_subsequent_turn(
        self,
        session: Session,
        request: str,
    ) -> AnalysisResult:
        """Handle turns after the first — full signal + aggregation pipeline.

        Steps:
          1. Run all signal extractors
          2. Apply benign-anchor suppression to escalation signals
          3. Build TurnScore from signal results
          4. Build turn history from session MTM fields
          5. Check benign floor
          6. Apply success forgiveness to persistence
          7. Aggregate via aggregate_session_risk()
          8. Update session MTM fields
          9. Return AnalysisResult
        """
        logger.debug(
            "monitor._analyze_subsequent_turn: starting",
            extra={
                "event": "conversation.monitor.subsequent_turn",
                "session_id": session.session_id,
                "turn_count": len(session.turns),
            },
        )

        # 1. Run all signal extractors
        signal_results = self._run_signals(request, session)

        # 2. Apply benign-anchor suppression (all signals, guarded by dangerous keywords)
        signal_results = self._apply_fp_suppression(signal_results, request)

        # 3. Build TurnScore from signal results
        current_turn = self._build_turn_score(signal_results)

        # 4. Build turn history from session MTM fields
        turn_history = self._build_turn_history(session, current_turn)

        # 5. Check benign floor
        benign_floor = check_benign_floor(turn_history, self._config)

        # 6. Aggregate
        aggregation = aggregate_session_risk(
            turn_scores=turn_history,
            current_turn=current_turn,
            config=self._config,
            benign_floor_active=benign_floor,
        )

        # 7. Apply success forgiveness to persistence count
        #    Re-aggregate with adjusted persistence if forgiveness changed it
        adjusted_persistence = apply_success_forgiveness(
            persistence_count=aggregation.persistence_count,
            session=session,
        )

        if adjusted_persistence != aggregation.persistence_count:
            aggregation = aggregate_session_risk(
                turn_scores=turn_history,
                current_turn=current_turn,
                config=self._config,
                benign_floor_active=benign_floor,
                persistence_override=adjusted_persistence,
            )

        # 8. Update session MTM fields
        if current_turn.score > session.mtm_peak_score:
            session.mtm_peak_score = current_turn.score

        # 9. Build result
        rule_scores = {
            name: result.score
            for name, result in signal_results.items()
            if result.score > 0.0
        }
        warnings = []
        for result in signal_results.values():
            warnings.extend(result.details)

        result = AnalysisResult(
            action=aggregation.action,
            total_score=aggregation.total,
            rule_scores=rule_scores,
            warnings=warnings,
            mtm_turn_score=current_turn.score,
            mtm_turn_categories=sorted(current_turn.categories),
        )

        logger.info(
            "monitor._analyze_subsequent_turn: result",
            extra={
                "event": "conversation.monitor.analysis",
                "session_id": session.session_id,
                "turn": len(session.turns),
                "action": result.action,
                "total_score": result.total_score,
                "rule_count": len(rule_scores),
                "peak": aggregation.peak,
                "persistence_ratio": aggregation.persistence_ratio,
                "diversity_count": aggregation.diversity_count,
                "benign_floor": benign_floor,
            },
        )

        # Emit audit events (fire-and-forget)
        self._emit_audit(session, request, current_turn, aggregation)

        return result

    def _run_signals(
        self,
        request: str,
        session: Session,
    ) -> dict[str, SignalResult]:
        """Run all registered signal extractors against the current request.

        Returns:
            Mapping of signal name to its result.
        """
        results: dict[str, SignalResult] = {}

        for name, extractor in SIGNAL_REGISTRY:
            weight = self._get_signal_weight(name)
            if weight == 0.0:
                logger.debug(
                    "monitor._run_signals: signal disabled",
                    extra={
                        "event": "conversation.monitor.signal_disabled",
                        "signal": name,
                    },
                )
                continue

            result = extractor(request, session, self._config)

            # Apply weight
            if weight != _DEFAULT_SIGNAL_WEIGHT and result.score > 0.0:
                result = SignalResult(
                    score=result.score * weight,
                    categories=result.categories,
                    details=result.details,
                )

            results[name] = result

        logger.debug(
            "monitor._run_signals: complete",
            extra={
                "event": "conversation.monitor.signals_complete",
                "signal_count": len(results),
                "non_zero": sum(1 for r in results.values() if r.score > 0.0),
            },
        )

        return results

    def _apply_fp_suppression(
        self,
        signal_results: dict[str, SignalResult],
        request: str,
    ) -> dict[str, SignalResult]:
        """Apply FP management to signal results.

        Applies benign-anchor suppression to ALL signals with non-zero
        scores. Phase 8 benchmark replay showed that restricting
        suppression to only "escalation" category signals allowed
        topic_shift and sensitive_topic to cause FPs on genuine learning
        sessions. The dangerous-keyword guard in apply_benign_anchor_suppression
        prevents suppression on actually dangerous requests.
        """
        suppressed = {}
        for name, result in signal_results.items():
            if result.score > 0.0:
                suppressed[name] = apply_benign_anchor_suppression(
                    result, request, self._config
                )
            else:
                suppressed[name] = result
        return suppressed

    def _build_turn_score(
        self,
        signal_results: dict[str, SignalResult],
    ) -> TurnScore:
        """Combine individual signal results into a single TurnScore."""
        total = sum(r.score for r in signal_results.values())
        categories: set[str] = set()
        for r in signal_results.values():
            if r.score > 0.0:
                categories.update(r.categories)

        return TurnScore(
            score=total,
            categories=frozenset(categories),
            signal_details={
                name: r for name, r in signal_results.items() if r.score > 0.0
            },
        )

    def _build_turn_history(
        self,
        session: Session,
        current_turn: TurnScore,
    ) -> list[TurnScore]:
        """Reconstruct turn history from session MTM fields.

        Previous turns store their MTM score and categories on the
        ConversationTurn dataclass. We reconstruct TurnScore objects
        from those stored values.
        """
        history: list[TurnScore] = []
        for turn in session.turns:
            history.append(
                TurnScore(
                    score=turn.mtm_turn_score,
                    categories=frozenset(turn.mtm_signal_categories),
                    signal_details={},  # Not stored per-turn
                )
            )
        # Append current turn
        history.append(current_turn)
        return history

    def _get_signal_weight(self, signal_name: str) -> float:
        """Get the weight for a signal, defaulting to 1.0."""
        return self._config.signal_weights.get(signal_name, _DEFAULT_SIGNAL_WEIGHT)

    def _emit_audit(
        self,
        session: Session,
        request: str,
        turn_score: TurnScore,
        aggregation: AggregationResult,
    ) -> None:
        """Emit per-turn audit event and summary on block.

        Fire-and-forget — exceptions are caught and logged, never
        raised to the caller. The security decision is never blocked
        by audit failures.
        """
        if self._audit_emitter is None:
            logger.debug(
                "monitor._emit_audit: no emitter configured",
                extra={"event": "conversation.monitor.audit_skipped"},
            )
            return

        try:
            turn_event = build_turn_audit_event(
                session_id=session.session_id,
                turn_index=len(session.turns),
                request=request,
                turn_score=turn_score,
                aggregation=aggregation,
                config=self._config,
            )
            # Collect coroutine for async flush — emit() is async,
            # analyze() is sync. Caller awaits flush_audit() after analyze().
            coro = self._audit_emitter.emit(turn_event)
            self._pending_audit_coros.append(coro)
        except Exception:
            # Warning (not debug) — audit emit failure is unexpected and
            # should be visible in production logs, unlike intake.py which
            # uses debug. Deliberate divergence: MTM audit is new and we
            # want visibility during rollout.
            logger.warning(
                "monitor._emit_audit: turn event emit failed",
                extra={
                    "event": "conversation.monitor.audit_emit_failed",
                    "error_category": "audit_emit",
                    "session_id": session.session_id,
                    "event_type": "conversation.mtm_turn",
                },
                exc_info=True,
            )

        # Emit session summary on block
        if aggregation.action == "block":
            try:
                summary_event = build_session_summary_event(
                    session=session,
                    final_action=aggregation.action,
                    aggregation=aggregation,
                )
                coro = self._audit_emitter.emit(summary_event)
                self._pending_audit_coros.append(coro)
            except Exception:
                logger.warning(
                    "monitor._emit_audit: summary event emit failed",
                    extra={
                        "event": "conversation.monitor.audit_summary_failed",
                        "error_category": "audit_emit",
                        "session_id": session.session_id,
                        "event_type": "conversation.mtm_summary",
                    },
                    exc_info=True,
                )

    async def flush_audit(self) -> None:
        """Await pending audit coroutines collected by _emit_audit.

        Called by the async intake layer after analyze() returns.
        Fire-and-forget — exceptions are caught per-coroutine, never
        raised to the caller.
        """
        if not self._pending_audit_coros:
            return
        coros = self._pending_audit_coros
        self._pending_audit_coros = []
        for coro in coros:
            try:
                await coro
            except Exception:
                logger.warning(
                    "monitor.flush_audit: coroutine failed",
                    extra={
                        "event": "conversation.monitor.flush_audit_failed",
                        "error_category": "audit_emit",
                    },
                    exc_info=True,
                )
