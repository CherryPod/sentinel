"""Intake pipeline stage — session binding, conversation analysis, contact resolution.

Extracts the session acquisition, locked-session rejection, and multi-turn
attack detection logic from the orchestrator. Security-critical: the
`input_pre_scanned` field controls whether S1 (input scan) is skipped
downstream, and `analyze_conversation` enforces session lock-on-block.

Contact resolution (resolve_contacts) runs AFTER the S1 input scan —
the security scan must see the raw message with real names first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinel.core.models import ConversationInfo, TaskResult
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.security.pipeline import ScanPipeline
from sentinel.session.store import ConversationTurn, Session, SessionStore

if TYPE_CHECKING:
    from sentinel.contacts.store import ContactStore

logger = logging.getLogger("sentinel.audit")


@dataclass
class IntakeResult:
    """Result of the session-binding intake stage."""

    session: Session | None = None
    conv_info: ConversationInfo | None = None
    blocked: bool = False
    task_result: TaskResult | None = None  # set when blocked
    # Security-critical: when True, the orchestrator MUST skip input scanning
    # because the router already scanned. When False, S1 scan is mandatory.
    input_pre_scanned: bool = False


async def bind_session(
    source_key: str | None,
    source: str,
    session_store: SessionStore | None,
    pre_scanned_session: Session | None,
) -> IntakeResult:
    """Acquire or create a session. Reject if locked.

    Handles both the standard path (get_or_create from store) and the
    pre-scanned path (router already bound the session and scanned input).

    Returns IntakeResult with `input_pre_scanned=True` when a pre-scanned
    session was provided, signalling the orchestrator to skip S1 input scan.
    """
    session: Session | None = None
    input_pre_scanned = pre_scanned_session is not None

    if pre_scanned_session is not None:
        session = pre_scanned_session
    elif session_store is not None:
        try:
            session = await session_store.get_or_create(source_key, source=source)
        except Exception as exc:
            logger.error(
                "Database error during session lookup",
                extra={
                    "event": "db_error",
                    "source_key": source_key,
                    "source": source,
                    "error": str(exc),
                },
            )
            return IntakeResult(
                blocked=True,
                task_result=TaskResult(
                    status="error",
                    reason="Service temporarily unavailable",
                ),
                input_pre_scanned=input_pre_scanned,
            )

    # Locked sessions get immediate rejection
    if session is not None and session.is_locked:
        conv_info = ConversationInfo(
            session_id=session.session_id,
            turn_number=len(session.turns),
            risk_score=session.cumulative_risk,
            action="block",
            warnings=["Session is locked due to accumulated violations"],
        )
        return IntakeResult(
            session=session,
            conv_info=conv_info,
            blocked=True,
            task_result=TaskResult(
                status="blocked",
                reason="Session locked — too many security violations",
                conversation=conv_info,
            ),
            input_pre_scanned=input_pre_scanned,
        )

    return IntakeResult(
        session=session,
        input_pre_scanned=input_pre_scanned,
    )


async def analyze_conversation(
    user_request: str,
    session: Session,
    conversation_analyzer: ConversationAnalyzer | None,
    session_store: SessionStore | None,
) -> IntakeResult:
    """Run multi-turn attack detection. Block/warn/allow.

    Updates session risk score and lock state. When the analyzer says
    "block", the session is locked and a blocked turn is recorded.
    For "warn", cumulative risk is ratcheted upward (SYS-4/RACE-3).

    Returns IntakeResult with conv_info populated. If blocked,
    `blocked=True` and `task_result` is set.
    """
    if conversation_analyzer is None:
        return IntakeResult(session=session)

    try:
        analysis = conversation_analyzer.analyze(session, user_request)
        # Persist fix-cycle forgiveness (Finding #11: moved out of analyzer)
        if analysis.new_success_forgives is not None:
            session.success_forgives_used = analysis.new_success_forgives
        conv_info = ConversationInfo(
            session_id=session.session_id,
            turn_number=len(session.turns),
            risk_score=analysis.total_score,
            action=analysis.action,
            warnings=analysis.warnings,
        )

        if analysis.action == "block":
            session.cumulative_risk = analysis.total_score
            if session_store is not None:
                await session_store.accumulate_risk(
                    session.session_id, analysis.total_score,
                )
            session.lock()
            if session_store is not None:
                await session_store.lock_session(session.session_id)
            turn = ConversationTurn(
                request_text=user_request,
                result_status="blocked",
                blocked_by=["conversation_analyzer"],
                risk_score=analysis.total_score,
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

        # For "warn", continue processing but include warnings
        # SYS-4/RACE-3: Atomic DB update — ratchets upward only
        if analysis.total_score > session.cumulative_risk:
            session.cumulative_risk = analysis.total_score
            if session_store is not None:
                await session_store.accumulate_risk(
                    session.session_id, analysis.total_score,
                )

        return IntakeResult(session=session, conv_info=conv_info)

    except Exception as exc:
        logger.error(
            "Conversation analysis failed",
            extra={
                "event": "conv_analysis_error",
                "session_id": session.session_id,
                "error": str(exc),
            },
        )
        return IntakeResult(
            blocked=True,
            task_result=TaskResult(
                status="error",
                reason="Service temporarily unavailable",
            ),
        )


@dataclass
class InputScanResult:
    """Result of the S1 input scan stage."""

    blocked: bool = False
    task_result: TaskResult | None = None  # set when blocked


async def scan_input(
    user_request: str,
    pipeline: ScanPipeline,
    session: Session | None,
    session_store: SessionStore | None,
    conv_info: ConversationInfo | None,
) -> InputScanResult:
    """Scan user input through the security pipeline. Enforces S1.

    Records a blocked turn on the session if the scan fails.
    Returns InputScanResult — caller checks `.blocked` before proceeding.
    """
    try:
        result = await pipeline.scan_input(user_request)
        if not result.is_clean:
            # Build specific block reason with scanner names and matched patterns
            violation_details = []
            for scanner_name, sr in result.violations.items():
                patterns = [m.pattern_name for m in sr.matches]
                violation_details.append(f"{scanner_name}: {', '.join(patterns)}")
            specific_reason = "Input blocked — " + "; ".join(violation_details)

            logger.warning(
                "Task input blocked by scan",
                extra={
                    "event": "task_input_blocked",
                    "violations": list(result.violations.keys()),
                    "detail": specific_reason,
                },
            )
            if session is not None:
                turn = ConversationTurn(
                    request_text=user_request,
                    result_status="blocked",
                    blocked_by=list(result.violations.keys()),
                    risk_score=conv_info.risk_score if conv_info else 0.0,
                )
                session.add_turn(turn)
                if session_store is not None:
                    await session_store.add_turn(
                        session.session_id, turn, session=session,
                    )
            return InputScanResult(
                blocked=True,
                task_result=TaskResult(
                    status="blocked",
                    reason=specific_reason,
                    conversation=conv_info,
                ),
            )
        return InputScanResult()
    except Exception as exc:
        logger.error(
            "Input scan failed",
            extra={"event": "input_scan_error", "error": str(exc)},
        )
        return InputScanResult(
            blocked=True,
            task_result=TaskResult(
                status="error",
                reason="Request processing failed",
                conversation=conv_info,
            ),
        )


# ── Contact resolution ────────────────────────────────────────────


@dataclass
class ContactResolutionResult:
    """Result of sender resolution and message rewriting."""

    user_id: int = 1
    rewritten_text: str = ""
    audit_log: list[dict] = field(default_factory=list)
    rejected: bool = False
    error: str | None = None


# Channels that require sender registration — unknown senders are rejected.
# Non-messaging sources (api, websocket, webhook) default to user_id=1.
_MESSAGING_CHANNELS = frozenset({"signal", "telegram", "email"})


def _parse_source_key(source_key: str | None) -> tuple[str | None, str | None]:
    """Extract (channel, identifier) from a source_key like 'signal:uuid'.

    Returns (None, None) for API/web requests or malformed keys.
    """
    if not source_key or ":" not in source_key:
        return None, None
    channel, _, identifier = source_key.partition(":")
    if not channel or not identifier:
        return None, None
    return channel, identifier


async def resolve_contacts(
    contact_store: "ContactStore | None",
    source_key: str | None,
    user_request: str,
) -> ContactResolutionResult:
    """Resolve sender identity and rewrite contact names to opaque IDs.

    Must run AFTER S1 input scan — the scanner needs the raw message.

    Two structurally separate code paths (F15 — no shared fallthrough):

    - **Messaging channel** (signal, telegram, email): resolve sender via
      contact store. Unknown sender → rejected (fail-closed). Never defaults
      to user 1.
    - **Non-messaging source** (api, websocket, webhook, None): default to
      user_id=1. This is where multi-user auth will plug in.

    Gracefully handles: no store, no source_key (API), empty text.
    """
    if contact_store is None or not user_request:
        return ContactResolutionResult(
            user_id=1,
            rewritten_text=user_request,
        )

    from sentinel.contacts.resolver import resolve_sender, rewrite_message

    # Step 1: Parse source_key into channel + identifier
    channel, identifier = _parse_source_key(source_key)

    # Step 2: Sender resolution — structurally separate paths
    if channel in _MESSAGING_CHANNELS and identifier is not None:
        # MESSAGING CHANNEL — must resolve or reject (fail-closed)
        try:
            resolved = await resolve_sender(contact_store, channel, identifier)
            if resolved is not None:
                user_id = resolved
            else:
                truncated = (
                    identifier[:8] + "..." if len(identifier) > 8 else identifier
                )
                logger.warning(
                    "Unknown channel sender — rejecting request",
                    extra={
                        "event": "unknown_sender_rejected",
                        "channel": channel,
                        "identifier": truncated,
                    },
                )
                return ContactResolutionResult(
                    user_id=0,
                    rewritten_text=user_request,
                    rejected=True,
                    error="Sender not registered in contacts",
                )
        except Exception as exc:
            logger.error(
                "Sender resolution failed — rejecting request",
                extra={
                    "event": "sender_resolution_error",
                    "channel": channel,
                    "error": str(exc),
                },
            )
            return ContactResolutionResult(
                user_id=0,
                rewritten_text=user_request,
                rejected=True,
                error=f"Sender resolution failed: {exc}",
            )
    else:
        # NON-MESSAGING SOURCE (api, websocket, webhook, None, etc.)
        # Read user identity from the ContextVar set by JWTMiddleware (HTTP) or by the
        # WebSocket / webhook handlers. If no auth context is present (user_id == 0),
        # reject loudly — this should never happen once auth is wired end-to-end.
        from sentinel.core.context import current_user_id
        user_id = current_user_id.get()
        if user_id == 0:
            logger.error(
                "No user context for non-messaging request — rejecting",
                extra={"event": "missing_user_context", "source_key": source_key},
            )
            return ContactResolutionResult(
                user_id=0,
                rewritten_text=user_request,
                rejected=True,
                error="Authentication required",
            )
        logger.debug(
            "Non-messaging request — user_id from context",
            extra={"event": "api_user_from_context", "source_key": source_key, "user_id": user_id},
        )

    # Step 3-4: Message rewriting (only reached for resolved/default users)
    try:
        rewritten_text, audit_log = await rewrite_message(
            contact_store, user_request, user_id,
        )
    except Exception as exc:
        logger.error(
            "Message rewriting failed — using original text",
            extra={"event": "rewrite_error", "error": str(exc)},
        )
        rewritten_text = user_request
        audit_log = []

    return ContactResolutionResult(
        user_id=user_id,
        rewritten_text=rewritten_text,
        audit_log=audit_log,
    )
