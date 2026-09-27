"""Input scanning and contact resolution — S1 pipeline stage.

Extracted from intake.py. Runs the security scan pipeline on user input
and resolves sender identity for messaging channels. Security-critical:
scan_input enforces S1 (input scan must pass before planner sees the message),
and resolve_contacts enforces fail-closed sender verification on messaging
channels.

Contact resolution runs AFTER the S1 input scan — the security scan must
see the raw message with real names first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinel.core.models import ConversationInfo, TaskResult
from sentinel.crypto.blind_index import log_hash
from sentinel.session.store import ConversationTurn, Session, SessionStore

if TYPE_CHECKING:
    from sentinel.contacts.store import ContactStore
    from sentinel.security.pipeline import ScanPipeline

logger = logging.getLogger(__name__)


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
    logger.debug(
        "scan_input called",
        extra={
            "event": "scan.input",
            "request_len": len(user_request),
            "has_session": session is not None,
        },
    )
    try:
        result = await pipeline.scan_input(user_request)
        if not result.is_clean:
            # Build specific block reason with scanner names and matched patterns
            violation_details = []
            for scanner_name, verdicts in result.unsuppressed_by_scanner().items():
                patterns = [v.match.rule_id for v in verdicts]
                violation_details.append(f"{scanner_name}: {', '.join(patterns)}")
            specific_reason = "Input blocked — " + "; ".join(violation_details)

            violated = list(result.violated_scanners())
            logger.warning(
                "Task input blocked by scan",
                extra={
                    "event": "task.input_blocked",
                    "violations": violated,
                    "detail": specific_reason,
                },
            )
            if session is not None:
                turn = ConversationTurn(
                    request_text=user_request,
                    result_status="blocked",
                    blocked_by=violated,
                    risk_score=conv_info.risk_score if conv_info else 0.0,
                    mtm_turn_score=conv_info.mtm_turn_score if conv_info else 0.0,
                    mtm_signal_categories=conv_info.mtm_turn_categories if conv_info else [],
                )
                session.add_turn(turn)
                if session_store is not None:
                    await session_store.add_turn(
                        session.session_id,
                        turn,
                        session=session,
                    )
            return InputScanResult(
                blocked=True,
                task_result=TaskResult(
                    status="blocked",
                    reason=specific_reason,
                    conversation=conv_info,
                ),
            )
        logger.debug(
            "scan_input passed — input is clean",
            extra={
                "event": "scan.input_clean",
                "request_len": len(user_request),
            },
        )
        return InputScanResult()
    except Exception as exc:
        logger.error(
            "Input scan failed",
            extra={"event": "input.scan_error", "error": str(exc)},
            exc_info=True,
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
    """Extract (channel, identifier) from a source_key.

    Returns (None, None) for API/web requests or malformed keys.

    For messaging channels (``_MESSAGING_CHANNELS``) the identifier is the
    first colon-separated segment after the channel prefix; any further
    segments are treated as session-binding metadata and ignored here.
    This supports the Q3-F9a Telegram shape
    ``telegram:{chat_id}:{sender_user_id}`` while keeping identifier
    matching against the contact store stable (stored identifiers are
    always the bare principal — phone / chat_id / email).

    Telegram carve-out (Q4-F20): for Telegram the *second* segment
    (``sender_user_id``) is the contact principal, not the first
    (``chat_id``). In a 1:1 chat the two segments are identical so the
    change is a no-op; in a group chat the second segment is the real
    sender. This preserves the ``get_source_key`` ordering (see
    ``telegram_channel.py``) which is load-bearing for in-flight
    approval / confirmation / session state.

    For non-messaging channels the full remainder is preserved so IPv6
    literals in ``api:::1`` still parse as ``("api", "::1")``.
    """
    if not source_key or ":" not in source_key:
        logger.debug(
            "_parse_source_key — no parseable key",
            extra={
                "event": "parse.source_key_none",
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
            },
        )
        return None, None
    logger.debug(
        "_parse_source_key: not_source_key_passed",
        extra={
            "event": "parse.source_key_none.passed",
            "reason": "not_source_key_passed",
        },
    )  # auto:neg
    channel, _, rest = source_key.partition(":")
    if not channel or not rest:
        logger.debug(
            "_parse_source_key — malformed key",
            extra={
                "event": "parse.source_key_none",
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
            },
        )
        return None, None
    if channel in _MESSAGING_CHANNELS:
        identifier, _, session = rest.partition(":")
        # Q4-F20: Telegram stores sender_user_id as the second segment;
        # chat_id is the first. Contact-store lookup must key on the
        # sender, not the chat, so group-chat members don't collapse
        # onto a single enrolled user. Single-segment keys (no session)
        # fall through unchanged. Keys with an empty first segment
        # (e.g. ``telegram::X``) are still rejected as malformed — the
        # live producer (``telegram_channel.py``) always emits a
        # non-empty chat_id, so an empty first segment can only arise
        # from malformed fixtures or tampered input.
        if channel == "telegram" and session and identifier:
            logger.debug(
                "_parse_source_key: channel_eq_telegram",
                extra={
                    "event": "planner.input_scan._parse_source_key.match",
                    "reason": "channel_eq_telegram",
                },
            )  # auto:neg
            identifier = session
        if not identifier:
            logger.debug(
                "_parse_source_key — messaging key missing principal",
                extra={
                    "event": "parse.source_key_none",
                    "source_channel": source_key.split(":", 1)[0]
                    if source_key and ":" in source_key
                    else None,
                    "source_key_hash": log_hash(source_key),
                    "source_key_len": len(source_key or ""),
                },
            )
            return None, None
    else:
        logger.debug(
            "_parse_source_key: channel_in_MESSAGING_CHANNELS",
            extra={
                "event": "planner.input_scan._parse_source_key.clean",
                "reason": "channel_in_MESSAGING_CHANNELS",
            },
        )  # auto:neg
        identifier = rest
    logger.debug(
        "_parse_source_key parsed",
        extra={
            "event": "parse.source_key_ok",
            "channel": channel,
            "has_identifier": bool(identifier),
        },
    )
    return channel, identifier


async def resolve_contacts(
    contact_store: ContactStore | None,
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
    logger.debug(
        "resolve_contacts called",
        extra={
            "event": "resolve.contacts",
            "has_store": contact_store is not None,
            "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
            "source_key_hash": log_hash(source_key),
            "source_key_len": len(source_key or ""),
        },
    )
    if contact_store is None or not user_request:
        logger.debug(
            "resolve_contacts skipped — no store or empty request",
            extra={
                "event": "resolve.contacts_skip",
                "has_store": contact_store is not None,
                "has_request": bool(user_request),
            },
        )
        return ContactResolutionResult(
            user_id=1,
            rewritten_text=user_request,
        )

    from sentinel.contacts.resolver import resolve_sender, rewrite_message

    # Step 1: Parse source_key into channel + identifier
    channel, identifier = _parse_source_key(source_key)

    # Step 2: Sender resolution — structurally separate paths
    is_messaging = channel in _MESSAGING_CHANNELS and identifier is not None
    logger.debug(
        "resolve_contacts branch decision",
        extra={
            "event": "resolve.contacts_branch",
            "channel": channel,
            "is_messaging": is_messaging,
        },
    )
    if is_messaging:
        # MESSAGING CHANNEL — must resolve or reject (fail-closed)
        try:
            resolved = await resolve_sender(contact_store, channel, identifier)
            if resolved is not None:
                user_id = resolved
            else:
                logger.warning(
                    "Unknown channel sender — rejecting request",
                    extra={
                        "event": "unknown.sender_rejected",
                        "channel": channel,
                        "identifier_len": len(identifier or ""),
                        "identifier_hash": log_hash(identifier),
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
                    "event": "sender.resolution_error",
                    "channel": channel,
                    "error": str(exc),
                },
                exc_info=True,
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
                extra={
                    "event": "missing.user_context",
                    "source_channel": source_key.split(":", 1)[0]
                    if source_key and ":" in source_key
                    else None,
                    "source_key_hash": log_hash(source_key),
                    "source_key_len": len(source_key or ""),
                },
            )
            return ContactResolutionResult(
                user_id=0,
                rewritten_text=user_request,
                rejected=True,
                error="Authentication required",
            )
        logger.debug(
            "Non-messaging request — user_id from context",
            extra={
                "event": "api.user_from_context",
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
                "user_id": user_id,
            },
        )

    # Step 3-4: Message rewriting (only reached for resolved/default users)
    try:
        rewritten_text, audit_log = await rewrite_message(
            contact_store,
            user_request,
            user_id,
        )
    except Exception as exc:
        logger.error(
            "Message rewriting failed — using original text",
            extra={"event": "rewrite.error", "error": str(exc)},
            exc_info=True,
        )
        rewritten_text = user_request
        audit_log = []

    logger.debug(
        "resolve_contacts completed",
        extra={
            "event": "resolve.contacts_exit",
            "user_id": user_id,
            "rewrite_count": len(audit_log),
        },
    )
    return ContactResolutionResult(
        user_id=user_id,
        rewritten_text=rewritten_text,
        audit_log=audit_log,
    )
