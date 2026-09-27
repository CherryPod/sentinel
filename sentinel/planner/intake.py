"""Intake pipeline stage — session binding.

Acquires or creates the session and rejects locked sessions. The remaining
intake responsibilities (conversation analysis and input scanning / contact
resolution) have been extracted to focused modules:

- conversation_gate.py — multi-turn attack detection and audit
- input_scan.py — S1 input scanning and contact resolution

All public symbols are re-exported below so existing import paths
(``from sentinel.planner.intake import ...``) continue to work.
"""

from __future__ import annotations

import logging

from sentinel.core.context import PrincipalRequiredError
from sentinel.core.models import ConversationInfo, TaskResult
from sentinel.crypto.blind_index import log_hash
from sentinel.planner._intake_types import IntakeResult  # noqa: F401
from sentinel.session.store import Session, SessionStore

logger = logging.getLogger(__name__)


async def bind_session(
    source_key: str | None,
    source: str,
    session_store: SessionStore | None,
    input_pre_scanned: bool = False,
) -> IntakeResult:
    """Acquire or create a session inside the per-session lock. Reject if locked.

    D42 (FL-C79-a2): replaced the previous ``pre_scanned_session`` carrier
    with a boolean ``input_pre_scanned`` signal. Earlier the router pre-loaded
    the ``Session`` object before any per-session-lock acquire and threaded
    the snapshot here as ``pre_scanned_session``; downstream writes
    (``add_turn``, ``set_task_in_progress``) then washed concurrent
    intra-lock counter bumps because the snapshot was stale by the time the
    orchestrator finally took the lock. Now ``bind_session`` always calls
    ``session_store.get_or_create`` from inside the orchestrator's locked
    region. ``input_pre_scanned`` carries forward only the scalar signal
    that the router already ran S1 input scan, so the orchestrator can
    skip the duplicate scan without smuggling in a stale session reference.
    """
    logger.debug(
        "bind_session called",
        extra={
            "event": "bind.session",
            "source_channel": source_key.split(":", 1)[0]
            if source_key and ":" in source_key
            else None,
            "source_key_hash": log_hash(source_key),
            "source_key_len": len(source_key or ""),
            "source": source,
            "input_pre_scanned": input_pre_scanned,
        },
    )
    session: Session | None = None

    if session_store is not None:
        logger.debug(
            "bind_session using get_or_create from store",
            extra={
                "event": "bind.session_path",
                "acquisition": "get_or_create",
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
            },
        )
        try:
            session = await session_store.get_or_create(source_key, source=source)
        except PrincipalRequiredError:
            # Q4: zero-principal must propagate to caller (auth/middleware bug).
            # Do NOT misclassify as a transient DB error.
            raise
        except Exception as exc:
            logger.error(
                "Database error during session lookup",
                extra={
                    "event": "db.error",
                    "source_channel": source_key.split(":", 1)[0]
                    if source_key and ":" in source_key
                    else None,
                    "source_key_hash": log_hash(source_key),
                    "source_key_len": len(source_key or ""),
                    "source": source,
                    "error": str(exc),
                },
                exc_info=True,
            )
            return IntakeResult(
                blocked=True,
                task_result=TaskResult(
                    status="error",
                    reason="Service temporarily unavailable",
                ),
                input_pre_scanned=input_pre_scanned,
            )
    else:
        logger.debug(
            "bind_session — no store available, session will be None",
            extra={
                "event": "bind.session_path",
                "acquisition": "no_store",
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
            },
        )

    # Locked sessions get immediate rejection
    if session is not None and session.is_locked:
        logger.info(
            "bind_session rejected — session is locked",
            extra={
                "event": "bind.session_locked",
                "session_id": session.session_id,
                "cumulative_risk": session.cumulative_risk,
            },
        )
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

    logger.debug(
        "bind_session completed",
        extra={
            "event": "bind.session_exit",
            "has_session": session is not None,
            "session_id": session.session_id if session else None,
            "input_pre_scanned": input_pre_scanned,
        },
    )
    return IntakeResult(
        session=session,
        input_pre_scanned=input_pre_scanned,
    )


# Re-exports — preserve all existing import paths.
# External code imports from sentinel.planner.intake; these ensure
# nothing breaks. Do not remove without checking import sites.
from sentinel.planner.conversation_gate import (  # noqa: F401, E402
    _emit_conversation_audit,
    analyze_conversation,
)
from sentinel.planner.input_scan import (  # noqa: F401, E402
    ContactResolutionResult,
    InputScanResult,
    _parse_source_key,
    resolve_contacts,
    scan_input,
)
