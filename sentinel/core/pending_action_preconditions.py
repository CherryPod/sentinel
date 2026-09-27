"""Shared precondition recheck helper for approval / confirmation submit paths.

Q10.fix.b / Q10.fix.c (hardening pass, fail-closed invariant).

Both :class:`~sentinel.core.approval.ApprovalManager` and
:class:`~sentinel.core.confirmation.ConfirmationGate` accept decisions that
execute previously-issued actions. Issuance-time preconditions (session not
locked, risk within band) are NOT automatically re-checked at submit-time.
If an abuse signal between issuance and submit causes
``SessionStore.lock_session(...)`` to set ``is_locked=True``, the pending
action can still be submitted and executed.

This helper encapsulates the recheck so approval and confirmation use
identical semantics. It is DI'd into both managers and queried inside the
submit path BEFORE the status-flip / SQL UPDATE.

Contract
--------

Decision table (see Q10 design §8, Q10.fix.b.review R2 extension):

    session resolved + is_locked=True   -> BLOCK (allow=False, reason=session_locked)
    session resolved + is_locked=False  -> ALLOW (reason=session_unlocked)
    session missing (evicted / not yet
    created / in_memory stub)           -> ALLOW, session_state_unavailable=True
                                           (D7: permissive + audit flag)
    session_store=None (DI not wired)   -> ALLOW, session_state_unavailable=True
                                           (test / backward-compat path)
    session_store.get() raised          -> BLOCK (allow=False,
                                           reason=session_store_error)
                                           — Q10 invariant: fail-closed on
                                           exception. Caller emits outcome=ERROR
                                           (not BLOCKED): infrastructure failure,
                                           policy was not evaluated. D7 does
                                           NOT apply — "session missing" is a
                                           clean answer from the store;
                                           "store raised" is unknown state.

Lookup key
~~~~~~~~~~

The helper looks up the session by the issuance ``source_key`` stored on
the approval / confirmation row (NOT by the caller-presented ``source_key``
argument, which is used for transport-session binding — Q3.fix.b). The
``source_key == session_id`` invariant at the binding sites
(``planner/intake.py``, ``_approval_gate.py``, ``fast_path.py``) means the
issuance source_key is the session id.

Risk ratchet
~~~~~~~~~~~~

Per design D2, risk-band is NOT rechecked. Session objects persist
``cumulative_risk`` but not a ratcheted "band" that would flip at submit
time. Adding one would require schema change + test-flake risk. Lock-state
(``is_locked``) is the enforcement signal.

Residual race (accepted)
~~~~~~~~~~~~~~~~~~~~~~~~

There is a microsecond race between this recheck's ``SessionStore.get()``
and the downstream status-flip: ``conversation_gate._handle_block`` can
begin its ``lock_session`` write AFTER ``get()`` returns ``is_locked=False``
but BEFORE the submit's UPDATE commits. Peer-consulted with Codex — Option 1
(accept + document) adopted. Mitigations: (a) same-principal race is low
severity (lock is driven by abuse signals on the same principal); (b) the
executing plan step still traverses the security pipeline which re-reads
session risk at each step; (c) upgrade path is a cross-path
``pg_advisory_xact_lock`` — documented as future hardening, not required
here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreconditionResult:
    """Outcome of a pending-action precondition recheck.

    ``allow=False`` means the submit MUST be rejected. The caller emits a
    ``*.submit_blocked_session_locked`` event and returns a generic failure
    to the caller (same shape as not-found, to avoid leaking whether the
    action existed).

    ``allow=True`` with ``session_state_unavailable=True`` means the submit
    proceeds but the caller MUST emit a ``*.session_state_unavailable``
    audit tag (WARNED outcome) so operators can see the permissive
    fall-through.
    """

    allow: bool
    reason: str
    session_state_unavailable: bool = False


async def recheck_pending_action(
    *,
    session_store: Any | None,
    issuance_source_key: str,
    user_id: int,
    conn: Any | None = None,
) -> PreconditionResult:
    """Re-check enforcement preconditions at submit-time.

    Uses the row-stored issuance source_key to resolve the session via
    :meth:`SessionStore.get`. On None (session missing / evicted / in_memory
    stub) returns ``allow=True`` + ``session_state_unavailable=True`` per
    design D7 (permissive + audit flag). On resolved session with
    ``is_locked=True`` returns ``allow=False`` so the caller fails closed.

    ``session_store=None`` is the test/backward-compat path: managers built
    without a session_store (legacy tests) see the permissive-unavailable
    branch. Production DI must wire a real store; see Q10 design D5 + F6
    DI-wiring assertion test.
    """
    logger.debug(
        "recheck_pending_action called",
        extra={"event": "core.pending_action_preconditions.recheck_pending_action"},
    )  # auto:entry
    if session_store is None:
        return PreconditionResult(
            allow=True,
            reason="session_store_not_wired",
            session_state_unavailable=True,
        )

    try:
        session = await session_store.get(issuance_source_key, user_id=user_id, conn=conn)
    except Exception:
        # Q10 invariant (findings doc §Invariant, line 41): fail CLOSED on
        # exception. Infrastructure failure (PG pool exhaustion, asyncpg
        # timeout, connection drop, etc.) means we could not evaluate the
        # policy — we must refuse rather than gate on ignorance. D7's
        # permissive-on-session-missing branch does NOT apply here: a
        # `session is None` return is a clean answer from the store;
        # `session_store.get()` raising is unknown world state. The caller
        # emits outcome=ERROR (not BLOCKED) so operators can distinguish
        # "user hit a policy" from "infrastructure couldn't evaluate one."
        # Q10.fix.b.review R2 (Codex thread 019dc06f) — demonstrable:
        # without this wrap, the exception propagated past the bool-
        # returning submit_approval contract.
        logger.warning(
            "session_store.get failed during precondition recheck — fail-closed",
            extra={
                "event": "core.pending_action_preconditions.session_store_error",
                "error_category": "session_store_get_exception",
            },
            exc_info=True,
        )
        return PreconditionResult(
            allow=False,
            reason="session_store_error",
        )

    if session is None:
        return PreconditionResult(
            allow=True,
            reason="session_missing",
            session_state_unavailable=True,
        )

    if session.is_locked:
        return PreconditionResult(
            allow=False,
            reason="session_locked",
        )

    return PreconditionResult(allow=True, reason="session_unlocked")
