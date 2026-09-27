"""Approval queue with configurable TTL.

PostgreSQL backend with in-memory dict fallback for tests (pool=None).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.config import settings
from sentinel.core.context import current_user_id, require_user_id
from sentinel.core.models import Plan
from sentinel.core.pending_action_preconditions import recheck_pending_action
from sentinel.crypto.blind_index import log_hash

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now_utc() -> datetime:
    return datetime.now(UTC)


@dataclass
class ApprovalEntry:
    """In-memory representation of an approval row."""

    approval_id: str
    plan_json: str
    status: str
    expires_at: datetime
    source_key: str
    user_request: str
    user_id: int = 0
    decided_at: str | None = None
    decided_reason: str = ""
    decided_by: str = ""
    created_at: str = field(default_factory=_now_iso)
    mtm_turn_score: float = 0.0
    mtm_signal_categories: list[str] = field(default_factory=list)


@dataclass
class ApprovalResult:
    granted: bool
    reason: str = ""
    approved_by: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class ApprovalManager:
    """Approval queue with configurable TTL.

    Dual-mode: PostgreSQL when pool is provided, in-memory dict fallback for tests.
    """

    # Allowlist for approved_by: alphanumeric, underscores, colons, hyphens, 1-64 chars.
    # Values that don't match (e.g. injection payloads, XSS) are sanitised to "unknown".
    _APPROVED_BY_PATTERN = re.compile(r"^[a-zA-Z0-9_:\-]{1,64}$")

    def __init__(
        self,
        pool: Any = None,
        timeout: int | None = None,
        event_bus: Any = None,
        audit_emitter: Any = None,
        session_store: Any = None,
    ):
        self._pool = pool
        self._in_memory = pool is None
        self._timeout = timeout if timeout is not None else settings.approval_timeout
        self._event_bus = event_bus
        self._audit_emitter = audit_emitter
        # Q10-F2: session_store is used by submit_approval to re-check the
        # session lock state at submit-time (enforcement boundary
        # fail-closed-on-precondition-change). None is the test / backward-
        # compat path — the precondition helper returns permissive +
        # session_state_unavailable. Production DI is via
        # api/init/orchestrator.py; a DI-wiring test asserts prod-built
        # managers have _session_store is not None (Codex F6).
        self._session_store = session_store
        if self._in_memory:
            self._mem: dict[str, ApprovalEntry] = {}

    async def _cleanup_expired(self) -> list[dict]:
        """Mark entries as expired if past their expires_at time.

        NOTE: Runs under RLS when called via the application pool — only
        expires current user's approvals. This is correct for single-user.
        For multi-user admin maintenance, use the admin pool (sentinel_owner).
        """
        if self._in_memory:
            now = _now_utc()
            expired = []
            for entry in self._mem.values():
                if entry.status == "pending" and entry.expires_at < now:
                    entry.status = "expired"
                    expired.append(
                        {
                            "approval_id": entry.approval_id,
                            "source_key": entry.source_key,
                        }
                    )
            for entry in expired:
                _src_key = entry["source_key"]
                logger.warning(
                    "Approval expired",
                    extra={
                        "event": "approval.auto_expired",
                        "approval_id": entry["approval_id"],
                        "source_channel": _src_key.split(":", 1)[0]
                        if _src_key and ":" in _src_key
                        else None,
                        "source_key_hash": log_hash(_src_key),
                        "source_key_len": len(_src_key or ""),
                    },
                )
            return expired

        async with self._pool.acquire() as conn:
            # Single atomic UPDATE RETURNING — eliminates the race where
            # submit_approval could approve a row between a SELECT and a
            # subsequent UPDATE, which would then overwrite it with 'expired'.
            rows = await conn.fetch(
                "UPDATE approvals SET status = 'expired' "
                "WHERE status = 'pending' AND expires_at < NOW() "
                "RETURNING approval_id, source_key"
            )
            if not rows:
                return []

        expired = [
            {"approval_id": r["approval_id"], "source_key": r["source_key"]}
            for r in rows
        ]
        for entry in expired:
            _src_key = entry["source_key"]
            logger.warning(
                "Approval expired",
                extra={
                    "event": "approval.auto_expired",
                    "approval_id": entry["approval_id"],
                    "source_channel": _src_key.split(":", 1)[0]
                    if _src_key and ":" in _src_key
                    else None,
                    "source_key_hash": log_hash(_src_key),
                    "source_key_len": len(_src_key or ""),
                },
            )
        return expired

    async def cleanup_and_notify(self) -> list[dict]:
        """Cleanup expired entries and publish approval.expired events."""
        expired = await self._cleanup_expired()
        if self._event_bus and expired:
            for entry in expired:
                await self._event_bus.publish(
                    "approval.expired",
                    {
                        "approval_id": entry["approval_id"],
                        "source_key": entry["source_key"],
                        "reason": "Approval request timed out",
                    },
                )
        if self._audit_emitter and expired:
            for entry in expired:
                await self._audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="approval.expired",
                        source_component="approval",
                        outcome="EXPIRED",
                        details={
                            "approval_id": entry["approval_id"],
                            "source_key": entry["source_key"],
                        },
                    )
                )
        return expired

    async def request_plan_approval(
        self,
        plan: Plan,
        source_key: str = "",
        user_request: str = "",
        mtm_turn_score: float = 0.0,
        mtm_signal_categories: list[str] | None = None,
    ) -> str:
        """Create an approval request. Returns the approval_id."""
        if mtm_signal_categories is None:
            mtm_signal_categories = []
        await self._cleanup_expired()
        approval_id = str(uuid.uuid4())
        resolved_user_id = require_user_id(
            current_user_id.get(), "ApprovalManager.request_plan_approval"
        )

        if self._in_memory:
            logger.debug(
                "request_plan_approval: in_memory",
                extra={
                    "event": "approval.request_plan_approval.match",
                    "reason": "in_memory",
                },
            )  # auto:neg
            self._mem[approval_id] = ApprovalEntry(
                approval_id=approval_id,
                plan_json=plan.model_dump_json(),
                status="pending",
                expires_at=_now_utc() + timedelta(seconds=self._timeout),
                source_key=source_key,
                user_request=user_request,
                user_id=resolved_user_id,
                mtm_turn_score=mtm_turn_score,
                mtm_signal_categories=list(mtm_signal_categories),
            )
        else:
            logger.debug(
                "request_plan_approval: in_memory",
                extra={
                    "event": "approval.request_plan_approval.clean",
                    "reason": "in_memory",
                },
            )  # auto:neg
            expires_at = datetime.now(UTC) + timedelta(seconds=self._timeout)
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO approvals "
                    "(approval_id, plan_json, expires_at, source_key, user_request, user_id, "
                    "mtm_turn_score, mtm_signal_categories) "
                    "VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8::jsonb)",
                    approval_id,
                    plan.model_dump_json(),
                    expires_at,
                    source_key,
                    user_request,
                    resolved_user_id,
                    mtm_turn_score,
                    json.dumps(mtm_signal_categories),
                )

        logger.info(
            "Approval requested",
            extra={
                "event": "approval.requested",
                "approval_id": approval_id,
                "plan_summary_len": len(plan.plan_summary),
                "plan_step_count": len(plan.steps),
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
                "user_request_len": len(user_request),
                "user_request_hash": log_hash(user_request),
            },
        )

        if self._audit_emitter is not None:
            await self._audit_emitter.emit(
                SecurityAuditEvent(
                    event_type="approval.requested",
                    source_component="approval",
                    outcome="SUCCESS",
                    details={
                        "approval_id": approval_id,
                        "source_key": source_key,
                        "plan_summary": plan.plan_summary,
                    },
                )
            )

        return approval_id

    async def check_approval(self, approval_id: str) -> dict:
        """Check status of an approval request."""
        await self._cleanup_expired()
        resolved_user_id = require_user_id(
            current_user_id.get(), "ApprovalManager.check_approval"
        )

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                logger.info(
                    "Approval not found",
                    extra={"event": "approval.not_found", "approval_id": approval_id},
                )
                return {"status": "not_found"}
            status = entry.status
            plan_json = entry.plan_json
            decided_reason = entry.decided_reason
            decided_by = entry.decided_by
        else:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT status, plan_json, decided_reason, decided_by "
                    "FROM approvals WHERE approval_id = $1 AND user_id = $2",
                    approval_id,
                    resolved_user_id,
                )
                if row is None:
                    logger.info(
                        "Approval not found",
                        extra={
                            "event": "approval.not_found",
                            "approval_id": approval_id,
                        },
                    )
                    return {"status": "not_found"}

                status = row["status"]
                plan_json = row["plan_json"]
                decided_reason = row["decided_reason"]
                decided_by = row["decided_by"]

        if status == "expired":
            logger.warning(
                "Approval expired",
                extra={"event": "approval.expired", "approval_id": approval_id},
            )
            return {"status": "expired", "reason": "Approval request expired"}
        logger.debug(
            "check_approval: status_eq_expired_passed",
            extra={
                "event": "approval.expired.passed",
                "reason": "status_eq_expired_passed",
            },
        )  # auto:neg

        if status == "pending":
            if isinstance(plan_json, dict):
                plan = Plan.model_validate(plan_json)
            else:
                plan = Plan.model_validate_json(plan_json)
            return {
                "status": "pending",
                "plan_summary": plan.plan_summary,
                "steps": [
                    {
                        "id": s.id,
                        "type": s.type,
                        "description": s.description,
                        "prompt": s.prompt,
                        "tool": s.tool,
                        "args": s.args or None,
                        "expects_code": s.expects_code,
                    }
                    for s in plan.steps
                ],
            }

        if status == "approved":
            return {
                "status": "approved",
                "reason": decided_reason,
                "approved_by": decided_by,
            }

        # status == "denied"
        return {"status": "denied", "reason": decided_reason}

    async def submit_approval(
        self,
        approval_id: str,
        granted: bool,
        reason: str = "",
        approved_by: str = "api",
        source_key: str | None = None,
    ) -> bool:
        """Submit an approval decision. Returns True if accepted.

        If ``source_key`` is provided, it must match the ``source_key``
        stored with the approval at create time. This enforces Q3-F4
        reconnect-invalidation: a reconnected WebSocket (new connection_id
        → new source_key) cannot submit an approval created by a dropped
        socket even if it knows the approval_id. Pass ``source_key=None``
        (the default) for callers that do not bind to a transport session
        (internal/REST paths that don't set a transport-scoped key).
        """
        resolved_user_id = require_user_id(
            current_user_id.get(), "ApprovalManager.submit_approval"
        )

        # Sanitise approved_by — reject anything outside the allowlist pattern.
        # This prevents injection payloads, XSS strings, or overly long values
        # from being stored verbatim in the audit trail.
        if not self._APPROVED_BY_PATTERN.match(approved_by):
            logger.warning(
                "Invalid approved_by value sanitised",
                extra={
                    "event": "approval.invalid_approved_by",
                    "raw": approved_by[:64],
                },
            )
            approved_by = "unknown"

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                logger.warning(
                    "Approval submit — not found",
                    extra={
                        "event": "approval.submit_not_found",
                        "approval_id": approval_id,
                    },
                )
                return False

            if entry.expires_at < _now_utc():
                entry.status = "expired"
                logger.warning(
                    "Approval submit — expired",
                    extra={
                        "event": "approval.submit_expired",
                        "approval_id": approval_id,
                    },
                )
                return False

            if entry.status != "pending":
                logger.warning(
                    "Approval submit — duplicate",
                    extra={
                        "event": "approval.submit_duplicate",
                        "approval_id": approval_id,
                    },
                )
                return False

            # Q3-F4: transport-session binding. When caller provided a
            # source_key, it must match the one recorded at create time.
            # Closes reconnect-replay of pending approvals from a dropped
            # socket (per fix-design §7.3). Logged as a negative-path
            # security check; caller gets a generic failure (same shape
            # as not_found) so cross-session replay attempts cannot
            # distinguish "wrong connection" from "nonexistent approval".
            if source_key is not None and entry.source_key != source_key:
                logger.warning(
                    "Approval submit — source_key mismatch",
                    extra={
                        "event": "approval.submit_source_key_mismatch",
                        "approval_id": approval_id,
                    },
                )
                return False

            # Q10-F2: submit-time precondition recheck. Re-resolve the
            # session by the row's issuance source_key (== session_id
            # invariant) and fail closed if the session is now locked.
            # Permissive on session-missing per design D7; the caller
            # emits a WARNED audit tag so operators see the fall-through.
            # Q10.fix.b.review R2: fail-closed-with-ERROR on
            # session_store_error (infrastructure couldn't evaluate
            # policy; distinct from BLOCKED which means policy-said-no).
            precondition = await recheck_pending_action(
                session_store=self._session_store,
                issuance_source_key=entry.source_key,
                user_id=resolved_user_id,
            )
            if not precondition.allow:
                if precondition.reason == "session_store_error":
                    event_name = "approval.submit_blocked_session_store_error"
                    log_msg = (
                        "Approval submit — session store error (fail-closed)"
                    )
                    outcome = "ERROR"
                else:
                    event_name = "approval.submit_blocked_session_locked"
                    log_msg = "Approval submit — session locked"
                    outcome = "BLOCKED"
                logger.warning(
                    log_msg,
                    extra={
                        "event": event_name,
                        "approval_id": approval_id,
                        "reason": precondition.reason,
                    },
                )
                if self._audit_emitter is not None:
                    await self._audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type=event_name,
                            source_component="approval",
                            outcome=outcome,
                            severity="MEDIUM",
                            details={
                                "approval_id": approval_id,
                                "reason": precondition.reason,
                            },
                        )
                    )
                return False
            if precondition.session_state_unavailable:
                logger.warning(
                    "Approval submit — session state unavailable",
                    extra={
                        "event": "approval.submit_session_state_unavailable",
                        "approval_id": approval_id,
                        "reason": precondition.reason,
                    },
                )
                if self._audit_emitter is not None:
                    await self._audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="approval.submit_session_state_unavailable",
                            source_component="approval",
                            outcome="WARNED",
                            severity="MEDIUM",
                            details={
                                "approval_id": approval_id,
                                "reason": precondition.reason,
                            },
                        )
                    )

            new_status = "approved" if granted else "denied"
            entry.status = new_status
            entry.decided_at = _now_iso()
            entry.decided_reason = reason
            entry.decided_by = approved_by
        else:
            # CRIT-11: collect audit events that must emit AFTER the acquire
            # block exits so audit_emitter.emit() (which acquires from the
            # same app_pool) does not nest inside the held transaction conn.
            _pending_audit: SecurityAuditEvent | None = None
            _precondition_blocked = False
            _rows_affected_zero = False
            rows_affected = 0

            async with self._pool.acquire() as conn, conn.transaction():
                # Q10-F2: submit-time precondition recheck. Fetch the row's
                # issuance source_key (== session_id invariant) so the
                # helper can resolve the session and check is_locked.
                # Runs inside the existing transaction so the read is a
                # consistent snapshot with the subsequent UPDATE. If the
                # row does not exist the UPDATE will report 0 rows affected
                # and fall through to the existing diagnostics. Residual
                # same-principal race between this SELECT and a concurrent
                # lock_session write is accepted (see helper docstring).
                issuance_row = await conn.fetchrow(
                    "SELECT source_key, status, expires_at FROM approvals "
                    "WHERE approval_id = $1 AND user_id = $2",
                    approval_id,
                    resolved_user_id,
                )
                if (
                    issuance_row is not None
                    and issuance_row["status"] == "pending"
                    and issuance_row["expires_at"] >= datetime.now(UTC)
                    and (source_key is None or issuance_row["source_key"] == source_key)
                ):
                    # Q10.fix.b.review R2: fail-closed-with-ERROR on
                    # session_store_error (infrastructure couldn't evaluate
                    # policy; distinct from BLOCKED which means policy-
                    # said-no). See helper docstring §Decision table.
                    # CRIT-11: pass held conn so session_store.get() reuses
                    # the existing connection instead of acquiring a new one.
                    precondition = await recheck_pending_action(
                        session_store=self._session_store,
                        issuance_source_key=issuance_row["source_key"],
                        user_id=resolved_user_id,
                        conn=conn,
                    )
                    if not precondition.allow:
                        if precondition.reason == "session_store_error":
                            event_name = (
                                "approval.submit_blocked_session_store_error"
                            )
                            log_msg = (
                                "Approval submit — session store error (fail-closed)"
                            )
                            outcome = "ERROR"
                        else:
                            event_name = "approval.submit_blocked_session_locked"
                            log_msg = "Approval submit — session locked"
                            outcome = "BLOCKED"
                        logger.warning(
                            log_msg,
                            extra={
                                "event": event_name,
                                "approval_id": approval_id,
                                "reason": precondition.reason,
                            },
                        )
                        if self._audit_emitter is not None:
                            _pending_audit = SecurityAuditEvent(
                                event_type=event_name,
                                source_component="approval",
                                outcome=outcome,
                                severity="MEDIUM",
                                details={
                                    "approval_id": approval_id,
                                    "reason": precondition.reason,
                                },
                            )
                        _precondition_blocked = True
                    if not _precondition_blocked and precondition.session_state_unavailable:
                        logger.warning(
                            "Approval submit — session state unavailable",
                            extra={
                                "event": "approval.submit_session_state_unavailable",
                                "approval_id": approval_id,
                                "reason": precondition.reason,
                            },
                        )
                        if self._audit_emitter is not None:
                            _pending_audit = SecurityAuditEvent(
                                event_type="approval.submit_session_state_unavailable",
                                source_component="approval",
                                outcome="WARNED",
                                severity="MEDIUM",
                                details={
                                    "approval_id": approval_id,
                                    "reason": precondition.reason,
                                },
                            )

                if not _precondition_blocked:
                    # Atomic UPDATE — only transitions from 'pending' within expiry.
                    # Eliminates TOCTOU race: concurrent callers cannot both see
                    # status='pending' because only one UPDATE can match the WHERE.
                    # Q3-F4: when source_key is provided, include it in the WHERE
                    # so reconnected sockets (new source_key) cannot submit a
                    # pending approval created on a dropped socket.
                    new_status = "approved" if granted else "denied"
                    if source_key is not None:
                        result = await conn.execute(
                            "UPDATE approvals SET status = $1, decided_at = NOW(), "
                            "decided_reason = $2, decided_by = $3 "
                            "WHERE approval_id = $4 AND user_id = $5 "
                            "AND source_key = $6 "
                            "AND status = 'pending' AND expires_at >= NOW()",
                            new_status,
                            reason,
                            approved_by,
                            approval_id,
                            resolved_user_id,
                            source_key,
                        )
                    else:
                        result = await conn.execute(
                            "UPDATE approvals SET status = $1, decided_at = NOW(), "
                            "decided_reason = $2, decided_by = $3 "
                            "WHERE approval_id = $4 AND user_id = $5 "
                            "AND status = 'pending' AND expires_at >= NOW()",
                            new_status,
                            reason,
                            approved_by,
                            approval_id,
                            resolved_user_id,
                        )

                    rows_affected = int(result.split()[-1])
                if not _precondition_blocked and rows_affected == 0:
                    # No row matched — determine why for logging. If caller
                    # provided source_key, first check whether the approval
                    # exists but with a different source_key (Q3-F4 mismatch)
                    # — distinct from the "not found" case so the security
                    # event is logged correctly.
                    # CRIT-11: set flag instead of returning inside the acquire
                    # block so the deferred audit event is always emitted first.
                    _rows_affected_zero = True
                    _is_source_key_mismatch = False
                    if source_key is not None:
                        sk_row = await conn.fetchrow(
                            "SELECT source_key, status, expires_at "
                            "FROM approvals "
                            "WHERE approval_id = $1 AND user_id = $2",
                            approval_id,
                            resolved_user_id,
                        )
                        if (
                            sk_row is not None
                            and sk_row["source_key"] != source_key
                            and sk_row["status"] == "pending"
                            and sk_row["expires_at"] >= datetime.now(UTC)
                        ):
                            logger.warning(
                                "Approval submit — source_key mismatch",
                                extra={
                                    "event": "approval.submit_source_key_mismatch",
                                    "approval_id": approval_id,
                                },
                            )
                            _is_source_key_mismatch = True
                    if not _is_source_key_mismatch:
                        row = await conn.fetchrow(
                            "SELECT status, expires_at FROM approvals "
                            "WHERE approval_id = $1 AND user_id = $2",
                            approval_id,
                            resolved_user_id,
                        )
                        if row is None:
                            logger.warning(
                                "Approval submit — not found",
                                extra={
                                    "event": "approval.submit_not_found",
                                    "approval_id": approval_id,
                                },
                            )
                        elif row["expires_at"] < datetime.now(UTC):
                            await conn.execute(
                                "UPDATE approvals SET status = 'expired' "
                                "WHERE approval_id = $1 AND user_id = $2 "
                                "AND status = 'pending'",
                                approval_id,
                                resolved_user_id,
                            )
                            logger.warning(
                                "Approval submit — expired",
                                extra={
                                    "event": "approval.submit_expired",
                                    "approval_id": approval_id,
                                },
                            )
                        else:
                            logger.warning(
                                "Approval submit — duplicate",
                                extra={
                                    "event": "approval.submit_duplicate",
                                    "approval_id": approval_id,
                                },
                            )

                if not _precondition_blocked and not _rows_affected_zero:
                    # Audit log — same transaction as the approval UPDATE.
                    # Rolls back together if either fails.
                    decision = "approved" if granted else "denied"
                    await conn.execute(
                        "INSERT INTO audit_log (user_id, event_type, session_id, details) "
                        "VALUES ($1, $2, NULL, $3::jsonb)",
                        resolved_user_id,
                        f"approval_{decision}",
                        json.dumps({"approval_id": approval_id, "reason": reason}),
                    )

            # CRIT-11: emit deferred audit event outside the acquire block
            # so audit_emitter.emit() (which acquires from app_pool) does not
            # nest inside the held transaction conn. Always runs before any
            # False return so WARNED events are preserved on UPDATE-0-rows paths.
            if _pending_audit is not None and self._audit_emitter is not None:
                await self._audit_emitter.emit(_pending_audit)
            if _precondition_blocked or _rows_affected_zero:
                return False

        decision = "approved" if granted else "denied"
        logger.info(
            "Approval submitted",
            extra={
                "event": "approval.submitted",
                "approval_id": approval_id,
                "granted": granted,
                "reason": reason,
            },
        )

        if self._audit_emitter is not None:
            await self._audit_emitter.emit(
                SecurityAuditEvent(
                    event_type="approval.decided",
                    source_component="approval",
                    outcome="APPROVED" if granted else "DENIED",
                    details={
                        "approval_id": approval_id,
                        "reason": reason,
                        "decided_by": approved_by,
                    },
                )
            )

        return True

    async def get_plan(self, approval_id: str) -> Plan | None:
        """Get the plan associated with an approval ID."""
        resolved_user_id = require_user_id(
            current_user_id.get(), "ApprovalManager.get_plan"
        )

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                return None
            return Plan.model_validate_json(entry.plan_json)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT plan_json FROM approvals WHERE approval_id = $1 AND user_id = $2",
                approval_id,
                resolved_user_id,
            )
            if row is None:
                return None
            plan_json = row["plan_json"]
            if isinstance(plan_json, dict):
                return Plan.model_validate(plan_json)
            return Plan.model_validate_json(plan_json)

    async def purge_old(self, days: int = 7, user_id: int | None = None) -> int:
        """Delete decided/expired approval entries older than N days.

        When user_id is provided, only deletes that user's entries.
        When None, deletes all users' entries (admin maintenance).
        """
        if self._in_memory:
            cutoff = _now_utc() - timedelta(days=days)
            to_delete = []
            for aid, entry in self._mem.items():
                if entry.status in ("expired", "approved", "denied"):
                    # Skip entries that don't belong to the requested user_id.
                    if user_id is not None and entry.user_id != user_id:
                        continue
                    try:
                        created = datetime.fromisoformat(entry.created_at)
                        if created < cutoff:
                            to_delete.append(aid)
                    except (ValueError, AttributeError):
                        logger.debug(
                            "Skipping entry with unparseable created_at during purge",
                            extra={
                                "event": "approval.purge_parse_skip",
                                "approval_id": aid,
                            },
                            exc_info=True,
                        )
                        continue
            for aid in to_delete:
                del self._mem[aid]
            deleted = len(to_delete)
        else:
            logger.debug(
                "purge_old: in_memory",
                extra={
                    "event": "approval.purge_parse_skip.clean",
                    "reason": "in_memory",
                },
            )  # auto:neg
            if user_id is not None:
                sql = (
                    "DELETE FROM approvals "
                    "WHERE status IN ('expired', 'approved', 'denied') "
                    "AND created_at < NOW() - INTERVAL '1 day' * $1 "
                    "AND user_id = $2"
                )
                params = (days, user_id)
            else:
                sql = (
                    "DELETE FROM approvals "
                    "WHERE status IN ('expired', 'approved', 'denied') "
                    "AND created_at < NOW() - INTERVAL '1 day' * $1"
                )
                params = (days,)
            async with self._pool.acquire() as conn:
                result = await conn.execute(sql, *params)
                deleted = int(result.split()[-1]) if result else 0

        if deleted > 0:
            logger.info(
                "Purged old approvals",
                extra={
                    "event": "approval.purge",
                    "deleted": deleted,
                    "retention_days": days,
                },
            )
        return deleted

    async def close(self) -> None:
        """Pool lifecycle managed by app.py lifespan."""
        self._pool = None

    async def is_approved(self, approval_id: str) -> bool | None:
        """Check if an approval was granted. Returns None if still pending/not found."""
        logger.debug(
            "is_approved called",
            extra={"event": "approval.is_approved", "approval_id": approval_id},
        )
        await self._cleanup_expired()
        resolved_user_id = require_user_id(
            current_user_id.get(), "ApprovalManager.is_approved"
        )

        if self._in_memory:
            logger.debug(
                "is_approved: in_memory",
                extra={"event": "approval.is_approved.match", "reason": "in_memory"},
            )  # auto:neg
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                return None
            status = entry.status
        else:
            logger.debug(
                "is_approved: in_memory",
                extra={"event": "approval.is_approved.clean", "reason": "in_memory"},
            )  # auto:neg
            async with self._pool.acquire() as conn:
                status = await conn.fetchval(
                    "SELECT status FROM approvals WHERE approval_id = $1 AND user_id = $2",
                    approval_id,
                    resolved_user_id,
                )
                if status is None:
                    return None

        if status == "approved":
            return True
        if status == "denied":
            return False
        return None  # pending or expired

    async def get_pending(self, approval_id: str) -> dict | None:
        """Get the full approval entry (plan + metadata)."""
        resolved_user_id = require_user_id(
            current_user_id.get(), "ApprovalManager.get_pending"
        )

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                return None
            return {
                "plan": Plan.model_validate_json(entry.plan_json),
                "source_key": entry.source_key,
                "user_request": entry.user_request,
                "mtm_turn_score": entry.mtm_turn_score,
                "mtm_signal_categories": list(entry.mtm_signal_categories),
            }

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT plan_json, source_key, user_request, "
                "mtm_turn_score, mtm_signal_categories "
                "FROM approvals WHERE approval_id = $1 AND user_id = $2",
                approval_id,
                resolved_user_id,
            )
            if row is None:
                return None

            plan_json = row["plan_json"]
            if isinstance(plan_json, dict):
                plan = Plan.model_validate(plan_json)
            else:
                plan = Plan.model_validate_json(plan_json)

            categories = row["mtm_signal_categories"]

            return {
                "plan": plan,
                "source_key": row["source_key"],
                "user_request": row["user_request"],
                "mtm_turn_score": row["mtm_turn_score"] if row["mtm_turn_score"] is not None else 0.0,
                "mtm_signal_categories": categories if isinstance(categories, list) else [],
            }

    async def get_pending_by_source_key(self, source_key: str) -> dict | None:
        """Get the oldest pending approval for a given source_key.

        Returns a dict with approval_id, plan, source_key, user_request,
        mtm_turn_score, mtm_signal_categories, or None if no pending approval
        exists for this source_key.
        """
        await self._cleanup_expired()
        resolved_user_id = require_user_id(
            current_user_id.get(), "ApprovalManager.get_pending_by_source_key"
        )

        if self._in_memory:
            # Find the oldest pending entry matching this source_key and user
            candidates = [
                e
                for e in self._mem.values()
                if e.status == "pending"
                and e.source_key == source_key
                and e.user_id == resolved_user_id
            ]
            if not candidates:
                return None
            entry = min(candidates, key=lambda e: e.created_at)
            return {
                "approval_id": entry.approval_id,
                "plan": Plan.model_validate_json(entry.plan_json),
                "source_key": entry.source_key,
                "user_request": entry.user_request,
                "mtm_turn_score": entry.mtm_turn_score,
                "mtm_signal_categories": list(entry.mtm_signal_categories),
            }

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT approval_id, plan_json, source_key, user_request, "
                "mtm_turn_score, mtm_signal_categories "
                "FROM approvals WHERE source_key = $1 AND status = 'pending' "
                "AND user_id = $2 ORDER BY created_at ASC LIMIT 1",
                source_key,
                resolved_user_id,
            )
            if row is None:
                return None

            plan_json = row["plan_json"]
            if isinstance(plan_json, dict):
                plan = Plan.model_validate(plan_json)
            else:
                plan = Plan.model_validate_json(plan_json)

            categories = row["mtm_signal_categories"]

            return {
                "approval_id": row["approval_id"],
                "plan": plan,
                "source_key": row["source_key"],
                "user_request": row["user_request"],
                "mtm_turn_score": row["mtm_turn_score"] if row["mtm_turn_score"] is not None else 0.0,
                "mtm_signal_categories": categories if isinstance(categories, list) else [],
            }

    async def get_status_counts(self, cutoff: str | None = None) -> dict[str, int]:
        """Count approvals grouped by status, optionally filtered by cutoff.

        Intentionally cross-user — this is an admin reporting method.
        Do not add user_id filtering here.

        Args:
            cutoff: ISO 8601 timestamp string. Only entries with created_at >= cutoff
                    are counted. None means count all.
        """
        if self._in_memory:
            if cutoff is not None:
                try:
                    cutoff_dt = datetime.fromisoformat(cutoff)
                except (ValueError, AttributeError):
                    logger.warning(
                        "get_status_counts: ValueError | AttributeError",
                        extra={"event": "approval.get_status_counts_error"},
                        exc_info=True,
                    )
                    cutoff_dt = None
            else:
                logger.debug(
                    "get_status_counts: no cutoff",
                    extra={"event": "approval.get_status_counts.no_cutoff"},
                )
                cutoff_dt = None

            counts: dict[str, int] = {}
            for entry in self._mem.values():
                if cutoff_dt is not None:
                    try:
                        created = datetime.fromisoformat(entry.created_at)
                        if created < cutoff_dt:
                            continue
                    except (ValueError, AttributeError):
                        logger.debug(
                            "Skipping entry with unparseable created_at in status counts",
                            extra={"event": "approval.status_count_parse_skip"},
                            exc_info=True,
                        )
                        continue
                counts[entry.status] = counts.get(entry.status, 0) + 1
            return counts
        logger.debug(
            "get_status_counts: in_memory_passed",
            extra={
                "event": "approval.get_status_counts.no_cutoff.passed",
                "reason": "in_memory_passed",
            },
        )  # auto:neg

        async with self._pool.acquire() as conn:
            if cutoff is not None:
                cutoff_parsed = datetime.fromisoformat(cutoff)
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM approvals "
                    "WHERE created_at >= $1 GROUP BY status",
                    cutoff_parsed,
                )
            else:
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM approvals GROUP BY status",
                )
            return {r["status"]: r["cnt"] for r in rows}


if TYPE_CHECKING:
    from sentinel.core.store_protocols import ApprovalManagerProtocol

    _: ApprovalManagerProtocol = cast("ApprovalManagerProtocol", ApprovalManager())
