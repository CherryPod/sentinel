"""Confirmation gate — action-level confirmation with channel routing.

Stores fully-resolved tool call payloads pending user confirmation.
PostgreSQL backend with in-memory dict fallback for tests (pool=None).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

# Q5-F1: default retention for terminal-state confirmations in periodic purge.
_DEFAULT_PURGE_RETENTION_DAYS = 7

from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.config import settings
from sentinel.core.context import current_user_id, require_user_id
from sentinel.core.pending_action_preconditions import recheck_pending_action
from sentinel.crypto.blind_index import log_hash

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(UTC)


@dataclass
class ConfirmationEntry:
    """In-memory representation of a confirmation record."""

    confirmation_id: str
    user_id: int
    channel: str
    source_key: str
    tool_name: str
    tool_params: dict
    preview_text: str
    original_request: str
    status: str  # pending / confirmed / cancelled / expired
    task_id: str
    created_at: datetime
    expires_at: datetime


class ConfirmationGate:
    """Action-level confirmation gate with configurable TTL.

    Dual-mode: PostgreSQL when pool is provided, in-memory dict fallback
    for tests (pool=None). At most one pending confirmation per source_key.
    """

    def __init__(
        self,
        pool: Any = None,
        timeout: int | None = None,
        audit_emitter: Any = None,
        session_store: Any = None,
    ) -> None:
        self._pool = pool
        self._in_memory = pool is None
        self._timeout = (
            timeout if timeout is not None else settings.confirmation_timeout
        )
        self._audit_emitter = audit_emitter
        # Q10-F3: session_store is used by confirm() to re-check session lock
        # state at submit-time (enforcement-boundary fail-closed-on-
        # precondition-change). None is the test / backward-compat path —
        # the precondition helper returns permissive + session_state_unavailable.
        # Production DI is via api/init/orchestrator.py; a DI-wiring test
        # asserts prod-built gates have _session_store is not None (Codex F6).
        self._session_store = session_store
        if self._in_memory:
            self._mem: dict[str, ConfirmationEntry] = {}

    async def create(
        self,
        user_id: int,
        channel: str,
        source_key: str,
        tool_name: str,
        tool_params: dict,
        preview_text: str,
        original_request: str,
        task_id: str,
    ) -> str:
        """Create a pending confirmation. Auto-cancels any existing pending for this source_key."""
        # Q4: fail-closed on zero-principal (defence-in-depth on the explicit
        # arg — caller's user_id must be non-zero even though it is typed int).
        user_id = require_user_id(user_id, "ConfirmationGate.create")

        # Cancel any existing pending confirmation for this source_key
        existing = await self.get_pending(source_key)
        if existing is not None:
            logger.debug(
                "Cancelling existing pending confirmation for source_key",
                extra={
                    "event": "confirmation.create.cancel_existing",
                    "source_channel": source_key.split(":", 1)[0]
                    if source_key and ":" in source_key
                    else None,
                    "source_key_hash": log_hash(source_key),
                    "source_key_len": len(source_key or ""),
                },
            )
            await self.cancel(existing.confirmation_id)

        confirmation_id = str(uuid.uuid4())
        now = _now_utc()
        expires_at = now + timedelta(seconds=self._timeout)

        # Use the explicit user_id parameter consistently for both in-memory
        # and PG paths. The caller provides user_id from the request context;
        # we don't mix with ContextVar to avoid inconsistency.
        if self._in_memory:
            logger.debug(
                "Using in-memory path for confirmation create",
                extra={"event": "confirmation.create.in_memory"},
            )
            self._mem[confirmation_id] = ConfirmationEntry(
                confirmation_id=confirmation_id,
                user_id=user_id,
                channel=channel,
                source_key=source_key,
                tool_name=tool_name,
                tool_params=tool_params,
                preview_text=preview_text,
                original_request=original_request,
                status="pending",
                task_id=task_id,
                created_at=now,
                expires_at=expires_at,
            )
        else:
            logger.debug(
                "create: in_memory",
                extra={
                    "event": "confirmation.create.in_memory.clean",
                    "reason": "in_memory",
                },
            )  # auto:neg
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    # Cancel existing pending for this source_key (scoped to user)
                    await conn.execute(
                        "UPDATE confirmations SET status = 'cancelled' "
                        "WHERE source_key = $1 AND status = 'pending' AND user_id = $2",
                        source_key,
                        user_id,
                    )
                    await conn.execute(
                        "INSERT INTO confirmations "
                        "(confirmation_id, user_id, channel, source_key, tool_name, "
                        "tool_params, preview_text, original_request, status, task_id, expires_at) "
                        "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, 'pending', $9, $10)",
                        confirmation_id,
                        user_id,
                        channel,
                        source_key,
                        tool_name,
                        json.dumps(tool_params),
                        preview_text,
                        original_request,
                        task_id,
                        expires_at,
                    )

        logger.info(
            "Confirmation created",
            extra={
                "event": "confirmation.created",
                "confirmation_id": confirmation_id,
                "tool_name": tool_name,
                "source_channel": source_key.split(":", 1)[0]
                if source_key and ":" in source_key
                else None,
                "source_key_hash": log_hash(source_key),
                "source_key_len": len(source_key or ""),
                "task_id": task_id,
            },
        )
        return confirmation_id

    async def get_pending(self, source_key: str) -> ConfirmationEntry | None:
        """Get the pending confirmation for a source_key, if any.

        Returns None if no pending confirmation or if it has expired.
        Scoped to current user via current_user_id ContextVar.
        """
        now = _now_utc()
        resolved_user_id = require_user_id(
            current_user_id.get(), "ConfirmationGate.get_pending"
        )

        if self._in_memory:
            for entry in self._mem.values():
                if (
                    entry.source_key == source_key
                    and entry.status == "pending"
                    and entry.expires_at > now
                    and entry.user_id == resolved_user_id
                ):
                    return entry
            return None

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM confirmations "
                "WHERE source_key = $1 AND status = 'pending' AND expires_at > NOW() "
                "AND user_id = $2 ORDER BY created_at DESC LIMIT 1",
                source_key,
                resolved_user_id,
            )
            if row is None:
                return None
            return self._row_to_entry(row)

    async def confirm(
        self,
        confirmation_id: str,
        source_key: str | None = None,
    ) -> ConfirmationEntry | None:
        """Mark a confirmation as confirmed. Returns the entry (with payload) or None.

        Scoped to current user via current_user_id ContextVar.

        Q10-F3: when ``source_key`` is provided, it must match the
        ``source_key`` stored with the confirmation at create time. This
        parallels Q3.fix.b's reconnect-invalidation for approvals and
        closes replay of pending confirmations from a dropped transport.
        Caller gets a generic failure (same shape as not-found / expired)
        so cross-session replay attempts cannot distinguish "wrong
        connection" from "nonexistent confirmation". REST submits via
        ``/confirm/{id}`` pass ``source_key=None`` (no transport binding
        available) and skip the binding check — still fail-closed on
        the session-lock recheck below.

        Q10-F3: submit-time precondition recheck. Re-resolves the session
        by the row's issuance ``source_key`` (``source_key == session_id``
        invariant) and fails closed if the session is now locked. Permissive
        on session-missing per design D7; caller emits a WARNED audit tag
        so operators see the permissive fall-through. Fails closed with
        outcome=ERROR on session_store.get() exception per Q10.fix.b.review
        R2 (infrastructure couldn't evaluate policy, distinct from
        policy-said-no BLOCKED).

        Event names use the ``approval.confirmation_*`` prefix per Q17.fix.design
        D5 amendment (2026-04-22) — confirmation is an invariant-sibling of
        approval, not a semantically distinct audit category.
        """
        now = _now_utc()
        resolved_user_id = require_user_id(
            current_user_id.get(), "ConfirmationGate.confirm"
        )

        if self._in_memory:
            entry = self._mem.get(confirmation_id)
            if (
                entry is None
                or entry.status != "pending"
                or entry.expires_at <= now
                or entry.user_id != resolved_user_id
            ):
                return None

            # Q10-F3: transport-session binding. Mirrors
            # approval.submit_source_key_mismatch (Q3-F4). Returns None
            # (same shape as not-found / expired) so callers cannot
            # distinguish a source_key mismatch from a missing entry.
            if source_key is not None and entry.source_key != source_key:
                logger.warning(
                    "Confirmation submit — source_key mismatch",
                    extra={
                        "event": "approval.confirmation_submit_source_key_mismatch",
                        "confirmation_id": confirmation_id,
                    },
                )
                if self._audit_emitter is not None:
                    await self._audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="approval.confirmation_submit_source_key_mismatch",
                            source_component="confirmation",
                            outcome="BLOCKED",
                            severity="MEDIUM",
                            details={"confirmation_id": confirmation_id},
                        )
                    )
                return None

            # Q10-F3: submit-time precondition recheck. See method
            # docstring + helper contract (pending_action_preconditions.py).
            precondition = await recheck_pending_action(
                session_store=self._session_store,
                issuance_source_key=entry.source_key,
                user_id=resolved_user_id,
            )
            if not precondition.allow:
                if precondition.reason == "session_store_error":
                    event_name = (
                        "approval.confirmation_submit_blocked_session_store_error"
                    )
                    log_msg = "Confirmation submit — session store error (fail-closed)"
                    outcome = "ERROR"
                else:
                    event_name = "approval.confirmation_submit_blocked_session_locked"
                    log_msg = "Confirmation submit — session locked"
                    outcome = "BLOCKED"
                logger.warning(
                    log_msg,
                    extra={
                        "event": event_name,
                        "confirmation_id": confirmation_id,
                        "reason": precondition.reason,
                    },
                )
                if self._audit_emitter is not None:
                    await self._audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type=event_name,
                            source_component="confirmation",
                            outcome=outcome,
                            severity="MEDIUM",
                            details={
                                "confirmation_id": confirmation_id,
                                "reason": precondition.reason,
                            },
                        )
                    )
                return None
            if precondition.session_state_unavailable:
                logger.warning(
                    "Confirmation submit — session state unavailable",
                    extra={
                        "event": "approval.confirmation_session_state_unavailable",
                        "confirmation_id": confirmation_id,
                        "reason": precondition.reason,
                    },
                )
                if self._audit_emitter is not None:
                    await self._audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="approval.confirmation_session_state_unavailable",
                            source_component="confirmation",
                            outcome="WARNED",
                            details={
                                "confirmation_id": confirmation_id,
                                "reason": precondition.reason,
                            },
                        )
                    )

            entry.status = "confirmed"
            logger.info(
                "Confirmation confirmed",
                extra={
                    "event": "confirmation.confirmed",
                    "confirmation_id": confirmation_id,
                    "tool_name": entry.tool_name,
                },
            )
            return entry

        # CRIT-11: collect audit events that must emit AFTER the acquire block
        # exits so audit_emitter.emit() (which acquires from app_pool) does not
        # nest inside the held transaction conn.
        _pending_audit: SecurityAuditEvent | None = None
        _early_exit = False
        _entry: ConfirmationEntry | None = None

        async with self._pool.acquire() as conn, conn.transaction():
            # Q10-F3: split the previous single UPDATE into SELECT → checks →
            # UPDATE so the source_key binding + precondition recheck run
            # before the status flip. The SELECT + UPDATE run inside a single
            # transaction so readers see a consistent snapshot; residual
            # same-principal race between this SELECT and a concurrent
            # lock_session write is accepted (see helper docstring).
            issuance_row = await conn.fetchrow(
                "SELECT source_key, status, expires_at, user_id "
                "FROM confirmations "
                "WHERE confirmation_id = $1 AND user_id = $2",
                confirmation_id,
                resolved_user_id,
            )
            if (
                issuance_row is None
                or issuance_row["status"] != "pending"
                or issuance_row["expires_at"] <= now
            ):
                return None

            row_source_key = issuance_row["source_key"]
            if source_key is not None and row_source_key != source_key:
                logger.warning(
                    "Confirmation submit — source_key mismatch",
                    extra={
                        "event": "approval.confirmation_submit_source_key_mismatch",
                        "confirmation_id": confirmation_id,
                    },
                )
                if self._audit_emitter is not None:
                    _pending_audit = SecurityAuditEvent(
                        event_type="approval.confirmation_submit_source_key_mismatch",
                        source_component="confirmation",
                        outcome="BLOCKED",
                        severity="MEDIUM",
                        details={"confirmation_id": confirmation_id},
                    )
                _early_exit = True

            if not _early_exit:
                # CRIT-11: pass held conn so session_store.get() reuses the
                # existing connection instead of acquiring a new one.
                precondition = await recheck_pending_action(
                    session_store=self._session_store,
                    issuance_source_key=row_source_key,
                    user_id=resolved_user_id,
                    conn=conn,
                )
                if not precondition.allow:
                    if precondition.reason == "session_store_error":
                        event_name = (
                            "approval.confirmation_submit_blocked_session_store_error"
                        )
                        log_msg = "Confirmation submit — session store error (fail-closed)"
                        outcome = "ERROR"
                    else:
                        event_name = "approval.confirmation_submit_blocked_session_locked"
                        log_msg = "Confirmation submit — session locked"
                        outcome = "BLOCKED"
                    logger.warning(
                        log_msg,
                        extra={
                            "event": event_name,
                            "confirmation_id": confirmation_id,
                            "reason": precondition.reason,
                        },
                    )
                    if self._audit_emitter is not None:
                        _pending_audit = SecurityAuditEvent(
                            event_type=event_name,
                            source_component="confirmation",
                            outcome=outcome,
                            severity="MEDIUM",
                            details={
                                "confirmation_id": confirmation_id,
                                "reason": precondition.reason,
                            },
                        )
                    _early_exit = True
                elif precondition.session_state_unavailable:
                    logger.warning(
                        "Confirmation submit — session state unavailable",
                        extra={
                            "event": "approval.confirmation_session_state_unavailable",
                            "confirmation_id": confirmation_id,
                            "reason": precondition.reason,
                        },
                    )
                    if self._audit_emitter is not None:
                        _pending_audit = SecurityAuditEvent(
                            event_type="approval.confirmation_session_state_unavailable",
                            source_component="confirmation",
                            outcome="WARNED",
                            details={
                                "confirmation_id": confirmation_id,
                                "reason": precondition.reason,
                            },
                        )

            if not _early_exit:
                # Atomic UPDATE — only transitions from 'pending' within expiry.
                # Q10-F3 preserves the original single-UPDATE atomicity guard
                # via the WHERE clause; the SELECT above is a read-only
                # precondition scope that cannot flip status.
                row = await conn.fetchrow(
                    "UPDATE confirmations SET status = 'confirmed' "
                    "WHERE confirmation_id = $1 AND status = 'pending' "
                    "AND expires_at > NOW() AND user_id = $2 RETURNING *",
                    confirmation_id,
                    resolved_user_id,
                )
                if row is not None:
                    _entry = self._row_to_entry(row)
                    logger.info(
                        "Confirmation confirmed",
                        extra={
                            "event": "confirmation.confirmed",
                            "confirmation_id": confirmation_id,
                            "tool_name": _entry.tool_name,
                        },
                    )

        # CRIT-11: emit deferred audit event outside the acquire block so
        # audit_emitter.emit() does not nest inside the held transaction conn.
        if _pending_audit is not None and self._audit_emitter is not None:
            await self._audit_emitter.emit(_pending_audit)
        if _early_exit:
            return None
        return _entry

    async def cancel(self, confirmation_id: str) -> None:
        """Mark a confirmation as cancelled. Scoped to current user."""
        resolved_user_id = require_user_id(
            current_user_id.get(), "ConfirmationGate.cancel"
        )

        if self._in_memory:
            entry = self._mem.get(confirmation_id)
            if (
                entry is not None
                and entry.status == "pending"
                and entry.user_id == resolved_user_id
            ):
                entry.status = "cancelled"
                logger.info(
                    "Confirmation cancelled",
                    extra={
                        "event": "confirmation.cancelled",
                        "confirmation_id": confirmation_id,
                    },
                )
            return

        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE confirmations SET status = 'cancelled' "
                "WHERE confirmation_id = $1 AND status = 'pending' AND user_id = $2",
                confirmation_id,
                resolved_user_id,
            )
            if result and result != "UPDATE 0":
                logger.info(
                    "Confirmation cancelled",
                    extra={
                        "event": "confirmation.cancelled",
                        "confirmation_id": confirmation_id,
                    },
                )

    async def cleanup_expired(self) -> int:
        """Mark expired pending entries. Returns the count.

        Intentionally cross-user — system maintenance task.
        Do not add user_id filtering here.
        """
        now = _now_utc()

        if self._in_memory:
            logger.debug(
                "cleanup_expired: in_memory",
                extra={
                    "event": "confirmation.cleanup_expired.match",
                    "reason": "in_memory",
                },
            )  # auto:neg
            count = 0
            for entry in self._mem.values():
                if entry.status == "pending" and entry.expires_at <= now:
                    entry.status = "expired"
                    count += 1
        else:
            logger.debug(
                "cleanup_expired: in_memory",
                extra={
                    "event": "confirmation.cleanup_expired.clean",
                    "reason": "in_memory",
                },
            )  # auto:neg
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "UPDATE confirmations SET status = 'expired' "
                    "WHERE status = 'pending' AND expires_at <= NOW()"
                )
                count = int(result.split()[-1]) if result else 0

        if count > 0:
            logger.info(
                "Expired pending confirmations",
                extra={"event": "confirmation.cleanup_expired", "expired_count": count},
            )
        return count

    async def purge_old(
        self,
        days: int = _DEFAULT_PURGE_RETENTION_DAYS,
        user_id: int | None = None,
    ) -> int:
        """Delete terminal-state confirmation entries older than N days.

        Mirrors :meth:`ApprovalManager.purge_old` shape. Terminal statuses
        covered: ``confirmed``, ``cancelled``, ``expired``. ``pending``
        entries are never purged here — those transition via
        :meth:`cleanup_expired` first.

        When ``user_id`` is provided, only deletes that user's entries.
        When ``None`` (the default), deletes across all users (admin
        maintenance). Called from ``run_db_maintenance`` via the admin
        pool which bypasses RLS.

        Returns the number of rows / entries deleted.
        """
        cutoff = _now_utc() - timedelta(days=days)
        terminal_states = ("confirmed", "cancelled", "expired")

        if self._in_memory:
            logger.debug(
                "purge_old: in_memory",
                extra={"event": "confirmation.purge.match", "reason": "in_memory"},
            )  # auto:neg
            to_delete: list[str] = []
            for cid, entry in self._mem.items():
                if entry.status not in terminal_states:
                    continue
                if user_id is not None and entry.user_id != user_id:
                    continue
                if entry.created_at < cutoff:
                    to_delete.append(cid)
            for cid in to_delete:
                del self._mem[cid]
            deleted = len(to_delete)
        else:
            logger.debug(
                "purge_old: pg",
                extra={
                    "event": "confirmation.purge.clean",
                    "reason": "pg",
                },
            )  # auto:neg
            if user_id is not None:
                sql = (
                    "DELETE FROM confirmations "
                    "WHERE status IN ('confirmed', 'cancelled', 'expired') "
                    "AND created_at < NOW() - INTERVAL '1 day' * $1 "
                    "AND user_id = $2"
                )
                params: tuple = (days, user_id)
            else:
                sql = (
                    "DELETE FROM confirmations "
                    "WHERE status IN ('confirmed', 'cancelled', 'expired') "
                    "AND created_at < NOW() - INTERVAL '1 day' * $1"
                )
                params = (days,)
            async with self._pool.acquire() as conn:
                result = await conn.execute(sql, *params)
                deleted = int(result.split()[-1]) if result else 0

        if deleted > 0:
            logger.info(
                "Purged old confirmations",
                extra={
                    "event": "confirmation.purge",
                    "deleted": deleted,
                    "retention_days": days,
                },
            )
        return deleted

    async def close(self) -> None:
        """Pool lifecycle managed by app.py lifespan."""
        self._pool = None

    @staticmethod
    def _row_to_entry(row) -> ConfirmationEntry:
        """Convert an asyncpg Record to a ConfirmationEntry."""
        tool_params = row["tool_params"]
        if isinstance(tool_params, str):
            tool_params = json.loads(tool_params)
        return ConfirmationEntry(
            confirmation_id=row["confirmation_id"],
            user_id=row["user_id"],
            channel=row["channel"],
            source_key=row["source_key"],
            tool_name=row["tool_name"],
            tool_params=tool_params,
            preview_text=row["preview_text"],
            original_request=row["original_request"],
            status=row["status"],
            task_id=row["task_id"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )


if TYPE_CHECKING:
    from sentinel.core.store_protocols import ConfirmationGateProtocol

    _: ConfirmationGateProtocol = cast("ConfirmationGateProtocol", ConfirmationGate())
