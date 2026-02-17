"""Confirmation gate — action-level confirmation with channel routing.

Stores fully-resolved tool call payloads pending user confirmation.
PostgreSQL backend with in-memory dict fallback for tests (pool=None).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

from sentinel.core.config import settings
from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.audit")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


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
    ) -> None:
        self._pool = pool
        self._in_memory = pool is None
        self._timeout = timeout if timeout is not None else settings.confirmation_timeout
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
        # Cancel any existing pending confirmation for this source_key
        existing = await self.get_pending(source_key)
        if existing is not None:
            await self.cancel(existing.confirmation_id)

        confirmation_id = str(uuid.uuid4())
        now = _now_utc()
        expires_at = now + timedelta(seconds=self._timeout)

        # Use the explicit user_id parameter consistently for both in-memory
        # and PG paths. The caller provides user_id from the request context;
        # we don't mix with ContextVar to avoid inconsistency.
        if self._in_memory:
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
            async with self._pool.acquire() as conn:
                # Cancel existing pending for this source_key (scoped to user)
                await conn.execute(
                    "UPDATE confirmations SET status = 'cancelled' "
                    "WHERE source_key = $1 AND status = 'pending' AND user_id = $2",
                    source_key, user_id,
                )
                await conn.execute(
                    "INSERT INTO confirmations "
                    "(confirmation_id, user_id, channel, source_key, tool_name, "
                    "tool_params, preview_text, original_request, status, task_id, expires_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, 'pending', $9, $10)",
                    confirmation_id, user_id, channel, source_key, tool_name,
                    json.dumps(tool_params), preview_text, original_request,
                    task_id, expires_at,
                )

        logger.info(
            "Confirmation created",
            extra={
                "event": "confirmation_created",
                "confirmation_id": confirmation_id,
                "tool_name": tool_name,
                "source_key": source_key,
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
        resolved_user_id = current_user_id.get()

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
                source_key, resolved_user_id,
            )
            if row is None:
                return None
            return self._row_to_entry(row)

    async def confirm(self, confirmation_id: str) -> ConfirmationEntry | None:
        """Mark a confirmation as confirmed. Returns the entry (with payload) or None.

        Scoped to current user via current_user_id ContextVar.
        """
        now = _now_utc()
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            entry = self._mem.get(confirmation_id)
            if (
                entry is None
                or entry.status != "pending"
                or entry.expires_at <= now
                or entry.user_id != resolved_user_id
            ):
                return None
            entry.status = "confirmed"
            logger.info(
                "Confirmation confirmed",
                extra={
                    "event": "confirmation_confirmed",
                    "confirmation_id": confirmation_id,
                    "tool_name": entry.tool_name,
                },
            )
            return entry

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE confirmations SET status = 'confirmed' "
                "WHERE confirmation_id = $1 AND status = 'pending' "
                "AND expires_at > NOW() AND user_id = $2 RETURNING *",
                confirmation_id, resolved_user_id,
            )
            if row is None:
                return None
            entry = self._row_to_entry(row)
            logger.info(
                "Confirmation confirmed",
                extra={
                    "event": "confirmation_confirmed",
                    "confirmation_id": confirmation_id,
                    "tool_name": entry.tool_name,
                },
            )
            return entry

    async def cancel(self, confirmation_id: str) -> None:
        """Mark a confirmation as cancelled. Scoped to current user."""
        resolved_user_id = current_user_id.get()

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
                        "event": "confirmation_cancelled",
                        "confirmation_id": confirmation_id,
                    },
                )
            return

        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE confirmations SET status = 'cancelled' "
                "WHERE confirmation_id = $1 AND status = 'pending' AND user_id = $2",
                confirmation_id, resolved_user_id,
            )
            if result and result != "UPDATE 0":
                logger.info(
                    "Confirmation cancelled",
                    extra={
                        "event": "confirmation_cancelled",
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
            count = 0
            for entry in self._mem.values():
                if entry.status == "pending" and entry.expires_at <= now:
                    entry.status = "expired"
                    count += 1
            return count

        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE confirmations SET status = 'expired' "
                "WHERE status = 'pending' AND expires_at <= NOW()"
            )
            return int(result.split()[-1]) if result else 0

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

    _: ConfirmationGateProtocol = cast(ConfirmationGateProtocol, ConfirmationGate())
