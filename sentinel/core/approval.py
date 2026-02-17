"""Approval queue with configurable TTL.

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
from sentinel.core.models import Plan

logger = logging.getLogger("sentinel.audit")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


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


@dataclass
class ApprovalResult:
    granted: bool
    reason: str = ""
    approved_by: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ApprovalManager:
    """Approval queue with configurable TTL.

    Dual-mode: PostgreSQL when pool is provided, in-memory dict fallback for tests.
    """

    def __init__(
        self,
        pool: Any = None,
        timeout: int | None = None,
        event_bus: Any = None,
    ):
        self._pool = pool
        self._in_memory = pool is None
        self._timeout = timeout if timeout is not None else settings.approval_timeout
        self._event_bus = event_bus
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
                    expired.append({"approval_id": entry.approval_id, "source_key": entry.source_key})
            for entry in expired:
                logger.warning(
                    "Approval expired",
                    extra={
                        "event": "approval_auto_expired",
                        "approval_id": entry["approval_id"],
                        "source_key": entry["source_key"],
                    },
                )
            return expired

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT approval_id, source_key FROM approvals "
                "WHERE status = 'pending' AND expires_at < NOW()"
            )
            if not rows:
                return []

            await conn.execute(
                "UPDATE approvals SET status = 'expired' "
                "WHERE status = 'pending' AND expires_at < NOW()"
            )

        expired = [{"approval_id": r["approval_id"], "source_key": r["source_key"]} for r in rows]
        for entry in expired:
            logger.warning(
                "Approval expired",
                extra={
                    "event": "approval_auto_expired",
                    "approval_id": entry["approval_id"],
                    "source_key": entry["source_key"],
                },
            )
        return expired

    async def cleanup_and_notify(self) -> list[dict]:
        """Cleanup expired entries and publish approval.expired events."""
        expired = await self._cleanup_expired()
        if self._event_bus and expired:
            for entry in expired:
                await self._event_bus.publish("approval.expired", {
                    "approval_id": entry["approval_id"],
                    "source_key": entry["source_key"],
                    "reason": "Approval request timed out",
                })
        return expired

    async def request_plan_approval(
        self, plan: Plan, source_key: str = "", user_request: str = "",
    ) -> str:
        """Create an approval request. Returns the approval_id."""
        await self._cleanup_expired()
        approval_id = str(uuid.uuid4())
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            self._mem[approval_id] = ApprovalEntry(
                approval_id=approval_id,
                plan_json=plan.model_dump_json(),
                status="pending",
                expires_at=_now_utc() + timedelta(seconds=self._timeout),
                source_key=source_key,
                user_request=user_request,
                user_id=resolved_user_id,
            )
        else:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._timeout)
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO approvals "
                    "(approval_id, plan_json, expires_at, source_key, user_request, user_id) "
                    "VALUES ($1, $2::jsonb, $3, $4, $5, $6)",
                    approval_id,
                    plan.model_dump_json(),
                    expires_at,
                    source_key,
                    user_request,
                    resolved_user_id,
                )

        logger.info(
            "Approval requested",
            extra={
                "event": "approval_requested",
                "approval_id": approval_id,
                "plan_summary": plan.plan_summary,
            },
        )
        return approval_id

    async def check_approval(self, approval_id: str) -> dict:
        """Check status of an approval request."""
        await self._cleanup_expired()
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                logger.info(
                    "Approval not found",
                    extra={"event": "approval_not_found", "approval_id": approval_id},
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
                    approval_id, resolved_user_id,
                )
                if row is None:
                    logger.info(
                        "Approval not found",
                        extra={"event": "approval_not_found", "approval_id": approval_id},
                    )
                    return {"status": "not_found"}

                status = row["status"]
                plan_json = row["plan_json"]
                decided_reason = row["decided_reason"]
                decided_by = row["decided_by"]

        if status == "expired":
            logger.warning(
                "Approval expired",
                extra={"event": "approval_expired", "approval_id": approval_id},
            )
            return {"status": "expired", "reason": "Approval request expired"}

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
                        "args": s.args if s.args else None,
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
    ) -> bool:
        """Submit an approval decision. Returns True if accepted."""
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                logger.warning(
                    "Approval submit — not found",
                    extra={"event": "approval_submit_not_found", "approval_id": approval_id},
                )
                return False

            if entry.expires_at < _now_utc():
                entry.status = "expired"
                logger.warning(
                    "Approval submit — expired",
                    extra={"event": "approval_submit_expired", "approval_id": approval_id},
                )
                return False

            if entry.status != "pending":
                logger.warning(
                    "Approval submit — duplicate",
                    extra={"event": "approval_submit_duplicate", "approval_id": approval_id},
                )
                return False

            new_status = "approved" if granted else "denied"
            entry.status = new_status
            entry.decided_at = _now_iso()
            entry.decided_reason = reason
            entry.decided_by = approved_by
        else:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT status, expires_at FROM approvals "
                    "WHERE approval_id = $1 AND user_id = $2",
                    approval_id, resolved_user_id,
                )
                if row is None:
                    logger.warning(
                        "Approval submit — not found",
                        extra={"event": "approval_submit_not_found", "approval_id": approval_id},
                    )
                    return False

                status = row["status"]
                expires_at = row["expires_at"]

                now = datetime.now(timezone.utc)
                if expires_at < now:
                    await conn.execute(
                        "UPDATE approvals SET status = 'expired' "
                        "WHERE approval_id = $1 AND user_id = $2",
                        approval_id, resolved_user_id,
                    )
                    logger.warning(
                        "Approval submit — expired",
                        extra={"event": "approval_submit_expired", "approval_id": approval_id},
                    )
                    return False

                if status != "pending":
                    logger.warning(
                        "Approval submit — duplicate",
                        extra={"event": "approval_submit_duplicate", "approval_id": approval_id},
                    )
                    return False

                new_status = "approved" if granted else "denied"
                await conn.execute(
                    "UPDATE approvals SET status = $1, decided_at = NOW(), "
                    "decided_reason = $2, decided_by = $3 "
                    "WHERE approval_id = $4 AND user_id = $5",
                    new_status, reason, approved_by, approval_id, resolved_user_id,
                )

        decision = "approved" if granted else "denied"
        logger.info(
            "Approval submitted",
            extra={
                "event": "approval_submitted",
                "approval_id": approval_id,
                "granted": granted,
                "reason": reason,
            },
        )

        # Audit log for approval state changes (PG only).
        # session_id is NULL — approvals are not tied to a specific session.
        # The approval_id is recorded in the details JSON for traceability.
        if not self._in_memory:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO audit_log (user_id, event_type, session_id, details) "
                    "VALUES ($1, $2, NULL, $3::jsonb)",
                    resolved_user_id, f"approval_{decision}",
                    json.dumps({"approval_id": approval_id, "reason": reason}),
                )

        return True

    async def get_plan(self, approval_id: str) -> Plan | None:
        """Get the plan associated with an approval ID."""
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                return None
            return Plan.model_validate_json(entry.plan_json)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT plan_json FROM approvals WHERE approval_id = $1 AND user_id = $2",
                approval_id, resolved_user_id,
            )
            if row is None:
                return None
            plan_json = row["plan_json"]
            if isinstance(plan_json, dict):
                return Plan.model_validate(plan_json)
            return Plan.model_validate_json(plan_json)

    async def purge_old(self, days: int = 7) -> int:
        """Delete decided/expired approval entries older than N days."""
        if self._in_memory:
            cutoff = _now_utc() - timedelta(days=days)
            to_delete = []
            for aid, entry in self._mem.items():
                if entry.status in ("expired", "approved", "denied"):
                    try:
                        created = datetime.fromisoformat(entry.created_at.replace("Z", "+00:00"))
                        if created < cutoff:
                            to_delete.append(aid)
                    except (ValueError, AttributeError):
                        continue
            for aid in to_delete:
                del self._mem[aid]
            deleted = len(to_delete)
        else:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM approvals "
                    "WHERE status IN ('expired', 'approved', 'denied') "
                    "AND created_at < NOW() - INTERVAL '1 day' * $1",
                    days,
                )
                deleted = int(result.split()[-1]) if result else 0

        if deleted > 0:
            logger.info(
                "Purged old approvals",
                extra={"event": "approval_purge", "deleted": deleted, "retention_days": days},
            )
        return deleted

    async def close(self) -> None:
        """Pool lifecycle managed by app.py lifespan."""
        self._pool = None

    async def is_approved(self, approval_id: str) -> bool | None:
        """Check if an approval was granted. Returns None if still pending/not found."""
        await self._cleanup_expired()
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                return None
            status = entry.status
        else:
            async with self._pool.acquire() as conn:
                status = await conn.fetchval(
                    "SELECT status FROM approvals WHERE approval_id = $1 AND user_id = $2",
                    approval_id, resolved_user_id,
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
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            entry = self._mem.get(approval_id)
            if entry is None or entry.user_id != resolved_user_id:
                return None
            return {
                "plan": Plan.model_validate_json(entry.plan_json),
                "source_key": entry.source_key,
                "user_request": entry.user_request,
            }

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT plan_json, source_key, user_request "
                "FROM approvals WHERE approval_id = $1 AND user_id = $2",
                approval_id, resolved_user_id,
            )
            if row is None:
                return None

            plan_json = row["plan_json"]
            if isinstance(plan_json, dict):
                plan = Plan.model_validate(plan_json)
            else:
                plan = Plan.model_validate_json(plan_json)

            return {
                "plan": plan,
                "source_key": row["source_key"],
                "user_request": row["user_request"],
            }

    async def get_pending_by_source_key(self, source_key: str) -> dict | None:
        """Get the oldest pending approval for a given source_key.

        Returns a dict with approval_id, plan, source_key, user_request,
        or None if no pending approval exists for this source_key.
        """
        await self._cleanup_expired()
        resolved_user_id = current_user_id.get()

        if self._in_memory:
            # Find the oldest pending entry matching this source_key and user
            candidates = [
                e for e in self._mem.values()
                if e.status == "pending" and e.source_key == source_key
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
            }

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT approval_id, plan_json, source_key, user_request "
                "FROM approvals WHERE source_key = $1 AND status = 'pending' "
                "AND user_id = $2 ORDER BY created_at ASC LIMIT 1",
                source_key, resolved_user_id,
            )
            if row is None:
                return None

            plan_json = row["plan_json"]
            if isinstance(plan_json, dict):
                plan = Plan.model_validate(plan_json)
            else:
                plan = Plan.model_validate_json(plan_json)

            return {
                "approval_id": row["approval_id"],
                "plan": plan,
                "source_key": row["source_key"],
                "user_request": row["user_request"],
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
                    cutoff_dt = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    cutoff_dt = None
            else:
                cutoff_dt = None

            counts: dict[str, int] = {}
            for entry in self._mem.values():
                if cutoff_dt is not None:
                    try:
                        created = datetime.fromisoformat(entry.created_at.replace("Z", "+00:00"))
                        if created < cutoff_dt:
                            continue
                    except (ValueError, AttributeError):
                        continue
                counts[entry.status] = counts.get(entry.status, 0) + 1
            return counts

        async with self._pool.acquire() as conn:
            if cutoff is not None:
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM approvals "
                    "WHERE created_at >= $1::timestamptz GROUP BY status",
                    cutoff,
                )
            else:
                rows = await conn.fetch(
                    "SELECT status, COUNT(*) AS cnt FROM approvals GROUP BY status",
                )
            return {r["status"]: r["cnt"] for r in rows}


if TYPE_CHECKING:
    from sentinel.core.store_protocols import ApprovalManagerProtocol

    _: ApprovalManagerProtocol = cast(ApprovalManagerProtocol, ApprovalManager())
