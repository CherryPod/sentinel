import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import settings
from .models import Plan

logger = logging.getLogger("sentinel.audit")


@dataclass
class ApprovalResult:
    granted: bool
    reason: str = ""
    approved_by: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ApprovalManager:
    """SQLite-backed approval queue with configurable TTL."""

    def __init__(self, db: sqlite3.Connection, timeout: int | None = None):
        self._db = db
        self._timeout = timeout if timeout is not None else settings.approval_timeout

    def _cleanup_expired(self) -> None:
        """Mark entries as expired if past their expires_at time."""
        self._db.execute(
            "UPDATE approvals SET status = 'expired' "
            "WHERE status = 'pending' AND expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
        )
        self._db.commit()

    async def request_plan_approval(
        self, plan: Plan, source_key: str = "", user_request: str = "",
    ) -> str:
        """Create an approval request. Returns the approval_id."""
        self._cleanup_expired()
        approval_id = str(uuid.uuid4())
        self._db.execute(
            "INSERT INTO approvals (approval_id, plan_json, expires_at, source_key, user_request) "
            "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?), ?, ?)",
            (
                approval_id,
                plan.model_dump_json(),
                f"+{self._timeout} seconds",
                source_key,
                user_request,
            ),
        )
        self._db.commit()
        logger.info(
            "Approval requested",
            extra={
                "event": "approval_requested",
                "approval_id": approval_id,
                "plan_summary": plan.plan_summary,
            },
        )
        return approval_id

    def check_approval(self, approval_id: str) -> dict:
        """Check status of an approval request.

        Returns dict with "status" key: "pending", "approved", "denied", "expired", or "not_found".
        """
        self._cleanup_expired()
        row = self._db.execute(
            "SELECT status, plan_json, decided_reason, decided_by FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            logger.info(
                "Approval not found",
                extra={"event": "approval_not_found", "approval_id": approval_id},
            )
            return {"status": "not_found"}

        status, plan_json, decided_reason, decided_by = row

        if status == "expired":
            logger.warning(
                "Approval expired",
                extra={"event": "approval_expired", "approval_id": approval_id},
            )
            return {"status": "expired", "reason": "Approval request expired"}

        if status == "pending":
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

    def submit_approval(
        self,
        approval_id: str,
        granted: bool,
        reason: str = "",
        approved_by: str = "api",
    ) -> bool:
        """Submit an approval decision. Returns True if accepted, False if invalid/duplicate."""
        row = self._db.execute(
            "SELECT status, expires_at FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            logger.warning(
                "Approval submit — not found",
                extra={"event": "approval_submit_not_found", "approval_id": approval_id},
            )
            return False

        status, expires_at = row

        # Check if expired via SQL comparison
        is_expired = self._db.execute(
            "SELECT ? < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", (expires_at,)
        ).fetchone()[0]
        if is_expired:
            self._db.execute(
                "UPDATE approvals SET status = 'expired' WHERE approval_id = ?",
                (approval_id,),
            )
            self._db.commit()
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
        self._db.execute(
            "UPDATE approvals SET status = ?, decided_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), "
            "decided_reason = ?, decided_by = ? WHERE approval_id = ?",
            (new_status, reason, approved_by, approval_id),
        )
        self._db.commit()

        logger.info(
            "Approval submitted",
            extra={
                "event": "approval_submitted",
                "approval_id": approval_id,
                "granted": granted,
                "reason": reason,
            },
        )
        return True

    def get_plan(self, approval_id: str) -> Plan | None:
        """Get the plan associated with an approval ID."""
        row = self._db.execute(
            "SELECT plan_json FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            return None
        return Plan.model_validate_json(row[0])

    def is_approved(self, approval_id: str) -> bool | None:
        """Check if an approval was granted. Returns None if still pending/not found."""
        self._cleanup_expired()
        row = self._db.execute(
            "SELECT status FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            return None
        status = row[0]
        if status == "approved":
            return True
        if status == "denied":
            return False
        return None  # pending or expired

    def get_pending(self, approval_id: str) -> dict | None:
        """Get the full approval entry (plan + metadata).

        Returns a dict with plan, source_key, user_request — or None if not found.
        Replaces the old PendingApproval dataclass.
        """
        row = self._db.execute(
            "SELECT plan_json, source_key, user_request FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            return None
        plan_json, source_key, user_request = row
        return {
            "plan": Plan.model_validate_json(plan_json),
            "source_key": source_key,
            "user_request": user_request,
        }
