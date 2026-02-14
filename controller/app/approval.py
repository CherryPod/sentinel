import logging
import time
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


@dataclass
class PendingApproval:
    approval_id: str
    plan: Plan
    created_at: float  # monotonic time for TTL
    result: ApprovalResult | None = None


class ApprovalManager:
    """HTTP-based approval with in-memory pending queue and TTL."""

    def __init__(self, timeout: int | None = None):
        self._timeout = timeout if timeout is not None else settings.approval_timeout
        self._pending: dict[str, PendingApproval] = {}

    async def request_plan_approval(self, plan: Plan) -> str:
        """Create an approval request. Returns the approval_id."""
        approval_id = str(uuid.uuid4())
        self._pending[approval_id] = PendingApproval(
            approval_id=approval_id,
            plan=plan,
            created_at=time.monotonic(),
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

    def check_approval(self, approval_id: str) -> dict:
        """Check status of an approval request.

        Returns dict with "status" key: "pending", "approved", "denied", "expired", or "not_found".
        """
        entry = self._pending.get(approval_id)
        if entry is None:
            logger.info(
                "Approval not found",
                extra={"event": "approval_not_found", "approval_id": approval_id},
            )
            return {"status": "not_found"}

        # Check TTL
        if time.monotonic() - entry.created_at > self._timeout:
            entry.result = ApprovalResult(
                granted=False, reason="Expired", approved_by="system",
            )
            elapsed = time.monotonic() - entry.created_at
            logger.warning(
                "Approval expired",
                extra={"event": "approval_expired", "approval_id": approval_id, "elapsed_s": round(elapsed, 1)},
            )
            return {
                "status": "expired",
                "reason": "Approval request expired",
            }

        if entry.result is None:
            return {
                "status": "pending",
                "plan_summary": entry.plan.plan_summary,
                "steps": [
                    {"id": s.id, "type": s.type, "description": s.description}
                    for s in entry.plan.steps
                ],
            }

        if entry.result.granted:
            return {
                "status": "approved",
                "reason": entry.result.reason,
                "approved_by": entry.result.approved_by,
            }
        else:
            return {
                "status": "denied",
                "reason": entry.result.reason,
            }

    def submit_approval(
        self,
        approval_id: str,
        granted: bool,
        reason: str = "",
        approved_by: str = "api",
    ) -> bool:
        """Submit an approval decision. Returns True if accepted, False if invalid/duplicate."""
        entry = self._pending.get(approval_id)
        if entry is None:
            logger.warning(
                "Approval submit — not found",
                extra={"event": "approval_submit_not_found", "approval_id": approval_id},
            )
            return False

        # Check TTL
        if time.monotonic() - entry.created_at > self._timeout:
            logger.warning(
                "Approval submit — expired",
                extra={"event": "approval_submit_expired", "approval_id": approval_id},
            )
            return False

        # Ignore duplicate submissions
        if entry.result is not None:
            logger.warning(
                "Approval submit — duplicate",
                extra={"event": "approval_submit_duplicate", "approval_id": approval_id},
            )
            return False

        entry.result = ApprovalResult(
            granted=granted,
            reason=reason,
            approved_by=approved_by,
        )

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
        entry = self._pending.get(approval_id)
        if entry is None:
            return None
        return entry.plan

    def is_approved(self, approval_id: str) -> bool | None:
        """Check if an approval was granted. Returns None if still pending/not found."""
        entry = self._pending.get(approval_id)
        if entry is None or entry.result is None:
            return None
        return entry.result.granted
