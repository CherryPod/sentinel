"""Role-based access guard for API endpoints.

Checks the current user's role against a minimum required role level.
Role hierarchy: owner > admin > user > pending.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException

from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.context import current_user_id

if TYPE_CHECKING:
    from sentinel.audit.emitter import AuditEmitter

logger = logging.getLogger(__name__)

ROLE_LEVELS = {"pending": 0, "user": 1, "admin": 2, "owner": 3}


async def _emit_role_denied(
    audit_emitter: AuditEmitter | None,
    required_role: str,
    actual_role: str | None,
) -> None:
    """Fire-and-forget access.role_denied audit event."""
    if audit_emitter is None:
        return
    try:
        await audit_emitter.emit(
            SecurityAuditEvent(
                event_type="access.role_denied",
                source_component="role_guard",
                outcome="BLOCKED",
                severity="MEDIUM",
                details={
                    "required_role": required_role,
                    "actual_role": actual_role,
                },
            )
        )
    except Exception:
        logger.warning(
            "Role guard audit emit failed (non-fatal)",
            extra={"event": "role_guard.audit_emit_failed"},
            exc_info=True,
        )


async def require_role(
    min_role: str,
    contact_store: Any,
    audit_emitter: AuditEmitter | None = None,
) -> None:
    """Raise 403 if the current user doesn't have the required role.

    Looks up the user's role from the DB via contact_store. Must be called
    after UserContextMiddleware has set current_user_id.
    """
    logger.debug(
        "require_role called",
        extra={
            "event": "role_guard.require_role",
            "min_role": min_role,
            "contact_store_type": type(contact_store).__name__,
        },
    )
    user_id = current_user_id.get()
    if user_id == 0:
        logger.warning(
            "require_role: unauthenticated request blocked",
            extra={"event": "role_guard.unauthenticated", "min_role": min_role},
        )
        await _emit_role_denied(audit_emitter, min_role, None)
        raise HTTPException(status_code=401, detail="Authentication required")
    role = await contact_store.get_user_role(user_id)
    if role is None:
        logger.warning(
            "Role guard: user not found",
            extra={
                "event": "role_guard.user_not_found",
                "user_id": user_id,
                "min_role": min_role,
            },
        )
        await _emit_role_denied(audit_emitter, min_role, None)
        raise HTTPException(status_code=403, detail="User not found")
    user_level = ROLE_LEVELS.get(role, 0)
    required_level = ROLE_LEVELS.get(min_role, 99)
    if user_level < required_level:
        logger.warning(
            "Role guard: access denied",
            extra={
                "event": "role_guard.denied",
                "user_id": user_id,
                "role": role,
                "min_role": min_role,
            },
        )
        await _emit_role_denied(audit_emitter, min_role, role)
        raise HTTPException(
            status_code=403,
            detail=f"Requires {min_role} role (current: {role})",
        )
    logger.debug(
        "Role guard: access granted",
        extra={
            "event": "role_guard.granted",
            "user_id": user_id,
            "role": role,
            "min_role": min_role,
        },
    )
