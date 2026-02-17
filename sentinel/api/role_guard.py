"""Role-based access guard for API endpoints.

Checks the current user's role against a minimum required role level.
Role hierarchy: owner > admin > user > pending.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException

from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.api.role_guard")

ROLE_LEVELS = {"pending": 0, "user": 1, "admin": 2, "owner": 3}


async def require_role(min_role: str, contact_store: Any) -> None:
    """Raise 403 if the current user doesn't have the required role.

    Looks up the user's role from the DB via contact_store. Must be called
    after UserContextMiddleware has set current_user_id.
    """
    user_id = current_user_id.get()
    role = await contact_store.get_user_role(user_id)
    if role is None:
        raise HTTPException(status_code=403, detail="User not found")
    user_level = ROLE_LEVELS.get(role, 0)
    required_level = ROLE_LEVELS.get(min_role, 99)
    if user_level < required_level:
        raise HTTPException(
            status_code=403,
            detail=f"Requires {min_role} role (current: {role})",
        )
