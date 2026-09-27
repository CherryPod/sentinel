"""User CRUD mixin for ContactStore.

Provides UserStoreMixin with all user table operations, plus
user_from_row() — the public row-conversion helper.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.contacts._rows import (
    USER_UPDATABLE,
    _dt_to_iso,
    _now_iso,
)
from sentinel.core.decorators import no_audit_log

logger = logging.getLogger(__name__)


class UserStoreMixin:
    """User CRUD operations.

    Expects on self (set by ContactStore.__init__):
    - _pool: asyncpg.Pool | None
    - _users: dict[int, dict]  (in-memory fallback)
    - _next_user_id: int  (in-memory auto-increment)
    """

    async def create_user(
        self,
        display_name: str,
        pin_hash: str | None = None,
    ) -> dict:
        """Create a new system user. Returns the user dict."""
        logger.debug(
            "create_user called",
            extra={
                "event": "store.create_user",
                "display_name_len": len(display_name) if display_name else 0,
            },
        )
        now = _now_iso()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO users (display_name, pin_hash) "
                    "VALUES ($1, $2) RETURNING *",
                    display_name,
                    pin_hash,
                )
                return user_from_row(row)

        # In-memory fallback
        uid = self._next_user_id
        self._next_user_id += 1
        user = {
            "user_id": uid,
            "display_name": display_name,
            "pin_hash": pin_hash,
            "is_active": True,
            "created_at": now,
        }
        self._users[uid] = user
        return dict(user)

    async def get_user(self, user_id: int) -> dict | None:
        """Get a user by ID. Returns None if not found."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM users WHERE user_id = $1",
                    user_id,
                )
                return user_from_row(row) if row else None

        user = self._users.get(user_id)
        return dict(user) if user else None

    @no_audit_log
    async def list_users(self, active_only: bool = True) -> list[dict]:
        """List all users, optionally filtered to active only."""
        logger.debug(
            "list_users called",
            extra={"event": "store.list_users", "active_only": active_only},
        )
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if active_only:
                    rows = await conn.fetch(
                        "SELECT * FROM users WHERE is_active = TRUE ORDER BY user_id",
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT * FROM users ORDER BY user_id",
                    )
                return [user_from_row(r) for r in rows]

        users = list(self._users.values())
        if active_only:
            users = [u for u in users if u["is_active"]]
        users.sort(key=lambda u: u["user_id"])
        return [dict(u) for u in users]

    async def update_user(self, user_id: int, **fields: Any) -> dict | None:
        """Update user fields. Returns updated user or None if not found."""
        logger.debug(
            "update_user called",
            extra={"event": "store.update_user", "user_id": user_id},
        )
        bad = set(fields) - USER_UPDATABLE
        if bad:
            raise ValueError(f"Invalid update fields: {bad}")

        if self._pool is not None:
            # Build SET clause
            set_parts, values = [], []
            for i, (k, v) in enumerate(fields.items(), 1):
                set_parts.append(f"{k} = ${i}")
                values.append(v)
            values.append(user_id)
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    f"UPDATE users SET {', '.join(set_parts)} "  # nosec B608 — column names from USER_UPDATABLE constant; values parameterised via asyncpg
                    f"WHERE user_id = ${len(values)} RETURNING *",
                    *values,
                )
                return user_from_row(row) if row else None

        user = self._users.get(user_id)
        if user is None:
            return None
        for k, v in fields.items():
            user[k] = v
        return dict(user)

    async def get_user_trust_level(self, user_id: int) -> int | None:
        """Return the user's per-user trust_level, or None if unset/not found."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT trust_level FROM users WHERE user_id = $1",
                    user_id,
                )
                return row["trust_level"] if row else None

        user = self._users.get(user_id)
        if user is None:
            return None
        return user.get("trust_level")

    async def get_user_role(self, user_id: int) -> str | None:
        """Return the user's role, or None if not found."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT role FROM users WHERE user_id = $1",
                    user_id,
                )
                return row["role"] if row else None

        user = self._users.get(user_id)
        if user is None:
            return None
        return user.get("role", "user")

    async def deactivate_user(self, user_id: int) -> bool:
        """Soft-disable a user. Returns True if the user existed."""
        logger.debug(
            "deactivate_user called",
            extra={"event": "store.deactivate_user", "user_id": user_id},
        )
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "UPDATE users SET is_active = FALSE WHERE user_id = $1",
                    user_id,
                )
                return result == "UPDATE 1"

        user = self._users.get(user_id)
        if user is None:
            return False
        user["is_active"] = False
        return True


# ── Row conversion ───────────────────────────────────────────────


def user_from_row(row: Any) -> dict:
    """Convert an asyncpg Record to a plain dict for users.

    Public API — used by auth_routes.py.
    """
    result = {
        "user_id": row["user_id"],
        "display_name": row["display_name"],
        "pin_hash": row["pin_hash"],
        "is_active": row["is_active"],
        "created_at": _dt_to_iso(row["created_at"]) or _now_iso(),
    }
    # Multi-user columns (may not exist on older in-memory dicts)
    for col in ("role", "trust_level", "sessions_invalidated_at"):
        try:
            result[col] = row[col]
        except (KeyError, TypeError):
            logger.debug(
                "user_from_row: KeyError | TypeError suppressed",
                extra={"event": "store.user_from_row.suppressed"},
                exc_info=True,
            )
    return result
