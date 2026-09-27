"""Contact CRUD mixin for ContactStore.

Provides ContactStoreMixin with all contact table operations, plus
contact_from_row() — the row-conversion helper.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.contacts._rows import (
    CONTACT_UPDATABLE,
    _dt_to_iso,
    _now_iso,
    _resolve_user_id,
)
from sentinel.core.context import require_user_id

logger = logging.getLogger(__name__)


class ContactStoreMixin:
    """Contact CRUD operations.

    Expects on self (set by ContactStore.__init__):
    - _pool: asyncpg.Pool | None
    - _contacts: dict[int, dict]  (in-memory fallback)
    - _next_contact_id: int  (in-memory auto-increment)
    - _channels: dict[int, dict]  (for cascade delete in in-memory mode)
    """

    async def create_contact(
        self,
        user_id: int,
        display_name: str,
        linked_user_id: int | None = None,
        is_user: bool = False,
    ) -> dict:
        """Create a contact in a user's address book. Returns the contact dict.

        Raises on duplicate (user_id, display_name) — enforced by DB constraint
        and replicated in-memory.
        """
        user_id = require_user_id(user_id, "ContactStoreMixin.create_contact")
        logger.debug(
            "create_contact called",
            extra={
                "event": "store.create_contact",
                "user_id": user_id,
                "display_name_len": len(display_name) if display_name else 0,
                "linked_user_id": linked_user_id,
            },
        )
        now = _now_iso()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO contacts "
                    "(user_id, display_name, linked_user_id, is_user) "
                    "VALUES ($1, $2, $3, $4) RETURNING *",
                    user_id,
                    display_name,
                    linked_user_id,
                    is_user,
                )
                return contact_from_row(row)

        # In-memory: enforce UNIQUE(user_id, display_name)
        for c in self._contacts.values():
            if c["user_id"] == user_id and c["display_name"] == display_name:
                raise ValueError(
                    f"Duplicate contact: user_id={user_id}, "
                    f"display_name={display_name!r}"
                )

        cid = self._next_contact_id
        self._next_contact_id += 1
        contact = {
            "contact_id": cid,
            "user_id": user_id,
            "display_name": display_name,
            "linked_user_id": linked_user_id,
            "is_user": is_user,
            "created_at": now,
        }
        self._contacts[cid] = contact
        return dict(contact)

    async def get_contact(
        self,
        contact_id: int,
        user_id: int | None = None,
    ) -> dict | None:
        """Get a contact by ID. Filters by user_id (belt and suspenders over RLS).
        Returns None if not found or belongs to a different user."""
        logger.debug(
            "get_contact called",
            extra={
                "event": "store.get_contact",
                "contact_id": contact_id,
                "user_id": user_id,
            },
        )
        uid = _resolve_user_id(user_id)
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM contacts WHERE contact_id = $1 AND user_id = $2",
                    contact_id,
                    uid,
                )
                return contact_from_row(row) if row else None

        contact = self._contacts.get(contact_id)
        if contact is None or contact["user_id"] != uid:
            return None
        return dict(contact)

    async def list_contacts(self, user_id: int) -> list[dict]:
        """List all contacts belonging to a user."""
        logger.debug(
            "list_contacts called",
            extra={"event": "contacts.contacts.list_contacts", "user_id": user_id},
        )  # auto:entry
        user_id = require_user_id(user_id, "ContactStoreMixin.list_contacts")
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM contacts WHERE user_id = $1 ORDER BY display_name",
                    user_id,
                )
                return [contact_from_row(r) for r in rows]

        contacts = [c for c in self._contacts.values() if c["user_id"] == user_id]
        contacts.sort(key=lambda c: c["display_name"])
        return [dict(c) for c in contacts]

    async def update_contact(
        self,
        contact_id: int,
        user_id: int | None = None,
        **fields: Any,
    ) -> dict | None:
        """Update contact fields. Filters by user_id (belt and suspenders over RLS).
        Returns updated contact or None if not found/wrong user."""
        logger.debug(
            "update_contact called",
            extra={
                "event": "store.update_contact",
                "contact_id": contact_id,
                "user_id": user_id,
            },
        )
        bad = set(fields) - CONTACT_UPDATABLE
        if bad:
            raise ValueError(f"Invalid update fields: {bad}")
        uid = _resolve_user_id(user_id)

        if self._pool is not None:
            set_parts, values = [], []
            for i, (k, v) in enumerate(fields.items(), 1):
                set_parts.append(f"{k} = ${i}")
                values.append(v)
            values.append(contact_id)
            values.append(uid)
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    f"UPDATE contacts SET {', '.join(set_parts)} "  # nosec B608 — column names from CONTACT_UPDATABLE constant; values parameterised via asyncpg
                    f"WHERE contact_id = ${len(values) - 1} "
                    f"AND user_id = ${len(values)} RETURNING *",
                    *values,
                )
                return contact_from_row(row) if row else None

        contact = self._contacts.get(contact_id)
        if contact is None or contact["user_id"] != uid:
            return None
        for k, v in fields.items():
            contact[k] = v
        return dict(contact)

    async def delete_contact(
        self,
        contact_id: int,
        user_id: int | None = None,
    ) -> bool:
        """Delete a contact and its channels (cascade). Filters by user_id
        (belt and suspenders over RLS). Returns True if existed and belonged
        to the user.

        Note: accesses self._channels for in-memory cascade —
        attribute owned by ChannelStoreMixin on the composed ContactStore.
        """
        logger.debug(
            "delete_contact called",
            extra={
                "event": "store.delete_contact",
                "contact_id": contact_id,
                "user_id": user_id,
            },
        )
        uid = _resolve_user_id(user_id)
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM contacts WHERE contact_id = $1 AND user_id = $2",
                    contact_id,
                    uid,
                )
                return result == "DELETE 1"

        # In-memory: check ownership then cascade to channels
        contact = self._contacts.get(contact_id)
        if contact is None or contact["user_id"] != uid:
            return False
        del self._contacts[contact_id]
        orphan_ids = [
            ch_id
            for ch_id, ch in self._channels.items()
            if ch["contact_id"] == contact_id
        ]
        for ch_id in orphan_ids:
            del self._channels[ch_id]
        return True


# ── Row conversion ───────────────────────────────────────────────


def contact_from_row(row: Any) -> dict:
    """Convert an asyncpg Record to a plain dict for contacts."""
    result = {
        "contact_id": row["contact_id"],
        "user_id": row["user_id"],
        "display_name": row["display_name"],
        "linked_user_id": row["linked_user_id"],
        "is_user": row["is_user"],
        "created_at": _dt_to_iso(row["created_at"]) or _now_iso(),
    }
    try:
        result["is_system"] = row["is_system"]
    except (KeyError, TypeError):
        logger.debug(
            "contact_from_row: is_system column missing (older record)",
            extra={"event": "store.contact_from_row.is_system_fallback"},
            exc_info=True,
        )
        result["is_system"] = False
    return result
