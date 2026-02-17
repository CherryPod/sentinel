"""CRUD store for the contact registry (users, contacts, contact_channels).

PostgreSQL-backed via asyncpg.  When pool=None, falls back to in-memory
dicts for tests.  Resolves human names to channel identifiers (Signal UUIDs,
Telegram chat IDs, email addresses) without leaking PII to the planner.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.contacts.store")


def _resolve_user_id(user_id: int | None) -> int:
    """Resolve user_id from explicit param or ContextVar. No fallback to 1."""
    if user_id is not None:
        return user_id
    return current_user_id.get()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── Updatable field whitelists ────────────────────────────────────

_USER_UPDATABLE = {"display_name", "pin_hash", "is_active", "role", "trust_level", "sessions_invalidated_at"}
_CONTACT_UPDATABLE = {"display_name", "linked_user_id", "is_user"}
_CHANNEL_UPDATABLE = {"channel", "identifier", "is_default"}


class ContactStore:
    """CRUD operations for users, contacts, and contact_channels tables."""

    def __init__(self, pool: Any = None):
        self._pool = pool
        # In-memory fallback for tests — keyed by integer IDs
        self._users: dict[int, dict] = {}
        self._contacts: dict[int, dict] = {}
        self._channels: dict[int, dict] = {}
        # Auto-increment counters for in-memory mode
        self._next_user_id = 1
        self._next_contact_id = 1
        self._next_channel_id = 1

    # ── Users ─────────────────────────────────────────────────────

    async def create_user(
        self, display_name: str, pin_hash: str | None = None,
    ) -> dict:
        """Create a new system user. Returns the user dict."""
        now = _now_iso()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO users (display_name, pin_hash) "
                    "VALUES ($1, $2) RETURNING *",
                    display_name, pin_hash,
                )
                return _user_from_row(row)

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
                    "SELECT * FROM users WHERE user_id = $1", user_id,
                )
                return _user_from_row(row) if row else None

        user = self._users.get(user_id)
        return dict(user) if user else None

    async def list_users(self, active_only: bool = True) -> list[dict]:
        """List all users, optionally filtered to active only."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if active_only:
                    rows = await conn.fetch(
                        "SELECT * FROM users WHERE is_active = TRUE "
                        "ORDER BY user_id",
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT * FROM users ORDER BY user_id",
                    )
                return [_user_from_row(r) for r in rows]

        users = list(self._users.values())
        if active_only:
            users = [u for u in users if u["is_active"]]
        users.sort(key=lambda u: u["user_id"])
        return [dict(u) for u in users]

    async def update_user(self, user_id: int, **fields: Any) -> dict | None:
        """Update user fields. Returns updated user or None if not found."""
        bad = set(fields) - _USER_UPDATABLE
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
                    f"UPDATE users SET {', '.join(set_parts)} "
                    f"WHERE user_id = ${len(values)} RETURNING *",
                    *values,
                )
                return _user_from_row(row) if row else None

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
                    "SELECT trust_level FROM users WHERE user_id = $1", user_id,
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
                    "SELECT role FROM users WHERE user_id = $1", user_id,
                )
                return row["role"] if row else None

        user = self._users.get(user_id)
        if user is None:
            return None
        return user.get("role", "user")

    async def deactivate_user(self, user_id: int) -> bool:
        """Soft-disable a user. Returns True if the user existed."""
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

    # ── Contacts ──────────────────────────────────────────────────

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
        now = _now_iso()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO contacts "
                    "(user_id, display_name, linked_user_id, is_user) "
                    "VALUES ($1, $2, $3, $4) RETURNING *",
                    user_id, display_name, linked_user_id, is_user,
                )
                return _contact_from_row(row)

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
        self, contact_id: int, user_id: int | None = None,
    ) -> dict | None:
        """Get a contact by ID. Filters by user_id (belt and suspenders over RLS).
        Returns None if not found or belongs to a different user."""
        uid = _resolve_user_id(user_id)
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM contacts "
                    "WHERE contact_id = $1 AND user_id = $2",
                    contact_id, uid,
                )
                return _contact_from_row(row) if row else None

        contact = self._contacts.get(contact_id)
        if contact is None or contact["user_id"] != uid:
            return None
        return dict(contact)

    async def list_contacts(self, user_id: int) -> list[dict]:
        """List all contacts belonging to a user."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM contacts WHERE user_id = $1 "
                    "ORDER BY display_name",
                    user_id,
                )
                return [_contact_from_row(r) for r in rows]

        contacts = [
            c for c in self._contacts.values() if c["user_id"] == user_id
        ]
        contacts.sort(key=lambda c: c["display_name"])
        return [dict(c) for c in contacts]

    async def update_contact(
        self, contact_id: int, user_id: int | None = None, **fields: Any,
    ) -> dict | None:
        """Update contact fields. Filters by user_id (belt and suspenders over RLS).
        Returns updated contact or None if not found/wrong user."""
        bad = set(fields) - _CONTACT_UPDATABLE
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
                    f"UPDATE contacts SET {', '.join(set_parts)} "
                    f"WHERE contact_id = ${len(values) - 1} "
                    f"AND user_id = ${len(values)} RETURNING *",
                    *values,
                )
                return _contact_from_row(row) if row else None

        contact = self._contacts.get(contact_id)
        if contact is None or contact["user_id"] != uid:
            return None
        for k, v in fields.items():
            contact[k] = v
        return dict(contact)

    async def delete_contact(
        self, contact_id: int, user_id: int | None = None,
    ) -> bool:
        """Delete a contact and its channels (cascade). Filters by user_id
        (belt and suspenders over RLS). Returns True if existed and belonged
        to the user."""
        uid = _resolve_user_id(user_id)
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM contacts "
                    "WHERE contact_id = $1 AND user_id = $2",
                    contact_id, uid,
                )
                return result == "DELETE 1"

        # In-memory: check ownership then cascade to channels
        contact = self._contacts.get(contact_id)
        if contact is None or contact["user_id"] != uid:
            return False
        del self._contacts[contact_id]
        orphan_ids = [
            ch_id for ch_id, ch in self._channels.items()
            if ch["contact_id"] == contact_id
        ]
        for ch_id in orphan_ids:
            del self._channels[ch_id]
        return True

    # ── Contact Channels ──────────────────────────────────────────

    async def create_channel(
        self,
        contact_id: int,
        channel: str,
        identifier: str,
        is_default: bool = True,
    ) -> dict:
        """Add a channel identifier to a contact. Returns the channel dict.

        Raises on duplicate (channel, identifier) — each identifier is globally
        unique per channel type (e.g. one Signal UUID maps to exactly one contact).
        """
        now = _now_iso()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO contact_channels "
                    "(contact_id, channel, identifier, is_default) "
                    "VALUES ($1, $2, $3, $4) RETURNING *",
                    contact_id, channel, identifier, is_default,
                )
                return _channel_from_row(row)

        # In-memory: enforce UNIQUE(channel, identifier)
        for ch in self._channels.values():
            if ch["channel"] == channel and ch["identifier"] == identifier:
                raise ValueError(
                    f"Duplicate channel: channel={channel!r}, "
                    f"identifier={identifier!r}"
                )

        ch_id = self._next_channel_id
        self._next_channel_id += 1
        chan = {
            "id": ch_id,
            "contact_id": contact_id,
            "channel": channel,
            "identifier": identifier,
            "is_default": is_default,
            "created_at": now,
        }
        self._channels[ch_id] = chan
        return dict(chan)

    async def get_channels(
        self, contact_id: int, user_id: int | None = None,
    ) -> list[dict]:
        """Get all channel identifiers for a contact. Verifies parent contact
        ownership (belt and suspenders over RLS)."""
        uid = _resolve_user_id(user_id)
        # Verify parent contact belongs to user
        contact = await self.get_contact(contact_id, user_id=uid)
        if contact is None:
            return []

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM contact_channels WHERE contact_id = $1 "
                    "ORDER BY channel",
                    contact_id,
                )
                return [_channel_from_row(r) for r in rows]

        channels = [
            ch for ch in self._channels.values()
            if ch["contact_id"] == contact_id
        ]
        channels.sort(key=lambda ch: ch["channel"])
        return [dict(ch) for ch in channels]

    async def get_by_identifier(
        self, channel: str, identifier: str,
    ) -> dict | None:
        """Reverse lookup — find a contact by channel identifier.

        Called on every incoming message to resolve the sender, so this must
        be efficient. The UNIQUE(channel, identifier) index makes this O(1)
        in PostgreSQL.
        """
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT cc.*, c.user_id, c.display_name AS contact_name "
                    "FROM contact_channels cc "
                    "JOIN contacts c ON c.contact_id = cc.contact_id "
                    "WHERE cc.channel = $1 AND cc.identifier = $2",
                    channel, identifier,
                )
                if row is None:
                    return None
                result = _channel_from_row(row)
                result["user_id"] = row["user_id"]
                result["contact_name"] = row["contact_name"]
                return result

        # In-memory: linear scan (acceptable for tests)
        for ch in self._channels.values():
            if ch["channel"] == channel and ch["identifier"] == identifier:
                result = dict(ch)
                contact = self._contacts.get(ch["contact_id"])
                if contact:
                    result["user_id"] = contact["user_id"]
                    result["contact_name"] = contact["display_name"]
                return result
        return None

    async def update_channel(
        self, channel_id: int, user_id: int | None = None, **fields: Any,
    ) -> dict | None:
        """Update channel fields. Verifies parent contact ownership
        (belt and suspenders over RLS). Returns None if not found or wrong user."""
        bad = set(fields) - _CHANNEL_UPDATABLE
        if bad:
            raise ValueError(f"Invalid update fields: {bad}")
        uid = _resolve_user_id(user_id)

        # Look up the channel to get its parent contact_id
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                ch_row = await conn.fetchrow(
                    "SELECT contact_id FROM contact_channels WHERE id = $1",
                    channel_id,
                )
                if ch_row is None:
                    return None
                # Verify parent contact ownership
                contact = await self.get_contact(ch_row["contact_id"], user_id=uid)
                if contact is None:
                    return None
                set_parts, values = [], []
                for i, (k, v) in enumerate(fields.items(), 1):
                    set_parts.append(f"{k} = ${i}")
                    values.append(v)
                values.append(channel_id)
                row = await conn.fetchrow(
                    f"UPDATE contact_channels SET {', '.join(set_parts)} "
                    f"WHERE id = ${len(values)} RETURNING *",
                    *values,
                )
                return _channel_from_row(row) if row else None

        ch = self._channels.get(channel_id)
        if ch is None:
            return None
        # Verify parent contact ownership
        contact = self._contacts.get(ch["contact_id"])
        if contact is None or contact["user_id"] != uid:
            return None
        for k, v in fields.items():
            ch[k] = v
        return dict(ch)

    async def delete_channel(
        self, channel_id: int, user_id: int | None = None,
    ) -> bool:
        """Delete a single channel identifier. Verifies parent contact ownership
        (belt and suspenders over RLS). Returns False if not found or wrong user."""
        uid = _resolve_user_id(user_id)

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                ch_row = await conn.fetchrow(
                    "SELECT contact_id FROM contact_channels WHERE id = $1",
                    channel_id,
                )
                if ch_row is None:
                    return False
                # Verify parent contact ownership
                contact = await self.get_contact(ch_row["contact_id"], user_id=uid)
                if contact is None:
                    return False
                result = await conn.execute(
                    "DELETE FROM contact_channels WHERE id = $1", channel_id,
                )
                return result == "DELETE 1"

        ch = self._channels.get(channel_id)
        if ch is None:
            return False
        # Verify parent contact ownership
        contact = self._contacts.get(ch["contact_id"])
        if contact is None or contact["user_id"] != uid:
            return False
        del self._channels[channel_id]
        return True


# ── Row conversion helpers ────────────────────────────────────────


def _user_from_row(row: Any) -> dict:
    """Convert an asyncpg Record to a plain dict for users."""
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
            pass
    return result


def _contact_from_row(row: Any) -> dict:
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
        result["is_system"] = False
    return result


def _channel_from_row(row: Any) -> dict:
    """Convert an asyncpg Record to a plain dict for contact_channels."""
    return {
        "id": row["id"],
        "contact_id": row["contact_id"],
        "channel": row["channel"],
        "identifier": row["identifier"],
        "is_default": row["is_default"],
        "created_at": _dt_to_iso(row["created_at"]) or _now_iso(),
    }
