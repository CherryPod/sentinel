"""Channel CRUD mixin for ContactStore with encryption.

Provides ChannelStoreMixin with all contact_channels table operations,
decrypt/audit helpers, and channel_from_row() — the row-conversion helper.

Channel identifiers are encrypted at rest with HKDF per-record key
derivation, AAD binding, and HMAC blind indexes.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.contacts._channel_crypto import (
    compute_channel_hmac,
    decrypt_channel_identifier,
    encrypt_channel_identifier,
)
from sentinel.contacts._rows import (
    CHANNEL_UPDATABLE,
    _dt_to_iso,
    _now_iso,
    _resolve_user_id,
)
from sentinel.crypto.store_mixin import CryptoAuditMixin

logger = logging.getLogger(__name__)


class ChannelStoreMixin(CryptoAuditMixin):
    """Channel CRUD with encryption.

    Expects on self (set by ContactStore.__init__):
    - _pool: asyncpg.Pool | None
    - _channels: dict[int, dict]  (in-memory fallback)
    - _next_channel_id: int  (in-memory auto-increment)
    - _master_key: bytes
    - _key_version: int
    - _audit_emitter: AuditEmitter | None

    Inherits _emit_crypto_event() from CryptoAuditMixin.
    Cross-mixin: calls self.get_contact() from ContactStoreMixin for ownership checks.
    In-memory paths also access self._contacts dict directly for lookups.
    """

    # ── Audit wrappers ───────────────────────────────────────────

    async def _emit_channel_crypto(
        self,
        event_type: str,
        channel_id: int,
        channel: str,
        *,
        outcome: str = "SUCCESS",
        severity: str = "INFO",
    ) -> None:
        """Channel-specific crypto audit wrapper."""
        await self._emit_crypto_event(
            event_type,
            table="contact_channels",
            field="encrypted_identifier",
            record_id=str(channel_id),
            outcome=outcome,
            severity=severity,
        )

    # ── Decrypt helpers ──────────────────────────────────────────

    async def _decrypt_and_audit(self, row: dict) -> dict:
        """Decrypt a single channel row with audit event emission.

        Emits decrypt on success, decrypt_failed on failure.
        """
        from sentinel.core.exceptions import DecryptionError

        try:
            result = self._decrypt_channel_row(row)
            await self._emit_channel_crypto("crypto.decrypt", row["id"], row["channel"])
            return result
        except DecryptionError:
            logger.warning(
                "Channel decryption failed",
                extra={
                    "event": "store.decrypt_failed",
                    "channel_id": row["id"],
                    "channel": row["channel"],
                },
                exc_info=True,
            )
            await self._emit_channel_crypto(
                "crypto.decrypt_failed",
                row["id"],
                row["channel"],
                outcome="FAILED",
                severity="HIGH",
            )
            raise

    async def _decrypt_channel_rows(self, rows: list[dict]) -> list[dict]:
        """Decrypt a list of channel dicts, emitting audit events."""
        return [await self._decrypt_and_audit(row) for row in rows]

    def _decrypt_channel_row(self, row: dict) -> dict:
        """Decrypt encrypted_identifier and populate ``identifier`` in the dict."""
        row["identifier"] = decrypt_channel_identifier(
            self._master_key,
            row["encrypted_identifier"],
            row["identifier_salt"],
            row["id"],
            row["channel"],
        )
        return row

    # ── Channel CRUD ─────────────────────────────────────────────

    async def create_channel(
        self,
        contact_id: int,
        channel: str,
        identifier: str,
        is_default: bool = True,
    ) -> dict:
        """Add a channel identifier to a contact. Returns the channel dict.

        Encrypts the identifier and computes an HMAC blind index.
        Raises on duplicate (channel, identifier_hmac) — each identifier is
        globally unique per channel type.
        """
        logger.debug(
            "create_channel called",
            extra={
                "event": "store.create_channel",
                "contact_id": contact_id,
                "channel": channel,
            },
        )
        if self._pool is not None:
            return await self._create_channel_pg(
                contact_id,
                channel,
                identifier,
                is_default,
            )
        return await self._create_channel_mem(
            contact_id,
            channel,
            identifier,
            is_default,
        )

    async def _create_channel_pg(
        self,
        contact_id: int,
        channel: str,
        identifier: str,
        is_default: bool,
    ) -> dict:
        """PostgreSQL insert path with encryption and HMAC."""
        logger.debug(
            "_create_channel_pg called",
            extra={"event": "store._create_channel_pg", "contact_id": contact_id},
        )
        async with self._pool.acquire() as conn:
            # Get the next channel ID for AAD before inserting
            seq_row = await conn.fetchrow(
                "SELECT nextval('contact_channels_id_seq')",
            )
            ch_id = seq_row["nextval"]
            # Encrypt with AAD bound to the assigned row ID
            encrypted, salt = encrypt_channel_identifier(
                self._master_key,
                identifier,
                ch_id,
                channel,
            )
            hmac_value = compute_channel_hmac(
                self._master_key,
                self._key_version,
                identifier,
            )
            row = await conn.fetchrow(
                "INSERT INTO contact_channels "
                "(id, contact_id, channel, encrypted_identifier, "
                "identifier_salt, identifier_hmac, key_version, is_default) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
                ch_id,
                contact_id,
                channel,
                encrypted,
                salt,
                hmac_value,
                self._key_version,
                is_default,
            )
            result = channel_from_row(row)
            result["identifier"] = identifier
            await self._emit_channel_crypto(
                "crypto.encrypt",
                ch_id,
                channel,
            )
            return result

    async def _create_channel_mem(
        self,
        contact_id: int,
        channel: str,
        identifier: str,
        is_default: bool,
    ) -> dict:
        """In-memory insert path with encryption and HMAC."""
        logger.debug(
            "_create_channel_mem called",
            extra={"event": "store._create_channel_mem", "contact_id": contact_id},
        )
        now = _now_iso()
        # Enforce UNIQUE(channel, identifier) via HMAC
        hmac_value = compute_channel_hmac(
            self._master_key,
            self._key_version,
            identifier,
        )
        for ch in self._channels.values():
            if ch["channel"] == channel and ch["identifier_hmac"] == hmac_value:
                raise ValueError(
                    f"Duplicate channel: channel={channel!r}, identifier={identifier!r}"
                )

        ch_id = self._next_channel_id
        self._next_channel_id += 1

        # Encrypt identifier and compute HMAC blind index
        encrypted, salt = encrypt_channel_identifier(
            self._master_key,
            identifier,
            ch_id,
            channel,
        )

        chan = {
            "id": ch_id,
            "contact_id": contact_id,
            "channel": channel,
            "encrypted_identifier": encrypted,
            "identifier_salt": salt,
            "identifier_hmac": hmac_value,
            "key_version": self._key_version,
            "is_default": is_default,
            "created_at": now,
        }
        self._channels[ch_id] = chan
        await self._emit_channel_crypto(
            "crypto.encrypt",
            ch_id,
            channel,
        )
        # Return with decrypted identifier for caller convenience
        result = dict(chan)
        result["identifier"] = identifier
        return result

    async def get_channels(
        self,
        contact_id: int,
        user_id: int | None = None,
    ) -> list[dict]:
        """Get all channel identifiers for a contact. Verifies parent contact
        ownership (belt and suspenders over RLS)."""
        logger.debug(
            "get_channels called",
            extra={
                "event": "store.get_channels",
                "contact_id": contact_id,
                "user_id": user_id,
            },
        )
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
                return await self._decrypt_channel_rows(
                    [channel_from_row(r) for r in rows]
                )

        channels = [
            ch for ch in self._channels.values() if ch["contact_id"] == contact_id
        ]
        channels.sort(key=lambda ch: ch["channel"])
        return await self._decrypt_channel_rows([dict(ch) for ch in channels])

    async def get_by_identifier(
        self,
        channel: str,
        identifier: str,
    ) -> dict | None:
        """Reverse lookup — find a contact by channel identifier via HMAC.

        Called on every incoming message to resolve the sender, so this must
        be efficient.  Uses the HMAC blind index for O(1) lookup in PostgreSQL
        without exposing plaintext to the query.
        """
        identifier_hmac = compute_channel_hmac(
            self._master_key,
            self._key_version,
            identifier,
        )
        logger.debug(
            "get_by_identifier called",
            extra={
                "event": "store.get_by_identifier",
                "channel": channel,
                "identifier_hmac_len": len(identifier_hmac),
            },
        )
        if self._pool is not None:
            return await self._get_by_identifier_pg(channel, identifier_hmac)
        return await self._get_by_identifier_mem(channel, identifier_hmac)

    async def _get_by_identifier_pg(
        self,
        channel: str,
        identifier_hmac: bytes,
    ) -> dict | None:
        """PostgreSQL HMAC lookup path."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT cc.*, c.user_id, c.display_name AS contact_name "
                "FROM contact_channels cc "
                "JOIN contacts c ON c.contact_id = cc.contact_id "
                "WHERE cc.channel = $1 AND cc.identifier_hmac = $2",
                channel,
                identifier_hmac,
            )
            if row is None:
                logger.debug(
                    "get_by_identifier: no match",
                    extra={
                        "event": "store.get_by_identifier.not_found",
                        "channel": channel,
                    },
                )
                return None
            result = channel_from_row(row)
            result["user_id"] = row["user_id"]
            result["contact_name"] = row["contact_name"]
            return await self._decrypt_and_audit(result)

    async def _get_by_identifier_mem(
        self,
        channel: str,
        identifier_hmac: bytes,
    ) -> dict | None:
        """In-memory HMAC scan path (acceptable for tests)."""
        for ch in self._channels.values():
            if (
                ch["channel"] == channel
                and ch.get("identifier_hmac") == identifier_hmac
            ):
                result = dict(ch)
                result = await self._decrypt_and_audit(result)
                contact = self._contacts.get(ch["contact_id"])
                if contact:
                    result["user_id"] = contact["user_id"]
                    result["contact_name"] = contact["display_name"]
                return result
        logger.debug(
            "get_by_identifier: no match",
            extra={"event": "store.get_by_identifier.not_found", "channel": channel},
        )
        return None

    async def update_channel(
        self,
        channel_id: int,
        user_id: int | None = None,
        **fields: Any,
    ) -> dict | None:
        """Update channel fields. Public entry point — validates and dispatches.

        Verifies parent contact ownership (belt and suspenders over RLS).
        Returns None if not found or wrong user.
        If ``identifier`` is updated, re-encrypts and recomputes HMAC.
        """
        logger.debug(
            "update_channel called",
            extra={
                "event": "store.update_channel",
                "channel_id": channel_id,
                "user_id": user_id,
            },
        )
        bad = set(fields) - CHANNEL_UPDATABLE
        if bad:
            logger.debug(
                "update_channel: invalid fields",
                extra={
                    "event": "store.update_channel.invalid_fields",
                    "fields": list(bad),
                },
            )
            raise ValueError(f"Invalid update fields: {bad}")
        logger.debug(
            "update_channel: fields validated",
            extra={"event": "store.update_channel.validated", "channel_id": channel_id},
        )
        uid = _resolve_user_id(user_id)
        if self._pool is not None:
            return await self._update_channel_pg(channel_id, uid, fields)
        return await self._update_channel_mem(channel_id, uid, fields)

    async def _update_channel_pg(
        self,
        channel_id: int,
        uid: int,
        fields: dict,
    ) -> dict | None:
        """PostgreSQL update path with optional re-encryption."""
        logger.debug(
            "_update_channel_pg called",
            extra={"event": "store._update_channel_pg", "channel_id": channel_id},
        )
        async with self._pool.acquire() as conn:
            ch_row = await conn.fetchrow(
                "SELECT contact_id, channel FROM contact_channels WHERE id = $1",
                channel_id,
            )
            if ch_row is None:
                return None
            # Verify parent contact ownership
            contact = await self.get_contact(ch_row["contact_id"], user_id=uid)
            if contact is None:
                return None
            set_parts, values = [], []
            # Build SET clause — skip "identifier" (handled via crypto below)
            for k, v in fields.items():
                if k != "identifier":
                    set_parts.append(f"{k} = ${len(values) + 1}")
                    values.append(v)
            # Re-encrypt if identifier changed
            if "identifier" in fields:
                logger.debug(
                    "_update_channel_pg: re-encrypting",
                    extra={
                        "event": "store._update_channel_pg.reencrypt",
                        "channel_id": channel_id,
                    },
                )
                new_id = fields["identifier"]
                ch_type = fields.get("channel", ch_row["channel"])
                encrypted, salt = encrypt_channel_identifier(
                    self._master_key,
                    new_id,
                    channel_id,
                    ch_type,
                )
                hmac_value = compute_channel_hmac(
                    self._master_key,
                    self._key_version,
                    new_id,
                )
                for col, val in (
                    ("encrypted_identifier", encrypted),
                    ("identifier_salt", salt),
                    ("identifier_hmac", hmac_value),
                    ("key_version", self._key_version),
                ):
                    set_parts.append(f"{col} = ${len(values) + 1}")
                    values.append(val)
            values.append(channel_id)
            row = await conn.fetchrow(
                f"UPDATE contact_channels SET {', '.join(set_parts)} "  # nosec B608 — column names from CHANNEL_UPDATABLE constant + crypto columns; values parameterised via asyncpg
                f"WHERE id = ${len(values)} RETURNING *",
                *values,
            )
            if row is None:
                return None
            result = channel_from_row(row)
            if "identifier" in fields:
                logger.debug(
                    "_update_channel_pg: identifier updated",
                    extra={
                        "event": "store._update_channel_pg.identifier_updated",
                        "channel_id": channel_id,
                    },
                )
                await self._emit_channel_crypto(
                    "crypto.encrypt",
                    channel_id,
                    ch_row["channel"],
                )
                result["identifier"] = fields["identifier"]
            else:
                logger.debug(
                    "_update_channel_pg: no identifier change",
                    extra={
                        "event": "store._update_channel_pg.no_identifier_change",
                        "channel_id": channel_id,
                    },
                )
                result = self._decrypt_channel_row(result)
            return result

    async def _update_channel_mem(
        self,
        channel_id: int,
        uid: int,
        fields: dict,
    ) -> dict | None:
        """In-memory update path with optional re-encryption."""
        logger.debug(
            "_update_channel_mem called",
            extra={"event": "store._update_channel_mem", "channel_id": channel_id},
        )
        ch = self._channels.get(channel_id)
        if ch is None:
            return None
        # Verify parent contact ownership
        contact = self._contacts.get(ch["contact_id"])
        if contact is None or contact["user_id"] != uid:
            return None
        # Apply non-identifier fields directly
        for k, v in fields.items():
            if k == "identifier":
                continue
            ch[k] = v
        # Re-encrypt if identifier changed
        new_identifier = fields.get("identifier")
        if new_identifier is not None:
            ch_type = ch["channel"]
            encrypted, salt = encrypt_channel_identifier(
                self._master_key,
                new_identifier,
                channel_id,
                ch_type,
            )
            ch["encrypted_identifier"] = encrypted
            ch["identifier_salt"] = salt
            ch["identifier_hmac"] = compute_channel_hmac(
                self._master_key,
                self._key_version,
                new_identifier,
            )
            ch["key_version"] = self._key_version
            await self._emit_channel_crypto(
                "crypto.encrypt",
                channel_id,
                ch_type,
            )
        # Return with decrypted identifier
        result = dict(ch)
        result["identifier"] = new_identifier or decrypt_channel_identifier(
            self._master_key,
            ch["encrypted_identifier"],
            ch["identifier_salt"],
            channel_id,
            ch["channel"],
        )
        return result

    async def delete_channel(
        self,
        channel_id: int,
        user_id: int | None = None,
    ) -> bool:
        """Delete a single channel identifier. Verifies parent contact ownership
        (belt and suspenders over RLS). Returns False if not found or wrong user."""
        logger.debug(
            "delete_channel called",
            extra={
                "event": "store.delete_channel",
                "channel_id": channel_id,
                "user_id": user_id,
            },
        )
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
                    "DELETE FROM contact_channels WHERE id = $1",
                    channel_id,
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


# ── Row conversion ───────────────────────────────────────────────


def channel_from_row(row: Any) -> dict:
    """Convert an asyncpg Record to a plain dict for contact_channels.

    Does NOT include ``identifier`` — that is populated by
    ``_decrypt_channel_row()`` after decryption.
    """
    result = {
        "id": row["id"],
        "contact_id": row["contact_id"],
        "channel": row["channel"],
        "is_default": row["is_default"],
        "created_at": _dt_to_iso(row["created_at"]) or _now_iso(),
    }
    # Crypto columns — always present after Phase 6
    for col in (
        "encrypted_identifier",
        "identifier_salt",
        "identifier_hmac",
        "key_version",
    ):
        val = row[col]
        # Convert memoryview to bytes (asyncpg returns memoryview for BYTEA)
        result[col] = bytes(val) if isinstance(val, (memoryview, bytes)) else val
    return result
