"""Per-user credential storage with AES-256-GCM encryption.

Stores encrypted service credentials (IMAP, SMTP, CalDAV, etc.) per user.
HKDF per-record key derivation with AAD binding.

Each credential record stores:
- encrypted_value: nonce || ciphertext (AES-256-GCM with HKDF-derived DEK)
- field_salt: 16-byte random salt for HKDF key derivation
- key_version: which master key version was used
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinel.core.context import require_user_id
from sentinel.core.decorators import no_audit_log
from sentinel.core.exceptions import DecryptionError
from sentinel.crypto.cipher import decrypt_field, encrypt_field_with_salt
from sentinel.crypto.keys import get_master_key
from sentinel.crypto.store_mixin import CryptoAuditMixin

logger = logging.getLogger(__name__)

# C74 Inv-3-app: legacy direct-construction / test-only fallback path.
# Production wiring (sentinel/api/init/orchestrator.py) MUST pass
# ``key_path=settings.crypto_key_path`` AND
# ``require_production_key=settings.crypto_require_production_key``
# explicitly per Inv-3-app.  Direct-construction with this constant
# fallback is preserved for test-fixture convenience but should not be
# used in production code paths — production-policy enforcement happens
# at the boot-wiring layer via init_orchestrator, not here.
_KEY_PATH = "/run/secrets/credential_key"
_AES_KEY_BYTES = 32
_GCM_NONCE_BYTES = 12
_MIN_BLOB_BYTES = _GCM_NONCE_BYTES + 1  # nonce + at least 1 byte ciphertext
_DEFAULT_KEY_VERSION = 1

# AAD format: binds ciphertext to a specific user+service record
_AAD_TEMPLATE = "user_credentials:{uid}:{service}"

# Sensitive fields that are masked in GET responses
_SENSITIVE_FIELDS = {"password", "secret", "token", "api_key", "private_key"}


def generate_key() -> bytes:
    """Generate a new random 32-byte AES-256 key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_credentials(data: dict, key: bytes) -> bytes:
    """Encrypt a credential dict to bytes using AES-256-GCM (single-key, used by tests).

    Format: nonce (12 bytes) + ciphertext (variable length).
    """
    nonce = os.urandom(_GCM_NONCE_BYTES)
    plaintext = json.dumps(data).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_credentials(blob: bytes, key: bytes) -> dict:
    """Decrypt credential bytes back to a dict (single-key, used by migration).

    Raises DecryptionError on failure (wrong key, corrupted data).
    """
    if len(blob) < _MIN_BLOB_BYTES:
        raise DecryptionError("Encrypted data too short")
    nonce, ct = blob[:_GCM_NONCE_BYTES], blob[_GCM_NONCE_BYTES:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError(f"Decryption failed: {exc}") from exc
    return json.loads(plaintext)


def mask_sensitive(data: dict) -> dict:
    """Return a copy with sensitive fields replaced by '***'."""
    return {k: "***" if k in _SENSITIVE_FIELDS else v for k, v in data.items()}


def _build_aad(user_id: int, service: str) -> bytes:
    """Build AAD bytes that bind ciphertext to its record context."""
    return _AAD_TEMPLATE.format(uid=user_id, service=service).encode()


class CredentialStore(CryptoAuditMixin):
    """CRUD operations for per-user encrypted credentials.

    When pool=None, falls back to in-memory dict for tests.

    Supports two construction modes:
    - key=<bytes>: use a specific key directly (tests)
    - key_path=<str>: load master key from file via crypto.keys module
    """

    def __init__(
        self,
        pool: Any = None,
        key: bytes | None = None,
        *,
        key_path: str | None = None,
        require_production_key: bool = False,
        key_version: int = _DEFAULT_KEY_VERSION,
        audit_emitter: Any | None = None,
    ) -> None:
        if key is not None:
            self._key = key
        elif key_path is not None:
            self._key = get_master_key(
                key_path, require_production=require_production_key
            )
        else:
            # Legacy default: load from standard Podman secret path
            self._key = get_master_key(
                _KEY_PATH, require_production=require_production_key
            )

        self._pool = pool
        self._key_version = key_version
        self._audit_emitter = audit_emitter
        # In-memory fallback: {(user_id, service): (blob, salt, key_version)}
        self._mem: dict[tuple[int, str], tuple[bytes, bytes, int]] = {}

    @no_audit_log  # parameters include key material via self._key
    def _encrypt(self, data: dict, user_id: int, service: str) -> tuple[bytes, bytes]:
        """Encrypt credential data with HKDF-derived key and AAD.

        Returns (encrypted_blob, salt).
        """
        plaintext = json.dumps(data).encode("utf-8")
        aad = _build_aad(user_id, service)
        blob, salt = encrypt_field_with_salt(self._key, plaintext, aad)
        return blob, salt

    @no_audit_log  # parameters include key material via self._key
    def _decrypt(
        self, entry: tuple[bytes, bytes, int], user_id: int, service: str
    ) -> dict:
        """Decrypt a credential entry using HKDF-derived key with AAD verification."""
        blob, salt, _key_ver = entry
        aad = _build_aad(user_id, service)
        plaintext = decrypt_field(self._key, salt, blob, aad)
        return json.loads(plaintext)

    async def _emit_credential_crypto(
        self,
        event_type: str,
        user_id: int,
        service: str,
        *,
        outcome: str = "SUCCESS",
        severity: str = "INFO",
    ) -> None:
        """Credential-specific crypto audit wrapper."""
        await self._emit_crypto_event(
            event_type,
            table="user_credentials",
            field="encrypted_value",
            record_id=f"{user_id}:{service}",
            outcome=outcome,
            severity=severity,
        )

    async def set(self, service: str, data: dict, user_id: int | None = None) -> None:
        """Encrypt and store (upsert) credentials for a service."""
        uid = require_user_id(user_id, "CredentialStore.set")
        logger.debug(
            "Storing credentials",
            extra={"event": "credential_store.set", "service": service, "user_id": uid},
        )
        blob, salt = self._encrypt(data, uid, service)

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO user_credentials "
                    "(user_id, service, encrypted_value, field_salt, key_version) "
                    "VALUES ($1, $2, $3, $4, $5) "
                    "ON CONFLICT (user_id, service) DO UPDATE SET "
                    "encrypted_value = $3, field_salt = $4, key_version = $5, "
                    "updated_at = NOW()",
                    uid,
                    service,
                    blob,
                    salt,
                    self._key_version,
                )
                await self._emit_credential_crypto("crypto.encrypt", uid, service)
                return

        self._mem[(uid, service)] = (blob, salt, self._key_version)
        await self._emit_credential_crypto("crypto.encrypt", uid, service)

    async def get(self, service: str, user_id: int | None = None) -> dict | None:
        """Retrieve and decrypt credentials for a service. Returns None if not set."""
        logger.debug(
            "get called",
            extra={
                "event": "credential_store.get",
                "service": service,
                "user_id": user_id,
            },
        )  # auto:entry
        uid = require_user_id(user_id, "CredentialStore.get")

        if self._pool is not None:
            return await self._get_from_db(uid, service)

        entry = self._mem.get((uid, service))
        if entry is None:
            return None
        try:
            result = self._decrypt(entry, uid, service)
            await self._emit_credential_crypto("crypto.decrypt", uid, service)
            return result
        except DecryptionError:
            logger.warning(
                "Credential decryption failed",
                extra={
                    "event": "credential_store.decrypt_failed",
                    "service": service,
                    "user_id": uid,
                    "key_version": entry[2],
                },
                exc_info=True,
            )
            await self._emit_credential_crypto(
                "crypto.decrypt_failed",
                uid,
                service,
                outcome="FAILED",
                severity="HIGH",
            )
            raise

    async def _get_from_db(self, uid: int, service: str) -> dict | None:
        """Read and decrypt a credential from PostgreSQL."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT encrypted_value, field_salt, key_version "
                "FROM user_credentials "
                "WHERE user_id = $1 AND service = $2",
                uid,
                service,
            )
            if row is None:
                return None

            blob = bytes(row["encrypted_value"])
            salt = bytes(row["field_salt"])
            key_ver = row["key_version"] or _DEFAULT_KEY_VERSION
            entry = (blob, salt, key_ver)
            try:
                result = self._decrypt(entry, uid, service)
                await self._emit_credential_crypto("crypto.decrypt", uid, service)
                return result
            except DecryptionError:
                logger.warning(
                    "Credential decryption failed",
                    extra={
                        "event": "credential_store.decrypt_failed",
                        "service": service,
                        "user_id": uid,
                        "key_version": key_ver,
                    },
                    exc_info=True,
                )
                await self._emit_credential_crypto(
                    "crypto.decrypt_failed",
                    uid,
                    service,
                    outcome="FAILED",
                    severity="HIGH",
                )
                raise

    async def delete(self, service: str, user_id: int | None = None) -> bool:
        """Delete credentials for a service. Returns True if deleted."""
        logger.debug(
            "delete called",
            extra={
                "event": "credential_store.delete",
                "service": service,
                "user_id": user_id,
            },
        )  # auto:entry
        uid = require_user_id(user_id, "CredentialStore.delete")

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM user_credentials WHERE user_id = $1 AND service = $2",
                    uid,
                    service,
                )
                return result == "DELETE 1"

        key = (uid, service)
        if key in self._mem:
            del self._mem[key]
            return True
        return False

    async def list_services(self, user_id: int | None = None) -> list[str]:
        """List services the user has credentials for (without values)."""
        uid = require_user_id(user_id, "CredentialStore.list_services")

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT service FROM user_credentials "
                    "WHERE user_id = $1 ORDER BY service",
                    uid,
                )
                return [r["service"] for r in rows]

        return sorted(service for (u, service) in self._mem if u == uid)
