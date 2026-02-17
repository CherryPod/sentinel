"""Per-user credential storage with AES-256-GCM encryption.

Stores encrypted service credentials (IMAP, SMTP, CalDAV, etc.) per user.
Each credential is a JSON dict encrypted with a system-wide key from
/run/secrets/credential_key (Podman secret).

The encryption key is 32 bytes. If the secret file doesn't exist, a dev
fallback key is used (NOT for production).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.core.credential_store")

_KEY_PATH = "/run/secrets/credential_key"
_DEV_KEY = b"sentinel-dev-credential-key!!"[:32].ljust(32, b"\x00")

# Sensitive fields that are masked in GET responses
_SENSITIVE_FIELDS = {"password", "secret", "token", "api_key", "private_key"}


class DecryptionError(Exception):
    """Raised when credential decryption fails (wrong key, corrupted data)."""


def _get_encryption_key() -> bytes:
    """Load the 32-byte encryption key from Podman secret or dev fallback."""
    if os.path.exists(_KEY_PATH):
        with open(_KEY_PATH, "rb") as f:
            key = f.read().strip()
            if len(key) < 32:
                key = key.ljust(32, b"\x00")
            return key[:32]
    logger.warning(
        "Credential key not found at %s — using dev fallback (NOT for production)",
        _KEY_PATH,
    )
    return _DEV_KEY


_cached_key: bytes | None = None


def get_encryption_key() -> bytes:
    """Return the cached encryption key, loading on first call."""
    global _cached_key
    if _cached_key is None:
        _cached_key = _get_encryption_key()
    return _cached_key


def generate_key() -> bytes:
    """Generate a new random 32-byte AES-256 key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_credentials(data: dict, key: bytes) -> bytes:
    """Encrypt a credential dict to bytes using AES-256-GCM.

    Format: nonce (12 bytes) + ciphertext (variable length).
    """
    nonce = os.urandom(12)
    plaintext = json.dumps(data).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_credentials(blob: bytes, key: bytes) -> dict:
    """Decrypt credential bytes back to a dict.

    Raises DecryptionError on failure (wrong key, corrupted data).
    """
    if len(blob) < 13:
        raise DecryptionError("Encrypted data too short")
    nonce, ct = blob[:12], blob[12:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:
        raise DecryptionError(f"Decryption failed: {exc}") from exc
    return json.loads(plaintext)


def mask_sensitive(data: dict) -> dict:
    """Return a copy with sensitive fields replaced by '***'."""
    return {
        k: "***" if k in _SENSITIVE_FIELDS else v
        for k, v in data.items()
    }


class CredentialStore:
    """CRUD operations for per-user encrypted credentials.

    When pool=None, falls back to in-memory dict for tests.
    """

    def __init__(self, pool: Any = None, key: bytes | None = None):
        self._pool = pool
        self._key = key or get_encryption_key()
        # In-memory fallback: {(user_id, service): encrypted_bytes}
        self._mem: dict[tuple[int, str], bytes] = {}

    async def set(self, service: str, data: dict, user_id: int | None = None) -> None:
        """Encrypt and store (upsert) credentials for a service."""
        uid = user_id if user_id is not None else current_user_id.get()
        encrypted = encrypt_credentials(data, self._key)

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO user_credentials (user_id, service, encrypted_value) "
                    "VALUES ($1, $2, $3) "
                    "ON CONFLICT (user_id, service) DO UPDATE SET "
                    "encrypted_value = $3, updated_at = NOW()",
                    uid, service, encrypted,
                )
                return

        self._mem[(uid, service)] = encrypted

    async def get(self, service: str, user_id: int | None = None) -> dict | None:
        """Retrieve and decrypt credentials for a service. Returns None if not set."""
        uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT encrypted_value FROM user_credentials "
                    "WHERE user_id = $1 AND service = $2",
                    uid, service,
                )
                if row is None:
                    return None
                return decrypt_credentials(bytes(row["encrypted_value"]), self._key)

        encrypted = self._mem.get((uid, service))
        if encrypted is None:
            return None
        return decrypt_credentials(encrypted, self._key)

    async def delete(self, service: str, user_id: int | None = None) -> bool:
        """Delete credentials for a service. Returns True if deleted."""
        uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM user_credentials "
                    "WHERE user_id = $1 AND service = $2",
                    uid, service,
                )
                return result == "DELETE 1"

        key = (uid, service)
        if key in self._mem:
            del self._mem[key]
            return True
        return False

    async def list_services(self, user_id: int | None = None) -> list[str]:
        """List services the user has credentials for (without values)."""
        uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT service FROM user_credentials "
                    "WHERE user_id = $1 ORDER BY service",
                    uid,
                )
                return [r["service"] for r in rows]

        return sorted(
            service for (u, service) in self._mem if u == uid
        )
