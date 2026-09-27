"""AES-256-GCM encrypt/decrypt with HKDF per-record key derivation.

Each field is stored as ``nonce (12 bytes) || ciphertext || GCM tag (16 bytes)``.
A per-record salt is stored alongside the blob; the DEK is re-derived from
(master_key, salt) on every access and never stored.
"""

from __future__ import annotations

import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinel.core.decorators import no_audit_log

from sentinel.core.exceptions import DecryptionError
from sentinel.crypto.keys import derive_dek

logger = logging.getLogger(__name__)

_GCM_NONCE_BYTES = 12
_HKDF_SALT_BYTES = 16
_MIN_BLOB_BYTES = _GCM_NONCE_BYTES + 1  # nonce + at least 1 byte of ciphertext+tag


@no_audit_log  # parameters include master_key — auto-entry logging would leak key material
def encrypt_field(
    master_key: bytes,
    salt: bytes,
    plaintext: bytes,
    aad: bytes | None,
) -> bytes:
    """Encrypt *plaintext* using AES-256-GCM with an HKDF-derived DEK.

    Returns ``nonce (12 bytes) || ciphertext || GCM tag``.  The *aad*
    (Associated Authenticated Data) binds ciphertext to its record
    context — an attacker who copies bytes between records gets a
    decryption failure.
    """
    dek = derive_dek(master_key, salt)
    nonce = os.urandom(_GCM_NONCE_BYTES)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return nonce + ct


@no_audit_log  # delegates to encrypt_field (also no_audit_log)
def encrypt_field_with_salt(
    master_key: bytes,
    plaintext: bytes,
    aad: bytes | None,
    *,
    salt_bytes: int = _HKDF_SALT_BYTES,
) -> tuple[bytes, bytes]:
    """Encrypt and generate a random salt.

    Returns ``(nonce || ciphertext, salt)`` — convenience for callers
    who want the salt generated for them.
    """
    salt = os.urandom(salt_bytes)
    blob = encrypt_field(master_key, salt, plaintext, aad)
    return blob, salt


@no_audit_log  # parameters include master_key — auto-entry logging would leak key material
def decrypt_field(
    master_key: bytes,
    salt: bytes,
    blob: bytes,
    aad: bytes | None,
) -> bytes:
    """Decrypt a blob produced by :func:`encrypt_field`.

    Raises :class:`DecryptionError` on any failure (wrong key, wrong
    salt, AAD mismatch, corruption).  The original exception is
    preserved as ``__cause__``.
    """
    if len(blob) < _MIN_BLOB_BYTES:
        raise DecryptionError(
            f"Ciphertext too short ({len(blob)} bytes, minimum {_MIN_BLOB_BYTES})"
        )

    nonce = blob[:_GCM_NONCE_BYTES]
    ct = blob[_GCM_NONCE_BYTES:]

    dek = derive_dek(master_key, salt)
    try:
        return AESGCM(dek).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed — wrong key, corrupted data, or AAD mismatch"
        ) from exc
