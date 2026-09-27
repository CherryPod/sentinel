"""Channel-specific crypto operations — encrypt, decrypt, HMAC.

Pure functions that wrap sentinel.crypto.* with channel AAD binding.
Stateless — master_key and key_version passed explicitly.
"""

from __future__ import annotations

from sentinel.core.decorators import no_audit_log
from sentinel.crypto.blind_index import derive_and_compute
from sentinel.crypto.cipher import decrypt_field, encrypt_field_with_salt

# AAD format: binds ciphertext to a specific channel record
CHANNEL_AAD_TEMPLATE = "contact_channels:{channel_id}:{channel}"


@no_audit_log  # callers pass key material
def encrypt_channel_identifier(
    master_key: bytes,
    identifier: str,
    channel_id: int,
    channel: str,
) -> tuple[bytes, bytes]:
    """Encrypt a channel identifier with HKDF-derived key and AAD.

    Returns (encrypted_blob, salt).
    """
    plaintext = identifier.encode("utf-8")
    aad = CHANNEL_AAD_TEMPLATE.format(
        channel_id=channel_id,
        channel=channel,
    ).encode()
    return encrypt_field_with_salt(master_key, plaintext, aad)


@no_audit_log  # callers pass key material
def decrypt_channel_identifier(
    master_key: bytes,
    blob: bytes,
    salt: bytes,
    channel_id: int,
    channel: str,
) -> str:
    """Decrypt an encrypted channel identifier."""
    aad = CHANNEL_AAD_TEMPLATE.format(
        channel_id=channel_id,
        channel=channel,
    ).encode()
    plaintext = decrypt_field(master_key, salt, blob, aad)
    return plaintext.decode("utf-8")


@no_audit_log  # callers pass key material
def compute_channel_hmac(
    master_key: bytes,
    key_version: int,
    identifier: str,
) -> bytes:
    """Compute HMAC blind index for a channel identifier."""
    return derive_and_compute(master_key, key_version, identifier)
