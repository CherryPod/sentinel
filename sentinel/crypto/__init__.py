"""Cryptographic primitives for encryption at rest.

Provides per-record key derivation (HKDF-SHA256), AES-256-GCM
encrypt/decrypt, and HMAC-SHA256 blind indexes.  Stores call into
this package at their boundaries — the crypto module knows nothing
about stores; stores know nothing about key management.
"""

from sentinel.crypto.audit import emit_crypto_event, record_id_hash
from sentinel.crypto.blind_index import compute_blind_index, derive_and_compute
from sentinel.crypto.cipher import decrypt_field, encrypt_field, encrypt_field_with_salt
from sentinel.crypto.keys import (
    clear_key_cache,
    derive_dek,
    derive_hmac_key,
    get_master_key,
    load_master_key,
)

# NOTE: sentinel.crypto.migration is NOT re-exported here because it imports
# from sentinel.core.credential_store, which in turn imports from this package.
# Import directly: from sentinel.crypto.migration import migrate_credentials

__all__ = [
    "clear_key_cache",
    "compute_blind_index",
    "decrypt_field",
    "derive_and_compute",
    "derive_dek",
    "derive_hmac_key",
    "emit_crypto_event",
    "encrypt_field",
    "encrypt_field_with_salt",
    "get_master_key",
    "load_master_key",
    "record_id_hash",
]
