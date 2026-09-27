"""Key loading, HKDF derivation, and caching.

Loads the master key from a Podman secret (file path), derives
per-record DEKs via HKDF-SHA256, and derives HMAC keys for blind
indexes.  Production mode hard-fails when the key file is missing;
dev mode falls back to a deterministic dev key with a warning.
"""

from __future__ import annotations

import logging

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sentinel.core.decorators import no_audit_log
from sentinel.core.exceptions import CryptoConfigError

logger = logging.getLogger(__name__)

_AES_KEY_BYTES = 32
_DEV_KEY = b"sentinel-dev-credential-key!!"[:_AES_KEY_BYTES].ljust(
    _AES_KEY_BYTES, b"\x00"
)

# Default HKDF info context for field-level DEK derivation
_DEFAULT_DEK_INFO = b"sentinel-field-dek"

# HKDF info context for blind index HMAC key derivation
_BLIND_INDEX_INFO = b"sentinel-blind-index"

# ASYNCIO SAFETY: _cached_keys is written once per path (sync function,
# no await), subsequent reads return the cached value.  Idempotent
# assignment — safe in single-threaded event loop without a lock.
#
# C74 Inv-1 (cache integrity): only successful file loads populate this
# cache.  The ``_DEV_KEY`` fallback returned by ``load_master_key`` when
# the key file is missing MUST NEVER enter ``_cached_keys`` — otherwise a
# subsequent production-required call would silently receive the dev key
# from cache instead of raising ``CryptoConfigError``.
_cached_keys: dict[str, bytes] = {}

# C74 E1 (warn-once-per-path-per-cache-epoch): bound the volume of
# dev-fallback warnings.  Without caching dev-fallback values (Inv-1),
# every missing-key call would re-emit the WARNING with ``exc_info=True``.
# Two separate sets — one per warning event — prevent cross-branch silencing
# when the same path is first missing and later found with a short key (or
# vice versa) within a single cache epoch.
_warned_missing_paths: set[str] = set()   # FileNotFoundError → dev_fallback
_warned_short_paths: set[str] = set()     # short key found   → dev_key_padded


@no_audit_log  # returns master key — auto-entry logging would leak key material
def get_master_key(
    key_path: str,
    *,
    require_production: bool = False,
) -> bytes:
    """Return the cached master key, loading from disk on first call.

    Caches by *key_path* so tests with different temp files don't collide.

    Cache integrity (C74 Inv-1): dev-fallback values are NEVER cached, AND
    production-required calls ALWAYS re-validate from disk (bypassing the
    cache).  A previously-cached real key must not satisfy a later
    production-required call when the underlying key file is missing —
    that would silently bypass the production fail-loud invariant.

    The cache continues to serve dev-mode (require_production=False)
    callers from any prior real-file load (file was present at load time
    so caching it is correct); only production-required reads re-open the
    file every time.  This is the minimum faithful enforcement of the
    "production must fail loud" contract documented at C74.design §2.6.
    """
    if require_production:
        # Bypass cache: production policy demands re-validation against
        # current filesystem state.  load_master_key writes to the cache
        # on file-success — subsequent dev callers will hit it correctly.
        return load_master_key(key_path, require_production=True)
    cached = _cached_keys.get(key_path)
    if cached is not None:
        return cached
    return load_master_key(key_path, require_production=False)


def clear_key_cache() -> None:
    """Clear the cached master key(s), the log-hash derived key, AND the
    dev-fallback warning state.

    For testing only — keeps the three caches in sync so test teardown does
    not leak state between tests that swap ``settings.crypto_key_path`` or
    that exercise the missing-key dev-fallback path.
    """
    _cached_keys.clear()
    _warned_missing_paths.clear()  # C74 E1: re-enable warnings on next missing/short-key call
    _warned_short_paths.clear()
    # Deferred import — avoid an import cycle when blind_index is loaded
    # via this module's ``derive_hmac_key`` import chain.
    from sentinel.crypto.blind_index import _reset_log_hmac_key

    _reset_log_hmac_key()


@no_audit_log  # returns master key — auto-entry logging would leak key material
def load_master_key(
    key_path: str,
    *,
    require_production: bool = False,
) -> bytes:
    """Load the 32-byte master key from *key_path*.

    If the file is missing and *require_production* is ``False``, a
    deterministic dev fallback key is returned with a warning.  When
    *require_production* is ``True``, a missing file raises
    :class:`CryptoConfigError`.

    Short-key handling (IMP-08): after stripping whitespace, if the
    file content is fewer than ``_AES_KEY_BYTES`` (32) bytes and
    *require_production* is ``True``, :class:`CryptoConfigError` is raised.
    On the dev path (``require_production=False``) short content is still
    zero-padded and a WARNING is emitted once per (path, cache-epoch).

    File-success branch caches the loaded key in ``_cached_keys`` and
    returns it.  Dev-fallback branch returns ``_DEV_KEY`` WITHOUT caching
    (C74 Inv-1) and emits a WARNING at most once per (path, cache-epoch)
    via ``_warned_missing_paths`` (C74 E1).  Short-key padding emits a
    separate WARNING via ``_warned_short_paths`` (C74 E1).

    Other I/O errors (PermissionError, IsADirectoryError, etc.) propagate
    as their own ``OSError`` subclass — uniform-exception-class wrapping
    is intentionally OUT of scope (would require a widen-wrap seam audit
    per cleanup-pass §Guardrails #6).
    """
    try:
        with open(key_path, "rb") as fh:
            raw = fh.read().strip()
    except FileNotFoundError:
        if require_production:
            raise CryptoConfigError(
                f"Master key not found at {key_path} "
                "(crypto_require_production_key is enabled)"
            )
        # C74 E1: warn-once-per-path-per-cache-epoch
        if key_path not in _warned_missing_paths:
            logger.warning(
                "Master key not found at %s — using dev fallback (NOT for production)",
                key_path,
                extra={"event": "crypto.keys.dev_fallback"},
                exc_info=True,  # auto:exc
            )
            _warned_missing_paths.add(key_path)
        return (
            _DEV_KEY  # C74 Inv-1: NOT cached — dev-fallback never enters _cached_keys
        )

    if require_production and len(raw) < _AES_KEY_BYTES:
        raise CryptoConfigError(
            f"Master key at {key_path} is too short "
            f"({len(raw)} bytes; {_AES_KEY_BYTES} required) "
            "(crypto_require_production_key is enabled)"
        )

    logger.info(
        "Master key loaded",
        extra={"event": "crypto.keys.loaded", "source": key_path},
    )

    # Pad short keys on the dev path; production-required calls raise above.
    # C74 E1: separate warn-once guard for the short-key event (distinct from
    # _warned_missing_paths) so the two warning types cannot cross-silence each
    # other when the same path is observed in both states within an epoch.
    if len(raw) < _AES_KEY_BYTES:
        if key_path not in _warned_short_paths:
            logger.warning(
                "Master key at %s is shorter than %d bytes (%d); zero-padding "
                "(NOT for production — use crypto_require_production_key=True to reject)",
                key_path,
                _AES_KEY_BYTES,
                len(raw),
                extra={"event": "crypto.keys.dev_key_padded", "original_length": len(raw)},
            )
            _warned_short_paths.add(key_path)
        raw = raw.ljust(_AES_KEY_BYTES, b"\x00")
    real_key = raw[:_AES_KEY_BYTES]
    _cached_keys[key_path] = (
        real_key  # C74 Inv-1: cache here, in file-success branch ONLY
    )
    return real_key


@no_audit_log  # parameters include master_key — auto-entry logging would leak key material
def derive_dek(
    master_key: bytes,
    salt: bytes,
    *,
    info: bytes = _DEFAULT_DEK_INFO,
    key_length: int = _AES_KEY_BYTES,
) -> bytes:
    """Derive a per-record data-encryption key via HKDF-SHA256.

    Each unique *salt* (random 16 bytes generated at encrypt time)
    produces a unique DEK.  The same (master_key, salt, info) triple
    always produces the same DEK — deterministic for decryption.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=key_length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_key)


@no_audit_log  # parameters include master_key — auto-entry logging would leak key material
def derive_hmac_key(
    master_key: bytes,
    key_version: int,
    *,
    key_length: int = _AES_KEY_BYTES,
) -> bytes:
    """Derive the HMAC key for blind index computation.

    Uses HKDF with no random salt (deterministic — same input always
    produces the same HMAC, required for ``WHERE hmac = $1`` lookups).
    The *key_version* is encoded into the info field so key rotation
    produces a new HMAC key.
    """
    info = _BLIND_INDEX_INFO + f":{key_version}".encode()
    hkdf = HKDF(
        algorithm=SHA256(),
        length=key_length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)
