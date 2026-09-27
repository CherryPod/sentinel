"""HMAC-SHA256 blind index computation for equality lookups.

Blind indexes allow ``WHERE identifier_hmac = $1`` queries on
encrypted fields.  They are deterministic (same input → same output)
and one-way (cannot recover plaintext from the HMAC).
"""

from __future__ import annotations

import logging  # auto:logger

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

from sentinel.core.decorators import no_audit_log
from sentinel.crypto.keys import derive_hmac_key

logger = logging.getLogger(__name__)  # auto:logger


def compute(hmac_key: bytes, plaintext: bytes | str) -> bytes:
    """Compute HMAC-SHA256 of *plaintext* using *hmac_key*.

    Returns the raw 32-byte digest (stored as BYTEA in the database).
    Accepts either bytes or str plaintext — strings are UTF-8 encoded.
    Uses ``cryptography`` library (OpenSSL backend) for consistency
    with the rest of the crypto package.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    h = HMAC(hmac_key, hashes.SHA256())
    h.update(plaintext)
    return h.finalize()


@no_audit_log  # parameters include master_key — auto-entry logging would leak key material
def derive_and_compute(
    master_key: bytes,
    key_version: int,
    plaintext: bytes | str,
) -> bytes:
    """Derive the HMAC key from *master_key* then compute the blind index.

    Convenience wrapper that calls :func:`~sentinel.crypto.keys.derive_hmac_key`
    followed by :func:`compute`.
    """
    hmac_key = derive_hmac_key(master_key, key_version)
    return compute(hmac_key, plaintext)


# Public alias for package-level re-export
compute_blind_index = compute


# ---------------------------------------------------------------------------
# Log-redaction primitive (Q16.fix.a)
#
# Provides a settings-backed keyed-HMAC hex digest for redacting low-entropy
# identifiers in log extras.  Distinct from the :func:`compute` /
# :func:`derive_and_compute` blind-index primitives above:
#   * blind index = caller-supplied key, full digest, used for DB equality
#   * log_hash    = module-cached key (lazy-init from settings), 16-hex
#                   truncation, used in ``logger.*(extra={...})``
#
# Keyed HMAC is mandatory because ``source_key`` / Matrix sender handles
# have enumerable keyspaces — a public hash would be brute-forceable.
# ---------------------------------------------------------------------------

_LOG_HASH_TRUNC = 16  # hex chars
_log_hmac_key: bytes | None = None


def _reset_log_hmac_key() -> None:
    """Reset the log-hash HMAC cache.  Hooked into keys.clear_key_cache()."""
    global _log_hmac_key
    _log_hmac_key = None


def _get_log_hmac_key() -> bytes | None:
    """Lazy-init the log-redaction HMAC key from settings.

    Returns ``None`` on non-production crypto-config failure so callers can
    fall back to the ``"nokey"`` sentinel.  When
    ``settings.crypto_require_production_key`` is True a missing key file
    propagates the underlying ``CryptoConfigError`` rather than silently
    degrading log redaction.

    Crucially, in dev mode (``crypto_require_production_key=False``) we do
    NOT consume the deterministic dev-key fallback that
    :func:`~sentinel.crypto.keys.get_master_key` returns when the key file
    is missing — using that fallback would derive a real-looking HMAC key
    and produce real-looking 16-hex digests in operator logs, defeating
    the locked CR-2 contract that ``log_hash`` returns the honest
    ``"nokey"`` correlation-loss sentinel when crypto bootstrap has
    failed.  We probe for the key file's existence first and short-circuit
    to ``None`` if it is absent.
    """
    import os.path

    logger.debug(
        "_get_log_hmac_key called",
        extra={"event": "crypto.blind_index._get_log_hmac_key"},
    )  # auto:entry
    global _log_hmac_key
    if _log_hmac_key is not None:
        return _log_hmac_key
    # Deferred imports for circular-safety with sentinel.core.config which
    # transitively pulls in many sentinel.* modules at import time.
    from sentinel.core.config import settings
    from sentinel.crypto.keys import get_master_key

    key_path = settings.crypto_key_path
    require_production = settings.crypto_require_production_key

    # Dev mode + no key file → honest correlation-loss sentinel via log_hash.
    # Refuses the deterministic _DEV_KEY fallback that get_master_key would
    # otherwise return; production-mode missing-key still raises below via
    # get_master_key's own require_production branch (preserved for
    # fail-loud semantics).
    if not require_production and not os.path.exists(key_path):
        return None

    try:
        master = get_master_key(
            key_path,
            require_production=require_production,
        )
    except Exception:
        logger.exception(
            "_get_log_hmac_key: Exception",
            extra={"event": "crypto.blind_index._get_log_hmac_key_error"},
        )  # auto:except
        if require_production:
            raise  # fail-loud: missing key in production is never acceptable
        return None
    _log_hmac_key = derive_hmac_key(master, settings.crypto_key_version)
    return _log_hmac_key


@no_audit_log  # parameters may be low-entropy identifiers — auto-entry logging would negate the redaction
def log_hash(value: str | None) -> str:
    """Truncated keyed-HMAC hex digest for log redaction of low-entropy identifiers.

    Returns ``""`` for None / empty input.  If the HMAC key cannot be
    loaded in non-production (dev) mode, returns the sentinel ``"nokey"``.
    In that failure mode log correlation is lost — every non-empty value
    maps to the same sentinel — but secrecy is preserved (no raw value
    leaks).  Production deployments set
    ``crypto_require_production_key=True`` so missing-key failures raise
    instead of degrading silently.

    Keyed HMAC (NOT plain SHA-256) is mandatory: ``source_key`` / Matrix
    sender handles have enumerable keyspace (~1000 principals × N
    channels).  A public hash would be trivially brute-forceable given
    2026 hardware.
    """
    if not value:
        return ""
    key = _get_log_hmac_key()
    if key is None:
        return "nokey"
    return compute(key, value).hex()[:_LOG_HASH_TRUNC]
