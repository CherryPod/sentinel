"""PIN authentication and failure tracking for Sentinel API.

PinVerifier — PBKDF2-HMAC-SHA256 PIN hashing with constant-time comparison.
_FailureTracker — per-IP failed attempt tracking with lockout.
"""

import hashlib
import hmac
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# PBKDF2 settings for PIN hashing (H-002)
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_HASH = "sha256"
_SALT_LENGTH = 32


class PinVerifier:
    """Holds a hashed PIN + salt — plaintext is never stored in memory.

    Uses PBKDF2-HMAC-SHA256 with 600k iterations (OWASP 2024 recommendation).
    """

    __slots__ = ("_hash", "_salt")

    def __init__(self, pin: str):
        self._salt = os.urandom(_SALT_LENGTH)
        self._hash = hashlib.pbkdf2_hmac(
            _PBKDF2_HASH,
            pin.encode("utf-8"),
            self._salt,
            _PBKDF2_ITERATIONS,
        )

    def verify(self, supplied: str) -> bool:
        """Verify a supplied PIN against the stored hash (constant-time)."""
        supplied_hash = hashlib.pbkdf2_hmac(
            _PBKDF2_HASH,
            supplied.encode("utf-8"),
            self._salt,
            _PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(supplied_hash, self._hash)

    def to_stored(self) -> str:
        """Serialise hash+salt for DB storage. Format: hex(salt):hex(hash)"""
        return self._salt.hex() + ":" + self._hash.hex()

    # Fixed salt for dummy verification — ensures user-not-found takes the same
    # wall-clock time as user-found, preventing timing side-channel leaks.
    _DUMMY_SALT = b"\x00" * _SALT_LENGTH
    _DUMMY_HASH = b"\x00" * 32

    @classmethod
    def dummy_verify(cls, supplied: str) -> None:
        """Run a PBKDF2 computation that takes the same time as a real verify.

        Call this on the user-not-found path to prevent timing side-channels
        from revealing whether a username exists.
        """
        dummy_hash = hashlib.pbkdf2_hmac(
            _PBKDF2_HASH,
            supplied.encode("utf-8"),
            cls._DUMMY_SALT,
            _PBKDF2_ITERATIONS,
        )
        # Constant-time compare against dummy to match real verify's code path
        hmac.compare_digest(dummy_hash, cls._DUMMY_HASH)

    @classmethod
    def from_stored(cls, stored: str) -> "PinVerifier":
        """Reconstruct from DB-stored format (hex(salt):hex(hash))."""
        logger.debug(
            "from_stored called",
            extra={"event": "auth.from_stored", "stored_length": len(stored)},
        )
        salt_hex, hash_hex = stored.split(":", 1)
        obj = object.__new__(cls)
        obj._salt = bytes.fromhex(salt_hex)
        obj._hash = bytes.fromhex(hash_hex)
        return obj


class _FailureTracker:
    """Thread-safe per-IP failed PIN attempt tracker with lockout.

    Thresholds are configurable via constructor args. The module-level
    singleton (created by create_failure_tracker()) reads them from
    Settings so they can be set via SENTINEL_LOGIN_MAX_FAILED_ATTEMPTS
    and SENTINEL_LOGIN_LOCKOUT_SECONDS environment variables.
    """

    _PRUNE_INTERVAL = 100  # Prune stale entries every N lookups

    def __init__(self, *, max_attempts: int = 5, lockout_seconds: int = 60):
        self._max_attempts = max_attempts
        self._lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        # {ip: (fail_count, last_fail_time)}
        self._attempts: dict[str, tuple[int, float]] = {}
        self._lookup_count = 0

    @property
    def lockout_seconds(self) -> int:
        """Total lockout duration in seconds."""
        return self._lockout_seconds

    def _prune_stale(self) -> None:
        """Remove entries older than lockout window. Called under lock."""
        now = time.monotonic()
        self._attempts = {
            ip: (count, ts)
            for ip, (count, ts) in self._attempts.items()
            if now - ts < self._lockout_seconds * 2
        }

    def is_locked_out(self, ip: str) -> bool:
        """Check if an IP is currently locked out due to repeated failures."""
        with self._lock:
            self._lookup_count += 1
            if self._lookup_count >= self._PRUNE_INTERVAL:
                self._prune_stale()
                self._lookup_count = 0

            record = self._attempts.get(ip)
            if record is None:
                return False
            count, last_fail = record
            if count >= self._max_attempts:
                if time.monotonic() - last_fail < self._lockout_seconds:
                    return True
                # Lockout expired — reset
                del self._attempts[ip]
                return False
            return False

    def get_failure_count(self, ip: str) -> int:
        """Return current failure count for *ip*, or 0 if no record."""
        with self._lock:
            record = self._attempts.get(ip)
            return record[0] if record is not None else 0

    def record_failure(self, ip: str) -> int:
        """Record a failed login attempt. Returns the new failure count."""
        with self._lock:
            record = self._attempts.get(ip)
            now = time.monotonic()
            if record is None:
                self._attempts[ip] = (1, now)
                return 1
            count, last_fail = record
            # Reset if lockout period has passed
            if count >= self._max_attempts and now - last_fail >= self._lockout_seconds:
                self._attempts[ip] = (1, now)
                return 1
            self._attempts[ip] = (count + 1, now)
            return count + 1

    def clear(self, ip: str) -> None:
        """Clear failure count for an IP (called on successful login)."""
        with self._lock:
            self._attempts.pop(ip, None)


def create_failure_tracker() -> _FailureTracker:
    """Create a _FailureTracker using thresholds from application settings."""
    from sentinel.core.config import settings

    return _FailureTracker(
        max_attempts=settings.login_max_failed_attempts,
        lockout_seconds=settings.login_lockout_seconds,
    )
