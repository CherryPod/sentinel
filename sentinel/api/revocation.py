"""JWT JTI revocation set for session token invalidation.

Provides a thread-safe in-memory set of revoked token IDs (jti claims).
The middleware (Task 3) checks each incoming token against this set and
rejects revoked tokens even if they haven't expired yet.

Entries are kept until they are older than the session TTL, at which point
they would be expired anyway — cleanup() trims these stale entries.

A module-level singleton is exposed via get_revocation_set(); callers should
use that rather than constructing their own instance.
"""

from __future__ import annotations

import threading
import time


class RevocationSet:
    """Thread-safe in-memory set of revoked JTI values.

    Each entry records the jti and the wall-clock time it was revoked (or
    the token's issued_at if provided). Entries older than ttl_seconds are
    pruned by cleanup() since the corresponding tokens would be expired and
    therefore harmless regardless.
    """

    def __init__(self, ttl_seconds: int = 3600) -> None:
        # Maximum age of a revocation entry before cleanup() removes it
        self._ttl = ttl_seconds
        # Maps jti → the timestamp used for age-tracking (revocation time or iat)
        self._revoked: dict[str, float] = {}
        self._lock = threading.Lock()

    def revoke(self, jti: str, issued_at: float | None = None) -> None:
        """Mark a single JTI as revoked.

        issued_at: the token's iat value if known. Falls back to the current
        wall-clock time. Using iat means cleanup() will drop the entry at the
        same point the token would have expired naturally.
        """
        timestamp = time.time()
        with self._lock:
            self._revoked[jti] = timestamp

    def is_revoked(self, jti: str) -> bool:
        """Return True if the JTI has been revoked."""
        with self._lock:
            return jti in self._revoked

    def revoke_all_for_user(
        self, jtis: list[str], issued_at: float | None = None
    ) -> None:
        """Revoke a batch of JTIs at once (e.g. on logout-all-sessions).

        issued_at applies to every entry in the batch. Falls back to the
        current wall-clock time if not provided.
        """
        timestamp = time.time()
        with self._lock:
            for jti in jtis:
                self._revoked[jti] = timestamp

    def cleanup(self) -> None:
        """Remove entries that are older than ttl_seconds.

        Call this periodically (e.g. on a background task) to prevent
        unbounded growth. Entries older than the TTL represent tokens that
        are already expired and no longer need to be tracked.
        """
        cutoff = time.time() - self._ttl
        with self._lock:
            stale = [jti for jti, ts in self._revoked.items() if ts < cutoff]
            for jti in stale:
                del self._revoked[jti]

    def __len__(self) -> int:
        """Return the number of currently tracked revoked JTIs."""
        with self._lock:
            return len(self._revoked)


# Module-level singleton — import and use this rather than constructing your own
_revocation_set = RevocationSet()


def get_revocation_set() -> RevocationSet:
    """Return the shared module-level revocation set."""
    return _revocation_set
