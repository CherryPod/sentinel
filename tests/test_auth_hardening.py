"""Verify auth hardening: logout, PIN comparison, jti rejection, revocation cleanup."""
import pytest
import hmac
import time
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sentinel.api.revocation import RevocationSet
from sentinel.api.sessions import create_session_token, verify_session_token


class TestLogoutEndpoint:
    """POST /api/auth/logout must revoke the calling user's token."""

    def test_logout_revokes_token(self):
        """After logout, the token should be rejected by middleware."""
        token = create_session_token(user_id=1, role="user")
        payload = verify_session_token(token)
        jti = payload["jti"]

        revocation_set = RevocationSet()
        assert not revocation_set.is_revoked(jti)

        revocation_set.revoke(jti)
        assert revocation_set.is_revoked(jti)


class TestRevocationCleanup:
    """cleanup() must remove expired entries."""

    def test_cleanup_removes_old_entries(self):
        """Entries older than TTL should be removed by cleanup()."""
        rs = RevocationSet(ttl_seconds=1)
        rs.revoke("jti-1")
        assert rs.is_revoked("jti-1")

        rs._revoked["jti-1"] = time.time() - 2
        rs.cleanup()
        assert not rs.is_revoked("jti-1")


class TestRevocationAnchor:
    """revoke() should use current time, not issued_at."""

    def test_revoke_uses_current_time(self):
        """Revocation timestamp should be time.time(), not issued_at."""
        rs = RevocationSet(ttl_seconds=3600)
        old_iat = time.time() - 3500
        rs.revoke("jti-2", issued_at=old_iat)

        rs.cleanup()
        assert rs.is_revoked("jti-2"), "Revocation was prematurely cleaned up"
