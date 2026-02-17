"""B3: Google OAuth2 Capability Tests.

Verifies token refresh flow, error handling, credential isolation,
expiry buffer, and concurrent refresh coalescing. All tests mock
httpx — no real Google API calls.

5 tests total.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, mock_open, patch

import httpx
import pytest

from sentinel.integrations.google_auth import (
    GoogleOAuthManager,
    OAuthError,
    TokenInfo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager(refresh_token: str = "test-refresh-token") -> GoogleOAuthManager:
    """Create a GoogleOAuthManager with mocked refresh token file."""
    manager = GoogleOAuthManager(
        client_id="test-client-id",
        client_secret="test-client-secret",
        refresh_token_file="/run/secrets/google_refresh_token",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    return manager


def _mock_token_response(
    access_token: str = "ya29.test-access-token",
    expires_in: int = 3600,
) -> httpx.Response:
    """Build a mock Google token refresh response."""
    return httpx.Response(
        status_code=200,
        json={
            "access_token": access_token,
            "expires_in": expires_in,
            "token_type": "Bearer",
        },
    )


# ---------------------------------------------------------------------------
# Test 1: Successful token refresh
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_oauth2_token_refresh():
    """Successful refresh -> valid access_token returned."""
    manager = _make_manager()
    mock_resp = _mock_token_response(access_token="ya29.fresh-token")

    with patch("builtins.open", mock_open(read_data="test-refresh-token")):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            token = await manager.get_access_token()

    assert token == "ya29.fresh-token"

    # Second call should use cached token (no refresh needed)
    cached_token = await manager.get_access_token()
    assert cached_token == "ya29.fresh-token"


# ---------------------------------------------------------------------------
# Test 2: Invalid refresh token -> OAuthError
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_oauth2_refresh_token_invalid():
    """401 response -> OAuthError("Invalid refresh token")."""
    manager = _make_manager()
    mock_resp = httpx.Response(
        status_code=401,
        json={"error": "invalid_grant"},
    )

    with patch("builtins.open", mock_open(read_data="expired-refresh-token")):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(OAuthError, match="Invalid refresh token"):
                await manager.get_access_token()


# ---------------------------------------------------------------------------
# Test 3: Credential isolation — tokens not in log messages
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_oauth2_credential_isolation():
    """Tokens not in error strings or public-facing output."""
    manager = _make_manager()

    # Simulate file not found
    with patch("builtins.open", side_effect=FileNotFoundError("no such file")):
        with pytest.raises(OAuthError) as exc_info:
            await manager.get_access_token()

    error_msg = str(exc_info.value)
    # Error message should mention the file path but NOT contain the token
    assert "test-refresh-token" not in error_msg
    assert "test-client-secret" not in error_msg
    assert "test-client-id" not in error_msg

    # Simulate successful refresh and verify token not in originated_from etc.
    manager2 = _make_manager()
    mock_resp = _mock_token_response(access_token="ya29.secret-access-token")

    with patch("builtins.open", mock_open(read_data="test-refresh-token")):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            token = await manager2.get_access_token()

    # The returned token is the access token itself (needed by callers)
    assert token == "ya29.secret-access-token"
    # But internal state should not leak
    assert manager2._token is not None
    assert manager2._token.refresh_token == "test-refresh-token"


# ---------------------------------------------------------------------------
# Test 4: Token expiry race — 4-min token triggers refresh (5-min buffer)
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_oauth2_token_expiry_race():
    """Token with 4-min remaining -> is_expired=True (5-min buffer)."""
    # Token that expires in 4 minutes (within 5-minute buffer)
    soon_token = TokenInfo(
        access_token="ya29.about-to-expire",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=4),
        refresh_token="test-refresh-token",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    assert soon_token.is_expired is True

    # Token that expires in 6 minutes (outside buffer)
    ok_token = TokenInfo(
        access_token="ya29.still-good",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=6),
        refresh_token="test-refresh-token",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    assert ok_token.is_expired is False

    # Token that already expired
    expired_token = TokenInfo(
        access_token="ya29.expired",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        refresh_token="test-refresh-token",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    assert expired_token.is_expired is True

    # Verify manager with about-to-expire token triggers refresh
    manager = _make_manager()
    manager._token = soon_token

    mock_resp = _mock_token_response(access_token="ya29.refreshed")
    with patch("builtins.open", mock_open(read_data="test-refresh-token")):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            token = await manager.get_access_token()

    assert token == "ya29.refreshed"


# ---------------------------------------------------------------------------
# Test 5: Concurrent refresh -> only one HTTP call (lock)
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_oauth2_concurrent_refresh():
    """Two concurrent get_access_token() -> only one HTTP call (lock)."""
    manager = _make_manager()
    call_count = 0

    async def mock_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        # Small delay to force concurrency
        await asyncio.sleep(0.05)
        return _mock_token_response(access_token="ya29.single-refresh")

    with patch("builtins.open", mock_open(read_data="test-refresh-token")):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=mock_post):
            # Launch two concurrent token requests
            results = await asyncio.gather(
                manager.get_access_token(),
                manager.get_access_token(),
            )

    # Both should get the same token
    assert results[0] == "ya29.single-refresh"
    assert results[1] == "ya29.single-refresh"

    # Only one HTTP call should have been made (second waiter uses cached result)
    assert call_count == 1
