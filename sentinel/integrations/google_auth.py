"""Google OAuth2 token management — offline refresh flow.

Manages access tokens for Google APIs (Gmail, Calendar, etc.).
Tokens are refreshed automatically when expired, with a 5-minute
buffer to prevent edge-case failures. Concurrent refresh requests
are coalesced via an async lock (single-flight pattern).
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

logger = logging.getLogger(__name__)

GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

# HTTP status codes — named constants for clarity
_HTTP_OK = 200
_HTTP_UNAUTHORIZED = 401


# Moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import OAuthError


@dataclass
class TokenInfo:
    """Cached OAuth2 token state."""

    access_token: str
    expires_at: datetime
    refresh_token: str
    scopes: list[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        """Token is expired or within 5-minute buffer of expiry."""
        return datetime.now(UTC) >= self.expires_at - timedelta(minutes=5)


class GoogleOAuthManager:
    """Manages Google OAuth2 access tokens with offline refresh.

    Features:
    - Cached access token with automatic refresh on expiry
    - 5-minute expiry buffer to prevent edge-case failures
    - Single-flight refresh via asyncio.Lock (concurrent callers
      wait for one refresh instead of stampeding)
    - Refresh token loaded from file (Podman secret mount)
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        refresh_token_file: str,
        scopes: list[str],
        api_timeout: int = 15,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token_file = refresh_token_file
        self._scopes = scopes
        # Q11-F1: settings-backed HTTP deadline for token refresh. Default
        # 15 preserves prior literal for tests; production wires
        # settings.google_api_timeout via init/orchestrator.
        self._api_timeout = api_timeout
        self._token: TokenInfo | None = None
        self._refresh_lock = asyncio.Lock()

    async def get_access_token(self) -> str:
        """Return cached token or refresh. Single-flight via lock."""
        logger.debug(
            "oauth2.get_access_token",
            extra={
                "event": "oauth2.get_access_token",
                "cached": self._token is not None and not self._token.is_expired,
            },
        )
        if self._token and not self._token.is_expired:
            return self._token.access_token

        async with self._refresh_lock:
            # Double-check after acquiring lock (another coroutine may have refreshed)
            if self._token and not self._token.is_expired:
                return self._token.access_token
            await self._refresh()
            return self._token.access_token  # type: ignore[union-attr]

    async def _refresh(self) -> None:
        """POST to Google token endpoint to refresh access token."""
        refresh_token = self._load_refresh_token()

        logger.info(
            "Refreshing Google OAuth2 access token",
            extra={"event": "oauth2.refresh_start"},
        )

        async with httpx.AsyncClient(timeout=self._api_timeout) as client:
            try:
                resp = await client.post(
                    GOOGLE_TOKEN_ENDPOINT,
                    data={
                        "grant_type": "refresh_token",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "refresh_token": refresh_token,
                    },
                )
            except httpx.TimeoutException as exc:
                raise OAuthError(f"Token refresh timed out: {exc}") from exc
            except httpx.ConnectError as exc:
                raise OAuthError(f"Cannot connect to Google OAuth: {exc}") from exc

        if resp.status_code == _HTTP_UNAUTHORIZED:
            raise OAuthError("Invalid refresh token — re-authorization required")

        if resp.status_code != _HTTP_OK:
            raise OAuthError(f"Token refresh failed with status {resp.status_code}")

        data = resp.json()
        self._token = TokenInfo(
            access_token=data["access_token"],
            expires_at=datetime.now(UTC)
            + timedelta(seconds=data.get("expires_in", 3600)),
            refresh_token=refresh_token,
            scopes=self._scopes,
        )

        logger.info(
            "Google OAuth2 token refreshed",
            extra={
                "event": "oauth2.refresh_success",
                "expires_in_s": data.get("expires_in", 3600),
            },
        )

    def _load_refresh_token(self) -> str:
        """Read refresh token from secrets file."""
        logger.debug(
            "oauth2.load_refresh_token",
            extra={"event": "oauth2.load_refresh_token"},
        )
        try:
            with open(self._refresh_token_file) as f:
                token = f.read().strip()
        except FileNotFoundError as exc:
            raise OAuthError(
                f"Refresh token file not found: {self._refresh_token_file}"
            ) from exc
        except OSError as exc:
            raise OAuthError(f"Cannot read refresh token file: {exc}") from exc

        if not token:
            raise OAuthError("Refresh token file is empty")
        return token
