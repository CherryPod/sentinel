"""Google OAuth2 token management — offline refresh flow.

Manages access tokens for Google APIs (Gmail, Calendar, etc.).
Tokens are refreshed automatically when expired, with a 5-minute
buffer to prevent edge-case failures. Concurrent refresh requests
are coalesced via an async lock (single-flight pattern).
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger("sentinel.audit")

GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


class OAuthError(Exception):
    """Error during OAuth2 token management."""


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
        return datetime.now(timezone.utc) >= self.expires_at - timedelta(minutes=5)


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
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token_file = refresh_token_file
        self._scopes = scopes
        self._token: TokenInfo | None = None
        self._refresh_lock = asyncio.Lock()

    async def get_access_token(self) -> str:
        """Return cached token or refresh. Single-flight via lock."""
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
            extra={"event": "oauth2_refresh_start"},
        )

        async with httpx.AsyncClient(timeout=15) as client:
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

        if resp.status_code == 401:
            raise OAuthError("Invalid refresh token — re-authorization required")

        if resp.status_code != 200:
            raise OAuthError(
                f"Token refresh failed with status {resp.status_code}"
            )

        data = resp.json()
        self._token = TokenInfo(
            access_token=data["access_token"],
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=data.get("expires_in", 3600)),
            refresh_token=refresh_token,
            scopes=self._scopes,
        )

        logger.info(
            "Google OAuth2 token refreshed",
            extra={
                "event": "oauth2_refresh_success",
                "expires_in_s": data.get("expires_in", 3600),
            },
        )

    def _load_refresh_token(self) -> str:
        """Read refresh token from secrets file."""
        try:
            with open(self._refresh_token_file) as f:
                token = f.read().strip()
        except FileNotFoundError:
            raise OAuthError(
                f"Refresh token file not found: {self._refresh_token_file}"
            )
        except OSError as exc:
            raise OAuthError(f"Cannot read refresh token file: {exc}")

        if not token:
            raise OAuthError("Refresh token file is empty")
        return token
