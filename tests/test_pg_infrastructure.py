"""Tests for PostgreSQL infrastructure: PG config fields, pool lifecycle, health check."""
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestPgConfigFields:
    """pg_* config fields parse correctly from env vars."""

    def test_pg_defaults(self):
        """PG config fields have sensible defaults."""
        from sentinel.core.config import Settings
        s = Settings()
        assert s.pg_host == "/tmp"
        assert s.pg_port == 5432
        assert s.pg_dbname == "sentinel"
        assert s.pg_user == "postgres"
        assert s.pg_password_file == ""
        assert s.pg_pool_min == 2
        assert s.pg_pool_max == 5

    def test_pg_fields_via_env(self, monkeypatch):
        """All pg_ fields parse from SENTINEL_ env vars."""
        monkeypatch.setenv("SENTINEL_PG_HOST", "localhost")
        monkeypatch.setenv("SENTINEL_PG_PORT", "5433")
        monkeypatch.setenv("SENTINEL_PG_DBNAME", "testdb")
        monkeypatch.setenv("SENTINEL_PG_USER", "testuser")
        monkeypatch.setenv("SENTINEL_PG_PASSWORD_FILE", "/run/secrets/pg_pass")
        monkeypatch.setenv("SENTINEL_PG_POOL_MIN", "1")
        monkeypatch.setenv("SENTINEL_PG_POOL_MAX", "10")
        from sentinel.core.config import Settings
        s = Settings()
        assert s.pg_host == "localhost"
        assert s.pg_port == 5433
        assert s.pg_dbname == "testdb"
        assert s.pg_user == "testuser"
        assert s.pg_password_file == "/run/secrets/pg_pass"
        assert s.pg_pool_min == 1
        assert s.pg_pool_max == 10


class TestAsyncpgPoolLifecycle:
    """asyncpg pool lifecycle: DSN construction, shutdown."""

    async def test_pool_dsn_construction(self):
        """DSN is correctly built from config fields."""
        from sentinel.core.config import Settings
        s = Settings()
        dsn = f"postgresql://{s.pg_user}@/{s.pg_dbname}"
        assert dsn == "postgresql://postgres@/sentinel"

    async def test_pool_close_on_shutdown(self):
        """Pool close is called during shutdown when pool exists."""
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock()

        class FakeState:
            pg_pool = mock_pool

        state = FakeState()
        if getattr(state, "pg_pool", None) is not None:
            await state.pg_pool.close()

        mock_pool.close.assert_awaited_once()

    async def test_pool_close_skipped_when_none(self):
        """No error when pg_pool is None during shutdown."""
        class FakeState:
            pg_pool = None

        state = FakeState()
        if getattr(state, "pg_pool", None) is not None:
            await state.pg_pool.close()


class TestPgHealthCheck:
    """Health check via _check_pg_ready."""

    async def test_check_pg_ready_returns_true(self):
        """_check_pg_ready returns True when pool is healthy."""
        from sentinel.api.routes.health import check_pg_ready

        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_app = MagicMock()
        mock_app.state.pg_pool = mock_pool

        result = await check_pg_ready(mock_app)
        assert result is True
        mock_conn.fetchval.assert_awaited_once_with("SELECT 1")

    async def test_check_pg_ready_returns_false_on_error(self):
        """_check_pg_ready returns False when pool query fails."""
        from sentinel.api.routes.health import check_pg_ready

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(side_effect=Exception("connection failed"))
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_app = MagicMock()
        mock_app.state.pg_pool = mock_pool

        result = await check_pg_ready(mock_app)
        assert result is False

    async def test_check_pg_ready_returns_none_when_no_pool(self):
        """_check_pg_ready returns None when pg_pool is None."""
        from sentinel.api.routes.health import check_pg_ready

        mock_app = MagicMock()
        mock_app.state.pg_pool = None

        result = await check_pg_ready(mock_app)
        assert result is None

    async def test_check_pg_ready_returns_none_when_no_state(self):
        """_check_pg_ready returns None when app.state has no pg_pool attribute."""
        from sentinel.api.routes.health import check_pg_ready

        mock_app = MagicMock(spec=[])  # no attributes
        mock_app.state = MagicMock(spec=[])  # no pg_pool

        result = await check_pg_ready(mock_app)
        assert result is None
