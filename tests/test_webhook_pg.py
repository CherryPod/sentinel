"""Tests for WebhookRegistry — PostgreSQL backend for webhooks.

Uses mock asyncpg pool/connection to verify SQL and parameter mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.channels.webhook import WebhookConfig, WebhookRegistry


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    conn = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = cm
    return pool, conn


@pytest.fixture
def store(mock_pool):
    pool, _ = mock_pool
    return WebhookRegistry(pool)


def _make_webhook_row(**overrides):
    now = datetime.now(timezone.utc)
    defaults = {
        "webhook_id": "wh-123",
        "name": "Test Hook",
        "secret": "s3cret",
        "enabled": True,
        "user_id": 1,
        "created_at": now,
    }
    defaults.update(overrides)
    return defaults


# ── register ──────────────────────────────────────────────────


class TestRegister:
    @pytest.mark.asyncio
    async def test_registers_webhook(self, store, mock_pool):
        _, conn = mock_pool
        now = datetime.now(timezone.utc)
        conn.fetchrow.return_value = {"created_at": now}

        config = await store.register("My Hook", "secret123")

        assert isinstance(config, WebhookConfig)
        assert config.name == "My Hook"
        assert config.secret == "secret123"
        assert config.webhook_id  # UUID generated

        # Verify INSERT was called
        args = conn.fetchrow.call_args[0]
        assert "INSERT INTO webhooks" in args[0]
        assert "RETURNING created_at" in args[0]


# ── get ───────────────────────────────────────────────────────


class TestGet:
    @pytest.mark.asyncio
    async def test_returns_webhook(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = _make_webhook_row()

        config = await store.get("wh-123")

        assert config is not None
        assert config.webhook_id == "wh-123"
        assert config.name == "Test Hook"
        assert config.secret == "s3cret"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetchrow.return_value = None

        result = await store.get("nonexistent")

        assert result is None


# ── delete ────────────────────────────────────────────────────


class TestDelete:
    @pytest.mark.asyncio
    async def test_returns_true_when_deleted(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 1"

        result = await store.delete("wh-123")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self, store, mock_pool):
        _, conn = mock_pool
        conn.execute.return_value = "DELETE 0"

        result = await store.delete("nonexistent")

        assert result is False


# ── list ──────────────────────────────────────────────────────


class TestList:
    @pytest.mark.asyncio
    async def test_lists_all_webhooks(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [
            _make_webhook_row(),
            _make_webhook_row(webhook_id="wh-456", name="Hook 2"),
        ]

        configs = await store.list()

        assert len(configs) == 2
        # Secrets should be redacted
        assert all(c.secret == "***" for c in configs)

    @pytest.mark.asyncio
    async def test_lists_by_user(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = [_make_webhook_row()]

        configs = await store.list(user_id=1)

        args = conn.fetch.call_args[0]
        assert "WHERE user_id = $1" in args[0]

    @pytest.mark.asyncio
    async def test_list_empty(self, store, mock_pool):
        _, conn = mock_pool
        conn.fetch.return_value = []

        configs = await store.list()

        assert configs == []
