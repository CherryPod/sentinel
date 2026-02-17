"""Tests for Telegram channel — fully mocked (no real bot)."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.channels.base import IncomingMessage, OutgoingMessage
from sentinel.channels.telegram_channel import TelegramChannel, TelegramConfig


@pytest.fixture
def config():
    return TelegramConfig(
        bot_token="fake:token",
        allowed_chat_ids={12345},
        rate_limit=10,
        max_message_length=4096,
        polling_timeout=1,
    )


@pytest.fixture
def open_config():
    """Config with empty allowlist (allow all)."""
    return TelegramConfig(
        bot_token="fake:token",
        allowed_chat_ids=set(),
        rate_limit=10,
        max_message_length=4096,
        polling_timeout=1,
    )


class TestTelegramStart:
    @pytest.mark.asyncio
    async def test_start_creates_application(self, config):
        with patch("telegram.ext.ApplicationBuilder") as mock_builder:
            mock_app = AsyncMock()
            mock_builder.return_value.token.return_value.build.return_value = mock_app
            ch = TelegramChannel(config)
            await ch.start()
            assert ch._running is True
            mock_app.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_shuts_down(self, config):
        with patch("telegram.ext.ApplicationBuilder") as mock_builder:
            mock_app = AsyncMock()
            mock_builder.return_value.token.return_value.build.return_value = mock_app
            ch = TelegramChannel(config)
            await ch.start()
            await ch.stop()
            assert ch._running is False
            mock_app.shutdown.assert_awaited_once()


class TestTelegramSend:
    @pytest.mark.asyncio
    async def test_send_message(self, config):
        with patch("telegram.ext.ApplicationBuilder") as mock_builder:
            mock_app = AsyncMock()
            mock_builder.return_value.token.return_value.build.return_value = mock_app
            ch = TelegramChannel(config)
            await ch.start()
            msg = OutgoingMessage(
                channel_id="12345",
                event_type="task.completed",
                data={"result": "done"},
            )
            await ch.send(msg)
            mock_app.bot.send_message.assert_awaited_once()
            call_kwargs = mock_app.bot.send_message.call_args
            assert call_kwargs.kwargs["chat_id"] == 12345
            assert call_kwargs.kwargs["text"] == "done"

    @pytest.mark.asyncio
    async def test_send_splits_long_messages(self, config):
        config.max_message_length = 10
        with patch("telegram.ext.ApplicationBuilder") as mock_builder:
            mock_app = AsyncMock()
            mock_builder.return_value.token.return_value.build.return_value = mock_app
            ch = TelegramChannel(config)
            await ch.start()
            msg = OutgoingMessage(
                channel_id="12345",
                event_type="task.completed",
                data={"result": "a" * 25},  # 25 chars, limit 10 → 3 chunks
            )
            await ch.send(msg)
            assert mock_app.bot.send_message.await_count == 3


    @pytest.mark.asyncio
    async def test_send_timeout_logs_warning(self, config):
        """Timeout on send_message logs a warning and stops sending."""
        with patch("telegram.ext.ApplicationBuilder") as mock_builder:
            mock_app = AsyncMock()
            mock_builder.return_value.token.return_value.build.return_value = mock_app
            # Make send_message hang forever (simulate unresponsive Telegram API)
            mock_app.bot.send_message = AsyncMock(side_effect=asyncio.TimeoutError)
            ch = TelegramChannel(config)
            await ch.start()

            msg = OutgoingMessage(
                channel_id="12345",
                event_type="task.completed",
                data={"result": "done"},
            )
            with patch("sentinel.channels.telegram_channel.asyncio.wait_for", side_effect=asyncio.TimeoutError):
                await ch.send(msg)
            # Should not raise — timeout is logged, not propagated

    @pytest.mark.asyncio
    async def test_send_timeout_stops_remaining_chunks(self, config):
        """If one chunk times out, remaining chunks are skipped."""
        config.max_message_length = 10
        with patch("telegram.ext.ApplicationBuilder") as mock_builder:
            mock_app = AsyncMock()
            mock_builder.return_value.token.return_value.build.return_value = mock_app

            call_count = 0

            async def wait_for_side_effect(coro, timeout=None):
                nonlocal call_count
                call_count += 1
                if call_count == 2:
                    raise asyncio.TimeoutError
                return await coro

            ch = TelegramChannel(config)
            await ch.start()
            msg = OutgoingMessage(
                channel_id="12345",
                event_type="task.completed",
                data={"result": "a" * 25},  # 3 chunks at limit 10
            )
            with patch("sentinel.channels.telegram_channel.asyncio.wait_for", side_effect=wait_for_side_effect):
                await ch.send(msg)
            # First chunk sent, second timed out, third skipped
            assert mock_app.bot.send_message.await_count == 1


class TestTelegramAllowlist:
    def test_disallowed_chat_filtered(self, config):
        ch = TelegramChannel(config)
        assert ch._is_allowed(99999) is False
        assert ch._is_allowed(12345) is True

    def test_empty_allowlist_allows_all(self, open_config):
        ch = TelegramChannel(open_config)
        assert ch._is_allowed(99999) is True
        assert ch._is_allowed(12345) is True


class TestTelegramRateLimit:
    def test_under_limit_passes(self, config):
        ch = TelegramChannel(config)
        for _ in range(config.rate_limit):
            assert ch._check_rate_limit(12345) is True

    def test_over_limit_blocked(self, config):
        ch = TelegramChannel(config)
        for _ in range(config.rate_limit):
            ch._check_rate_limit(12345)
        assert ch._check_rate_limit(12345) is False

    def test_different_chats_independent(self, config):
        ch = TelegramChannel(config)
        for _ in range(config.rate_limit):
            ch._check_rate_limit(11111)
        # Different chat should still be allowed
        assert ch._check_rate_limit(22222) is True


class TestTelegramFormat:
    def test_format_result(self):
        msg = OutgoingMessage(channel_id="1", event_type="x", data={"result": "hello"})
        assert TelegramChannel._format_outgoing(msg) == "hello"

    def test_format_payload(self):
        msg = OutgoingMessage(channel_id="1", event_type="x", data={"payload": "world"})
        assert TelegramChannel._format_outgoing(msg) == "world"

    def test_format_confirmation_preview(self):
        """Confirmation gate preview renders correctly."""
        msg = OutgoingMessage(
            channel_id="1", event_type="x",
            data={
                "preview": "Send via Signal to Alice: hello",
                "confirmation_id": "abc-123",
                "original_request": "tell alice hello",
            },
        )
        result = TelegramChannel._format_outgoing(msg)
        assert "Send via Signal to Alice: hello" in result
        assert "go" in result.lower()

    def test_format_plan_approval(self):
        """Plan approval request renders with steps."""
        msg = OutgoingMessage(
            channel_id="1", event_type="x",
            data={
                "approval_id": "plan-001",
                "plan_summary": "Send email and update calendar",
                "steps": [
                    {"type": "tool_call", "description": "Send email to Bob"},
                    {"type": "tool_call", "description": "Add calendar event"},
                ],
            },
        )
        result = TelegramChannel._format_outgoing(msg)
        assert "Send email and update calendar" in result
        assert "Send email to Bob" in result
        assert "go" in result.lower()

    def test_format_fallback_json(self):
        msg = OutgoingMessage(channel_id="1", event_type="x", data={"foo": "bar"})
        text = TelegramChannel._format_outgoing(msg)
        assert '"foo"' in text
        assert '"bar"' in text
