"""A3 capability tests for Signal channel integration.

Tests cover: E2E message receive → orchestrator routing, sender allowlist,
crash recovery with socket reconnect, signal-cli unavailability, rate limiting,
response splitting, and markdown stripping. All use mocked I/O — no signal-cli needed.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.channels.base import ChannelRouter, OutgoingMessage
from sentinel.channels.signal_channel import (
    SignalChannel,
    SignalConfig,
    _format_response,
    _split_response,
    _strip_markdown,
)
from sentinel.core.bus import EventBus


# ── Shared test helpers ──────────────────────────────────────────────


class FakeProcess:
    """Mock asyncio subprocess for testing (daemon mode — no stdin needed)."""

    def __init__(self, *, returncode=None):
        self.pid = 12345
        self.returncode = returncode
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self._terminated = False
        self._killed = False

    def terminate(self):
        self._terminated = True
        self.returncode = -15

    def kill(self):
        self._killed = True
        self.returncode = -9

    async def wait(self):
        return self.returncode


class FakeSocketReader:
    """Mock asyncio.StreamReader backed by an asyncio.Queue.

    Pass a channel to stop_on_eof() so that _running is cleared when the EOF
    is actually consumed by readline(), triggering the reconnect-loop exit
    check in _read_loop (``if not self._running: break``).
    """

    def __init__(self):
        self._lines: asyncio.Queue = asyncio.Queue()
        self._channel = None

    def stop_on_eof(self, channel):
        """Set channel._running = False when EOF is consumed."""
        self._channel = channel

    def push_line(self, data):
        """Push a line for readline() to return."""
        if isinstance(data, dict):
            data = json.dumps(data).encode() + b"\n"
        elif isinstance(data, str):
            data = data.encode() + b"\n"
        self._lines.put_nowait(data)

    def push_eof(self):
        """Signal EOF (empty bytes)."""
        self._lines.put_nowait(b"")

    async def readline(self):
        data = await self._lines.get()
        if not data and self._channel is not None:
            self._channel._running = False
        return data


class FakeSocketWriter:
    """Mock asyncio.StreamWriter that records writes."""

    def __init__(self):
        self.written: list[bytes] = []
        self._closed = False

    def write(self, data: bytes):
        self.written.append(data)

    async def drain(self):
        pass

    def close(self):
        self._closed = True

    async def wait_closed(self):
        pass


def _make_receive_notification(source: str, message: str) -> dict:
    """Build a signal-cli JSON-RPC receive notification."""
    return {
        "jsonrpc": "2.0",
        "method": "receive",
        "params": {
            "envelope": {
                "source": source,
                "timestamp": 1000,
                "dataMessage": {"message": message},
            },
        },
    }


# ── Capability tests ─────────────────────────────────────────────────


@pytest.mark.capability
class TestSignalMessageReceive:
    """E2E: notification → _read_loop (via socket) → queue → ChannelRouter → orchestrator."""

    async def test_signal_message_receive(self):
        """Signal message flows through to orchestrator.handle_task via ChannelRouter."""
        bus = EventBus()
        cfg = SignalConfig(account="+0000000000", allowed_senders=["+1234567890"])
        channel = SignalChannel(cfg, event_bus=bus)

        reader = FakeSocketReader()
        channel._reader = reader
        channel._running = True

        # Push a message then EOF to stop the read loop
        reader.stop_on_eof(channel)
        reader.push_line(_make_receive_notification("+1234567890", "Hello Sentinel"))
        reader.push_eof()

        await channel._read_loop()

        # Message should be queued
        assert channel._message_queue.qsize() == 1
        msg = channel._message_queue.get_nowait()
        assert msg.content == "Hello Sentinel"
        assert msg.source == "signal"
        assert msg.channel_id == "+1234567890"

        # Route through ChannelRouter with mock orchestrator
        mock_orchestrator = MagicMock()
        mock_orchestrator.handle_task = AsyncMock(return_value=MagicMock(
            model_dump=lambda: {"status": "ok", "response": "Done"}
        ))
        mock_orchestrator.approval_manager = None
        router = ChannelRouter(mock_orchestrator, bus)

        await router.handle_message(channel, msg)
        mock_orchestrator.handle_task.assert_called_once()
        call_kwargs = mock_orchestrator.handle_task.call_args
        assert call_kwargs.kwargs["user_request"] == "Hello Sentinel"
        assert call_kwargs.kwargs["source"] == "signal"


@pytest.mark.capability
class TestSignalUnknownSender:
    """Allowlist set → messages from unknown numbers are dropped."""

    async def test_signal_message_from_unknown_sender(self):
        cfg = SignalConfig(
            allowed_senders={"+1111111111", "+2222222222"},
        )
        channel = SignalChannel(cfg)

        reader = FakeSocketReader()
        channel._reader = reader
        channel._running = True

        # Message from a number NOT in the allowlist
        reader.push_line(_make_receive_notification("+9999999999", "Should be dropped"))
        # Message from an allowed number
        reader.stop_on_eof(channel)
        reader.push_line(_make_receive_notification("+1111111111", "Allowed"))
        reader.push_eof()

        await channel._read_loop()

        # Only the allowed message should be queued
        assert channel._message_queue.qsize() == 1
        msg = channel._message_queue.get_nowait()
        assert msg.channel_id == "+1111111111"
        assert msg.content == "Allowed"


@pytest.mark.capability
class TestSignalCrashRecovery:
    """Process exits → _health_monitor detects → _start_process + _connect_socket called."""

    async def test_signal_cli_crash_recovery(self):
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._running = True

        # Simulate a crashed process (returncode set)
        proc = FakeProcess(returncode=1)
        channel._process = proc

        restart_called = False
        connect_called = False

        async def mock_start():
            nonlocal restart_called
            restart_called = True
            channel._process = FakeProcess()  # New process
            channel._running = False  # Stop monitor after one restart

        async def mock_connect():
            nonlocal connect_called
            connect_called = True

        channel._start_process = mock_start
        channel._connect_socket = mock_connect

        with patch("sentinel.channels.signal_channel.asyncio.sleep", new_callable=AsyncMock):
            await channel._health_monitor()

        assert restart_called
        assert connect_called
        assert channel._backoff.attempt == 1


@pytest.mark.capability
class TestSignalCliNotAvailable:
    """create_subprocess_exec raises FileNotFoundError → no crash, send() logs warning."""

    async def test_signal_cli_not_available(self):
        cfg = SignalConfig(signal_cli_path="/nonexistent/signal-cli")
        channel = SignalChannel(cfg)

        # _start_process catches the exception and sets _process = None
        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=FileNotFoundError("signal-cli not found"),
        ):
            await channel._start_process()

        assert channel._process is None

        # send() should not crash when socket is not connected
        msg = OutgoingMessage(channel_id="+1", event_type="test", data={"response": "test"})
        await channel.send(msg)  # should log warning, not raise


@pytest.mark.capability
class TestSignalRateLimiting:
    """Rate limit enforcement: N messages per 60s window per sender."""

    async def test_signal_rate_limiting(self):
        cfg = SignalConfig(rate_limit=3, allowed_senders=["+1111111111", "+2222222222"])
        channel = SignalChannel(cfg)

        reader = FakeSocketReader()
        channel._reader = reader
        channel._running = True

        # Push 5 messages from the same sender — only 3 should be accepted
        for i in range(5):
            reader.push_line(_make_receive_notification("+1111111111", f"Msg {i}"))

        # Also push 2 from a different sender — both should pass (separate window)
        reader.push_line(_make_receive_notification("+2222222222", "Other 1"))
        reader.stop_on_eof(channel)
        reader.push_line(_make_receive_notification("+2222222222", "Other 2"))
        reader.push_eof()

        await channel._read_loop()

        # 3 from first sender + 2 from second sender = 5 total
        assert channel._message_queue.qsize() == 5

        # Verify first sender's messages are the first 3
        messages = []
        while not channel._message_queue.empty():
            messages.append(channel._message_queue.get_nowait())

        sender_1_msgs = [m for m in messages if m.channel_id == "+1111111111"]
        sender_2_msgs = [m for m in messages if m.channel_id == "+2222222222"]
        assert len(sender_1_msgs) == 3
        assert len(sender_2_msgs) == 2


@pytest.mark.capability
class TestSignalResponseSplitting:
    """Long text split into chunks respecting max_length and boundaries."""

    def test_signal_long_response_splitting(self):
        # Build a text with clear paragraph boundaries exceeding 100 chars
        paragraphs = [
            "This is the first paragraph with enough text to matter.",
            "This is the second paragraph that adds more content here.",
            "And a third paragraph to push us well over the limit.",
        ]
        text = "\n\n".join(paragraphs)

        parts = _split_response(text, max_length=100)

        # All parts should be within limit
        for part in parts:
            assert len(part) <= 100, f"Part too long ({len(part)}): {part[:50]}..."

        # Reconstructed text should preserve all content
        reconstructed = "\n\n".join(p.strip() for p in parts)
        assert all(p in reconstructed for p in paragraphs)

        # Should be split into multiple parts
        assert len(parts) >= 2

    def test_short_text_not_split(self):
        """Text within limit returns single chunk."""
        parts = _split_response("Short message", max_length=100)
        assert parts == ["Short message"]

    def test_empty_text(self):
        """Empty input returns single empty string."""
        parts = _split_response("", max_length=100)
        assert parts == [""]

    def test_hard_break_no_boundaries(self):
        """Text with no natural break points gets hard-split."""
        text = "A" * 250
        parts = _split_response(text, max_length=100)
        assert len(parts) == 3
        assert all(len(p) <= 100 for p in parts)
        assert "".join(parts) == text


@pytest.mark.capability
class TestSignalFormattingStrip:
    """_strip_markdown handles bold, headers, links, code blocks, images, rules."""

    def test_signal_formatting_strip(self):
        md = (
            "# Header\n"
            "**bold text** and *italic text*\n"
            "`inline code` here\n"
            "```python\nprint('hello')\n```\n"
            "[link text](https://example.com)\n"
            "![alt text](image.png)\n"
            "---\n"
            "~~strikethrough~~"
        )
        result = _strip_markdown(md)

        # Headers stripped of #
        assert "# Header" not in result
        assert "Header" in result
        # Bold markers removed
        assert "**" not in result
        assert "bold text" in result
        # Italic markers removed
        assert "italic text" in result
        # Inline code backticks removed
        assert "`" not in result
        assert "inline code" in result
        # Code block fences removed
        assert "```" not in result
        assert "print('hello')" in result
        # Link rendered as text only
        assert "link text" in result
        assert "https://example.com" not in result
        # Image rendered as alt text
        assert "alt text" in result
        assert "image.png" not in result
        # Horizontal rule removed
        assert "---" not in result
        # Strikethrough
        assert "~~" not in result
        assert "strikethrough" in result

    def test_format_response_extracts_response(self):
        """_format_response extracts the 'response' field."""
        assert _format_response({"response": "Hello"}) == "Hello"

    def test_format_response_extracts_reason(self):
        """_format_response handles error/block payloads."""
        result = _format_response({"status": "blocked", "reason": "Too risky"})
        assert "Too risky" in result
        assert "blocked" in result

    def test_format_response_empty(self):
        """_format_response handles empty dict."""
        assert _format_response({}) == ""

    def test_format_response_fallback_json(self):
        """_format_response falls back to JSON for unrecognised shapes."""
        result = _format_response({"custom_key": "custom_value"})
        assert "custom_key" in result
        assert "custom_value" in result
