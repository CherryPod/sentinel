"""Tests for WebSocket endpoint and channel implementation."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from sentinel.channels.web import WebSocketChannel
from sentinel.core.bus import EventBus


# ── WebSocketChannel unit tests ──────────────────────────────────


class FakeWebSocket:
    """Minimal WebSocket mock for unit tests."""

    def __init__(self):
        self.client = MagicMock(host="127.0.0.1")
        self.sent = []
        self._receive_queue = asyncio.Queue()
        self.closed = False
        self.close_code = None
        self.close_reason = None

    async def send_json(self, data):
        self.sent.append(data)

    async def receive_text(self):
        return await self._receive_queue.get()

    async def close(self, code=1000, reason=""):
        self.closed = True
        self.close_code = code
        self.close_reason = reason

    def push_message(self, data):
        """Push a message for receive_text to return."""
        if isinstance(data, dict):
            data = json.dumps(data)
        self._receive_queue.put_nowait(data)


class FakeFailureTracker:
    """Minimal failure tracker mock."""

    def __init__(self, locked=False):
        self._locked = locked
        self.failures = []
        self.clears = []

    def is_locked_out(self, ip):
        return self._locked

    def record_failure(self, ip):
        self.failures.append(ip)
        return len(self.failures)

    def clear(self, ip):
        self.clears.append(ip)


class TestWebSocketAuth:
    async def test_auth_success(self):
        """Valid PIN → auth_ok response, returns True."""
        ws = FakeWebSocket()
        ws.push_message({"type": "auth", "pin": "1234"})
        tracker = FakeFailureTracker()

        channel = WebSocketChannel(ws, pin_getter=lambda: "1234", failure_tracker=tracker)
        result = await channel.authenticate()

        assert result is True
        assert ws.sent == [{"type": "auth_ok"}]
        assert tracker.clears == ["127.0.0.1"]

    async def test_auth_no_pin_configured(self):
        """No PIN configured → auto-authenticate."""
        ws = FakeWebSocket()
        tracker = FakeFailureTracker()

        channel = WebSocketChannel(ws, pin_getter=lambda: None, failure_tracker=tracker)
        result = await channel.authenticate()

        assert result is True
        assert ws.sent == [{"type": "auth_ok"}]

    async def test_auth_wrong_pin(self):
        """Wrong PIN → auth_error, connection closed with 4001."""
        ws = FakeWebSocket()
        ws.push_message({"type": "auth", "pin": "9999"})
        tracker = FakeFailureTracker()

        channel = WebSocketChannel(ws, pin_getter=lambda: "1234", failure_tracker=tracker)
        result = await channel.authenticate()

        assert result is False
        assert ws.close_code == 4001
        assert tracker.failures == ["127.0.0.1"]
        # Should have sent auth_error before closing
        assert any(m.get("type") == "auth_error" for m in ws.sent)

    async def test_auth_locked_out(self):
        """Locked out IP → connection closed immediately."""
        ws = FakeWebSocket()
        tracker = FakeFailureTracker(locked=True)

        channel = WebSocketChannel(ws, pin_getter=lambda: "1234", failure_tracker=tracker)
        result = await channel.authenticate()

        assert result is False
        assert ws.close_code == 4001

    async def test_auth_invalid_json(self):
        """Invalid JSON message → connection closed."""
        ws = FakeWebSocket()
        ws.push_message("not json at all {{{")
        tracker = FakeFailureTracker()

        channel = WebSocketChannel(ws, pin_getter=lambda: "1234", failure_tracker=tracker)
        result = await channel.authenticate()

        assert result is False
        assert ws.closed is True

    async def test_auth_wrong_message_type(self):
        """Message with wrong type → connection closed."""
        ws = FakeWebSocket()
        ws.push_message({"type": "task", "request": "hello"})
        tracker = FakeFailureTracker()

        channel = WebSocketChannel(ws, pin_getter=lambda: "1234", failure_tracker=tracker)
        result = await channel.authenticate()

        assert result is False
        assert ws.closed is True

    async def test_auth_timeout(self):
        """No message within timeout → connection closed."""
        ws = FakeWebSocket()
        tracker = FakeFailureTracker()

        channel = WebSocketChannel(ws, pin_getter=lambda: "1234", failure_tracker=tracker)
        # Don't push any message — will timeout
        # Patch the timeout to be very short
        with patch("sentinel.channels.web.asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await channel.authenticate()

        assert result is False
        assert ws.closed is True


class TestWebSocketSend:
    async def test_send_message(self):
        """send() serializes OutgoingMessage to JSON."""
        from sentinel.channels.base import OutgoingMessage

        ws = FakeWebSocket()
        tracker = FakeFailureTracker()
        channel = WebSocketChannel(ws, pin_getter=lambda: None, failure_tracker=tracker)

        msg = OutgoingMessage(
            channel_id="ch1",
            event_type="task.123.started",
            data={"source": "test"},
        )
        await channel.send(msg)

        assert len(ws.sent) == 1
        assert ws.sent[0]["type"] == "task.123.started"
        assert ws.sent[0]["data"]["source"] == "test"


class TestWebSocketReceive:
    async def test_receive_valid_messages(self):
        """receive() yields IncomingMessage for valid JSON."""
        ws = FakeWebSocket()
        tracker = FakeFailureTracker()
        channel = WebSocketChannel(ws, pin_getter=lambda: None, failure_tracker=tracker)

        ws.push_message({"type": "task", "request": "hello"})

        # Receive one message, then simulate disconnect
        messages = []
        async for msg in channel.receive():
            messages.append(msg)
            break  # Only get one

        assert len(messages) == 1
        assert messages[0].content == "hello"
        assert messages[0].metadata["type"] == "task"

    async def test_receive_invalid_json_sends_error(self):
        """Invalid JSON → error response sent, continues listening."""
        ws = FakeWebSocket()
        tracker = FakeFailureTracker()
        channel = WebSocketChannel(ws, pin_getter=lambda: None, failure_tracker=tracker)

        ws.push_message("not json")
        ws.push_message({"type": "task", "request": "real message"})

        messages = []
        async for msg in channel.receive():
            messages.append(msg)
            break  # Get the valid one after the error

        assert len(messages) == 1
        assert messages[0].content == "real message"
        # Error response should have been sent
        assert any(m.get("type") == "error" for m in ws.sent)


# ── Integration test with TestClient ────────────────────────────

class TestWebSocketEndpointIntegration:
    """Test the /ws endpoint with TestClient.

    These require the FastAPI app to be importable but use mocked internals.
    """

    @patch("sentinel.api.app._pin", None)
    @patch("sentinel.api.app._orchestrator", None)
    @patch("sentinel.api.app._event_bus", None)
    def test_ws_no_orchestrator_returns_error(self):
        """WS connects but gets error when orchestrator not initialized."""
        from sentinel.api.app import app
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            # Auth (no PIN required)
            ws.send_text(json.dumps({"type": "auth", "pin": ""}))
            # Should get auth_ok since no PIN configured
            msg = ws.receive_json()
            assert msg["type"] == "auth_ok"
            # Then error about orchestrator
            msg = ws.receive_json()
            assert msg["type"] == "error"

    @patch("sentinel.api.app._pin", "1234")
    @patch("sentinel.api.app._orchestrator", None)
    def test_ws_wrong_pin_closes(self):
        """Wrong PIN → connection closed."""
        from sentinel.api.app import app
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "pin": "9999"}))
            # Should get auth_error then close
            msg = ws.receive_json()
            assert msg["type"] == "auth_error"
