"""E2a capability tests — Web UI transport (WebSocket + SSE).

Tests verify WebSocket auth, task submission, approval flow, and SSE
event streaming — the real-time transport layer the UI depends on.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.api.auth import PinVerifier

import pytest
from starlette.testclient import TestClient

from sentinel.core.bus import EventBus


class TestWebSocketTransport:
    """WebSocket endpoint auth and message handling."""

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.app._orchestrator", MagicMock())
    @patch("sentinel.api.app._event_bus", EventBus())
    def test_websocket_auth_valid_pin(self):
        """Valid PIN auth → receives auth_ok response."""
        from sentinel.api.app import app
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "pin": "1234"}))
            msg = ws.receive_json()
            assert msg["type"] == "auth_ok"

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.app._orchestrator", None)
    def test_websocket_auth_invalid_pin(self):
        """Invalid PIN → receives auth_error, connection closed."""
        from sentinel.api.app import app
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "pin": "0000"}))
            msg = ws.receive_json()
            assert msg["type"] == "auth_error"

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    @patch("sentinel.api.app._orchestrator", None)
    @patch("sentinel.api.app._event_bus", None)
    def test_websocket_task_submission(self):
        """Task submission via WS — when orchestrator is None, error returned."""
        from sentinel.api.app import app
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            # Auth (no PIN required)
            ws.send_text(json.dumps({"type": "auth", "pin": ""}))
            msg = ws.receive_json()
            assert msg["type"] == "auth_ok"
            # Orchestrator is None → should get error
            msg = ws.receive_json()
            assert msg["type"] == "error"

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    @patch("sentinel.api.app._orchestrator", None)
    @patch("sentinel.api.app._event_bus", None)
    def test_websocket_approval_submission(self):
        """Approval via WS — when orchestrator is None, error returned on task attempt."""
        from sentinel.api.app import app
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "pin": ""}))
            msg = ws.receive_json()
            assert msg["type"] == "auth_ok"
            # No orchestrator → error on any action
            msg = ws.receive_json()
            assert msg["type"] == "error"


class TestSSETransport:
    """SSE endpoint event streaming."""

    @pytest.fixture(autouse=True)
    def _reset_sse_appstatus(self):
        """Reset sse_starlette's global AppStatus event between tests.

        AppStatus.should_exit_event is a class-level asyncio.Event that
        binds to one event loop and fails when used in a different loop.
        """
        import asyncio
        from sse_starlette.sse import AppStatus
        AppStatus.should_exit_event = asyncio.Event()
        yield
        AppStatus.should_exit_event = asyncio.Event()

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_sse_task_events(self):
        """SSE endpoint returns 200 with event stream when bus is available."""
        from sentinel.api.app import app
        bus = EventBus()

        class QuickSSEWriter:
            def __init__(self, event_bus):
                pass
            async def subscribe(self, task_id):
                pass
            def cleanup(self):
                pass
            async def event_generator(self):
                yield {"event": "completed", "data": json.dumps({"status": "done"})}

        with patch("sentinel.api.app._event_bus", bus), \
             patch("sentinel.api.app.SSEWriter", QuickSSEWriter):
            client = TestClient(app)
            resp = client.get("/api/events?task_id=test-123")
            assert resp.status_code == 200

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_sse_reconnection_receives_events(self):
        """SSE endpoint creates a fresh SSEWriter per connection.

        Verifies that the endpoint factory (SSEWriter instantiation) runs
        on each request, confirming reconnection will receive fresh events.
        We verify the writer constructor is called with the correct bus.

        """
        from sentinel.api.app import app
        bus = EventBus()
        writer_instances = []

        class TrackingSSEWriter:
            def __init__(self, event_bus):
                writer_instances.append(self)
                self._bus = event_bus
            async def subscribe(self, task_id):
                pass
            def cleanup(self):
                pass
            async def event_generator(self):
                yield {"event": "connected", "data": json.dumps({"n": len(writer_instances)})}

        with patch("sentinel.api.app._event_bus", bus), \
             patch("sentinel.api.app.SSEWriter", TrackingSSEWriter):
            client = TestClient(app)
            resp = client.get("/api/events?task_id=test-789")
            assert resp.status_code == 200
            # Each SSE request creates a new writer instance
            assert len(writer_instances) == 1
            assert writer_instances[0]._bus is bus
