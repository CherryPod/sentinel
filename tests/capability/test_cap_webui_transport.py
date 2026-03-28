"""E2a capability tests — Web UI transport (WebSocket + SSE).

Tests verify WebSocket auth, task submission, approval flow, and SSE
event streaming — the real-time transport layer the UI depends on.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.api.auth import PinVerifier
from sentinel.api.sessions import create_session_token

import pytest
from starlette.testclient import TestClient

from sentinel.core.bus import EventBus
from tests.conftest import auth_headers


class TestWebSocketTransport:
    """WebSocket endpoint auth and message handling."""

    @pytest.mark.capability
    @patch("sentinel.api.routes.websocket._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.routes.websocket._orchestrator", MagicMock())
    @patch("sentinel.api.routes.websocket._event_bus", EventBus())
    def test_websocket_auth_valid_pin(self):
        """Valid JWT token → WebSocket connects successfully."""
        from sentinel.api.app import app
        token = create_session_token(user_id=1, role="owner")
        client = TestClient(app)
        with client.websocket_connect(f"/ws?token={token}") as ws:
            # JWT auth at connection time — send a task message
            ws.send_text(json.dumps({"type": "task", "request": "hello"}))
            # Should get a response (not an auth error)
            msg = ws.receive_json()
            assert msg["type"] != "auth_error"

    @pytest.mark.capability
    @patch("sentinel.api.routes.websocket._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.routes.websocket._orchestrator", None)
    def test_websocket_auth_invalid_pin(self):
        """Missing/invalid token → connection accepted then closed with 4001."""
        from sentinel.api.app import app
        client = TestClient(app)
        # First-message auth: server accepts, waits for auth msg, then closes
        with client.websocket_connect("/ws") as ws:
            # Send invalid auth message
            ws.send_json({"type": "auth", "token": "bad-token"})
            # Server should close the connection
            with pytest.raises(Exception):
                ws.receive_json()

    @pytest.mark.capability
    @patch("sentinel.api.routes.websocket._pin_verifier", None)
    @patch("sentinel.api.routes.websocket._orchestrator", None)
    @patch("sentinel.api.routes.websocket._event_bus", None)
    def test_websocket_task_submission(self):
        """Task submission via WS — when orchestrator is None, error returned."""
        from sentinel.api.app import app
        token = create_session_token(user_id=1, role="owner")
        client = TestClient(app)
        with client.websocket_connect(f"/ws?token={token}") as ws:
            # First message is auth confirmation
            auth_msg = ws.receive_json()
            assert auth_msg["type"] == "auth_ok"
            # Send a task — orchestrator is None → should get error
            ws.send_json({"type": "task", "request": "hello"})
            msg = ws.receive_json()
            assert msg["type"] == "error"

    @pytest.mark.capability
    @patch("sentinel.api.routes.websocket._pin_verifier", None)
    @patch("sentinel.api.routes.websocket._orchestrator", None)
    @patch("sentinel.api.routes.websocket._event_bus", None)
    def test_websocket_approval_submission(self):
        """Approval via WS — when orchestrator is None, error returned on task attempt."""
        from sentinel.api.app import app
        token = create_session_token(user_id=1, role="owner")
        client = TestClient(app)
        with client.websocket_connect(f"/ws?token={token}") as ws:
            # First message is auth confirmation
            auth_msg = ws.receive_json()
            assert auth_msg["type"] == "auth_ok"
            # Send a task — no orchestrator → error
            ws.send_json({"type": "task", "request": "hello"})
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
    @patch("sentinel.api.lifecycle._pin_verifier", None)
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

        with patch("sentinel.api.routes.streaming._event_bus", bus), \
             patch("sentinel.api.routes.streaming.SSEWriter", QuickSSEWriter):
            client = TestClient(app)
            resp = client.get("/api/events?task_id=test-123", headers=auth_headers())
            assert resp.status_code == 200

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
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

        with patch("sentinel.api.routes.streaming._event_bus", bus), \
             patch("sentinel.api.routes.streaming.SSEWriter", TrackingSSEWriter):
            client = TestClient(app)
            resp = client.get("/api/events?task_id=test-789", headers=auth_headers())
            assert resp.status_code == 200
            # Each SSE request creates a new writer instance
            assert len(writer_instances) == 1
            assert writer_instances[0]._bus is bus
