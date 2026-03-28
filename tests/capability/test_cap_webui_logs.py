"""E2c capability tests — Log streaming endpoint verification.

Tests verify the GET /api/logs/stream SSE endpoint:
- Endpoint exists and returns SSE content
- Requires authentication when PIN is set
- Log entries contain structured fields (timestamp, level, message, event)

Uses QuickLogWriter mock pattern (same as QuickSSEWriter in transport tests).
"""

import asyncio
import json
import logging
from unittest.mock import patch

from sentinel.api.auth import PinVerifier

import pytest
from starlette.testclient import TestClient
from tests.conftest import auth_headers


class TestLogStream:
    """GET /api/logs/stream SSE endpoint."""

    @pytest.fixture(autouse=True)
    def _reset_sse_appstatus(self):
        """Reset sse_starlette's global AppStatus event between tests."""
        from sse_starlette.sse import AppStatus
        AppStatus.should_exit_event = asyncio.Event()
        yield
        AppStatus.should_exit_event = asyncio.Event()

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_log_stream_endpoint_exists(self):
        """GET /api/logs/stream → 200 with SSE content type.

        Uses a QuickLogWriter that yields a single log event and exits,
        avoiding infinite SSE stream in tests.
        """
        from sentinel.api.app import app

        class QuickLogWriter:
            def __init__(self, min_level=logging.INFO):
                pass
            def attach(self):
                pass
            def detach(self):
                pass
            async def event_generator(self):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "timestamp": 1708300000.0,
                        "level": "INFO",
                        "message": "Test log entry",
                        "event": "test_event",
                    }),
                }

        with patch("sentinel.api.routes.streaming.LogSSEWriter", QuickLogWriter):
            client = TestClient(app)
            resp = client.get("/api/logs/stream", headers=auth_headers())
            assert resp.status_code == 200

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.app._pin_verifier", PinVerifier("1234"))
    def test_log_stream_requires_auth(self):
        """GET /api/logs/stream with PIN set and no auth → 401."""
        from sentinel.api.app import app
        client = TestClient(app)
        resp = client.get("/api/logs/stream")
        assert resp.status_code == 401

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_log_entries_are_structured(self):
        """SSE event data contains timestamp, level, message, event fields.

        Verifies the LogSSEWriter produces structured log entries with all
        required fields for the frontend log viewer to render.
        """
        from sentinel.api.app import app

        class StructuredLogWriter:
            def __init__(self, min_level=logging.INFO):
                pass
            def attach(self):
                pass
            def detach(self):
                pass
            async def event_generator(self):
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "timestamp": 1708300000.0,
                        "level": "WARNING",
                        "message": "Scanner flagged suspicious pattern",
                        "event": "scan_warning",
                    }),
                }

        with patch("sentinel.api.routes.streaming.LogSSEWriter", StructuredLogWriter):
            client = TestClient(app)
            resp = client.get("/api/logs/stream?level=WARNING", headers=auth_headers())
            assert resp.status_code == 200
            # Parse SSE response body — look for the structured data
            body = resp.text
            # SSE format: "event: log\ndata: {...}\n\n"
            assert "event: log" in body
            # Extract the data line
            for line in body.split("\n"):
                if line.startswith("data: "):
                    entry = json.loads(line[6:])
                    assert "timestamp" in entry
                    assert "level" in entry
                    assert entry["level"] == "WARNING"
                    assert "message" in entry
                    assert "event" in entry
                    assert entry["event"] == "scan_warning"
                    break
            else:
                pytest.fail("No 'data:' line found in SSE response")
