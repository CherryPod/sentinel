"""Tests for SSE endpoint and SSEWriter implementation."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.channels.web import SSEWriter
from sentinel.core.bus import EventBus


# ── SSEWriter unit tests ─────────────────────────────────────────


class TestSSEWriter:
    async def test_subscribe_registers_on_bus(self):
        """subscribe() registers a handler on the event bus."""
        bus = EventBus()
        writer = SSEWriter(bus)
        await writer.subscribe("task-123")

        assert bus.subscriber_count == 1
        assert "task.task-123.*" in bus.patterns

    async def test_events_appear_in_generator(self):
        """Events published on the bus appear in the SSE generator."""
        bus = EventBus()
        writer = SSEWriter(bus)
        await writer.subscribe("task-123")

        # Publish an event
        await bus.publish("task.task-123.started", {"source": "test"})

        # Collect events with timeout
        events = []
        async for event in writer.event_generator():
            events.append(event)
            break  # Just get the first one

        assert len(events) == 1
        assert events[0]["event"] == "started"
        data = json.loads(events[0]["data"])
        assert data["source"] == "test"

    async def test_completed_event_ends_stream(self):
        """A 'completed' event signals the generator to stop."""
        bus = EventBus()
        writer = SSEWriter(bus)
        await writer.subscribe("task-456")

        # Publish started + completed
        await bus.publish("task.task-456.started", {"source": "test"})
        await bus.publish("task.task-456.completed", {"status": "success"})

        events = []
        async for event in writer.event_generator():
            events.append(event)

        event_types = [e["event"] for e in events]
        assert "started" in event_types
        assert "completed" in event_types

    async def test_cleanup_unsubscribes(self):
        """cleanup() removes all subscriptions from the bus."""
        bus = EventBus()
        writer = SSEWriter(bus)
        await writer.subscribe("task-789")
        assert bus.subscriber_count == 1

        writer.cleanup()
        assert bus.subscriber_count == 0

    async def test_generator_cleans_up_on_exit(self):
        """Generator auto-cleans up subscriptions when it exits."""
        bus = EventBus()
        writer = SSEWriter(bus)
        await writer.subscribe("task-abc")

        await bus.publish("task.task-abc.completed", {"status": "success"})

        async for _ in writer.event_generator():
            pass

        # Should have cleaned up
        assert bus.subscriber_count == 0

    async def test_keepalive_on_timeout(self):
        """If no events arrive within timeout, a keepalive comment is sent."""
        bus = EventBus()
        writer = SSEWriter(bus)
        await writer.subscribe("task-keep")

        # Override the timeout to be very short for testing
        events = []

        async def collect_with_short_timeout():
            """Collect events from generator with very short timeout."""
            original_gen = writer.event_generator()
            async for event in original_gen:
                events.append(event)
                # After first event (keepalive), stop
                break

        # Patch wait_for to timeout immediately
        original_wait_for = asyncio.wait_for
        call_count = 0

        async def fast_timeout(coro, timeout):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise asyncio.TimeoutError
            return await original_wait_for(coro, timeout=0.1)

        with patch("sentinel.channels.web.asyncio.wait_for", side_effect=fast_timeout):
            await bus.publish("task.task-keep.completed", {"done": True})
            await collect_with_short_timeout()

        # First event should be a keepalive comment
        assert len(events) >= 1
        assert events[0].get("comment") == "keepalive"

    async def test_multiple_subscriptions(self):
        """Writer can subscribe to events for multiple tasks."""
        bus = EventBus()
        writer = SSEWriter(bus)
        await writer.subscribe("task-a")
        await writer.subscribe("task-b")

        assert bus.subscriber_count == 2
        writer.cleanup()
        assert bus.subscriber_count == 0


# ── SSE Endpoint integration test ─────────────────────────────


class TestSSEEndpoint:
    @patch("sentinel.api.app._pin", None)
    @patch("sentinel.api.app._event_bus", None)
    def test_sse_no_bus_returns_503(self):
        """SSE endpoint returns 503 when event bus is not initialized."""
        from starlette.testclient import TestClient
        from sentinel.api.app import app

        client = TestClient(app)
        resp = client.get("/api/events?task_id=test-123")
        assert resp.status_code == 503

    @patch("sentinel.api.app._pin", None)
    def test_sse_missing_task_id_returns_422(self):
        """SSE endpoint returns 422 when task_id is missing."""
        from starlette.testclient import TestClient
        from sentinel.api.app import app

        client = TestClient(app)
        resp = client.get("/api/events")
        assert resp.status_code == 422

    @patch("sentinel.api.app._pin", None)
    def test_sse_with_bus_returns_200(self):
        """SSE endpoint returns 200 when event bus is available.

        We patch the SSEWriter at the app module level so the endpoint
        uses our mock that immediately yields a completed event and stops.
        """
        from starlette.testclient import TestClient
        from sentinel.api.app import app
        from sentinel.core.bus import EventBus

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
