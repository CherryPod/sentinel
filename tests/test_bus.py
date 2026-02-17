"""Tests for sentinel.core.bus — async event bus with wildcard matching."""

import asyncio

import pytest

from sentinel.core.bus import EventBus


@pytest.fixture
def bus():
    return EventBus()


class TestSubscribe:
    def test_subscribe_adds_handler(self, bus):
        async def handler(topic, data):
            pass

        bus.subscribe("task.*", handler)
        assert bus.subscriber_count == 1
        assert "task.*" in bus.patterns

    def test_subscribe_same_handler_twice_is_idempotent(self, bus):
        async def handler(topic, data):
            pass

        bus.subscribe("task.*", handler)
        bus.subscribe("task.*", handler)
        assert bus.subscriber_count == 1

    def test_subscribe_different_handlers(self, bus):
        async def handler1(topic, data):
            pass

        async def handler2(topic, data):
            pass

        bus.subscribe("task.*", handler1)
        bus.subscribe("task.*", handler2)
        assert bus.subscriber_count == 2

    def test_subscribe_different_patterns(self, bus):
        async def handler(topic, data):
            pass

        bus.subscribe("task.*", handler)
        bus.subscribe("session.*", handler)
        assert bus.subscriber_count == 2
        assert len(bus.patterns) == 2


class TestUnsubscribe:
    def test_unsubscribe_removes_handler(self, bus):
        async def handler(topic, data):
            pass

        bus.subscribe("task.*", handler)
        bus.unsubscribe("task.*", handler)
        assert bus.subscriber_count == 0
        assert "task.*" not in bus.patterns

    def test_unsubscribe_nonexistent_handler_is_noop(self, bus):
        async def handler(topic, data):
            pass

        bus.unsubscribe("task.*", handler)
        assert bus.subscriber_count == 0

    def test_unsubscribe_wrong_pattern_is_noop(self, bus):
        async def handler(topic, data):
            pass

        bus.subscribe("task.*", handler)
        bus.unsubscribe("session.*", handler)
        assert bus.subscriber_count == 1


class TestPublish:
    @pytest.mark.asyncio
    async def test_exact_match(self, bus):
        received = []

        async def handler(topic, data):
            received.append((topic, data))

        bus.subscribe("task.created", handler)
        await bus.publish("task.created", {"id": "t1"})
        assert len(received) == 1
        assert received[0] == ("task.created", {"id": "t1"})

    @pytest.mark.asyncio
    async def test_wildcard_match(self, bus):
        received = []

        async def handler(topic, data):
            received.append(topic)

        bus.subscribe("task.*", handler)
        await bus.publish("task.created")
        await bus.publish("task.completed")
        await bus.publish("session.started")  # should NOT match
        assert received == ["task.created", "task.completed"]

    @pytest.mark.asyncio
    async def test_no_match_no_call(self, bus):
        received = []

        async def handler(topic, data):
            received.append(topic)

        bus.subscribe("task.*", handler)
        await bus.publish("session.started")
        assert received == []

    @pytest.mark.asyncio
    async def test_multiple_handlers_called(self, bus):
        results = []

        async def handler1(topic, data):
            results.append("h1")

        async def handler2(topic, data):
            results.append("h2")

        bus.subscribe("task.*", handler1)
        bus.subscribe("task.*", handler2)
        await bus.publish("task.created")
        assert sorted(results) == ["h1", "h2"]

    @pytest.mark.asyncio
    async def test_data_passed_through(self, bus):
        received_data = []

        async def handler(topic, data):
            received_data.append(data)

        bus.subscribe("task.*", handler)
        payload = {"key": "value", "nested": {"a": 1}}
        await bus.publish("task.created", payload)
        assert received_data == [payload]

    @pytest.mark.asyncio
    async def test_none_data_default(self, bus):
        received_data = []

        async def handler(topic, data):
            received_data.append(data)

        bus.subscribe("task.*", handler)
        await bus.publish("task.created")
        assert received_data == [None]

    @pytest.mark.asyncio
    async def test_handler_error_does_not_stop_others(self, bus):
        results = []

        async def bad_handler(topic, data):
            raise ValueError("boom")

        async def good_handler(topic, data):
            results.append("ok")

        bus.subscribe("task.*", bad_handler)
        bus.subscribe("task.*", good_handler)
        await bus.publish("task.created")
        assert results == ["ok"]

    @pytest.mark.asyncio
    async def test_publish_with_no_subscribers(self, bus):
        # Should not raise
        await bus.publish("orphan.event", {"data": 1})


class TestWildcardPatterns:
    @pytest.mark.asyncio
    async def test_star_matches_any_suffix(self, bus):
        received = []

        async def handler(topic, data):
            received.append(topic)

        bus.subscribe("approval.*", handler)
        await bus.publish("approval.requested")
        await bus.publish("approval.decided")
        await bus.publish("approval.expired")
        assert len(received) == 3

    @pytest.mark.asyncio
    async def test_exact_and_wildcard_both_fire(self, bus):
        received = []

        async def exact_handler(topic, data):
            received.append(("exact", topic))

        async def wild_handler(topic, data):
            received.append(("wild", topic))

        bus.subscribe("task.created", exact_handler)
        bus.subscribe("task.*", wild_handler)
        await bus.publish("task.created")
        assert ("exact", "task.created") in received
        assert ("wild", "task.created") in received

    @pytest.mark.asyncio
    async def test_star_star_matches_nested(self, bus):
        received = []

        async def handler(topic, data):
            received.append(topic)

        bus.subscribe("memory.*", handler)
        await bus.publish("memory.stored")
        await bus.publish("memory.searched")
        assert len(received) == 2


class TestAllTopicPrefixes:
    """Verify all documented topic prefixes work."""

    PREFIXES = ["task", "approval", "session", "channel", "routine", "memory"]

    @pytest.mark.asyncio
    async def test_all_prefixes(self, bus):
        received = []

        async def handler(topic, data):
            received.append(topic)

        for prefix in self.PREFIXES:
            bus.subscribe(f"{prefix}.*", handler)

        for prefix in self.PREFIXES:
            await bus.publish(f"{prefix}.test_event")

        assert len(received) == len(self.PREFIXES)
