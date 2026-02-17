"""Tests for channel abstraction layer and event bus wiring in the orchestrator."""

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

# Common settings patch for orchestrator tests that bypass CodeShield/etc
_ORCH_SETTINGS = {
    "sentinel.planner.orchestrator.settings": MagicMock(
        conversation_enabled=False,
        spotlighting_enabled=False,
        require_codeshield=False,
        verbose_results=False,
        auto_memory=False,
    ),
}

import pytest

from sentinel.channels.base import (
    Channel,
    ChannelRouter,
    IncomingMessage,
    OutgoingMessage,
)
from sentinel.core.bus import EventBus
from sentinel.core.models import Plan, PlanStep, StepResult, TaskResult


# ── Dataclass tests ──────────────────────────────────────────────


class TestIncomingMessage:
    def test_create_with_defaults(self):
        msg = IncomingMessage(channel_id="ch1", source="test", content="hello")
        assert msg.channel_id == "ch1"
        assert msg.source == "test"
        assert msg.content == "hello"
        assert msg.metadata == {}
        assert msg.timestamp is not None

    def test_create_with_metadata(self):
        msg = IncomingMessage(
            channel_id="ch1", source="ws", content="hi",
            metadata={"type": "task"},
        )
        assert msg.metadata["type"] == "task"


class TestOutgoingMessage:
    def test_create_with_defaults(self):
        msg = OutgoingMessage(channel_id="ch1", event_type="task.started")
        assert msg.channel_id == "ch1"
        assert msg.event_type == "task.started"
        assert msg.data == {}
        assert msg.timestamp is not None

    def test_create_with_data(self):
        msg = OutgoingMessage(
            channel_id="ch1",
            event_type="task.completed",
            data={"status": "success"},
        )
        assert msg.data["status"] == "success"


# ── Channel ABC tests ────────────────────────────────────────────


class TestChannelABC:
    def test_cannot_instantiate_directly(self):
        """Channel is abstract — can't be instantiated without implementing all methods."""
        with pytest.raises(TypeError):
            Channel()

    def test_concrete_subclass_works(self):
        """A subclass that implements all abstract methods can be instantiated."""
        class FakeChannel(Channel):
            channel_type = "fake"
            async def start(self): pass
            async def stop(self): pass
            async def send(self, message): pass
            async def receive(self):
                return
                yield  # make it an async generator

        ch = FakeChannel()
        assert ch.channel_type == "fake"


# ── ChannelRouter tests ──────────────────────────────────────────


class FakeChannel(Channel):
    """Minimal channel implementation for testing the router."""
    channel_type = "test"

    def __init__(self):
        self.sent_messages: list[OutgoingMessage] = []

    async def start(self): pass
    async def stop(self): pass

    async def send(self, message: OutgoingMessage) -> None:
        self.sent_messages.append(message)

    async def receive(self):
        return
        yield


class TestChannelRouter:
    def _make_router(self, orchestrator=None, bus=None):
        orch = orchestrator or AsyncMock()
        bus = bus or EventBus()
        return ChannelRouter(orch, bus), orch, bus

    async def test_handle_message_calls_orchestrator(self):
        """Router calls orchestrator.handle_task with correct args."""
        router, orch, bus = self._make_router()
        orch.handle_task = AsyncMock(return_value=TaskResult(status="success"))

        channel = FakeChannel()
        msg = IncomingMessage(
            channel_id="ch1", source="websocket", content="What is 2+2?",
            metadata={"source_key": "ws:127.0.0.1"},
        )

        task_id = await router.handle_message(channel, msg)
        assert task_id  # should return a UUID string
        uuid.UUID(task_id)  # should not raise

        orch.handle_task.assert_called_once()
        call_kwargs = orch.handle_task.call_args.kwargs
        assert call_kwargs["user_request"] == "What is 2+2?"
        assert call_kwargs["source"] == "websocket"
        assert call_kwargs["task_id"] == task_id

    async def test_handle_message_subscribes_and_unsubscribes(self):
        """Router subscribes to bus events before execution, unsubscribes after."""
        bus = EventBus()
        router, orch, _ = self._make_router(bus=bus)
        orch.handle_task = AsyncMock(return_value=TaskResult(status="success"))

        channel = FakeChannel()
        msg = IncomingMessage(channel_id="ch1", source="test", content="hello")

        # Before
        assert bus.subscriber_count == 0
        await router.handle_message(channel, msg)
        # After — should have unsubscribed
        assert bus.subscriber_count == 0

    async def test_handle_message_forwards_bus_events(self):
        """Events published on the bus during execution are forwarded to the channel."""
        bus = EventBus()
        router, orch, _ = self._make_router(bus=bus)

        channel = FakeChannel()
        msg = IncomingMessage(channel_id="ch1", source="test", content="hello")

        captured_task_id = None

        async def fake_handle_task(**kwargs):
            nonlocal captured_task_id
            captured_task_id = kwargs["task_id"]
            # Simulate orchestrator publishing an event
            await bus.publish(f"task.{captured_task_id}.started", {"source": "test"})
            return TaskResult(status="success")

        orch.handle_task = fake_handle_task
        await router.handle_message(channel, msg)

        # Channel should have received the forwarded event
        assert len(channel.sent_messages) == 1
        assert "started" in channel.sent_messages[0].event_type

    async def test_handle_message_unsubscribes_on_error(self):
        """Router unsubscribes even if orchestrator raises an exception."""
        bus = EventBus()
        router, orch, _ = self._make_router(bus=bus)
        orch.handle_task = AsyncMock(side_effect=RuntimeError("boom"))

        channel = FakeChannel()
        msg = IncomingMessage(channel_id="ch1", source="test", content="hello")

        with pytest.raises(RuntimeError, match="boom"):
            await router.handle_message(channel, msg)

        # Should still have cleaned up subscriptions
        assert bus.subscriber_count == 0

    async def test_handle_approval_granted(self):
        """Router handles approved approvals by executing the plan."""
        router, orch, _ = self._make_router()
        orch._approval_manager = MagicMock()
        orch._approval_manager.submit_approval.return_value = True
        orch.execute_approved_plan = AsyncMock(
            return_value=TaskResult(status="success", plan_summary="done"),
        )

        channel = FakeChannel()
        result = await router.handle_approval(channel, "ap-123", granted=True)
        assert result["status"] == "success"

    async def test_handle_approval_denied(self):
        """Router returns denial status when approval is denied."""
        router, orch, _ = self._make_router()
        orch._approval_manager = MagicMock()
        orch._approval_manager.submit_approval.return_value = True

        channel = FakeChannel()
        result = await router.handle_approval(
            channel, "ap-123", granted=False, reason="Not needed",
        )
        assert result["status"] == "denied"

    async def test_handle_approval_no_manager(self):
        """Router returns error if approval manager is not configured."""
        router, orch, _ = self._make_router()
        orch._approval_manager = None

        channel = FakeChannel()
        result = await router.handle_approval(channel, "ap-123", granted=True)
        assert result["status"] == "error"

    async def test_handle_approval_invalid(self):
        """Router returns error for expired/invalid approval."""
        router, orch, _ = self._make_router()
        orch._approval_manager = MagicMock()
        orch._approval_manager.submit_approval.return_value = False

        channel = FakeChannel()
        result = await router.handle_approval(channel, "ap-invalid", granted=True)
        assert result["status"] == "error"


# ── Orchestrator event bus wiring tests ──────────────────────────


@patch("sentinel.planner.orchestrator.settings", MagicMock(
    conversation_enabled=False, spotlighting_enabled=False,
    require_codeshield=False, verbose_results=False, auto_memory=False,
))
class TestOrchestratorEventBusWiring:
    """Test that the orchestrator publishes events at the correct points."""

    def _make_orchestrator(self, bus=None):
        """Create an orchestrator with mocked dependencies."""
        from sentinel.planner.orchestrator import Orchestrator

        planner = AsyncMock()
        pipeline = MagicMock()
        pipeline.scan_input.return_value = MagicMock(is_clean=True)

        return Orchestrator(
            planner=planner,
            pipeline=pipeline,
            event_bus=bus,
        )

    async def test_events_emitted_on_success(self):
        """Orchestrator emits started, planned, step_completed, completed events."""
        bus = EventBus()
        events_received = []

        async def capture(topic, data):
            events_received.append(topic)

        bus.subscribe("task.*.*", capture)

        orch = self._make_orchestrator(bus=bus)
        plan = Plan(
            plan_summary="Test plan",
            steps=[PlanStep(id="step_1", type="llm_task", description="test", prompt="hello")],
        )
        orch._planner.create_plan = AsyncMock(return_value=plan)
        orch._pipeline.process_with_qwen = AsyncMock(
            return_value=MagicMock(id="d1", content="result", trust_level="untrusted", scan_results={}),
        )

        result = await orch.handle_task("What is 2+2?")

        # Should have: started, planned, step_completed, completed
        event_suffixes = [e.split(".")[-1] for e in events_received]
        assert "started" in event_suffixes
        assert "planned" in event_suffixes
        assert "step_completed" in event_suffixes
        assert "completed" in event_suffixes
        assert result.task_id  # task_id should be set

    async def test_no_events_without_bus(self):
        """Orchestrator works fine without an event bus (None)."""
        orch = self._make_orchestrator(bus=None)
        plan = Plan(
            plan_summary="Test plan",
            steps=[PlanStep(id="step_1", type="llm_task", description="test", prompt="hello")],
        )
        orch._planner.create_plan = AsyncMock(return_value=plan)
        orch._pipeline.process_with_qwen = AsyncMock(
            return_value=MagicMock(id="d1", content="result", trust_level="untrusted", scan_results={}),
        )

        result = await orch.handle_task("What is 2+2?")
        assert result.status == "success"
        assert result.task_id  # task_id still assigned even without bus

    async def test_task_id_passed_through(self):
        """If a task_id is provided, the orchestrator uses it instead of generating one."""
        bus = EventBus()
        events_received = []

        async def capture(topic, data):
            events_received.append(topic)

        bus.subscribe("task.*.*", capture)

        orch = self._make_orchestrator(bus=bus)
        plan = Plan(
            plan_summary="Test plan",
            steps=[PlanStep(id="step_1", type="llm_task", description="test", prompt="hello")],
        )
        orch._planner.create_plan = AsyncMock(return_value=plan)
        orch._pipeline.process_with_qwen = AsyncMock(
            return_value=MagicMock(id="d1", content="result", trust_level="untrusted", scan_results={}),
        )

        custom_id = "custom-task-id-123"
        result = await orch.handle_task("test", task_id=custom_id)

        assert result.task_id == custom_id
        # All events should use the custom task_id
        for event in events_received:
            assert custom_id in event

    async def test_task_id_in_result(self):
        """TaskResult includes the task_id field."""
        result = TaskResult(task_id="abc-123", status="success")
        assert result.task_id == "abc-123"
        d = result.model_dump()
        assert d["task_id"] == "abc-123"

    async def test_task_id_default_empty(self):
        """TaskResult task_id defaults to empty string."""
        result = TaskResult(status="error")
        assert result.task_id == ""
