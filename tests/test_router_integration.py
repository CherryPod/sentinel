"""End-to-end: message -> ChannelRouter -> MessageRouter -> fast path."""
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.channels.base import ChannelRouter, Channel, IncomingMessage, OutgoingMessage
from sentinel.core.bus import EventBus
from sentinel.core.models import TaskResult


class FakeChannel(Channel):
    channel_type = "test"
    def __init__(self):
        self.sent: list[OutgoingMessage] = []
    async def start(self): pass
    async def stop(self): pass
    async def send(self, msg): self.sent.append(msg)
    async def receive(self):
        return; yield


@pytest.mark.asyncio
async def test_channel_router_delegates_to_message_router():
    """When message_router is provided, ChannelRouter calls route() not handle_task()."""
    bus = EventBus()
    message_router = AsyncMock()
    message_router.route.return_value = TaskResult(status="success")

    orchestrator = AsyncMock()
    cr = ChannelRouter(orchestrator, bus, message_router=message_router)

    channel = FakeChannel()
    msg = IncomingMessage(channel_id="ch1", source="signal", content="weather",
                          metadata={"source_key": "s:1"})

    task_id = await cr.handle_message(channel, msg)
    assert task_id
    message_router.route.assert_awaited_once()
    orchestrator.handle_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_channel_router_without_message_router_uses_orchestrator():
    """Without message_router, ChannelRouter calls orchestrator directly (backward compat)."""
    bus = EventBus()
    orchestrator = AsyncMock()
    orchestrator.handle_task = AsyncMock(return_value=TaskResult(status="success"))

    cr = ChannelRouter(orchestrator, bus)  # no message_router

    channel = FakeChannel()
    msg = IncomingMessage(channel_id="ch1", source="test", content="hello",
                          metadata={"source_key": "t:1"})

    await cr.handle_message(channel, msg)
    orchestrator.handle_task.assert_awaited_once()


@pytest.mark.asyncio
async def test_channel_router_approval_not_affected():
    """handle_approval() does not use the message router."""
    bus = EventBus()
    message_router = AsyncMock()
    orchestrator = AsyncMock()
    orchestrator.approval_manager = MagicMock()
    orchestrator.submit_approval = AsyncMock(return_value=False)

    cr = ChannelRouter(orchestrator, bus, message_router=message_router)

    result = await cr.handle_approval(FakeChannel(), "some-id", True)
    assert result["status"] == "error"
    message_router.route.assert_not_awaited()
