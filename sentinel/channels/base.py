"""Channel abstraction layer for multi-channel access.

Defines the Channel ABC that all transport backends (WebSocket, SSE, Signal, MCP)
implement, plus dataclasses for message routing and a ChannelRouter that connects
channels to the orchestrator via the event bus.
"""

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.core.bus import EventBus


@dataclass
class IncomingMessage:
    """A message received from a channel."""
    channel_id: str
    source: str          # e.g. "websocket", "signal", "mcp"
    content: str
    metadata: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class OutgoingMessage:
    """A message to send to a channel."""
    channel_id: str
    event_type: str      # e.g. "task.started", "task.completed"
    data: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Channel(ABC):
    """Abstract base class for all transport channels."""
    channel_type: str = ""  # "websocket", "sse", "signal", "mcp"

    @abstractmethod
    async def start(self) -> None:
        """Initialize the channel (connect, bind, etc.)."""

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully shut down the channel."""

    @abstractmethod
    async def send(self, message: OutgoingMessage) -> None:
        """Send a message to the remote end."""

    @abstractmethod
    async def receive(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages from the remote end."""
        # Must be overridden with `async def receive(self) -> AsyncIterator[...]:`
        # Using yield to make this a valid abstract async generator
        yield  # pragma: no cover


class ChannelRouter:
    """Routes messages between channels and the orchestrator via the event bus.

    Handles subscription lifecycle: subscribes a channel to task events before
    execution starts, and unsubscribes after completion.
    """

    def __init__(self, orchestrator, event_bus: EventBus, audit_logger=None):
        self._orchestrator = orchestrator
        self._bus = event_bus
        self._audit = audit_logger

    async def handle_message(
        self, channel: Channel, message: IncomingMessage,
    ) -> str:
        """Route an incoming message through the orchestrator.

        1. Generate a task_id
        2. Subscribe channel.send to bus events for this task
        3. Call orchestrator.handle_task() with the task_id and bus
        4. Unsubscribe after completion

        Returns the task_id for tracking.
        """
        task_id = str(uuid.uuid4())
        pattern = f"task.{task_id}.*"

        # Create a bus handler that forwards events to the channel
        async def _forward_to_channel(topic: str, data):
            event_type = topic  # e.g. "task.<id>.started"
            out = OutgoingMessage(
                channel_id=message.channel_id,
                event_type=event_type,
                data=data if isinstance(data, dict) else {"payload": data},
            )
            try:
                await channel.send(out)
            except Exception:
                pass  # channel may have disconnected

        self._bus.subscribe(pattern, _forward_to_channel)
        try:
            result = await self._orchestrator.handle_task(
                user_request=message.content,
                source=message.source,
                approval_mode=message.metadata.get("approval_mode", "auto"),
                source_key=message.metadata.get("source_key"),
                task_id=task_id,
            )
            return task_id
        finally:
            self._bus.unsubscribe(pattern, _forward_to_channel)

    async def handle_approval(
        self,
        channel: Channel,
        approval_id: str,
        granted: bool,
        reason: str = "",
    ) -> dict:
        """Handle an approval decision from a channel.

        Returns the result of executing the approved plan, or a status dict.
        """
        if self._orchestrator._approval_manager is None:
            return {"status": "error", "reason": "Approval manager not available"}

        accepted = self._orchestrator._approval_manager.submit_approval(
            approval_id=approval_id,
            granted=granted,
            reason=reason,
        )
        if not accepted:
            return {"status": "error", "reason": "Invalid, expired, or duplicate approval"}

        if granted:
            result = await self._orchestrator.execute_approved_plan(approval_id)
            return result.model_dump()

        return {"status": "denied", "reason": reason}
