"""Channel abstraction layer for multi-channel access.

Defines the Channel ABC that all transport backends (WebSocket, SSE, Signal, MCP)
implement, plus dataclasses for message routing and a ChannelRouter that connects
channels to the orchestrator via the event bus.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from sentinel.core.decorators import no_audit_log
from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import create_tagged_data

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sentinel.core.bus import EventBus
    from sentinel.core.config import Settings

logger = logging.getLogger(__name__)


@no_audit_log
def _format_file_size(size_bytes: int) -> str:
    """Format bytes as human-readable MB string."""
    return f"{size_bytes / 1_048_576:.1f} MB"


@no_audit_log
def _sanitise_for_prompt(value: str) -> str:
    """Strip control characters and angle brackets from a string before
    interpolating it into the planner prompt. Defends against newline
    injection (fake [ATTACHMENTS] entries) and XML tag interference."""
    return value.replace("\n", "").replace("\r", "").replace("<", "").replace(">", "")


def format_attachment_context(attachments: list[dict]) -> str:
    """Format attachment metadata into a text block for the planner.

    Returns an [ATTACHMENTS] block listing each attachment's type, size,
    and workspace path. The planner sees metadata only — never file content.
    Returns empty string if no attachments.
    """
    if not attachments:
        return ""

    lines = ["[ATTACHMENTS]"]
    for att in attachments:
        mime = _sanitise_for_prompt(att.get("mime_type", "unknown"))
        size = _format_file_size(att.get("file_size", 0))
        path = att.get("workspace_path", "")
        # Use safe_filename (already sanitised upstream) rather than
        # original_filename which comes directly from the sender.
        name = _sanitise_for_prompt(
            att.get("safe_filename") or att.get("original_filename", "unknown")
        )
        logger.debug(
            "Formatting attachment for planner context",
            extra={
                "event": "attachment.context_format",
                "attachment_id": att.get("attachment_id", "unknown"),
                "mime_type": mime,
                "file_size": att.get("file_size", 0),
            },
        )
        lines.append(f"- {name} ({mime}, {size}): {path}")

    return "\n".join(lines)


@dataclass(frozen=True)
class ChannelDescriptor:
    """Declares channel metadata — set as a ClassVar on each Channel subclass.

    The registry reads these fields to wire tool dispatch, keyword patterns,
    health checks, episodic domain mappings, and template previews without
    any per-channel branching in consumer code.
    """

    name: str  # "signal", "telegram", "matrix", "email"
    tool_name: str  # "signal_send" — executor handler key. "" for non-tool channels
    tool_description: str  # human-readable, included in planner tool list
    domain: str  # "messaging" — for episodic TOOL_TO_DOMAIN
    config_prefix: str  # "signal_" — identifies settings fields
    health_check: bool = True  # include in /health endpoint
    keywords: tuple[
        str, ...
    ] = ()  # keyword classifier patterns for this channel's tool
    preview_label: str = ""  # "Signal" — for template preview formatting
    needs_recipient: bool = (
        True  # Signal/Telegram need explicit recipient; Matrix auto-resolves
    )


@dataclass
class IncomingMessage:
    """A message received from a channel."""

    channel_id: str
    source: str  # e.g. "websocket", "signal", "mcp"
    content: str
    metadata: dict = field(default_factory=dict)
    attachments: list[dict] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class OutgoingMessage:
    """A message to send to a channel."""

    channel_id: str
    event_type: str  # e.g. "task.started", "task.completed"
    data: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class Channel(ABC):
    """Abstract base class for all transport channels.

    Subclasses must define a ``descriptor`` ClassVar and implement all
    abstract methods.  The descriptor drives registry-based wiring — tool
    dispatch, keyword patterns, health checks, and template previews all
    read from the descriptor instead of branching on channel names.
    """

    descriptor: ClassVar[ChannelDescriptor]
    channel_type: str = ""  # backward compat — derived from descriptor.name

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Derive channel_type from descriptor if the subclass provides one.
        # Keeps backward compat for code that reads channel.channel_type.
        if hasattr(cls, "descriptor"):
            cls.channel_type = cls.descriptor.name

    # -- Lifecycle (unchanged) -------------------------------------------------

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

    # -- Registry extensions ---------------------------------------------------

    @classmethod
    @abstractmethod
    def from_settings(cls, settings: Settings) -> Channel | None:
        """Build a channel instance from flat Settings fields.

        Returns None if the channel is disabled in config, which tells
        the registry to skip it entirely.
        """

    @abstractmethod
    async def send_message(self, text: str, recipient: str | None = None) -> dict:
        """High-level send for tool dispatch.

        Builds an OutgoingMessage internally so callers don't need to
        know the message structure. Returns a result dict.
        """

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Whether the channel is currently active. Used by health checks."""

    @no_audit_log
    def get_sender_id(self, message: IncomingMessage) -> str:
        """Extract the sender identifier from an incoming message.

        Default: uses message.channel_id. Channels where the sender is
        elsewhere (e.g. Matrix uses metadata["sender"]) override this.
        """
        return message.channel_id

    @no_audit_log
    def get_source_key(self, message: IncomingMessage) -> str:
        """Build a source_key for contact resolution and loop tracking.

        Default: '{channel_name}:{sender_id}'. Override if needed.
        """
        return f"{self.descriptor.name}:{self.get_sender_id(message)}"


class NullChannel(Channel):
    """No-op channel for fire-and-forget contexts (e.g. webhooks).

    All operations are async-safe and silently discard output.
    """

    descriptor = ChannelDescriptor(
        name="null",
        tool_name="",
        tool_description="",
        domain="",
        config_prefix="",
        health_check=False,
    )

    @no_audit_log
    async def start(self) -> None:
        pass

    @no_audit_log
    async def stop(self) -> None:
        pass

    @no_audit_log
    async def send(self, message: OutgoingMessage) -> None:
        pass

    @no_audit_log
    async def receive(self) -> AsyncIterator[IncomingMessage]:
        return
        yield  # pragma: no cover

    @classmethod
    @no_audit_log
    def from_settings(cls, settings: Settings) -> NullChannel:
        return cls()

    @no_audit_log
    async def send_message(self, text: str, recipient: str | None = None) -> dict:
        return {"status": "discarded"}

    @property
    @no_audit_log
    def is_running(self) -> bool:
        return False


class ChannelRouter:
    """Routes messages between channels and the orchestrator via the event bus.

    Handles subscription lifecycle: subscribes a channel to task events before
    execution starts, and unsubscribes after completion.
    """

    def __init__(
        self,
        orchestrator,
        event_bus: EventBus,
        audit_logger=None,
        *,
        message_router=None,
        loop_controller=None,
        loop_store=None,
    ):
        self._orchestrator = orchestrator
        self._bus = event_bus
        self._audit = audit_logger
        self._message_router = message_router
        self._loop_controller = loop_controller
        self._loop_store = loop_store

    async def handle_message(
        self,
        channel: Channel,
        message: IncomingMessage,
    ) -> str:
        """Route an incoming message through the orchestrator.

        1. Generate a task_id
        2. Subscribe channel.send to bus events for this task
        3. Call orchestrator.handle_task() with the task_id and bus
        4. Unsubscribe after completion

        Returns the task_id for tracking.
        """
        task_id = str(uuid.uuid4())

        # Enrich request with attachment metadata so the planner knows
        # media files are available. Planner sees paths and MIME types
        # only — never file content (privacy boundary preserved).
        attachment_block = format_attachment_context(message.attachments)
        if attachment_block:
            effective_request = f"{message.content}\n\n{attachment_block}"
            logger.info(
                "Attachment metadata enriched into request",
                extra={
                    "event": "attachment.context_enriched",
                    "task_id": task_id,
                    "attachment_count": len(message.attachments),
                    "context_length": len(attachment_block),
                },
            )
        else:
            logger.debug(
                "handle_message: clean",
                extra={"event": "attachment.context_enriched.clean"},
            )
            effective_request = message.content

        # Q8.fix.a — wrap the post-enrichment request as UNTRUSTED at the
        # channel ingress boundary. Covers every channel transport that
        # funnels through this router (signal/telegram/matrix/email/web/
        # webhook/WebSocket). Caller-supplied trust assertions are
        # structurally absent from IncomingMessage; mint our own tag.
        effective_tagged = await create_tagged_data(
            content=effective_request,
            source=DataSource.USER,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from=(f"ingress:channel:{message.source}:{message.channel_id}"),
        )
        user_request_data_id = effective_tagged.id
        logger.info(
            "Channel ingress tagged UNTRUSTED",
            extra={
                "event": "channel.ingress_tagged",
                "task_id": task_id,
                "source": message.source,
                "channel_id": message.channel_id,
                "data_id": user_request_data_id,
                "request_len": len(effective_request),
            },
        )

        pattern = f"task.{task_id}.*"

        # Circuit breaker: unsubscribe after consecutive send failures
        _consecutive_failures = 0
        _max_failures = 5

        async def _forward_to_channel(topic: str, data):
            nonlocal _consecutive_failures
            logger.info(
                "forward_to_channel fired",
                extra={
                    "event": "forward.to_channel",
                    "topic": topic,
                    "channel_type": channel.channel_type,
                },
            )
            event_type = topic  # e.g. "task.<id>.started"
            out = OutgoingMessage(
                channel_id=message.channel_id,
                event_type=event_type,
                data=data if isinstance(data, dict) else {"payload": data},
            )
            try:
                await channel.send(out)
                _consecutive_failures = 0
            except Exception as exc:
                _consecutive_failures += 1
                logger.warning(
                    "Channel send failed",
                    exc_info=True,
                    extra={
                        "event": "channel.send_failed",
                        "channel": channel.channel_type,
                        "channel_id": message.channel_id,
                        "error": str(exc),
                        "consecutive_failures": _consecutive_failures,
                    },
                )
                if _consecutive_failures >= _max_failures:
                    logger.error(
                        "Channel circuit breaker tripped — unsubscribing",
                        exc_info=True,
                        extra={
                            "event": "channel.circuit_breaker",
                            "channel": channel.channel_type,
                            "channel_id": message.channel_id,
                            "failures": _consecutive_failures,
                        },
                    )
                    self._bus.unsubscribe(pattern, _forward_to_channel)

        self._bus.subscribe(pattern, _forward_to_channel)
        try:
            # Loop controller wraps every task with gap-driven retry (default 5 attempts).
            # Falls back to single-pass if loop controller not available.
            if self._loop_controller is not None and self._loop_store is not None:
                from sentinel.core.config import settings
                from sentinel.core.context import current_user_id

                source = message.source
                source_key = message.metadata.get("source_key")
                approval_mode = message.metadata.get("approval_mode", "auto")

                async def _execute(user_request: str, src: str):
                    if self._message_router is not None:
                        return await self._message_router.route(
                            user_request=user_request,
                            source=src,
                            approval_mode=approval_mode,
                            source_key=source_key,
                            task_id=task_id,
                            user_request_data_id=user_request_data_id,
                        )
                    return await self._orchestrator.handle_task(
                        user_request=user_request,
                        source=src,
                        approval_mode=approval_mode,
                        source_key=source_key,
                        task_id=task_id,
                        user_request_data_id=user_request_data_id,
                    )

                user_id = current_user_id.get()
                if user_id == 0:
                    raise RuntimeError(
                        "channels.base: run_loop dispatch requires user context"
                    )
                await self._loop_controller.run_loop(
                    loop_id=task_id,
                    user_id=user_id,
                    request=effective_request,
                    max_iterations=settings.loop_max_iterations,
                    timeout_seconds=settings.loop_timeout_seconds,
                    source=source,
                    execute_fn=_execute,
                )
            elif self._message_router is not None:
                await self._message_router.route(
                    user_request=effective_request,
                    source=message.source,
                    approval_mode=message.metadata.get("approval_mode", "auto"),
                    source_key=message.metadata.get("source_key"),
                    task_id=task_id,
                    user_request_data_id=user_request_data_id,
                )
            else:
                await self._orchestrator.handle_task(
                    user_request=effective_request,
                    source=message.source,
                    approval_mode=message.metadata.get("approval_mode", "auto"),
                    source_key=message.metadata.get("source_key"),
                    task_id=task_id,
                    user_request_data_id=user_request_data_id,
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
        source_key: str | None = None,
    ) -> dict:
        """Handle an approval decision from a channel.

        ``source_key`` is forwarded to the orchestrator and, when provided,
        enforces transport-session binding on the approval submission
        (Q3-F4): a reconnected transport session cannot submit an approval
        created on a prior session, even if it knows the approval_id.
        Transports without per-session keys pass None.

        Returns the result of executing the approved plan, or a status dict.
        """
        logger.debug(
            "handle_approval called",
            extra={
                "event": "base.handle_approval",
                "channel_type": type(channel).__name__,
                "approval_id": approval_id,
                "granted": granted,
            },
        )
        if self._orchestrator.approval_manager is None:
            logger.warning(
                "handle_approval: no approval manager",
                extra={
                    "event": "base.handle_approval.no_manager",
                    "approval_id": approval_id,
                },
            )
            return {"status": "error", "reason": "Approval manager not available"}

        accepted = await self._orchestrator.submit_approval(
            approval_id=approval_id,
            granted=granted,
            reason=reason,
            source_key=source_key,
        )
        if not accepted:
            logger.info(
                "handle_approval: rejected",
                extra={
                    "event": "base.handle_approval.rejected",
                    "approval_id": approval_id,
                },
            )
            return {
                "status": "error",
                "reason": "Invalid, expired, or duplicate approval",
            }
        logger.debug(
            "handle_approval: not_accepted_passed",
            extra={
                "event": "base.handle_approval.rejected.passed",
                "reason": "not_accepted_passed",
            },
        )  # auto:neg

        if granted:
            result = await self._orchestrator.execute_approved_plan(approval_id)
            return result.model_dump()

        return {"status": "denied", "reason": reason}
