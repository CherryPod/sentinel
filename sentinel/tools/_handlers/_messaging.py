"""Messaging handler mixin — generic channel send via registry.

Replaced per-channel _signal_send / _telegram_send / _matrix_send with a
generic _make_channel_handler() factory during Phase 1 Session 3 (channel
registry wiring migration).

The mixin expects these attributes on self (provided by ToolExecutor):
  - _channel_registry: ChannelRegistry (or None)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.security.provenance import create_tagged_data
from sentinel.tools._handlers._types import ToolError

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from sentinel.channels.base import Channel

logger = logging.getLogger(__name__)


class MessagingHandlerMixin:
    """Generic messaging tool handlers — one factory, any channel."""

    # -- Tool descriptions ---------------------------------------------------

    def _messaging_tool_descriptions(self) -> list[dict]:
        """Dynamic messaging tool descriptions from channel registry."""
        if self._channel_registry is None:
            return []
        return self._channel_registry.tool_descriptions()

    # -- Generic handler factory ---------------------------------------------

    @staticmethod
    def _make_channel_handler(
        channel: Channel,
    ) -> Callable[[Any, dict], Coroutine[Any, Any, tuple[TaggedData, dict | None]]]:
        """Build an async handler for a messaging channel.

        Returns a bound async method that validates input, calls
        channel.send_message(), and returns tagged data. Each channel
        handles its own OutgoingMessage construction internally.
        """
        tool_name = channel.descriptor.tool_name
        ch_name = channel.descriptor.name
        needs_recipient = channel.descriptor.needs_recipient

        async def _handle(
            self_executor: Any, args: dict
        ) -> tuple[TaggedData, dict | None]:
            logger.debug(
                "%s: entry",
                tool_name,
                extra={
                    "event": f"{ch_name}.send_entry",
                    "message_len": len(args.get("message", "")),
                    "has_recipient": bool(args.get("recipient")),
                },
            )

            message = args.get("message", "").strip()
            if not message:
                logger.warning(
                    "%s rejected: empty message",
                    tool_name,
                    extra={
                        "event": f"tool.{tool_name}_rejected",
                        "reason": "empty_message",
                    },
                )
                raise ToolError("'message' is required")
            logger.debug(
                "_handle: not_message_passed",
                extra={
                    "event": "_messaging._handle.not_message_passed",
                    "reason": "not_message_passed",
                },
            )  # auto:neg

            # Recipient is pre-resolved by tool dispatch (contact registry)
            recipient = (args.get("recipient") or "").strip()
            if needs_recipient and not recipient:
                logger.warning(
                    "%s rejected: no recipient",
                    tool_name,
                    extra={
                        "event": f"tool.{tool_name}_rejected",
                        "reason": "no_recipient",
                    },
                )
                raise ToolError(
                    "No recipient — contact resolution failed or no default contact configured"
                )

            logger.debug(
                "%s: sending message",
                tool_name,
                extra={"event": f"{ch_name}.send_start", "message_len": len(message)},
            )

            await channel.send_message(message, recipient or None)

            logger.info(
                "%s message sent via tool",
                ch_name.title(),
                extra={"event": f"tool.{tool_name}"},
            )
            return await create_tagged_data(
                content=f"{ch_name.title()} message sent to recipient",
                source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED,
                originated_from=f"tool:{tool_name}",
            ), None

        return _handle
