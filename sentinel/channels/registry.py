"""Channel registry — explicit, testable, no global state.

Holds active channel instances keyed by descriptor name. Consumers query
the registry for tool dispatch, health checks, keyword patterns, and
domain mappings instead of branching on hardcoded channel names.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sentinel.core.decorators import no_audit_log

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sentinel.channels.base import Channel

logger = logging.getLogger(__name__)


class ChannelRegistry:
    """Explicit registry of active channel instances.

    Created once during init, passed as a dependency. No singletons,
    no global state — testable by construction.
    """

    def __init__(self) -> None:
        self._channels: dict[str, Channel] = {}  # keyed by descriptor.name

    def register(self, channel: Channel) -> None:
        """Register a live channel instance. Raises on duplicate name."""
        name = channel.descriptor.name
        if name in self._channels:
            raise ValueError(f"Channel already registered: {name}")
        self._channels[name] = channel
        logger.info(
            "Channel registered",
            extra={"event": "channel_registry.registered", "channel": name},
        )

    @no_audit_log
    def get(self, name: str) -> Channel | None:
        """Look up a channel by descriptor name."""
        return self._channels.get(name)

    def get_by_tool(self, tool_name: str) -> Channel | None:
        """Look up a channel by its tool_name (e.g. 'signal_send')."""
        for ch in self._channels.values():
            if ch.descriptor.tool_name == tool_name:
                return ch
        logger.debug(
            "channel_registry.get_by_tool_miss",
            extra={
                "event": "channel_registry.get_by_tool_miss",
                "tool_name": tool_name,
            },
        )
        return None

    @no_audit_log
    def enabled(self) -> Iterator[Channel]:
        """Iterate over all registered (= enabled) channels."""
        yield from self._channels.values()

    @no_audit_log
    def with_health_check(self) -> Iterator[Channel]:
        """Iterate over channels that expose a health check."""
        yield from (c for c in self._channels.values() if c.descriptor.health_check)

    @no_audit_log
    def with_tools(self) -> Iterator[Channel]:
        """Iterate over channels that have an associated tool."""
        yield from (c for c in self._channels.values() if c.descriptor.tool_name)

    @no_audit_log
    def tool_to_domain_map(self) -> dict[str, str]:
        """Build {tool_name: domain} mapping for episodic store."""
        return {c.descriptor.tool_name: c.descriptor.domain for c in self.with_tools()}

    @no_audit_log
    def keyword_patterns(self) -> dict[str, tuple[str, ...]]:
        """Build {tool_name: keywords} mapping for keyword classifier."""
        return {
            c.descriptor.tool_name: c.descriptor.keywords
            for c in self.with_tools()
            if c.descriptor.keywords
        }

    @no_audit_log
    def tool_descriptions(self) -> list[dict[str, str]]:
        """Build tool description list for the planner."""
        return [
            {
                "name": c.descriptor.tool_name,
                "description": c.descriptor.tool_description,
            }
            for c in self.with_tools()
        ]

    @no_audit_log
    def __len__(self) -> int:
        return len(self._channels)

    @no_audit_log
    def __contains__(self, name: str) -> bool:
        return name in self._channels
