"""Internal async event bus for Sentinel.

Pub/sub with topic-based routing and wildcard matching.

Topics use dotted namespaces with glob-style wildcards:
  - "task.created"      — exact match
  - "task.*"            — matches any single segment after "task."
  - "approval.*"        — matches "approval.requested", "approval.decided", etc.

Supported topic prefixes: task, approval, session, channel, routine, memory.
"""

import asyncio
import fnmatch
import logging
from collections import defaultdict
from typing import Any, Callable, Coroutine

logger = logging.getLogger("sentinel.audit")

# Type alias for async event handlers
EventHandler = Callable[[str, Any], Coroutine[Any, Any, None]]


class EventBus:
    """Async pub/sub event bus with wildcard topic matching."""

    def __init__(self) -> None:
        # pattern → list of handlers
        self._subscribers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, pattern: str, handler: EventHandler) -> None:
        """Subscribe a handler to a topic pattern.

        Args:
            pattern: Topic pattern, supports '*' wildcard (e.g. "task.*").
            handler: Async callable(topic: str, data: Any) -> None.
        """
        if handler not in self._subscribers[pattern]:
            self._subscribers[pattern].append(handler)
            logger.debug(
                "Event bus subscription",
                extra={"event": "bus_subscribe", "pattern": pattern},
            )

    def unsubscribe(self, pattern: str, handler: EventHandler) -> None:
        """Remove a handler from a topic pattern.

        Args:
            pattern: The exact pattern used when subscribing.
            handler: The handler to remove.
        """
        handlers = self._subscribers.get(pattern, [])
        if handler in handlers:
            handlers.remove(handler)
            logger.debug(
                "Event bus unsubscription",
                extra={"event": "bus_unsubscribe", "pattern": pattern},
            )
            if not handlers:
                del self._subscribers[pattern]

    async def publish(self, topic: str, data: Any = None) -> None:
        """Publish an event to all matching subscribers.

        Handlers are called concurrently via asyncio.gather. Exceptions
        in individual handlers are logged but don't prevent other handlers
        from running.

        Args:
            topic: The specific topic (e.g. "task.created").
            data: Arbitrary event payload.
        """
        matching_handlers: list[EventHandler] = []

        for pattern, handlers in self._subscribers.items():
            if fnmatch.fnmatch(topic, pattern):
                matching_handlers.extend(handlers)

        if not matching_handlers:
            return

        results = await asyncio.gather(
            *(h(topic, data) for h in matching_handlers),
            return_exceptions=True,
        )

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "Event handler error",
                    extra={
                        "event": "bus_handler_error",
                        "topic": topic,
                        "error": str(result),
                    },
                )

    @property
    def subscriber_count(self) -> int:
        """Total number of active subscriptions (handler instances)."""
        return sum(len(handlers) for handlers in self._subscribers.values())

    @property
    def patterns(self) -> list[str]:
        """List of subscribed patterns."""
        return list(self._subscribers.keys())
