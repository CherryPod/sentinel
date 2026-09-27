"""Tool handler registry — decorator-based auto-discovery for tool handlers.

Each handler method is decorated with @tool_handler(...) which attaches a
ToolMeta dataclass to the function. ToolExecutor.__init__ discovers all
decorated methods via introspection, building the _handlers dict and tool
descriptions automatically.

Adding a new tool = add a decorated method to a mixin. Zero modifications
to executor.py or any other existing file.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel for "description provided by a separate method" — used by
# messaging tools where descriptions come from the channel registry.
_DYNAMIC_DESCRIPTION = object()


@dataclass(frozen=True)
class ToolMeta:
    """Metadata attached to a tool handler method via @tool_handler."""

    name: str
    # Static string, callable returning a string (for backend-dependent text),
    # or _DYNAMIC_DESCRIPTION (descriptions come from elsewhere, e.g. channel registry).
    description: str | Callable[[], str] | object = ""
    # Static dict or callable returning a dict (for backend-dependent args).
    args: dict[str, str] | Callable[[], dict[str, str]] = field(default_factory=dict)
    aliases: tuple[str, ...] = ()
    group: str = ""
    # Optional settings gate — callable returning bool.
    # When provided, the tool description is only included if enabled() is True.
    # The handler is always registered (policy engine handles actual blocking).
    enabled: Callable[[], bool] | None = None
    # Ordering weight within get_tool_descriptions() output.
    # Lower values appear first. Tools with the same weight keep definition order.
    order: int = 100

    def to_description_dict(self) -> dict[str, Any]:
        """Convert to the dict format expected by the planner.

        Resolves callable descriptions and args at call time so that
        backend-dependent text (e.g. "Gmail" vs "IMAP") is always current.

        Raises ValueError if description is _DYNAMIC_DESCRIPTION — those
        tools get their descriptions from another source (e.g. channel registry).
        """
        logger.debug(
            "to_description_dict called",
            extra={"event": "registry.to_description_dict"},
        )  # auto:entry
        if self.description is _DYNAMIC_DESCRIPTION:
            raise ValueError(
                f"Tool {self.name!r} has _DYNAMIC_DESCRIPTION — "
                "descriptions must be provided by the registry, not to_description_dict()"
            )
        desc = self.description() if callable(self.description) else self.description
        args = self.args() if callable(self.args) else self.args
        d: dict[str, Any] = {"name": self.name, "description": desc}
        if args:
            d["args"] = args
        return d


def tool_handler(
    name: str,
    description: str | Callable[[], str] | object = "",
    args: dict[str, str] | Callable[[], dict[str, str]] | None = None,
    *,
    aliases: tuple[str, ...] = (),
    group: str = "",
    enabled: Callable[[], bool] | None = None,
    order: int = 100,
) -> Callable:
    """Decorator that registers a method as a tool handler.

    Usage::

        @tool_handler(
            "web_search",
            description="Search the web for current information.",
            args={"query": "string (search query)"},
        )
        async def _web_search(self, args: dict) -> tuple[TaggedData, dict | None]:
            ...

    The decorator does NOT modify the method's behaviour — it only attaches
    a ToolMeta instance as the ``__tool_meta__`` attribute.
    """
    meta = ToolMeta(
        name=name,
        description=description,
        args=args or {},
        aliases=aliases,
        group=group,
        enabled=enabled,
        order=order,
    )

    def _decorator(fn: Callable) -> Callable:
        fn.__tool_meta__ = meta  # type: ignore[attr-defined]
        return fn

    return _decorator
