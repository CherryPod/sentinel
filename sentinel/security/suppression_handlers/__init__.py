"""Suppression handler registry.

All 7 handlers are imported and registered here.  The
``get_handler()`` function looks up a handler by its ``handler_id``.
"""

from __future__ import annotations

from sentinel.security.suppression_handlers.build_context import BuildContextHandler
from sentinel.security.suppression_handlers.code_block_safe import (
    CodeBlockSafeHandler,
)
from sentinel.security.suppression_handlers.display_context import (
    DisplayContextHandler,
)
from sentinel.security.suppression_handlers.educational_context import (
    EducationalContextHandler,
)
from sentinel.security.suppression_handlers.env_template import EnvTemplateHandler
from sentinel.security.suppression_handlers.placeholder_values import (
    PlaceholderValuesHandler,
)
from sentinel.security.suppression_handlers.uri_parsing import UriParsingHandler

# Type alias for any handler instance
SuppressionHandler = (
    BuildContextHandler
    | CodeBlockSafeHandler
    | DisplayContextHandler
    | EducationalContextHandler
    | EnvTemplateHandler
    | PlaceholderValuesHandler
    | UriParsingHandler
)

# Registry mapping handler_id -> handler class
_HANDLER_CLASSES: dict[str, type] = {
    "build_context": BuildContextHandler,
    "code_block_safe": CodeBlockSafeHandler,
    "display_context": DisplayContextHandler,
    "educational_context": EducationalContextHandler,
    "env_template": EnvTemplateHandler,
    "placeholder_values": PlaceholderValuesHandler,
    "uri_parsing": UriParsingHandler,
}


def get_handler(handler_id: str) -> SuppressionHandler:
    """Look up and instantiate a handler by its handler_id.

    Raises ``KeyError`` if the handler_id is not registered.
    """
    cls = _HANDLER_CLASSES.get(handler_id)
    if cls is None:
        msg = f"Unknown handler: {handler_id!r}"
        raise KeyError(msg)
    return cls()
