"""Handler modules extracted from executor.py (Phase 1 structural refactor).

Each handler group is a mixin class that the ToolExecutor inherits from.
Handlers access shared state (policy engine, credential store, channels)
via self — the mixin expects these attributes to exist on the concrete class.

Re-exports shared types for convenience.
"""

from sentinel.tools._handlers._calendar import CalendarHandlerMixin
from sentinel.tools._handlers._container import ContainerHandlerMixin
from sentinel.tools._handlers._email import EmailHandlerMixin
from sentinel.tools._handlers._external_data import ExternalDataHandlerMixin
from sentinel.tools._handlers._file import (
    FileHandlerMixin,  # backward-compat combined class
)
from sentinel.tools._handlers._file_ops import FileOpsHandlerMixin
from sentinel.tools._handlers._file_patch import PatchHandlerMixin
from sentinel.tools._handlers._file_write import WriteHandlerMixin
from sentinel.tools._handlers._messaging import MessagingHandlerMixin
from sentinel.tools._handlers._types import (
    ToolBlockedError,
    ToolError,
    _CredentialOverlay,
)
from sentinel.tools._handlers._website import WebsiteHandlerMixin

__all__ = [
    "CalendarHandlerMixin",
    "ContainerHandlerMixin",
    "EmailHandlerMixin",
    "ExternalDataHandlerMixin",
    "FileHandlerMixin",
    "FileOpsHandlerMixin",
    "MessagingHandlerMixin",
    "PatchHandlerMixin",
    "ToolBlockedError",
    "ToolError",
    "WebsiteHandlerMixin",
    "WriteHandlerMixin",
    "_CredentialOverlay",
]
