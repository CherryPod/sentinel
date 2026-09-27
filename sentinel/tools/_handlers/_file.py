"""File operations handler mixin — backward-compat re-export.

Split into three focused mixins during Phase 5 modularisation:
  - _file_ops.py   → FileOpsHandlerMixin (shared utilities, file_read, mkdir, shell)
  - _file_write.py → WriteHandlerMixin (file_write and sub-methods)
  - _file_patch.py → PatchHandlerMixin (file_patch and sub-methods)

This file re-exports FileHandlerMixin as a combined class for backward
compatibility with existing imports.
"""

from sentinel.tools._handlers._file_ops import FileOpsHandlerMixin
from sentinel.tools._handlers._file_patch import PatchHandlerMixin
from sentinel.tools._handlers._file_write import WriteHandlerMixin


class FileHandlerMixin(WriteHandlerMixin, PatchHandlerMixin, FileOpsHandlerMixin):
    """File operations tool handlers.

    Backward-compatible combined class — inherits from the three split mixins.
    New code should import the specific mixin it needs.
    """
