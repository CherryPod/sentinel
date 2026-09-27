"""Patch backends — language-specific anchor resolution for file_patch."""

import logging

from sentinel.tools.patch_backends._protocol import AnchorResult, PatchBackend

logger = logging.getLogger(__name__)

__all__ = ["AnchorResult", "PatchBackend"]
