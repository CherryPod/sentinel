"""Shared helpers for scanner plugins.

Small utilities used across multiple scanner implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.security._scan_context import ContextRegion


def find_enclosing_region(
    offset: int,
    regions: tuple[ContextRegion, ...],
) -> ContextRegion | None:
    """Find the region containing the given offset, or None (prose)."""
    for region in regions:
        if region.start <= offset < region.end:
            return region
    return None
