"""Suppression handler: display context.

Suppresses matches in ``PROSE`` regions when the output destination
is ``DISPLAY``.  This replaces the old ``strict`` parameter pattern
where ``scan_output_text(strict=False)`` enabled prose suppression
for display-bound output.

This is a NEW handler (not extracted from scanner.py).
"""

from __future__ import annotations

import logging

from sentinel.security._enums import OutputDestination, RegionType
from sentinel.security._scan_context import ScanContext, ScanMatch

logger = logging.getLogger(__name__)


class DisplayContextHandler:
    """Suppress prose matches when output_destination is DISPLAY."""

    handler_id: str = "display_context"

    def evaluate(
        self,
        match: ScanMatch,
        context: ScanContext,
        params: dict | None = None,
    ) -> bool:
        """Return True if the match should be suppressed.

        Checks: output_destination is DISPLAY AND match is in a PROSE
        region.
        """
        logger.debug(
            "Evaluating display context",
            extra={
                "event": "security.suppression.display_context.evaluate",
                "rule_id": match.rule_id,
                "offset": match.offset,
            },
        )

        # Only applies when output is going to display
        if context.metadata.output_destination != OutputDestination.DISPLAY:
            return False

        # Find the enclosing region for this match
        region = match.region
        if region is None:
            for r in context.regions:
                if r.start <= match.offset < r.end:
                    region = r
                    break

        # Suppress if match is in a PROSE region
        if region is not None and region.region_type == RegionType.PROSE:
            logger.debug(
                "Display context: suppressed (prose in DISPLAY output)",
                extra={
                    "event": "security.suppression.display_context.suppressed",
                    "reason": "prose_in_display",
                },
            )
            return True

        return False
