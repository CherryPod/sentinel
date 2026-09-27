"""Scanner registry: metadata and protocol for pipeline scanners.

Each scanner that participates in the scan pipeline declares a
``scanner_meta`` property of type :class:`ScannerMeta` and an async
``scan(context)`` method (``ScannerPlugin`` protocol).  The pipeline
inspects this metadata to decide *how* to invoke each scanner
(phase-1 vs phase-2 expensive, execution-only DISPLAY gating) without
per-scanner branching.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sentinel.security._scan_context import ScanContext, ScanMatch

from sentinel.security._enums import Phase, Platform

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScannerMeta:
    """Metadata for a scanner plugin.

    ``expensive`` separates fast regex scanners (Phase 1, sequential) from
    ML/external scanners (Phase 2, concurrent with timeouts).

    ``execution_only`` skips the scanner during output scanning when
    ``output_destination == DISPLAY``.  Has no effect during input scanning
    (all scanners always run on input).
    """

    name: str
    order: int
    phases: frozenset[Phase]
    platforms: frozenset[Platform]
    description: str
    expensive: bool = False
    execution_only: bool = False


@runtime_checkable
class ScannerPlugin(Protocol):
    """Unified protocol for all refactored scanners.

    Every scanner implements ``scanner_meta`` (property) and ``scan``
    (async method).  Regex scanners are trivially async.  ML/external
    scanners do real async work.  The pipeline just
    ``await scanner.scan(context)`` for everything.
    """

    @property
    def scanner_meta(self) -> ScannerMeta: ...

    async def scan(self, context: ScanContext) -> list[ScanMatch]: ...
