"""Late-binding dependency bundle for Orchestrator post-init wiring.

These dependencies are not available at Orchestrator construction time
because they are created later in the startup sequence (lifecycle Tier 5).
Instead of 4 individual ``set_*()`` methods, the orchestrator exposes a
single ``wire_late_deps(deps)`` call that wires all of them atomically.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.memory.episodic import EpisodicStore

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class OrchestratorDeps:
    """Late-bound dependencies injected after all startup tiers complete.

    Fields correspond to the former ``set_episodic_store``,
    ``set_domain_summary_store``, ``set_strategy_store``, and
    ``set_reranker`` methods on Orchestrator.
    """

    episodic_store: EpisodicStore | None = None
    domain_summary_store: object | None = None
    strategy_store: object | None = None
    reranker: object | None = None
