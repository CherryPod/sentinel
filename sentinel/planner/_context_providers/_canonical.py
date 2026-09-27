"""Context provider for canonical trajectory lookups.

Wraps the canonical trajectory fetch logic to provide proven strategies
for a given domain as learning context for the planner.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import TYPE_CHECKING

from sentinel.planner._context_provider import ContextBuildArgs, ContextSection

if TYPE_CHECKING:
    from sentinel.memory.chunks import MemoryStore

logger = logging.getLogger(__name__)


class CanonicalTrajectoryProvider:
    """Fetches the best proven strategy for the current task's domain.

    Priority 30 — canonical trajectories appear after domain summaries
    and insights, providing specific strategic guidance.
    """

    @property
    def name(self) -> str:
        return "canonical_trajectory"

    @property
    def priority(self) -> int:
        return 30

    async def build(self, args: ContextBuildArgs) -> ContextSection:
        """Fetch and format the canonical trajectory, or return empty on failure."""
        domain: str | None = args.domain
        memory_store: MemoryStore | None = args.memory_store

        text = await self._fetch_canonical_trajectory(domain, memory_store)
        return ContextSection(name=self.name, text=text, priority=self.priority)

    async def _fetch_canonical_trajectory(
        self,
        domain: str | None,
        memory_store: MemoryStore | None,
    ) -> str:
        if memory_store is None or not domain:
            logger.debug(
                "Canonical trajectory skipped — no store or no domain",
                extra={
                    "event": "canonical.skip",
                    "has_store": memory_store is not None,
                    "domain": domain,
                },
            )
            return ""

        try:
            canonical_chunks = await memory_store.list_chunks(
                source="system:canonical",
            )
            for chunk in canonical_chunks:
                if chunk.metadata.get("domain") != domain:
                    continue

                # Check expiry
                expires = chunk.metadata.get("expires_at", "")
                if expires:
                    try:
                        from datetime import datetime as _dt

                        exp_dt = _dt.fromisoformat(expires)
                        if exp_dt < _dt.now(UTC):
                            logger.debug(
                                "Canonical trajectory expired",
                                extra={
                                    "event": "canonical.expired",
                                    "domain": domain,
                                    "expires_at": expires,
                                },
                            )
                            continue
                    except (ValueError, TypeError) as exc:
                        logger.debug(
                            "Canonical trajectory expiry parse failed",
                            extra={
                                "event": "canonical.expiry_parse_error",
                                "error": str(exc),
                                "expires_raw": expires,
                            },
                        )

                rate = chunk.metadata.get("success_rate", 0)
                strategy = chunk.metadata.get("strategy", "")
                if rate and strategy:
                    logger.debug(
                        "Canonical trajectory found",
                        extra={
                            "event": "learning.context_canonical",
                            "domain": domain,
                            "strategy": strategy,
                            "success_rate": rate,
                        },
                    )
                    return (
                        f"[CANONICAL APPROACH]\n"
                        f"Best proven strategy for {domain} tasks "
                        f"(success rate: {rate:.0%}): {strategy}\n"
                        f"[END CANONICAL APPROACH]\n\n"
                    )
                break  # only use the first matching canonical

            logger.debug(
                "No canonical trajectory for domain",
                extra={"event": "canonical.miss", "domain": domain},
            )
            return ""
        except Exception as exc:  # catch-all: context provider graceful degradation
            logger.debug(
                "Canonical trajectory fetch failed",
                extra={
                    "event": "learning.context_canonical",
                    "domain": domain,
                    "error": str(exc),
                },
                exc_info=True,
            )
            return ""
