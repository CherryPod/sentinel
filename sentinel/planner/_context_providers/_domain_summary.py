"""Context provider for domain summary lookups.

Wraps the domain summary store to provide accumulated domain knowledge
(success rates, common patterns) as learning context for the planner.
"""

from __future__ import annotations

import logging

from sentinel.memory.episodic import _redact_paths, _sanitise_for_planner
from sentinel.planner._context_provider import ContextBuildArgs, ContextSection

logger = logging.getLogger(__name__)


class DomainSummaryProvider:
    """Fetches the domain summary for the current task's domain.

    Priority 10 — domain context appears early in the assembled prompt
    so the planner has situational awareness before specific examples.
    """

    @property
    def name(self) -> str:
        return "domain_summary"

    @property
    def priority(self) -> int:
        return 10

    async def build(self, args: ContextBuildArgs) -> ContextSection:
        """Fetch and format the domain summary, or return empty on failure."""
        domain = args.domain
        domain_summary_store = args.domain_summary_store

        if domain_summary_store is None or not domain:
            logger.debug(
                "Domain summary skipped — no store or no domain",
                extra={
                    "event": "domain.summary_skip",
                    "has_store": domain_summary_store is not None,
                    "domain": domain,
                },
            )
            return ContextSection(name=self.name, text="", priority=self.priority)

        try:
            summary = await domain_summary_store.get(domain)
            if summary and summary.summary_text:
                logger.debug(
                    "Domain summary found",
                    extra={
                        "event": "learning.context_summary",
                        "domain": domain,
                        "total_tasks": summary.total_tasks,
                        "success_count": summary.success_count,
                        "summary_preview": summary.summary_text[:200],
                    },
                )
                # Q7-F6: summary.summary_text aggregates raw stderr fragments
                # via memory/domain_summary.py:388-391 ← planner/_episodic.py:187-193.
                # Apply SP+RP stacked (marker scrub first, then path redact) —
                # aggregated errors carry both injection markers and filesystem
                # paths. Stacking order is render-time; _redact_paths' ≥3-segment
                # regex leaves controlled-vocab `Strategies:` sub-lines intact.
                scrubbed = _redact_paths(_sanitise_for_planner(summary.summary_text))
                text = f"[DOMAIN INSIGHT]\n{scrubbed}\n[END DOMAIN INSIGHT]\n\n"
                return ContextSection(name=self.name, text=text, priority=self.priority)

            logger.debug(
                "Domain summary empty or missing",
                extra={
                    "event": "learning.context_summary",
                    "domain": domain,
                    "found": False,
                },
            )
            return ContextSection(name=self.name, text="", priority=self.priority)
        except Exception as exc:  # catch-all: context provider graceful degradation
            logger.debug(
                "Domain summary fetch failed",
                extra={
                    "event": "learning.context_summary",
                    "domain": domain,
                    "error": str(exc),
                },
                exc_info=True,
            )
            return ContextSection(name=self.name, text="", priority=self.priority)
