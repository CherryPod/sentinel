"""Context provider for detailed plan history (tier-2 episodic lookup).

Wraps the former ``_fetch_detailed_plan_history`` function from builders.py.
When episodic search results are available, fetches the top match's full
plan JSON and renders it as structured context for the planner.

Depends on ``search_results`` being populated by an upstream provider
(e.g. EpisodicRecordsProvider) before this provider runs.
"""

from __future__ import annotations

import logging

from sentinel.planner._context_provider import ContextBuildArgs, ContextSection

logger = logging.getLogger(__name__)


class DetailedPlanHistoryProvider:
    """Fetches and renders the full plan JSON for the top episodic match.

    Priority 35 — runs after episodic search (which populates
    ``args.search_results``) but before lower-priority providers.
    """

    @property
    def name(self) -> str:
        return "detailed_plan_history"

    @property
    def priority(self) -> int:
        return 35

    async def build(self, args: ContextBuildArgs) -> ContextSection:
        """Build detailed plan history section from the top search result."""
        results = args.search_results
        episodic_store = args.episodic_store
        memory_store = args.memory_store

        if not results or episodic_store is None:
            logger.debug(
                "Detailed plan history skipped",
                extra={
                    "event": "plan.history_skip",
                    "has_results": bool(results),
                    "has_episodic_store": episodic_store is not None,
                },
            )
            return ContextSection(name=self.name, text="", priority=self.priority)

        try:
            text = await self._fetch_detailed(results, episodic_store, memory_store)
            return ContextSection(name=self.name, text=text, priority=self.priority)
        except Exception as exc:  # catch-all: context provider graceful degradation
            logger.debug(
                "plan_history: tier-2 lookup failed (non-fatal)",
                extra={"event": "plan.history_tier2_error", "error": str(exc)},
                exc_info=True,
            )
            return ContextSection(name=self.name, text="", priority=self.priority)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _fetch_detailed(
        results: list,
        episodic_store: object,
        memory_store: object,
    ) -> str:
        """Core fetch logic — preserved from the original builders.py function."""
        # Lazy import to avoid circular dependency: builders → _context_providers → builders
        from sentinel.planner.builders import render_plan_history

        top_chunk_id = results[0].chunk_id
        chunk = await memory_store.get(top_chunk_id)
        if not chunk or not chunk.metadata or not chunk.metadata.get("record_id"):
            logger.debug(
                "plan_history: top match has no record_id, tier-2 skipped",
                extra={
                    "event": "plan.history_tier2_skip",
                    "chunk_id": top_chunk_id,
                },
            )
            return ""
        logger.debug(
            "_fetch_detailed: not_chunk_passed",
            extra={
                "event": "plan.history_tier2_skip.passed",
                "reason": "not_chunk_passed",
            },
        )  # auto:neg

        record_id = chunk.metadata["record_id"]
        record = await episodic_store.get(record_id)
        if not record or not record.plan_json:
            logger.debug(
                "plan_history: record %s has no plan_json, tier-2 skipped",
                record_id if record else top_chunk_id,
                extra={"event": "plan.history_tier2_skip"},
            )
            return ""

        section = render_plan_history(
            record.plan_json,
            task_status=record.task_status,
            step_count=record.step_count,
            success_count=record.success_count,
            task_domain=record.task_domain,
        )
        logger.info(
            "plan_history: detailed rendering for record %s (%d phases)",
            record_id,
            len(record.plan_json.get("phases", [])),
            extra={
                "event": "plan.history_tier2_rendered",
                "record_id": record_id,
                "phase_count": len(record.plan_json.get("phases", [])),
                "record_task_status": record.task_status,
                "record_plan_summary_len": (
                    len(record.plan_summary) if record.plan_summary else 0
                ),
                "record_request_len": (
                    len(record.user_request) if record.user_request else 0
                ),
                "record_step_count": record.step_count,
                "record_success_count": record.success_count,
                "detailed_section_chars": len(section),
            },
        )
        return section
