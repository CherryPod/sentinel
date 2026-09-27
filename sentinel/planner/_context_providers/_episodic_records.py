"""Context provider for episodic memory records.

Wraps the _accumulate_records_within_budget helper, which formats
episodic search results as context lines with per-record budget
tracking and logging.  The standalone helper is also exported so
the builder can call it directly during the transition period.
"""

from __future__ import annotations

import logging

from sentinel.memory.episodic import _sanitise_for_planner
from sentinel.planner._context_provider import ContextBuildArgs, ContextSection

logger = logging.getLogger(__name__)


def accumulate_records_within_budget(
    results: list,
    budget_remaining: int,
) -> tuple[list[str], int]:
    """Accumulate episodic record lines up to the character budget.

    Returns (record_lines, chars_used).  Logs each inclusion and the
    first drop when the budget is exhausted.
    """
    logger.debug(
        "_accumulate_records_within_budget called",
        extra={
            "event": "accumulate.records_within_budget_entry",
            "result_count": len(results) if results else 0,
            "budget_remaining": budget_remaining,
        },
    )
    record_lines: list[str] = []
    used = 0

    for i, r in enumerate(results):
        # Q7-F1: r.content is stored MemoryChunk.content replayed from hybrid
        # search. Apply SP (marker scrub) at the render sink so planted
        # injection markers cannot reach the planner prompt. No RP — chunk
        # bodies carry paths as task-relevance signal, not leakage.
        line = f"- {_sanitise_for_planner(r.content)}"
        if used + len(line) > budget_remaining:
            logger.debug(
                "Episodic record %d/%d dropped — budget exhausted (%d/%d chars)",
                i + 1,
                len(results),
                used,
                budget_remaining,
                extra={
                    "event": "learning.context_record_dropped",
                    "record_index": i,
                    "budget_used": used,
                    "budget_total": budget_remaining,
                    "record_len": len(r.content),
                },
            )
            break
        record_lines.append(line)
        used += len(line)
        logger.debug(
            "Episodic record %d/%d injected — %d chars, preview: %s",
            i + 1,
            len(results),
            len(line),
            r.content[:120],
            extra={
                "event": "learning.context_record_injected",
                "record_index": i,
                "record_chars": len(line),
                "budget_used": used,
                "budget_total": budget_remaining,
                "record_len": len(r.content),
                "score": round(r.score, 4) if hasattr(r, "score") else None,
            },
        )

    logger.debug(
        "_accumulate_records_within_budget exit",
        extra={
            "event": "accumulate.records_within_budget_exit",
            "records_kept": len(record_lines),
            "chars_used": used,
            "budget_remaining": budget_remaining,
        },
    )
    return record_lines, used


class EpisodicRecordsProvider:
    """Formats episodic search results as context lines.

    Budget-aware: the builder passes available budget through the
    accumulate_records_within_budget helper.  This provider formats
    all records and sets budget_aware=True so the builder can trim
    if needed.

    Priority 40 — episodic records appear after domain summary (10),
    planning insights (20), and canonical trajectory (30), but before
    detailed plan history (50).
    """

    @property
    def name(self) -> str:
        return "episodic_records"

    @property
    def priority(self) -> int:
        return 40

    async def build(self, args: ContextBuildArgs) -> ContextSection:
        """Format episodic search results as context lines."""
        results = args.search_results
        if not results:
            logger.debug(
                "Episodic records skipped — no search results",
                extra={
                    "event": "episodic.records_skip",
                    "has_results": results is not None,
                    "result_count": 0,
                },
            )
            return ContextSection(name=self.name, text="", priority=self.priority)

        # Format all records — budget trimming coordinated by the builder
        # via accumulate_records_within_budget when assembling sections.
        # Q7-F1: same scrub as the budget-accumulator path above.
        lines = [f"- {_sanitise_for_planner(r.content)}" for r in results]
        text = "\n".join(lines)

        logger.debug(
            "Episodic records provider built %d lines (%d chars)",
            len(lines),
            len(text),
            extra={
                "event": "episodic.records_built",
                "record_count": len(lines),
                "total_chars": len(text),
            },
        )

        return ContextSection(
            name=self.name,
            text=text,
            priority=self.priority,
            budget_aware=True,
        )
