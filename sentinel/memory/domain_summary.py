"""Domain summary store — PostgreSQL backend with in-memory fallback.

Stores aggregated intelligence per task domain per user. Summaries are
built deterministically from episodic records (no LLM) and injected
into the planner's context as high-signal, low-token guidance.

When pool is None, falls back to in-memory dict (useful for tests).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sentinel.core.context import current_user_id
from sentinel.memory.episodic import _categorise_strategy

if TYPE_CHECKING:
    from sentinel.memory.episodic import EpisodicStore
    from sentinel.memory.strategy_store import StrategyPatternStore

logger = logging.getLogger("sentinel.audit")


@dataclass
class DomainSummary:
    """Aggregated summary for a task domain."""

    domain: str
    user_id: int
    total_tasks: int = 0
    success_count: int = 0
    summary_text: str = ""
    patterns_json: list[dict] = field(default_factory=list)
    last_task_count: int = 0
    updated_at: str = ""


def _row_to_summary(row: Any) -> DomainSummary:
    """Convert an asyncpg Record to a DomainSummary dataclass."""
    patterns = row["patterns_json"]
    if isinstance(patterns, str):
        patterns = json.loads(patterns)

    updated = row["updated_at"]
    if hasattr(updated, "isoformat"):
        updated = updated.isoformat()

    return DomainSummary(
        domain=row["domain"],
        user_id=row["user_id"],
        total_tasks=row["total_tasks"],
        success_count=row["success_count"],
        summary_text=row["summary_text"],
        patterns_json=patterns if patterns else [],
        last_task_count=row["last_task_count"],
        updated_at=str(updated),
    )


class DomainSummaryStore:
    """PostgreSQL domain summary store with in-memory fallback for tests."""

    def __init__(self, pool: Any = None):
        self._pool = pool
        self._mem: dict[tuple[str, int], DomainSummary] = {}

    @property
    def pool(self) -> Any:
        return self._pool

    async def get(self, domain: str, user_id: int | None = None) -> DomainSummary | None:
        """Fetch a domain summary. Returns None if not found."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM domain_summaries "
                    "WHERE domain = $1 AND user_id = $2",
                    domain, resolved_uid,
                )
                return _row_to_summary(row) if row else None
        else:
            return self._mem.get((domain, resolved_uid))

    async def upsert(self, summary: DomainSummary) -> None:
        """Insert or update a domain summary."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO domain_summaries "
                    "(domain, user_id, total_tasks, success_count, "
                    "summary_text, patterns_json, last_task_count, updated_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, NOW()) "
                    "ON CONFLICT (domain, user_id) DO UPDATE SET "
                    "total_tasks = $3, success_count = $4, "
                    "summary_text = $5, patterns_json = $6::jsonb, "
                    "last_task_count = $7, updated_at = NOW()",
                    summary.domain, summary.user_id,
                    summary.total_tasks, summary.success_count,
                    summary.summary_text, json.dumps(summary.patterns_json),
                    summary.last_task_count,
                )
        else:
            self._mem[(summary.domain, summary.user_id)] = summary

        logger.info(
            "Domain summary upserted",
            extra={
                "event": "domain_summary_upsert",
                "domain": summary.domain,
                "total_tasks": summary.total_tasks,
            },
        )

    async def list_all(self, user_id: int | None = None) -> list[DomainSummary]:
        """List all domain summaries for a user."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM domain_summaries "
                    "WHERE user_id = $1 ORDER BY total_tasks DESC",
                    resolved_uid,
                )
                return [_row_to_summary(row) for row in rows]
        else:
            return [
                s for (d, uid), s in self._mem.items()
                if uid == resolved_uid
            ]

    async def delete(self, domain: str, user_id: int | None = None) -> bool:
        """Delete a domain summary. Returns True if deleted."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM domain_summaries "
                    "WHERE domain = $1 AND user_id = $2",
                    domain, resolved_uid,
                )
                return "DELETE 1" in result
        else:
            key = (domain, resolved_uid)
            if key in self._mem:
                del self._mem[key]
                return True
            return False

    async def increment_task_count(
        self, domain: str, user_id: int | None = None,
    ) -> int:
        """Increment last_task_count and return new value.

        Used to track tasks since last summary refresh. Returns the new
        count, or 0 if no summary exists for this domain yet.
        """
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "UPDATE domain_summaries "
                    "SET last_task_count = last_task_count + 1 "
                    "WHERE domain = $1 AND user_id = $2 "
                    "RETURNING last_task_count",
                    domain, resolved_uid,
                )
                return row["last_task_count"] if row else 0
        else:
            key = (domain, resolved_uid)
            if key in self._mem:
                self._mem[key].last_task_count += 1
                return self._mem[key].last_task_count
            return 0


async def _build_patterns(
    domain: str,
    user_id: int,
    records: list,
    strategy_store: StrategyPatternStore | None = None,
) -> list[dict]:
    """Build strategy patterns list from strategy_store or raw records.

    Prefers strategy_store (pre-aggregated, incremental) when available.
    Falls back to re-computing from raw episodic records if strategy_store
    is None or returns no data.
    """
    # Try strategy_store first — pre-aggregated data
    if strategy_store is not None:
        try:
            top = await strategy_store.get_top_strategies(domain, user_id, limit=10)
            if top:
                return [
                    {
                        "strategy": s.strategy_name,
                        "count": s.occurrence_count,
                        "success_rate": round(s.success_rate, 2),
                    }
                    for s in top
                ]
        except Exception:
            pass  # graceful fallback to raw computation

    # Fallback: re-compute from raw records
    strategy_stats: dict[str, dict] = {}
    for record in records:
        outcomes = record.step_outcomes or []
        strategy = _categorise_strategy(outcomes)

        if strategy not in strategy_stats:
            strategy_stats[strategy] = {"total": 0, "success": 0}
        strategy_stats[strategy]["total"] += 1
        if record.task_status in ("success", "completed"):
            strategy_stats[strategy]["success"] += 1

    patterns = []
    for strategy, stats in sorted(
        strategy_stats.items(), key=lambda x: x[1]["total"], reverse=True,
    ):
        rate = stats["success"] / stats["total"] if stats["total"] > 0 else 0
        patterns.append({
            "strategy": strategy,
            "count": stats["total"],
            "success_rate": round(rate, 2),
        })
    return patterns


async def generate_domain_summary(
    domain: str,
    episodic_store: EpisodicStore,
    user_id: int = 1,
    strategy_store: StrategyPatternStore | None = None,
) -> DomainSummary:
    """Generate a domain summary from episodic records. Deterministic — no LLM.

    Queries the last 100 records for the domain and aggregates:
    - Total tasks, success count
    - Strategy patterns with success rates (from strategy_store if available,
      otherwise re-computed from raw records)
    - Code fixer activation count
    - Common error patterns
    """
    records = await episodic_store.list_by_domain(domain, user_id=user_id, limit=100)

    total = len(records)
    successes = sum(1 for r in records if r.task_status in ("success", "completed"))

    # Strategy patterns — prefer strategy_store (pre-aggregated) over raw re-computation
    fixer_count = 0
    error_counts: dict[str, int] = {}

    for record in records:
        outcomes = record.step_outcomes or []

        # Code fixer count — per-task, not per-step
        for o in outcomes:
            if o.get("code_fixer_changed"):
                fixer_count += 1
                break

        # Error patterns
        for err in (record.error_patterns or []):
            key = err[:50]
            error_counts[key] = error_counts.get(key, 0) + 1

    # Build patterns_json from strategy_store or raw records
    patterns = await _build_patterns(domain, user_id, records, strategy_store)

    # Build summary_text
    success_pct = round(100 * successes / total) if total > 0 else 0
    lines = [f"{domain}: {total} tasks, {successes}/{total} ({success_pct}%) success."]

    if patterns:
        strat_parts = []
        for p in patterns[:3]:
            pct = round(p["success_rate"] * 100)
            strat_parts.append(f"{p['strategy']} {pct}% success ({p['count']} tasks)")
        lines.append(f"Strategies: {', '.join(strat_parts)}.")

    if error_counts:
        top_errors = sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        err_parts = [f"{err} ({count})" for err, count in top_errors]
        lines.append(f"Common errors: {', '.join(err_parts)}.")

    summary_text = " ".join(lines)

    return DomainSummary(
        domain=domain,
        user_id=user_id,
        total_tasks=total,
        success_count=successes,
        summary_text=summary_text,
        patterns_json=patterns,
        last_task_count=0,
    )
