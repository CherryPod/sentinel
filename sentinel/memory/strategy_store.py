"""Strategy pattern store — PostgreSQL backend with in-memory fallback.

Tracks which step-sequence strategies are used for each task domain,
how often they succeed, and their average duration. Feeds into domain
summaries and canonical trajectory extraction.

When pool is None, falls back to in-memory dict (useful for tests).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.audit")


@dataclass
class StrategyPattern:
    """A tracked strategy pattern for a task domain."""

    pattern_id: str
    domain: str
    user_id: int
    strategy_name: str
    step_sequence: list[str]
    occurrence_count: int = 0
    success_count: int = 0
    avg_duration_s: float | None = None
    last_seen: str = ""
    created_at: str = ""

    @property
    def success_rate(self) -> float:
        """Fraction of occurrences that succeeded."""
        if self.occurrence_count == 0:
            return 0.0
        return self.success_count / self.occurrence_count


def _row_to_pattern(row: Any) -> StrategyPattern:
    """Convert an asyncpg Record to a StrategyPattern dataclass."""
    seq = row["step_sequence"]
    if isinstance(seq, str):
        seq = json.loads(seq)

    last_seen = row["last_seen"]
    if hasattr(last_seen, "isoformat"):
        last_seen = last_seen.isoformat()

    created = row["created_at"]
    if hasattr(created, "isoformat"):
        created = created.isoformat()

    return StrategyPattern(
        pattern_id=row["pattern_id"],
        domain=row["domain"],
        user_id=row["user_id"],
        strategy_name=row["strategy_name"],
        step_sequence=seq if seq else [],
        occurrence_count=row["occurrence_count"],
        success_count=row["success_count"],
        avg_duration_s=row["avg_duration_s"],
        last_seen=str(last_seen),
        created_at=str(created),
    )


class StrategyPatternStore:
    """PostgreSQL strategy pattern store with in-memory fallback for tests."""

    def __init__(self, pool: Any = None):
        self._pool = pool
        # In-memory fallback: keyed by (domain, user_id, strategy_name)
        self._mem: dict[tuple[str, int, str], StrategyPattern] = {}

    @property
    def pool(self) -> Any:
        return self._pool

    async def upsert(
        self,
        domain: str,
        user_id: int | None = None,
        strategy_name: str = "",
        step_sequence: list[str] | None = None,
        success: bool = False,
        duration_s: float | None = None,
    ) -> None:
        """Insert or increment a strategy pattern.

        If the pattern already exists for (domain, user_id, strategy_name),
        increments occurrence_count (and success_count if success=True).
        Updates avg_duration_s with a running average.
        """
        resolved_uid = user_id if user_id is not None else current_user_id.get()
        seq = step_sequence or []

        if self._pool is not None:
            pattern_id = str(uuid.uuid4())
            async with self._pool.acquire() as conn:
                # Upsert: INSERT on first occurrence, UPDATE on subsequent
                await conn.execute(
                    "INSERT INTO strategy_patterns "
                    "(pattern_id, domain, user_id, strategy_name, step_sequence, "
                    "occurrence_count, success_count, avg_duration_s, last_seen) "
                    "VALUES ($1, $2, $3, $4, $5::jsonb, 1, $6, $7, NOW()) "
                    "ON CONFLICT (domain, user_id, strategy_name) DO UPDATE SET "
                    "occurrence_count = strategy_patterns.occurrence_count + 1, "
                    "success_count = strategy_patterns.success_count + $6, "
                    "avg_duration_s = CASE "
                    "  WHEN $7 IS NOT NULL AND strategy_patterns.avg_duration_s IS NOT NULL "
                    "    THEN (strategy_patterns.avg_duration_s * strategy_patterns.occurrence_count + $7) "
                    "         / (strategy_patterns.occurrence_count + 1) "
                    "  WHEN $7 IS NOT NULL THEN $7 "
                    "  ELSE strategy_patterns.avg_duration_s END, "
                    "last_seen = NOW()",
                    pattern_id, domain, resolved_uid, strategy_name,
                    json.dumps(seq), int(success), duration_s,
                )
        else:
            key = (domain, resolved_uid, strategy_name)
            if key in self._mem:
                p = self._mem[key]
                p.occurrence_count += 1
                if success:
                    p.success_count += 1
                if duration_s is not None:
                    if p.avg_duration_s is not None:
                        p.avg_duration_s = (
                            (p.avg_duration_s * (p.occurrence_count - 1) + duration_s)
                            / p.occurrence_count
                        )
                    else:
                        p.avg_duration_s = duration_s
                p.last_seen = datetime.now(timezone.utc).isoformat()
            else:
                now = datetime.now(timezone.utc).isoformat()
                self._mem[key] = StrategyPattern(
                    pattern_id=str(uuid.uuid4()),
                    domain=domain,
                    user_id=resolved_uid,
                    strategy_name=strategy_name,
                    step_sequence=seq,
                    occurrence_count=1,
                    success_count=1 if success else 0,
                    avg_duration_s=duration_s,
                    last_seen=now,
                    created_at=now,
                )

        logger.info(
            "Strategy pattern upserted",
            extra={
                "event": "strategy_upsert",
                "domain": domain,
                "strategy": strategy_name,
                "success": success,
            },
        )

    async def get_top_strategies(
        self,
        domain: str,
        user_id: int | None = None,
        limit: int = 5,
    ) -> list[StrategyPattern]:
        """Get top strategies for a domain, ordered by success rate then count."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM strategy_patterns "
                    "WHERE domain = $1 AND user_id = $2 "
                    "ORDER BY "
                    "  CASE WHEN occurrence_count > 0 "
                    "    THEN success_count::float / occurrence_count "
                    "    ELSE 0 END DESC, "
                    "  occurrence_count DESC "
                    "LIMIT $3",
                    domain, resolved_uid, limit,
                )
                return [_row_to_pattern(row) for row in rows]
        else:
            matches = [
                p for (d, uid, _), p in self._mem.items()
                if d == domain and uid == resolved_uid
            ]
            matches.sort(key=lambda p: (p.success_rate, p.occurrence_count), reverse=True)
            return matches[:limit]

    async def get_by_pattern(
        self,
        domain: str,
        user_id: int | None = None,
        strategy_name: str = "",
    ) -> StrategyPattern | None:
        """Get a specific strategy pattern."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM strategy_patterns "
                    "WHERE domain = $1 AND user_id = $2 AND strategy_name = $3",
                    domain, resolved_uid, strategy_name,
                )
                return _row_to_pattern(row) if row else None
        else:
            return self._mem.get((domain, resolved_uid, strategy_name))

    async def list_all(self, user_id: int | None = None) -> list[StrategyPattern]:
        """List all strategy patterns for a user."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM strategy_patterns "
                    "WHERE user_id = $1 ORDER BY domain, occurrence_count DESC",
                    resolved_uid,
                )
                return [_row_to_pattern(row) for row in rows]
        else:
            return [
                p for (_, uid, _), p in self._mem.items()
                if uid == resolved_uid
            ]

    async def get_domain_total(
        self,
        domain: str,
        user_id: int | None = None,
    ) -> int:
        """Get total occurrence count for a domain (across all strategies)."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT COALESCE(SUM(occurrence_count), 0) AS total "
                    "FROM strategy_patterns "
                    "WHERE domain = $1 AND user_id = $2",
                    domain, resolved_uid,
                )
                return int(row["total"]) if row else 0
        else:
            return sum(
                p.occurrence_count for (d, uid, _), p in self._mem.items()
                if d == domain and uid == resolved_uid
            )

    async def get_canonical(
        self,
        domain: str,
        user_id: int | None = None,
    ) -> StrategyPattern | None:
        """Get the best canonical strategy for a domain.

        Returns the highest success-rate pattern with >=3 examples,
        but only if the domain has >=10 total tasks.
        Returns None if criteria are not met.
        """
        total = await self.get_domain_total(domain, user_id)
        if total < 10:
            return None

        strategies = await self.get_top_strategies(domain, user_id, limit=10)
        for s in strategies:
            if s.occurrence_count >= 3 and s.success_rate >= 0.6:
                return s
        return None

    async def should_regenerate_canonical(
        self,
        domain: str,
        user_id: int | None = None,
        last_generated: datetime | None = None,
        tasks_since: int = 0,
    ) -> bool:
        """Check if canonical trajectory should be regenerated.

        Returns True if:
        - No canonical has ever been generated (last_generated is None), OR
        - 30+ days since last generation, OR
        - 20+ new tasks since last generation
        """
        if last_generated is None:
            return True

        now = datetime.now(timezone.utc)
        days_since = (now - last_generated).total_seconds() / 86400.0
        if days_since >= 30:
            return True
        if tasks_since >= 20:
            return True
        return False
