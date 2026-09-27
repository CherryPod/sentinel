"""Planning insight store and extractor.

Stores distilled planning heuristics from plan-outcome pairs.
Confidence scoring uses asymptotic confirmation / sharp contradiction.
Sanitisation ensures security-sensitive terms never reach the planner.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinel.core.context import require_user_id
from sentinel.memory.episodic import _sanitise_for_planner

logger = logging.getLogger(__name__)


@dataclass
class PlanningInsight:
    """A single planning heuristic distilled from plan-outcome pairs."""

    insight_id: str
    user_id: int
    category: str  # tool_pattern | error_avoidance | strategy
    insight: str
    evidence_count: int = 1
    confidence: float = 0.5
    source_records: list[str] = field(default_factory=list)
    domain: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


def update_confidence(current: float, *, confirmed: bool) -> float:
    """Update confidence score.

    Confirmation: asymptotic approach to 1.0.
    Contradiction: sharp drop but never below 0.1.
    """
    if confirmed:
        return min(1.0, current + (1.0 - current) * 0.15)
    return max(0.1, current * 0.7)


def _row_to_insight(row: Any) -> PlanningInsight:
    """Convert an asyncpg Record to a PlanningInsight."""
    source_raw = row["source_records"]
    if isinstance(source_raw, str):
        source_records = json.loads(source_raw)
    else:
        source_records = source_raw or []

    return PlanningInsight(
        insight_id=row["insight_id"],
        user_id=row["user_id"],
        category=row["category"],
        insight=row["insight"],
        evidence_count=row["evidence_count"],
        confidence=row["confidence"],
        source_records=source_records,
        domain=row.get("domain"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class InsightStore:
    """PostgreSQL CRUD for planning_insights table."""

    def __init__(self, pool: Any) -> None:
        self.pool = pool

    async def upsert(self, insight: PlanningInsight) -> None:
        """Insert or update an insight (upsert by insight_id)."""
        require_user_id(insight.user_id, "InsightStore.upsert")
        now = datetime.now(UTC)
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO planning_insights
                    (insight_id, user_id, category, insight, evidence_count,
                     confidence, source_records, domain, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
                ON CONFLICT (insight_id) DO UPDATE SET
                    insight = EXCLUDED.insight,
                    evidence_count = EXCLUDED.evidence_count,
                    confidence = EXCLUDED.confidence,
                    source_records = EXCLUDED.source_records,
                    updated_at = $9
                """,
                insight.insight_id,
                insight.user_id,
                insight.category,
                insight.insight,
                insight.evidence_count,
                insight.confidence,
                json.dumps(insight.source_records),
                insight.domain,
                now,
            )
        logger.info(
            "insight_store: upserted %s (confidence=%.2f, evidence=%d)",
            insight.insight_id,
            insight.confidence,
            insight.evidence_count,
            extra={"event": "insight.upsert", "insight_id": insight.insight_id},
        )

    async def get_top(
        self,
        user_id: int,
        domain: str | None = None,
        limit: int = 8,
    ) -> list[PlanningInsight]:
        """Get top insights by confidence for a domain (includes universal)."""
        require_user_id(user_id, "InsightStore.get_top")
        logger.debug(
            "insights.get_top",
            extra={"event": "insights.get_top", "domain": domain, "limit": limit},
        )
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT insight_id, user_id, category, insight, evidence_count,
                       confidence, source_records, domain, created_at, updated_at
                FROM planning_insights
                WHERE user_id = $1 AND (domain = $2 OR domain IS NULL)
                ORDER BY confidence DESC
                LIMIT $3
                """,
                user_id,
                domain,
                limit,
            )
        return [_row_to_insight(r) for r in rows]

    async def list_all(self, user_id: int) -> list[PlanningInsight]:
        """List all insights for a user."""
        require_user_id(user_id, "InsightStore.list_all")
        logger.debug("insights.list_all", extra={"event": "insights.list_all"})
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT insight_id, user_id, category, insight, evidence_count,
                       confidence, source_records, domain, created_at, updated_at
                FROM planning_insights
                WHERE user_id = $1
                ORDER BY confidence DESC
                """,
                user_id,
            )
        return [_row_to_insight(r) for r in rows]

    async def get_by_domain(self, user_id: int, domain: str) -> list[PlanningInsight]:
        """Get insights for a specific domain (for extraction dedup)."""
        require_user_id(user_id, "InsightStore.get_by_domain")
        logger.debug(
            "insights.get_by_domain",
            extra={"event": "insights.get_by_domain", "domain": domain},
        )
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT insight_id, user_id, category, insight, evidence_count,
                       confidence, source_records, domain, created_at, updated_at
                FROM planning_insights
                WHERE user_id = $1 AND domain = $2
                ORDER BY confidence DESC
                """,
                user_id,
                domain,
            )
        return [_row_to_insight(r) for r in rows]


# ── Sanitisation ─────────────────────────────────────────────────

# Terms that must never appear in planner-facing text
_FORBIDDEN_TERMS = frozenset(
    {
        "semgrep",
        "yara",
        "clamav",
        "scanner",
        "scan_pipeline",
        "codeshield",
        "rule_id",
        "innerHTML-xss",
        "no-new-privileges",
        "securityopt",
    }
)

_FORBIDDEN_RE = re.compile(
    "|".join(re.escape(t) for t in _FORBIDDEN_TERMS),
    re.IGNORECASE,
)


def _sanitise_plan_summaries(text: str) -> str:
    """Strip security-sensitive terms from plan summaries before extraction."""
    return _FORBIDDEN_RE.sub("a security check", text)


# ── Insight Extractor ────────────────────────────────────────────


class InsightExtractor:
    """Batch extraction of planning insights from plan-outcome pairs.

    Queries episodic records with plan_json, groups by domain,
    sends to planner for insight extraction, deduplicates against
    existing insights.
    """

    def __init__(
        self, episodic_store: Any, insight_store: InsightStore, planner: Any
    ) -> None:
        self.episodic_store = episodic_store
        self.insight_store = insight_store
        self.planner = planner

    async def extract(
        self,
        user_id: int,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[PlanningInsight]:
        """Extract insights from recent plan-outcome pairs.

        Groups records by domain, sends each group to the planner
        with existing insights for dedup, stores results.
        """
        records = await self._fetch_records(user_id, since, limit)
        if not records:
            logger.info("insight_extract: no records with plan_json found")
            return []

        # Group by domain
        by_domain: dict[str, list] = {}
        for rec in records:
            domain = rec.get("task_domain") or "general"
            by_domain.setdefault(domain, []).append(rec)

        all_insights: list[PlanningInsight] = []

        for domain, domain_records in by_domain.items():
            try:
                insights = await self._extract_domain(user_id, domain, domain_records)
                all_insights.extend(insights)
            except Exception:
                logger.exception(
                    "insight_extract: domain failed",
                    extra={"event": "insight.extract_error", "domain": domain},
                )

        logger.info(
            "insight_extract: %d insights from %d records (%d domains)",
            len(all_insights),
            len(records),
            len(by_domain),
            extra={"event": "insight.extract_complete"},
        )

        return all_insights

    async def _fetch_records(self, user_id: int, since, limit: int) -> list[dict]:
        """Fetch episodic records that have plan_json."""
        logger.debug(
            "_fetch_records called",
            extra={
                "event": "memory.insights._fetch_records",
                "user_id": user_id,
                "since_type": type(since).__name__,
                "limit": limit,
            },
        )  # auto:entry
        require_user_id(user_id, "InsightExtractor._fetch_records")
        async with self.episodic_store.pool.acquire() as conn:
            sql = """
                SELECT record_id, task_domain, user_request, task_status, plan_json
                FROM episodic_records
                WHERE user_id = $1 AND plan_json IS NOT NULL
            """
            params: list = [user_id]
            if since:
                logger.debug(
                    "_fetch_records: since",
                    extra={
                        "event": "memory.insights._fetch_records.match",
                        "reason": "since",
                    },
                )  # auto:neg
                sql += " AND created_at >= $2"
                params.append(since)
                sql += f" ORDER BY created_at DESC LIMIT ${len(params) + 1}"
            else:
                logger.debug(
                    "_fetch_records: since",
                    extra={
                        "event": "memory.insights._fetch_records.clean",
                        "reason": "since",
                    },
                )  # auto:neg
                sql += f" ORDER BY created_at DESC LIMIT ${len(params) + 1}"
            params.append(limit)

            rows = await conn.fetch(sql, *params)

        result = []
        for row in rows:
            plan_raw = row["plan_json"]
            plan_json = json.loads(plan_raw) if isinstance(plan_raw, str) else plan_raw
            result.append(
                {
                    "record_id": row["record_id"],
                    "task_domain": row["task_domain"],
                    "user_request": row["user_request"],
                    "task_status": row["task_status"],
                    "plan_json": plan_json,
                }
            )
        return result

    async def _extract_domain(
        self,
        user_id: int,
        domain: str,
        records: list[dict],
    ) -> list[PlanningInsight]:
        """Extract insights for a single domain group."""
        existing = await self.insight_store.get_by_domain(user_id, domain)

        # Build summaries (sanitised)
        summaries = []
        for rec in records:
            summary = self._render_record_summary(rec)
            summaries.append(_sanitise_plan_summaries(summary))

        # Build extraction prompt with existing insights for dedup
        existing_text = ""
        if existing:
            existing_text = (
                "\n\nEXISTING INSIGHTS (merge into these if they cover the same "
                "pattern, return their insight_id):\n"
            )
            for ins in existing:
                existing_text += (
                    f"- [{_sanitise_for_planner(ins.insight_id)}] "
                    f"{_sanitise_for_planner(ins.insight)} "
                    f"(confidence: {ins.confidence:.2f})\n"
                )

        prompt = (
            f"Analyse these {len(records)} plan-outcome pairs for {domain} tasks.\n"
            f"Extract reusable planning rules in these categories:\n"
            f"- tool_pattern: tools or tool sequences that consistently work or fail\n"
            f"- error_avoidance: approaches that get rejected and what works instead\n"
            f"- strategy: high-level approaches that succeed for this type of task\n\n"
            f"Return a JSON array. Each insight must have: category, insight (text), "
            f"confidence (0.0-1.0), source_records (list of record_ids).\n"
            f"If merging with an existing insight, include its insight_id.\n"
            f"Insights must be actionable and NEVER reference scanners, rules, "
            f"or security mechanisms.\n"
            f"{existing_text}\n"
            f"PLAN-OUTCOME DATA:\n" + "\n---\n".join(summaries)
        )

        # Call planner
        response_text = await self._call_planner(prompt)

        # Parse response
        try:
            raw_insights = json.loads(response_text)
        except json.JSONDecodeError:
            logger.warning(
                "insight_extract: planner returned non-JSON",
                extra={"event": "insight.extract_parse_error", "domain": domain},
                exc_info=True,
            )
            return []

        insights = []
        for raw in raw_insights:
            insight_id = raw.get("insight_id") or f"ins-{uuid.uuid4().hex[:12]}"
            ins = PlanningInsight(
                insight_id=insight_id,
                user_id=user_id,
                category=raw.get("category", "strategy"),
                insight=_sanitise_plan_summaries(raw.get("insight", "")),
                evidence_count=len(raw.get("source_records", [])),
                confidence=float(raw.get("confidence", 0.5)),
                source_records=raw.get("source_records", []),
                domain=domain,
            )

            # If merging with existing, update confidence
            existing_match = next(
                (e for e in existing if e.insight_id == insight_id),
                None,
            )
            if existing_match:
                ins.confidence = update_confidence(
                    existing_match.confidence,
                    confirmed=True,
                )
                ins.evidence_count = existing_match.evidence_count + ins.evidence_count

            await self.insight_store.upsert(ins)
            insights.append(ins)

        return insights

    async def _call_planner(self, prompt: str) -> str:
        """Call the planner for free-form text completion.

        Supports both raw_completion (test mocks) and the real
        Claude client via planner._client.
        """
        if hasattr(self.planner, "raw_completion"):
            return await self.planner.raw_completion(prompt)

        # Fall back to Claude API via planner's client
        from sentinel.core.config import settings

        response = await self.planner._client.messages.create(
            model=settings.claude_model,
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _render_record_summary(self, rec: dict) -> str:
        """Render a single record's plan-outcome data for the extraction prompt."""
        logger.debug(
            "_render_record_summary called",
            extra={
                "event": "insight.render_record_summary",
                "rec_len": len(rec) if hasattr(rec, "__len__") else 0,
            },
        )
        plan_json = rec.get("plan_json", {})
        phases = plan_json.get("phases", [])

        lines = [
            f"Record: {rec['record_id']}",
            f"Request: {_sanitise_for_planner(rec.get('user_request', ''))[:150]}",
            f"Status: {rec.get('task_status', 'unknown')}",
        ]

        for phase in phases:
            trigger = phase.get("trigger", "initial")
            plan = phase.get("plan", {})
            outcomes = phase.get("step_outcomes_summary", {})
            lines.append(
                f"  Phase ({trigger}): {_sanitise_for_planner(plan.get('summary', ''))[:100]}",
            )
            for step_id, outcome in outcomes.items():
                status = outcome.get("status", "unknown")
                error = outcome.get("error", "")
                line = f"    {_sanitise_for_planner(step_id)}: {status}"
                if error:
                    line += f" ({_sanitise_for_planner(error)[:60]})"
                lines.append(line)

        return "\n".join(lines)
