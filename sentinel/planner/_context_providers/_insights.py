"""Planning insights context provider.

Wraps the existing ``_fetch_planning_insights`` logic and the
``render_insights`` helper into a ``ContextProvider`` implementation.
``render_insights`` is also exported at module level because other code
references it directly.
"""

from __future__ import annotations

import logging

from sentinel.memory.episodic import _sanitise_for_planner
from sentinel.planner._context_provider import ContextBuildArgs, ContextSection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public helper — also used outside this provider
# ---------------------------------------------------------------------------


def render_insights(insights: list) -> str:
    """Format a list of insight records into a bracketed context block."""
    logger.debug(
        "render_insights called",
        extra={
            "event": "insights.render",
            "insights_len": len(insights) if hasattr(insights, "__len__") else 0,
        },
    )
    if not insights:
        return ""

    lines = ["[PLANNING INSIGHTS — learned from prior tasks]"]
    for ins in insights[:8]:
        # Q7-F5 (replay): stored ins.insight is replayed verbatim into the
        # planner prompt. Apply SP (marker scrub) at the render sink so an
        # insight poisoned at extraction time (Q7-F5 extraction side is
        # closed separately by Q7.fix.d) cannot inject planner-prompt
        # markers on replay. No RP — insights are short controlled
        # natural-language text, not path-bearing aggregates.
        lines.append(
            f"- {_sanitise_for_planner(ins.insight)} (confidence: {ins.confidence:.2f}, seen {ins.evidence_count} times)"
        )
    lines.append("[END PLANNING INSIGHTS]")
    return "\n".join(lines) + "\n\n"


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class PlanningInsightsProvider:
    """Fetches and renders planning insights for the current domain.

    Priority 20 — appears early in assembled context so the planner
    sees learned patterns before episodic details.
    """

    @property
    def name(self) -> str:
        return "planning_insights"

    @property
    def priority(self) -> int:
        return 20

    async def build(self, args: ContextBuildArgs) -> ContextSection:
        """Build the planning-insights context section."""
        logger.debug(
            "build called",
            extra={"event": "insights.build", "args_type": type(args).__name__},
        )  # auto:entry
        domain = args.domain
        insight_store = args.insight_store
        user_id = args.user_id

        result_text = await _fetch_planning_insights(domain, insight_store, user_id)
        return ContextSection(name=self.name, text=result_text, priority=self.priority)


# ---------------------------------------------------------------------------
# Internal fetch logic (preserved from builders.py)
# ---------------------------------------------------------------------------


async def _fetch_planning_insights(
    domain: str | None,
    insight_store: object | None,
    user_id: int | None,
) -> str:
    """Fetch and render planning insights for *domain*.

    Returns rendered text or ``""`` on skip/failure.  All error paths
    are swallowed so the provider never raises.
    """
    if insight_store is None or not domain:
        logger.debug(
            "Planning insights skipped — no store or no domain",
            extra={
                "event": "planning.insights_skip",
                "has_store": insight_store is not None,
                "domain": domain,
            },
        )
        return ""

    try:
        if not user_id:
            logger.debug(
                "Planning insights skipped — no user_id",
                extra={"event": "planning.insights_skip", "reason": "no_user_id"},
            )
            return ""

        insights = await insight_store.get_top(
            user_id=user_id,
            domain=domain,
            limit=8,
        )
        if insights:
            section = render_insights(insights)
            logger.debug(
                "Planning insights found",
                extra={
                    "event": "learning.context_insights",
                    "domain": domain,
                    "count": len(insights),
                },
            )
            return section
        return ""
    except Exception as exc:  # catch-all: context provider graceful degradation
        logger.debug(
            "Planning insights fetch failed",
            extra={"event": "learning.context_insights", "error": str(exc)},
            exc_info=True,
        )
        return ""
