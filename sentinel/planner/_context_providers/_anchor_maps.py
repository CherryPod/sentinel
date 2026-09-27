"""Context provider for anchor map lookups.

Wraps the anchor map fetch logic to provide structural anchor references
as learning context for the planner. Budget-aware: can be trimmed to fit
remaining token budget.
"""

from __future__ import annotations

import logging

from sentinel.crypto.blind_index import log_hash
from sentinel.memory.episodic import _redact_paths, _sanitise_for_planner
from sentinel.planner._context_provider import ContextBuildArgs, ContextSection

logger = logging.getLogger(__name__)

# Exported so the builder can check whether the remaining budget is worth
# requesting anchor maps at all.
MIN_ANCHOR_BUDGET_CHARS = 100


class AnchorMapsProvider:
    """Fetches anchor maps from the episodic store.

    Priority 60 — anchor maps appear after most other context sections.
    Budget-aware: the builder may trim the returned text to fit remaining
    token budget rather than dropping it entirely.
    """

    @property
    def name(self) -> str:
        return "anchor_maps"

    @property
    def priority(self) -> int:
        return 60

    async def build(self, args: ContextBuildArgs) -> ContextSection:
        """Fetch and format anchor maps, or return empty on failure."""
        text = await self._fetch_anchor_maps(
            args.episodic_store,
            args.user_id,
        )
        return ContextSection(
            name=self.name,
            text=text,
            priority=self.priority,
            budget_aware=True,
        )

    async def _fetch_anchor_maps(
        self,
        episodic_store: object | None,
        user_id: int | None,
    ) -> str:
        if episodic_store is None:
            logger.debug(
                "_fetch_anchor_maps skipped — no episodic_store",
                extra={
                    "event": "fetch.anchor_maps_skip",
                    "reason": "no_episodic_store",
                },
            )
            return ""

        try:
            import json as _json

            anchor_facts = await episodic_store.search_facts(  # type: ignore[union-attr]
                query="anchor_map",
                fact_type="anchor_map",
                user_id=user_id or 1,
                limit=20,
            )
            if not anchor_facts:
                logger.debug(
                    "No anchor maps found",
                    extra={"event": "anchor.map_empty", "user_id": user_id or 1},
                )
                return ""

            anchor_lines: list[str] = []
            for fact in anchor_facts:
                try:
                    data = _json.loads(fact.content)
                    # Q7.fix.g (field-specific scrub, Codex reframe thread
                    # 019db690-0d4e-7b10-bdef-3de78b9f33de; MC-review fix-now
                    # adjustments on threads 019db6a1 + SP agent a8ef4780):
                    #   - fact.file_path + anchor name: SP only — exact
                    #     identifiers the planner reuses verbatim in tool
                    #     calls and anchor-map lookups. RP would collapse
                    #     directory context / corrupt identifiers. `or ""`
                    #     guard: EpisodicFact.file_path is str | None; a
                    #     stored None would raise TypeError in SP and be
                    #     caught by the outer catch-all, silently dropping
                    #     the entire fact batch. Graceful per-fact fallback.
                    #   - anchor description: RP(SP(RP(x))) triple-pass —
                    #     single-pass SP(RP) under-redacts paths with
                    #     tag/chat-token-shaped segments that break the
                    #     abs-path regex (Codex repro /a/b/<|system|>foo.txt).
                    #     Single-pass RP(SP) under-redacts paths with
                    #     marker-colon segments where SP replaces the marker
                    #     with `[REDACTED]` whose brackets then break RP's
                    #     abs-path regex (/a/b/SYSTEM:foo.txt). Triple-pass
                    #     closes both gaps with one extra regex call.
                    # Q7-U1 umbrella tracks extraction of field-specific
                    # wrappers (scrub_planner_{identifier,path,text}) and
                    # harmonisation of ~20 free-text sites to the triple-pass
                    # shape or regex-class broadening.
                    scrubbed_file_path = _sanitise_for_planner(
                        fact.file_path or ""
                    )
                    anchor_lines.append(f"\n[ANCHOR MAP: {scrubbed_file_path}]")
                    for a in data.get("anchors", []):
                        scrubbed_name = _sanitise_for_planner(a["name"])
                        scrubbed_desc = _redact_paths(
                            _sanitise_for_planner(
                                _redact_paths(a["description"])
                            )
                        )
                        end = (
                            f" (pair: {scrubbed_name}-end)" if a.get("has_end") else ""
                        )
                        anchor_lines.append(f"  {scrubbed_name} — {scrubbed_desc}{end}")
                    anchor_lines.append("[END ANCHOR MAP]")
                except (ValueError, KeyError) as exc:
                    logger.debug(
                        "Anchor map parse failed for fact",
                        extra={
                            "event": "anchor.map_parse_error",
                            "error": str(exc),
                            "file_path_ref_hash": log_hash(getattr(fact, "file_path", None) or ""),
                            "file_path_ref_len": len(getattr(fact, "file_path", "") or ""),
                        },
                    )
                    continue

            if anchor_lines:
                logger.debug(
                    "Anchor maps fetched",
                    extra={
                        "event": "anchor.map_found",
                        "fact_count": len(anchor_facts),
                        "line_count": len(anchor_lines),
                    },
                )
                return "\n".join(anchor_lines)
            return ""
        except Exception as exc:  # catch-all: context provider graceful degradation
            logger.debug(
                "Anchor map fetch failed (non-fatal)",
                extra={"event": "anchor.map_fetch_error", "error": str(exc)},
                exc_info=True,
            )
            return ""
