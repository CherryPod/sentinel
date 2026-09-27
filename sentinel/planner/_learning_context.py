"""Learning context builders — episodic memory, auto-store, pruning flush.

Constructs the cross-session learning context injected into the planner's
system prompt. Handles episodic record search, provider-based section
assembly, budget management, and auto-memory persistence.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import TYPE_CHECKING

from sentinel.core.decorators import no_audit_log

from ._context_provider import (
    ContextBuildArgs,
    ContextProvider,
    ContextSection,
)
from ._context_providers._anchor_maps import (
    MIN_ANCHOR_BUDGET_CHARS as _MIN_ANCHOR_BUDGET_CHARS,
)
from ._context_providers._episodic_records import (
    accumulate_records_within_budget,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sentinel.memory.chunks import MemoryStore
    from sentinel.worker.base import EmbeddingBase

logger = logging.getLogger(__name__)

# Embedding calls go to Ollama over HTTP — bound them so a stalled
# inference server doesn't block context building indefinitely.
_EMBEDDING_TIMEOUT = 30.0

# Minimum results from domain-filtered search before retrying unfiltered
_DOMAIN_SEARCH_MIN_RESULTS = 3


# ── Domain classification ──────────────────────────────────────


@no_audit_log
def _classify_request_domain(user_request: str) -> str | None:
    """Classify a user request into a task domain for filtered retrieval.

    Simple keyword-based classifier — runs at retrieval time before we
    have step_outcomes. Returns None when no strong signal is found,
    which means the search will be unfiltered.
    """
    low = user_request.lower()
    if any(w in low for w in ("fix", "debug", "error", "broken", "bug", "not working")):
        logger.debug(
            "Request domain classified",
            extra={"event": "builders.classifydomain", "domain": "code_debugging"},
        )
        return "code_debugging"
    if any(w in low for w in ("send", "message", "email", "signal", "telegram")):
        logger.debug(
            "Request domain classified",
            extra={"event": "builders.classifydomain", "domain": "messaging"},
        )
        return "messaging"
    # Site/file modification takes priority over search — "search X then add
    # to dashboard" is a composite task, not a pure search task
    has_site_mod = any(
        w in low
        for w in (
            "dashboard",
            "panel",
            "website",
            "site",
            "sitrep",
            "add to",
            "update the",
            "populate",
            "add a",
        )
    )
    if any(w in low for w in ("search", "find", "look up", "google")):
        if has_site_mod:
            logger.debug(
                "Request domain classified",
                extra={"event": "builders.classifydomain", "domain": "composite"},
            )
            return "composite"
        logger.debug(
            "Request domain classified",
            extra={"event": "builders.classifydomain", "domain": "search"},
        )
        return "search"
    if any(w in low for w in ("calendar", "event", "schedule", "meeting")):
        logger.debug(
            "Request domain classified",
            extra={"event": "builders.classifydomain", "domain": "calendar"},
        )
        return "calendar"
    if has_site_mod:
        logger.debug(
            "Request domain classified",
            extra={"event": "builders.classifydomain", "domain": "file_ops"},
        )
        return "file_ops"
    logger.debug(
        "Request domain classified",
        extra={"event": "builders.classifydomain", "domain": "none"},
    )
    return None


# ── Provider helpers ───────────────────────────────────────────


def _default_providers() -> list[ContextProvider]:
    """Create the standard 5-section provider set.

    Called when ``build_learning_context`` is invoked without an explicit
    ``providers`` argument.  Each call returns fresh instances.
    """
    from sentinel.planner._context_providers import (
        AnchorMapsProvider,
        CanonicalTrajectoryProvider,
        DetailedPlanHistoryProvider,
        DomainSummaryProvider,
        PlanningInsightsProvider,
    )

    # EpisodicRecordsProvider is NOT included here — episodic records are
    # handled directly by the builder via accumulate_records_within_budget
    # with per-record budget tracking.  Including the provider would
    # duplicate records in the output.
    return [
        DomainSummaryProvider(),
        PlanningInsightsProvider(),
        CanonicalTrajectoryProvider(),
        DetailedPlanHistoryProvider(),
        AnchorMapsProvider(),
    ]


# ── Episodic search ───────────────────────────────────────────


async def _search_episodic_records(
    user_request: str,
    memory_store: MemoryStore,
    embedding_client: EmbeddingBase | None,
    reranker,
    domain: str | None,
) -> list:
    """Search and optionally rerank episodic records for learning context.

    1. Generate query embedding (if embedding_client available)
    2. Hybrid search with domain filter
    3. Fallback to unfiltered search if domain filter returns < 3 results
    4. Rerank via reranker if available (over-retrieve k=15 → top 5)

    Returns the final list of search results (possibly reranked).
    Raises on search failure (caller handles).
    """
    from sentinel.memory.search import hybrid_search

    # getattr defensive: matches orchestrator entry log pattern — a broken
    # reranker without .available falls back to no-rerank rather than crashing
    has_reranker = reranker is not None and getattr(reranker, "available", False)
    retrieve_k = 15 if has_reranker else 5
    final_k = 5

    logger.debug(
        "Episodic record search starting",
        extra={
            "event": "episodic.search_start",
            "has_reranker": has_reranker,
            "retrieve_k": retrieve_k,
            "domain": domain,
        },
    )

    # Try embedding for hybrid search, fall back to full-text-only
    query_embedding = None
    if embedding_client is not None:
        try:
            query_embedding = await asyncio.wait_for(
                embedding_client.embed(user_request, prefix="search_query: "),
                timeout=_EMBEDDING_TIMEOUT,
            )
            logger.debug(
                "Query embedding generated",
                extra={
                    "event": "learning.context_embed",
                    "dimensions": len(query_embedding) if query_embedding else 0,
                },
            )
        except Exception as exc:  # catch-all: embedding fallback to FTS-only
            logger.debug(
                "Query embedding failed — FTS only",
                extra={
                    "event": "learning.context_embed",
                    "error": str(exc),
                    "error_category": "embedding_fallback",
                },
            )

    # Domain-filtered search
    results = await hybrid_search(
        pool=memory_store.pool,
        query=user_request,
        embedding=query_embedding,
        k=retrieve_k,
        task_domain=domain,
    )
    logger.debug(
        "Hybrid search results (domain-filtered)",
        extra={
            "event": "learning.context_search",
            "domain_filter": domain,
            "result_count": len(results),
            "scores": [
                {
                    "content_len": len(r.content),
                    "score": round(r.score, 4),
                    "match_type": r.match_type,
                }
                for r in results[:5]
            ],
        },
    )

    # Fallback: if domain-filtered search returns few results, retry unfiltered
    if len(results) < _DOMAIN_SEARCH_MIN_RESULTS and domain is not None:
        logger.debug(
            "Domain filter returned few results — retrying unfiltered",
            extra={
                "event": "learning.context_search_fallback",
                "domain": domain,
                "filtered_count": len(results),
            },
        )
        results = await hybrid_search(
            pool=memory_store.pool,
            query=user_request,
            embedding=query_embedding,
            k=retrieve_k,
        )
        logger.debug(
            "Hybrid search results (unfiltered fallback)",
            extra={
                "event": "learning.context_search",
                "domain_filter": None,
                "result_count": len(results),
                "scores": [
                    {
                        "content_len": len(r.content),
                        "score": round(r.score, 4),
                        "match_type": r.match_type,
                    }
                    for r in results[:5]
                ],
            },
        )

    # Re-rank if reranker is available — narrows candidates to top final_k
    if has_reranker and results:
        pre_rerank_order = [
            {"content_len": len(r.content), "score": round(r.score, 4)}
            for r in results[:8]
        ]
        reranked = reranker.rerank(
            query=user_request,
            candidates=results,
            top_k=final_k,
        )
        post_rerank_order = [
            {
                "content_len": len(r.content),
                "rerank_score": round(r.rerank_score, 4),
                "original_score": round(r.original_score, 4),
            }
            for r in reranked
        ]
        logger.debug(
            "Reranker reshuffled results",
            extra={
                "event": "learning.context_rerank",
                "candidates_in": len(results),
                "results_out": len(reranked),
                "pre_rerank_top5": pre_rerank_order[:5],
                "post_rerank": post_rerank_order,
            },
        )
        results = reranked

    return results


# ── Budget assembly helpers ────────────────────────────────────


def _assemble_fixed_and_records(
    sections: list[ContextSection],
    results: list,
    budget_chars: int,
) -> tuple[list[str], list[ContextSection], dict[str, bool], int, int]:
    """Assemble fixed (non-budget-aware) sections and episodic records within budget.

    Returns (parts, budget_aware_sections, section_flags, records_used, records_cut).
    """
    header = "[EPISODIC CONTEXT — previous task execution history:]"
    footer = "[END EPISODIC CONTEXT]"

    # Fixed sections (non-budget-aware) go first
    fixed_sections = [s for s in sections if not s.budget_aware and s.text]
    fixed_overhead = (
        len(header) + sum(len(s.text) for s in fixed_sections) + len(footer)
    )

    # Budget-aware: episodic records get accumulated within remaining budget
    record_lines: list[str] = []
    records_used = 0
    records_cut = 0
    if results:
        logger.debug(
            "build_learning_context: results",
            extra={
                "event": "builders.build_learning_context.match",
                "reason": "results",
            },
        )  # auto:neg
        record_lines, records_used = accumulate_records_within_budget(
            results,
            budget_chars - fixed_overhead,
        )
        records_cut = len(results) - len(record_lines)

    # If nothing to inject at all, bail
    if not record_lines and not fixed_sections:
        return [], [], {}, 0, 0

    # Combine: header → fixed sections → record lines → footer
    parts = [header]
    section_flags: dict[str, bool] = {}
    for section in fixed_sections:
        logger.debug(
            "build_learning_context: section included",
            extra={
                "event": "builders.build_learning_context.match",
                "section_name": section.name,
            },
        )
        parts.append(section.text.rstrip())
        section_flags[section.name] = True
    parts.extend(record_lines)
    parts.append(footer)

    logger.info(
        "Episodic context assembled — %d records injected, %d dropped, sections: %s",
        len(record_lines),
        records_cut,
        ", ".join(section_flags.keys()) or "none",
        extra={
            "event": "learning.context_assembled",
            "context_chars": sum(len(p) for p in parts) + len(parts) - 1,
            "records_injected": len(record_lines),
            "records_dropped": records_cut,
            "section_names": list(section_flags.keys()),
            "budget_chars": budget_chars,
            "budget_used": fixed_overhead + records_used,
        },
    )

    budget_aware_sections = [s for s in sections if s.budget_aware and s.text]
    return parts, budget_aware_sections, section_flags, records_used, records_cut


def _append_budget_aware_sections(
    parts: list[str],
    budget_aware_sections: list[ContextSection],
    budget_chars: int,
) -> None:
    """Append budget-aware sections (anchor maps etc.) trimmed to remaining budget.

    Modifies ``parts`` in-place.
    """
    for ba_section in budget_aware_sections:
        current_chars = sum(len(p) for p in parts) + len(parts) - 1
        remaining = max(0, budget_chars - current_chars)
        if len(ba_section.text) <= remaining:
            parts.append(ba_section.text)
        elif remaining > _MIN_ANCHOR_BUDGET_CHARS:
            # Trim to fit at a newline boundary to avoid malformed content
            trimmed = ba_section.text[:remaining]
            last_nl = trimmed.rfind("\n")
            if last_nl > 0:
                trimmed = trimmed[:last_nl]
            parts.append(trimmed)
            logger.debug(
                "Budget-aware section trimmed to fit",
                extra={
                    "event": "learning.context_section_trimmed",
                    "section_name": ba_section.name,
                    "section_chars": len(ba_section.text),
                    "remaining_budget": remaining,
                },
            )
        else:
            logger.debug(
                "Budget-aware section skipped — insufficient budget",
                extra={
                    "event": "learning.context_section_skipped",
                    "section_name": ba_section.name,
                    "section_chars": len(ba_section.text),
                    "remaining_budget": remaining,
                },
            )


# ── Main builder ───────────────────────────────────────────────


async def build_learning_context(
    user_request: str,
    memory_store: MemoryStore | None,
    embedding_client: EmbeddingBase | None,
    cross_session_token_budget: int,
    domain_summary_store=None,
    reranker=None,
    episodic_store=None,
    insight_store=None,
    providers: Sequence[ContextProvider] | None = None,
) -> str:
    """Build hierarchical learning context for the planner.

    Iterates over registered ``ContextProvider`` instances in priority
    order, assembling their sections within the token budget.  The
    default provider set reproduces the original 6-section layout:

    1. Domain summary (~200 tokens) — always included if available
    2. Planning insights — distilled heuristics from past plan-outcome pairs
    3. Canonical trajectory — proven best approach for the domain
    4. Detailed plan history — tier-2 rendering of top episodic match
    5. Episodic records — budget-trimmed search results
    6. Anchor maps — file anchors from prior tasks

    Pass a custom ``providers`` list to add or replace sections without
    modifying this function.

    Returns formatted context string, or "" if nothing found.
    """
    if memory_store is None or memory_store.pool is None:
        logger.debug(
            "Learning context skipped — no memory store",
            extra={"event": "learning.context_skip", "reason": "no_memory_store"},
        )
        return ""

    # Classify request domain for filtered retrieval
    domain = _classify_request_domain(user_request)

    # Resolve user_id once — needed by insights and anchor maps
    from sentinel.core.context import current_user_id

    user_id: int | None = current_user_id.get()

    logger.debug(
        "Learning context entry",
        extra={
            "event": "learning.context_entry",
            "domain": domain,
            "request_len": len(user_request) if user_request else 0,
            "has_reranker": reranker is not None
            and getattr(reranker, "available", False),
            "has_domain_summary_store": domain_summary_store is not None,
            "has_embedding_client": embedding_client is not None,
            "token_budget": cross_session_token_budget,
            "user_id": user_id,
        },
    )

    # Episodic search — infrastructure, not a provider.  Populates
    # search_results on the shared args for downstream providers.
    try:
        results = await _search_episodic_records(
            user_request,
            memory_store,
            embedding_client,
            reranker,
            domain,
        )
    except Exception as exc:  # catch-all: cross-session search best-effort
        logger.warning(
            "Cross-session search failed (non-fatal)",
            extra={
                "event": "cross.session_search_failed",
                "error": str(exc),
                "error_category": "episodic_search",
            },
            exc_info=True,
        )
        return ""

    # Build shared args for all providers
    args = ContextBuildArgs(
        user_request=user_request,
        domain=domain,
        user_id=user_id,
        memory_store=memory_store,
        embedding_client=embedding_client,
        reranker=reranker,
        domain_summary_store=domain_summary_store,
        episodic_store=episodic_store,
        insight_store=insight_store,
        search_results=results,
    )

    # Default provider set — reproduces the original 6-section layout
    if providers is None:
        providers = _default_providers()

    # Run all providers and collect sections in priority order
    sections: list[ContextSection] = []
    for provider in sorted(providers, key=lambda p: p.priority):
        section = await provider.build(args)
        sections.append(section)

    # Check if we have anything at all
    has_content = any(s.text for s in sections if not s.budget_aware)
    if not results and not has_content:
        logger.debug(
            "Learning context empty — no results and no provider content",
            extra={"event": "learning.context_empty"},
        )
        return ""
    logger.debug(
        "build_learning_context: not_results_passed",
        extra={
            "event": "learning.context_empty.passed",
            "reason": "not_results_passed",
        },
    )  # auto:neg

    # Assemble sections within token budget (~4 chars per token)
    budget_chars = cross_session_token_budget * 4

    parts, budget_aware_sections, section_flags, records_used, records_cut = (
        _assemble_fixed_and_records(sections, results, budget_chars)
    )
    if not parts:
        logger.debug(
            "Learning context empty — no records fit budget",
            extra={
                "event": "learning.context_empty",
                "budget_chars": budget_chars,
                "available_records": len(results),
            },
        )
        return ""

    # Budget-aware sections (anchor maps etc.) — appended after main assembly,
    # trimmed to remaining budget to prevent exceeding token limit.
    _append_budget_aware_sections(parts, budget_aware_sections, budget_chars)

    context = "\n".join(parts)
    logger.debug(
        "Learning context built",
        extra={
            "event": "learning.context_built",
            "domain": domain,
            "context_chars": len(context),
            "budget_chars": budget_chars,
            "context_hash": hashlib.sha256(context.encode()).hexdigest()[:16],
        },
    )
    return context
