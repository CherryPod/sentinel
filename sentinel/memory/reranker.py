"""Lightweight cross-encoder re-ranking via FlashRank + MMR diversity.

Wraps FlashRank's Ranker to re-score (query, document) pairs after
initial hybrid retrieval, then applies Maximal Marginal Relevance (MMR)
to ensure the final top-k results are diverse (no near-duplicate content).

Degrades gracefully if flashrank is not installed — callers get an empty
rerank that returns candidates as-is.

Model: ms-marco-MiniLM-L-12-v2 (~33MB ONNX, CPU-only, no PyTorch).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger("sentinel.audit")

# Lazy import — flashrank may not be installed
_flashrank_available = False
try:
    from flashrank import Ranker as _Ranker, RerankRequest as _RerankRequest
    _flashrank_available = True
except ImportError:
    _Ranker = None  # type: ignore[assignment,misc]
    _RerankRequest = None  # type: ignore[assignment,misc]


@dataclass
class RerankResult:
    """A re-ranked search result with the original fields plus reranker score."""

    chunk_id: str
    content: str
    source: str
    original_score: float
    rerank_score: float
    match_type: str


# ── MMR helpers ─────────────────────────────────────────────────


def _jaccard_similarity(text_a: str, text_b: str) -> float:
    """Word-level Jaccard similarity between two texts.

    Returns 0.0 for empty inputs, 1.0 for identical texts.
    """
    words_a = set(text_a.lower().split())
    words_b = set(text_b.lower().split())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)


def _apply_mmr(
    results: list[RerankResult],
    top_k: int,
    mmr_lambda: float = 0.7,
) -> list[RerankResult]:
    """Apply Maximal Marginal Relevance to diversify results.

    Greedy selection: pick the candidate that maximises
        mmr_lambda * relevance - (1 - mmr_lambda) * max_sim_to_selected

    Uses Jaccard word similarity — simple, fast, and directly
    measures the content overlap we're trying to reduce.

    Args:
        results: FlashRank-scored results, sorted by rerank_score desc.
        top_k: Number of results to return.
        mmr_lambda: Balance between relevance (1.0) and diversity (0.0).
                    Default 0.7 favours relevance but penalises near-dupes.

    Returns:
        Diversified list of up to top_k RerankResult objects.
    """
    if len(results) <= 1:
        return results[:top_k]

    # Normalise scores to [0, 1] for fair MMR balancing
    max_score = max(r.rerank_score for r in results)
    min_score = min(r.rerank_score for r in results)
    score_range = max_score - min_score
    if score_range == 0:
        # All scores identical — MMR degrades to pure diversity selection
        norm_scores = [1.0] * len(results)
    else:
        norm_scores = [
            (r.rerank_score - min_score) / score_range for r in results
        ]

    selected: list[int] = []
    remaining = list(range(len(results)))

    # First pick: always the highest-scoring candidate
    best_idx = max(remaining, key=lambda i: norm_scores[i])
    selected.append(best_idx)
    remaining.remove(best_idx)

    while len(selected) < top_k and remaining:
        best_mmr = -1.0
        best_candidate = remaining[0]

        for i in remaining:
            relevance = norm_scores[i]
            # Max similarity to any already-selected result
            max_sim = max(
                _jaccard_similarity(results[i].content, results[j].content)
                for j in selected
            )
            mmr_score = mmr_lambda * relevance - (1.0 - mmr_lambda) * max_sim
            if mmr_score > best_mmr:
                best_mmr = mmr_score
                best_candidate = i

        selected.append(best_candidate)
        remaining.remove(best_candidate)

    return [results[i] for i in selected]


# ── Reranker ────────────────────────────────────────────────────


class Reranker:
    """Cross-encoder re-ranker wrapping FlashRank.

    Graceful degradation: if flashrank is not installed or model loading
    fails, rerank() returns candidates unchanged (sorted by original score).
    """

    def __init__(self, cache_dir: str = "/tmp/flashrank") -> None:
        self._ranker = None
        if not _flashrank_available:
            logger.warning(
                "flashrank not installed — re-ranking disabled",
                extra={"event": "reranker_init", "available": False},
            )
            return
        try:
            # MiniLM-L-12: 12-layer cross-encoder (~33MB), significantly
            # better relevance than TinyBERT-L-2 (~4MB, 2 layers).
            # max_length=512 matches the model's full token capacity.
            # 128 truncated enriched records to identical prefixes,
            # producing uniform 0.999x scores (sigmoid saturation).
            self._ranker = _Ranker(
                model_name="ms-marco-MiniLM-L-12-v2",
                cache_dir=cache_dir,
                max_length=512,
            )
            logger.info(
                "FlashRank reranker loaded",
                extra={"event": "reranker_init", "available": True},
            )
        except Exception as exc:
            logger.warning(
                "FlashRank model load failed — re-ranking disabled",
                extra={"event": "reranker_init", "error": str(exc)},
            )

    @property
    def available(self) -> bool:
        """Whether the reranker is loaded and ready."""
        return self._ranker is not None

    def rerank(
        self,
        query: str,
        candidates: list,
        top_k: int = 5,
        mmr_lambda: float = 0.7,
    ) -> list[RerankResult]:
        """Re-rank candidates by cross-encoder relevance, then diversify via MMR.

        Args:
            query: The user's request text.
            candidates: List of SearchResult objects from hybrid_search.
            top_k: Number of top results to return after re-ranking.
            mmr_lambda: MMR diversity parameter (1.0 = pure relevance,
                        0.0 = pure diversity). Default 0.7.

        Returns:
            Top-k RerankResult objects, diversified by MMR.
            If reranker is unavailable, returns candidates converted to
            RerankResult sorted by original score, truncated to top_k.
        """
        if not candidates:
            return []

        if self._ranker is None:
            # Graceful fallback — return as-is, sorted by original score
            sorted_candidates = sorted(
                candidates, key=lambda c: c.score, reverse=True
            )
            return [
                RerankResult(
                    chunk_id=c.chunk_id,
                    content=c.content,
                    source=c.source,
                    original_score=c.score,
                    rerank_score=c.score,
                    match_type=c.match_type,
                )
                for c in sorted_candidates[:top_k]
            ]

        # Build passages for FlashRank — each needs "id" and "text" keys
        passages = [
            {"id": i, "text": c.content, "meta": {"chunk_id": c.chunk_id}}
            for i, c in enumerate(candidates)
        ]

        # Map id → original candidate for field preservation
        id_to_candidate = {i: c for i, c in enumerate(candidates)}

        try:
            request = _RerankRequest(query=query, passages=passages)
            reranked = self._ranker.rerank(request)
        except Exception as exc:
            logger.warning(
                "FlashRank rerank failed — returning original order",
                extra={"event": "rerank_error", "error": str(exc)},
            )
            sorted_candidates = sorted(
                candidates, key=lambda c: c.score, reverse=True
            )
            return [
                RerankResult(
                    chunk_id=c.chunk_id,
                    content=c.content,
                    source=c.source,
                    original_score=c.score,
                    rerank_score=c.score,
                    match_type=c.match_type,
                )
                for c in sorted_candidates[:top_k]
            ]

        # Build all scored results (over-retrieve for MMR selection pool)
        scored_results = []
        for item in reranked:
            idx = item["id"]
            original = id_to_candidate[idx]
            scored_results.append(
                RerankResult(
                    chunk_id=original.chunk_id,
                    content=original.content,
                    source=original.source,
                    original_score=original.score,
                    rerank_score=float(item.get("score", 0.0)),
                    match_type=original.match_type,
                )
            )

        # Apply MMR to diversify the final selection
        results = _apply_mmr(scored_results, top_k=top_k, mmr_lambda=mmr_lambda)

        # Score distribution — the key diagnostic for the max_length fix.
        # Pre-fix: all scores were 0.999x (uniform). Post-fix: expect spread.
        all_scores = [r.rerank_score for r in scored_results]
        selected_scores = [r.rerank_score for r in results]
        logger.debug(
            "Re-ranking completed (with MMR)",
            extra={
                "event": "rerank_complete",
                "candidates_in": len(candidates),
                "scored": len(scored_results),
                "results_out": len(results),
                "mmr_lambda": mmr_lambda,
                "top_score": selected_scores[0] if selected_scores else 0.0,
                "min_score": min(all_scores) if all_scores else 0.0,
                "score_spread": round(max(all_scores) - min(all_scores), 4) if all_scores else 0.0,
                "selected_scores": [round(s, 4) for s in selected_scores],
                "mmr_reordered": [r.chunk_id[-8:] for r in results],
            },
        )
        return results
