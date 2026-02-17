"""Tests for MMR diversity enforcement in the reranker.

Verifies that _apply_mmr and _jaccard_similarity produce diverse
result sets and handle edge cases correctly.
"""

from sentinel.memory.reranker import (
    RerankResult,
    _apply_mmr,
    _jaccard_similarity,
)


# ── Jaccard similarity ───────────────────────────────────────────


class TestJaccardSimilarity:
    """Word-level Jaccard similarity helper."""

    def test_identical_texts(self):
        assert _jaccard_similarity("hello world", "hello world") == 1.0

    def test_completely_different(self):
        assert _jaccard_similarity("hello world", "foo bar") == 0.0

    def test_partial_overlap(self):
        # {"hello", "world"} & {"hello", "foo"} = {"hello"}
        # union = {"hello", "world", "foo"} → 1/3
        result = _jaccard_similarity("hello world", "hello foo")
        assert abs(result - 1 / 3) < 0.01

    def test_case_insensitive(self):
        assert _jaccard_similarity("Hello World", "hello world") == 1.0

    def test_empty_string(self):
        assert _jaccard_similarity("", "hello") == 0.0
        assert _jaccard_similarity("hello", "") == 0.0
        assert _jaccard_similarity("", "") == 0.0


# ── MMR selection ────────────────────────────────────────────────


def _make_result(chunk_id: str, content: str, score: float) -> RerankResult:
    return RerankResult(
        chunk_id=chunk_id,
        content=content,
        source="system:episodic",
        original_score=score,
        rerank_score=score,
        match_type="hybrid",
    )


class TestApplyMMR:
    """MMR greedy selection produces diverse top-k."""

    def test_diverse_inputs_preserved(self):
        """Diverse results stay in order when content doesn't overlap."""
        results = [
            _make_result("c1", "fix the authentication bug in login", 0.95),
            _make_result("c2", "deploy new database migration", 0.90),
            _make_result("c3", "update frontend routing config", 0.85),
        ]
        selected = _apply_mmr(results, top_k=3)
        assert len(selected) == 3
        # First pick is always highest score
        assert selected[0].chunk_id == "c1"

    def test_near_duplicates_filtered(self):
        """Near-duplicate content gets deprioritised in favour of diversity.

        When scores are close, MMR should prefer a diverse result over
        a near-duplicate of an already-selected result.
        """
        results = [
            _make_result("c1", "fix the bug in the login authentication module", 0.95),
            _make_result("c2", "fix the bug in the login authentication system", 0.93),
            _make_result("c3", "fix the bug in the login authentication handler", 0.91),
            _make_result("c4", "deploy database migration for user table", 0.89),
            _make_result("c5", "update frontend CSS styling for dashboard", 0.87),
        ]
        selected = _apply_mmr(results, top_k=3)
        assert len(selected) == 3
        # First pick: highest scorer
        assert selected[0].chunk_id == "c1"
        # With close scores and high overlap between c1/c2/c3 (Jaccard ~0.75),
        # the diverse c4/c5 should be preferred over near-duplicate c2/c3
        selected_ids = {r.chunk_id for r in selected}
        assert selected_ids & {"c4", "c5"}, (
            f"Expected diverse content but got {selected_ids}"
        )

    def test_lambda_1_preserves_relevance_order(self):
        """lambda=1.0 disables diversity penalty → pure relevance order."""
        results = [
            _make_result("c1", "fix the bug in login auth", 0.95),
            _make_result("c2", "fix the bug in login auth system", 0.94),
            _make_result("c3", "deploy database migration", 0.80),
        ]
        selected = _apply_mmr(results, top_k=3, mmr_lambda=1.0)
        assert [r.chunk_id for r in selected] == ["c1", "c2", "c3"]

    def test_lambda_0_maximises_diversity(self):
        """lambda=0.0 picks purely for diversity (most different from selected)."""
        results = [
            _make_result("c1", "fix the bug in the login module", 0.95),
            _make_result("c2", "fix the bug in the login handler", 0.94),
            _make_result("c3", "deploy database migration scripts", 0.50),
        ]
        selected = _apply_mmr(results, top_k=2, mmr_lambda=0.0)
        # First pick is still the highest scorer
        assert selected[0].chunk_id == "c1"
        # Second pick: c3 is most different from c1 despite lowest score
        assert selected[1].chunk_id == "c3"

    def test_single_result(self):
        """Single result returned as-is."""
        results = [_make_result("c1", "only one", 0.9)]
        selected = _apply_mmr(results, top_k=5)
        assert len(selected) == 1
        assert selected[0].chunk_id == "c1"

    def test_empty_results(self):
        """Empty input returns empty output."""
        assert _apply_mmr([], top_k=5) == []

    def test_top_k_smaller_than_input(self):
        """Only top_k results returned even with more candidates."""
        results = [
            _make_result(f"c{i}", f"unique content number {i}", 0.9 - i * 0.1)
            for i in range(10)
        ]
        selected = _apply_mmr(results, top_k=3)
        assert len(selected) == 3

    def test_identical_scores_uses_diversity(self):
        """When all scores are identical, MMR selects for maximum diversity."""
        results = [
            _make_result("c1", "fix the login authentication bug", 0.90),
            _make_result("c2", "fix the login authentication error", 0.90),
            _make_result("c3", "deploy new database migration", 0.90),
            _make_result("c4", "update frontend dashboard styling", 0.90),
        ]
        selected = _apply_mmr(results, top_k=3, mmr_lambda=0.5)
        selected_ids = {r.chunk_id for r in selected}
        # With identical scores, MMR should pick diverse content
        # c3 and c4 are most different from c1/c2
        assert selected_ids & {"c3", "c4"}, (
            f"Expected diverse content with identical scores but got {selected_ids}"
        )
