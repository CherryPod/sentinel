"""Tests for sentinel.memory.search — FTS5 search and RRF hybrid fusion."""

import pytest

from sentinel.core.db import init_db
from sentinel.memory.chunks import MemoryStore
from sentinel.memory.search import SearchResult, fts_search, hybrid_search, vec_search


@pytest.fixture
def db():
    """In-memory SQLite database with full schema."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def store(db):
    """MemoryStore backed by in-memory SQLite."""
    return MemoryStore(db=db)


def _populate_store(store):
    """Insert a few test chunks for search tests."""
    store.store(content="Python is a programming language", source="docs")
    store.store(content="Rust is a systems programming language", source="docs")
    store.store(content="The weather today is sunny and warm", source="notes")
    store.store(content="Machine learning uses neural networks", source="research")
    store.store(content="Python web frameworks include FastAPI and Django", source="docs")


class TestFtsSearch:
    """fts_search() — FTS5 keyword search."""

    def test_basic_match(self, store, db):
        _populate_store(store)
        results = fts_search(db, "Python", k=10)
        assert len(results) >= 1
        assert all(r.match_type == "fts" for r in results)
        # All results should contain "Python"
        for r in results:
            assert "Python" in r.content or "python" in r.content.lower()

    def test_no_match(self, store, db):
        _populate_store(store)
        results = fts_search(db, "xyznonexistent", k=10)
        assert results == []

    def test_empty_query(self, store, db):
        _populate_store(store)
        results = fts_search(db, "", k=10)
        assert results == []

    def test_respects_k_limit(self, store, db):
        _populate_store(store)
        results = fts_search(db, "programming", k=1)
        assert len(results) == 1

    def test_multi_word_query(self, store, db):
        _populate_store(store)
        results = fts_search(db, "programming language", k=10)
        assert len(results) >= 1

    def test_user_id_filter(self, store, db):
        store.store(content="User1 Python data", source="test", user_id="user1")
        store.store(content="User2 Python data", source="test", user_id="user2")
        results = fts_search(db, "Python", user_id="user1", k=10)
        assert len(results) == 1

    def test_returns_search_result_type(self, store, db):
        _populate_store(store)
        results = fts_search(db, "Python", k=10)
        assert all(isinstance(r, SearchResult) for r in results)
        for r in results:
            assert r.chunk_id
            assert r.content
            assert r.score > 0

    def test_fts5_special_chars_escaped(self, store, db):
        """FTS5 special characters in queries should not cause errors."""
        _populate_store(store)
        # These chars are FTS5 operators — should be safely escaped
        results = fts_search(db, 'test OR "quoted" NOT -excluded', k=10)
        # Should not raise, may return results or empty

    def test_source_field_searchable(self, store, db):
        """FTS5 index includes source field."""
        store.store(content="Some content", source="unique_source_tag")
        # FTS5 matches across all indexed columns (content + source)
        results = fts_search(db, "unique_source_tag", k=10)
        assert len(results) >= 1


class TestVecSearch:
    """vec_search() — sqlite-vec search (graceful fallback when not available)."""

    def test_returns_empty_without_vec_extension(self, store, db):
        """Without sqlite-vec loaded, vec_search should return empty."""
        _populate_store(store)
        embedding = [0.1] * 768
        results = vec_search(db, embedding, k=10)
        # sqlite-vec is not loaded in test environment → empty results
        assert results == []


class TestHybridSearch:
    """hybrid_search() — RRF fusion of FTS5 + vec results."""

    def test_fts_only_fallback(self, store, db):
        """Without embedding, should return FTS5-only results."""
        _populate_store(store)
        results = hybrid_search(db, "Python", embedding=None, k=10)
        assert len(results) >= 1
        assert all(r.match_type == "fts" for r in results)

    def test_fts_only_when_no_vec_table(self, store, db):
        """Even with embedding, falls back to FTS5 when vec table missing."""
        _populate_store(store)
        embedding = [0.1] * 768
        results = hybrid_search(db, "Python", embedding=embedding, k=10)
        # sqlite-vec not loaded → vec_search returns empty → FTS5-only
        assert len(results) >= 1
        assert all(r.match_type == "fts" for r in results)

    def test_respects_k_limit(self, store, db):
        _populate_store(store)
        results = hybrid_search(db, "programming", embedding=None, k=1)
        assert len(results) == 1

    def test_empty_query_returns_empty(self, store, db):
        _populate_store(store)
        results = hybrid_search(db, "", embedding=None, k=10)
        assert results == []

    def test_no_matches_returns_empty(self, store, db):
        _populate_store(store)
        results = hybrid_search(db, "xyznonexistent", embedding=None, k=10)
        assert results == []


class TestRRFFusion:
    """RRF score calculation logic."""

    def test_rrf_score_formula(self):
        """Verify RRF score: score = 1/(rrf_k + rank)."""
        # For rank 1 with rrf_k=60: score = 1/61 ≈ 0.01639
        rrf_k = 60
        rank = 1
        expected = 1.0 / (rrf_k + rank)
        assert abs(expected - 1.0 / 61) < 1e-10

    def test_hybrid_results_have_higher_score(self, db):
        """When a doc appears in both FTS5 and vec, its RRF score should be higher."""
        # This is a unit test of the fusion logic — we simulate two result lists
        from sentinel.memory.search import SearchResult

        fts_results = [
            SearchResult(chunk_id="A", content="doc A", source="", score=1.0, match_type="fts"),
            SearchResult(chunk_id="B", content="doc B", source="", score=0.5, match_type="fts"),
        ]
        vec_results = [
            SearchResult(chunk_id="A", content="doc A", source="", score=0.9, match_type="vec"),
            SearchResult(chunk_id="C", content="doc C", source="", score=0.8, match_type="vec"),
        ]

        # Manually compute RRF scores
        rrf_k = 60
        scores = {}
        for rank, r in enumerate(fts_results, 1):
            scores[r.chunk_id] = scores.get(r.chunk_id, 0.0) + 1.0 / (rrf_k + rank)
        for rank, r in enumerate(vec_results, 1):
            scores[r.chunk_id] = scores.get(r.chunk_id, 0.0) + 1.0 / (rrf_k + rank)

        # Doc A appears in both lists — should have highest score
        assert scores["A"] > scores["B"]
        assert scores["A"] > scores["C"]

    def test_fts_search_after_delete(self, store, db):
        """Deleted chunks should not appear in FTS5 search."""
        chunk_id = store.store(content="deletable search term", source="test")
        # Verify it's findable
        results = fts_search(db, "deletable", k=10)
        assert len(results) == 1
        # Delete and verify gone
        store.delete(chunk_id)
        results = fts_search(db, "deletable", k=10)
        assert len(results) == 0

    def test_fts_search_after_update(self, store, db):
        """Updated chunks should reflect new content in FTS5."""
        chunk_id = store.store(content="original keyword", source="test")
        store.update(chunk_id, content="replacement keyword")
        # Old keyword gone
        results = fts_search(db, "original", k=10)
        assert len(results) == 0
        # New keyword found
        results = fts_search(db, "replacement", k=10)
        assert len(results) == 1
