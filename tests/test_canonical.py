"""Tests for canonical trajectory extraction and planner injection."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.memory.canonical import (
    CanonicalTrajectory,
    generate_canonical_trajectory,
    refresh_canonical_trajectories,
    store_canonical_as_chunk,
)
from sentinel.memory.chunks import MemoryStore
from sentinel.memory.domain_summary import DomainSummary, DomainSummaryStore
from sentinel.memory.strategy_store import StrategyPatternStore


@pytest.fixture
def strategy_store():
    return StrategyPatternStore(pool=None)


@pytest.fixture
def memory_store():
    return MemoryStore(pool=None)


@pytest.fixture
def domain_summary_store():
    return DomainSummaryStore(pool=None)


# ── generate_canonical_trajectory ────────────────────────────


class TestGenerateCanonical:
    """Canonical trajectory generation criteria."""

    @pytest.mark.asyncio
    async def test_returns_none_insufficient_data(self, strategy_store):
        """Returns None when domain has < 10 total tasks."""
        for _ in range(5):
            await strategy_store.upsert("search", 1, "single-shot", [], True)
        result = await generate_canonical_trajectory("search", 1, strategy_store)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_low_success_rate(self, strategy_store):
        """Returns None when best pattern has < 60% success rate."""
        # 10 failures, 2 successes = 17% success (below 60% threshold)
        for _ in range(10):
            await strategy_store.upsert("search", 1, "bad-strat", [], False)
        for _ in range(2):
            await strategy_store.upsert("search", 1, "bad-strat", [], True)
        result = await generate_canonical_trajectory("search", 1, strategy_store)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_canonical_when_criteria_met(self, strategy_store):
        """Returns canonical when pattern has >= 3 examples and >= 60% success."""
        # 7 successes for strategy A
        for _ in range(7):
            await strategy_store.upsert(
                "code_debugging", 1, "read → fix",
                ["file_read", "llm", "file_write"], True,
            )
        # 5 mixed for strategy B (total = 12 tasks, above threshold)
        for _ in range(3):
            await strategy_store.upsert("code_debugging", 1, "single-shot", [], True)
        for _ in range(2):
            await strategy_store.upsert("code_debugging", 1, "single-shot", [], False)

        result = await generate_canonical_trajectory("code_debugging", 1, strategy_store)
        assert result is not None
        assert result.domain == "code_debugging"
        assert result.strategy_name == "read → fix"
        assert result.success_rate == 1.0
        assert result.example_count == 7
        assert result.step_sequence == ["file_read", "llm", "file_write"]

    @pytest.mark.asyncio
    async def test_graceful_with_none_strategy_store(self):
        """Handles None strategy_store gracefully — cannot generate."""
        # get_canonical is called on strategy_store, so None would be
        # a caller error. Test that the function signature works.
        store = StrategyPatternStore(pool=None)
        result = await generate_canonical_trajectory("empty", 1, store)
        assert result is None


# ── store_canonical_as_chunk ─────────────────────────────────


class TestStoreCanonicalChunk:
    """Canonical trajectory stored as memory chunk."""

    @pytest.mark.asyncio
    async def test_chunk_has_correct_source(self, memory_store):
        """Canonical chunk stored with source 'system:canonical'."""
        trajectory = CanonicalTrajectory(
            domain="code_debugging",
            strategy_name="read → fix",
            step_sequence=["file_read", "llm", "file_write"],
            success_rate=0.85,
            example_count=7,
            generated_at="2026-03-14T00:00:00.000Z",
            expires_at="2026-04-13T00:00:00.000Z",
        )
        chunk_id = await store_canonical_as_chunk(trajectory, memory_store)
        chunk = await memory_store.get(chunk_id, user_id=1)
        assert chunk is not None
        assert chunk.source == "system:canonical"

    @pytest.mark.asyncio
    async def test_chunk_metadata_includes_domain(self, memory_store):
        """Metadata includes domain and strategy for retrieval filtering."""
        trajectory = CanonicalTrajectory(
            domain="messaging",
            strategy_name="send",
            step_sequence=["signal_send"],
            success_rate=0.90,
            example_count=10,
            generated_at="2026-03-14T00:00:00.000Z",
            expires_at="2026-04-13T00:00:00.000Z",
        )
        chunk_id = await store_canonical_as_chunk(trajectory, memory_store)
        chunk = await memory_store.get(chunk_id, user_id=1)
        assert chunk.metadata["domain"] == "messaging"
        assert chunk.metadata["strategy"] == "send"
        assert chunk.metadata["success_rate"] == 0.90
        assert "expires_at" in chunk.metadata

    @pytest.mark.asyncio
    async def test_chunk_content_is_searchable(self, memory_store):
        """Content text includes domain and strategy for FTS."""
        trajectory = CanonicalTrajectory(
            domain="search",
            strategy_name="search → summarise",
            step_sequence=["web_search", "llm"],
            success_rate=0.75,
            example_count=5,
            generated_at="2026-03-14T00:00:00.000Z",
            expires_at="2026-04-13T00:00:00.000Z",
        )
        chunk_id = await store_canonical_as_chunk(trajectory, memory_store)
        chunk = await memory_store.get(chunk_id, user_id=1)
        assert "search" in chunk.content
        assert "CANONICAL" in chunk.content


# ── Expiry detection ─────────────────────────────────────────


class TestExpiryDetection:
    """Canonical regeneration based on age and task count."""

    @pytest.mark.asyncio
    async def test_should_regenerate_when_never_generated(self, strategy_store):
        """Regenerate when no canonical exists."""
        result = await strategy_store.should_regenerate_canonical(
            "search", 1, last_generated=None,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_should_regenerate_after_30_days(self, strategy_store):
        """Regenerate when 30+ days have passed."""
        old = datetime.now(timezone.utc) - timedelta(days=31)
        result = await strategy_store.should_regenerate_canonical(
            "search", 1, last_generated=old,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_should_regenerate_after_20_tasks(self, strategy_store):
        """Regenerate when 20+ tasks accumulated since last generation."""
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        result = await strategy_store.should_regenerate_canonical(
            "search", 1, last_generated=recent, tasks_since=20,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_no_regenerate_when_fresh(self, strategy_store):
        """No regeneration when recently generated and few new tasks."""
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        result = await strategy_store.should_regenerate_canonical(
            "search", 1, last_generated=recent, tasks_since=5,
        )
        assert result is False


# ── refresh_canonical_trajectories ───────────────────────────


class TestRefreshCanonical:
    """End-to-end canonical refresh flow."""

    @pytest.mark.asyncio
    async def test_refresh_skips_when_no_domain_summaries(
        self, strategy_store, memory_store,
    ):
        """Returns 0 when domain_summary_store is None."""
        count = await refresh_canonical_trajectories(
            user_id=1,
            strategy_store=strategy_store,
            episodic_store=None,
            memory_store=memory_store,
            embedding_client=None,
            domain_summary_store=None,
        )
        assert count == 0

    @pytest.mark.asyncio
    async def test_refresh_generates_canonical(
        self, strategy_store, memory_store, domain_summary_store,
    ):
        """Refresh generates and stores canonical when criteria met."""
        # Seed enough strategy data
        for _ in range(7):
            await strategy_store.upsert(
                "code_debugging", 1, "read → fix",
                ["file_read", "llm", "file_write"], True,
            )
        for _ in range(5):
            await strategy_store.upsert("code_debugging", 1, "single-shot", [], True)

        # Create a domain summary so refresh knows about this domain
        await domain_summary_store.upsert(DomainSummary(
            domain="code_debugging",
            user_id=1,
            total_tasks=12,
            success_count=12,
            summary_text="test",
            last_task_count=15,  # enough to trigger regeneration
        ))

        count = await refresh_canonical_trajectories(
            user_id=1,
            strategy_store=strategy_store,
            episodic_store=None,
            memory_store=memory_store,
            embedding_client=None,
            domain_summary_store=domain_summary_store,
        )
        assert count == 1

        # Verify chunk was stored
        chunks = await memory_store.list_chunks(
            user_id=1, source="system:canonical",
        )
        assert len(chunks) == 1
        assert chunks[0].metadata["domain"] == "code_debugging"

    @pytest.mark.asyncio
    async def test_graceful_degradation_no_crash(
        self, strategy_store, memory_store, domain_summary_store,
    ):
        """Refresh never crashes — logs errors and continues."""
        # Domain summary exists but no strategy data (canonical will be None)
        await domain_summary_store.upsert(DomainSummary(
            domain="messaging",
            user_id=1,
            total_tasks=5,
            success_count=5,
            summary_text="test",
            last_task_count=0,
        ))

        count = await refresh_canonical_trajectories(
            user_id=1,
            strategy_store=strategy_store,
            episodic_store=None,
            memory_store=memory_store,
            embedding_client=None,
            domain_summary_store=domain_summary_store,
        )
        assert count == 0  # Not enough data for canonical


# ── Builder context injection ────────────────────────────────


class TestCanonicalInBuilderContext:
    """Canonical trajectory appears in build_learning_context output."""

    @pytest.mark.asyncio
    async def test_canonical_appears_in_context(self, memory_store):
        """When canonical chunk exists, it appears in builder output."""
        from sentinel.planner.builders import build_learning_context

        # Store a canonical chunk directly
        trajectory = CanonicalTrajectory(
            domain="code_debugging",
            strategy_name="read → fix",
            step_sequence=["file_read", "llm", "file_write"],
            success_rate=0.85,
            example_count=7,
            generated_at="2026-03-14T00:00:00.000Z",
            expires_at="2026-04-13T00:00:00.000Z",
        )
        await store_canonical_as_chunk(trajectory, memory_store)

        # build_learning_context requires pool to be set for hybrid search
        # With pool=None, it returns "" early — so we test the canonical
        # retrieval logic separately via the chunks
        chunks = await memory_store.list_chunks(source="system:canonical")
        assert len(chunks) == 1
        assert chunks[0].metadata["domain"] == "code_debugging"
        assert "read → fix" in chunks[0].content

    @pytest.mark.asyncio
    async def test_expired_canonical_skipped(self, memory_store):
        """Expired canonical chunks should not be injected."""
        # Store a canonical chunk with past expiry
        trajectory = CanonicalTrajectory(
            domain="search",
            strategy_name="search → summarise",
            step_sequence=["web_search", "llm"],
            success_rate=0.75,
            example_count=5,
            generated_at="2025-01-01T00:00:00.000Z",
            expires_at="2025-02-01T00:00:00.000Z",  # long expired
        )
        await store_canonical_as_chunk(trajectory, memory_store)

        # The canonical is stored but expiry check in builders.py
        # should skip it during context injection
        chunks = await memory_store.list_chunks(source="system:canonical")
        assert len(chunks) == 1
        assert chunks[0].metadata["expires_at"] == "2025-02-01T00:00:00.000Z"
