"""Tests for strategy pattern store — in-memory fallback path."""

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.memory.strategy_store import StrategyPatternStore


@pytest.fixture
def store():
    """In-memory strategy store for tests."""
    return StrategyPatternStore(pool=None)


# ── Upsert ──────────────────────────────────────────────────────


class TestUpsert:
    """Strategy pattern creation and increment."""

    @pytest.mark.asyncio
    async def test_upsert_creates_new_pattern(self, store):
        """First upsert creates a new pattern with count=1."""
        await store.upsert(
            domain="code_debugging",
            user_id=1,
            strategy_name="read → write",
            step_sequence=["file_read", "file_write"],
            success=True,
        )
        result = await store.get_by_pattern("code_debugging", 1, "read → write")
        assert result is not None
        assert result.occurrence_count == 1
        assert result.success_count == 1
        assert result.step_sequence == ["file_read", "file_write"]

    @pytest.mark.asyncio
    async def test_upsert_increments_existing(self, store):
        """Subsequent upserts increment counts."""
        await store.upsert(
            domain="messaging", user_id=1, strategy_name="send",
            success=True,
        )
        await store.upsert(
            domain="messaging", user_id=1, strategy_name="send",
            success=False,
        )
        await store.upsert(
            domain="messaging", user_id=1, strategy_name="send",
            success=True,
        )
        result = await store.get_by_pattern("messaging", 1, "send")
        assert result is not None
        assert result.occurrence_count == 3
        assert result.success_count == 2

    @pytest.mark.asyncio
    async def test_upsert_tracks_duration(self, store):
        """Duration averaging works across upserts."""
        await store.upsert(
            domain="search", user_id=1, strategy_name="search",
            success=True, duration_s=10.0,
        )
        await store.upsert(
            domain="search", user_id=1, strategy_name="search",
            success=True, duration_s=20.0,
        )
        result = await store.get_by_pattern("search", 1, "search")
        assert result is not None
        assert result.avg_duration_s == pytest.approx(15.0)


# ── Retrieval ───────────────────────────────────────────────────


class TestRetrieval:
    """Querying strategy patterns."""

    @pytest.mark.asyncio
    async def test_get_top_strategies_ordered_by_success_rate(self, store):
        """Top strategies sorted by success rate descending."""
        # High success rate but fewer occurrences
        for _ in range(3):
            await store.upsert("code_debugging", 1, "read → fix", success=True)
        # Low success rate but more occurrences
        for _ in range(5):
            await store.upsert("code_debugging", 1, "single-shot", success=False)
        await store.upsert("code_debugging", 1, "single-shot", success=True)

        top = await store.get_top_strategies("code_debugging", 1)
        assert len(top) == 2
        assert top[0].strategy_name == "read → fix"  # 100% success
        assert top[1].strategy_name == "single-shot"  # ~17% success

    @pytest.mark.asyncio
    async def test_list_all(self, store):
        """List all patterns for a user across domains."""
        await store.upsert("messaging", 1, "send", success=True)
        await store.upsert("search", 1, "search", success=True)
        all_patterns = await store.list_all(1)
        assert len(all_patterns) == 2

    @pytest.mark.asyncio
    async def test_get_domain_total(self, store):
        """Domain total sums occurrence counts across strategies."""
        await store.upsert("code_debugging", 1, "read → fix", success=True)
        await store.upsert("code_debugging", 1, "read → fix", success=True)
        await store.upsert("code_debugging", 1, "single-shot", success=False)
        total = await store.get_domain_total("code_debugging", 1)
        assert total == 3


# ── User isolation ──────────────────────────────────────────────


class TestUserIsolation:
    """Different users cannot see each other's patterns."""

    @pytest.mark.asyncio
    async def test_patterns_isolated_by_user(self, store):
        """User 1 patterns are invisible to user 2."""
        await store.upsert("messaging", 1, "send", success=True)
        await store.upsert("messaging", 2, "receive", success=True)
        user1 = await store.list_all(1)
        user2 = await store.list_all(2)
        assert len(user1) == 1
        assert user1[0].strategy_name == "send"
        assert len(user2) == 1
        assert user2[0].strategy_name == "receive"


# ── Canonical extraction ────────────────────────────────────────


class TestCanonical:
    """Canonical strategy selection criteria."""

    @pytest.mark.asyncio
    async def test_canonical_returns_none_insufficient_data(self, store):
        """No canonical when domain has <10 total tasks."""
        for _ in range(5):
            await store.upsert("search", 1, "search", success=True)
        result = await store.get_canonical("search", 1)
        assert result is None

    @pytest.mark.asyncio
    async def test_canonical_returns_best_strategy(self, store):
        """Returns highest success-rate pattern with >=3 examples."""
        # 7 successes for read → fix
        for _ in range(7):
            await store.upsert("code_debugging", 1, "read → fix", success=True)
        # 5 failures for single-shot (3 success, 5 total = but low rate won't matter)
        for _ in range(3):
            await store.upsert("code_debugging", 1, "single-shot", success=True)
        for _ in range(2):
            await store.upsert("code_debugging", 1, "single-shot", success=False)
        # Total: 12 tasks, above threshold
        result = await store.get_canonical("code_debugging", 1)
        assert result is not None
        assert result.strategy_name == "read → fix"
        assert result.success_rate == 1.0

    @pytest.mark.asyncio
    async def test_canonical_requires_min_examples(self, store):
        """Strategy with <3 examples excluded even if success rate is high."""
        # 2 perfect successes (below 3 threshold)
        for _ in range(2):
            await store.upsert("search", 1, "perfect", success=True)
        # 10 mediocre successes (above threshold, but low rate)
        for _ in range(10):
            await store.upsert("search", 1, "mediocre", success=False)
        result = await store.get_canonical("search", 1)
        # mediocre has 0% success rate, perfect has <3 examples
        assert result is None


# ── Regeneration check ─────────────────────────────────────────


class TestShouldRegenerateCanonical:
    """Canonical trajectory regeneration criteria."""

    @pytest.mark.asyncio
    async def test_regenerate_when_never_generated(self, store):
        """Should regenerate when last_generated is None."""
        result = await store.should_regenerate_canonical(
            "search", user_id=1, last_generated=None, tasks_since=0,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_regenerate_after_30_days(self, store):
        """Should regenerate when 30+ days have passed."""
        old = datetime.now(timezone.utc) - timedelta(days=31)
        result = await store.should_regenerate_canonical(
            "search", user_id=1, last_generated=old, tasks_since=0,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_regenerate_after_20_tasks(self, store):
        """Should regenerate when 20+ new tasks since last generation."""
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        result = await store.should_regenerate_canonical(
            "search", user_id=1, last_generated=recent, tasks_since=20,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_no_regenerate_when_fresh(self, store):
        """Should NOT regenerate when recent and few new tasks."""
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        result = await store.should_regenerate_canonical(
            "search", user_id=1, last_generated=recent, tasks_since=5,
        )
        assert result is False
