"""Tests for Step 2.1: Domain summary store.

Verifies CRUD operations on DomainSummaryStore using the in-memory fallback.
"""

import pytest

from sentinel.memory.domain_summary import DomainSummary, DomainSummaryStore


@pytest.mark.asyncio
async def test_upsert_and_get():
    """Upsert a summary and retrieve it."""
    store = DomainSummaryStore(pool=None)
    summary = DomainSummary(
        domain="code_debugging",
        user_id=1,
        total_tasks=47,
        success_count=34,
        summary_text="code_debugging: 47 tasks, 34/47 (72%) success.",
        patterns_json=[{"strategy": "read→fix", "count": 23, "success_rate": 0.82}],
    )
    await store.upsert(summary)

    result = await store.get("code_debugging", user_id=1)
    assert result is not None
    assert result.domain == "code_debugging"
    assert result.total_tasks == 47
    assert result.success_count == 34
    assert len(result.patterns_json) == 1


@pytest.mark.asyncio
async def test_get_nonexistent():
    """Get returns None for missing domain."""
    store = DomainSummaryStore(pool=None)
    result = await store.get("nonexistent", user_id=1)
    assert result is None


@pytest.mark.asyncio
async def test_upsert_overwrites():
    """Second upsert updates the existing record."""
    store = DomainSummaryStore(pool=None)

    await store.upsert(DomainSummary(domain="search", user_id=1, total_tasks=10))
    await store.upsert(DomainSummary(domain="search", user_id=1, total_tasks=20))

    result = await store.get("search", user_id=1)
    assert result is not None
    assert result.total_tasks == 20


@pytest.mark.asyncio
async def test_list_all():
    """List returns all summaries for a user."""
    store = DomainSummaryStore(pool=None)
    await store.upsert(DomainSummary(domain="messaging", user_id=1, total_tasks=5))
    await store.upsert(DomainSummary(domain="calendar", user_id=1, total_tasks=3))

    results = await store.list_all(user_id=1)
    assert len(results) == 2
    domains = {r.domain for r in results}
    assert domains == {"messaging", "calendar"}


@pytest.mark.asyncio
async def test_user_isolation():
    """Summaries for different users are isolated."""
    store = DomainSummaryStore(pool=None)
    await store.upsert(DomainSummary(domain="search", user_id=1, total_tasks=10))
    await store.upsert(DomainSummary(domain="search", user_id=2, total_tasks=20))

    r1 = await store.get("search", user_id=1)
    r2 = await store.get("search", user_id=2)
    assert r1 is not None and r1.total_tasks == 10
    assert r2 is not None and r2.total_tasks == 20

    list1 = await store.list_all(user_id=1)
    assert len(list1) == 1


@pytest.mark.asyncio
async def test_delete():
    """Delete removes the summary and returns True."""
    store = DomainSummaryStore(pool=None)
    await store.upsert(DomainSummary(domain="system", user_id=1, total_tasks=5))

    deleted = await store.delete("system", user_id=1)
    assert deleted is True

    result = await store.get("system", user_id=1)
    assert result is None


@pytest.mark.asyncio
async def test_delete_nonexistent():
    """Delete returns False for missing domain."""
    store = DomainSummaryStore(pool=None)
    deleted = await store.delete("nonexistent", user_id=1)
    assert deleted is False


@pytest.mark.asyncio
async def test_increment_task_count():
    """increment_task_count increments and returns new count."""
    store = DomainSummaryStore(pool=None)
    await store.upsert(DomainSummary(domain="code_debugging", user_id=1, last_task_count=5))

    new_count = await store.increment_task_count("code_debugging", user_id=1)
    assert new_count == 6

    new_count = await store.increment_task_count("code_debugging", user_id=1)
    assert new_count == 7


@pytest.mark.asyncio
async def test_increment_nonexistent_returns_zero():
    """increment_task_count returns 0 for missing domain."""
    store = DomainSummaryStore(pool=None)
    result = await store.increment_task_count("nonexistent", user_id=1)
    assert result == 0
