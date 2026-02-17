"""Tests for Step 1.2: Task domain classification.

Verifies classify_task_domain() correctly maps tool usage patterns
to domain categories, and that domain is stored on episodic records.
"""

import pytest

from sentinel.memory.episodic import (
    TASK_DOMAINS,
    TOOL_TO_DOMAIN,
    classify_task_domain,
)


def test_single_tool_domain():
    """A plan with one tool_call should return that tool's domain."""
    outcomes = [
        {"step_type": "tool_call", "tool": "signal_send", "status": "success"},
    ]
    assert classify_task_domain(outcomes) == "messaging"


def test_dominant_domain():
    """When one domain accounts for >50%, it wins."""
    outcomes = [
        {"step_type": "tool_call", "tool": "file_write", "status": "success"},
        {"step_type": "tool_call", "tool": "shell", "status": "success"},
        {"step_type": "tool_call", "tool": "shell_exec", "status": "success"},
    ]
    # file_write → code_generation, shell → code_generation, shell_exec → code_generation
    # code_generation: 3/3 = 100% → dominant
    assert classify_task_domain(outcomes) == "code_generation"


def test_composite_fallback():
    """When no domain exceeds 50%, return 'composite'."""
    outcomes = [
        {"step_type": "tool_call", "tool": "web_search", "status": "success"},
        {"step_type": "tool_call", "tool": "signal_send", "status": "success"},
        {"step_type": "tool_call", "tool": "calendar_create_event", "status": "success"},
        {"step_type": "tool_call", "tool": "file_write", "status": "success"},
    ]
    # 4 different domains, each 25%
    assert classify_task_domain(outcomes) == "composite"


def test_debug_pattern_detection():
    """file_read + llm_task + file_write = code_debugging."""
    outcomes = [
        {"step_type": "tool_call", "tool": "file_read", "status": "success"},
        {"step_type": "llm_task", "status": "success"},
        {"step_type": "tool_call", "tool": "file_write", "status": "success"},
    ]
    assert classify_task_domain(outcomes) == "code_debugging"


def test_empty_outcomes():
    """Empty step_outcomes → None."""
    assert classify_task_domain([]) is None


def test_pure_llm_task():
    """Plans with only llm_task steps → None (no tools to classify)."""
    outcomes = [
        {"step_type": "llm_task", "status": "success"},
    ]
    assert classify_task_domain(outcomes) is None


def test_unknown_tool_defaults_to_system():
    """Unknown tools map to 'system' domain."""
    outcomes = [
        {"step_type": "tool_call", "tool": "unknown_new_tool", "status": "success"},
    ]
    assert classify_task_domain(outcomes) == "system"


def test_all_domains_are_valid():
    """Every value in TOOL_TO_DOMAIN must be a valid TASK_DOMAIN."""
    for tool, domain in TOOL_TO_DOMAIN.items():
        assert domain in TASK_DOMAINS, f"Tool '{tool}' maps to invalid domain '{domain}'"


@pytest.mark.asyncio
async def test_domain_stored_on_episodic_record():
    """In-memory EpisodicStore.create() should accept task_domain."""
    from sentinel.memory.episodic import EpisodicStore

    store = EpisodicStore(pool=None)
    record_id = await store.create(
        session_id="test",
        user_request="test",
        task_status="success",
        task_domain="code_debugging",
    )
    assert record_id is not None


def test_domain_stored_on_memory_chunk():
    """MemoryStore.store() should accept task_domain param."""
    import inspect
    from sentinel.memory.chunks import MemoryStore

    sig = inspect.signature(MemoryStore.store)
    assert "task_domain" in sig.parameters

    sig2 = inspect.signature(MemoryStore.store_with_embedding)
    assert "task_domain" in sig2.parameters
