"""Tests for Step 2.3: Summary Refresh Trigger.

Verifies that _store_episodic_record triggers a background domain summary
refresh when the task count crosses the staleness threshold (>=10).
"""

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.memory.episodic import EpisodicStore
from sentinel.memory.chunks import MemoryStore


def _make_orchestrator(**kwargs):
    """Create an Orchestrator with mocked dependencies for testing."""
    from sentinel.planner.orchestrator import Orchestrator

    mock_planner = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline._worker = MagicMock()
    mock_pipeline._worker._last_generate_stats = None

    with patch("sentinel.planner.orchestrator.semgrep_scanner") as mock_sg:
        mock_sg.is_loaded.return_value = False
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            **kwargs,
        )
    return orch


def _step_outcomes_with_domain():
    """Step outcomes that classify to a known domain (file_write -> coding)."""
    return [
        {
            "step_type": "tool_call",
            "tool": "file_write",
            "status": "success",
            "file_path": "/workspace/app.py",
            "file_size_before": None,
            "file_size_after": 500,
            "output_language": "python",
        },
    ]


class TestSummaryRefreshTrigger:
    """Verify domain summary staleness check after episodic record storage."""

    @pytest.mark.asyncio
    async def test_stale_triggers_refresh(self):
        """When increment_task_count returns >=10, _refresh_domain_summary is called."""
        mock_ds_store = AsyncMock()
        mock_ds_store.increment_task_count.return_value = 10

        orch = _make_orchestrator(domain_summary_store=mock_ds_store)
        orch._memory_store = MemoryStore(pool=None)
        orch.set_episodic_store(EpisodicStore(pool=None))

        # Patch _refresh_domain_summary to track calls without running it
        orch._refresh_domain_summary = AsyncMock()

        await orch._store_episodic_record(
            session_id="s1",
            task_id="t1",
            user_request="build a widget",
            task_status="success",
            plan_summary="Built widget",
            step_outcomes=_step_outcomes_with_domain(),
        )

        mock_ds_store.increment_task_count.assert_called_once()
        # asyncio.create_task wraps _refresh_domain_summary, but since we
        # patched the method we can verify it was scheduled
        orch._refresh_domain_summary.assert_called_once()

    @pytest.mark.asyncio
    async def test_below_threshold_no_refresh(self):
        """When increment_task_count returns <10, no refresh is triggered."""
        mock_ds_store = AsyncMock()
        mock_ds_store.increment_task_count.return_value = 5

        orch = _make_orchestrator(domain_summary_store=mock_ds_store)
        orch._memory_store = MemoryStore(pool=None)
        orch.set_episodic_store(EpisodicStore(pool=None))

        orch._refresh_domain_summary = AsyncMock()

        await orch._store_episodic_record(
            session_id="s1",
            task_id="t1",
            user_request="build a widget",
            task_status="success",
            plan_summary="Built widget",
            step_outcomes=_step_outcomes_with_domain(),
        )

        mock_ds_store.increment_task_count.assert_called_once()
        orch._refresh_domain_summary.assert_not_called()

    @pytest.mark.asyncio
    async def test_refresh_failure_non_fatal(self):
        """If the domain summary check raises, _store_episodic_record still succeeds."""
        mock_ds_store = AsyncMock()
        mock_ds_store.increment_task_count.side_effect = Exception("DB gone")

        orch = _make_orchestrator(domain_summary_store=mock_ds_store)
        orch._memory_store = MemoryStore(pool=None)
        orch.set_episodic_store(EpisodicStore(pool=None))

        # Should not raise — the outer try/except in _store_episodic_record
        # catches domain summary errors separately
        await orch._store_episodic_record(
            session_id="s1",
            task_id="t1",
            user_request="build a widget",
            task_status="success",
            plan_summary="Built widget",
            step_outcomes=_step_outcomes_with_domain(),
        )

    @pytest.mark.asyncio
    async def test_no_store_skips_check(self):
        """When domain_summary_store is None, no error and no check."""
        orch = _make_orchestrator()  # no domain_summary_store
        orch._memory_store = MemoryStore(pool=None)
        orch.set_episodic_store(EpisodicStore(pool=None))

        # Should not raise
        await orch._store_episodic_record(
            session_id="s1",
            task_id="t1",
            user_request="build a widget",
            task_status="success",
            plan_summary="Built widget",
            step_outcomes=_step_outcomes_with_domain(),
        )
        # No assertion needed — the test passes if no exception is raised
