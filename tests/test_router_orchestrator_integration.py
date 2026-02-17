"""Tests for Orchestrator.plan_and_execute() — the router entry point.

plan_and_execute() is called by the MessageRouter after it has already:
- Bound the session
- Scanned input (clean)
- Checked session lock

So it skips session creation and input scanning, going straight to
conversation analysis -> F2 detection -> Claude planning -> execution.
"""

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import Plan, PlanStep, TaskResult
from sentinel.planner.orchestrator import Orchestrator
from sentinel.security.pipeline import PipelineScanResult, ScanPipeline
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.provenance import reset_store


@pytest.fixture(autouse=True)
async def _reset_provenance():
    await reset_store()
    yield
    await reset_store()


@pytest.fixture
def mock_planner():
    planner = MagicMock(spec=ClaudePlanner)
    planner.create_plan = AsyncMock()
    return planner


@pytest.fixture
def mock_pipeline():
    pipeline = MagicMock(spec=ScanPipeline)
    clean_result = PipelineScanResult()
    pipeline.scan_input = AsyncMock(return_value=clean_result)
    pipeline.scan_output = AsyncMock(return_value=PipelineScanResult())
    pipeline.process_with_qwen = AsyncMock()
    return pipeline


def _make_orchestrator(planner=None, pipeline=None, **kwargs):
    """Create an Orchestrator with minimal mocks."""
    planner = planner or MagicMock(spec=ClaudePlanner)
    pipeline = pipeline or MagicMock(spec=ScanPipeline)
    return Orchestrator(planner=planner, pipeline=pipeline, **kwargs)


class TestPlanAndExecuteExists:
    """Basic interface checks for the new method."""

    def test_method_exists(self):
        """plan_and_execute exists on Orchestrator."""
        assert hasattr(Orchestrator, "plan_and_execute")

    def test_accepts_pre_bound_session(self):
        """plan_and_execute accepts a session parameter."""
        sig = inspect.signature(Orchestrator.plan_and_execute)
        assert "session" in sig.parameters

    def test_accepts_standard_params(self):
        """plan_and_execute accepts the same core params as handle_task."""
        sig = inspect.signature(Orchestrator.plan_and_execute)
        for param in ("user_request", "source", "approval_mode", "source_key", "task_id"):
            assert param in sig.parameters, f"Missing parameter: {param}"


class TestPlanAndExecuteShutdown:
    """Shutdown guard behaviour."""

    @pytest.mark.asyncio
    async def test_returns_error_when_shutting_down(self, mock_planner, mock_pipeline):
        """plan_and_execute returns error when orchestrator is shutting down."""
        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)
        orch._shutting_down = True

        result = await orch.plan_and_execute(
            user_request="test",
            session=MagicMock(),
        )
        assert result.status == "error"
        assert "shutting down" in result.reason.lower()


class TestPlanAndExecuteSkipsInputScan:
    """Verify that input scanning is NOT called by plan_and_execute."""

    @pytest.mark.asyncio
    async def test_does_not_call_scan_input(self, mock_planner, mock_pipeline):
        """plan_and_execute must not re-scan input — router already did it."""
        # Set up planner to return a simple plan
        mock_planner.create_plan = AsyncMock(return_value=Plan(
            plan_summary="test plan",
            steps=[PlanStep(id="s1", type="tool_call", tool="health_check",
                            description="Check health")],
        ))
        mock_planner._last_usage = None

        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        session = MagicMock()
        session.is_locked = False
        session.session_id = "test-session"
        session.turns = []
        session.task_in_progress = False
        session.cumulative_risk = 0.0

        with patch.object(orch, '_execute_plan', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = TaskResult(status="success", plan_summary="done")
            await orch.plan_and_execute(
                user_request="hello",
                session=session,
                source_key="api:127.0.0.1",
            )

        # Input scan should NOT have been called
        mock_pipeline.scan_input.assert_not_called()


class TestPlanAndExecuteSessionHandling:
    """Session handling in the pre-scanned path."""

    @pytest.mark.asyncio
    async def test_uses_provided_session(self, mock_planner, mock_pipeline):
        """plan_and_execute uses the session passed in, not session_store."""
        mock_planner.create_plan = AsyncMock(return_value=Plan(
            plan_summary="test plan",
            steps=[PlanStep(id="s1", type="tool_call", tool="health_check",
                            description="Check health")],
        ))
        mock_planner._last_usage = None

        mock_store = MagicMock()
        mock_store.set_task_in_progress = AsyncMock()
        mock_store.add_turn = AsyncMock()
        mock_lock = AsyncMock()
        mock_store.get_lock.return_value = mock_lock
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            session_store=mock_store,
        )

        session = MagicMock()
        session.is_locked = False
        session.session_id = "pre-bound-session"
        session.turns = []
        session.task_in_progress = False
        session.cumulative_risk = 0.0

        with patch.object(orch, '_execute_plan', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = TaskResult(status="success", plan_summary="done")
            await orch.plan_and_execute(
                user_request="hello",
                session=session,
                source_key="api:127.0.0.1",
            )

        # Should NOT have called get_or_create on the session store
        mock_store.get_or_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_locked_session_blocked(self, mock_planner, mock_pipeline):
        """plan_and_execute blocks if the provided session is locked."""
        orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)

        session = MagicMock()
        session.is_locked = True
        session.session_id = "locked-session"
        session.turns = [MagicMock(), MagicMock()]
        session.cumulative_risk = 99.0

        # Conversation analyzer that would detect the lock
        analyzer = MagicMock()
        orch._conversation_analyzer = analyzer

        result = await orch.plan_and_execute(
            user_request="test",
            session=session,
            source_key="api:127.0.0.1",
        )

        assert result.status == "blocked"
        assert "locked" in result.reason.lower()
