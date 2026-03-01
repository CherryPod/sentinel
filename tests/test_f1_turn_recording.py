"""Tests for F1 turn recording — step_outcomes flow through to ConversationTurn."""

import pytest
from unittest.mock import MagicMock, AsyncMock

from sentinel.core.models import DataSource, PlanStep, StepResult, TrustLevel
from sentinel.planner.orchestrator import Orchestrator
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.pipeline import ScanPipeline, PipelineScanResult
from sentinel.security.provenance import create_tagged_data
from sentinel.session.store import SessionStore


def _make_plan(steps, summary="Test plan"):
    from sentinel.core.models import Plan
    return Plan(
        plan_summary=summary,
        steps=[PlanStep(**s) for s in steps],
    )


@pytest.fixture
def _disable_semgrep():
    from sentinel.core.config import settings
    original = settings.require_semgrep
    settings.require_semgrep = False
    yield
    settings.require_semgrep = original


class TestHandleTaskRecordsTurnWithOutcomes:
    @pytest.mark.asyncio
    async def test_handle_task_passes_step_outcomes_to_turn(self, _disable_semgrep):
        mock_planner = MagicMock(spec=ClaudePlanner)
        mock_planner.create_plan = AsyncMock()
        mock_pipeline = MagicMock(spec=ScanPipeline)
        mock_pipeline.scan_input.return_value = PipelineScanResult()
        mock_pipeline.process_with_qwen = AsyncMock()

        store = SessionStore(ttl=3600, max_count=100)

        plan = _make_plan([
            {"id": "step_1", "type": "llm_task", "description": "Write code", "prompt": "Hi"}
        ], summary="Test summary")
        mock_planner.create_plan.return_value = plan
        tagged = create_tagged_data("print('hello')", DataSource.QWEN, TrustLevel.UNTRUSTED)
        mock_pipeline.process_with_qwen.return_value = tagged

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            session_store=store,
            conversation_analyzer=MagicMock(
                analyze=MagicMock(return_value=MagicMock(
                    action="allow", total_score=0.0, rule_scores={}, warnings=[],
                ))
            ),
        )

        result = await orch.handle_task("write hello.py", source_key="api:test-f1")

        assert result.status == "success"
        session = store.get("api:test-f1")
        assert session is not None
        assert len(session.turns) == 1
        turn = session.turns[0]
        # F1: step_outcomes should be populated
        assert turn.step_outcomes is not None
        assert len(turn.step_outcomes) == 1
        assert turn.step_outcomes[0]["step_type"] == "llm_task"
        assert turn.step_outcomes[0]["status"] == "success"

    @pytest.mark.asyncio
    async def test_handle_task_none_when_no_steps(self, _disable_semgrep):
        """A plan with no steps produces an empty step_outcomes list → stored as None."""
        mock_planner = MagicMock(spec=ClaudePlanner)
        mock_planner.create_plan = AsyncMock()
        mock_pipeline = MagicMock(spec=ScanPipeline)
        mock_pipeline.scan_input.return_value = PipelineScanResult()
        mock_pipeline.process_with_qwen = AsyncMock()

        store = SessionStore(ttl=3600, max_count=100)

        plan = _make_plan([], summary="Empty plan")
        mock_planner.create_plan.return_value = plan

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            session_store=store,
            conversation_analyzer=MagicMock(
                analyze=MagicMock(return_value=MagicMock(
                    action="allow", total_score=0.0, rule_scores={}, warnings=[],
                ))
            ),
        )

        result = await orch.handle_task("do nothing", source_key="api:test-f1b")

        assert result.status == "success"
        session = store.get("api:test-f1b")
        assert session is not None
        assert len(session.turns) == 1
        # Empty step_outcomes → stored as None (not empty list)
        assert session.turns[0].step_outcomes is None
