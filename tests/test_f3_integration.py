"""F3: Worker-Side Context integration tests."""

import pytest
from sentinel.core.models import PlanStep


class TestPlanStepWorkerHistory:
    """F3: include_worker_history field on PlanStep."""

    def test_include_worker_history_defaults_false(self):
        step = PlanStep(id="step_1", type="llm_task", description="test")
        assert step.include_worker_history is False

    def test_include_worker_history_set_true(self):
        step = PlanStep(
            id="step_1", type="llm_task", description="test",
            include_worker_history=True,
        )
        assert step.include_worker_history is True

    def test_include_worker_history_from_dict(self):
        """Plan JSON from Claude includes the field."""
        data = {
            "id": "step_1",
            "type": "llm_task",
            "description": "diagnose bug",
            "prompt": "Fix the code in $current_code",
            "include_worker_history": True,
            "input_vars": ["current_code"],
        }
        step = PlanStep(**data)
        assert step.include_worker_history is True

    def test_include_worker_history_absent_in_dict(self):
        """Plans without the field default to False (backward compat)."""
        data = {"id": "step_1", "type": "llm_task", "description": "test"}
        step = PlanStep(**data)
        assert step.include_worker_history is False


from sentinel.core.config import Settings


class TestF3Config:
    """F3 configuration settings."""

    def test_worker_turn_buffer_size_default(self):
        s = Settings(
            _env_file=None,
            claude_api_key_file="/dev/null",
            pin_file="/dev/null",
        )
        assert s.worker_turn_buffer_size == 10

    def test_worker_context_token_budget_default(self):
        s = Settings(
            _env_file=None,
            claude_api_key_file="/dev/null",
            pin_file="/dev/null",
        )
        assert s.worker_context_token_budget == 2000


class TestSessionWorkspaceTracking:
    """F3 Feature 1: Planner sees SESSION FILES with per-turn metadata."""

    def test_build_session_files_single_create(self):
        """Single file created in one turn."""
        from sentinel.planner.builders import build_session_files_context

        turns = [_mock_turn(1, [
            {"step_type": "tool_call", "file_path": "/workspace/app.py",
             "file_size_after": 1200, "status": "success"},
        ])]
        result = build_session_files_context(turns)
        assert "/workspace/app.py" in result
        assert "turn 1" in result
        assert "created" in result
        assert "1200" in result

    def test_build_session_files_multi_turn_modify(self):
        """File created in turn 1, modified in turn 3 — shows timeline."""
        from sentinel.planner.builders import build_session_files_context

        turns = [
            _mock_turn(1, [
                {"step_type": "tool_call", "file_path": "/workspace/app.py",
                 "file_size_after": 1200, "output_language": "python",
                 "syntax_valid": True, "status": "success",
                 "defined_symbols": ["main", "process"]},
            ]),
            _mock_turn(2, [
                {"step_type": "llm_task", "output_size": 500, "status": "success"},
            ]),
            _mock_turn(3, [
                {"step_type": "tool_call", "file_path": "/workspace/app.py",
                 "file_size_after": 1800, "output_language": "python",
                 "syntax_valid": False, "status": "success",
                 "scanner_result": "clean", "diff_stats": "+8/-2 lines"},
            ]),
        ]
        result = build_session_files_context(turns)
        assert "/workspace/app.py" in result
        assert "turn 1" in result
        assert "turn 3" in result
        assert "syntax" in result.lower()

    def test_build_session_files_empty(self):
        """No file operations — returns empty string."""
        from sentinel.planner.builders import build_session_files_context

        turns = [_mock_turn(1, [
            {"step_type": "llm_task", "output_size": 300, "status": "success"},
        ])]
        result = build_session_files_context(turns)
        assert result == ""

    def test_build_session_files_none_outcomes(self):
        """Handles turns with None step_outcomes gracefully."""
        from sentinel.planner.builders import build_session_files_context

        turns = [_mock_turn(1, None)]
        result = build_session_files_context(turns)
        assert result == ""


class TestPlannerDiagnosticPattern:
    """F3 Feature 2: Planner system prompt teaches debugging chains."""

    def test_system_prompt_contains_debugging_section(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "<debugging>" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_system_prompt_documents_include_worker_history(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "include_worker_history" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_system_prompt_mentions_session_files(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "SESSION FILES" in _PLANNER_SYSTEM_PROMPT_TEMPLATE


from unittest.mock import AsyncMock, MagicMock, patch
from sentinel.core.models import TaggedData, TrustLevel, DataSource


class TestWorkerContextInjection:
    """F3 Feature 3: Orchestrator injects worker context into llm_task prompts."""

    @pytest.mark.asyncio
    async def test_context_injected_when_flag_true(self):
        """include_worker_history=True causes context prepend."""
        from sentinel.planner.orchestrator import Orchestrator, ExecutionContext
        from sentinel.worker.context import WorkerContext, WorkerTurn
        import time

        orch = _make_orchestrator()

        # Pre-populate a worker context
        ctx = WorkerContext(session_id="test-session")
        ctx.add_turn(WorkerTurn(
            turn_number=1,
            prompt_summary="Generate a tracker",
            response_summary="<!DOCTYPE html>...",
            step_outcome={"output_size": 2847, "output_language": "html", "syntax_valid": True},
            timestamp=time.time(),
        ))
        orch._worker_contexts["test-session"] = ctx

        step = PlanStep(
            id="step_1", type="llm_task",
            description="fix the bug",
            prompt="Fix the CSS issue",
            include_worker_history=True,
        )

        # Capture what process_with_qwen receives
        captured_prompt = []

        async def mock_process(prompt, **kwargs):
            captured_prompt.append(prompt)
            return TaggedData(
                id="td1", content="fixed code",
                trust_level=TrustLevel.UNTRUSTED,
                source=DataSource.QWEN,
            )
        orch._pipeline.process_with_qwen = mock_process

        with patch("sentinel.planner.orchestrator.semgrep_scanner") as mock_sg:
            mock_sg.is_loaded.return_value = False
            result = await orch._execute_llm_task(
                step, ExecutionContext(), session_id="test-session",
            )

        assert len(captured_prompt) == 1
        assert "[Previous work in this session:]" in captured_prompt[0]
        assert "[Current task:]" in captured_prompt[0]

    @pytest.mark.asyncio
    async def test_context_not_injected_when_flag_false(self):
        """include_worker_history=False skips context injection."""
        from sentinel.planner.orchestrator import Orchestrator, ExecutionContext
        from sentinel.worker.context import WorkerContext, WorkerTurn
        import time

        orch = _make_orchestrator()
        ctx = WorkerContext(session_id="test-session")
        ctx.add_turn(WorkerTurn(
            turn_number=1,
            prompt_summary="Generate a tracker",
            response_summary="<!DOCTYPE html>...",
            step_outcome={"output_size": 2847},
            timestamp=time.time(),
        ))
        orch._worker_contexts["test-session"] = ctx

        step = PlanStep(
            id="step_1", type="llm_task",
            description="fresh task",
            prompt="Write a hello world script",
            include_worker_history=False,
        )

        captured_prompt = []

        async def mock_process(prompt, **kwargs):
            captured_prompt.append(prompt)
            return TaggedData(
                id="td1", content="print('hello')",
                trust_level=TrustLevel.UNTRUSTED,
                source=DataSource.QWEN,
            )
        orch._pipeline.process_with_qwen = mock_process

        with patch("sentinel.planner.orchestrator.semgrep_scanner") as mock_sg:
            mock_sg.is_loaded.return_value = False
            result = await orch._execute_llm_task(
                step, ExecutionContext(), session_id="test-session",
            )

        assert len(captured_prompt) == 1
        assert "[Previous work in this session:]" not in captured_prompt[0]

    @pytest.mark.asyncio
    async def test_session_isolation(self):
        """Different sessions get different worker contexts."""
        from sentinel.planner.orchestrator import Orchestrator
        from sentinel.worker.context import WorkerContext

        orch = _make_orchestrator()
        orch._worker_contexts["session-a"] = WorkerContext(session_id="session-a")
        orch._worker_contexts["session-b"] = WorkerContext(session_id="session-b")

        assert orch._worker_contexts["session-a"].session_id == "session-a"
        assert orch._worker_contexts["session-b"].session_id == "session-b"
        assert len(orch._worker_contexts) == 2


def _make_orchestrator():
    """Create an Orchestrator with mocked dependencies for testing."""
    from sentinel.planner.orchestrator import Orchestrator

    mock_planner = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline._worker = MagicMock()
    mock_pipeline._worker._last_generate_stats = None

    orch = Orchestrator(
        planner=mock_planner,
        pipeline=mock_pipeline,
    )
    return orch


def _mock_turn(turn_number, step_outcomes):
    """Create a minimal mock turn with step_outcomes for testing."""
    class MockTurn:
        def __init__(self, outcomes):
            self.step_outcomes = outcomes
    return MockTurn(step_outcomes)
