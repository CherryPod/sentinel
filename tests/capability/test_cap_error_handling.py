"""Pre-Phase Cross-Cutting Error Tests.

Establishes the fail-safe baseline: Sentinel fails safely under all
conditions.  These 9 tests must pass BEFORE any phase work begins.

Covers: planner failures, worker failures, scanner crashes, database
errors, disk-full, concurrent task isolation, and graceful shutdown.
"""

import asyncio
import errno
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.bus import EventBus
from sentinel.core.models import (
    DataSource,
    Plan,
    PlanStep,
    PolicyResult,
    ScanMatch,
    ScanResult,
    TaggedData,
    TrustLevel,
    ValidationResult,
)
from sentinel.planner.orchestrator import Orchestrator
from sentinel.planner.planner import PlannerError
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.security.pipeline import PipelineScanResult, ScanPipeline
from sentinel.security.provenance import create_tagged_data
from sentinel.security.scanner import (
    CommandPatternScanner,
    CredentialScanner,
    EncodingNormalizationScanner,
    SensitivePathScanner,
)
from sentinel.session.store import SessionStore
from sentinel.tools.executor import ToolError, ToolExecutor
from sentinel.worker.base import ProviderConnectionError

from .conftest import _make_plan


# ---------------------------------------------------------------------------
# Test 1: Planner API timeout
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_planner_api_timeout(mock_planner, mock_pipeline):
    """Planner timeout returns a clear error — no Qwen fallback, no step results."""
    mock_planner.create_plan.side_effect = PlannerError(
        "Request timed out after 60s"
    )

    orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)
    result = await orch.handle_task("Summarise this document")

    assert result.status == "error"
    assert "Planning failed" in result.reason
    assert not result.step_results
    mock_pipeline.process_with_qwen.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2: Planner API down
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_planner_api_down(mock_planner, mock_pipeline):
    """Planner returning 503 produces error — never falls back to Qwen for planning."""
    mock_planner.create_plan.side_effect = PlannerError(
        "HTTP 503 Service Unavailable"
    )

    orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)
    result = await orch.handle_task("Help me write a cover letter")

    assert result.status == "error"
    assert "Planning failed" in result.reason
    # No Qwen fallback for planning — Qwen is worker-only
    mock_pipeline.process_with_qwen.assert_not_called()


# ---------------------------------------------------------------------------
# Test 3: Worker model down
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_worker_model_down(mock_planner, mock_pipeline):
    """Worker (Qwen/Ollama) connection failure stops plan execution at the failed step."""
    plan = _make_plan([
        {"id": "step_1", "type": "llm_task", "description": "First task", "prompt": "Do step 1"},
        {"id": "step_2", "type": "llm_task", "description": "Second task", "prompt": "Do step 2"},
    ])
    mock_planner.create_plan.return_value = plan
    mock_pipeline.process_with_qwen.side_effect = ProviderConnectionError(
        "Connection refused: sentinel-qwen:11434"
    )

    orch = Orchestrator(planner=mock_planner, pipeline=mock_pipeline)
    result = await orch.handle_task("Two step task")

    assert result.status == "error"
    assert len(result.step_results) == 1  # step 2 never ran
    assert result.step_results[0].status == "error"
    assert "LLM task failed" in result.step_results[0].error


# ---------------------------------------------------------------------------
# Test 4: Pipeline scanner crash
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_pipeline_scanner_crash(mock_planner):
    """A crashing scanner fails closed — blocks the request, identifies the crash."""
    cred = MagicMock(spec=CredentialScanner)
    cred.scan.side_effect = RuntimeError("Segfault in regex engine")

    path = MagicMock(spec=SensitivePathScanner)
    path.scan.return_value = ScanResult(
        found=False, matches=[], scanner_name="sensitive_path_scanner",
    )

    cmd = MagicMock(spec=CommandPatternScanner)
    cmd.scan.return_value = ScanResult(
        found=False, matches=[], scanner_name="command_pattern_scanner",
    )

    enc = MagicMock(spec=EncodingNormalizationScanner)
    enc.scan.return_value = ScanResult(
        found=False, matches=[], scanner_name="encoding_normalization_scanner",
    )

    pipeline = ScanPipeline(
        cred_scanner=cred,
        path_scanner=path,
        cmd_scanner=cmd,
        worker=MagicMock(),
        encoding_scanner=enc,
    )

    orch = Orchestrator(planner=mock_planner, pipeline=pipeline)
    result = await orch.handle_task("Normal everyday request")

    # Scanner crash → fail closed → request blocked
    assert result.status == "blocked"
    assert "scanner_crash" in result.reason
    assert "credential_scanner" in result.reason
    mock_planner.create_plan.assert_not_called()


# ---------------------------------------------------------------------------
# Test 5: Pipeline partial scanner degradation
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_pipeline_partial_scanner_degradation(mock_planner):
    """One scanner crashes, other three complete — crashed scanner identified,
    remaining results preserved, request still blocked (fail-closed)."""
    cred = MagicMock(spec=CredentialScanner)
    cred.scan.return_value = ScanResult(
        found=False, matches=[], scanner_name="credential_scanner",
    )

    path = MagicMock(spec=SensitivePathScanner)
    path.scan.return_value = ScanResult(
        found=False, matches=[], scanner_name="sensitive_path_scanner",
    )

    cmd = MagicMock(spec=CommandPatternScanner)
    cmd.scan.return_value = ScanResult(
        found=False, matches=[], scanner_name="command_pattern_scanner",
    )

    enc = MagicMock(spec=EncodingNormalizationScanner)
    enc.scan.side_effect = RuntimeError("Decoder stack overflow")

    pipeline = ScanPipeline(
        cred_scanner=cred,
        path_scanner=path,
        cmd_scanner=cmd,
        worker=MagicMock(),
        encoding_scanner=enc,
    )

    orch = Orchestrator(planner=mock_planner, pipeline=pipeline)
    result = await orch.handle_task("Innocent question about weather")

    assert result.status == "blocked"
    # The crashed scanner is identified in the reason
    assert "encoding_normalization_scanner" in result.reason
    assert "scanner_crash" in result.reason
    # Planner never called — input rejected
    mock_planner.create_plan.assert_not_called()

    # Verify the other scanners completed successfully (their results preserved)
    # The pipeline scan result is consumed internally, but we can verify by
    # checking that only the encoding scanner crash caused the block
    assert "credential_scanner" not in result.reason
    assert "sensitive_path_scanner" not in result.reason
    assert "command_pattern_scanner" not in result.reason


# ---------------------------------------------------------------------------
# Test 6: Database unavailable
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_database_unavailable(mock_planner, mock_pipeline):
    """Closed database connection returns clear error — no unhandled 500."""
    db = sqlite3.connect(":memory:")
    db.close()  # Closed DB — any query raises ProgrammingError

    session_store = SessionStore(db=db, ttl=3600, max_count=100)
    analyzer = ConversationAnalyzer()

    orch = Orchestrator(
        planner=mock_planner,
        pipeline=mock_pipeline,
        session_store=session_store,
        conversation_analyzer=analyzer,
    )
    result = await orch.handle_task("Hello", source_key="api:test")

    assert result.status == "error"
    assert "Database" in result.reason
    mock_planner.create_plan.assert_not_called()


# ---------------------------------------------------------------------------
# Test 7: Workspace disk full
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_workspace_disk_full(mock_planner, mock_pipeline):
    """ENOSPC during file_write produces a clear step error."""
    plan = _make_plan([{
        "id": "step_1",
        "type": "tool_call",
        "description": "Write output file",
        "tool": "file_write",
        "args": {"path": "/workspace/output.txt", "content": "data"},
    }])
    mock_planner.create_plan.return_value = plan

    # Mock policy engine to allow the write
    mock_engine = MagicMock()
    mock_engine.check_file_write.return_value = ValidationResult(
        status=PolicyResult.ALLOWED, path="/workspace/output.txt",
    )
    executor = ToolExecutor(policy_engine=mock_engine)

    orch = Orchestrator(
        planner=mock_planner,
        pipeline=mock_pipeline,
        tool_executor=executor,
    )

    with patch("sentinel.tools.executor.os.makedirs"):
        with patch(
            "builtins.open",
            side_effect=OSError(errno.ENOSPC, "No space left on device"),
        ):
            result = await orch.handle_task("Write a file")

    assert result.status == "error"
    assert len(result.step_results) == 1
    assert result.step_results[0].status == "error"
    assert "file_write failed" in result.step_results[0].error


# ---------------------------------------------------------------------------
# Test 8: Concurrent task isolation
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_concurrent_task_isolation(mock_planner, mock_pipeline):
    """Two concurrent tasks get separate task IDs and sessions — no cross-contamination."""
    plan = _make_plan([
        {"id": "step_1", "type": "llm_task", "description": "Generate", "prompt": "Hello"},
    ], summary="Test task")
    mock_planner.create_plan.return_value = plan

    tagged = create_tagged_data(
        content="response text",
        source=DataSource.QWEN,
        trust_level=TrustLevel.UNTRUSTED,
    )
    mock_pipeline.process_with_qwen.return_value = tagged

    session_store = SessionStore(ttl=3600, max_count=100)
    analyzer = MagicMock(spec=ConversationAnalyzer)
    analyzer.analyze.return_value = MagicMock(
        action="allow", total_score=0.0, rule_scores={}, warnings=[],
    )

    orch = Orchestrator(
        planner=mock_planner,
        pipeline=mock_pipeline,
        session_store=session_store,
        conversation_analyzer=analyzer,
    )

    result_a, result_b = await asyncio.gather(
        orch.handle_task("Request from user A", source_key="api:user_a"),
        orch.handle_task("Request from user B", source_key="api:user_b"),
    )

    # Both succeed
    assert result_a.status == "success"
    assert result_b.status == "success"

    # Different task IDs
    assert result_a.task_id != result_b.task_id

    # Different sessions
    session_a = session_store.get("api:user_a")
    session_b = session_store.get("api:user_b")
    assert session_a is not None
    assert session_b is not None
    assert session_a.session_id != session_b.session_id

    # Each session has exactly 1 turn with the correct request
    assert len(session_a.turns) == 1
    assert session_a.turns[0].request_text == "Request from user A"
    assert len(session_b.turns) == 1
    assert session_b.turns[0].request_text == "Request from user B"

    # Pipeline was called twice (once per task)
    assert mock_pipeline.process_with_qwen.call_count == 2


# ---------------------------------------------------------------------------
# Test 9: Graceful shutdown
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_graceful_shutdown():
    """RoutineEngine starts and stops cleanly — no orphaned tasks, DB usable after."""
    from sentinel.routines.engine import RoutineEngine
    from sentinel.routines.store import RoutineStore

    store = RoutineStore()  # in-memory
    mock_orchestrator = MagicMock(spec=Orchestrator)
    bus = EventBus()

    engine = RoutineEngine(
        store=store,
        orchestrator=mock_orchestrator,
        event_bus=bus,
        tick_interval=1,
    )

    # Start the engine
    await engine.start()
    assert engine._scheduler_task is not None
    assert not engine._stopped

    # Let the scheduler tick once
    await asyncio.sleep(0.1)

    # Stop the engine
    await engine.stop()
    assert engine._stopped
    assert engine._scheduler_task is None
    assert len(engine._running) == 0

    # Verify EventBus is still usable after shutdown (not corrupted)
    received = []

    async def _handler(topic, data):
        received.append(topic)

    bus.subscribe("test.topic", _handler)
    await bus.publish("test.topic", {})
    assert "test.topic" in received
