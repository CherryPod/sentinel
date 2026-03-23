"""Tests for the fast-path executor."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.confirmation import ConfirmationGate
from sentinel.router.fast_path import FastPathExecutor
from sentinel.router.templates import Template, TemplateRegistry
from sentinel.session.store import Session


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def registry() -> TemplateRegistry:
    """Registry with a mix of single-tool, chain, and side-effect templates."""
    reg = TemplateRegistry()
    reg.register(
        Template(
            name="web_search",
            description="Search the web",
            tool="web_search",
            required_params=["query"],
        )
    )
    reg.register(
        Template(
            name="email_read",
            description="Search and read an email",
            tool="email_search+email_read",
            required_params=["query"],
        )
    )
    reg.register(
        Template(
            name="signal_send",
            description="Send a message via Signal",
            tool="signal_send",
            required_params=["message"],
            side_effect=True,
            source_is_user=True,
        )
    )
    return reg


@pytest.fixture
def tool_executor() -> AsyncMock:
    """Mock ToolExecutor — returns a TaggedData-like tuple by default."""
    executor = AsyncMock()
    tagged = MagicMock()
    tagged.content = "tool result"
    tagged.tag = "tool_output"
    executor.execute = AsyncMock(return_value=(tagged, None))
    return executor


@pytest.fixture
def pipeline() -> AsyncMock:
    """Mock ScanPipeline — clean by default."""
    pipe = AsyncMock()
    scan_result = MagicMock()
    scan_result.is_clean = True
    scan_result.violations = {}
    pipe.scan_output = AsyncMock(return_value=scan_result)
    return pipe


@pytest.fixture
def event_bus() -> AsyncMock:
    """Mock EventBus."""
    bus = AsyncMock()
    bus.publish = AsyncMock()
    return bus


@pytest.fixture
def session() -> Session:
    return Session(session_id="test-session", source="test")


@pytest.fixture
def executor(tool_executor, pipeline, event_bus, registry) -> FastPathExecutor:
    return FastPathExecutor(
        tool_executor=tool_executor,
        pipeline=pipeline,
        event_bus=event_bus,
        registry=registry,
    )


# ── Test: single tool success ───────────────────────────────────────


@pytest.mark.asyncio
async def test_single_tool_success(executor, tool_executor, pipeline, session):
    """Single-tool template executes, scans, records turn, returns success."""
    result = await executor.execute(
        template_name="web_search",
        params={"query": "weather today"},
        session=session,
        task_id="t1",
    )

    assert result["status"] == "success"
    assert result["response"] == "tool result"
    assert result["template"] == "web_search"

    # Tool executor called with the right args
    tool_executor.execute.assert_awaited_once_with("web_search", {"query": "weather today"})

    # Output was scanned
    pipeline.scan_output.assert_awaited_once()

    # Session turn recorded
    assert len(session.turns) == 1
    turn = session.turns[0]
    assert turn.result_status == "success"
    assert turn.request_text == "web_search"


# ── Test: output scan blocks ────────────────────────────────────────


@pytest.mark.asyncio
async def test_output_scan_blocks(executor, pipeline, session):
    """When the scan pipeline blocks output, result is 'blocked'."""
    blocked_result = MagicMock()
    blocked_result.is_clean = False
    blocked_result.violations = {"prompt_guard": MagicMock(matches=["bad"])}
    pipeline.scan_output.return_value = blocked_result

    result = await executor.execute(
        template_name="web_search",
        params={"query": "test"},
        session=session,
        task_id="t2",
    )

    assert result["status"] == "blocked"
    assert len(session.turns) == 1
    assert session.turns[0].result_status == "blocked"
    assert "prompt_guard" in session.turns[0].blocked_by


# ── Test: tool execution error ──────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_execution_error(executor, tool_executor, session):
    """When tool_executor raises, result is 'error' and turn is recorded."""
    tool_executor.execute.side_effect = RuntimeError("connection failed")

    result = await executor.execute(
        template_name="web_search",
        params={"query": "test"},
        session=session,
        task_id="t3",
    )

    assert result["status"] == "error"
    assert "connection failed" in result["reason"]
    assert len(session.turns) == 1
    assert session.turns[0].result_status == "error"


# ── Test: unknown template ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_template(executor, session):
    """Unknown template name returns error without calling tools."""
    result = await executor.execute(
        template_name="nonexistent",
        params={},
        session=session,
        task_id="t4",
    )

    assert result["status"] == "error"
    assert "unknown" in result["reason"].lower()


# ── Test: events emitted ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_events_emitted(executor, event_bus, session):
    """Started and completed events are published to the bus."""
    await executor.execute(
        template_name="web_search",
        params={"query": "test"},
        session=session,
        task_id="t5",
    )

    # Collect all published topics
    topics = [call.args[0] for call in event_bus.publish.call_args_list]
    assert "task.t5.started" in topics
    assert "task.t5.completed" in topics


# ── Test: chain execution (email_read) ──────────────────────────────


@pytest.mark.asyncio
async def test_chain_email_read(executor, tool_executor, session):
    """email_read chain: calls email_search first, then email_read per message."""
    # email_search returns JSON list of messages
    search_tagged = MagicMock()
    search_tagged.content = json.dumps([
        {"message_id": "msg-1"},
        {"message_id": "msg-2"},
    ])
    search_tagged.tag = "tool_output"

    # email_read returns body text
    read_tagged = MagicMock()
    read_tagged.content = "Email body content"
    read_tagged.tag = "tool_output"

    tool_executor.execute = AsyncMock(
        side_effect=[
            (search_tagged, None),  # email_search
            (read_tagged, None),    # email_read msg-1
            (read_tagged, None),    # email_read msg-2
        ]
    )

    result = await executor.execute(
        template_name="email_read",
        params={"query": "from:alice"},
        session=session,
        task_id="t6",
    )

    assert result["status"] == "success"
    # Should have called execute 3 times: search + 2 reads
    assert tool_executor.execute.await_count == 3

    # First call: email_search with query
    first_call = tool_executor.execute.call_args_list[0]
    assert first_call.args[0] == "email_search"

    # Second and third calls: email_read with message_id
    for call in tool_executor.execute.call_args_list[1:]:
        assert call.args[0] == "email_read"
        assert "message_id" in call.args[1]


# ── Test: side-effect template (signal_send) ────────────────────────


@pytest.mark.asyncio
async def test_side_effect_template(executor, tool_executor, session):
    """Side-effect templates (signal_send) execute and return success."""
    result = await executor.execute(
        template_name="signal_send",
        params={"message": "Hello!"},
        session=session,
        task_id="t7",
    )

    assert result["status"] == "success"
    tool_executor.execute.assert_awaited_once_with("signal_send", {"message": "Hello!"})


# ── Test: blocked event emitted ─────────────────────────────────────


@pytest.mark.asyncio
async def test_blocked_event_emitted(executor, pipeline, event_bus, session):
    """When scan blocks, a 'blocked' event is emitted."""
    blocked_result = MagicMock()
    blocked_result.is_clean = False
    blocked_result.violations = {"scanner_x": MagicMock(matches=[])}
    pipeline.scan_output.return_value = blocked_result

    await executor.execute(
        template_name="web_search",
        params={"query": "test"},
        session=session,
        task_id="t8",
    )

    topics = [call.args[0] for call in event_bus.publish.call_args_list]
    assert "task.t8.blocked" in topics


# ── Test: no bus is fine ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_event_bus(tool_executor, pipeline, registry, session):
    """Executor works without an event bus (bus=None)."""
    executor = FastPathExecutor(
        tool_executor=tool_executor,
        pipeline=pipeline,
        event_bus=None,
        registry=registry,
    )

    result = await executor.execute(
        template_name="web_search",
        params={"query": "test"},
        session=session,
        task_id="t9",
    )

    assert result["status"] == "success"


# ── Confirmation gate tests ──────────────────────────────────────


def _make_executor(confirmation_gate=None):
    """Build a FastPathExecutor with mocked dependencies and the default registry."""
    tool_exec = AsyncMock()
    tagged = MagicMock()
    tagged.content = "tool result"
    tagged.tag = "tool_output"
    tool_exec.execute = AsyncMock(return_value=(tagged, None))

    pipe = AsyncMock()
    scan_result = MagicMock()
    scan_result.is_clean = True
    scan_result.violations = {}
    pipe.scan_output = AsyncMock(return_value=scan_result)

    bus = AsyncMock()
    bus.publish = AsyncMock()

    registry = TemplateRegistry.default()

    return FastPathExecutor(
        tool_executor=tool_exec,
        pipeline=pipe,
        event_bus=bus,
        registry=registry,
        confirmation_gate=confirmation_gate,
    )


def _make_session():
    return Session(session_id="test-session", source="test")


class TestFastPathConfirmation:
    @pytest.mark.asyncio
    async def test_side_effect_template_returns_awaiting_confirmation(self):
        """Templates with requires_confirmation=True should pause and return awaiting status."""
        gate = ConfirmationGate(pool=None, timeout=600)
        executor = _make_executor(confirmation_gate=gate)
        result = await executor.execute(
            "signal_send",
            {"message": "hello", "recipient": "keith"},
            _make_session(),
            "task-001",
            user_id=1,
        )
        assert result["status"] == "awaiting_confirmation"
        assert "preview" in result
        # Should have created a pending confirmation
        assert len(gate._mem) == 1

    @pytest.mark.asyncio
    async def test_read_only_template_executes_immediately(self):
        """Templates without requires_confirmation should execute as before."""
        gate = ConfirmationGate(pool=None, timeout=600)
        executor = _make_executor(confirmation_gate=gate)
        result = await executor.execute(
            "web_search",
            {"query": "test"},
            _make_session(),
            "task-002",
            user_id=1,
        )
        assert result["status"] == "success"
        assert len(gate._mem) == 0

    @pytest.mark.asyncio
    async def test_execute_confirmed_runs_stored_payload(self):
        """execute_confirmed should run the tool with the stored params."""
        gate = ConfirmationGate(pool=None, timeout=600)
        executor = _make_executor(confirmation_gate=gate)
        result = await executor.execute_confirmed(
            "signal_send",
            {"message": "hello", "recipient": "keith"},
            "task-003",
        )
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_no_gate_executes_immediately(self):
        """Without a confirmation gate, side-effect templates execute immediately (backwards compat)."""
        executor = _make_executor(confirmation_gate=None)
        result = await executor.execute(
            "signal_send",
            {"message": "hello", "recipient": "keith"},
            _make_session(),
            "task-004",
            user_id=1,
        )
        assert result["status"] == "success"
