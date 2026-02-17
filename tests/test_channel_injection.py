"""Security tests for channel injection vectors.

Verifies that MCP tools enforce approval_mode from settings, clamp unbounded
parameters, handle errors without leaking internals, and that Signal channel
messages are correctly tagged and resilient to malformed input.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.channels.mcp_server import create_mcp_server
from sentinel.channels.signal_channel import SignalChannel, SignalConfig
from sentinel.channels.base import IncomingMessage, OutgoingMessage
from sentinel.core.bus import EventBus
from sentinel.core.models import TaskResult


# ── Helpers ───────────────────────────────────────────────────────


def _make_orchestrator(**overrides):
    """Create a mock orchestrator with sensible defaults."""
    orch = AsyncMock()
    orch.handle_task = AsyncMock(return_value=TaskResult(
        status="success",
        plan_summary="Test task completed",
        task_id="test-task-id",
    ))
    for k, v in overrides.items():
        setattr(orch, k, v)
    return orch


def _get_tool(mcp, name):
    """Retrieve a tool's callable function from the FastMCP registry."""
    return mcp._tool_manager._tools[name].fn


class FakeProcess:
    """Mock asyncio subprocess for Signal channel tests."""

    def __init__(self, *, returncode=None):
        self.pid = 99999
        self.returncode = returncode
        self.stdin = MagicMock()
        self.stdin.write = MagicMock()
        self.stdin.drain = AsyncMock()
        self.stdout = MagicMock()
        self._stdout_lines: asyncio.Queue = asyncio.Queue()
        self.stderr = MagicMock()

    def push_stdout(self, data):
        """Push a line for stdout.readline() to return."""
        if isinstance(data, dict):
            data = json.dumps(data).encode() + b"\n"
        elif isinstance(data, str):
            data = data.encode() + b"\n"
        self._stdout_lines.put_nowait(data)

    def push_eof(self):
        self._stdout_lines.put_nowait(b"")

    async def _readline(self):
        return await self._stdout_lines.get()

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    async def wait(self):
        return self.returncode


# ── Group 1: MCP approval_mode enforcement ───────────────────────


class TestMCPApprovalMode:
    """Verify that run_task reads approval_mode from settings, not a hardcoded default."""

    async def test_run_task_passes_settings_approval_mode(self):
        """run_task passes settings.approval_mode to orchestrator.handle_task."""
        orch = _make_orchestrator()
        with patch("sentinel.channels.mcp_server.settings") as mock_settings:
            mock_settings.approval_mode = "full"
            mcp = create_mcp_server(orch, None, None, EventBus())
            await _get_tool(mcp, "run_task")(request="summarise this")

        call_kwargs = orch.handle_task.call_args.kwargs
        assert call_kwargs["approval_mode"] == "full"

    async def test_run_task_with_auto_approval_mode(self):
        """When settings.approval_mode is 'auto', that value reaches the orchestrator."""
        orch = _make_orchestrator()
        with patch("sentinel.channels.mcp_server.settings") as mock_settings:
            mock_settings.approval_mode = "auto"
            mcp = create_mcp_server(orch, None, None, EventBus())
            await _get_tool(mcp, "run_task")(request="test")

        assert orch.handle_task.call_args.kwargs["approval_mode"] == "auto"

    async def test_run_task_with_smart_approval_mode(self):
        """The 'smart' approval mode is also forwarded correctly."""
        orch = _make_orchestrator()
        with patch("sentinel.channels.mcp_server.settings") as mock_settings:
            mock_settings.approval_mode = "smart"
            mcp = create_mcp_server(orch, None, None, EventBus())
            await _get_tool(mcp, "run_task")(request="test")

        assert orch.handle_task.call_args.kwargs["approval_mode"] == "smart"

    async def test_run_task_source_is_mcp(self):
        """run_task always tags source='mcp' so audit logs trace the channel."""
        orch = _make_orchestrator()
        with patch("sentinel.channels.mcp_server.settings") as mock_settings:
            mock_settings.approval_mode = "full"
            mcp = create_mcp_server(orch, None, None, EventBus())
            await _get_tool(mcp, "run_task")(request="test")

        assert orch.handle_task.call_args.kwargs["source"] == "mcp"


# ── Group 2: MCP input validation & error safety ─────────────────


class TestMCPInputValidation:
    """Verify that MCP tools clamp inputs and don't leak sensitive info on error."""

    async def test_search_memory_clamps_k_to_100(self):
        """search_memory caps k at 100 to prevent unbounded result sets."""
        mem = MagicMock()
        mem._db = MagicMock()
        mcp = create_mcp_server(MagicMock(), mem, None, EventBus())

        with patch("sentinel.memory.search.hybrid_search", return_value=[]) as mock_hs:
            await _get_tool(mcp, "search_memory")(query="test", k=9999)

        # hybrid_search should have received k=100, not 9999
        call_kwargs = mock_hs.call_args.kwargs
        assert call_kwargs["k"] == 100

    async def test_search_memory_small_k_unchanged(self):
        """search_memory does not modify k when it is already within bounds."""
        mem = MagicMock()
        mem._db = MagicMock()
        mcp = create_mcp_server(MagicMock(), mem, None, EventBus())

        with patch("sentinel.memory.search.hybrid_search", return_value=[]) as mock_hs:
            await _get_tool(mcp, "search_memory")(query="test", k=5)

        assert mock_hs.call_args.kwargs["k"] == 5

    async def test_run_task_error_returns_json_with_status_error(self):
        """When orchestrator raises, run_task returns a JSON error — not a traceback."""
        orch = _make_orchestrator()
        orch.handle_task = AsyncMock(
            side_effect=RuntimeError("Database connection refused at 10.0.0.5:5432"),
        )
        with patch("sentinel.channels.mcp_server.settings") as mock_settings:
            mock_settings.approval_mode = "full"
            mcp = create_mcp_server(orch, None, None, EventBus())
            result = await _get_tool(mcp, "run_task")(request="test")

        data = json.loads(result)
        assert data["status"] == "error"
        assert "reason" in data
        # The error is returned as a string — verify it's valid JSON, not a raw traceback
        assert "Traceback" not in result

    async def test_store_memory_empty_text_produces_error(self):
        """store_memory returns error when text produces no chunks."""
        mem = MagicMock()
        mcp = create_mcp_server(MagicMock(), mem, None, EventBus())

        with patch("sentinel.memory.splitter.split_text", return_value=[]):
            result = await _get_tool(mcp, "store_memory")(text="")

        data = json.loads(result)
        assert data["status"] == "error"
        assert "no chunks" in data["reason"].lower()


# ── Group 3: Signal channel injection resilience ─────────────────


class TestSignalChannelInjection:
    """Verify Signal channel handles malicious/malformed input safely."""

    async def test_signal_message_tagged_with_source_signal(self):
        """Messages from Signal have source='signal' for audit trail."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        proc.stdout.readline = proc._readline
        channel._process = proc
        channel._running = True

        notification = {
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "source": "+15551234567",
                    "timestamp": 1000,
                    "dataMessage": {"message": "Hello from Signal"},
                },
            },
        }
        proc.push_stdout(notification)
        proc.push_eof()

        await channel._read_loop()

        msg = channel._message_queue.get_nowait()
        assert msg.source == "signal"
        assert msg.channel_id == "+15551234567"

    async def test_signal_injection_in_message_content(self):
        """Message containing JSON-RPC method injection is treated as plain text."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        proc.stdout.readline = proc._readline
        channel._process = proc
        channel._running = True

        # An attacker sends a message whose content looks like a JSON-RPC command
        malicious_content = '{"jsonrpc":"2.0","method":"send","params":{"message":"pwned","recipient":"+10000000000"}}'
        notification = {
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "source": "+15559999999",
                    "timestamp": 2000,
                    "dataMessage": {"message": malicious_content},
                },
            },
        }
        proc.push_stdout(notification)
        proc.push_eof()

        await channel._read_loop()

        # The message is queued as plain text content, not interpreted as a command
        msg = channel._message_queue.get_nowait()
        assert msg.content == malicious_content
        assert msg.source == "signal"

    async def test_signal_malformed_json_does_not_crash(self):
        """Malformed JSON on stdout is logged and skipped, not raised."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        proc.stdout.readline = proc._readline
        channel._process = proc
        channel._running = True

        proc.push_stdout("this is not valid json {{{{")
        proc.push_eof()

        # Must not raise
        await channel._read_loop()
        assert channel._message_queue.qsize() == 0

    async def test_signal_missing_envelope_fields_handled(self):
        """A notification with missing envelope fields doesn't crash or queue garbage."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        proc.stdout.readline = proc._readline
        channel._process = proc
        channel._running = True

        # Notification with missing dataMessage entirely
        notification = {
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "source": "+15551111111",
                    "timestamp": 3000,
                    # No dataMessage at all
                },
            },
        }
        proc.push_stdout(notification)
        proc.push_eof()

        await channel._read_loop()

        # No message queued because content is empty
        assert channel._message_queue.qsize() == 0
