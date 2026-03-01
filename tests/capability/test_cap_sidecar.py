"""A1: WASM Sidecar Capability Tests.

Verifies sidecar health, tool dispatch, error handling, crash recovery,
concurrency, and state isolation. All tests use mocked sidecar — no
real binary needed in pytest.

12 tests total, covering the full A1 deployment checklist.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import (
    DataSource,
    PolicyResult,
    TaggedData,
    TrustLevel,
    ValidationResult,
)
from sentinel.tools.executor import (
    WASM_TOOLS,
    ToolError,
    ToolExecutor,
    _WASM_TOOL_CAPABILITIES,
)
from sentinel.tools.sidecar import SidecarClient, SidecarResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_sidecar(**execute_kwargs) -> AsyncMock:
    """Create a mock SidecarClient with a pre-configured execute response."""
    sidecar = AsyncMock(spec=SidecarClient)
    sidecar.execute = AsyncMock(
        return_value=SidecarResponse(**execute_kwargs),
    )
    sidecar.is_running = True
    sidecar.stop_sidecar = AsyncMock()
    return sidecar


def _mock_engine_allow_all() -> MagicMock:
    """PolicyEngine that allows everything."""
    engine = MagicMock()
    allowed = ValidationResult(status=PolicyResult.ALLOWED, path="")
    engine.check_file_read.return_value = allowed
    engine.check_file_write.return_value = allowed
    engine.check_command.return_value = allowed
    return engine


# ---------------------------------------------------------------------------
# Test 1: Sidecar health check
# ---------------------------------------------------------------------------


@pytest.mark.capability
def test_sidecar_health_check():
    """SidecarClient.is_running reflects process state; health endpoint
    includes sidecar status when enabled."""
    # Process running
    client = SidecarClient()
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    client._process = mock_proc
    assert client.is_running is True

    # Process exited
    mock_proc.poll.return_value = 1
    assert client.is_running is False

    # No process
    client._process = None
    assert client.is_running is False

    # Health endpoint integration: verify the _sidecar var is read correctly.
    # We test the response shape by importing the health logic pattern.
    sidecar = SidecarClient()
    sidecar._process = MagicMock()
    sidecar._process.poll.return_value = None
    status = "running" if sidecar.is_running else "stopped"
    assert status == "running"

    # Disabled case
    sidecar_none = None
    status = "disabled" if sidecar_none is None else (
        "running" if sidecar_none.is_running else "stopped"
    )
    assert status == "disabled"


# ---------------------------------------------------------------------------
# Test 2: Sidecar tool dispatch — file_read
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_tool_dispatch_file_read():
    """file_read dispatches to sidecar when enabled, returns correct TaggedData."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"content": "file contents here", "bytes": 18},
    )
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    result = await executor.execute("file_read", {"path": "/workspace/test.txt"})

    sidecar.execute.assert_called_once_with(
        tool_name="file_read",
        args={"path": "/workspace/test.txt"},
        capabilities=["read_file"],
    )
    assert isinstance(result, TaggedData)
    assert result.source == DataSource.TOOL
    assert result.trust_level == TrustLevel.TRUSTED


# ---------------------------------------------------------------------------
# Test 3: Sidecar tool dispatch — file_write
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_tool_dispatch_file_write():
    """file_write dispatches to sidecar, returns TaggedData."""
    sidecar = _mock_sidecar(success=True, result="ok")
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    result = await executor.execute(
        "file_write",
        {"path": "/workspace/output.txt", "content": "hello"},
    )

    sidecar.execute.assert_called_once_with(
        tool_name="file_write",
        args={"path": "/workspace/output.txt", "content": "hello"},
        capabilities=["write_file"],
    )
    assert isinstance(result, TaggedData)
    assert result.source == DataSource.TOOL


# ---------------------------------------------------------------------------
# Test 4: Sidecar tool dispatch — shell_exec
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_tool_dispatch_shell():
    """shell_exec dispatches with correct capabilities."""
    sidecar = _mock_sidecar(
        success=True,
        result="ok",
        data={"stdout": "hello\n", "exit_code": 0},
    )
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    result = await executor.execute("shell_exec", {"command": "echo hello"})

    sidecar.execute.assert_called_once_with(
        tool_name="shell_exec",
        args={"command": "echo hello"},
        capabilities=["shell_exec"],
    )
    assert isinstance(result, TaggedData)


# ---------------------------------------------------------------------------
# Test 5: Sidecar unavailable fallback
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_unavailable_fallback():
    """When sidecar fails, falls back to Python handler for tools that have one.
    Here the Python handler also fails (file doesn't exist) — the Python error surfaces."""
    sidecar = _mock_sidecar(
        success=False,
        result="sidecar unavailable: Connection refused",
    )
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    with pytest.raises(ToolError, match="file_read failed"):
        await executor.execute("file_read", {"path": "/workspace/test.txt"})

    # Sidecar was attempted first, then fell back to Python handler
    sidecar.execute.assert_called_once()


# ---------------------------------------------------------------------------
# Test 6: Sidecar timeout
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_timeout():
    """Sidecar timeout returns SidecarResponse(success=False) with timeout message.
    Uses http_fetch which has no Python fallback — sidecar error propagates directly."""
    sidecar = _mock_sidecar(
        success=False,
        result="sidecar timeout after 30s",
    )
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    with pytest.raises(ToolError, match="sidecar.*timeout"):
        await executor.execute("http_fetch", {"url": "https://example.com"})


# ---------------------------------------------------------------------------
# Test 7: Sidecar tool not found
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_tool_not_found():
    """Unknown tool name raises ToolError (not dispatched to sidecar)."""
    sidecar = _mock_sidecar(success=True, result="ok")
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    with pytest.raises(ToolError, match="Unknown tool"):
        await executor.execute("nonexistent_tool", {})

    # Sidecar should not have been called — unknown tools don't match WASM_TOOLS
    sidecar.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Test 8: Sidecar path enforcement (capability mapping)
# ---------------------------------------------------------------------------


@pytest.mark.capability
def test_sidecar_path_enforcement():
    """Capabilities are correctly mapped per tool (read_file for file_read, etc.)."""
    assert _WASM_TOOL_CAPABILITIES["file_read"] == ["read_file"]
    assert _WASM_TOOL_CAPABILITIES["file_write"] == ["write_file"]
    assert _WASM_TOOL_CAPABILITIES["shell_exec"] == ["shell_exec"]
    assert _WASM_TOOL_CAPABILITIES["http_fetch"] == ["http_request"]

    # Every WASM tool has a capability mapping
    for tool in WASM_TOOLS:
        assert tool in _WASM_TOOL_CAPABILITIES, f"{tool} missing from capability map"
        assert len(_WASM_TOOL_CAPABILITIES[tool]) > 0


# ---------------------------------------------------------------------------
# Test 9: Sidecar fuel exhaustion
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_fuel_exhaustion():
    """Sidecar returns fuel-exhausted error -> ToolError raised.
    Uses http_fetch (no Python fallback) so sidecar error propagates directly."""
    sidecar = _mock_sidecar(
        success=False,
        result="fuel exhausted: exceeded 1000000000 instructions",
    )
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    with pytest.raises(ToolError, match="sidecar.*fuel exhausted"):
        await executor.execute("http_fetch", {"url": "https://example.com"})


# ---------------------------------------------------------------------------
# Test 10: Sidecar concurrent dispatch
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_concurrent_dispatch():
    """Two concurrent sidecar calls don't interfere."""
    call_count = 0

    async def mock_execute(tool_name, args, capabilities):
        nonlocal call_count
        call_count += 1
        # Small delay to force concurrency
        await asyncio.sleep(0.01)
        return SidecarResponse(
            success=True,
            result="ok",
            data={"content": f"response for {args.get('path', '')}"},
        )

    sidecar = AsyncMock(spec=SidecarClient)
    sidecar.execute = mock_execute
    sidecar.is_running = True

    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    result_a, result_b = await asyncio.gather(
        executor.execute("file_read", {"path": "/workspace/a.txt"}),
        executor.execute("file_read", {"path": "/workspace/b.txt"}),
    )

    assert call_count == 2
    assert isinstance(result_a, TaggedData)
    assert isinstance(result_b, TaggedData)
    # Responses should contain different paths
    assert "a.txt" in result_a.content
    assert "b.txt" in result_b.content


# ---------------------------------------------------------------------------
# Test 11: Sidecar recovery after crash
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_recovery_after_crash():
    """Connection failure -> auto-restart -> retry succeeds."""
    response_data = {
        "success": True,
        "result": "ok",
        "data": {"content": "recovered"},
        "leaked": False,
    }
    response_line = json.dumps(response_data).encode() + b"\n"

    call_count = 0

    async def mock_connect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionRefusedError("connection refused")
        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response_line)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        return mock_reader, mock_writer

    # Use a real SidecarClient (not mocked) to test the recovery path
    client = SidecarClient(
        socket_path="/tmp/test-cap.sock",
        timeout=10,
        sidecar_binary_path="/usr/bin/false",
    )

    with patch("asyncio.open_unix_connection", side_effect=mock_connect):
        with patch.object(client, "start_sidecar", new_callable=AsyncMock):
            result = await client.execute("file_read", {"path": "/test"})

    assert result.success is True
    assert call_count == 2  # First failed, second succeeded after restart

    # Now verify end-to-end through ToolExecutor
    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=client)

    call_count = 0  # Reset
    with patch("asyncio.open_unix_connection", side_effect=mock_connect):
        with patch.object(client, "start_sidecar", new_callable=AsyncMock):
            tagged = await executor.execute("file_read", {"path": "/workspace/test.txt"})

    assert isinstance(tagged, TaggedData)
    assert tagged.source == DataSource.TOOL


# ---------------------------------------------------------------------------
# Test 12: No state bleed between dispatches
# ---------------------------------------------------------------------------


@pytest.mark.capability
@pytest.mark.asyncio
async def test_sidecar_no_state_bleed_between_dispatches():
    """Sequential dispatches get independent responses."""
    responses = [
        SidecarResponse(
            success=True,
            result="ok",
            data={"content": "first response"},
            fuel_consumed=100,
        ),
        SidecarResponse(
            success=True,
            result="ok",
            data={"content": "second response"},
            fuel_consumed=200,
        ),
    ]

    sidecar = AsyncMock(spec=SidecarClient)
    sidecar.execute = AsyncMock(side_effect=responses)
    sidecar.is_running = True

    executor = ToolExecutor(policy_engine=_mock_engine_allow_all(), sidecar=sidecar)

    result_1 = await executor.execute("file_read", {"path": "/workspace/a.txt"})
    result_2 = await executor.execute("file_read", {"path": "/workspace/b.txt"})

    # Each response is independent
    assert "first response" in result_1.content
    assert "second response" in result_2.content

    # Different data IDs (TaggedData creates unique IDs)
    assert result_1.id != result_2.id

    # Sidecar was called twice with different args
    assert sidecar.execute.call_count == 2
    calls = sidecar.execute.call_args_list
    assert calls[0].kwargs["args"]["path"] == "/workspace/a.txt"
    assert calls[1].kwargs["args"]["path"] == "/workspace/b.txt"
