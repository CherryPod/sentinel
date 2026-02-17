"""Tests for the SidecarClient and WASM tool integration.

Tests use mock Unix sockets — no real sidecar binary needed.
"""

import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.tools.sidecar import SidecarClient, SidecarResponse


# ── SidecarResponse Tests ────────────────────────────────────────────────


class TestSidecarResponse:
    def test_success_response(self):
        resp = SidecarResponse(success=True, result="ok", data={"content": "hello"})
        assert resp.success is True
        assert resp.result == "ok"
        assert resp.data == {"content": "hello"}
        assert resp.leaked is False
        assert resp.fuel_consumed is None

    def test_error_response(self):
        resp = SidecarResponse(success=False, result="capability denied")
        assert resp.success is False
        assert resp.result == "capability denied"
        assert resp.data is None

    def test_leaked_response(self):
        resp = SidecarResponse(
            success=True,
            result="[REDACTED:aws_access_key]",
            leaked=True,
            fuel_consumed=42000,
        )
        assert resp.leaked is True
        assert resp.fuel_consumed == 42000

    def test_default_values(self):
        resp = SidecarResponse(success=True, result="ok")
        assert resp.data is None
        assert resp.leaked is False
        assert resp.fuel_consumed is None


# ── SidecarClient Unit Tests ─────────────────────────────────────────────


class TestSidecarClientInit:
    def test_default_config(self):
        client = SidecarClient()
        assert client._socket_path == "/tmp/sentinel-sidecar.sock"
        assert client._timeout == 30
        assert client._binary_path == ""
        assert client._process is None

    def test_custom_config(self):
        client = SidecarClient(
            socket_path="/custom/path.sock",
            timeout=60,
            sidecar_binary_path="/usr/local/bin/sidecar",
            tool_dir="/tools",
        )
        assert client._socket_path == "/custom/path.sock"
        assert client._timeout == 60
        assert client._binary_path == "/usr/local/bin/sidecar"
        assert client._tool_dir == "/tools"

    def test_is_running_no_process(self):
        client = SidecarClient()
        assert client.is_running is False

    def test_is_running_with_process(self):
        client = SidecarClient()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Still running
        client._process = mock_proc
        assert client.is_running is True

    def test_is_running_exited_process(self):
        client = SidecarClient()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0  # Exited
        client._process = mock_proc
        assert client.is_running is False


# ── SidecarClient._send_request Tests (mock socket) ─────────────────────


class TestSidecarClientSendRequest:
    @pytest.mark.asyncio
    async def test_successful_request(self):
        """Mock the Unix socket connection to test request/response flow."""
        client = SidecarClient(socket_path="/tmp/test.sock")

        response_data = {
            "success": True,
            "result": "ok",
            "data": {"content": "hello world", "bytes": 11},
            "leaked": False,
            "fuel_consumed": 5000,
        }
        response_line = json.dumps(response_data).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response_line)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            request = {
                "request_id": "test-1",
                "tool_name": "file_read",
                "args": {"path": "/workspace/test.txt"},
                "capabilities": ["read_file"],
                "credentials": {},
            }
            result = await client._send_request(request)

        assert result.success is True
        assert result.result == "ok"
        assert result.data == {"content": "hello world", "bytes": 11}
        assert result.fuel_consumed == 5000
        assert result.leaked is False

    @pytest.mark.asyncio
    async def test_error_response(self):
        client = SidecarClient(socket_path="/tmp/test.sock")

        response_data = {
            "success": False,
            "result": "unknown tool: nonexistent",
            "leaked": False,
        }
        response_line = json.dumps(response_data).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response_line)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            request = {
                "request_id": "test-2",
                "tool_name": "nonexistent",
                "args": {},
                "capabilities": [],
                "credentials": {},
            }
            result = await client._send_request(request)

        assert result.success is False
        assert "unknown tool" in result.result

    @pytest.mark.asyncio
    async def test_connection_closed(self):
        """Server closes connection before sending response."""
        client = SidecarClient(socket_path="/tmp/test.sock")

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=b"")  # EOF
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            with pytest.raises(ConnectionError, match="sidecar closed connection"):
                await client._send_request({
                    "request_id": "test-3",
                    "tool_name": "file_read",
                    "args": {},
                    "capabilities": [],
                    "credentials": {},
                })

    @pytest.mark.asyncio
    async def test_leaked_response(self):
        client = SidecarClient(socket_path="/tmp/test.sock")

        response_data = {
            "success": True,
            "result": "ok",
            "data": {"content": "[REDACTED:aws_access_key]"},
            "leaked": True,
            "fuel_consumed": 8000,
        }
        response_line = json.dumps(response_data).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response_line)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            result = await client._send_request({
                "request_id": "test-4",
                "tool_name": "file_read",
                "args": {"path": "/workspace/secret.txt"},
                "capabilities": ["read_file"],
                "credentials": {},
            })

        assert result.leaked is True
        assert "[REDACTED" in result.data["content"]


# ── SidecarClient.execute Tests ──────────────────────────────────────────


class TestSidecarClientExecute:
    @pytest.mark.asyncio
    async def test_execute_success(self):
        client = SidecarClient(socket_path="/tmp/test.sock", timeout=10)

        response_data = {
            "success": True,
            "result": "ok",
            "data": {"content": "test"},
            "leaked": False,
        }
        response_line = json.dumps(response_data).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response_line)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            result = await client.execute("file_read", {"path": "/workspace/test.txt"}, ["read_file"])

        assert result.success is True

    @pytest.mark.asyncio
    async def test_execute_timeout(self):
        client = SidecarClient(socket_path="/tmp/test.sock", timeout=1)

        async def slow_connect(*args, **kwargs):
            await asyncio.sleep(10)

        with patch("asyncio.open_unix_connection", side_effect=slow_connect):
            result = await client.execute("file_read", {"path": "/workspace/test.txt"})

        assert result.success is False
        assert "timeout" in result.result

    @pytest.mark.asyncio
    async def test_execute_crash_recovery(self):
        """On first connection failure, restart sidecar and retry."""
        client = SidecarClient(
            socket_path="/tmp/test.sock",
            timeout=10,
            sidecar_binary_path="/usr/bin/false",
        )

        response_data = {
            "success": True,
            "result": "ok",
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

        with patch("asyncio.open_unix_connection", side_effect=mock_connect):
            with patch.object(client, "start_sidecar", new_callable=AsyncMock):
                result = await client.execute("file_read", {"path": "/test"})

        assert result.success is True
        assert call_count == 2  # First attempt failed, second succeeded

    @pytest.mark.asyncio
    async def test_execute_with_credentials(self):
        client = SidecarClient(socket_path="/tmp/test.sock")

        response_data = {
            "success": True,
            "result": "ok",
            "leaked": False,
        }
        response_line = json.dumps(response_data).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response_line)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        sent_data = None

        async def capture_connect(*args, **kwargs):
            return mock_reader, mock_writer

        original_write = mock_writer.write

        with patch("asyncio.open_unix_connection", side_effect=capture_connect):
            result = await client.execute(
                "http_fetch",
                {"url": "https://api.example.com"},
                capabilities=["http_request", "use_credential"],
                credentials={"api_key": "secret123"},
                http_allowlist=["*.example.com"],
            )

        assert result.success is True

    @pytest.mark.asyncio
    async def test_execute_with_timeout_override(self):
        client = SidecarClient(socket_path="/tmp/test.sock", timeout=30)

        response_data = {"success": True, "result": "ok", "leaked": False}
        response_line = json.dumps(response_data).encode() + b"\n"

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=response_line)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            result = await client.execute(
                "shell_exec",
                {"command": "long-running-command"},
                capabilities=["shell_exec"],
                timeout=60,
            )

        assert result.success is True


# ── SidecarClient Start/Stop Tests ───────────────────────────────────────


class TestSidecarClientLifecycle:
    @pytest.mark.asyncio
    async def test_start_sidecar_no_binary(self):
        client = SidecarClient(sidecar_binary_path="")
        with pytest.raises(RuntimeError, match="no sidecar binary path configured"):
            await client.start_sidecar()

    @pytest.mark.asyncio
    async def test_stop_sidecar_no_process(self):
        """Stopping when no process is running should be a no-op."""
        client = SidecarClient()
        await client.stop_sidecar()  # Should not raise

    @pytest.mark.asyncio
    async def test_stop_sidecar_with_process(self):
        client = SidecarClient()
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        client._process = mock_proc

        await client.stop_sidecar()

        mock_proc.send_signal.assert_called_once()
        assert client._process is None


# ── ToolExecutor WASM Dispatch Tests ─────────────────────────────────────


class TestToolExecutorWasmDispatch:
    @pytest.mark.asyncio
    async def test_wasm_tool_dispatched_to_sidecar(self):
        """When sidecar is configured, WASM tools go to sidecar."""
        from sentinel.tools.executor import ToolExecutor, WASM_TOOLS
        from sentinel.security.policy_engine import PolicyEngine

        mock_sidecar = AsyncMock(spec=SidecarClient)
        mock_sidecar.execute = AsyncMock(return_value=SidecarResponse(
            success=True,
            result="ok",
            data={"content": "hello", "bytes": 5},
        ))

        engine = PolicyEngine.__new__(PolicyEngine)
        executor = ToolExecutor(engine, sidecar=mock_sidecar)

        result = await executor.execute("file_read", {"path": "/workspace/test.txt"})

        mock_sidecar.execute.assert_called_once()
        assert result.content  # TaggedData should have content
        assert result.source.value == "tool"

    @pytest.mark.asyncio
    async def test_non_wasm_tool_uses_python_handler(self):
        """Non-WASM tools (mkdir) should use the Python handler, not sidecar."""
        from sentinel.tools.executor import ToolExecutor
        from sentinel.security.policy_engine import PolicyEngine

        mock_sidecar = AsyncMock(spec=SidecarClient)
        engine = MagicMock(spec=PolicyEngine)

        # Make the policy check pass
        from sentinel.core.models import PolicyResult as PR
        mock_result = MagicMock()
        mock_result.status = PR.ALLOWED
        engine.check_file_write.return_value = mock_result

        executor = ToolExecutor(engine, sidecar=mock_sidecar)

        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = os.path.join(tmpdir, "test_subdir")
            result = await executor.execute("mkdir", {"path": test_path})

        # Sidecar should NOT have been called for mkdir
        mock_sidecar.execute.assert_not_called()
        assert result.content  # Should still work

    @pytest.mark.asyncio
    async def test_no_sidecar_uses_python_handler(self):
        """When no sidecar is configured, WASM tools use Python handlers."""
        from sentinel.tools.executor import ToolExecutor
        from sentinel.security.policy_engine import PolicyEngine
        from sentinel.core.models import PolicyResult as PR

        engine = MagicMock(spec=PolicyEngine)
        mock_result = MagicMock()
        mock_result.status = PR.ALLOWED
        engine.check_file_read.return_value = mock_result

        # No sidecar — executor should fall through to Python handler
        executor = ToolExecutor(engine, sidecar=None)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content")
            f.flush()
            try:
                result = await executor.execute("file_read", {"path": f.name})
                assert "test content" in result.content
            finally:
                os.unlink(f.name)

    @pytest.mark.asyncio
    async def test_sidecar_failure_raises_tool_error(self):
        """SidecarResponse failure should raise ToolError."""
        from sentinel.tools.executor import ToolExecutor, ToolError
        from sentinel.security.policy_engine import PolicyEngine

        mock_sidecar = AsyncMock(spec=SidecarClient)
        mock_sidecar.execute = AsyncMock(return_value=SidecarResponse(
            success=False,
            result="capability denied: ReadFile",
        ))

        engine = PolicyEngine.__new__(PolicyEngine)
        executor = ToolExecutor(engine, sidecar=mock_sidecar)

        with pytest.raises(ToolError, match="sidecar.*capability denied"):
            await executor.execute("file_read", {"path": "/workspace/test.txt"})

    @pytest.mark.asyncio
    async def test_sidecar_leak_logged(self):
        """Leaked credentials should still return success but with a warning."""
        from sentinel.tools.executor import ToolExecutor
        from sentinel.security.policy_engine import PolicyEngine

        mock_sidecar = AsyncMock(spec=SidecarClient)
        mock_sidecar.execute = AsyncMock(return_value=SidecarResponse(
            success=True,
            result="ok",
            data={"content": "[REDACTED:aws_access_key]"},
            leaked=True,
            fuel_consumed=5000,
        ))

        engine = PolicyEngine.__new__(PolicyEngine)
        executor = ToolExecutor(engine, sidecar=mock_sidecar)

        result = await executor.execute("file_read", {"path": "/workspace/secrets.txt"})
        # Should succeed — leak was already redacted by sidecar
        assert result.content

    @pytest.mark.asyncio
    async def test_wasm_tool_set_is_correct(self):
        """Verify the WASM_TOOLS constant has the expected tools."""
        from sentinel.tools.executor import WASM_TOOLS
        assert "file_read" in WASM_TOOLS
        assert "file_write" in WASM_TOOLS
        assert "shell_exec" in WASM_TOOLS
        assert "http_fetch" in WASM_TOOLS
        assert "mkdir" not in WASM_TOOLS
        assert "podman_build" not in WASM_TOOLS


# ── Config Tests ─────────────────────────────────────────────────────────


class TestSidecarConfig:
    def test_sidecar_config_defaults(self):
        from sentinel.core.config import Settings
        s = Settings()
        assert s.sidecar_enabled is False
        assert s.sidecar_socket == "/tmp/sentinel-sidecar.sock"
        assert s.sidecar_timeout == 30
        assert s.sidecar_tool_dir == "./sidecar/wasm"

    def test_sidecar_config_env_override(self):
        from sentinel.core.config import Settings
        with patch.dict(os.environ, {
            "SENTINEL_SIDECAR_ENABLED": "true",
            "SENTINEL_SIDECAR_SOCKET": "/custom/path.sock",
            "SENTINEL_SIDECAR_TIMEOUT": "60",
        }):
            s = Settings()
        assert s.sidecar_enabled is True
        assert s.sidecar_socket == "/custom/path.sock"
        assert s.sidecar_timeout == 60
