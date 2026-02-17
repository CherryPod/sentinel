"""Sidecar security tests — Python client-side handling of adversarial inputs.

Verifies:
- Path traversal sequences in tool args are passed through (sidecar enforces)
- Null bytes in args don't crash the client
- Socket path not leaked in error messages
- Timeout produces a clean SidecarResponse, not an unhandled exception
- Fuel exhaustion field correctly parsed from sidecar JSON responses
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.tools.sidecar import SidecarClient, SidecarResponse


# ── Helpers ──────────────────────────────────────────────────────────


def _make_mock_socket(response_data: dict):
    """Create mock reader/writer that returns the given JSON response."""
    response_line = json.dumps(response_data).encode() + b"\n"

    mock_reader = AsyncMock()
    mock_reader.readline = AsyncMock(return_value=response_line)
    mock_writer = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    return mock_reader, mock_writer


# ── Tests ────────────────────────────────────────────────────────────


class TestSidecarSecurity:

    @pytest.mark.asyncio
    async def test_path_traversal_in_tool_args(self):
        """Tool args containing '../' sequences should be passed to the sidecar.

        The Python client intentionally does NOT filter path traversal —
        that's the Rust sidecar's responsibility (defence in depth). The
        client's job is faithful serialization; the sidecar enforces path
        containment within /workspace/.
        """
        client = SidecarClient(socket_path="/tmp/test-security.sock", timeout=5)

        # Sidecar would reject this, but we mock a success to verify the
        # client transmits the args faithfully without mangling them
        response_data = {
            "success": False,
            "result": "path traversal denied: ../../../../etc/passwd",
            "leaked": False,
        }
        mock_reader, mock_writer = _make_mock_socket(response_data)

        sent_data = None
        original_write = mock_writer.write

        def capture_write(data):
            nonlocal sent_data
            sent_data = data
            return original_write(data)

        mock_writer.write = capture_write

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            result = await client.execute(
                "file_read",
                {"path": "../../../../etc/passwd"},
                capabilities=["read_file"],
            )

        # Client should pass the args through without filtering
        assert sent_data is not None
        request_json = json.loads(sent_data.decode())
        assert "../../../../etc/passwd" in request_json["args"]["path"]

        # The (mocked) sidecar rejected it
        assert result.success is False
        assert "path traversal" in result.result

    @pytest.mark.asyncio
    async def test_null_bytes_in_tool_args(self):
        """Null bytes in args don't crash the client.

        Null byte injection is a classic attack against C-based path
        handling. The Python client should serialize these without error;
        the sidecar (Rust) handles them safely.
        """
        client = SidecarClient(socket_path="/tmp/test-security.sock", timeout=5)

        response_data = {
            "success": False,
            "result": "invalid argument",
            "leaked": False,
        }
        mock_reader, mock_writer = _make_mock_socket(response_data)

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            # This should not raise — null bytes are valid in JSON strings
            result = await client.execute(
                "file_read",
                {"path": "/workspace/test\x00.txt", "extra": "a\x00b"},
                capabilities=["read_file"],
            )

        # Client should have completed without crashing
        assert isinstance(result, SidecarResponse)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_socket_path_not_in_error(self):
        """When connection fails, the error message doesn't leak the socket path.

        The socket path is an internal implementation detail. Exposing it in
        error messages could help an attacker understand the system layout.
        """
        secret_socket_path = "/var/run/sentinel/secret-internal-path.sock"
        client = SidecarClient(
            socket_path=secret_socket_path,
            timeout=5,
            sidecar_binary_path="/usr/bin/fake-sidecar",
        )

        # Simulate connection failure — both initial and retry attempts fail.
        # Mock start_sidecar so it doesn't actually try to spawn a binary.
        with patch(
            "asyncio.open_unix_connection",
            side_effect=ConnectionRefusedError("connection refused"),
        ), patch.object(client, "start_sidecar", new_callable=AsyncMock):
            result = await client.execute(
                "file_read",
                {"path": "/workspace/test.txt"},
            )

        # The result should indicate failure but not expose the socket path
        assert result.success is False
        assert secret_socket_path not in result.result, (
            f"Socket path leaked in error message: {result.result}"
        )

    @pytest.mark.asyncio
    async def test_timeout_gives_clean_error(self):
        """Timeout produces a clean SidecarResponse, not a stack trace.

        The client wraps asyncio.wait_for around the socket call. On timeout,
        it should return a structured SidecarResponse(success=False) rather
        than letting TimeoutError propagate up the call stack.
        """
        client = SidecarClient(socket_path="/tmp/test-security.sock", timeout=1)

        async def slow_connect(*args, **kwargs):
            # Simulate a hung sidecar — never returns
            await asyncio.sleep(60)

        with patch("asyncio.open_unix_connection", side_effect=slow_connect):
            result = await client.execute(
                "shell_exec",
                {"command": "long-running-command"},
                capabilities=["shell_exec"],
            )

        # Should be a clean response, not an exception
        assert isinstance(result, SidecarResponse)
        assert result.success is False
        assert "timeout" in result.result.lower()
        # Should include the timeout value for debugging
        assert "1s" in result.result

    @pytest.mark.asyncio
    async def test_fuel_exhaustion_parsed(self):
        """A response with fuel_consumed field is correctly parsed.

        The WASM sidecar uses fuel metering to limit computation. When a tool
        exhausts its fuel budget, the sidecar returns the amount consumed.
        The Python client must parse this field correctly for audit logging.
        """
        client = SidecarClient(socket_path="/tmp/test-security.sock", timeout=5)

        response_data = {
            "success": False,
            "result": "fuel exhausted after 1000000000 instructions",
            "data": None,
            "leaked": False,
            "fuel_consumed": 1_000_000_000,
        }
        mock_reader, mock_writer = _make_mock_socket(response_data)

        with patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer)):
            result = await client.execute(
                "shell_exec",
                {"command": "while true; do :; done"},
                capabilities=["shell_exec"],
            )

        assert isinstance(result, SidecarResponse)
        assert result.success is False
        assert result.fuel_consumed == 1_000_000_000
        assert "fuel" in result.result.lower()
        assert result.leaked is False
