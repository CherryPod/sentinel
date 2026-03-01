"""Tests for Signal channel — all using mocked I/O (no signal-cli needed).

Tests cover: daemon mode subprocess args, Unix socket connect/retry/close,
socket-based send/receive, health monitor with ping detection, crash recovery
with socket reconnect, and all existing backoff/config/formatting tests.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.channels.signal_channel import (
    ExponentialBackoff,
    SignalChannel,
    SignalConfig,
)
from sentinel.channels.base import OutgoingMessage
from sentinel.core.bus import EventBus


# ── Shared test helpers ────────────────────────────────────────────


class FakeProcess:
    """Mock asyncio subprocess for testing (no stdin/stdout needed for socket mode)."""

    def __init__(self, *, returncode=None):
        self.pid = 12345
        self.returncode = returncode
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self._terminated = False
        self._killed = False

    def terminate(self):
        self._terminated = True
        self.returncode = -15

    def kill(self):
        self._killed = True
        self.returncode = -9

    async def wait(self):
        return self.returncode


class FakeSocketReader:
    """Mock asyncio.StreamReader backed by an asyncio.Queue."""

    def __init__(self):
        self._lines: asyncio.Queue = asyncio.Queue()

    def push_line(self, data):
        """Push a line for readline() to return."""
        if isinstance(data, dict):
            data = json.dumps(data).encode() + b"\n"
        elif isinstance(data, str):
            data = data.encode() + b"\n"
        self._lines.put_nowait(data)

    def push_eof(self):
        """Signal EOF (empty bytes)."""
        self._lines.put_nowait(b"")

    async def readline(self):
        return await self._lines.get()


class FakeSocketWriter:
    """Mock asyncio.StreamWriter that records writes."""

    def __init__(self):
        self.written: list[bytes] = []
        self._closed = False
        self._fail_on_write = False

    def write(self, data: bytes):
        if self._fail_on_write:
            raise ConnectionResetError("socket closed")
        self.written.append(data)

    async def drain(self):
        if self._fail_on_write:
            raise ConnectionResetError("socket closed")

    def close(self):
        self._closed = True

    async def wait_closed(self):
        pass


def _make_receive_notification(source: str, message: str) -> dict:
    """Build a signal-cli JSON-RPC receive notification."""
    return {
        "jsonrpc": "2.0",
        "method": "receive",
        "params": {
            "envelope": {
                "source": source,
                "timestamp": 1000,
                "dataMessage": {"message": message},
            },
        },
    }


# ── ExponentialBackoff tests ──────────────────────────────────────


class TestExponentialBackoff:
    def test_initial_delay(self):
        """First delay is the base value."""
        b = ExponentialBackoff(base=1.0, max_delay=300.0)
        assert b.next_delay() == 1.0

    def test_delays_double(self):
        """Delays double with each attempt."""
        b = ExponentialBackoff(base=1.0, max_delay=300.0)
        assert b.next_delay() == 1.0
        assert b.next_delay() == 2.0
        assert b.next_delay() == 4.0
        assert b.next_delay() == 8.0

    def test_caps_at_max(self):
        """Delays cap at max_delay."""
        b = ExponentialBackoff(base=1.0, max_delay=5.0)
        b.next_delay()  # 1
        b.next_delay()  # 2
        b.next_delay()  # 4
        d = b.next_delay()  # would be 8, capped to 5
        assert d == 5.0

    def test_reset(self):
        """reset() brings delay back to base."""
        b = ExponentialBackoff(base=1.0, max_delay=300.0)
        b.next_delay()
        b.next_delay()
        b.next_delay()
        b.reset()
        assert b.next_delay() == 1.0

    def test_custom_base(self):
        """Custom base value is respected."""
        b = ExponentialBackoff(base=2.0, max_delay=300.0)
        assert b.next_delay() == 2.0
        assert b.next_delay() == 4.0

    def test_attempt_count(self):
        """attempt property tracks the count."""
        b = ExponentialBackoff()
        assert b.attempt == 0
        b.next_delay()
        assert b.attempt == 1
        b.next_delay()
        assert b.attempt == 2
        b.reset()
        assert b.attempt == 0


# ── SignalConfig tests ────────────────────────────────────────────


class TestSignalConfig:
    def test_defaults(self):
        """Default config values including new socket-mode fields."""
        cfg = SignalConfig()
        assert cfg.signal_cli_path == "/usr/local/bin/signal-cli"
        assert cfg.signal_cli_config == "/app/signal-data"
        assert cfg.socket_path == "/tmp/signal.sock"
        assert cfg.account == ""
        assert cfg.trust_all_known is False

    def test_custom_values(self):
        """Custom config values."""
        cfg = SignalConfig(
            signal_cli_path="/opt/bin/signal-cli",
            signal_cli_config="/data/signal",
            socket_path="/run/signal.sock",
            account="+1234567890",
            trust_all_known=True,
        )
        assert cfg.account == "+1234567890"
        assert cfg.signal_cli_config == "/data/signal"
        assert cfg.socket_path == "/run/signal.sock"


# ── SignalChannel tests ───────────────────────────────────────────


class TestSignalChannelStart:
    async def test_start_creates_subprocess_daemon_mode(self):
        """start() launches signal-cli in daemon mode with socket arg."""
        cfg = SignalConfig(account="+1234567890")
        channel = SignalChannel(cfg)

        proc = FakeProcess()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc) as mock_exec:
            with patch.object(channel, "_connect_socket", new_callable=AsyncMock):
                with patch.object(channel, "_read_loop", new_callable=AsyncMock):
                    with patch.object(channel, "_health_monitor", new_callable=AsyncMock):
                        await channel.start()

        assert channel._process is proc
        assert channel._running is True

        # Verify daemon mode args
        call_args = mock_exec.call_args[0]
        assert call_args[0] == cfg.signal_cli_path
        assert "--config" in call_args
        assert cfg.signal_cli_config in call_args
        assert "-u" in call_args
        assert "+1234567890" in call_args
        assert "daemon" in call_args
        assert "--socket" in call_args
        assert cfg.socket_path in call_args

    async def test_start_without_account(self):
        """start() omits -u flag when no account is configured."""
        cfg = SignalConfig(account="")
        channel = SignalChannel(cfg)

        proc = FakeProcess()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc) as mock_exec:
            with patch.object(channel, "_connect_socket", new_callable=AsyncMock):
                with patch.object(channel, "_read_loop", new_callable=AsyncMock):
                    with patch.object(channel, "_health_monitor", new_callable=AsyncMock):
                        await channel.start()

        call_args = mock_exec.call_args[0]
        assert "-u" not in call_args
        assert "daemon" in call_args


class TestSignalChannelConnectSocket:
    async def test_connect_socket_success(self):
        """_connect_socket connects on first try."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._running = True

        reader = FakeSocketReader()
        writer = FakeSocketWriter()

        with patch("asyncio.open_unix_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            await channel._connect_socket()

        assert channel._reader is reader
        assert channel._writer is writer

    async def test_connect_socket_retries_on_file_not_found(self):
        """_connect_socket retries when socket file doesn't exist yet."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._running = True
        # Use a short timeout for testing
        channel._SOCKET_CONNECT_TIMEOUT = 2.0

        reader = FakeSocketReader()
        writer = FakeSocketWriter()

        call_count = 0

        async def mock_connect(path):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise FileNotFoundError("socket not ready yet")
            return (reader, writer)

        with patch("asyncio.open_unix_connection", side_effect=mock_connect):
            with patch("sentinel.channels.signal_channel.asyncio.sleep", new_callable=AsyncMock):
                await channel._connect_socket()

        assert call_count == 3
        assert channel._reader is reader
        assert channel._writer is writer

    async def test_connect_socket_timeout(self):
        """_connect_socket gives up after timeout."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._running = True
        channel._SOCKET_CONNECT_TIMEOUT = 0.1  # Very short for test

        with patch("asyncio.open_unix_connection", new_callable=AsyncMock, side_effect=FileNotFoundError):
            await channel._connect_socket()

        assert channel._reader is None
        assert channel._writer is None


class TestSignalChannelCloseSocket:
    async def test_close_socket(self):
        """_close_socket closes writer and clears references."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        writer = FakeSocketWriter()
        reader = FakeSocketReader()
        channel._writer = writer
        channel._reader = reader

        await channel._close_socket()

        assert writer._closed is True
        assert channel._writer is None
        assert channel._reader is None

    async def test_close_socket_when_already_none(self):
        """_close_socket is a no-op when socket is already closed."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._writer = None
        channel._reader = None

        # Should not raise
        await channel._close_socket()


class TestSignalChannelStop:
    async def test_stop_closes_socket_then_terminates(self):
        """stop() closes socket before terminating process."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        writer = FakeSocketWriter()
        reader = FakeSocketReader()
        channel._process = proc
        channel._writer = writer
        channel._reader = reader
        channel._running = True

        await channel.stop()

        assert writer._closed is True
        assert channel._writer is None
        assert channel._reader is None
        assert proc._terminated is True
        assert channel._running is False
        assert channel._process is None


class TestSignalChannelSend:
    async def test_send_writes_jsonrpc_to_socket(self):
        """send() writes a JSON-RPC request to the Unix socket."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        writer = FakeSocketWriter()
        channel._writer = writer

        msg = OutgoingMessage(
            channel_id="+1234567890",
            event_type="task.completed",
            data={"status": "success"},
        )
        await channel.send(msg)

        assert len(writer.written) == 1
        rpc = json.loads(writer.written[0].decode())
        assert rpc["jsonrpc"] == "2.0"
        assert rpc["method"] == "send"
        assert rpc["params"]["recipient"] == "+1234567890"

    async def test_send_without_socket(self):
        """send() logs warning when socket is not connected."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._writer = None

        msg = OutgoingMessage(channel_id="+1", event_type="test", data={})
        # Should not raise
        await channel.send(msg)

    async def test_send_handles_write_error(self):
        """send() handles socket write errors gracefully."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        writer = FakeSocketWriter()
        writer._fail_on_write = True
        channel._writer = writer

        msg = OutgoingMessage(
            channel_id="+1",
            event_type="test",
            data={"response": "test"},
        )
        # Should not raise
        await channel.send(msg)


class TestSignalChannelReadLoop:
    async def test_incoming_message_queued(self):
        """_read_loop parses signal-cli notifications and queues messages."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        reader = FakeSocketReader()
        channel._reader = reader
        channel._running = True

        reader.push_line(_make_receive_notification("+1234567890", "Hello Sentinel"))
        reader.push_eof()

        await channel._read_loop()

        assert channel._message_queue.qsize() == 1
        msg = channel._message_queue.get_nowait()
        assert msg.content == "Hello Sentinel"
        assert msg.channel_id == "+1234567890"
        assert msg.source == "signal"

    async def test_malformed_json_handled(self):
        """_read_loop handles malformed JSON without crashing."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        reader = FakeSocketReader()
        channel._reader = reader
        channel._running = True

        reader.push_line("not valid json at all")
        reader.push_eof()

        await channel._read_loop()
        assert channel._message_queue.qsize() == 0

    async def test_empty_messages_ignored(self):
        """_read_loop ignores notifications with empty message content."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        reader = FakeSocketReader()
        channel._reader = reader
        channel._running = True

        notification = {
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "source": "+1",
                    "dataMessage": {"message": ""},
                },
            },
        }
        reader.push_line(notification)
        reader.push_eof()

        await channel._read_loop()
        assert channel._message_queue.qsize() == 0

    async def test_read_loop_waits_when_no_reader(self):
        """_read_loop sleeps when reader is None (not yet connected)."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._reader = None
        channel._running = True

        sleep_count = 0

        async def counting_sleep(duration):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                channel._running = False  # Stop after a couple waits

        with patch("sentinel.channels.signal_channel.asyncio.sleep", side_effect=counting_sleep):
            await channel._read_loop()

        assert sleep_count >= 2


class TestSignalChannelPingSocket:
    async def test_ping_success(self):
        """_ping_socket sends listAccounts RPC and returns True."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        writer = FakeSocketWriter()
        reader = FakeSocketReader()
        channel._writer = writer
        channel._reader = reader

        result = await channel._ping_socket()

        assert result is True
        assert len(writer.written) == 1
        rpc = json.loads(writer.written[0].decode())
        assert rpc["method"] == "listAccounts"

    async def test_ping_fails_when_no_writer(self):
        """_ping_socket returns False when socket is not connected."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._writer = None

        result = await channel._ping_socket()
        assert result is False

    async def test_ping_fails_on_write_error(self):
        """_ping_socket returns False when socket write fails."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        writer = FakeSocketWriter()
        writer._fail_on_write = True
        channel._writer = writer

        result = await channel._ping_socket()
        assert result is False


class TestSignalChannelHealthMonitor:
    async def test_crash_triggers_restart_with_socket_reconnect(self):
        """Process crash triggers restart + socket reconnect."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._running = True

        proc = FakeProcess(returncode=1)
        channel._process = proc

        start_called = False
        connect_called = False

        async def mock_start():
            nonlocal start_called
            start_called = True
            channel._process = FakeProcess()  # New process
            channel._running = False  # Stop monitor after one restart

        async def mock_connect():
            nonlocal connect_called
            connect_called = True

        channel._start_process = mock_start
        channel._connect_socket = mock_connect

        with patch("sentinel.channels.signal_channel.asyncio.sleep", new_callable=AsyncMock):
            await channel._health_monitor()

        assert start_called
        assert connect_called
        assert channel._backoff.attempt == 1

    async def test_ping_failure_triggers_restart(self):
        """Failed socket ping kills process and restarts."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._running = True
        channel._PING_INTERVAL = 1.0  # Trigger ping quickly

        proc = FakeProcess()
        channel._process = proc

        writer = FakeSocketWriter()
        writer._fail_on_write = True
        channel._writer = writer

        start_called = False
        connect_called = False

        async def mock_start():
            nonlocal start_called
            start_called = True
            channel._process = FakeProcess()
            channel._running = False  # Stop after one restart

        async def mock_connect():
            nonlocal connect_called
            connect_called = True

        channel._start_process = mock_start
        channel._connect_socket = mock_connect

        sleep_count = 0

        async def fast_sleep(duration):
            nonlocal sleep_count
            sleep_count += 1

        with patch("sentinel.channels.signal_channel.asyncio.sleep", side_effect=fast_sleep):
            await channel._health_monitor()

        assert proc._killed is True
        assert start_called
        assert connect_called
        assert channel._backoff.attempt == 1

    async def test_backoff_increases_on_repeated_crashes(self):
        """Repeated crashes increase the backoff delay."""
        b = ExponentialBackoff(base=1.0, max_delay=300.0)

        d1 = b.next_delay()
        d2 = b.next_delay()
        d3 = b.next_delay()

        assert d1 == 1.0
        assert d2 == 2.0
        assert d3 == 4.0
