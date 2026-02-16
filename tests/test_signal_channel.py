"""Tests for Signal channel — all using mocked subprocess (no signal-cli needed)."""

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
        """Default config values."""
        cfg = SignalConfig()
        assert cfg.signal_cli_path == "/usr/bin/signal-cli"
        assert cfg.account == ""
        assert cfg.trust_all_known is False

    def test_custom_values(self):
        """Custom config values."""
        cfg = SignalConfig(
            signal_cli_path="/opt/bin/signal-cli",
            account="+1234567890",
            trust_all_known=True,
        )
        assert cfg.account == "+1234567890"


# ── SignalChannel tests ───────────────────────────────────────────


class FakeProcess:
    """Mock asyncio subprocess for testing."""

    def __init__(self, *, returncode=None):
        self.pid = 12345
        self.returncode = returncode
        self.stdin = MagicMock()
        self.stdin.write = MagicMock()
        self.stdin.drain = AsyncMock()
        self.stdout = MagicMock()
        self._stdout_lines = asyncio.Queue()
        self.stderr = MagicMock()
        self._terminated = False
        self._killed = False

    def push_stdout(self, data):
        """Push a line for stdout.readline() to return."""
        if isinstance(data, dict):
            data = json.dumps(data).encode() + b"\n"
        elif isinstance(data, str):
            data = data.encode() + b"\n"
        self._stdout_lines.put_nowait(data)

    def push_eof(self):
        """Signal EOF on stdout."""
        self._stdout_lines.put_nowait(b"")

    async def _readline(self):
        return await self._stdout_lines.get()

    def terminate(self):
        self._terminated = True
        self.returncode = -15

    def kill(self):
        self._killed = True
        self.returncode = -9

    async def wait(self):
        return self.returncode


class TestSignalChannelStart:
    async def test_start_creates_subprocess(self):
        """start() launches signal-cli with correct args."""
        cfg = SignalConfig(account="+1234567890")
        channel = SignalChannel(cfg)

        proc = FakeProcess()
        proc.stdout.readline = proc._readline

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc):
            # Don't actually start background tasks
            with patch.object(channel, "_read_loop", new_callable=AsyncMock):
                with patch.object(channel, "_health_monitor", new_callable=AsyncMock):
                    await channel.start()

        assert channel._process is proc
        assert channel._running is True


class TestSignalChannelStop:
    async def test_stop_terminates_process(self):
        """stop() terminates the subprocess gracefully."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        channel._process = proc
        channel._running = True

        await channel.stop()

        assert proc._terminated is True
        assert channel._running is False
        assert channel._process is None


class TestSignalChannelSend:
    async def test_send_writes_jsonrpc(self):
        """send() writes a JSON-RPC request to stdin."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        channel._process = proc

        msg = OutgoingMessage(
            channel_id="+1234567890",
            event_type="task.completed",
            data={"status": "success"},
        )
        await channel.send(msg)

        proc.stdin.write.assert_called_once()
        written = proc.stdin.write.call_args[0][0]
        rpc = json.loads(written.decode())
        assert rpc["jsonrpc"] == "2.0"
        assert rpc["method"] == "send"
        assert rpc["params"]["recipient"] == "+1234567890"

    async def test_send_without_process(self):
        """send() logs warning when process is not running."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._process = None

        msg = OutgoingMessage(channel_id="+1", event_type="test", data={})
        # Should not raise
        await channel.send(msg)


class TestSignalChannelReadLoop:
    async def test_incoming_message_queued(self):
        """_read_loop parses signal-cli notifications and queues messages."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        proc = FakeProcess()
        proc.stdout.readline = proc._readline
        channel._process = proc
        channel._running = True

        # Push a signal-cli receive notification
        notification = {
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "source": "+1234567890",
                    "timestamp": 1000,
                    "dataMessage": {
                        "message": "Hello Sentinel",
                    },
                },
            },
        }
        proc.push_stdout(notification)
        proc.push_eof()  # Stop the loop

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
        proc = FakeProcess()
        proc.stdout.readline = proc._readline
        channel._process = proc
        channel._running = True

        proc.push_stdout("not valid json at all")
        proc.push_eof()

        # Should not raise
        await channel._read_loop()
        assert channel._message_queue.qsize() == 0

    async def test_empty_messages_ignored(self):
        """_read_loop ignores notifications with empty message content."""
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
                    "source": "+1",
                    "dataMessage": {"message": ""},
                },
            },
        }
        proc.push_stdout(notification)
        proc.push_eof()

        await channel._read_loop()
        assert channel._message_queue.qsize() == 0


class TestSignalChannelHealthMonitor:
    async def test_crash_triggers_restart(self):
        """Process crash triggers restart with backoff."""
        cfg = SignalConfig()
        channel = SignalChannel(cfg)
        channel._running = True

        # Simulate a crashed process
        proc = FakeProcess(returncode=1)
        channel._process = proc

        restart_called = False
        original_start = channel._start_process

        async def mock_start():
            nonlocal restart_called
            restart_called = True
            channel._running = False  # Stop the monitor after one restart

        channel._start_process = mock_start

        # Patch sleep to not actually wait
        with patch("sentinel.channels.signal_channel.asyncio.sleep", new_callable=AsyncMock):
            await channel._health_monitor()

        assert restart_called
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
