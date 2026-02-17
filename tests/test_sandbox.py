"""Tests for Podman sandbox shell execution.

Tests use mocked httpx responses — no real Podman socket needed.
"""

import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import reset_store, get_tagged_data
from sentinel.tools.executor import ToolExecutor
from sentinel.tools.sandbox import PodmanSandbox, SandboxResult


class TestDataSourceSandbox:
    def test_sandbox_enum_exists(self):
        assert DataSource.SANDBOX == "sandbox"

    def test_sandbox_distinct_from_tool(self):
        assert DataSource.SANDBOX != DataSource.TOOL


class TestSandboxConfig:
    def test_default_settings(self):
        from sentinel.core.config import Settings
        s = Settings()
        assert s.sandbox_enabled is False
        assert s.sandbox_socket == "/run/podman/podman.sock"
        assert s.sandbox_image == "sentinel-sandbox:latest"
        assert s.sandbox_timeout == 30
        assert s.sandbox_max_timeout == 300
        assert s.sandbox_memory_limit == 268435456  # 256MB
        assert s.sandbox_cpu_quota == 100000  # 1 CPU core
        assert s.sandbox_output_limit == 65536  # 64KB
        assert s.sandbox_workspace_volume == "sentinel-workspace"

    def test_env_override(self):
        from sentinel.core.config import Settings
        env = {
            "SENTINEL_SANDBOX_ENABLED": "true",
            "SENTINEL_SANDBOX_TIMEOUT": "60",
            "SENTINEL_SANDBOX_IMAGE": "alpine:3.19",
        }
        with patch.dict(os.environ, env, clear=False):
            s = Settings()
            assert s.sandbox_enabled is True
            assert s.sandbox_timeout == 60
            assert s.sandbox_image == "alpine:3.19"


class TestSandboxResult:
    def test_success_result(self):
        from sentinel.tools.sandbox import SandboxResult
        r = SandboxResult(
            stdout="hello world",
            stderr="",
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            container_id="abc123",
        )
        assert r.stdout == "hello world"
        assert r.stderr == ""
        assert r.exit_code == 0
        assert r.timed_out is False
        assert r.oom_killed is False
        assert r.container_id == "abc123"

    def test_timeout_result(self):
        from sentinel.tools.sandbox import SandboxResult
        r = SandboxResult(
            stdout="",
            stderr="",
            exit_code=-1,
            timed_out=True,
            oom_killed=False,
            container_id="def456",
        )
        assert r.timed_out is True
        assert r.exit_code == -1

    def test_oom_result(self):
        from sentinel.tools.sandbox import SandboxResult
        r = SandboxResult(
            stdout="",
            stderr="",
            exit_code=-1,
            timed_out=False,
            oom_killed=True,
            container_id="ghi789",
        )
        assert r.oom_killed is True


class TestPodmanSandboxInit:
    def test_default_config(self):
        from sentinel.tools.sandbox import PodmanSandbox
        sb = PodmanSandbox(
            socket_path="/run/podman/podman.sock",
            image="python:3.12-slim",
            default_timeout=30,
            max_timeout=300,
            memory_limit=268435456,
            cpu_quota=100000,
            workspace_volume="sentinel-workspace",
            output_limit=65536,
        )
        assert sb._socket_path == "/run/podman/podman.sock"
        assert sb._image == "python:3.12-slim"
        assert sb._default_timeout == 30
        assert sb._max_timeout == 300
        assert sb._memory_limit == 268435456
        assert sb._cpu_quota == 100000
        assert sb._workspace_volume == "sentinel-workspace"
        assert sb._output_limit == 65536


class TestPodmanSandboxHealth:
    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Health check passes when Podman API responds and image exists."""
        from sentinel.tools.sandbox import PodmanSandbox

        sb = PodmanSandbox(
            socket_path="/fake/podman.sock",
            image="python:3.12-slim",
            default_timeout=30,
            max_timeout=300,
            memory_limit=268435456,
            cpu_quota=100000,
            workspace_volume="sentinel-workspace",
            output_limit=65536,
        )

        # Mock the httpx client — base_url needed for relative URL resolution
        mock_transport = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"version": {"Version": "5.0.0"}})
            if "info" in str(req.url) else
            httpx.Response(200, json=[{"Id": "sha256:abc"}])
        )
        sb._client = httpx.AsyncClient(
            transport=mock_transport, base_url="http://podman"
        )

        result = await sb.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_no_image(self):
        """Health check fails when sandbox image is not available."""
        from sentinel.tools.sandbox import PodmanSandbox

        sb = PodmanSandbox(
            socket_path="/fake/podman.sock",
            image="python:3.12-slim",
            default_timeout=30,
            max_timeout=300,
            memory_limit=268435456,
            cpu_quota=100000,
            workspace_volume="sentinel-workspace",
            output_limit=65536,
        )

        mock_transport = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"version": {"Version": "5.0.0"}})
            if "info" in str(req.url) else
            httpx.Response(200, json=[])  # no matching images
        )
        sb._client = httpx.AsyncClient(
            transport=mock_transport, base_url="http://podman"
        )

        result = await sb.health_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_connection_error(self):
        """Health check fails when Podman socket is unreachable."""
        from sentinel.tools.sandbox import PodmanSandbox

        sb = PodmanSandbox(
            socket_path="/nonexistent/podman.sock",
            image="python:3.12-slim",
            default_timeout=30,
            max_timeout=300,
            memory_limit=268435456,
            cpu_quota=100000,
            workspace_volume="sentinel-workspace",
            output_limit=65536,
        )
        # Don't set _client — will use real socket path which doesn't exist

        result = await sb.health_check()
        assert result is False


def _make_sandbox():
    """Helper to create a PodmanSandbox with default test config."""
    from sentinel.tools.sandbox import PodmanSandbox
    return PodmanSandbox(
        socket_path="/fake/podman.sock",
        image="python:3.12-slim",
        default_timeout=30,
        max_timeout=300,
        memory_limit=268435456,
        cpu_quota=100000,
        workspace_volume="sentinel-workspace",
        output_limit=65536,
    )


class TestPodmanSandboxCleanup:
    @pytest.mark.asyncio
    async def test_cleanup_removes_stale_containers(self):
        sb = _make_sandbox()

        call_count = {"delete": 0}
        def handler(req):
            if req.method == "GET" and "containers/json" in str(req.url):
                return httpx.Response(200, json=[
                    {"Id": "aaa111", "Names": ["sentinel-sandbox-uuid1"]},
                    {"Id": "bbb222", "Names": ["sentinel-sandbox-uuid2"]},
                ])
            if req.method == "DELETE":
                call_count["delete"] += 1
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        removed = await sb.cleanup_stale()
        assert removed == 2
        assert call_count["delete"] == 2

    @pytest.mark.asyncio
    async def test_cleanup_no_stale(self):
        sb = _make_sandbox()

        def handler(req):
            if req.method == "GET":
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        removed = await sb.cleanup_stale()
        assert removed == 0

    @pytest.mark.asyncio
    async def test_cleanup_handles_api_error(self):
        sb = _make_sandbox()

        def handler(req):
            return httpx.Response(500, text="internal error")

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        removed = await sb.cleanup_stale()
        assert removed == 0


import json as json_lib


class TestPodmanSandboxRun:
    @pytest.mark.asyncio
    async def test_successful_command(self):
        """Basic command runs and returns stdout."""
        sb = _make_sandbox()

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "container123"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                if "stdout=true" in url:
                    return httpx.Response(200, text="hello world\n")
                if "stderr=true" in url:
                    return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        result = await sb.run("echo hello world")
        assert result.stdout == "hello world\n"
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.timed_out is False
        assert result.oom_killed is False
        assert result.container_id == "container123"

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self):
        """Command returns nonzero exit code."""
        sb = _make_sandbox()

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c456"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 1})
            if req.method == "GET" and "logs" in url:
                if "stdout=true" in url:
                    return httpx.Response(200, text="")
                if "stderr=true" in url:
                    return httpx.Response(200, text="command not found\n")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        result = await sb.run("badcommand")
        assert result.exit_code == 1
        assert result.stderr == "command not found\n"

    @pytest.mark.asyncio
    async def test_oom_killed(self):
        """Container killed by OOM returns oom_killed=True."""
        sb = _make_sandbox()

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c789"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 137})
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": True},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        result = await sb.run("stress-ng --vm 1")
        assert result.oom_killed is True
        assert result.exit_code == 137

    @pytest.mark.asyncio
    async def test_output_truncation(self):
        """Stdout/stderr truncated to output_limit."""
        sb = _make_sandbox()
        sb._output_limit = 100  # small limit for test

        big_output = "x" * 200

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_trunc"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                if "stdout=true" in url:
                    return httpx.Response(200, text=big_output)
                if "stderr=true" in url:
                    return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        result = await sb.run("cat bigfile")
        assert len(result.stdout) == 100

    @pytest.mark.asyncio
    async def test_container_create_payload(self):
        """Verify the container creation payload has all safety settings."""
        sb = _make_sandbox()
        captured_body = {}

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                captured_body.update(json_lib.loads(req.content))
                return httpx.Response(201, json={"Id": "c_payload"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        await sb.run("whoami")

        # Verify safety settings — field names must be Docker API PascalCase,
        # NOT snake_case. Podman's compat API silently ignores snake_case
        # fields, which caused sandbox containers to run with no volume mounts
        # and no security hardening (Fix V, 2026-02-28).
        assert captured_body.get("NetworkDisabled") is True

        host_config = captured_body.get("HostConfig", {})
        assert host_config.get("CapDrop") == ["ALL"]
        assert host_config.get("ReadonlyRootfs") is True
        assert host_config.get("NoNewPrivileges") is True
        assert host_config.get("Memory") == 268435456

        # Fix W: Podman-reliable equivalents for silently-ignored fields
        assert host_config.get("NetworkMode") == "none"
        assert host_config.get("SecurityOpt") == ["no-new-privileges"]
        # Fix X: CAP_SETUID/SETGID needed for setpriv privilege drop
        assert host_config.get("CapAdd") == ["CAP_SETUID", "CAP_SETGID"]

        # Verify command is wrapped in privilege-drop wrapper
        cmd = captured_body.get("Cmd", [])
        assert cmd[0] == "sh"
        assert cmd[1] == "-c"
        # Wrapper: chmod workspace, then setpriv drops to nobody (65534)
        assert "setpriv" in cmd[2]
        assert "65534" in cmd[2]
        assert "whoami" in cmd[2]
        assert "chmod" in cmd[2]

        # Verify container name starts with prefix
        name_param = captured_body.get("Name", "")
        assert name_param.startswith("sentinel-sandbox-")

    @pytest.mark.asyncio
    async def test_container_cleanup_on_error(self):
        """Container is deleted even when API errors occur after creation."""
        sb = _make_sandbox()
        deleted = {"called": False}

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_err"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(500, text="internal error")
            if req.method == "DELETE":
                deleted["called"] = True
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        from sentinel.tools.executor import ToolError
        with pytest.raises(ToolError, match="sandbox"):
            await sb.run("echo hello")

        assert deleted["called"] is True

    @pytest.mark.asyncio
    async def test_create_failure_raises_tool_error(self):
        """Container creation failure raises ToolError."""
        sb = _make_sandbox()

        def handler(req):
            return httpx.Response(500, text="image not found")

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        from sentinel.tools.executor import ToolError
        with pytest.raises(ToolError, match="sandbox"):
            await sb.run("echo hello")

    @pytest.mark.asyncio
    async def test_custom_timeout(self):
        """Custom timeout is clamped to max_timeout."""
        sb = _make_sandbox()
        sb._max_timeout = 60

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_to"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        # Should not raise — timeout 999 clamped to max 60
        result = await sb.run("sleep 10", timeout=999)
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_timeout_kills_container(self):
        """When asyncio timeout fires, container is killed then deleted."""
        import asyncio
        sb = _make_sandbox()
        sb._default_timeout = 1  # 1 second timeout

        killed = {"called": False}
        deleted = {"called": False}

        async def slow_handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_slow"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                # Simulate a container that never finishes
                await asyncio.sleep(10)
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "POST" and "kill" in url:
                killed["called"] = True
                return httpx.Response(204)
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="partial output")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False, "Running": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                deleted["called"] = True
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(slow_handler), base_url="http://podman"
        )
        result = await sb.run("sleep 999")
        assert result.timed_out is True
        assert result.exit_code == -1
        assert deleted["called"] is True


class TestPodmanSandboxHardeningGate:
    @pytest.mark.asyncio
    async def test_hardening_blocks_missing_network_isolation(self):
        """Container is deleted and ToolError raised when NetworkMode != none."""
        sb = _make_sandbox()
        deleted = {"called": False}

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_unsafe"})
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "bridge",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                deleted["called"] = True
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        from sentinel.tools.executor import ToolError
        with pytest.raises(ToolError, match="NetworkMode"):
            await sb.run("echo hello")

        assert deleted["called"] is True

    @pytest.mark.asyncio
    async def test_hardening_blocks_missing_security_opt(self):
        """Container is deleted when SecurityOpt is missing no-new-privileges."""
        sb = _make_sandbox()

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_unsafe2"})
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": [],
                        "Memory": 268435456,
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        from sentinel.tools.executor import ToolError
        with pytest.raises(ToolError, match="no-new-privileges"):
            await sb.run("echo hello")

    @pytest.mark.asyncio
    async def test_hardening_blocks_missing_capdrop(self):
        """Container is deleted when CapDrop is missing (BH3-006)."""
        sb = _make_sandbox()

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_nocap"})
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": [],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        from sentinel.tools.executor import ToolError
        with pytest.raises(ToolError, match="CapDrop"):
            await sb.run("echo hello")

    @pytest.mark.asyncio
    async def test_hardening_passes_valid_config(self):
        """Container starts normally when all hardening checks pass."""
        sb = _make_sandbox()

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                return httpx.Response(201, json={"Id": "c_safe"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )

        result = await sb.run("echo ok")
        assert result.exit_code == 0


class TestSandboxNonRootExecution:
    """Verify sandbox commands run as non-root user (UID 65534 / nobody)."""

    @pytest.mark.asyncio
    async def test_command_wrapped_with_setpriv(self):
        """User command is wrapped with setpriv to drop to UID 65534."""
        sb = _make_sandbox()
        captured_cmd = {}

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                body = json_lib.loads(req.content)
                captured_cmd["cmd"] = body.get("Cmd", [])
                return httpx.Response(201, json={"Id": "c_nonroot"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        await sb.run("cat /etc/shadow")

        cmd = captured_cmd["cmd"]
        assert cmd[0] == "sh" and cmd[1] == "-c"
        wrapper = cmd[2]
        # chmod makes workspace writable before privilege drop
        assert "chmod 1777 /workspace" in wrapper
        # setpriv drops to nobody (65534)
        assert "setpriv --reuid=65534 --regid=65534 --clear-groups" in wrapper
        # Original command is properly quoted inside the wrapper
        assert "cat /etc/shadow" in wrapper

    @pytest.mark.asyncio
    async def test_command_with_quotes_preserved(self):
        """Commands containing quotes are properly escaped in the wrapper."""
        sb = _make_sandbox()
        captured_cmd = {}

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                body = json_lib.loads(req.content)
                captured_cmd["cmd"] = body.get("Cmd", [])
                return httpx.Response(201, json={"Id": "c_quotes"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        await sb.run("echo 'hello world' && ls /workspace")

        wrapper = captured_cmd["cmd"][2]
        # shlex.quote wraps the compound command safely
        assert "echo" in wrapper
        assert "hello world" in wrapper
        assert "ls /workspace" in wrapper

    @pytest.mark.asyncio
    async def test_no_user_field_in_create_body(self):
        """Container-level User field is NOT set — privilege drop is via setpriv."""
        sb = _make_sandbox()
        captured_body = {}

        def handler(req):
            url = str(req.url)
            if req.method == "POST" and "containers/create" in url:
                captured_body.update(json_lib.loads(req.content))
                return httpx.Response(201, json={"Id": "c_nouser"})
            if req.method == "POST" and "start" in url:
                return httpx.Response(204)
            if req.method == "POST" and "wait" in url:
                return httpx.Response(200, json={"StatusCode": 0})
            if req.method == "GET" and "logs" in url:
                return httpx.Response(200, text="")
            if req.method == "GET" and "json" in url:
                return httpx.Response(200, json={
                    "State": {"OOMKilled": False},
                    "HostConfig": {
                        "NetworkMode": "none",
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                        "Memory": 268435456,
                        "CapDrop": ["ALL"],
                        "Binds": ["sentinel-workspace:/workspace:rw"],
                    },
                })
            if req.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        sb._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://podman"
        )
        await sb.run("whoami")

        # No "User" key in create body — root starts the container,
        # setpriv drops privileges before the user command runs
        assert "User" not in captured_body


class TestSandboxClose:
    """BH3-099: Verify httpx client is properly closed."""

    @pytest.mark.asyncio
    async def test_close_releases_client(self):
        """close() calls aclose on the httpx client and sets it to None."""
        sb = _make_sandbox()
        # Force client creation
        sb._get_client()
        assert sb._client is not None
        await sb.close()
        assert sb._client is None

    @pytest.mark.asyncio
    async def test_close_noop_when_no_client(self):
        """close() is safe to call when no client has been created."""
        sb = _make_sandbox()
        assert sb._client is None
        await sb.close()  # Should not raise
        assert sb._client is None


class TestSandboxLifecycleWiring:
    """Verify sandbox is wired into app.py lifespan correctly."""

    def test_executor_receives_sandbox_and_trust_level(self):
        """ToolExecutor constructor accepts sandbox and trust_level params."""
        from sentinel.tools.executor import ToolExecutor
        from sentinel.tools.sandbox import PodmanSandbox
        from unittest.mock import MagicMock

        mock_engine = MagicMock()
        mock_sandbox = MagicMock(spec=PodmanSandbox)

        executor = ToolExecutor(
            policy_engine=mock_engine,
            sandbox=mock_sandbox,
            trust_level=2,
        )
        assert executor._sandbox is mock_sandbox
        assert executor._trust_level == 2

    def test_executor_works_without_sandbox(self):
        """ToolExecutor still works when sandbox is not provided."""
        from sentinel.tools.executor import ToolExecutor
        from unittest.mock import MagicMock

        mock_engine = MagicMock()
        executor = ToolExecutor(policy_engine=mock_engine)
        assert executor._sandbox is None
        assert executor._trust_level == 0


class TestSandboxProvenance:
    """Verify sandbox output is UNTRUSTED in the provenance system."""

    @pytest.fixture(autouse=True)
    async def _reset(self):
        await reset_store()
        yield
        await reset_store()

    @pytest.mark.asyncio
    async def test_sandbox_output_is_untrusted(self, engine):
        """Sandbox output creates UNTRUSTED tagged data with SANDBOX source."""
        mock_sandbox = AsyncMock(spec=PodmanSandbox)
        mock_sandbox._default_timeout = 30
        mock_sandbox.run.return_value = SandboxResult(
            stdout="sandboxed result",
            stderr="",
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            container_id="prov_test_123",
        )

        executor = ToolExecutor(policy_engine=engine, sandbox=mock_sandbox, trust_level=2)

        with patch.object(engine, "check_command") as mock_cmd:
            from sentinel.core.models import PolicyResult, ValidationResult
            mock_cmd.return_value = ValidationResult(status=PolicyResult.ALLOWED, path="")
            tagged, exec_meta = await executor.execute("shell", {"command": "ls"})

        assert tagged.trust_level == TrustLevel.UNTRUSTED
        assert tagged.source == DataSource.SANDBOX

        # Verify it's in the provenance store
        stored = await get_tagged_data(tagged.id)
        assert stored is not None
        assert stored.trust_level == TrustLevel.UNTRUSTED
        assert stored.source == DataSource.SANDBOX
        assert "sandbox:ls" in stored.originated_from
