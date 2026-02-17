"""Tests for the Podman socket API proxy allowlist."""

import asyncio
import json

import pytest

from sentinel.tools.podman_proxy import PodmanProxy, SANDBOX_NAME_PREFIX


class TestAllowlist:
    """Direct tests for _check_allowed() — no sockets needed."""

    def setup_method(self):
        self.proxy = PodmanProxy(upstream="/dev/null", listen="/dev/null")

    def test_info_allowed(self):
        ok, _ = self.proxy._check_allowed("GET", "/v5.0.0/info", b"")
        assert ok

    def test_images_json_allowed(self):
        ok, _ = self.proxy._check_allowed("GET", "/v5.0.0/images/json", b"")
        assert ok

    def test_container_list_allowed(self):
        ok, _ = self.proxy._check_allowed("GET", "/v5.0.0/containers/json", b"")
        assert ok

    def test_container_list_with_query_allowed(self):
        ok, _ = self.proxy._check_allowed(
            "GET", "/v5.0.0/containers/json", b""
        )
        assert ok

    def test_libpod_path_blocked(self):
        """Podman-native libpod paths are NOT in the allowlist."""
        ok, reason = self.proxy._check_allowed(
            "GET", "/v4.0.0/libpod/containers/json", b""
        )
        assert not ok
        assert "not in allowlist" in reason

    def test_exec_blocked(self):
        """Container exec is never allowed."""
        self.proxy._tracked_ids.add("abc123")
        ok, reason = self.proxy._check_allowed(
            "POST", "/v5.0.0/containers/abc123/exec", b""
        )
        assert not ok

    def test_arbitrary_path_blocked(self):
        ok, reason = self.proxy._check_allowed("GET", "/v5.0.0/volumes/json", b"")
        assert not ok
        assert "not in allowlist" in reason

    def test_different_api_version_allowed(self):
        """Version-agnostic matching — v4.0.0 containers/json should work."""
        ok, _ = self.proxy._check_allowed("GET", "/v4.0.0/containers/json", b"")
        assert ok


class TestContainerCreate:
    """Tests for container create validation."""

    def setup_method(self):
        self.proxy = PodmanProxy(upstream="/dev/null", listen="/dev/null")

    def test_valid_create_allowed(self):
        body = json.dumps({
            "name": f"{SANDBOX_NAME_PREFIX}abc123def456",
            "image": "python:3.12-slim",
        }).encode()
        ok, _ = self.proxy._check_allowed("POST", "/v5.0.0/containers/create", body)
        assert ok

    def test_wrong_name_prefix_blocked(self):
        body = json.dumps({
            "name": "evil-container",
            "image": "python:3.12-slim",
        }).encode()
        ok, reason = self.proxy._check_allowed("POST", "/v5.0.0/containers/create", body)
        assert not ok
        assert "name must start with" in reason.lower()

    def test_wrong_image_blocked(self):
        body = json.dumps({
            "name": f"{SANDBOX_NAME_PREFIX}abc123def456",
            "image": "ubuntu:latest",
        }).encode()
        ok, reason = self.proxy._check_allowed("POST", "/v5.0.0/containers/create", body)
        assert not ok
        assert "image" in reason.lower()

    def test_empty_body_blocked(self):
        ok, reason = self.proxy._check_allowed("POST", "/v5.0.0/containers/create", b"")
        assert not ok
        assert "empty" in reason.lower()

    def test_invalid_json_blocked(self):
        ok, reason = self.proxy._check_allowed(
            "POST", "/v5.0.0/containers/create", b"not json"
        )
        assert not ok
        assert "invalid json" in reason.lower()


class TestContainerIdTracking:
    """Tests for stateful container ID tracking."""

    def setup_method(self):
        self.proxy = PodmanProxy(upstream="/dev/null", listen="/dev/null")

    def test_tracked_container_start_allowed(self):
        self.proxy._tracked_ids.add("abc123def456")
        ok, _ = self.proxy._check_allowed(
            "POST", "/v5.0.0/containers/abc123def456/start", b""
        )
        assert ok

    def test_untracked_container_start_blocked(self):
        ok, reason = self.proxy._check_allowed(
            "POST", "/v5.0.0/containers/unknown123/start", b""
        )
        assert not ok
        assert "not in tracked set" in reason

    def test_tracked_container_logs_allowed(self):
        self.proxy._tracked_ids.add("abc123def456")
        ok, _ = self.proxy._check_allowed(
            "GET", "/v5.0.0/containers/abc123def456/logs", b""
        )
        assert ok

    def test_tracked_container_wait_allowed(self):
        self.proxy._tracked_ids.add("abc123def456")
        ok, _ = self.proxy._check_allowed(
            "POST", "/v5.0.0/containers/abc123def456/wait", b""
        )
        assert ok

    def test_tracked_container_kill_allowed(self):
        self.proxy._tracked_ids.add("abc123def456")
        ok, _ = self.proxy._check_allowed(
            "POST", "/v5.0.0/containers/abc123def456/kill", b""
        )
        assert ok

    def test_tracked_container_inspect_allowed(self):
        self.proxy._tracked_ids.add("abc123def456")
        ok, _ = self.proxy._check_allowed(
            "GET", "/v5.0.0/containers/abc123def456/json", b""
        )
        assert ok

    def test_tracked_container_delete_allowed(self):
        self.proxy._tracked_ids.add("abc123def456")
        ok, _ = self.proxy._check_allowed(
            "DELETE", "/v5.0.0/containers/abc123def456", b""
        )
        assert ok

    def test_track_created_container(self):
        """Simulates extracting container ID from a create response."""
        response = (
            b"HTTP/1.1 201 Created\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            + json.dumps({"Id": "deadbeef12345678abcdef"}).encode()
        )
        self.proxy._track_created_container(bytearray(response))
        assert "deadbeef12345678abcdef" in self.proxy._tracked_ids
        # Short ID also tracked
        assert "deadbeef1234" in self.proxy._tracked_ids

    def test_delete_untracks_container(self):
        """After DELETE, the container should no longer be tracked."""
        self.proxy._tracked_ids.add("abc123def456")
        # Simulate what _proxy_request does after DELETE
        self.proxy._tracked_ids.discard("abc123def456")
        assert "abc123def456" not in self.proxy._tracked_ids


class TestAttackScenarios:
    """Tests modelling actual B3 red team attack patterns."""

    def setup_method(self):
        self.proxy = PodmanProxy(upstream="/dev/null", listen="/dev/null")

    def test_list_all_host_containers_blocked(self):
        """B3 attack: list all containers via libpod API."""
        ok, _ = self.proxy._check_allowed(
            "GET", "/v4.0.0/libpod/containers/json", b""
        )
        assert not ok

    def test_exec_into_ollama_blocked(self):
        """B3 attack: exec into sentinel-ollama via known container name."""
        ok, _ = self.proxy._check_allowed(
            "POST", "/v4.0.0/libpod/containers/sentinel-ollama/exec",
            json.dumps({"Cmd": ["sh"]}).encode(),
        )
        assert not ok

    def test_create_non_sandbox_container_blocked(self):
        """B3 attack: create a container with full network access."""
        body = json.dumps({
            "name": "attacker-container",
            "image": "alpine:latest",
            "network_disabled": False,
        }).encode()
        ok, _ = self.proxy._check_allowed("POST", "/v5.0.0/containers/create", body)
        assert not ok

    def test_volume_list_blocked(self):
        """B3 attack: enumerate host volumes."""
        ok, _ = self.proxy._check_allowed("GET", "/v5.0.0/volumes/json", b"")
        assert not ok

    def test_network_list_blocked(self):
        """B3 attack: enumerate networks."""
        ok, _ = self.proxy._check_allowed("GET", "/v5.0.0/networks/json", b"")
        assert not ok

    def test_image_pull_blocked(self):
        """B3 attack: pull arbitrary image."""
        ok, _ = self.proxy._check_allowed(
            "POST", "/v5.0.0/images/create", b""
        )
        assert not ok
