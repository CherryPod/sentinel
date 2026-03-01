"""Tests for the A2A (Agent-to-Agent) protocol adapter.

Covers: Agent Card discovery, JSON-RPC 2.0 request parsing, state mapping,
error responses, tasks/send, tasks/get, tasks/cancel, and the adapter module
functions directly.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from sentinel.api.a2a import (
    AGENT_CARD,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    build_a2a_task,
    handle_tasks_get,
    handle_tasks_send,
    jsonrpc_error,
    jsonrpc_success,
    map_sentinel_state,
    parse_jsonrpc_request,
)
from sentinel.api.auth import PinAuthMiddleware
from sentinel.core.models import StepResult, TaskResult


# ── Agent Card ────────────────────────────────────────────────────


class TestAgentCard:
    """GET /.well-known/agent.json returns the A2A Agent Card."""

    def test_card_has_required_fields(self):
        """Agent Card must have name, description, url, version, capabilities."""
        assert AGENT_CARD["name"] == "Sentinel"
        assert "description" in AGENT_CARD
        assert "url" in AGENT_CARD
        assert "version" in AGENT_CARD
        assert "capabilities" in AGENT_CARD
        assert "skills" in AGENT_CARD

    def test_card_capabilities(self):
        """Capabilities must declare streaming support."""
        caps = AGENT_CARD["capabilities"]
        assert caps["streaming"] is True
        assert caps["pushNotifications"] is False
        assert caps["stateTransitionHistory"] is False

    def test_card_authentication(self):
        """Authentication scheme must be bearer."""
        assert AGENT_CARD["authentication"]["schemes"] == ["bearer"]

    def test_card_skills_not_empty(self):
        """At least one skill must be declared."""
        skills = AGENT_CARD["skills"]
        assert len(skills) >= 1
        assert skills[0]["id"] == "general-task"

    def test_card_io_modes(self):
        """Default input/output modes must be text."""
        assert AGENT_CARD["defaultInputModes"] == ["text"]
        assert AGENT_CARD["defaultOutputModes"] == ["text"]


# ── State mapping ────────────────────────────────────────────────


class TestStateMapping:
    """Sentinel status -> A2A state mapping."""

    def test_awaiting_approval_maps_to_input_required(self):
        assert map_sentinel_state("awaiting_approval") == "input-required"

    def test_success_maps_to_completed(self):
        assert map_sentinel_state("success") == "completed"

    def test_blocked_maps_to_failed(self):
        assert map_sentinel_state("blocked") == "failed"

    def test_error_maps_to_failed(self):
        assert map_sentinel_state("error") == "failed"

    def test_refused_maps_to_failed(self):
        assert map_sentinel_state("refused") == "failed"

    def test_denied_maps_to_failed(self):
        assert map_sentinel_state("denied") == "failed"

    def test_unknown_status_maps_to_failed(self):
        """Any unrecognized status defaults to failed (fail-safe)."""
        assert map_sentinel_state("some_new_status") == "failed"


# ── JSON-RPC helpers ─────────────────────────────────────────────


class TestJsonRpcHelpers:
    """jsonrpc_success() and jsonrpc_error() response builders."""

    def test_success_response_structure(self):
        resp = jsonrpc_success(1, {"state": "completed"})
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert resp["result"] == {"state": "completed"}
        assert "error" not in resp

    def test_error_response_structure(self):
        resp = jsonrpc_error(2, -32600, "Bad request")
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 2
        assert resp["error"]["code"] == -32600
        assert resp["error"]["message"] == "Bad request"

    def test_error_with_data(self):
        resp = jsonrpc_error(3, -32603, "Internal", data={"detail": "stack"})
        assert resp["error"]["data"] == {"detail": "stack"}

    def test_error_without_data(self):
        resp = jsonrpc_error(4, -32601, "Not found")
        assert "data" not in resp["error"]

    def test_success_with_none_id(self):
        """Notifications have null id -- still valid JSON-RPC."""
        resp = jsonrpc_success(None, "ok")
        assert resp["id"] is None


# ── JSON-RPC request parsing ─────────────────────────────────────


class TestParseJsonRpcRequest:
    """parse_jsonrpc_request() validates JSON-RPC 2.0 structure."""

    def test_valid_request(self):
        result = parse_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {"message": {}},
        })
        assert isinstance(result, tuple)
        req_id, method, params = result
        assert req_id == 1
        assert method == "tasks/send"
        assert params == {"message": {}}

    def test_missing_jsonrpc_version(self):
        result = parse_jsonrpc_request({"id": 1, "method": "tasks/send"})
        assert isinstance(result, dict)
        assert result["error"]["code"] == INVALID_REQUEST

    def test_wrong_jsonrpc_version(self):
        result = parse_jsonrpc_request({
            "jsonrpc": "1.0", "id": 1, "method": "tasks/send",
        })
        assert isinstance(result, dict)
        assert result["error"]["code"] == INVALID_REQUEST

    def test_missing_method(self):
        result = parse_jsonrpc_request({"jsonrpc": "2.0", "id": 1})
        assert isinstance(result, dict)
        assert result["error"]["code"] == INVALID_REQUEST

    def test_empty_method(self):
        result = parse_jsonrpc_request({
            "jsonrpc": "2.0", "id": 1, "method": "",
        })
        assert isinstance(result, dict)
        assert result["error"]["code"] == INVALID_REQUEST

    def test_non_string_method(self):
        result = parse_jsonrpc_request({
            "jsonrpc": "2.0", "id": 1, "method": 42,
        })
        assert isinstance(result, dict)
        assert result["error"]["code"] == INVALID_REQUEST

    def test_params_default_to_empty_dict(self):
        result = parse_jsonrpc_request({
            "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
        })
        assert isinstance(result, tuple)
        _, _, params = result
        assert params == {}

    def test_non_object_params_rejected(self):
        result = parse_jsonrpc_request({
            "jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": [1, 2],
        })
        assert isinstance(result, dict)
        assert result["error"]["code"] == INVALID_REQUEST


# ── build_a2a_task ───────────────────────────────────────────────


class TestBuildA2aTask:
    """build_a2a_task() converts TaskResult to A2A Task objects."""

    def test_completed_task_with_steps(self):
        result = TaskResult(
            task_id="abc-123",
            status="success",
            plan_summary="Wrote a file",
            step_results=[
                StepResult(step_id="s1", status="success", content="File written"),
            ],
        )
        task = build_a2a_task(result)
        assert task["id"] == "abc-123"
        assert task["status"]["state"] == "completed"
        assert len(task["artifacts"]) == 1
        assert task["artifacts"][0]["parts"][0]["text"] == "File written"

    def test_failed_task_has_reason(self):
        result = TaskResult(
            task_id="fail-1",
            status="blocked",
            reason="Security violation detected",
        )
        task = build_a2a_task(result)
        assert task["status"]["state"] == "failed"
        assert "Security violation" in task["status"]["message"]["parts"][0]["text"]

    def test_awaiting_approval_has_approval_id(self):
        result = TaskResult(
            task_id="ap-1",
            status="awaiting_approval",
            plan_summary="Read /etc/passwd",
            approval_id="uuid-approval",
        )
        task = build_a2a_task(result)
        assert task["status"]["state"] == "input-required"
        msg_text = task["status"]["message"]["parts"][0]["text"]
        assert "uuid-approval" in msg_text
        assert "approval" in msg_text.lower()

    def test_completed_task_no_steps(self):
        """Completed task without step output should not have artifacts."""
        result = TaskResult(task_id="empty-1", status="success", plan_summary="Done")
        task = build_a2a_task(result)
        assert task["status"]["state"] == "completed"
        assert "artifacts" not in task

    def test_task_id_from_result(self):
        result = TaskResult(task_id="", status="error", reason="bad")
        task = build_a2a_task(result)
        assert task["id"] == "unknown"  # fallback for empty task_id


# ── Integration: Agent Card endpoint (via app) ───────────────────


class TestAgentCardEndpoint:
    """Test the /.well-known/agent.json route via TestClient.

    Uses a minimal app setup to avoid full lifespan initialization.
    """

    @pytest.fixture
    def client(self):
        # Build a minimal app with just the agent card route to test routing
        app = FastAPI()

        @app.get("/.well-known/agent.json")
        async def agent_card():
            return JSONResponse(content=AGENT_CARD)

        return TestClient(app)

    def test_agent_card_returns_200(self, client):
        resp = client.get("/.well-known/agent.json")
        assert resp.status_code == 200

    def test_agent_card_content_type_json(self, client):
        resp = client.get("/.well-known/agent.json")
        assert "application/json" in resp.headers["content-type"]

    def test_agent_card_body_matches(self, client):
        resp = client.get("/.well-known/agent.json")
        data = resp.json()
        assert data["name"] == "Sentinel"
        assert data["version"] == "0.3.0-alpha"
        assert data["capabilities"]["streaming"] is True


# ── Integration: /a2a endpoint error handling ────────────────────


class TestA2aEndpointErrors:
    """Test the /a2a JSON-RPC endpoint error paths.

    Uses a minimal app that mimics the real /a2a route but with
    mocked orchestrator to avoid full lifespan.
    """

    @pytest.fixture
    def client(self):
        app = FastAPI()
        # Mock orchestrator that always returns a success TaskResult
        mock_orch = MagicMock()
        mock_orch.handle_task = AsyncMock(return_value=TaskResult(
            task_id="test-123",
            status="success",
            plan_summary="Test done",
            step_results=[StepResult(step_id="s1", status="success", content="hello")],
        ))
        mock_orch._approval_manager = None

        @app.post("/a2a")
        async def a2a_endpoint(request: Request):
            try:
                body = await request.json()
            except Exception:
                return JSONResponse(content=jsonrpc_error(None, INVALID_REQUEST, "Invalid JSON"))

            parsed = parse_jsonrpc_request(body)
            if isinstance(parsed, dict):
                return JSONResponse(content=parsed)

            req_id, method, params = parsed

            if method == "tasks/send":
                try:
                    client_ip = request.client.host if request.client else "unknown"
                    task_result = await handle_tasks_send(params, mock_orch, client_ip)
                    a2a_task = build_a2a_task(task_result)
                    return JSONResponse(content=jsonrpc_success(req_id, a2a_task))
                except ValueError as exc:
                    return JSONResponse(content=jsonrpc_error(req_id, INVALID_REQUEST, str(exc)))

            elif method == "tasks/get":
                task = await handle_tasks_get(params, mock_orch)
                if task is None:
                    return JSONResponse(content=jsonrpc_error(req_id, INVALID_REQUEST, "Task not found"))
                return JSONResponse(content=jsonrpc_success(req_id, task))

            elif method == "tasks/cancel":
                return JSONResponse(
                    content=jsonrpc_error(req_id, METHOD_NOT_FOUND, "tasks/cancel not yet implemented"),
                )

            else:
                return JSONResponse(
                    content=jsonrpc_error(req_id, METHOD_NOT_FOUND, f"Unknown method: {method}"),
                )

        return TestClient(app)

    def test_invalid_json_returns_error(self, client):
        resp = client.post("/a2a", content=b"not json", headers={"Content-Type": "application/json"})
        data = resp.json()
        assert data["error"]["code"] == INVALID_REQUEST

    def test_missing_jsonrpc_version_returns_error(self, client):
        resp = client.post("/a2a", json={"id": 1, "method": "tasks/send"})
        data = resp.json()
        assert data["error"]["code"] == INVALID_REQUEST

    def test_unknown_method_returns_method_not_found(self, client):
        resp = client.post("/a2a", json={
            "jsonrpc": "2.0", "id": 1, "method": "unknown/thing",
        })
        data = resp.json()
        assert data["error"]["code"] == METHOD_NOT_FOUND

    def test_tasks_cancel_returns_not_implemented(self, client):
        resp = client.post("/a2a", json={
            "jsonrpc": "2.0", "id": 1, "method": "tasks/cancel", "params": {"id": "x"},
        })
        data = resp.json()
        assert data["error"]["code"] == METHOD_NOT_FOUND
        assert "not yet implemented" in data["error"]["message"]

    def test_tasks_send_empty_message_returns_error(self, client):
        """tasks/send with no text parts should return an error."""
        resp = client.post("/a2a", json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {"message": {"parts": []}},
        })
        data = resp.json()
        assert data["error"]["code"] == INVALID_REQUEST
        assert "No text content" in data["error"]["message"]

    def test_tasks_send_success(self, client):
        """tasks/send with a valid message should return a completed A2A task."""
        resp = client.post("/a2a", json={
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tasks/send",
            "params": {
                "message": {
                    "parts": [{"text": "Write hello world"}],
                },
            },
        })
        data = resp.json()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] == 42
        assert data["result"]["id"] == "test-123"
        assert data["result"]["status"]["state"] == "completed"

    def test_tasks_get_not_found(self, client):
        """tasks/get for a non-existent task returns an error."""
        resp = client.post("/a2a", json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tasks/get",
            "params": {"id": "nonexistent"},
        })
        data = resp.json()
        assert data["error"]["code"] == INVALID_REQUEST
        assert "not found" in data["error"]["message"].lower()

    def test_tasks_get_empty_id(self, client):
        """tasks/get with empty id returns error."""
        resp = client.post("/a2a", json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tasks/get",
            "params": {"id": ""},
        })
        data = resp.json()
        assert data["error"]["code"] == INVALID_REQUEST


# ── Auth exemption for Agent Card ────────────────────────────────


class TestAgentCardAuthExemption:
    """Verify /.well-known/agent.json is in the PIN auth exempt paths."""

    def test_well_known_in_exempt_paths(self):
        """The agent card path should be exempted from PIN auth."""
        from sentinel.api.auth import PinVerifier
        verifier = PinVerifier("test-pin")
        app = FastAPI()
        app.add_middleware(PinAuthMiddleware, pin_verifier_getter=lambda: verifier)

        @app.get("/.well-known/agent.json")
        async def agent_card():
            return JSONResponse(content={"name": "test"})

        client = TestClient(app)
        # Should be accessible WITHOUT a PIN header
        resp = client.get("/.well-known/agent.json")
        assert resp.status_code == 200
        assert resp.json()["name"] == "test"

    def test_a2a_endpoint_requires_pin(self):
        """The /a2a endpoint should still require PIN auth."""
        from sentinel.api.auth import PinVerifier
        verifier = PinVerifier("test-pin")
        app = FastAPI()
        app.add_middleware(PinAuthMiddleware, pin_verifier_getter=lambda: verifier)

        @app.post("/a2a")
        async def a2a():
            return JSONResponse(content={"result": "ok"})

        client = TestClient(app)
        # Without PIN, should get 401
        resp = client.post("/a2a", json={"test": True})
        assert resp.status_code == 401
