"""E2b capability tests — Dashboard view (health + session APIs).

Tests verify the backend APIs return data sufficient for the dashboard
view to render health cards, session info, and component status.
"""

import pytest
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient
from tests.conftest import auth_headers


class TestDashboardHealth:
    """Verify /api/health returns all fields the dashboard needs."""

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    @patch("sentinel.api.lifecycle._engine", True)
    @patch("sentinel.api.lifecycle._prompt_guard_loaded", True)
    @patch("sentinel.api.lifecycle._semgrep_loaded", True)
    @patch("sentinel.api.lifecycle._planner_available", True)
    def test_health_data_sufficient_for_dashboard(self):
        """GET /api/health returns all fields needed by dashboard health cards."""
        from sentinel.api.app import app

        client = TestClient(app)
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()

        # Dashboard needs these exact keys for the 12 health cards
        required_keys = [
            "status",
            "policy_loaded",
            "prompt_guard_loaded",
            "semgrep_loaded",
            "planner_available",
            "conversation_tracking",
            "pin_auth_enabled",
            "sidecar",
            "signal",
            "telegram",
            "sandbox",
            "email",
            "calendar",
        ]
        for key in required_keys:
            assert key in data, f"Missing health key: {key}"

        # Values should be usable booleans or known strings
        assert data["status"] == "ok"
        assert isinstance(data["policy_loaded"], bool)
        assert isinstance(data["prompt_guard_loaded"], bool)
        assert data["sidecar"] in ("running", "stopped", "disabled")
        assert data["signal"] in ("running", "stopped", "disabled")
        assert data["telegram"] in ("running", "stopped", "disabled")
        assert data["sandbox"] in ("enabled", "disabled")
        assert isinstance(data["email"], str)
        assert isinstance(data["calendar"], str)


class TestDashboardSession:
    """Verify /api/session/{id} returns data the dashboard needs."""

    @pytest.fixture
    def session_store(self):
        """SessionStore using in-memory fallback."""
        from sentinel.session.store import SessionStore

        store = SessionStore()
        yield store

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    async def test_session_endpoint_returns_state(self, session_store):
        """GET /api/session/{id} returns session state with expected fields."""
        from sentinel.api.app import app
        from sentinel.core.context import current_user_id

        # UserContextMiddleware sets current_user_id=1 for every API request,
        # so the session must be created with user_id=1 to match.
        token = current_user_id.set(1)
        try:
            session = await session_store.get_or_create(session_id=None, source="webui")
        finally:
            current_user_id.reset(token)

        with patch("sentinel.api.routes.task._session_store", session_store):
            client = TestClient(app)
            resp = client.get(f"/api/session/{session.session_id}", headers=auth_headers())
            assert resp.status_code == 200
            data = resp.json()

            # Dashboard session card needs these fields
            assert data["session_id"] == session.session_id
            assert "turn_count" in data
            assert "cumulative_risk" in data
            assert "violation_count" in data
            assert "is_locked" in data

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_session_not_found(self, session_store):
        """GET /api/session/{id} for nonexistent session returns error."""
        from sentinel.api.app import app

        with patch("sentinel.api.routes.task._session_store", session_store):
            client = TestClient(app)
            resp = client.get("/api/session/nonexistent-id", headers=auth_headers())
            assert resp.status_code == 404  # session not found returns 404
            data = resp.json()
            assert "error" in data
