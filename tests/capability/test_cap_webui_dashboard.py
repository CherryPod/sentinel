"""E2b capability tests — Dashboard view (health + session APIs).

Tests verify the backend APIs return data sufficient for the dashboard
view to render health cards, session info, and component status.
"""

import sqlite3

import pytest
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from sentinel.core.db import _create_tables, _create_fts_index, _try_create_vec_table


class TestDashboardHealth:
    """Verify /api/health returns all fields the dashboard needs."""

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    @patch("sentinel.api.app._engine", True)
    @patch("sentinel.api.app._prompt_guard_loaded", True)
    @patch("sentinel.api.app._semgrep_loaded", True)
    @patch("sentinel.api.app._planner_available", True)
    def test_health_data_sufficient_for_dashboard(self):
        """GET /api/health returns all fields needed by dashboard health cards."""
        from sentinel.api.app import app

        client = TestClient(app)
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()

        # Dashboard needs these exact keys for the 8 health cards
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
        ]
        for key in required_keys:
            assert key in data, f"Missing health key: {key}"

        # Values should be usable booleans or known strings
        assert data["status"] == "ok"
        assert isinstance(data["policy_loaded"], bool)
        assert isinstance(data["prompt_guard_loaded"], bool)
        assert data["sidecar"] in ("running", "stopped", "disabled")
        assert data["signal"] in ("running", "stopped", "disabled")


class TestDashboardSession:
    """Verify /api/session/{id} returns data the dashboard needs."""

    @pytest.fixture
    def session_store(self):
        """SessionStore backed by in-memory SQLite (thread-safe)."""
        from sentinel.session.store import SessionStore

        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _create_tables(conn)
        _create_fts_index(conn)
        _try_create_vec_table(conn)
        conn.commit()
        store = SessionStore(db=conn)
        yield store
        conn.close()

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_session_endpoint_returns_state(self, session_store):
        """GET /api/session/{id} returns session state with expected fields."""
        from sentinel.api.app import app

        session = session_store.get_or_create(session_id=None, source="webui")

        with patch("sentinel.api.app._session_store", session_store):
            client = TestClient(app)
            resp = client.get(f"/api/session/{session.session_id}")
            assert resp.status_code == 200
            data = resp.json()

            # Dashboard session card needs these fields
            assert data["session_id"] == session.session_id
            assert "turn_count" in data
            assert "cumulative_risk" in data
            assert "violation_count" in data
            assert "is_locked" in data

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_session_not_found(self, session_store):
        """GET /api/session/{id} for nonexistent session returns error."""
        from sentinel.api.app import app

        with patch("sentinel.api.app._session_store", session_store):
            client = TestClient(app)
            resp = client.get("/api/session/nonexistent-id")
            assert resp.status_code == 200  # endpoint returns 200 with error field
            data = resp.json()
            assert "error" in data
