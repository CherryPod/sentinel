"""Tests for GET /api/metrics endpoint."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from starlette.testclient import TestClient

from sentinel.api.auth import PinVerifier
from sentinel.core.approval import ApprovalManager
from sentinel.api.metrics import get_metrics
from tests.conftest import auth_headers


@pytest.fixture
def metrics_stores():
    """Create mock store instances for the metrics endpoint."""
    session_store = AsyncMock()
    session_store.get_auto_approved_count.return_value = 0
    session_store.get_turn_outcome_counts.return_value = {}
    session_store.get_blocked_by_counts.return_value = []
    session_store.get_session_health.return_value = {
        "active": 0, "locked": 0, "avg_risk": 0.0, "total_violations": 0,
    }
    session_store.get_response_time_stats.return_value = {
        "avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0,
    }

    approval_manager = AsyncMock()
    approval_manager.get_status_counts.return_value = {}

    orchestrator = MagicMock()
    orchestrator.approval_manager = approval_manager

    routine_engine = MagicMock()
    routine_engine.get_execution_stats = AsyncMock(return_value={
        "total": 0, "success": 0, "error": 0, "timeout": 0, "avg_duration_s": 0.0,
    })

    return session_store, orchestrator, routine_engine


class TestMetricsEndpoint:
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_metrics_endpoint_returns_all_sections(self, metrics_stores):
        session_store, orchestrator, routine_engine = metrics_stores
        with patch("sentinel.api.routes.health._session_store", session_store), \
             patch("sentinel.api.routes.health._orchestrator", orchestrator), \
             patch("sentinel.api.routes.health._routine_engine", routine_engine), \
             patch("sentinel.api.routes.health._get_metrics_fn", get_metrics):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics", headers=auth_headers())
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["window"] == "24h"
            assert "trust_level" in data
            # All data sections present
            for key in ["approval_funnel", "task_outcomes", "scanner_blocks",
                        "routine_health", "session_health", "response_times"]:
                assert key in data["data"], f"Missing section: {key}"

    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_metrics_window_parameter(self, metrics_stores):
        session_store, orchestrator, routine_engine = metrics_stores
        with patch("sentinel.api.routes.health._session_store", session_store), \
             patch("sentinel.api.routes.health._orchestrator", orchestrator), \
             patch("sentinel.api.routes.health._routine_engine", routine_engine), \
             patch("sentinel.api.routes.health._get_metrics_fn", get_metrics):
            from sentinel.api.app import app
            client = TestClient(app)
            for window in ["7d", "30d", "all"]:
                resp = client.get(f"/api/metrics?window={window}", headers=auth_headers())
                assert resp.status_code == 200
                assert resp.json()["window"] == window

    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_metrics_invalid_window(self, metrics_stores):
        session_store, orchestrator, routine_engine = metrics_stores
        with patch("sentinel.api.routes.health._session_store", session_store), \
             patch("sentinel.api.routes.health._orchestrator", orchestrator), \
             patch("sentinel.api.routes.health._routine_engine", routine_engine), \
             patch("sentinel.api.routes.health._get_metrics_fn", get_metrics):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics?window=1y", headers=auth_headers())
            assert resp.status_code == 422

    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_metrics_includes_trust_level(self, metrics_stores):
        session_store, orchestrator, routine_engine = metrics_stores
        with patch("sentinel.api.routes.health._session_store", session_store), \
             patch("sentinel.api.routes.health._orchestrator", orchestrator), \
             patch("sentinel.api.routes.health._routine_engine", routine_engine), \
             patch("sentinel.api.routes.health._get_metrics_fn", get_metrics), \
             patch("sentinel.core.config.settings.trust_level", 2):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics", headers=auth_headers())
            assert resp.status_code == 200
            assert resp.json()["trust_level"] == 2

    def test_metrics_auth_required(self, metrics_stores):
        """When PIN is set, unauthenticated requests should be rejected."""
        session_store, orchestrator, routine_engine = metrics_stores
        with patch("sentinel.api.routes.health._session_store", session_store), \
             patch("sentinel.api.routes.health._orchestrator", orchestrator), \
             patch("sentinel.api.routes.health._routine_engine", routine_engine), \
             patch("sentinel.api.routes.health._get_metrics_fn", get_metrics), \
             patch("sentinel.api.lifecycle._pin_verifier", PinVerifier("1234")), \
             patch("sentinel.api.app._pin_verifier", PinVerifier("1234")):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics")
            assert resp.status_code == 401
