"""Tests for health endpoint config fields (runner hardening)."""
from unittest.mock import patch

from fastapi.testclient import TestClient

from sentinel.api.routes.health import HealthState


def _make_health_state(**overrides) -> HealthState:
    """Build a HealthState with optional overrides."""
    defaults = dict(
        prompt_guard_loaded=True,
        semgrep_loaded=True,
        ollama_reachable=True,
        planner_available=True,
        engine=True,
        pin_verifier=None,
    )
    defaults.update(overrides)
    return HealthState(**defaults)


class TestHealthConfigFields:
    """Verify /health and /api/health expose config for runner verification."""

    @patch("sentinel.api.lifecycle._pin_verifier", None)
    @patch("sentinel.api.routes.health._health_state")
    def test_health_includes_approval_mode(self, mock_hs):
        mock_hs.__class__ = HealthState
        # Replace with real HealthState so attribute access works
        import sentinel.api.routes.health as hmod
        hmod._health_state = _make_health_state()
        try:
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert "approval_mode" in data
            assert data["approval_mode"] in ("full", "smart", "auto")
        finally:
            hmod._health_state = None

    @patch("sentinel.api.lifecycle._pin_verifier", None)
    @patch("sentinel.api.routes.health._health_state")
    def test_health_includes_benchmark_mode(self, mock_hs):
        import sentinel.api.routes.health as hmod
        hmod._health_state = _make_health_state()
        try:
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert "benchmark_mode" in data
            assert isinstance(data["benchmark_mode"], bool)
        finally:
            hmod._health_state = None

    @patch("sentinel.api.lifecycle._pin_verifier", None)
    @patch("sentinel.api.routes.health._health_state")
    def test_api_health_includes_approval_mode(self, mock_hs):
        import sentinel.api.routes.health as hmod
        hmod._health_state = _make_health_state()
        try:
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert "approval_mode" in data
            assert data["approval_mode"] in ("full", "smart", "auto")
        finally:
            hmod._health_state = None

    @patch("sentinel.api.lifecycle._pin_verifier", None)
    @patch("sentinel.api.routes.health._health_state")
    def test_api_health_includes_benchmark_mode(self, mock_hs):
        import sentinel.api.routes.health as hmod
        hmod._health_state = _make_health_state()
        try:
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert "benchmark_mode" in data
            assert isinstance(data["benchmark_mode"], bool)
        finally:
            hmod._health_state = None
