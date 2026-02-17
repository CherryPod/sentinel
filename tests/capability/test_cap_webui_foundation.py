"""E2a capability tests — Web UI foundation (static files, health, auth).

Tests verify that the restructured UI files are served correctly and that
the health/auth endpoints return data sufficient for the UI to function.
"""

import pytest
from unittest.mock import patch

from sentinel.api.auth import PinVerifier
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient

# Valid Origin header for CSRF middleware — matches settings.allowed_origins default
_ORIGIN = {"Origin": "https://localhost:3001"}


# ── Static file serving tests ──────────────────────────────────


class TestStaticFoundation:
    """Verify restructured UI static files serve correctly."""

    @pytest.fixture
    def static_dir(self, tmp_path):
        """Create temp directory with mock UI files matching new structure."""
        (tmp_path / "index.html").write_text(
            '<!DOCTYPE html><html><body><nav id="nav-rail"></nav></body></html>'
        )
        (tmp_path / "style.css").write_text(
            ':root { --accent-bold: #C41E3A; } #nav-rail { width: 200px; }'
        )
        (tmp_path / "app.js").write_text(
            'function showView(name) { /* view routing */ }'
        )
        (tmp_path / "manifest.json").write_text(
            '{"name": "Sentinel", "theme_color": "#C41E3A"}'
        )
        return str(tmp_path)

    @pytest.fixture
    def client(self, static_dir):
        app = FastAPI()

        @app.get("/api/health")
        async def health():
            return {"status": "ok"}

        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
        return TestClient(app)

    @pytest.mark.capability
    def test_static_files_served(self, client):
        """GET / returns HTML with nav-rail element."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "nav-rail" in resp.text
        assert "text/html" in resp.headers.get("content-type", "")

    @pytest.mark.capability
    def test_static_css_served(self, client):
        """GET /style.css returns CSS with nav-rail styles."""
        resp = client.get("/style.css")
        assert resp.status_code == 200
        assert "nav-rail" in resp.text
        assert "text/css" in resp.headers.get("content-type", "")

    @pytest.mark.capability
    def test_static_js_served(self, client):
        """GET /app.js returns JS with view routing."""
        resp = client.get("/app.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers.get("content-type", "")


# ── Health endpoint tests ──────────────────────────────────────


class TestHealthEndpoint:

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    @patch("sentinel.api.lifecycle._engine", True)  # truthy = loaded
    @patch("sentinel.api.lifecycle._prompt_guard_loaded", True)
    @patch("sentinel.api.lifecycle._semgrep_loaded", True)
    @patch("sentinel.api.lifecycle._planner_available", True)
    def test_health_endpoint_returns_all_components(self):
        """GET /health returns status for all dashboard-required components."""
        from sentinel.api.app import app
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        # All required keys for dashboard health cards
        assert data["status"] == "ok"
        assert "policy_loaded" in data
        assert "prompt_guard_loaded" in data
        assert "semgrep_loaded" in data
        assert "planner_available" in data
        assert "conversation_tracking" in data
        assert "pin_auth_enabled" in data
        # Phase A additions
        assert "sidecar" in data
        assert "signal" in data


# ── PIN auth tests ──────────────────────────────────────────────


class TestPinAuth:

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.app._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.routes.task._orchestrator", None)
    def test_pin_auth_blocks_unauthenticated(self):
        """POST /api/task without PIN header returns 401."""
        from sentinel.api.app import app
        client = TestClient(app)
        resp = client.post("/api/task", json={"request": "Hello world"}, headers=_ORIGIN)
        assert resp.status_code == 401

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.app._pin_verifier", PinVerifier("1234"))
    @patch("sentinel.api.routes.task._orchestrator", None)
    def test_pin_auth_accepts_valid_pin(self):
        """POST /api/task with valid PIN is not rejected with 401.

        The request may still fail (orchestrator not initialized) but
        auth should pass — we check it's NOT a 401.
        """
        from sentinel.api.app import app
        client = TestClient(app)
        resp = client.post(
            "/api/task",
            json={"request": "Hello world"},
            headers={"X-Sentinel-Pin": "1234", **_ORIGIN},
        )
        # Should not be 401 (auth passed). May be 200 with error about orchestrator.
        assert resp.status_code != 401
