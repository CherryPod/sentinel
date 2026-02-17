"""Tests for static file serving and HTTP→HTTPS redirect."""

import os
import tempfile

import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient

from sentinel.api.redirect import HTTPSRedirectApp


class TestStaticFileServing:
    """Verify static files are served correctly and don't shadow API routes."""

    @pytest.fixture
    def static_dir(self, tmp_path):
        """Create a temporary directory with static files."""
        (tmp_path / "index.html").write_text("<!DOCTYPE html><html><body>Sentinel UI</body></html>")
        (tmp_path / "style.css").write_text("body { color: white; }")
        (tmp_path / "app.js").write_text("console.log('hello');")
        return str(tmp_path)

    @pytest.fixture
    def client(self, static_dir):
        """App with API route and static files (mirrors production setup)."""
        app = FastAPI()

        @app.get("/api/health")
        async def health():
            return {"status": "ok"}

        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
        return TestClient(app)

    def test_root_serves_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Sentinel UI" in resp.text

    def test_css_served(self, client):
        resp = client.get("/style.css")
        assert resp.status_code == 200
        assert "color: white" in resp.text

    def test_js_served(self, client):
        resp = client.get("/app.js")
        assert resp.status_code == 200
        assert "console.log" in resp.text

    def test_api_route_not_shadowed(self, client):
        """API routes declared before static mount take priority."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_unknown_path_returns_404(self, client):
        """Paths that don't match files or API routes return 404."""
        resp = client.get("/nonexistent-file.xyz")
        assert resp.status_code == 404


class TestHTTPSRedirectApp:
    """Verify the redirect ASGI app returns correct 301 responses."""

    @pytest.fixture
    def client(self):
        from starlette.testclient import TestClient as StarletteClient
        return StarletteClient(HTTPSRedirectApp())

    def test_redirect_status_301(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 301

    def test_redirect_location_has_https(self, client):
        resp = client.get("/some/path", follow_redirects=False)
        location = resp.headers["location"]
        assert location.startswith("https://")
        assert "/some/path" in location

    def test_redirect_preserves_query_string(self, client):
        resp = client.get("/page?foo=bar", follow_redirects=False)
        location = resp.headers["location"]
        assert "foo=bar" in location

    def test_redirect_uses_external_port(self, client):
        from sentinel.core.config import settings
        resp = client.get("/", follow_redirects=False)
        location = resp.headers["location"]
        assert f":{settings.external_https_port}" in location
