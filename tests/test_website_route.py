"""Tests for the /sites static file serving route."""
import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.testclient import TestClient


def _make_sites_app(tmp_path):
    """Create a minimal app with /sites mount pointing at tmp_path/sites."""
    sites_dir = tmp_path / "sites"
    sites_dir.mkdir()

    app = FastAPI()
    app.mount("/sites", StaticFiles(directory=str(sites_dir), html=True), name="sites")
    return app, sites_dir


class TestSitesRoute:
    def test_serves_site_index_html(self, tmp_path):
        app, sites_dir = _make_sites_app(tmp_path)
        site_dir = sites_dir / "test-site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Hello</body></html>")

        client = TestClient(app)
        resp = client.get("/sites/test-site/index.html")
        assert resp.status_code == 200
        assert "Hello" in resp.text

    def test_directory_index_serves_index_html(self, tmp_path):
        """GET /sites/test-site/ serves index.html via html=True directory index."""
        app, sites_dir = _make_sites_app(tmp_path)
        site_dir = sites_dir / "test-site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Directory Index</body></html>")

        client = TestClient(app)
        resp = client.get("/sites/test-site/")
        assert resp.status_code == 200
        assert "Directory Index" in resp.text

    def test_serves_site_css(self, tmp_path):
        app, sites_dir = _make_sites_app(tmp_path)
        site_dir = sites_dir / "test-site"
        site_dir.mkdir()
        (site_dir / "style.css").write_text("body { color: red; }")

        client = TestClient(app)
        resp = client.get("/sites/test-site/style.css")
        assert resp.status_code == 200
        assert "color: red" in resp.text

    def test_nonexistent_site_returns_404(self, tmp_path):
        app, _sites_dir = _make_sites_app(tmp_path)
        client = TestClient(app)
        resp = client.get("/sites/no-such-site/index.html")
        assert resp.status_code == 404
