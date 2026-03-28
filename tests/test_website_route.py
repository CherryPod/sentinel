"""Tests for the /sites dynamic file serving route.

Sites live at /workspace/{user_id}/sites/{site_id}/ but are served at
/sites/{site_id}/ via the dynamic route registered by _register_sites_route().
"""
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from sentinel.api.lifecycle import _register_sites_route


def _make_sites_app(tmp_path):
    """Create a minimal app with dynamic /sites route backed by tmp_path."""
    app = FastAPI()
    with patch("sentinel.api.lifecycle.settings") as mock_settings:
        mock_settings.workspace_path = str(tmp_path)
        _register_sites_route(app)
    return app


def _create_site(tmp_path, user_id, site_id, filename="index.html", content="<html>Hello</html>"):
    """Helper: create a site file under /workspace/{user_id}/sites/{site_id}/."""
    site_dir = tmp_path / str(user_id) / "sites" / site_id
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / filename).write_text(content)
    return site_dir


class TestSitesRoute:
    def test_serves_site_index_html(self, tmp_path):
        app = _make_sites_app(tmp_path)
        _create_site(tmp_path, 1, "test-site", "index.html", "<html><body>Hello</body></html>")

        client = TestClient(app)
        resp = client.get("/sites/test-site/index.html")
        assert resp.status_code == 200
        assert "Hello" in resp.text

    def test_directory_index_serves_index_html(self, tmp_path):
        """GET /sites/test-site serves index.html by default."""
        app = _make_sites_app(tmp_path)
        _create_site(tmp_path, 1, "test-site", "index.html", "<html>Directory Index</html>")

        client = TestClient(app)
        resp = client.get("/sites/test-site")
        assert resp.status_code == 200
        assert "Directory Index" in resp.text

    def test_serves_site_css(self, tmp_path):
        app = _make_sites_app(tmp_path)
        _create_site(tmp_path, 1, "test-site", "style.css", "body { color: red; }")

        client = TestClient(app)
        resp = client.get("/sites/test-site/style.css")
        assert resp.status_code == 200
        assert "color: red" in resp.text

    def test_nonexistent_site_returns_404(self, tmp_path):
        app = _make_sites_app(tmp_path)
        client = TestClient(app)
        resp = client.get("/sites/no-such-site/index.html")
        assert resp.status_code == 404

    def test_serves_from_different_users(self, tmp_path):
        """A site created by user 2 is reachable at /sites/{site_id}/."""
        app = _make_sites_app(tmp_path)
        _create_site(tmp_path, 2, "user2-site", "index.html", "<html>User 2</html>")

        client = TestClient(app)
        resp = client.get("/sites/user2-site")
        assert resp.status_code == 200
        assert "User 2" in resp.text

    def test_path_traversal_blocked(self, tmp_path):
        app = _make_sites_app(tmp_path)
        _create_site(tmp_path, 1, "test-site")

        client = TestClient(app)
        resp = client.get("/sites/../../../etc/passwd")
        assert resp.status_code in (400, 404)

    def test_site_id_traversal_blocked(self, tmp_path):
        app = _make_sites_app(tmp_path)
        client = TestClient(app)
        resp = client.get("/sites/..%2F..%2Fetc/passwd")
        assert resp.status_code in (400, 404)
