"""Tests for security headers, CSRF, and request size limit middleware."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from sentinel.api.middleware import (
    CSRFMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)


# ── Expected security headers ────────────────────────────────────

EXPECTED_HEADERS = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "x-xss-protection": "1; mode=block",
    "referrer-policy": "strict-origin-when-cross-origin",
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self' wss: ws:; frame-ancestors 'none';"
    ),
    "strict-transport-security": "max-age=31536000; includeSubDomains",
}


def _make_app():
    """Minimal FastAPI app with SecurityHeadersMiddleware for testing."""
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/ok")
    async def ok():
        return {"status": "ok"}

    @app.get("/error")
    async def error():
        return JSONResponse(status_code=500, content={"error": "something broke"})

    @app.get("/not-found")
    async def not_found():
        return JSONResponse(status_code=404, content={"error": "not found"})

    return app


class TestSecurityHeaders:
    @pytest.fixture
    def client(self):
        return TestClient(_make_app())

    def test_all_6_headers_present_on_success(self, client):
        resp = client.get("/ok")
        assert resp.status_code == 200
        for header_name, expected_value in EXPECTED_HEADERS.items():
            assert resp.headers.get(header_name) == expected_value, (
                f"Missing or wrong header: {header_name}"
            )

    def test_all_6_headers_present_on_error_response(self, client):
        resp = client.get("/error")
        assert resp.status_code == 500
        for header_name, expected_value in EXPECTED_HEADERS.items():
            assert resp.headers.get(header_name) == expected_value, (
                f"Missing header on error response: {header_name}"
            )

    def test_all_6_headers_present_on_404(self, client):
        resp = client.get("/not-found")
        assert resp.status_code == 404
        for header_name, expected_value in EXPECTED_HEADERS.items():
            assert resp.headers.get(header_name) == expected_value, (
                f"Missing header on 404 response: {header_name}"
            )

    def test_x_frame_options_deny(self, client):
        resp = client.get("/ok")
        assert resp.headers["x-frame-options"] == "DENY"

    def test_hsts_present(self, client):
        resp = client.get("/ok")
        assert "max-age=31536000" in resp.headers["strict-transport-security"]

    def test_csp_blocks_frames(self, client):
        resp = client.get("/ok")
        assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


class TestCSRFMiddleware:
    @pytest.fixture
    def client(self):
        app = FastAPI()
        app.add_middleware(CSRFMiddleware, allowed_origins=["https://example.com"])

        @app.post("/action")
        async def action():
            return {"status": "ok"}

        @app.get("/read")
        async def read():
            return {"status": "ok"}

        return TestClient(app)

    def test_allowed_origin_passes(self, client):
        resp = client.post("/action", headers={"Origin": "https://example.com"})
        assert resp.status_code == 200

    def test_disallowed_origin_blocked(self, client):
        resp = client.post("/action", headers={"Origin": "https://evil.com"})
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["reason"]

    def test_no_origin_header_passes(self, client):
        """Requests without Origin header pass (same-origin, CLI tools, etc.)."""
        resp = client.post("/action")
        assert resp.status_code == 200

    def test_get_requests_not_checked(self, client):
        resp = client.get("/read", headers={"Origin": "https://evil.com"})
        assert resp.status_code == 200


class TestRequestSizeLimitMiddleware:
    @pytest.fixture
    def client(self):
        app = FastAPI()
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=100)

        @app.post("/upload")
        async def upload():
            return {"status": "ok"}

        return TestClient(app)

    def test_small_request_passes(self, client):
        resp = client.post("/upload", content=b"x" * 50, headers={"Content-Length": "50"})
        assert resp.status_code == 200

    def test_oversized_request_rejected(self, client):
        resp = client.post("/upload", content=b"x" * 200, headers={"Content-Length": "200"})
        assert resp.status_code == 413
        assert "too large" in resp.json()["reason"].lower()
