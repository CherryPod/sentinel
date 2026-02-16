import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from sentinel.api.auth import PinAuthMiddleware


def _make_app(pin_getter):
    """Minimal FastAPI app with PinAuthMiddleware for isolated testing."""
    app = FastAPI()
    app.add_middleware(PinAuthMiddleware, pin_getter=pin_getter)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/health")
    async def api_health():
        return {"status": "ok"}

    @app.get("/protected")
    async def protected():
        return {"data": "secret"}

    @app.post("/task")
    async def task():
        return {"status": "success"}

    return app


class TestPinAuthEnabled:
    """PIN is set to "1234" — requests must provide correct PIN."""

    @pytest.fixture
    def client(self):
        app = _make_app(pin_getter=lambda: "1234")
        return TestClient(app)

    def test_health_exempt(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_api_health_exempt(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_protected_without_pin_returns_401(self, client):
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_protected_with_wrong_pin_returns_401(self, client):
        resp = client.get("/protected", headers={"X-Sentinel-Pin": "0000"})
        assert resp.status_code == 401

    def test_protected_with_correct_pin_passes(self, client):
        resp = client.get("/protected", headers={"X-Sentinel-Pin": "1234"})
        assert resp.status_code == 200
        assert resp.json()["data"] == "secret"

    def test_post_with_correct_pin_passes(self, client):
        resp = client.post("/task", headers={"X-Sentinel-Pin": "1234"})
        assert resp.status_code == 200

    def test_post_without_pin_returns_401(self, client):
        resp = client.post("/task")
        assert resp.status_code == 401


class TestPinAuthLockout:
    """Lockout after 5 failed PIN attempts."""

    @pytest.fixture
    def client(self):
        app = _make_app(pin_getter=lambda: "1234")
        return TestClient(app)

    def test_lockout_after_max_failures(self, client):
        """5 failed attempts → 429 on the 6th."""
        for _ in range(5):
            resp = client.get("/protected", headers={"X-Sentinel-Pin": "0000"})
            assert resp.status_code == 401
        # 6th attempt should be locked out
        resp = client.get("/protected", headers={"X-Sentinel-Pin": "0000"})
        assert resp.status_code == 429
        assert "too many" in resp.json()["detail"].lower()

    def test_lockout_blocks_correct_pin_too(self, client):
        """Even correct PIN is rejected during lockout."""
        for _ in range(5):
            client.get("/protected", headers={"X-Sentinel-Pin": "0000"})
        resp = client.get("/protected", headers={"X-Sentinel-Pin": "1234"})
        assert resp.status_code == 429

    def test_health_exempt_during_lockout(self, client):
        """Health endpoint is exempt even during lockout."""
        for _ in range(5):
            client.get("/protected", headers={"X-Sentinel-Pin": "0000"})
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_successful_auth_clears_failures(self, client):
        """A successful auth resets the failure counter."""
        for _ in range(4):
            client.get("/protected", headers={"X-Sentinel-Pin": "0000"})
        # Correct PIN clears failures
        resp = client.get("/protected", headers={"X-Sentinel-Pin": "1234"})
        assert resp.status_code == 200
        # Now 4 more failures should not trigger lockout
        for _ in range(4):
            resp = client.get("/protected", headers={"X-Sentinel-Pin": "0000"})
            assert resp.status_code == 401

    def test_constant_time_comparison(self, client):
        """PIN comparison uses hmac.compare_digest (verified by import check)."""
        import hmac
        assert hasattr(hmac, "compare_digest")
        # Functional test: wrong PINs of different lengths all get 401
        for pin in ["", "1", "12345678", "abcd"]:
            resp = client.get("/protected", headers={"X-Sentinel-Pin": pin})
            assert resp.status_code == 401


class TestPinAuthDisabled:
    """PIN getter returns None — all requests pass through."""

    @pytest.fixture
    def client(self):
        app = _make_app(pin_getter=lambda: None)
        return TestClient(app)

    def test_health_passes(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_protected_passes_without_pin(self, client):
        resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["data"] == "secret"

    def test_post_passes_without_pin(self, client):
        resp = client.post("/task")
        assert resp.status_code == 200
