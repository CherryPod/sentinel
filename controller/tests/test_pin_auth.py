import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from app.auth import PinAuthMiddleware


def _make_app(pin_getter):
    """Minimal FastAPI app with PinAuthMiddleware for isolated testing."""
    app = FastAPI()
    app.add_middleware(PinAuthMiddleware, pin_getter=pin_getter)

    @app.get("/health")
    async def health():
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
