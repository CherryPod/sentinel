"""Tests for GET /api/metrics endpoint."""

import sqlite3

import pytest
from unittest.mock import patch

from starlette.testclient import TestClient

from sentinel.api.auth import PinVerifier
from sentinel.core.db import _create_tables, _migrate_tables, _create_fts_index


@pytest.fixture
def metrics_db():
    """In-memory database usable across threads (TestClient requirement)."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("PRAGMA foreign_keys=ON")
    _create_tables(conn)
    _migrate_tables(conn)
    _create_fts_index(conn)
    conn.commit()
    yield conn
    conn.close()


class TestMetricsEndpoint:
    @patch("sentinel.api.app._pin_verifier", None)
    def test_metrics_endpoint_returns_all_sections(self, metrics_db):
        with patch("sentinel.api.app._db", metrics_db):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["window"] == "24h"
            assert "trust_level" in data
            # All data sections present
            for key in ["approval_funnel", "task_outcomes", "scanner_blocks",
                        "routine_health", "session_health", "response_times"]:
                assert key in data["data"], f"Missing section: {key}"

    @patch("sentinel.api.app._pin_verifier", None)
    def test_metrics_window_parameter(self, metrics_db):
        with patch("sentinel.api.app._db", metrics_db):
            from sentinel.api.app import app
            client = TestClient(app)
            for window in ["7d", "30d", "all"]:
                resp = client.get(f"/api/metrics?window={window}")
                assert resp.status_code == 200
                assert resp.json()["window"] == window

    @patch("sentinel.api.app._pin_verifier", None)
    def test_metrics_invalid_window(self, metrics_db):
        with patch("sentinel.api.app._db", metrics_db):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics?window=1y")
            assert resp.status_code == 422

    @patch("sentinel.api.app._pin_verifier", None)
    def test_metrics_includes_trust_level(self, metrics_db):
        with patch("sentinel.api.app._db", metrics_db), \
             patch("sentinel.core.config.settings.trust_level", 2):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics")
            assert resp.status_code == 200
            assert resp.json()["trust_level"] == 2

    def test_metrics_auth_required(self, metrics_db):
        """When PIN is set, unauthenticated requests should be rejected."""
        with patch("sentinel.api.app._db", metrics_db), \
             patch("sentinel.api.app._pin_verifier", PinVerifier("1234")):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/metrics")
            assert resp.status_code == 401
