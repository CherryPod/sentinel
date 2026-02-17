"""E2b capability tests — Routines view (CRUD, toggle, trigger, history APIs).

Tests verify the routine API endpoints return correct data for the
routine management view: list, create, update, delete, trigger, history.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from sentinel.routines.store import RoutineStore

# Valid Origin header for CSRF middleware — matches settings.allowed_origins default
_ORIGIN = {"Origin": "https://localhost:3001"}


@pytest.fixture
def routine_store():
    """Create a RoutineStore using in-memory dict (no database)."""
    return RoutineStore(pool=None)


@pytest.fixture
def client_with_store(routine_store):
    """TestClient with routine store patched into the real app."""
    from sentinel.api.app import app

    with patch("sentinel.api.lifecycle._pin_verifier", None), \
         patch("sentinel.api.routes.routines._routine_store", routine_store), \
         patch("sentinel.api.routes.routines._routine_engine", None):
        yield TestClient(app), routine_store


class TestRoutineList:
    """Routine listing tests."""

    @pytest.mark.capability
    def test_routine_list_empty(self, client_with_store):
        """GET /api/routine with no routines returns empty list."""
        client, _ = client_with_store
        resp = client.get("/api/routine")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["routines"] == []
        assert data["count"] == 0


class TestRoutineCreate:
    """Routine creation tests."""

    @pytest.mark.capability
    def test_routine_create_cron(self, client_with_store):
        """POST /api/routine with valid cron trigger creates routine."""
        client, _ = client_with_store
        resp = client.post("/api/routine", json={
            "name": "Daily summary",
            "trigger_type": "cron",
            "trigger_config": {"cron": "0 9 * * *"},
            "action_config": {"prompt": "Summarise today's activity"},
        }, headers=_ORIGIN)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["routine"]["name"] == "Daily summary"
        assert data["routine"]["trigger_type"] == "cron"
        assert data["routine"]["enabled"] is True

        # Verify it appears in the list
        resp2 = client.get("/api/routine")
        assert resp2.json()["count"] == 1

    @pytest.mark.capability
    def test_routine_create_invalid_trigger(self, client_with_store):
        """POST /api/routine with invalid cron expression returns 400."""
        client, _ = client_with_store
        resp = client.post("/api/routine", json={
            "name": "Bad cron",
            "trigger_type": "cron",
            "trigger_config": {"cron": "not a cron"},
            "action_config": {"prompt": "Do something"},
        }, headers=_ORIGIN)
        assert resp.status_code == 400
        assert resp.json()["status"] == "error"

    @pytest.mark.capability
    def test_routine_create_missing_prompt(self, client_with_store):
        """POST /api/routine with empty name is rejected."""
        client, _ = client_with_store
        resp = client.post("/api/routine", json={
            "name": "",
            "trigger_type": "cron",
            "trigger_config": {"cron": "0 9 * * *"},
            "action_config": {"prompt": "Do something"},
        }, headers=_ORIGIN)
        assert resp.status_code == 422  # Pydantic validation


class TestRoutineToggle:
    """Routine enable/disable toggle tests."""

    @pytest.mark.capability
    async def test_routine_toggle_enabled(self, client_with_store):
        """PATCH /api/routine/{id} can toggle enabled flag."""
        client, store = client_with_store

        # Create enabled routine
        routine = await store.create(
            name="Toggle test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Test"},
            enabled=True,
        )

        # Disable it
        resp = client.patch(
            f"/api/routine/{routine.routine_id}",
            json={"enabled": False},
            headers=_ORIGIN,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["routine"]["enabled"] is False

        # Re-enable it
        resp2 = client.patch(
            f"/api/routine/{routine.routine_id}",
            json={"enabled": True},
            headers=_ORIGIN,
        )
        assert resp2.status_code == 200
        assert resp2.json()["routine"]["enabled"] is True


class TestRoutineDelete:
    """Routine deletion tests."""

    @pytest.mark.capability
    async def test_routine_delete(self, client_with_store):
        """DELETE /api/routine/{id} removes the routine."""
        client, store = client_with_store

        routine = await store.create(
            name="To delete",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Test"},
        )

        resp = client.delete(f"/api/routine/{routine.routine_id}", headers=_ORIGIN)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        # Verify it's gone
        resp2 = client.get("/api/routine")
        assert resp2.json()["count"] == 0


class TestRoutineExecutionHistory:
    """Routine execution history tests."""

    @pytest.mark.capability
    async def test_routine_execution_history(self, client_with_store):
        """GET /api/routine/{id}/executions returns history (empty when no engine)."""
        client, store = client_with_store

        routine = await store.create(
            name="History test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Test"},
        )

        resp = client.get(f"/api/routine/{routine.routine_id}/executions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "executions" in data


class TestRoutineManualTrigger:
    """Routine manual trigger tests."""

    @pytest.mark.capability
    async def test_routine_manual_trigger_engine_disabled(self, client_with_store):
        """POST /api/routine/{id}/run with no engine returns 503."""
        client, store = client_with_store

        routine = await store.create(
            name="Trigger test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Test"},
        )

        # _routine_engine is None (patched in fixture)
        resp = client.post(f"/api/routine/{routine.routine_id}/run", headers=_ORIGIN)
        assert resp.status_code == 503
        assert resp.json()["reason"] == "Routine engine not running"


class TestRoutineRateLimit:
    """Routine API rate limiting tests."""

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_routine_rate_limit(self):
        """POST /api/routine respects per-user max routine limit."""
        from sentinel.api.app import app
        from sentinel.core.config import settings

        store = RoutineStore(pool=None)

        # Set a low limit for testing
        original_max = settings.routine_max_per_user
        settings.routine_max_per_user = 2

        try:
            with patch("sentinel.api.routes.routines._routine_store", store), \
                 patch("sentinel.api.routes.routines._routine_engine", None):
                client = TestClient(app)

                # Create up to the limit
                for i in range(2):
                    resp = client.post("/api/routine", json={
                        "name": f"Routine {i}",
                        "trigger_type": "cron",
                        "trigger_config": {"cron": "0 9 * * *"},
                        "action_config": {"prompt": f"Task {i}"},
                    }, headers=_ORIGIN)
                    assert resp.status_code == 200, f"Routine {i} failed: {resp.json()}"

                # Third should be rejected (rate limit / max per user)
                resp = client.post("/api/routine", json={
                    "name": "Over limit",
                    "trigger_type": "cron",
                    "trigger_config": {"cron": "0 9 * * *"},
                    "action_config": {"prompt": "Should fail"},
                }, headers=_ORIGIN)
                assert resp.status_code == 429
        finally:
            settings.routine_max_per_user = original_max
