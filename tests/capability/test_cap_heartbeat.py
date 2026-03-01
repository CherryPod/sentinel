"""C2 capability tests — Heartbeat System.

Verifies the 5 deployment-gate behaviours: scheduled health checks,
degraded service detection, system memory protection, API endpoint,
and failure recovery.

All tests use in-memory SQLite and mock health check functions.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.db import init_db
from sentinel.memory.chunks import MemoryStore
from sentinel.routines.heartbeat import (
    HEARTBEAT_SOURCE,
    HeartbeatManager,
    seed_heartbeat_routine,
)
from sentinel.routines.store import RoutineStore

pytestmark = pytest.mark.capability


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def memory_store(db):
    return MemoryStore(db=db)


@pytest.fixture
def healthy_check():
    """Health check function that returns all-healthy data."""

    async def _check():
        return {
            "planner_available": True,
            "semgrep_loaded": True,
            "prompt_guard_loaded": True,
            "sidecar": "running",
            "signal": "disabled",
        }

    return _check


@pytest.fixture
def heartbeat(memory_store, healthy_check, db):
    return HeartbeatManager(
        memory_store=memory_store,
        health_check_fn=healthy_check,
        db=db,
    )


# ── Tests ────────────────────────────────────────────────────────


class TestHeartbeatFiresOnSchedule:
    """heartbeat_fires_on_schedule — run_heartbeat stores result in memory."""

    async def test_heartbeat_stores_in_memory(self, heartbeat, memory_store, db):
        health = await heartbeat.run_heartbeat()

        assert health["planner_available"] is True
        assert heartbeat._last_check_at is not None
        assert heartbeat._consecutive_failures == 0

        # Verify stored in memory with correct source
        row = db.execute(
            "SELECT content, source FROM memory_chunks WHERE source = ?",
            (HEARTBEAT_SOURCE,),
        ).fetchone()
        assert row is not None
        assert "healthy" in row[0]
        assert row[1] == HEARTBEAT_SOURCE

    async def test_seed_heartbeat_routine_creates_once(self, db):
        store = RoutineStore(db=db)

        # First call creates the routine
        rid = seed_heartbeat_routine(store)
        assert rid is not None

        # Second call is idempotent — returns None
        rid2 = seed_heartbeat_routine(store)
        assert rid2 is None


class TestHeartbeatDetectsDegradedService:
    """heartbeat_detects_degraded_service — identifies failed components."""

    async def test_detects_planner_down(self, memory_store, db):
        async def _degraded():
            return {
                "planner_available": False,
                "semgrep_loaded": True,
                "prompt_guard_loaded": True,
                "sidecar": "running",
                "signal": "disabled",
            }

        hb = HeartbeatManager(memory_store=memory_store, health_check_fn=_degraded, db=db)
        await hb.run_heartbeat()

        summary = hb.get_status_summary()
        assert summary["status"] == "degraded"
        assert "planner" in summary["degraded_components"]

    async def test_detects_multiple_degraded(self, memory_store, db):
        async def _multi_fail():
            return {
                "planner_available": False,
                "semgrep_loaded": False,
                "prompt_guard_loaded": True,
                "sidecar": "stopped",
                "signal": "disabled",
            }

        hb = HeartbeatManager(memory_store=memory_store, health_check_fn=_multi_fail, db=db)
        await hb.run_heartbeat()

        summary = hb.get_status_summary()
        assert summary["status"] == "degraded"
        assert "planner" in summary["degraded_components"]
        assert "semgrep" in summary["degraded_components"]
        assert "sidecar" in summary["degraded_components"]

    async def test_healthy_status_when_all_ok(self, heartbeat):
        await heartbeat.run_heartbeat()

        summary = heartbeat.get_status_summary()
        assert summary["status"] == "healthy"
        assert summary["degraded_components"] == []

    def test_unknown_status_before_first_check(self, heartbeat):
        summary = heartbeat.get_status_summary()
        assert summary["status"] == "unknown"


class TestHeartbeatMemoryProtected:
    """heartbeat_memory_protected — system: source entries cannot be deleted."""

    async def test_cannot_delete_heartbeat_entry(self, heartbeat, memory_store, db):
        await heartbeat.run_heartbeat()

        # Find the heartbeat chunk
        row = db.execute(
            "SELECT chunk_id FROM memory_chunks WHERE source = ?",
            (HEARTBEAT_SOURCE,),
        ).fetchone()
        assert row is not None

        # Attempt to delete — should raise ValueError
        with pytest.raises(ValueError, match="system-protected"):
            memory_store.delete(row[0])

    def test_can_delete_normal_entries(self, memory_store):
        chunk_id = memory_store.store(content="test data", source="user")
        deleted = memory_store.delete(chunk_id)
        assert deleted is True

    def test_system_protection_in_memory_fallback(self):
        """In-memory store also blocks system: deletion."""
        store = MemoryStore(db=None)
        chunk_id = store.store(content="heartbeat data", source="system:heartbeat")

        with pytest.raises(ValueError, match="system-protected"):
            store.delete(chunk_id)


class TestHeartbeatApiEndpoint:
    """heartbeat_api_endpoint — GET /api/heartbeat returns status via module global."""

    async def test_heartbeat_endpoint_returns_status(self, heartbeat):
        import sentinel.api.app as app_module

        original = app_module._heartbeat_manager
        try:
            app_module._heartbeat_manager = heartbeat
            await heartbeat.run_heartbeat()

            import httpx
            from httpx import ASGITransport

            transport = ASGITransport(app=app_module.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                resp = await client.get("/api/heartbeat")

            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert "heartbeat" in data
            assert "degraded_components" in data["heartbeat"]
            assert "last_check_at" in data["heartbeat"]
        finally:
            app_module._heartbeat_manager = original

    async def test_heartbeat_endpoint_503_when_not_initialized(self):
        import sentinel.api.app as app_module

        original = app_module._heartbeat_manager
        try:
            app_module._heartbeat_manager = None

            import httpx
            from httpx import ASGITransport

            transport = ASGITransport(app=app_module.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                resp = await client.get("/api/heartbeat")

            assert resp.status_code == 503
        finally:
            app_module._heartbeat_manager = original


class TestHeartbeatContinuesAfterFailure:
    """heartbeat_continues_after_failure — failures increment counter, next check recovers."""

    async def test_failure_increments_then_recovers(self, memory_store, db):
        call_count = 0

        async def _fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise RuntimeError("service unavailable")
            return {
                "planner_available": True,
                "semgrep_loaded": True,
                "prompt_guard_loaded": True,
                "sidecar": "running",
                "signal": "disabled",
            }

        hb = HeartbeatManager(
            memory_store=memory_store,
            health_check_fn=_fail_then_succeed,
            db=db,
        )

        # First two calls fail
        with pytest.raises(RuntimeError):
            await hb.run_heartbeat()
        assert hb._consecutive_failures == 1

        with pytest.raises(RuntimeError):
            await hb.run_heartbeat()
        assert hb._consecutive_failures == 2

        # Third call succeeds — counter resets
        health = await hb.run_heartbeat()
        assert hb._consecutive_failures == 0
        assert health["planner_available"] is True
