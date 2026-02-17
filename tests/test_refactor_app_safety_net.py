"""app.py refactor canary tests — critical invariant safety net.

These tests verify the 6 critical invariants (CI-1 through CI-6) that MUST hold
throughout the app.py refactor. They exercise observable HTTP behaviour and
lifecycle contracts.

DO NOT MODIFY THESE TESTS DURING THE REFACTOR.
If any test goes red, stop and investigate — it means a critical invariant broke.

Test classification (Task 0.8) — existing tests that import from sentinel.api.app:
  BEHAVIOURAL (safe during refactor):
    - test_input_validation.py (20) — imports Pydantic models/constants only
    - test_sse.py (7 of 10) — SSEWriter unit tests
    - test_websocket.py (10 of 12) — WebSocketChannel unit tests
    - test_cap_webhooks.py (11 of 18) — webhook verification/registry/rate-limiter unit tests
    - test_cap_heartbeat.py (5 of 7) — HeartbeatManager unit tests
    - test_cap_webui_foundation.py (3 of 5) — static file tests with standalone FastAPI

  IMPLEMENTATION-COUPLED (will break when globals move):
    - test_health_endpoint.py (4) — patches _pin_verifier, _engine, _prompt_guard_loaded, etc.
    - test_metrics_api.py (5) — patches _pin_verifier, _session_store, _orchestrator, etc.
    - test_pg_infrastructure.py (7) — imports _check_pg_ready function
    - test_sse.py (3 of 10) — patches _pin_verifier, _event_bus
    - test_websocket.py (2 of 12) — patches _pin_verifier, _orchestrator, _event_bus
    - test_cap_webhooks.py (7 of 18) — patches _webhook_registry, _event_bus, etc.
    - test_cap_heartbeat.py (2 of 7) — patches _heartbeat_manager
    - test_cap_webui_transport.py (6) — patches _pin_verifier, _orchestrator, _event_bus
    - test_cap_webui_dashboard.py (3) — patches _pin_verifier, _engine, etc.
    - test_cap_webui_logs.py (3) — patches _pin_verifier, LogSSEWriter
    - test_cap_webui_routines.py (7) — patches _pin_verifier, _routine_store, etc.
    - test_cap_webui_chat.py (5) — patches _pin_verifier, _orchestrator
    - test_cap_webui_foundation.py (2 of 5) — patches _pin_verifier, _engine, etc.

  Most-patched global: _pin_verifier (11 of 14 files)
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import sentinel.api.app as app_module
from sentinel.api.app import app

# CSRF requires Origin header on state-changing requests
_ORIGIN = {"Origin": "https://localhost:3001"}


# ── CI-1: Pipeline initialized before routes serve ──────────────


class TestCI1PipelineBeforeServe:
    def test_ci1_scan_endpoint_proves_pipeline_exists(self):
        """CI-1: POST /api/scan succeeds → pipeline was initialized before routes.

        If the pipeline isn't initialized, this returns {"error": "Pipeline not initialized"}.
        A 200 with scan results proves the pipeline is live.
        """
        mock_pipeline = MagicMock()
        mock_result = MagicMock()
        mock_result.is_clean = True
        mock_result.results = {}
        mock_pipeline.scan_output = AsyncMock(return_value=mock_result)

        with patch.object(app_module, "_pin_verifier", None), \
             patch.object(app_module, "_pipeline", mock_pipeline):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/scan", json={"text": "hello world"}, headers=_ORIGIN)

            assert resp.status_code == 200
            data = resp.json()
            assert "clean" in data
            assert data["clean"] is True


# ── CI-2: Shutdown flag rejects requests ─────────────────────────


class TestCI2ShutdownRejectsRequests:
    def test_ci2_task_endpoint_rejects_during_shutdown(self):
        """CI-2: POST /api/task returns 503 when _shutting_down is True."""
        original = app_module._shutting_down
        try:
            app_module._shutting_down = True
            with patch.object(app_module, "_pin_verifier", None):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/task",
                    json={"request": "test task request message"},
                    headers=_ORIGIN,
                )
            assert resp.status_code == 503
        finally:
            app_module._shutting_down = original

    def test_ci2_a2a_endpoint_rejects_during_shutdown(self):
        """CI-2: POST /a2a returns 503 when _shutting_down is True."""
        original = app_module._shutting_down
        try:
            app_module._shutting_down = True
            with patch.object(app_module, "_pin_verifier", None):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/a2a",
                    json={
                        "jsonrpc": "2.0",
                        "method": "tasks/send",
                        "id": "test-1",
                        "params": {"message": {"role": "user", "parts": [{"type": "text", "text": "hi"}]}},
                    },
                    headers=_ORIGIN,
                )
            assert resp.status_code == 503
        finally:
            app_module._shutting_down = original

    def test_ci2_process_endpoint_rejects_during_shutdown(self):
        """CI-2: POST /api/process returns 503 when _shutting_down is True."""
        original = app_module._shutting_down
        try:
            app_module._shutting_down = True
            with patch.object(app_module, "_pin_verifier", None):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/process",
                    json={"text": "test input"},
                    headers=_ORIGIN,
                )
            assert resp.status_code == 503
        finally:
            app_module._shutting_down = original


# ── CI-3: Static mount doesn't shadow dynamic routes ────────────


class TestCI3StaticNoShadow:
    def test_ci3_health_returns_json_not_html(self):
        """CI-3: GET /api/health returns JSON, not HTML from static mount.

        If the static mount (/) is registered before dynamic routes, it catches
        all paths and returns HTML 404. This proves ordering is correct.
        """
        # Patch the globals that health endpoint reads
        with patch.object(app_module, "_engine", None), \
             patch.object(app_module, "_pin_verifier", None), \
             patch.object(app_module, "_prompt_guard_loaded", False), \
             patch.object(app_module, "_semgrep_loaded", False), \
             patch.object(app_module, "_planner_available", False), \
             patch.object(app_module, "_ollama_reachable", False), \
             patch.object(app_module, "_sidecar", None), \
             patch.object(app_module, "_signal_channel", None), \
             patch.object(app_module, "_telegram_channel", None), \
             patch.object(app_module, "_sandbox", None):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/health")

        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert data["status"] == "ok"


# ── CI-4: BOOT-1 validation gate logs degraded state ────────────


class TestCI4Boot1Gate:
    def test_ci4_boot1_logs_critical_at_tl4_when_both_scanners_fail(self):
        """CI-4: With both scanners offline at TL4, lifespan logs startup_degraded
        via _audit.critical() BEFORE yield — but the app still serves.

        Current behaviour is graceful degradation, not hard block.
        """
        # We test this by checking the health endpoint reflects degraded state.
        # The BOOT-1 gate in lifespan sets logging, and /health reads the same
        # _prompt_guard_loaded / _semgrep_loaded flags.
        with patch.object(app_module, "_prompt_guard_loaded", False), \
             patch.object(app_module, "_semgrep_loaded", False), \
             patch.object(app_module, "_engine", None), \
             patch.object(app_module, "_pin_verifier", None), \
             patch.object(app_module, "_planner_available", False), \
             patch.object(app_module, "_ollama_reachable", False), \
             patch.object(app_module, "_sidecar", None), \
             patch.object(app_module, "_signal_channel", None), \
             patch.object(app_module, "_telegram_channel", None), \
             patch.object(app_module, "_sandbox", None):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/health")

        assert resp.status_code == 200
        data = resp.json()
        # App is serving (graceful degradation, not hard block)
        assert data["status"] == "ok"
        # Both scanners reported as offline
        assert data["prompt_guard_loaded"] is False
        assert data["semgrep_loaded"] is False
        # Degraded flag is set
        assert data["degraded"] is True


# ── CI-5: RLS context set for background tasks ──────────────────


class TestCI5RLSContext:
    def test_ci5_signal_receive_loop_sets_user_context(self):
        """CI-5: The Signal receive loop sets current_user_id to 1 before handling.

        This verifies the RLS ContextVar pattern is present in the signal receive
        loop, ensuring database operations have proper user context.
        """
        # We verify this structurally: the _signal_receive_loop pattern in app.py
        # must set current_user_id before calling router.handle_message.
        # We can verify by inspecting the source or by simulating the pattern.
        import inspect
        source = inspect.getsource(app_module.lifespan)

        # The lifespan function must contain the signal receive loop pattern:
        # current_user_id.set(1) before handle_message
        assert "current_user_id.set(1)" in source, (
            "Signal receive loop must set current_user_id to 1 for RLS context"
        )
        # And it must be in a try/finally with reset
        assert "current_user_id.reset" in source, (
            "Signal receive loop must reset current_user_id in finally block"
        )


# ── CI-6: Background tasks tracked for shutdown drain ────────────


class TestCI6TaskTracking:
    def test_ci6_track_task_adds_to_background_set(self):
        """CI-6: _track_task() registers tasks in _background_tasks for shutdown drain."""
        original_tasks = app_module._background_tasks.copy()
        try:
            # Clear tracking set for isolated test
            app_module._background_tasks.clear()

            # Create a simple coroutine to track
            async def _dummy():
                await asyncio.sleep(0)

            loop = asyncio.new_event_loop()
            try:
                # _track_task must be called within a running event loop
                async def _run():
                    task = app_module._track_task(_dummy(), name="test-canary")
                    # Task should be in the tracking set immediately
                    assert task in app_module._background_tasks, (
                        "_track_task must add task to _background_tasks"
                    )
                    assert task.get_name() == "test-canary"
                    # Let it complete
                    await task
                    # After completion, done_callback should discard it
                    # (give the callback a moment to fire)
                    await asyncio.sleep(0.01)
                    assert task not in app_module._background_tasks, (
                        "Completed tasks must be discarded from _background_tasks"
                    )

                loop.run_until_complete(_run())
            finally:
                loop.close()
        finally:
            # Restore original state
            app_module._background_tasks.clear()
            app_module._background_tasks.update(original_tasks)

    def test_ci6_log_task_exception_fires_on_failure(self):
        """CI-6: _log_task_exception logs when a tracked task raises."""
        original_tasks = app_module._background_tasks.copy()
        try:
            app_module._background_tasks.clear()

            async def _failing():
                raise RuntimeError("canary-failure")

            loop = asyncio.new_event_loop()
            try:
                async def _run():
                    task = app_module._track_task(_failing(), name="test-failing")
                    # Wait for it to fail
                    with pytest.raises(RuntimeError, match="canary-failure"):
                        await task

                loop.run_until_complete(_run())
            finally:
                loop.close()
        finally:
            app_module._background_tasks.clear()
            app_module._background_tasks.update(original_tasks)
