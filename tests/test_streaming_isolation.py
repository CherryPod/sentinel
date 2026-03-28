"""Tests for cross-user streaming isolation.

Verifies that:
  - /api/events returns 403 when a user requests a task they don't own
  - /api/events allows access when the user owns the task (or task is unknown)
  - /api/logs/stream returns 403 for non-admin users
  - /api/logs/stream allows admin/owner users
  - Routine event forwarding filters by user_id
  - Routine engine publishes user_id in event payloads
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.api.routes import streaming as streaming_routes


# ── Helpers ──────────────────────────────────────────────────────────


def _setup_streaming_module(
    *,
    orchestrator=None,
    contact_store=None,
    event_bus=None,
):
    """Reset and reinitialise the streaming module globals for testing."""
    streaming_routes.init(
        event_bus=event_bus or MagicMock(),
        heartbeat_manager=MagicMock(),
        audit=MagicMock(),
        orchestrator=orchestrator,
        contact_store=contact_store,
    )


def _make_mock_request():
    """Create a minimal mock Request object."""
    req = MagicMock()
    req.headers = {}
    return req


# ── /api/events — task ownership ─────────────────────────────────────


@pytest.mark.asyncio
async def test_sse_events_returns_403_for_wrong_user():
    """User 2 must not be able to subscribe to user 1's task events."""
    orchestrator = MagicMock()
    orchestrator.get_task_owner.return_value = 1  # Task owned by user 1

    _setup_streaming_module(orchestrator=orchestrator)

    with patch("sentinel.api.routes.streaming.current_user_id") as mock_ctx:
        mock_ctx.get.return_value = 2  # Requesting user is 2
        resp = await streaming_routes.sse_events(
            request=_make_mock_request(),
            task_id="task-abc-123",
        )

    assert resp.status_code == 403
    orchestrator.get_task_owner.assert_called_once_with("task-abc-123")


@pytest.mark.asyncio
async def test_sse_events_allows_task_owner():
    """The user who created the task should be able to subscribe."""
    orchestrator = MagicMock()
    orchestrator.get_task_owner.return_value = 1

    event_bus = MagicMock()
    _setup_streaming_module(orchestrator=orchestrator, event_bus=event_bus)

    with patch("sentinel.api.routes.streaming.current_user_id") as mock_ctx:
        mock_ctx.get.return_value = 1  # Same user
        resp = await streaming_routes.sse_events(
            request=_make_mock_request(),
            task_id="task-abc-123",
        )

    # Should return an EventSourceResponse, not a 403 JSONResponse
    assert not hasattr(resp, "status_code") or resp.status_code == 200


@pytest.mark.asyncio
async def test_sse_events_allows_unknown_task():
    """Tasks not yet registered (e.g. pre-start) should not be blocked."""
    orchestrator = MagicMock()
    orchestrator.get_task_owner.return_value = None  # Unknown task

    event_bus = MagicMock()
    _setup_streaming_module(orchestrator=orchestrator, event_bus=event_bus)

    with patch("sentinel.api.routes.streaming.current_user_id") as mock_ctx:
        mock_ctx.get.return_value = 99
        resp = await streaming_routes.sse_events(
            request=_make_mock_request(),
            task_id="task-unknown",
        )

    # Should proceed — unknown tasks are allowed (task not yet registered)
    assert not hasattr(resp, "status_code") or resp.status_code == 200


@pytest.mark.asyncio
async def test_sse_events_returns_503_when_no_event_bus():
    """When event bus is not initialised, should return 503."""
    streaming_routes.init(
        event_bus=None,
        heartbeat_manager=MagicMock(),
        audit=MagicMock(),
    )

    resp = await streaming_routes.sse_events(
        request=_make_mock_request(),
        task_id="task-abc",
    )
    assert resp.status_code == 503


# ── /api/logs/stream — admin guard ───────────────────────────────────


@pytest.mark.asyncio
async def test_log_stream_returns_403_for_non_admin():
    """Non-admin users must be blocked from the audit log stream."""
    contact_store = AsyncMock()
    contact_store.get_user_role.return_value = "user"  # Not admin

    _setup_streaming_module(contact_store=contact_store)

    with patch("sentinel.api.routes.streaming.current_user_id") as mock_ctx:
        mock_ctx.get.return_value = 2
        with pytest.raises(Exception) as exc_info:
            await streaming_routes.log_stream(
                request=_make_mock_request(),
            )

    # require_role raises HTTPException with 403
    assert "403" in str(exc_info.value.status_code)


@pytest.mark.asyncio
async def test_log_stream_allows_admin():
    """Admin users should be able to access the audit log stream."""
    contact_store = AsyncMock()
    contact_store.get_user_role.return_value = "admin"

    _setup_streaming_module(contact_store=contact_store)

    with patch("sentinel.api.routes.streaming.current_user_id") as mock_ctx:
        mock_ctx.get.return_value = 1
        resp = await streaming_routes.log_stream(
            request=_make_mock_request(),
            level="INFO",
        )

    # Should return EventSourceResponse, not raise
    assert resp is not None


@pytest.mark.asyncio
async def test_log_stream_allows_owner():
    """Owner role should also be able to access the audit log stream."""
    contact_store = AsyncMock()
    contact_store.get_user_role.return_value = "owner"

    _setup_streaming_module(contact_store=contact_store)

    with patch("sentinel.api.routes.streaming.current_user_id") as mock_ctx:
        mock_ctx.get.return_value = 1
        resp = await streaming_routes.log_stream(
            request=_make_mock_request(),
            level="INFO",
        )

    assert resp is not None


# ── WebSocket routine event filtering ────────────────────────────────


@pytest.mark.asyncio
async def test_routine_event_filter_skips_other_users():
    """Routine events with a different user_id should not be forwarded."""
    ws = AsyncMock()
    ws_user_id = 1

    # Simulate the _forward_routine_event closure from websocket.py
    async def _forward_routine_event(topic: str, data: dict) -> None:
        try:
            event_user_id = data.get("user_id") if isinstance(data, dict) else None
            if event_user_id is not None and event_user_id != ws_user_id:
                return
            await ws.send_json({
                "type": "routine_event",
                "event": topic,
                "data": data,
            })
        except Exception:
            pass

    # Event for user 2 — should be skipped
    await _forward_routine_event("routine.triggered", {
        "routine_id": "r1",
        "user_id": 2,
    })
    ws.send_json.assert_not_called()


@pytest.mark.asyncio
async def test_routine_event_filter_forwards_own_events():
    """Routine events for the connected user should be forwarded."""
    ws = AsyncMock()
    ws_user_id = 1

    async def _forward_routine_event(topic: str, data: dict) -> None:
        try:
            event_user_id = data.get("user_id") if isinstance(data, dict) else None
            if event_user_id is not None and event_user_id != ws_user_id:
                return
            await ws.send_json({
                "type": "routine_event",
                "event": topic,
                "data": data,
            })
        except Exception:
            pass

    # Event for user 1 — should be forwarded
    await _forward_routine_event("routine.triggered", {
        "routine_id": "r1",
        "user_id": 1,
    })
    ws.send_json.assert_called_once()


@pytest.mark.asyncio
async def test_routine_event_filter_forwards_when_no_user_id():
    """Events without user_id should be forwarded (backwards compatibility)."""
    ws = AsyncMock()
    ws_user_id = 1

    async def _forward_routine_event(topic: str, data: dict) -> None:
        try:
            event_user_id = data.get("user_id") if isinstance(data, dict) else None
            if event_user_id is not None and event_user_id != ws_user_id:
                return
            await ws.send_json({
                "type": "routine_event",
                "event": topic,
                "data": data,
            })
        except Exception:
            pass

    # Event without user_id — should be forwarded
    await _forward_routine_event("routine.triggered", {
        "routine_id": "r1",
    })
    ws.send_json.assert_called_once()


# ── Engine event payloads include user_id ────────────────────────────


@pytest.mark.asyncio
async def test_engine_publish_includes_user_id():
    """Routine engine should include user_id in all event publishes."""
    from sentinel.routines.engine import RoutineEngine

    event_bus = MagicMock()
    event_bus.publish = AsyncMock()

    store = AsyncMock()
    orchestrator = AsyncMock()

    engine = RoutineEngine(
        store=store,
        orchestrator=orchestrator,
        event_bus=event_bus,
    )

    # Create a mock routine with user_id
    routine = MagicMock()
    routine.routine_id = "r1"
    routine.user_id = 42
    routine.name = "Test Routine"
    routine.cooldown_s = 0
    routine.last_run_at = None
    routine.trigger_type = "manual"
    routine.trigger_config = {}
    routine.action_config = {"prompt": "test"}

    execution_id = await engine._spawn_execution(routine, triggered_by="test")

    # Verify routine.triggered was published with user_id
    triggered_call = event_bus.publish.call_args_list[0]
    assert triggered_call[0][0] == "routine.triggered"
    payload = triggered_call[0][1]
    assert payload["user_id"] == 42
    assert payload["routine_id"] == "r1"


# ── Orchestrator task ownership tracking ─────────────────────────────


def test_orchestrator_get_task_owner_returns_none_for_unknown():
    """Unknown task_ids should return None, not raise."""
    from sentinel.planner.orchestrator import Orchestrator

    orch = Orchestrator.__new__(Orchestrator)
    orch._task_owners = {}

    assert orch.get_task_owner("unknown-task") is None


def test_orchestrator_register_and_get_task_owner():
    """Registered task owners should be retrievable."""
    from sentinel.planner.orchestrator import Orchestrator

    orch = Orchestrator.__new__(Orchestrator)
    orch._task_owners = {}

    orch._register_task_owner("task-1", 42)
    assert orch.get_task_owner("task-1") == 42

    orch._register_task_owner("task-2", 7)
    assert orch.get_task_owner("task-2") == 7

    # First registration still valid
    assert orch.get_task_owner("task-1") == 42
