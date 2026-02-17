"""Tests for MessageRouter — scan-first, classify, dispatch."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.bus import EventBus
from sentinel.core.confirmation import ConfirmationGate
from sentinel.core.context import current_user_id
from sentinel.core.models import TaskResult
from sentinel.router.classifier import ClassificationResult, Route
from sentinel.router.router import MessageRouter
from sentinel.session.store import Session


@pytest.fixture(autouse=True)
def _set_user_id():
    """Set current_user_id to 1 — matches user_id in gate.create() calls."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


# ── Helpers ───────────────────────────────────────────────────────


def _make_router(
    classifier_result: ClassificationResult | None = None,
    scan_clean: bool = True,
    session_locked: bool = False,
    router_enabled: bool = True,
    session_store_present: bool = True,
):
    """Build a MessageRouter with all dependencies mocked."""
    classifier = AsyncMock()
    classifier.classify.return_value = classifier_result or ClassificationResult(
        route=Route.PLANNER, reason="default",
    )

    pipeline = AsyncMock()
    scan_result = MagicMock()
    scan_result.is_clean = scan_clean
    scan_result.violations = (
        {}
        if scan_clean
        else {"test_scanner": MagicMock(matches=[MagicMock(pattern_name="test")])}
    )
    pipeline.scan_input.return_value = scan_result

    session_store: MagicMock | None
    if session_store_present:
        session_store = MagicMock()
        session = Session(session_id="test-session", source="signal")
        if session_locked:
            session.is_locked = True
        session_store.get_or_create = AsyncMock(return_value=session)
        session_store.add_turn = AsyncMock()
        session_store.get_lock.return_value = None
    else:
        session_store = None
        session = None

    fast_path = AsyncMock()
    fast_path.execute.return_value = {
        "status": "success",
        "response": "done",
        "reason": "",
        "template": "test_template",
    }

    orchestrator = AsyncMock()
    orchestrator.handle_task = AsyncMock(
        return_value=TaskResult(status="success"),
    )
    orchestrator.plan_and_execute = AsyncMock(
        return_value=TaskResult(status="success"),
    )

    bus = EventBus()

    router = MessageRouter(
        classifier=classifier,
        fast_path=fast_path,
        orchestrator=orchestrator,
        pipeline=pipeline,
        session_store=session_store,
        event_bus=bus,
        enabled=router_enabled,
    )
    return router, classifier, fast_path, orchestrator, pipeline, session_store, session


# ── Tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fast_route_dispatches_to_fast_path():
    """Fast classification dispatches to fast_path.execute, not orchestrator."""
    result_cls = ClassificationResult(
        route=Route.FAST, template_name="send_signal", params={"to": "alice"},
    )
    router, classifier, fast_path, orchestrator, *_ = _make_router(
        classifier_result=result_cls,
    )

    result = await router.route("send a signal", source="signal", source_key="k1")

    fast_path.execute.assert_awaited_once()
    orchestrator.handle_task.assert_not_awaited()
    assert result.status == "success"


@pytest.mark.asyncio
async def test_planner_route_dispatches_to_orchestrator():
    """Planner classification dispatches to orchestrator.plan_and_execute."""
    result_cls = ClassificationResult(route=Route.PLANNER, reason="complex")
    router, classifier, fast_path, orchestrator, *_ = _make_router(
        classifier_result=result_cls,
    )

    result = await router.route("do something complex", source="api", source_key="k2")

    orchestrator.plan_and_execute.assert_awaited_once()
    fast_path.execute.assert_not_awaited()
    assert result.status == "success"


@pytest.mark.asyncio
async def test_input_scan_blocks_before_classifier():
    """Dirty input scan blocks the request before classification runs."""
    router, classifier, fast_path, orchestrator, *_ = _make_router(scan_clean=False)

    result = await router.route("bad input", source="api", source_key="k3")

    classifier.classify.assert_not_awaited()
    fast_path.execute.assert_not_awaited()
    orchestrator.handle_task.assert_not_awaited()
    assert result.status == "blocked"


@pytest.mark.asyncio
async def test_locked_session_rejected():
    """Locked session returns blocked without reaching classifier."""
    router, classifier, fast_path, orchestrator, *_ = _make_router(
        session_locked=True,
    )

    result = await router.route("anything", source="signal", source_key="k4")

    classifier.classify.assert_not_awaited()
    assert result.status == "blocked"
    assert "locked" in result.reason.lower()


@pytest.mark.asyncio
async def test_disabled_router_passes_through():
    """When enabled=False, router calls orchestrator directly — no classification."""
    router, classifier, fast_path, orchestrator, *_ = _make_router(
        router_enabled=False,
    )

    result = await router.route(
        "anything", source="api", source_key="k5", task_id="t1",
    )

    orchestrator.handle_task.assert_awaited_once()
    classifier.classify.assert_not_awaited()
    assert result.status == "success"


@pytest.mark.asyncio
async def test_fast_path_gets_session_passed_through():
    """Session object is threaded through to fast_path.execute."""
    result_cls = ClassificationResult(
        route=Route.FAST, template_name="calendar_add", params={"title": "meeting"},
    )
    router, _, fast_path, _, _, _, session = _make_router(
        classifier_result=result_cls,
    )

    await router.route("add meeting", source="signal", source_key="k6")

    call_kwargs = fast_path.execute.call_args
    # session should be the 3rd positional arg (template_name, params, session)
    assert call_kwargs.args[2].session_id == "test-session"


@pytest.mark.asyncio
async def test_user_id_threaded_through():
    """user_id resolved by contact resolution reaches fast_path.execute.

    With no contact_store, resolve_contacts defaults to user_id=1.
    """
    result_cls = ClassificationResult(
        route=Route.FAST, template_name="send_signal", params={"to": "alice"},
    )
    router, _, fast_path, *_ = _make_router(classifier_result=result_cls)

    await router.route(
        "send signal", source="signal", source_key="k7",
    )

    call_kwargs = fast_path.execute.call_args
    # user_id is typically a keyword arg or 5th positional — default 1 from resolution
    all_args = list(call_kwargs.args) + list(call_kwargs.kwargs.values())
    assert 1 in all_args


@pytest.mark.asyncio
async def test_session_turn_recorded_on_input_block():
    """When input scan blocks, a ConversationTurn is recorded on the session."""
    router, _, _, _, _, _, session = _make_router(scan_clean=False)

    await router.route("bad stuff", source="signal", source_key="k8")

    assert len(session.turns) == 1
    assert session.turns[0].result_status == "blocked"


@pytest.mark.asyncio
async def test_no_session_store_gracefully_handled():
    """With session_store=None, routing still works (session will be None)."""
    result_cls = ClassificationResult(route=Route.PLANNER, reason="complex")
    router, _, fast_path, orchestrator, *_ = _make_router(
        classifier_result=result_cls, session_store_present=False,
    )

    result = await router.route("do something", source="api")

    # Should still reach the orchestrator without error
    orchestrator.plan_and_execute.assert_awaited_once()
    assert result.status == "success"


# ── Confirmation Intercept Tests ─────────────────────────────────


@pytest.mark.asyncio
async def test_go_confirms_and_executes():
    """'go' message with pending confirmation should confirm and execute."""
    gate = ConfirmationGate(pool=None, timeout=600)
    cid = await gate.create(
        user_id=1, channel="signal", source_key="signal:abc",
        tool_name="signal_send",
        tool_params={"message": "hello", "recipient": "alice"},
        preview_text="Send via Signal to Alice: hello",
        original_request="tell alice hello",
        task_id="task-001",
    )

    router, classifier, fast_path, orchestrator, *_ = _make_router()
    router._confirmation_gate = gate

    fast_path.execute_confirmed = AsyncMock(
        return_value={"status": "success", "response": "sent", "reason": ""},
    )

    result = await router.route(
        user_request="go",
        source="signal",
        source_key="signal:abc",
    )

    assert result.status == "success"
    # Pending should be cleared
    assert await gate.get_pending("signal:abc") is None


@pytest.mark.asyncio
async def test_go_case_insensitive():
    """'GO', 'Go', ' go ' should all work."""
    gate = ConfirmationGate(pool=None, timeout=600)
    await gate.create(
        user_id=1, channel="signal", source_key="signal:abc",
        tool_name="signal_send",
        tool_params={"message": "hi", "recipient": "alice"},
        preview_text="preview", original_request="request",
        task_id="task-002",
    )
    router, _, fast_path, *_ = _make_router()
    router._confirmation_gate = gate
    fast_path.execute_confirmed = AsyncMock(
        return_value={"status": "success", "response": "sent", "reason": ""},
    )

    result = await router.route(
        user_request="  GO  ",
        source="signal",
        source_key="signal:abc",
    )
    assert result.status == "success"


@pytest.mark.asyncio
async def test_non_go_cancels_and_routes_normally():
    """Any message other than 'go' cancels the pending and routes the new message."""
    gate = ConfirmationGate(pool=None, timeout=600)
    cid = await gate.create(
        user_id=1, channel="signal", source_key="signal:abc",
        tool_name="signal_send",
        tool_params={"message": "hi", "recipient": "alice"},
        preview_text="preview", original_request="request",
        task_id="task-003",
    )
    router, classifier, fast_path, orchestrator, *_ = _make_router()
    router._confirmation_gate = gate

    result = await router.route(
        user_request="search my email instead",
        source="signal",
        source_key="signal:abc",
    )
    # Confirmation should be cancelled
    assert await gate.get_pending("signal:abc") is None
    assert gate._mem[cid].status == "cancelled"
    # The new message should have been routed normally — classifier called
    assert classifier.classify.called


@pytest.mark.asyncio
async def test_no_pending_routes_normally():
    """Without a pending confirmation, routing is unchanged."""
    gate = ConfirmationGate(pool=None, timeout=600)
    router, classifier, fast_path, *_ = _make_router()
    router._confirmation_gate = gate

    result = await router.route(
        user_request="what's on my calendar",
        source="signal",
        source_key="signal:abc",
    )
    # Normal classification should happen
    assert classifier.classify.called


# ── Plan Approval Intercept Tests ────────────────────────────────


@pytest.mark.asyncio
async def test_go_triggers_pending_plan_approval():
    """'go' with no fast-path confirmation triggers a pending plan approval."""
    gate = ConfirmationGate(pool=None, timeout=600)
    router, classifier, fast_path, orchestrator, *_ = _make_router()
    router._confirmation_gate = gate

    # Set up approval manager with a pending approval
    approval_manager = MagicMock()
    pending = {
        "approval_id": "ap-001",
        "plan": MagicMock(),
        "source_key": "signal:abc",
        "user_request": "send email to bob",
    }
    approval_manager.get_pending_by_source_key = AsyncMock(return_value=pending)
    orchestrator.approval_manager = approval_manager
    orchestrator.submit_approval = AsyncMock(return_value=True)
    orchestrator.execute_approved_plan = AsyncMock(
        return_value=TaskResult(status="success", response="Plan executed"),
    )

    result = await router.route(
        user_request="go",
        source="signal",
        source_key="signal:abc",
    )

    assert result.status == "success"
    orchestrator.submit_approval.assert_awaited_once_with(
        approval_id="ap-001", granted=True, reason="confirmed via channel",
    )
    orchestrator.execute_approved_plan.assert_awaited_once_with("ap-001")
    # Classifier should NOT have been called — we short-circuited
    classifier.classify.assert_not_awaited()


@pytest.mark.asyncio
async def test_go_no_pending_approval_routes_normally():
    """'go' with no fast-path confirmation AND no plan approval routes normally."""
    gate = ConfirmationGate(pool=None, timeout=600)
    router, classifier, fast_path, orchestrator, *_ = _make_router()
    router._confirmation_gate = gate

    approval_manager = MagicMock()
    approval_manager.get_pending_by_source_key = AsyncMock(return_value=None)
    orchestrator.approval_manager = approval_manager

    result = await router.route(
        user_request="go",
        source="signal",
        source_key="signal:abc",
    )

    # No pending approval — should fall through to classifier
    classifier.classify.assert_awaited_once()


@pytest.mark.asyncio
async def test_go_expired_plan_approval():
    """'go' when the plan approval has expired returns expired status."""
    gate = ConfirmationGate(pool=None, timeout=600)
    router, classifier, fast_path, orchestrator, *_ = _make_router()
    router._confirmation_gate = gate

    approval_manager = MagicMock()
    pending = {
        "approval_id": "ap-expired",
        "plan": MagicMock(),
        "source_key": "signal:abc",
        "user_request": "send email",
    }
    approval_manager.get_pending_by_source_key = AsyncMock(return_value=pending)
    orchestrator.approval_manager = approval_manager
    orchestrator.submit_approval = AsyncMock(return_value=False)

    result = await router.route(
        user_request="go",
        source="signal",
        source_key="signal:abc",
    )

    assert result.status == "expired"
    assert "expired" in result.reason.lower()


@pytest.mark.asyncio
async def test_non_go_with_no_confirmation_skips_approval_check():
    """Non-'go' messages don't trigger plan approval lookup."""
    gate = ConfirmationGate(pool=None, timeout=600)
    router, classifier, fast_path, orchestrator, *_ = _make_router()
    router._confirmation_gate = gate

    approval_manager = MagicMock()
    approval_manager.get_pending_by_source_key = AsyncMock(return_value=None)
    orchestrator.approval_manager = approval_manager

    await router.route(
        user_request="check my email",
        source="signal",
        source_key="signal:abc",
    )

    # Non-"go" message should NOT check for plan approvals
    approval_manager.get_pending_by_source_key.assert_not_awaited()
    classifier.classify.assert_awaited_once()
