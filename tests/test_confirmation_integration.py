"""Integration test: confirmation gate end-to-end flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.bus import EventBus
from sentinel.core.confirmation import ConfirmationGate
from sentinel.core.context import current_user_id


@pytest.fixture(autouse=True)
def _set_user_id():
    """Set current_user_id to 1 — matches user_id passed by contact resolution."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)
from sentinel.core.models import TaskResult
from sentinel.router.classifier import ClassificationResult, Route
from sentinel.router.fast_path import FastPathExecutor
from sentinel.router.router import MessageRouter
from sentinel.router.templates import TemplateRegistry
from sentinel.session.store import Session


@pytest.mark.asyncio
class TestConfirmationE2E:
    async def test_full_flow_signal_send(self):
        """signal_send: classify -> pause -> preview -> 'go' -> execute."""
        gate = ConfirmationGate(pool=None, timeout=600)
        bus = EventBus()
        events_captured = []

        async def capture(topic, data):
            events_captured.append((topic, data))

        bus.subscribe("task.*", capture)

        # Mock dependencies
        pipeline = AsyncMock()
        scan_ok = MagicMock(is_clean=True, violations={})
        pipeline.scan_input.return_value = scan_ok
        pipeline.scan_output.return_value = scan_ok

        tool_executor = AsyncMock()
        tagged = MagicMock()
        tagged.content = "Message sent"
        tool_executor.execute.return_value = (tagged, {})

        registry = TemplateRegistry.default()

        fast_path = FastPathExecutor(
            tool_executor=tool_executor,
            pipeline=pipeline,
            event_bus=bus,
            registry=registry,
            confirmation_gate=gate,
        )

        classifier = AsyncMock()
        classifier.classify.return_value = ClassificationResult(
            route=Route.FAST,
            template_name="signal_send",
            params={"message": "hello", "recipient": "alice"},
            reason="matched",
        )

        session_store = MagicMock()
        session = Session(session_id="signal:abc", source="signal")
        session_store.get_or_create = AsyncMock(return_value=session)
        session_store.add_turn = AsyncMock()

        orchestrator = AsyncMock()
        # Prevent plan approval check from triggering
        orchestrator.approval_manager = None

        router = MessageRouter(
            classifier=classifier,
            fast_path=fast_path,
            orchestrator=orchestrator,
            pipeline=pipeline,
            session_store=session_store,
            event_bus=bus,
            enabled=True,
            confirmation_gate=gate,
        )

        # Step 1: Send the original message — should pause
        result1 = await router.route(
            user_request="tell alice hello on signal",
            source="signal",
            source_key="signal:abc",
        )
        assert result1.status == "awaiting_confirmation"

        # Verify a confirmation was created
        pending = await gate.get_pending("signal:abc")
        assert pending is not None
        assert pending.tool_name == "signal_send"

        # Step 2: Reply "go" — should execute
        # Reset classifier so we can verify it wasn't called
        classifier.classify.reset_mock()

        result2 = await router.route(
            user_request="go",
            source="signal",
            source_key="signal:abc",
        )
        assert result2.status == "success"

        # Classifier should NOT have been called (intercepted by confirmation)
        assert not classifier.classify.called

        # Confirmation should be cleared
        assert await gate.get_pending("signal:abc") is None

    async def test_full_flow_cancel_and_reroute(self):
        """Cancel pending and route the new message normally."""
        gate = ConfirmationGate(pool=None, timeout=600)
        bus = EventBus()

        pipeline = AsyncMock()
        scan_ok = MagicMock(is_clean=True, violations={})
        pipeline.scan_input.return_value = scan_ok
        pipeline.scan_output.return_value = scan_ok

        tool_executor = AsyncMock()
        tagged = MagicMock()
        tagged.content = "search results"
        tool_executor.execute.return_value = (tagged, {})

        registry = TemplateRegistry.default()
        fast_path = FastPathExecutor(
            tool_executor=tool_executor,
            pipeline=pipeline,
            event_bus=bus,
            registry=registry,
            confirmation_gate=gate,
        )

        # First classify as signal_send, second as web_search
        classifier = AsyncMock()
        classifier.classify.side_effect = [
            ClassificationResult(
                route=Route.FAST,
                template_name="signal_send",
                params={"message": "hello", "recipient": "alice"},
                reason="matched",
            ),
            ClassificationResult(
                route=Route.FAST,
                template_name="web_search",
                params={"query": "weather"},
                reason="matched",
            ),
        ]

        session_store = MagicMock()
        session = Session(session_id="signal:abc", source="signal")
        session_store.get_or_create = AsyncMock(return_value=session)
        session_store.add_turn = AsyncMock()

        orchestrator = AsyncMock()
        orchestrator.approval_manager = None

        router = MessageRouter(
            classifier=classifier,
            fast_path=fast_path,
            orchestrator=orchestrator,
            pipeline=pipeline,
            session_store=session_store,
            event_bus=bus,
            enabled=True,
            confirmation_gate=gate,
        )

        # Step 1: Trigger confirmation
        result1 = await router.route(
            user_request="tell alice hello",
            source="signal",
            source_key="signal:abc",
        )
        assert result1.status == "awaiting_confirmation"

        # Step 2: Send different message — cancels + routes new one
        result2 = await router.route(
            user_request="what's the weather",
            source="signal",
            source_key="signal:abc",
        )
        # Should have executed web_search (no confirmation needed)
        assert result2.status == "success"
        assert await gate.get_pending("signal:abc") is None
