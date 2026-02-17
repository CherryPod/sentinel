import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.approval import ApprovalManager, ApprovalResult
from sentinel.core.context import current_user_id
from sentinel.core.models import DataSource, Plan, PlanStep, TrustLevel
from sentinel.planner.orchestrator import Orchestrator
from sentinel.security.pipeline import ScanPipeline
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.provenance import create_tagged_data, reset_store


@pytest.fixture(autouse=True)
async def _reset_provenance():
    await reset_store()
    yield
    await reset_store()


def _make_plan(summary: str = "Test plan") -> Plan:
    return Plan(
        plan_summary=summary,
        steps=[
            PlanStep(
                id="step_1",
                type="llm_task",
                description="Generate output",
                prompt="Hello world",
                output_var="$result",
            )
        ],
    )


class TestApprovalManager:
    async def test_create_returns_id(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)
        assert isinstance(approval_id, str)
        assert len(approval_id) > 0

    async def test_check_pending(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan("My plan")
        approval_id = await mgr.request_plan_approval(plan)

        status = await mgr.check_approval(approval_id)
        assert status["status"] == "pending"
        assert status["plan_summary"] == "My plan"

    async def test_submit_approval_granted(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        accepted = await mgr.submit_approval(approval_id, granted=True, reason="Looks good")
        assert accepted is True

        status = await mgr.check_approval(approval_id)
        assert status["status"] == "approved"
        assert status["reason"] == "Looks good"

    async def test_submit_denial(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        accepted = await mgr.submit_approval(approval_id, granted=False, reason="Too risky")
        assert accepted is True

        status = await mgr.check_approval(approval_id)
        assert status["status"] == "denied"
        assert status["reason"] == "Too risky"

    async def test_expired_approval(self):
        mgr = ApprovalManager(pool=None, timeout=0)  # immediate expiry
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        # Wait a tiny bit to ensure expiry
        time.sleep(0.01)

        status = await mgr.check_approval(approval_id)
        assert status["status"] == "expired"

    async def test_duplicate_submission_ignored(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        await mgr.submit_approval(approval_id, granted=True, reason="First")
        accepted = await mgr.submit_approval(approval_id, granted=False, reason="Second")
        assert accepted is False  # duplicate ignored

        status = await mgr.check_approval(approval_id)
        assert status["status"] == "approved"  # first decision stands

    async def test_invalid_approval_id(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        status = await mgr.check_approval("nonexistent-id")
        assert status["status"] == "not_found"

    async def test_submit_invalid_id(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        accepted = await mgr.submit_approval("nonexistent", granted=True)
        assert accepted is False

    async def test_is_approved_pending(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)
        assert await mgr.is_approved(approval_id) is None  # still pending

    async def test_get_plan(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan("Retrieve me")
        approval_id = await mgr.request_plan_approval(plan)
        retrieved = await mgr.get_plan(approval_id)
        assert retrieved is not None
        assert retrieved.plan_summary == "Retrieve me"

    async def test_get_pending_returns_metadata(self):
        """get_pending returns plan, source_key, and user_request."""
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan("With metadata")
        approval_id = await mgr.request_plan_approval(
            plan, source_key="api:127.0.0.1", user_request="Build something"
        )
        pending = await mgr.get_pending(approval_id)
        assert pending is not None
        assert pending["plan"].plan_summary == "With metadata"
        assert pending["source_key"] == "api:127.0.0.1"
        assert pending["user_request"] == "Build something"

    async def test_cleanup_expired_returns_ids(self):
        """_cleanup_expired returns list of newly expired entries."""
        mgr = ApprovalManager(pool=None, timeout=0)  # immediate expiry
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(
            plan, source_key="signal:+1234567890"
        )
        time.sleep(0.01)

        expired = await mgr._cleanup_expired()
        assert len(expired) == 1
        assert expired[0]["approval_id"] == approval_id
        assert expired[0]["source_key"] == "signal:+1234567890"

    async def test_cleanup_expired_second_call_empty(self):
        """Second call to _cleanup_expired returns empty (already marked)."""
        mgr = ApprovalManager(pool=None, timeout=0)
        plan = _make_plan()
        await mgr.request_plan_approval(plan)
        time.sleep(0.01)

        await mgr._cleanup_expired()
        second = await mgr._cleanup_expired()
        assert second == []

    async def test_cleanup_and_notify_publishes_events(self):
        """cleanup_and_notify publishes approval.expired events via event bus."""
        from sentinel.core.bus import EventBus

        bus = EventBus()
        received_events = []

        async def handler(topic, data):
            received_events.append((topic, data))

        bus.subscribe("approval.expired", handler)

        mgr = ApprovalManager(pool=None, timeout=0, event_bus=bus)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(
            plan, source_key="telegram:12345"
        )
        time.sleep(0.01)

        expired = await mgr.cleanup_and_notify()
        assert len(expired) == 1
        assert len(received_events) == 1
        topic, data = received_events[0]
        assert topic == "approval.expired"
        assert data["approval_id"] == approval_id
        assert data["source_key"] == "telegram:12345"
        assert data["reason"] == "Approval request timed out"

    async def test_cleanup_and_notify_no_bus(self):
        """cleanup_and_notify works without event bus (returns expired, no publish)."""
        mgr = ApprovalManager(pool=None, timeout=0)
        plan = _make_plan()
        await mgr.request_plan_approval(plan)
        time.sleep(0.01)

        expired = await mgr.cleanup_and_notify()
        assert len(expired) == 1

    async def test_purge_old(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)
        await mgr.submit_approval(approval_id, granted=True, reason="ok")
        # With days=0, everything decided should be purged
        deleted = await mgr.purge_old(days=0)
        assert deleted == 1
        assert await mgr.get_plan(approval_id) is None

    async def test_get_status_counts(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        plan = _make_plan()
        a1 = await mgr.request_plan_approval(plan)
        a2 = await mgr.request_plan_approval(plan)
        a3 = await mgr.request_plan_approval(plan)
        await mgr.submit_approval(a1, granted=True, reason="ok")
        await mgr.submit_approval(a2, granted=False, reason="no")
        counts = await mgr.get_status_counts()
        assert counts.get("approved", 0) == 1
        assert counts.get("denied", 0) == 1
        assert counts.get("pending", 0) == 1

    async def test_close_is_safe(self):
        mgr = ApprovalManager(pool=None, timeout=300)
        await mgr.close()  # should not raise


class TestApprovalWithOrchestrator:
    @pytest.fixture(autouse=True)
    def _disable_semgrep_requirement(self):
        """Semgrep isn't loaded in unit tests; disable fail-closed."""
        from sentinel.core.config import settings
        original = settings.require_semgrep
        settings.require_semgrep = False
        yield
        settings.require_semgrep = original

    async def test_full_approval_flow(self):
        """Task -> awaiting_approval -> approve -> execution proceeds."""
        mock_planner = MagicMock(spec=ClaudePlanner)
        mock_planner.create_plan = AsyncMock(return_value=_make_plan("Full flow"))

        mock_pipeline = MagicMock(spec=ScanPipeline)
        from sentinel.security.pipeline import PipelineScanResult
        mock_pipeline.scan_input = AsyncMock(return_value=PipelineScanResult())

        tagged = await create_tagged_data(
            content="Hello world output",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )
        mock_pipeline.process_with_qwen = AsyncMock(return_value=(tagged, None))

        approval_mgr = ApprovalManager(pool=None, timeout=300)
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            approval_manager=approval_mgr,
        )

        # Step 1: Submit task in full approval mode
        result = await orch.handle_task("Build something", approval_mode="full")
        assert result.status == "awaiting_approval"
        approval_id = result.approval_id

        # Step 2: Check status — should be pending
        status = await approval_mgr.check_approval(approval_id)
        assert status["status"] == "pending"

        # Step 3: Approve
        await approval_mgr.submit_approval(approval_id, granted=True, reason="Go ahead")

        # Step 4: Execute the approved plan
        exec_result = await orch.execute_approved_plan(approval_id)
        assert exec_result.status == "success"
        assert len(exec_result.step_results) == 1

    async def test_denied_plan_not_executed(self):
        """Denied plan returns denied status."""
        mock_planner = MagicMock(spec=ClaudePlanner)
        mock_planner.create_plan = AsyncMock(return_value=_make_plan())

        mock_pipeline = MagicMock(spec=ScanPipeline)
        from sentinel.security.pipeline import PipelineScanResult
        mock_pipeline.scan_input = AsyncMock(return_value=PipelineScanResult())

        approval_mgr = ApprovalManager(pool=None, timeout=300)
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            approval_manager=approval_mgr,
        )

        result = await orch.handle_task("Build something", approval_mode="full")
        approval_id = result.approval_id

        await approval_mgr.submit_approval(approval_id, granted=False, reason="Nope")

        exec_result = await orch.execute_approved_plan(approval_id)
        assert exec_result.status == "denied"


class TestApprovalUserIdIsolation:
    """F3/F4: Approval manager stores and filters by user_id."""

    async def test_request_stores_user_id(self):
        """request_plan_approval stores user_id from ContextVar."""
        mgr = ApprovalManager(pool=None, timeout=300)
        token = current_user_id.set(42)
        try:
            approval_id = await mgr.request_plan_approval(
                plan=_make_plan(), source_key="test",
                user_request="do something",
            )
            # Verify: check_approval should work for user 42
            result = await mgr.check_approval(approval_id)
            assert result["status"] == "pending"
            # Verify the in-memory entry recorded user_id
            entry = mgr._mem[approval_id]
            assert entry.user_id == 42
        finally:
            current_user_id.reset(token)

    async def test_check_approval_filters_by_user_id(self):
        """check_approval returns not_found for wrong user."""
        mgr = ApprovalManager(pool=None, timeout=300)
        # Create approval as user 1
        token = current_user_id.set(1)
        try:
            approval_id = await mgr.request_plan_approval(
                plan=_make_plan(), source_key="test",
                user_request="do something",
            )
        finally:
            current_user_id.reset(token)

        # Check as wrong user — should not find it
        token = current_user_id.set(99)
        try:
            result = await mgr.check_approval(approval_id)
            assert result["status"] == "not_found"
        finally:
            current_user_id.reset(token)

    async def test_cleanup_expired_is_cross_user(self):
        """_cleanup_expired operates across all users (admin maintenance)."""
        mgr = ApprovalManager(pool=None, timeout=0)
        # Create approval as user 1
        token = current_user_id.set(1)
        try:
            await mgr.request_plan_approval(
                plan=_make_plan(), source_key="test",
            )
        finally:
            current_user_id.reset(token)

        time.sleep(0.01)

        # Run cleanup as user 99 — should still expire user 1's entry
        token = current_user_id.set(99)
        try:
            expired = await mgr._cleanup_expired()
            assert len(expired) == 1
        finally:
            current_user_id.reset(token)
