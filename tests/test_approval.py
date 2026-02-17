import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.approval import ApprovalManager, ApprovalResult
from sentinel.core.db import init_db
from sentinel.core.models import DataSource, Plan, PlanStep, TrustLevel
from sentinel.planner.orchestrator import Orchestrator
from sentinel.security.pipeline import ScanPipeline
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.provenance import create_tagged_data, reset_store


@pytest.fixture(autouse=True)
def _reset_provenance():
    reset_store()
    yield
    reset_store()


@pytest.fixture
def db():
    """In-memory SQLite database for testing."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


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
    @pytest.mark.asyncio
    async def test_create_returns_id(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)
        assert isinstance(approval_id, str)
        assert len(approval_id) > 0

    @pytest.mark.asyncio
    async def test_check_pending(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan("My plan")
        approval_id = await mgr.request_plan_approval(plan)

        status = mgr.check_approval(approval_id)
        assert status["status"] == "pending"
        assert status["plan_summary"] == "My plan"

    @pytest.mark.asyncio
    async def test_submit_approval_granted(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        accepted = mgr.submit_approval(approval_id, granted=True, reason="Looks good")
        assert accepted is True

        status = mgr.check_approval(approval_id)
        assert status["status"] == "approved"
        assert status["reason"] == "Looks good"

    @pytest.mark.asyncio
    async def test_submit_denial(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        accepted = mgr.submit_approval(approval_id, granted=False, reason="Too risky")
        assert accepted is True

        status = mgr.check_approval(approval_id)
        assert status["status"] == "denied"
        assert status["reason"] == "Too risky"

    @pytest.mark.asyncio
    async def test_expired_approval(self, db):
        mgr = ApprovalManager(db=db, timeout=0)  # immediate expiry
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        # Wait a tiny bit to ensure expiry
        time.sleep(0.01)

        status = mgr.check_approval(approval_id)
        assert status["status"] == "expired"

    @pytest.mark.asyncio
    async def test_duplicate_submission_ignored(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)

        mgr.submit_approval(approval_id, granted=True, reason="First")
        accepted = mgr.submit_approval(approval_id, granted=False, reason="Second")
        assert accepted is False  # duplicate ignored

        status = mgr.check_approval(approval_id)
        assert status["status"] == "approved"  # first decision stands

    @pytest.mark.asyncio
    async def test_invalid_approval_id(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        status = mgr.check_approval("nonexistent-id")
        assert status["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_submit_invalid_id(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        accepted = mgr.submit_approval("nonexistent", granted=True)
        assert accepted is False

    @pytest.mark.asyncio
    async def test_is_approved_pending(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan()
        approval_id = await mgr.request_plan_approval(plan)
        assert mgr.is_approved(approval_id) is None  # still pending

    @pytest.mark.asyncio
    async def test_get_plan(self, db):
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan("Retrieve me")
        approval_id = await mgr.request_plan_approval(plan)
        retrieved = mgr.get_plan(approval_id)
        assert retrieved is not None
        assert retrieved.plan_summary == "Retrieve me"

    @pytest.mark.asyncio
    async def test_persistence_across_manager_instances(self, db):
        """Data persists in SQLite even when creating a new ApprovalManager."""
        mgr1 = ApprovalManager(db=db, timeout=300)
        plan = _make_plan("Persistent")
        approval_id = await mgr1.request_plan_approval(plan)

        # Create a new manager pointing to the same db
        mgr2 = ApprovalManager(db=db, timeout=300)
        status = mgr2.check_approval(approval_id)
        assert status["status"] == "pending"
        assert status["plan_summary"] == "Persistent"

    @pytest.mark.asyncio
    async def test_get_pending_returns_metadata(self, db):
        """get_pending returns plan, source_key, and user_request."""
        mgr = ApprovalManager(db=db, timeout=300)
        plan = _make_plan("With metadata")
        approval_id = await mgr.request_plan_approval(
            plan, source_key="api:127.0.0.1", user_request="Build something"
        )
        pending = mgr.get_pending(approval_id)
        assert pending is not None
        assert pending["plan"].plan_summary == "With metadata"
        assert pending["source_key"] == "api:127.0.0.1"
        assert pending["user_request"] == "Build something"


class TestApprovalWithOrchestrator:
    @pytest.fixture(autouse=True)
    def _disable_codeshield_requirement(self):
        """CodeShield isn't loaded in unit tests; disable fail-closed."""
        from sentinel.core.config import settings
        original = settings.require_codeshield
        settings.require_codeshield = False
        yield
        settings.require_codeshield = original

    @pytest.mark.asyncio
    async def test_full_approval_flow(self, db):
        """Task → awaiting_approval → approve → execution proceeds."""
        mock_planner = MagicMock(spec=ClaudePlanner)
        mock_planner.create_plan = AsyncMock(return_value=_make_plan("Full flow"))

        mock_pipeline = MagicMock(spec=ScanPipeline)
        from sentinel.security.pipeline import PipelineScanResult
        mock_pipeline.scan_input.return_value = PipelineScanResult()

        tagged = create_tagged_data(
            content="Hello world output",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )
        mock_pipeline.process_with_qwen = AsyncMock(return_value=tagged)

        approval_mgr = ApprovalManager(db=db, timeout=300)
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
        status = approval_mgr.check_approval(approval_id)
        assert status["status"] == "pending"

        # Step 3: Approve
        approval_mgr.submit_approval(approval_id, granted=True, reason="Go ahead")

        # Step 4: Execute the approved plan
        exec_result = await orch.execute_approved_plan(approval_id)
        assert exec_result.status == "success"
        assert len(exec_result.step_results) == 1

    @pytest.mark.asyncio
    async def test_denied_plan_not_executed(self, db):
        """Denied plan returns denied status."""
        mock_planner = MagicMock(spec=ClaudePlanner)
        mock_planner.create_plan = AsyncMock(return_value=_make_plan())

        mock_pipeline = MagicMock(spec=ScanPipeline)
        from sentinel.security.pipeline import PipelineScanResult
        mock_pipeline.scan_input.return_value = PipelineScanResult()

        approval_mgr = ApprovalManager(db=db, timeout=300)
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            approval_manager=approval_mgr,
        )

        result = await orch.handle_task("Build something", approval_mode="full")
        approval_id = result.approval_id

        approval_mgr.submit_approval(approval_id, granted=False, reason="Nope")

        exec_result = await orch.execute_approved_plan(approval_id)
        assert exec_result.status == "denied"
