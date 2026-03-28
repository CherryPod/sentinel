"""E2c capability tests — Chat endpoint verification.

Tests verify the REST API endpoints that the chat UI depends on:
task submission, approval flow, input validation, and rate limiting.

Uses TestClient(app) + @patch("sentinel.api.lifecycle._pin_verifier", None) pattern
from existing webui tests.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from tests.conftest import auth_headers
from sentinel.core.approval import ApprovalManager, ApprovalEntry
from sentinel.core.models import (
    ConversationInfo,
    Plan,
    PlanStep,
    StepResult,
    TaskResult,
)
from sentinel.planner.orchestrator import Orchestrator

# Valid Origin header for CSRF middleware — matches settings.allowed_origins default
_ORIGIN = {"Origin": "https://localhost:3001"}


def _make_task_result(**kwargs) -> TaskResult:
    """Build a TaskResult with sensible defaults."""
    defaults = {
        "task_id": "test-task-123",
        "status": "success",
        "plan_summary": "Test plan summary",
        "step_results": [
            StepResult(step_id="step_1", status="success", content="Done"),
        ],
    }
    defaults.update(kwargs)
    return TaskResult(**defaults)


def _make_approval_manager() -> ApprovalManager:
    """Create an ApprovalManager with in-memory dict fallback."""
    return ApprovalManager(pool=None, timeout=300)


def _seed_approval(am: ApprovalManager, approval_id: str, plan: Plan,
                   source_key: str = "", user_request: str = "") -> None:
    """Seed a pending approval directly into the in-memory store.

    user_id=1 matches the UserContextMiddleware which sets current_user_id=1
    for all HTTP requests (single-user mode).
    """
    am._mem[approval_id] = ApprovalEntry(
        approval_id=approval_id,
        plan_json=plan.model_dump_json(),
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=300),
        source_key=source_key,
        user_request=user_request,
        user_id=1,
    )


class TestTaskSubmission:
    """POST /api/task endpoint."""

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_task_submission_returns_structured_response(self):
        """POST /api/task returns TaskResult with task_id, plan_summary, step_results."""
        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch.handle_task = AsyncMock(return_value=_make_task_result())

        with patch("sentinel.api.routes.task._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.post("/api/task", json={"request": "Hello world"}, headers={**auth_headers(), **_ORIGIN})

        assert resp.status_code == 200
        data = resp.json()
        assert data["task_id"] == "test-task-123"
        assert data["status"] == "success"
        assert data["plan_summary"] == "Test plan summary"
        assert len(data["step_results"]) == 1
        assert data["step_results"][0]["step_id"] == "step_1"


class TestApprovalFlow:
    """GET /api/approval/{id} and POST /api/approve/{id} endpoints."""

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_approval_check_returns_plan_details(self):
        """GET /api/approval/{id} returns pending status with plan details."""
        am = _make_approval_manager()
        plan = Plan(
            plan_summary="Test plan",
            steps=[PlanStep(
                id="step_1",
                type="llm_task",
                description="Generate output",
                prompt="Write something",
            )],
        )
        _seed_approval(am, "test-approval-1", plan)

        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch.approval_manager = am
        mock_orch.check_approval = AsyncMock(side_effect=am.check_approval)

        with patch("sentinel.api.routes.task._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/approval/test-approval-1", headers=auth_headers())

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["plan_summary"] == "Test plan"
        assert len(data["steps"]) == 1
        assert data["steps"][0]["id"] == "step_1"

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_approval_submit_approve(self):
        """POST /api/approve/{id} with granted=true executes the approved plan."""
        am = _make_approval_manager()
        plan = Plan(
            plan_summary="Approved plan",
            steps=[PlanStep(
                id="step_1",
                type="llm_task",
                description="Do something",
                prompt="Do it",
            )],
        )
        _seed_approval(am, "approve-1", plan, source_key="api:test", user_request="original request")

        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch.approval_manager = am
        mock_orch.submit_approval = AsyncMock(side_effect=am.submit_approval)
        mock_orch.execute_approved_plan = AsyncMock(
            return_value=_make_task_result(status="success"),
        )

        with patch("sentinel.api.routes.task._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.post(
                "/api/approve/approve-1",
                json={"granted": True, "reason": "Looks good"},
                headers={**auth_headers(), **_ORIGIN},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        mock_orch.execute_approved_plan.assert_called_once_with("approve-1")

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_approval_submit_deny(self):
        """POST /api/approve/{id} with granted=false returns denied status."""
        am = _make_approval_manager()
        plan = Plan(
            plan_summary="Plan to deny",
            steps=[PlanStep(id="s1", type="llm_task", description="X", prompt="Y")],
        )
        _seed_approval(am, "deny-1", plan)

        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch.approval_manager = am
        mock_orch.submit_approval = AsyncMock(side_effect=am.submit_approval)

        with patch("sentinel.api.routes.task._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.post(
                "/api/approve/deny-1",
                json={"granted": False, "reason": "Not safe"},
                headers={**auth_headers(), **_ORIGIN},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "denied"
        assert data["reason"] == "Not safe"

    @pytest.mark.capability
    @patch("sentinel.api.lifecycle._pin_verifier", None)
    def test_approval_expired_or_invalid(self):
        """GET /api/approval/nonexistent returns not_found status."""
        am = _make_approval_manager()
        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch.approval_manager = am
        mock_orch.check_approval = AsyncMock(side_effect=am.check_approval)

        with patch("sentinel.api.routes.task._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/approval/nonexistent-id", headers=auth_headers())

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_found"
