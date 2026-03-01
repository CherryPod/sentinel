"""E2c capability tests — Chat endpoint verification.

Tests verify the REST API endpoints that the chat UI depends on:
task submission, approval flow, input validation, and rate limiting.

Uses TestClient(app) + @patch("sentinel.api.app._pin_verifier", None) pattern
from existing webui tests.
"""

import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from sentinel.core.approval import ApprovalManager
from sentinel.core.models import (
    ConversationInfo,
    Plan,
    PlanStep,
    StepResult,
    TaskResult,
)
from sentinel.planner.orchestrator import Orchestrator


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
    """Create an ApprovalManager backed by an in-memory SQLite DB."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("""CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY,
        plan_json TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        expires_at TEXT,
        decided_at TEXT,
        decided_reason TEXT DEFAULT '',
        decided_by TEXT DEFAULT '',
        source_key TEXT DEFAULT '',
        user_request TEXT DEFAULT ''
    )""")
    db.commit()
    return ApprovalManager(db)


class TestTaskSubmission:
    """POST /api/task endpoint."""

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_task_submission_returns_structured_response(self):
        """POST /api/task returns TaskResult with task_id, plan_summary, step_results."""
        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch.handle_task = AsyncMock(return_value=_make_task_result())

        with patch("sentinel.api.app._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.post("/api/task", json={"request": "Hello world"})

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
    @patch("sentinel.api.app._pin_verifier", None)
    def test_approval_check_returns_plan_details(self):
        """GET /api/approval/{id} returns pending status with plan details."""
        am = _make_approval_manager()
        # Insert a pending approval directly
        plan = Plan(
            plan_summary="Test plan",
            steps=[PlanStep(
                id="step_1",
                type="llm_task",
                description="Generate output",
                prompt="Write something",
            )],
        )
        am._db.execute(
            "INSERT INTO approvals (approval_id, plan_json, expires_at) "
            "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+300 seconds'))",
            ("test-approval-1", plan.model_dump_json()),
        )
        am._db.commit()

        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch._approval_manager = am

        with patch("sentinel.api.app._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/approval/test-approval-1")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["plan_summary"] == "Test plan"
        assert len(data["steps"]) == 1
        assert data["steps"][0]["id"] == "step_1"

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
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
        am._db.execute(
            "INSERT INTO approvals (approval_id, plan_json, expires_at, source_key, user_request) "
            "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+300 seconds'), ?, ?)",
            ("approve-1", plan.model_dump_json(), "api:test", "original request"),
        )
        am._db.commit()

        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch._approval_manager = am
        mock_orch.execute_approved_plan = AsyncMock(
            return_value=_make_task_result(status="success"),
        )

        with patch("sentinel.api.app._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.post(
                "/api/approve/approve-1",
                json={"granted": True, "reason": "Looks good"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        mock_orch.execute_approved_plan.assert_called_once_with("approve-1")

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_approval_submit_deny(self):
        """POST /api/approve/{id} with granted=false returns denied status."""
        am = _make_approval_manager()
        plan = Plan(
            plan_summary="Plan to deny",
            steps=[PlanStep(id="s1", type="llm_task", description="X", prompt="Y")],
        )
        am._db.execute(
            "INSERT INTO approvals (approval_id, plan_json, expires_at) "
            "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+300 seconds'))",
            ("deny-1", plan.model_dump_json()),
        )
        am._db.commit()

        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch._approval_manager = am

        with patch("sentinel.api.app._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.post(
                "/api/approve/deny-1",
                json={"granted": False, "reason": "Not safe"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "denied"
        assert data["reason"] == "Not safe"

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_approval_expired_or_invalid(self):
        """GET /api/approval/nonexistent returns not_found status."""
        am = _make_approval_manager()
        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch._approval_manager = am

        with patch("sentinel.api.app._orchestrator", mock_orch):
            from sentinel.api.app import app
            client = TestClient(app)
            resp = client.get("/api/approval/nonexistent-id")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_found"


class TestInputValidation:
    """Pydantic validation on POST /api/task."""

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    @patch("sentinel.api.app._orchestrator", MagicMock())
    def test_task_input_validation_too_short(self):
        """POST /api/task with <3 chars rejected by Pydantic (422)."""
        from sentinel.api.app import app
        client = TestClient(app)
        resp = client.post("/api/task", json={"request": "ab"})
        assert resp.status_code == 422

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    @patch("sentinel.api.app._orchestrator", MagicMock())
    def test_task_input_validation_too_long(self):
        """POST /api/task with >50000 chars rejected by Pydantic (422)."""
        from sentinel.api.app import app
        client = TestClient(app)
        long_text = "A" * 50_001
        resp = client.post("/api/task", json={"request": long_text})
        assert resp.status_code == 422


class TestRateLimit:
    """Rate limiting on POST /api/task."""

    @pytest.mark.capability
    @patch("sentinel.api.app._pin_verifier", None)
    def test_task_rate_limit(self):
        """POST /api/task × 11 rapid requests → 429 rate limited.

        The endpoint has a 10/minute rate limit per IP. The 11th request
        within the same minute should be rejected with 429.
        """
        mock_orch = MagicMock(spec=Orchestrator)
        mock_orch.handle_task = AsyncMock(return_value=_make_task_result())

        with patch("sentinel.api.app._orchestrator", mock_orch):
            from sentinel.api.app import app, limiter
            # Reset rate limiter state for a clean test
            limiter.reset()

            client = TestClient(app)
            statuses = []
            for i in range(11):
                resp = client.post(
                    "/api/task",
                    json={"request": f"Request number {i}"},
                )
                statuses.append(resp.status_code)

            # First 10 should succeed (200), 11th should be rate-limited (429)
            assert statuses.count(200) == 10
            assert 429 in statuses
