"""Tests for F1 model additions — TaskStatus enum, StepStatus enum, step_outcomes on TaskResult."""

from sentinel.core.models import TaskResult


class TestTaskStatus:
    def test_enum_values_exist(self):
        from sentinel.core.models import TaskStatus
        assert TaskStatus.SUCCESS.value == "success"
        assert TaskStatus.PARTIAL.value == "partial"
        assert TaskStatus.SCAN_BLOCKED.value == "scan_blocked"
        assert TaskStatus.WORKER_ERROR.value == "worker_error"
        assert TaskStatus.EXECUTION_ERROR.value == "execution_error"
        assert TaskStatus.PLANNER_ERROR.value == "planner_error"
        assert TaskStatus.REFUSED.value == "refused"
        assert TaskStatus.DENIED.value == "denied"
        assert TaskStatus.TIMEOUT.value == "timeout"
        assert TaskStatus.LOCKED.value == "locked"

    def test_enum_is_str_enum(self):
        from sentinel.core.models import TaskStatus
        assert isinstance(TaskStatus.SUCCESS, str)
        assert TaskStatus.SUCCESS == "success"


class TestStepStatus:
    def test_enum_values_exist(self):
        from sentinel.core.models import StepStatus
        assert StepStatus.SUCCESS.value == "success"
        assert StepStatus.BLOCKED.value == "blocked"
        assert StepStatus.ERROR.value == "error"
        assert StepStatus.SKIPPED.value == "skipped"
        assert StepStatus.SCAN_BLOCKED.value == "scan_blocked"
        assert StepStatus.TRUST_BLOCKED.value == "trust_blocked"
        assert StepStatus.FORMAT_ERROR.value == "format_error"


class TestTaskResultStepOutcomes:
    def test_step_outcomes_default_empty(self):
        result = TaskResult(status="success")
        assert result.step_outcomes == []

    def test_step_outcomes_accepts_dicts(self):
        outcomes = [
            {"step_type": "llm_task", "status": "success", "output_size": 200},
            {"step_type": "tool_call", "status": "blocked", "error_detail": "policy"},
        ]
        result = TaskResult(status="success", step_outcomes=outcomes)
        assert len(result.step_outcomes) == 2
        assert result.step_outcomes[0]["step_type"] == "llm_task"
