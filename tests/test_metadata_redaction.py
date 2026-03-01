"""Tests for metadata redaction in _build_step_outcome.

Verifies that step outcome metadata exposed to the planner does not leak
scanner names, specific blocked commands, file paths in errors, or other
implementation details that could help an adversary learn defence rules.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock

from sentinel.core.models import PlanStep, StepResult, OutputDestination


def _make_orchestrator():
    """Minimal Orchestrator with mocked deps (same pattern as test_f1_outcome_builder)."""
    from sentinel.planner.orchestrator import Orchestrator
    orch = Orchestrator.__new__(Orchestrator)
    orch._pipeline = MagicMock()
    orch._planner = MagicMock()
    orch._tool_executor = MagicMock()
    orch._tool_executor._last_exec_meta = None
    orch._session_store = None
    orch._approval_manager = None
    orch._memory_store = None
    orch._bus = MagicMock()
    orch._bus.emit = AsyncMock()
    orch._event_bus = None
    orch._worker_contexts = {}
    orch._current_session_id = None
    return orch


# ---------------------------------------------------------------------------
# _genericise_error unit tests
# ---------------------------------------------------------------------------

class TestGenericiseError:
    def _call(self, error):
        from sentinel.planner.orchestrator import Orchestrator
        return Orchestrator._genericise_error(error)

    def test_none_returns_none(self):
        assert self._call(None) is None

    def test_empty_returns_none(self):
        assert self._call("") is None

    def test_shell_command_not_in_allowed_list(self):
        assert self._call("Command not in allowed list: cd") == "shell command blocked"

    def test_shell_blocked(self):
        assert self._call("shell blocked: dangerous command") == "shell command blocked"

    def test_file_path_blocked(self):
        assert self._call("Path blocked: /etc/shadow not allowed") == "file operation blocked"

    def test_file_path_denied(self):
        assert self._call("File path denied by policy") == "file operation blocked"

    def test_semgrep_scanner(self):
        assert self._call("Semgrep: insecure code detected (2 issues)") == "scan blocked"

    def test_sensitive_path_scanner(self):
        assert self._call("sensitive_path_scanner: /etc/shadow") == "scan blocked"

    def test_credential_scanner(self):
        assert self._call("credential_scanner: API key detected") == "scan blocked"

    def test_command_pattern_scanner(self):
        assert self._call("command_pattern: subprocess.call(cmd, shell=True)") == "scan blocked"

    def test_encoding_scanner(self):
        assert self._call("encoding_scanner: base64 encoded content") == "scan blocked"

    def test_prompt_guard(self):
        assert self._call("prompt_guard: injection detected (score=0.95)") == "scan blocked"

    def test_echo_scanner(self):
        assert self._call("echo_scanner: reflected input detected") == "scan blocked"

    def test_dockerfile_scanner(self):
        assert self._call("dockerfile scanner: untagged image") == "scan blocked"

    def test_denylist_block(self):
        assert self._call("Constitutional denylist: rm -rf /") == "constraint violation"

    def test_constraint_violation(self):
        assert self._call("Constraint violation: command exceeds plan-approved scope") == "constraint violation"

    def test_tool_execution_failed(self):
        assert self._call("Tool execution failed: FileNotFoundError") == "execution error"

    def test_generic_execution_error(self):
        assert self._call("execution timeout after 30s") == "execution error"

    def test_unknown_error_gets_fallback(self):
        assert self._call("something completely unexpected happened") == "operation blocked"

    def test_case_insensitive(self):
        """Matching should be case-insensitive."""
        assert self._call("SEMGREP: INSECURE CODE") == "scan blocked"
        assert self._call("Shell Blocked: bad command") == "shell command blocked"


# ---------------------------------------------------------------------------
# _build_step_outcome redaction tests
# ---------------------------------------------------------------------------

class TestBuildStepOutcomeRedaction:
    """Verify _build_step_outcome no longer leaks implementation details."""

    def test_scanner_details_not_in_outcome(self):
        """scanner_details field must not exist in the outcome dict."""
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Write code")
        result = StepResult(
            step_id="step_1", status="blocked",
            error="sensitive_path_scanner: /etc/shadow",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.5)
        assert "scanner_details" not in outcome

    def test_scanner_result_still_present(self):
        """scanner_result (blocked/clean) must still be present."""
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Write code")
        result = StepResult(
            step_id="step_1", status="blocked",
            error="Semgrep: insecure code detected",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.5)
        assert outcome["scanner_result"] == "blocked"

    def test_clean_step_has_no_scanner_details(self):
        """Clean steps also must not have scanner_details."""
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Write code")
        result = StepResult(
            step_id="step_1", status="success", content="print('hello')",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=1.0)
        assert "scanner_details" not in outcome
        assert outcome["scanner_result"] == "clean"

    def test_error_detail_no_scanner_names(self):
        """error_detail must not contain scanner implementation names."""
        orch = _make_orchestrator()
        scanner_errors = [
            "Semgrep: insecure code detected (2 issues)",
            "sensitive_path_scanner: /etc/shadow",
            "credential_scanner: API key detected",
            "command_pattern: subprocess.call(cmd, shell=True)",
            "encoding_scanner: base64 encoded content",
        ]
        for error in scanner_errors:
            step = PlanStep(id="step_1", type="llm_task", description="Test")
            result = StepResult(step_id="step_1", status="blocked", error=error)
            outcome = orch._build_step_outcome(step, result, elapsed_s=0.1)
            assert outcome["error_detail"] == "scan blocked", (
                f"Expected 'scan blocked' for error '{error}', "
                f"got '{outcome['error_detail']}'"
            )

    def test_error_detail_no_command_names(self):
        """error_detail must not reveal which command was blocked."""
        orch = _make_orchestrator()
        step = PlanStep(
            id="step_1", type="tool_call", description="Run command", tool="shell",
        )
        result = StepResult(
            step_id="step_1", status="blocked",
            error="Command not in allowed list: cd",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.1)
        assert outcome["error_detail"] == "shell command blocked"
        assert "cd" not in outcome["error_detail"]

    def test_error_detail_no_file_paths(self):
        """error_detail must not reveal which file path was blocked."""
        orch = _make_orchestrator()
        step = PlanStep(
            id="step_1", type="tool_call", description="Read file", tool="file_read",
        )
        result = StepResult(
            step_id="step_1", status="blocked",
            error="Path blocked: /etc/shadow not allowed",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.1)
        assert outcome["error_detail"] == "file operation blocked"
        assert "/etc/shadow" not in outcome["error_detail"]

    def test_planner_gets_enough_for_replanning(self):
        """Planner can still replan — status, generic error, scanner_result present."""
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Generate")
        result = StepResult(
            step_id="step_1", status="blocked",
            error="Semgrep: insecure code detected",
        )
        outcome = orch._build_step_outcome(
            step, result, elapsed_s=0.3,
            destination=OutputDestination.DISPLAY,
        )
        # These fields give the planner enough info to replan
        assert outcome["status"] == "blocked"
        assert outcome["error_detail"] is not None  # knows something went wrong
        assert outcome["scanner_result"] == "blocked"  # knows it was a scan
        assert outcome["step_type"] == "llm_task"
        assert outcome["destination"] == "display"
        assert outcome["duration_s"] == 0.3

    def test_success_error_detail_is_none(self):
        """Successful steps should have error_detail=None."""
        orch = _make_orchestrator()
        step = PlanStep(id="step_1", type="llm_task", description="Generate code")
        result = StepResult(
            step_id="step_1", status="success", content="print('hello')",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=1.0)
        assert outcome["error_detail"] is None

    def test_constraint_result_still_present_for_tool_calls(self):
        """D5 constraint_result should still work correctly."""
        orch = _make_orchestrator()
        step = PlanStep(
            id="step_1", type="tool_call", description="Run command",
            tool="shell", allowed_commands=["ls", "cat"],
        )
        result = StepResult(step_id="step_1", status="success", content="ok")
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.1)
        assert outcome["constraint_result"] == "validated"

    def test_denylist_constraint_result(self):
        """Denylist blocks produce correct constraint_result."""
        orch = _make_orchestrator()
        step = PlanStep(
            id="step_1", type="tool_call", description="Bad command",
            tool="shell",
        )
        result = StepResult(
            step_id="step_1", status="blocked",
            error="Constitutional denylist: rm -rf /",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.1)
        assert outcome["constraint_result"] == "denylist_block"
        assert outcome["error_detail"] == "constraint violation"

    def test_post_review_fields_still_present(self):
        """Fields flagged for post-test review must still be present."""
        orch = _make_orchestrator()
        orch._tool_executor._last_exec_meta = {
            "exit_code": 0,
            "stderr": "warning: something",
            "file_size_before": 100,
            "file_size_after": 250,
        }
        step = PlanStep(
            id="step_1", type="tool_call", description="Write file",
            tool="file_write", args={"path": "/workspace/app.py", "content": "new"},
        )
        result = StepResult(
            step_id="step_1", status="success",
            content="File written: /workspace/app.py",
        )
        outcome = orch._build_step_outcome(step, result, elapsed_s=0.1)
        # These are flagged for review but NOT yet redacted
        assert outcome["output_size"] is not None
        assert outcome["stderr_preview"] is not None
        assert outcome["file_size_before"] == 100
        assert outcome["file_size_after"] == 250
