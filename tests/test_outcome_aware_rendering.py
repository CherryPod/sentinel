"""Step 1.4: Outcome-aware text rendering tests."""

import pytest

from sentinel.memory.episodic import _categorise_strategy, render_episodic_text


class TestCategoriseStrategy:
    """Strategy pattern extraction from step_outcomes."""

    def test_empty_outcomes(self):
        assert _categorise_strategy([]) == "empty"

    def test_single_tool_call(self):
        outcomes = [{"step_type": "tool_call", "tool": "web_search"}]
        assert _categorise_strategy(outcomes) == "single-shot"

    def test_read_fix_pattern(self):
        outcomes = [
            {"step_type": "tool_call", "tool": "file_read"},
            {"step_type": "llm_task"},
            {"step_type": "tool_call", "tool": "file_write"},
        ]
        assert _categorise_strategy(outcomes) == "read → generate → write"

    def test_repeated_tools_collapsed(self):
        # Two consecutive file_reads should collapse to one "read"
        outcomes = [
            {"step_type": "tool_call", "tool": "file_read"},
            {"step_type": "tool_call", "tool": "file_read"},
            {"step_type": "tool_call", "tool": "file_write"},
        ]
        assert _categorise_strategy(outcomes) == "read → write"

    def test_search_send_pattern(self):
        outcomes = [
            {"step_type": "tool_call", "tool": "web_search"},
            {"step_type": "tool_call", "tool": "telegram_send"},
        ]
        assert _categorise_strategy(outcomes) == "search → send"

    def test_no_tool_steps_returns_unknown(self):
        outcomes = [{"step_type": "display"}]
        assert _categorise_strategy(outcomes) == "unknown"

    def test_shell_exec_labelled(self):
        outcomes = [
            {"step_type": "tool_call", "tool": "file_write"},
            {"step_type": "tool_call", "tool": "shell_exec"},
        ]
        assert _categorise_strategy(outcomes) == "write → exec"


class TestRenderEpisodicText:
    """Outcome-aware render_episodic_text output format."""

    def test_domain_tag_present(self):
        result = render_episodic_text(
            user_request="Fix syntax error in Python file",
            task_status="success",
            task_domain="code_debugging",
        )
        assert result.startswith("[code_debugging]")

    def test_domain_tag_absent_when_none(self):
        result = render_episodic_text(
            user_request="Fix syntax error",
            task_status="success",
            task_domain=None,
        )
        assert not result.startswith("[")
        assert result.startswith("Fix syntax error")

    def test_result_line_format(self):
        result = render_episodic_text(
            user_request="Do something",
            task_status="success",
            step_count=3,
            success_count=3,
        )
        assert "Result: SUCCESS (3/3 steps)" in result

    def test_total_duration_from_step_outcomes(self):
        outcomes = [
            {"step_type": "tool_call", "tool": "file_read", "duration_s": 1.5},
            {"step_type": "tool_call", "tool": "file_write", "duration_s": 2.0},
        ]
        result = render_episodic_text(
            user_request="Fix file",
            task_status="success",
            step_count=2,
            success_count=2,
            step_outcomes=outcomes,
        )
        # 1.5 + 2.0 = 3.5 → "4s" (rounded)
        assert "4s" in result

    def test_strategy_line_present(self):
        outcomes = [
            {"step_type": "tool_call", "tool": "file_read"},
            {"step_type": "tool_call", "tool": "file_write"},
        ]
        result = render_episodic_text(
            user_request="Edit a file",
            task_status="success",
            step_count=2,
            success_count=2,
            step_outcomes=outcomes,
        )
        assert "Strategy: read → write" in result

    def test_code_fixer_not_in_output(self):
        """Code fixer is internal infrastructure — not shown to planner."""
        outcomes = [
            {
                "step_type": "tool_call",
                "tool": "file_write",
                "code_fixer_changed": True,
                "code_fixer_fixes": ["indentation", "trailing_whitespace"],
            },
        ]
        result = render_episodic_text(
            user_request="Write Python files",
            task_status="success",
            step_count=1,
            success_count=1,
            step_outcomes=outcomes,
        )
        assert "code_fixer" not in result.lower()
        assert "Code fixer" not in result

    def test_error_highlight_on_failure(self):
        outcomes = [
            {
                "step_type": "tool_call",
                "tool": "shell",
                "status": "failed",
                "error_detail": "ModuleNotFoundError: No module named 'foo'",
            },
        ]
        result = render_episodic_text(
            user_request="Run test",
            task_status="failed",
            step_count=1,
            success_count=0,
            step_outcomes=outcomes,
        )
        # New format: S1(tool): FAILED; description; error detail
        assert "FAILED" in result
        assert "ModuleNotFoundError" in result

    def test_no_key_line_when_no_insights(self):
        result = render_episodic_text(
            user_request="Simple task",
            task_status="success",
            step_count=1,
            success_count=1,
            step_outcomes=[{"step_type": "tool_call", "tool": "web_search"}],
        )
        assert "Key:" not in result

    def test_output_under_800_chars(self):
        # Long request + many steps should still stay under 800
        outcomes = [
            {
                "step_type": "tool_call",
                "tool": f"tool_{i}",
                "duration_s": 1.0,
                "code_fixer_changed": True,
                "code_fixer_fixes": [f"fix_type_{i}"],
            }
            for i in range(20)
        ]
        result = render_episodic_text(
            user_request="A" * 200,
            task_status="success",
            step_count=20,
            success_count=20,
            step_outcomes=outcomes,
            task_domain="code_generation",
            plan_summary="B" * 200,
        )
        assert len(result) <= 800

    def test_plan_summary_included(self):
        result = render_episodic_text(
            user_request="Build widget",
            task_status="success",
            plan_summary="Created widget.py with 3 functions",
        )
        assert "Plan: Created widget.py" in result

    def test_strategy_empty_when_no_outcomes(self):
        result = render_episodic_text(
            user_request="Hello",
            task_status="success",
        )
        assert "Strategy: empty" in result
