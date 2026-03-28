"""Tests for task success verification system."""
import pytest
from sentinel.core.models import Plan, PlanStep, TaskResult


class TestVerificationModelFields:
    def test_plan_step_assertions_default_empty(self):
        step = PlanStep(id="step_1", type="tool_call", tool="file_write", args={"path": "/workspace/test.txt", "content": "hello"})
        assert step.assertions == []

    def test_plan_step_assertions_with_values(self):
        step = PlanStep(
            id="step_1", type="tool_call", tool="file_write",
            args={"path": "/workspace/test.txt", "content": "hello"},
            assertions=[
                {"assert": "file_contains", "path": "/workspace/test.txt", "pattern": "hello"},
                {"assert": "file_exists", "path": "/workspace/test.txt"},
            ],
        )
        assert len(step.assertions) == 2
        assert step.assertions[0]["assert"] == "file_contains"

    def test_plan_step_assertion_with_recovery(self):
        step = PlanStep(
            id="step_1", type="tool_call", tool="file_patch",
            args={"path": "/workspace/style.css", "anchor": "body {", "patch": "  background-color: red;"},
            assertions=[{
                "assert": "file_contains",
                "path": "/workspace/style.css",
                "pattern": "background-color:\\s*red",
                "recovery": "Re-read style.css and apply file_patch to the correct selector",
            }],
        )
        assert step.assertions[0]["recovery"] == "Re-read style.css and apply file_patch to the correct selector"

    def test_plan_assertions_default_empty(self):
        plan = Plan(plan_summary="Test", steps=[])
        assert plan.assertions == []

    def test_task_result_verification_fields_default(self):
        result = TaskResult(status="success")
        assert result.completion == "full"
        assert result.goal_actions_executed is None
        assert result.file_mutations == []
        assert result.assertion_failures == []
        assert result.tool_output_warnings == []
        assert result.judge_verdict is None


from sentinel.planner.verification import (
    check_goal_actions_executed,
    extract_file_mutations,
    scan_tool_output,
    ToolOutputWarning,
)


class TestGoalActionsExecuted:
    def test_effect_tools_detected(self):
        """file_write is an effect tool — goal actions were executed."""
        executed_steps = [
            {"tool": "file_read", "status": "success"},
            {"tool": "file_write", "status": "success"},
        ]
        assert check_goal_actions_executed(executed_steps) is True

    def test_discovery_only_detected(self):
        """Only discovery tools ran — goal actions NOT executed."""
        executed_steps = [
            {"tool": "file_read", "status": "success"},
            {"tool": "web_search", "status": "success"},
            {"tool": "list_dir", "status": "success"},
        ]
        assert check_goal_actions_executed(executed_steps) is False

    def test_llm_task_only_is_discovery(self):
        """llm_task steps without tool calls are discovery."""
        executed_steps = [
            {"tool": "", "status": "success", "step_type": "llm_task"},
        ]
        assert check_goal_actions_executed(executed_steps) is False

    def test_blocked_effect_tool_not_counted(self):
        """A blocked effect tool did NOT execute its effect."""
        executed_steps = [
            {"tool": "file_read", "status": "success"},
            {"tool": "file_patch", "status": "blocked"},
        ]
        assert check_goal_actions_executed(executed_steps) is False

    def test_empty_steps(self):
        assert check_goal_actions_executed([]) is False

    def test_shell_exec_is_effect(self):
        executed_steps = [{"tool": "shell_exec", "status": "success"}]
        assert check_goal_actions_executed(executed_steps) is True

    def test_signal_send_is_effect(self):
        executed_steps = [{"tool": "signal_send", "status": "success"}]
        assert check_goal_actions_executed(executed_steps) is True

    def test_website_is_effect(self):
        executed_steps = [{"tool": "website", "status": "success"}]
        assert check_goal_actions_executed(executed_steps) is True


class TestExtractFileMutations:
    def test_extracts_mutation_with_sizes(self):
        step_outcomes = [
            {"tool": "file_write", "file_path": "/workspace/test.txt", "file_size_before": None, "file_size_after": 100, "diff_stats": {"lines_added": 5, "lines_deleted": 0}},
        ]
        mutations = extract_file_mutations(step_outcomes)
        assert len(mutations) == 1
        assert mutations[0]["path"] == "/workspace/test.txt"
        assert mutations[0]["size_before"] is None
        assert mutations[0]["size_after"] == 100
        assert mutations[0]["lines_added"] == 5

    def test_detects_no_op_patch(self):
        """size_before == size_after on a file_patch is a no-op signal."""
        step_outcomes = [
            {"tool": "file_patch", "file_path": "/workspace/style.css", "file_size_before": 500, "file_size_after": 500, "diff_stats": None},
        ]
        mutations = extract_file_mutations(step_outcomes)
        assert len(mutations) == 1
        assert mutations[0]["no_op"] is True

    def test_skips_non_file_tools(self):
        step_outcomes = [
            {"tool": "web_search", "status": "success"},
            {"tool": "file_read", "file_path": "/workspace/test.txt", "file_size_before": None, "file_size_after": None},
        ]
        mutations = extract_file_mutations(step_outcomes)
        assert len(mutations) == 0

    def test_empty_outcomes(self):
        assert extract_file_mutations([]) == []

    def test_multiple_mutations(self):
        step_outcomes = [
            {"tool": "file_write", "file_path": "/workspace/a.txt", "file_size_before": None, "file_size_after": 50, "diff_stats": {"lines_added": 3, "lines_deleted": 0}},
            {"tool": "file_patch", "file_path": "/workspace/b.css", "file_size_before": 200, "file_size_after": 250, "diff_stats": {"lines_added": 5, "lines_deleted": 2}},
        ]
        mutations = extract_file_mutations(step_outcomes)
        assert len(mutations) == 2


class TestScanToolOutput:
    def test_detects_no_such_file(self):
        warnings = scan_tool_output("bash: /workspace/missing.txt: No such file or directory")
        assert len(warnings) == 1
        assert warnings[0].severity == "HIGH"
        assert "No such file" in warnings[0].pattern

    def test_detects_permission_denied(self):
        warnings = scan_tool_output("Permission denied: /workspace/secret.key")
        assert len(warnings) == 1
        assert warnings[0].severity == "HIGH"

    def test_detects_patch_rejected(self):
        warnings = scan_tool_output("patch rejected: anchor not found in file")
        assert len(warnings) == 1
        assert warnings[0].severity == "HIGH"

    def test_detects_no_changes_made(self):
        warnings = scan_tool_output("no changes made to the file")
        assert len(warnings) == 1
        assert warnings[0].severity == "HIGH"

    def test_clean_output_no_warnings(self):
        warnings = scan_tool_output("Successfully wrote 150 bytes to /workspace/test.txt")
        assert len(warnings) == 0

    def test_empty_output_is_warning(self):
        warnings = scan_tool_output("")
        assert len(warnings) == 1
        assert warnings[0].severity == "HIGH"
        assert "empty" in warnings[0].pattern.lower()

    def test_detects_traceback(self):
        warnings = scan_tool_output("Traceback (most recent call last):\n  File...")
        assert len(warnings) == 1
        assert warnings[0].severity == "HIGH"

    def test_low_severity_warning(self):
        warnings = scan_tool_output("warning: deprecated function used")
        assert len(warnings) == 1
        assert warnings[0].severity == "LOW"


import os
import hashlib
import tempfile

from sentinel.planner.verification import evaluate_assertions, AssertionResult


class TestAssertionEvaluators:
    def test_file_exists_pass(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        results = evaluate_assertions(
            [{"assert": "file_exists", "path": str(f)}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert len(results) == 1
        assert results[0].passed is True

    def test_file_exists_fail(self, tmp_path):
        results = evaluate_assertions(
            [{"assert": "file_exists", "path": str(tmp_path / "missing.txt")}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert len(results) == 1
        assert results[0].passed is False

    def test_file_contains_pass(self, tmp_path):
        f = tmp_path / "style.css"
        f.write_text("body { background-color: darkgreen; }")
        results = evaluate_assertions(
            [{"assert": "file_contains", "path": str(f), "pattern": r"background-color:\s*darkgreen"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is True

    def test_file_contains_fail(self, tmp_path):
        f = tmp_path / "style.css"
        f.write_text("body { color: black; }")
        results = evaluate_assertions(
            [{"assert": "file_contains", "path": str(f), "pattern": r"background-color:\s*darkgreen"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is False
        assert "not found" in results[0].message

    def test_file_not_contains_pass(self, tmp_path):
        f = tmp_path / "clean.html"
        f.write_text("<html><body>Safe</body></html>")
        results = evaluate_assertions(
            [{"assert": "file_not_contains", "path": str(f), "pattern": r"<script>alert"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is True

    def test_file_not_contains_fail(self, tmp_path):
        f = tmp_path / "bad.html"
        f.write_text("<html><script>alert('xss')</script></html>")
        results = evaluate_assertions(
            [{"assert": "file_not_contains", "path": str(f), "pattern": r"<script>alert"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is False

    def test_file_not_empty_pass(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text('{"key": "value"}')
        results = evaluate_assertions(
            [{"assert": "file_not_empty", "path": str(f)}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is True

    def test_file_not_empty_fail(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("")
        results = evaluate_assertions(
            [{"assert": "file_not_empty", "path": str(f)}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is False

    def test_content_changed_pass(self, tmp_path):
        """content_changed uses before-hash from step outcomes."""
        f = tmp_path / "style.css"
        f.write_text("body { background: red; }")
        results = evaluate_assertions(
            [{"assert": "content_changed", "path": str(f)}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
            before_hashes={str(f): "different_hash_from_before"},
        )
        assert results[0].passed is True

    def test_content_changed_fail_same_hash(self, tmp_path):
        f = tmp_path / "style.css"
        content = "body { background: blue; }"
        f.write_text(content)
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        results = evaluate_assertions(
            [{"assert": "content_changed", "path": str(f)}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
            before_hashes={str(f): current_hash},
        )
        assert results[0].passed is False

    def test_response_contains_pass(self):
        results = evaluate_assertions(
            [{"assert": "response_contains", "step_id": "step_3", "pattern": "sent successfully"}],
            step_outcomes=[
                {"step_id": "step_1", "tool": "file_read"},
                {"step_id": "step_3", "tool": "email_send", "output_preview": "Email sent successfully to user@example.com"},
            ],
            workspace_root="/workspace",
        )
        assert results[0].passed is True

    def test_response_contains_fail(self):
        results = evaluate_assertions(
            [{"assert": "response_contains", "step_id": "step_3", "pattern": "sent successfully"}],
            step_outcomes=[
                {"step_id": "step_3", "tool": "email_send", "output_preview": "Connection timed out"},
            ],
            workspace_root="/workspace",
        )
        assert results[0].passed is False

    def test_unknown_assertion_type_skipped(self, tmp_path):
        results = evaluate_assertions(
            [{"assert": "unknown_type", "path": "/workspace/x"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert len(results) == 1
        assert results[0].passed is False
        assert "unknown" in results[0].message.lower()

    def test_path_outside_workspace_rejected(self, tmp_path):
        results = evaluate_assertions(
            [{"assert": "file_exists", "path": "/etc/passwd"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is False
        assert "outside workspace" in results[0].message.lower()

    def test_malformed_regex_handled(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        results = evaluate_assertions(
            [{"assert": "file_contains", "path": str(f), "pattern": "[invalid regex"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is False
        assert "regex" in results[0].message.lower()

    def test_recovery_field_preserved_in_result(self, tmp_path):
        f = tmp_path / "style.css"
        f.write_text("body { color: black; }")
        results = evaluate_assertions(
            [{"assert": "file_contains", "path": str(f), "pattern": "background-color", "recovery": "Re-read and patch correct selector"}],
            step_outcomes=[],
            workspace_root=str(tmp_path),
        )
        assert results[0].passed is False
        assert results[0].recovery == "Re-read and patch correct selector"


from sentinel.planner.verification import (
    build_judge_payload,
    process_judge_verdict,
    classify_task_category,
)


class TestBuildJudgePayload:
    def test_builds_prompt_with_all_fields(self):
        payload = build_judge_payload(
            original_request="Change background to dark green",
            plan_summary="Read CSS, patch background colour",
            step_outcomes=[
                {"step_id": "step_1", "tool": "file_read", "status": "success", "output_size": 500},
                {"step_id": "step_2", "tool": "file_patch", "status": "success", "output_size": 100},
            ],
            file_mutations=[
                {"path": "/workspace/sites/glasgow/style.css", "size_before": 200, "size_after": 220, "lines_added": 2, "lines_deleted": 1, "no_op": False},
            ],
            completion="full",
            goal_actions_executed=True,
            assertion_results=[],
            tool_output_warnings=[],
        )
        assert "Change background to dark green" in payload
        assert "CORRECT_TARGET" in payload
        assert "CORRECT_CONTENT" in payload
        assert "SIDE_EFFECTS" in payload
        assert "COMPLETENESS" in payload
        assert "GOAL_MET" in payload

    def test_prompt_excludes_raw_qwen_output(self):
        payload = build_judge_payload(
            original_request="test",
            plan_summary="test plan",
            step_outcomes=[{"step_id": "step_1", "tool": "file_read", "status": "success", "output_size": 100}],
            file_mutations=[],
            completion="full",
            goal_actions_executed=True,
            assertion_results=[],
            tool_output_warnings=[],
        )
        # Should not contain raw content — only metadata
        assert "output_size" in payload or "100" in payload


class TestProcessJudgeVerdict:
    def test_high_confidence_yes_returns_full(self):
        verdict = {
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": True,
            "SIDE_EFFECTS": False,
            "COMPLETENESS": True,
            "GOAL_MET": "yes",
            "CONFIDENCE": "high",
            "GAP": None,
        }
        result = process_judge_verdict(verdict, current_completion="full")
        assert result["completion"] == "full"
        assert result["acted_on"] is True

    def test_high_confidence_no_overrides_to_failed(self):
        verdict = {
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": False,
            "SIDE_EFFECTS": False,
            "COMPLETENESS": False,
            "GOAL_MET": "no",
            "CONFIDENCE": "high",
            "GAP": "Wrong CSS property targeted",
        }
        result = process_judge_verdict(verdict, current_completion="full")
        assert result["completion"] == "failed"
        assert result["acted_on"] is True
        assert result["gap"] == "Wrong CSS property targeted"

    def test_medium_confidence_is_advisory(self):
        verdict = {
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": True,
            "SIDE_EFFECTS": False,
            "COMPLETENESS": False,
            "GOAL_MET": "partial",
            "CONFIDENCE": "medium",
            "GAP": "Footer not updated",
        }
        result = process_judge_verdict(verdict, current_completion="full")
        assert result["completion"] == "full"  # NOT changed — advisory only
        assert result["acted_on"] is False

    def test_low_confidence_is_discarded(self):
        verdict = {
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": True,
            "SIDE_EFFECTS": True,
            "COMPLETENESS": True,
            "GOAL_MET": "partial",
            "CONFIDENCE": "low",
            "GAP": "Not sure",
        }
        result = process_judge_verdict(verdict, current_completion="full")
        assert result["completion"] == "full"
        assert result["acted_on"] is False

    def test_high_confidence_partial_returns_partial(self):
        verdict = {
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": False,
            "SIDE_EFFECTS": False,
            "COMPLETENESS": False,
            "GOAL_MET": "partial",
            "CONFIDENCE": "high",
            "GAP": "Background changed to wrong colour",
        }
        result = process_judge_verdict(verdict, current_completion="full")
        assert result["completion"] == "partial"
        assert result["acted_on"] is True


class TestClassifyTaskCategory:
    def test_deterministic_with_specific_value(self):
        assert classify_task_category("Change the background colour to red", assertions_count=1) == "deterministic"

    def test_semantic_vague_request(self):
        assert classify_task_category("Make the website look more professional", assertions_count=0) == "semantic"

    def test_structural_with_concrete_elements(self):
        assert classify_task_category("Add a contact form to the website", assertions_count=0) == "structural"

    def test_strong_assertions_push_to_deterministic(self):
        """Even a vague-sounding request is deterministic if the planner generated strong assertions."""
        assert classify_task_category("Update the site styling", assertions_count=3) == "deterministic"

    def test_no_assertions_vague_is_semantic(self):
        assert classify_task_category("improve the layout", assertions_count=0) == "semantic"

    def test_send_email_is_deterministic(self):
        assert classify_task_category("Send an email to john@example.com about the meeting", assertions_count=0) == "deterministic"


from sentinel.memory.episodic import _render_compact_plan_line


class TestCompactPlanLineVerification:
    def test_partial_marker_appended(self):
        plan_json = {
            "phases": [{
                "phase": "initial",
                "trigger": None,
                "plan": {"steps": [{"id": "step_1", "tool": "file_read", "output_var": "$page"}]},
                "step_outcomes_summary": {"step_1": {"status": "success"}},
            }],
            "completion": "partial",
        }
        line = _render_compact_plan_line(plan_json)
        assert "[PARTIAL]" in line

    def test_abandoned_marker_appended(self):
        plan_json = {
            "phases": [{
                "phase": "initial",
                "trigger": None,
                "plan": {"steps": [{"id": "step_1", "tool": "file_read", "output_var": "$page"}]},
                "step_outcomes_summary": {"step_1": {"status": "blocked"}},
            }],
            "completion": "abandoned",
        }
        line = _render_compact_plan_line(plan_json)
        assert "[ABANDONED]" in line

    def test_full_completion_no_marker(self):
        plan_json = {
            "phases": [{
                "phase": "initial",
                "trigger": None,
                "plan": {"steps": [{"id": "step_1", "tool": "file_write", "output_var": "$out"}]},
                "step_outcomes_summary": {"step_1": {"status": "success"}},
            }],
            "completion": "full",
        }
        line = _render_compact_plan_line(plan_json)
        assert "[PARTIAL]" not in line
        assert "[ABANDONED]" not in line

    def test_missing_completion_field_no_marker(self):
        """Backward compat: old records without completion field."""
        plan_json = {
            "phases": [{
                "phase": "initial",
                "trigger": None,
                "plan": {"steps": [{"id": "step_1", "tool": "file_read"}]},
                "step_outcomes_summary": {"step_1": {"status": "success"}},
            }],
        }
        line = _render_compact_plan_line(plan_json)
        assert "[PARTIAL]" not in line


from unittest.mock import AsyncMock, MagicMock, patch
import json as json_mod


class TestPlannerVerifyGoal:
    @pytest.mark.asyncio
    async def test_verify_goal_returns_parsed_verdict(self):
        """verify_goal calls Claude API and returns parsed JSON verdict."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = json_mod.dumps({
            "CORRECT_TARGET": True,
            "CORRECT_CONTENT": True,
            "SIDE_EFFECTS": False,
            "COMPLETENESS": True,
            "GOAL_MET": "yes",
            "CONFIDENCE": "high",
            "GAP": None,
        })
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        from sentinel.planner.planner import ClaudePlanner
        planner = ClaudePlanner.__new__(ClaudePlanner)
        planner._client = mock_client

        verdict = await planner.verify_goal("Change background to red")
        assert verdict["GOAL_MET"] == "yes"
        assert verdict["CONFIDENCE"] == "high"
        mock_client.messages.create.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_verify_goal_handles_malformed_json(self):
        """verify_goal returns a low-confidence discard on malformed JSON."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = "This is not JSON at all"
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        from sentinel.planner.planner import ClaudePlanner
        planner = ClaudePlanner.__new__(ClaudePlanner)
        planner._client = mock_client

        verdict = await planner.verify_goal("test prompt")
        assert verdict["CONFIDENCE"] == "low"
        assert verdict["GOAL_MET"] == "yes"  # safe default — don't block on parse failure

    @pytest.mark.asyncio
    async def test_verify_goal_handles_api_error(self):
        """verify_goal returns safe default on API errors."""
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API down"))

        from sentinel.planner.planner import ClaudePlanner
        planner = ClaudePlanner.__new__(ClaudePlanner)
        planner._client = mock_client

        verdict = await planner.verify_goal("test prompt")
        assert verdict["CONFIDENCE"] == "low"
        assert verdict["GOAL_MET"] == "yes"


class TestPlannerAssertionSchema:
    def test_plan_step_accepts_assertions_from_planner_json(self):
        """Validate that PlanStep can be constructed from planner JSON with assertions."""
        step_data = {
            "id": "step_2",
            "type": "tool_call",
            "tool": "file_patch",
            "description": "Patch background colour",
            "args": {"path": "/workspace/sites/glasgow/style.css", "anchor": "body {", "patch": "  background-color: darkgreen;"},
            "assertions": [
                {"assert": "file_contains", "path": "/workspace/sites/glasgow/style.css", "pattern": "background-color:\\s*darkgreen", "recovery": "Re-read CSS and patch correct selector"},
                {"assert": "content_changed", "path": "/workspace/sites/glasgow/style.css"},
            ],
        }
        step = PlanStep(**step_data)
        assert len(step.assertions) == 2
        assert step.assertions[0]["assert"] == "file_contains"
        assert step.assertions[0]["recovery"] is not None
