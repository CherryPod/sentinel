"""Plan-outcome memory: tier-1 compact and tier-2 detailed rendering."""

import pytest
from sentinel.core.context import current_user_id


@pytest.fixture(autouse=True)
def _set_user_id():
    """All tests run as user 1."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


from sentinel.memory.episodic import render_episodic_text


class TestCompactPlanRendering:
    """Tier 1: render_episodic_text includes compact plan line when plan_json present."""

    def test_plan_line_with_plan_json(self):
        result = render_episodic_text(
            user_request="Build dashboard",
            task_status="success",
            step_count=3,
            success_count=2,
            plan_summary="Build dashboard with clock",
            step_outcomes=[
                {"step_type": "tool_call", "tool": "file_read", "status": "success"},
                {"step_type": "llm_task", "tool": "", "status": "success", "description": "gen widget"},
                {"step_type": "tool_call", "tool": "file_patch", "status": "blocked", "description": "patch"},
            ],
            plan_json={
                "phases": [
                    {
                        "phase": "initial",
                        "plan": {
                            "steps": [
                                {"id": "step_1", "type": "tool_call", "tool": "file_read", "output_var": "$page"},
                                {"id": "step_2", "type": "llm_task", "output_var": "$widget"},
                                {"id": "step_3", "type": "tool_call", "tool": "file_patch"},
                            ],
                        },
                        "step_outcomes_summary": {
                            "step_1": {"status": "success"},
                            "step_2": {"status": "success"},
                            "step_3": {"status": "blocked", "error": "innerHTML"},
                        },
                    },
                ],
            },
        )
        # Should contain a Plan: line with tool chain and outcome annotations
        assert "Plan:" in result
        assert "file_read" in result
        assert "file_patch" in result

    def test_no_plan_json_falls_back(self):
        """Without plan_json, renders plan_summary as before."""
        result = render_episodic_text(
            user_request="Build dashboard",
            task_status="success",
            plan_summary="Build dashboard with clock",
        )
        assert "Plan: Build dashboard with clock" in result

    def test_empty_plan_json_falls_back(self):
        result = render_episodic_text(
            user_request="Build dashboard",
            task_status="success",
            plan_summary="Build dashboard with clock",
            plan_json=None,
        )
        assert "Plan: Build dashboard with clock" in result


from sentinel.planner.builders import render_plan_history


MULTI_PHASE_PLAN_JSON = {
    "phases": [
        {
            "phase": "initial",
            "trigger": None,
            "trigger_step": None,
            "plan": {
                "summary": "Read page, generate clock, patch into dashboard",
                "steps": [
                    {"id": "step_1", "type": "tool_call", "tool": "file_read",
                     "args": {"path": "/workspace/index.html"}, "output_var": "$page"},
                    {"id": "step_2", "type": "llm_task", "description": "Generate clock widget",
                     "prompt": "Generate an HTML clock widget using textContent for DOM updates, not innerHTML. The widget should update every second showing HH:MM:SS format.",
                     "output_var": "$clock_html"},
                    {"id": "step_3", "type": "tool_call", "tool": "file_patch",
                     "args": {"anchor": "css:#content", "operation": "insert_after"}},
                ],
            },
            "step_outcomes_summary": {
                "step_1": {"status": "success", "output_size": 2341},
                "step_2": {"status": "success", "output_size": 180},
                "step_3": {"status": "blocked", "error": "innerHTML blocked by Semgrep",
                           "failure_fingerprint": "a3f2c1d8e9b0"},
            },
            "replan_context_summary": None,
        },
        {
            "phase": "continuation_1",
            "trigger": "soft_failed",
            "trigger_step": "step_3",
            "plan": {
                "summary": "Retry patch using textContent approach",
                "steps": [
                    {"id": "step_3_c1", "type": "llm_task", "description": "Regenerate clock without innerHTML",
                     "prompt": "Regenerate the clock widget. Use textContent instead of innerHTML for all DOM manipulation.",
                     "output_var": "$clock_v2"},
                    {"id": "step_4_c1", "type": "tool_call", "tool": "file_patch",
                     "args": {"anchor": "css:#content", "operation": "insert_after"}},
                ],
            },
            "step_outcomes_summary": {
                "step_3_c1": {"status": "success", "output_size": 165},
                "step_4_c1": {"status": "success", "file_size_before": 1200, "file_size_after": 1380},
            },
            "replan_context_summary": "Step 3 blocked: innerHTML-xss scanner rule. Prior steps succeeded.",
        },
    ],
    "user_request_full": "Build a dashboard with a live clock using dark theme",
}


class TestRenderPlanHistory:
    """Tier 2: render_plan_history produces detailed plan evolution text."""

    def test_renders_multi_phase_plan(self):
        result = render_plan_history(
            MULTI_PHASE_PLAN_JSON,
            task_status="success",
            step_count=5,
            success_count=4,
            task_domain="code_generation",
        )
        # Header
        assert "DETAILED PLAN HISTORY" in result
        # Phase 1
        assert "Phase 1 (initial)" in result
        assert "file_read" in result
        assert "step_1" in result
        assert "SUCCESS" in result
        # Failure with fingerprint
        assert "BLOCKED" in result
        assert "a3f2c1" in result
        # Phase 2 (continuation)
        assert "Phase 2 (continuation" in result
        assert "soft_fail" in result
        assert "Context:" in result
        # Worker prompt truncated but present
        assert "Generate an HTML clock widget" in result
        # File size delta
        assert "1200" in result
        assert "1380" in result
        # Footer
        assert "END DETAILED PLAN HISTORY" in result

    def test_single_phase_no_replan(self):
        plan_json = {
            "phases": [{
                "phase": "initial",
                "trigger": None,
                "trigger_step": None,
                "plan": {
                    "summary": "Simple read",
                    "steps": [{"id": "step_1", "type": "tool_call", "tool": "file_read",
                               "args": {"path": "/workspace/f.txt"}}],
                },
                "step_outcomes_summary": {
                    "step_1": {"status": "success", "output_size": 100},
                },
                "replan_context_summary": None,
            }],
            "user_request_full": "Read the file",
        }
        result = render_plan_history(plan_json, task_status="success", step_count=1, success_count=1)
        assert "Phase 1 (initial)" in result
        assert "Repeated failure fingerprints: none" in result

    def test_none_plan_json_returns_empty(self):
        assert render_plan_history(None) == ""

    def test_empty_phases_returns_empty(self):
        assert render_plan_history({"phases": []}) == ""


from sentinel.memory.episodic import EpisodicStore


SAMPLE_PLAN_JSON = {
    "phases": [
        {
            "phase": "initial",
            "trigger": None,
            "trigger_step": None,
            "plan": {
                "summary": "Read page, generate widget, patch",
                "steps": [
                    {"id": "step_1", "type": "tool_call", "tool": "file_read",
                     "args": {"path": "/workspace/index.html"}, "output_var": "$page"},
                    {"id": "step_2", "type": "llm_task", "description": "Generate widget",
                     "prompt": "Generate a clock widget using textContent",
                     "output_var": "$widget"},
                ],
            },
            "step_outcomes_summary": {
                "step_1": {"status": "success", "output_size": 2341},
                "step_2": {"status": "success", "output_size": 180},
            },
            "replan_context_summary": None,
        },
    ],
    "user_request_full": "Build a dashboard with a live clock",
}


class TestEndToEndRoundTrip:
    """Full round-trip: create record with plan_json -> render compact -> render detailed."""

    async def test_full_round_trip(self):
        store = EpisodicStore(pool=None)

        record_id = await store.create(
            session_id="s1",
            user_request="Build a dashboard with a live clock using dark theme",
            task_status="success",
            plan_summary="Read page, gen clock, patch",
            step_count=5,
            success_count=4,
            file_paths=["/workspace/sites/dashboard/index.html"],
            step_outcomes=[
                {"step_type": "tool_call", "tool": "file_read", "status": "success"},
                {"step_type": "llm_task", "tool": "", "status": "success", "description": "gen clock"},
                {"step_type": "tool_call", "tool": "file_patch", "status": "blocked", "description": "patch"},
                {"step_type": "llm_task", "tool": "", "status": "success", "description": "regen clock"},
                {"step_type": "tool_call", "tool": "file_patch", "status": "success", "description": "patch"},
            ],
            plan_json=MULTI_PHASE_PLAN_JSON,
        )

        record = await store.get(record_id)
        assert record is not None
        assert record.plan_json is not None

        # Tier 1: compact rendering includes plan line
        compact = render_episodic_text(
            user_request=record.user_request,
            task_status=record.task_status,
            step_count=record.step_count,
            success_count=record.success_count,
            file_paths=record.file_paths,
            plan_summary=record.plan_summary,
            step_outcomes=record.step_outcomes,
            task_domain=record.task_domain,
            plan_json=record.plan_json,
        )
        assert "Plan:" in compact
        assert "file_read" in compact

        # Tier 2: detailed rendering
        detailed = render_plan_history(
            record.plan_json,
            task_status=record.task_status,
            step_count=record.step_count,
            success_count=record.success_count,
            task_domain=record.task_domain,
        )
        assert "DETAILED PLAN HISTORY" in detailed
        assert "Phase 1" in detailed
        assert "Phase 2" in detailed
        assert "a3f2c1" in detailed  # failure fingerprint
