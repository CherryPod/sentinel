"""Verify TaskResult.response is populated for planner-routed tasks."""

import pytest
from sentinel.core.models import StepResult


def test_planner_task_result_has_response():
    """Last llm_task step content should be extractable as response."""
    step_results = [
        StepResult(step_id="tool_call:file_read", status="success", content="file contents here"),
        StepResult(step_id="llm_task", status="success", content="The README has two key sections: Features and Installation."),
    ]

    response = ""
    for sr in reversed(step_results):
        if sr.step_id.startswith("llm_task") and sr.content:
            response = sr.content
            break

    assert response != "", "Response should be populated from last llm_task step"
    assert "Features" in response


def test_planner_task_result_empty_when_no_llm_task():
    """Response stays empty if no llm_task steps exist."""
    step_results = [
        StepResult(step_id="tool_call:file_write", status="success", content="wrote file"),
    ]

    response = ""
    for sr in reversed(step_results):
        if sr.step_id.startswith("llm_task") and sr.content:
            response = sr.content
            break

    assert response == "", "Response should be empty when no llm_task steps"
