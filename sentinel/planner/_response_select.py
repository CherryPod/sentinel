"""Response-text selection helper for the plan execution result builder.

This module is intentionally thin — it only imports from sentinel.core.models
so it can be imported in tests without pulling in the full planner import chain
(asyncpg, anthropic, audit logger, etc.).

Used by ExecutionMixin._build_execution_result in _execution.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.core.models import PlanStep, StepResult


def _select_response_text(
    step_results: list[StepResult],
    executed_steps: list[PlanStep],
) -> str:
    """Return content of the last executed llm_task step with non-empty content.

    Selects by step type (PlanStep.type == "llm_task"), not by step_id prefix.
    step_results and executed_steps are always equal-length and parallel
    (appended in lockstep by _execute_plan), so zipping them is safe.
    """
    for step, sr in zip(reversed(executed_steps), reversed(step_results)):
        if step.type == "llm_task" and sr.content:
            return sr.content
    return ""
