"""Shared fixtures for capability deployment tests.

Follows patterns from tests/test_orchestrator.py — provides mock planner,
mock pipeline, and safety-setting overrides so capability tests can focus
on behaviour without fighting Semgrep/PromptGuard availability.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.models import Plan, PlanStep
from sentinel.planner.orchestrator import Orchestrator
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.pipeline import PipelineScanResult, ScanPipeline
from sentinel.security.provenance import reset_store


@pytest.fixture(autouse=True)
async def _reset_provenance():
    """Reset the provenance store before and after each test."""
    await reset_store()
    yield
    await reset_store()


@pytest.fixture(autouse=True)
def _disable_semgrep_requirement():
    """Semgrep isn't loaded in unit tests; disable fail-closed."""
    from sentinel.core.config import settings
    original = settings.require_semgrep
    settings.require_semgrep = False
    yield
    settings.require_semgrep = original


@pytest.fixture(autouse=True)
def _disable_prompt_guard():
    """Prompt Guard isn't loaded in unit tests; disable so real pipelines work."""
    from sentinel.core.config import settings
    original = settings.prompt_guard_enabled
    settings.prompt_guard_enabled = False
    yield
    settings.prompt_guard_enabled = original


@pytest.fixture
def mock_planner():
    """Mock ClaudePlanner — create_plan is an AsyncMock."""
    planner = MagicMock(spec=ClaudePlanner)
    planner.create_plan = AsyncMock()
    return planner


@pytest.fixture
def mock_pipeline():
    """Mock ScanPipeline — scan_input returns clean, process_with_qwen is AsyncMock."""
    pipeline = MagicMock(spec=ScanPipeline)
    clean_result = PipelineScanResult()
    pipeline.scan_input.return_value = clean_result
    pipeline.process_with_qwen = AsyncMock()
    return pipeline


def _make_plan(steps: list[dict], summary: str = "Test plan") -> Plan:
    """Build a Plan from a list of step dicts."""
    return Plan(
        plan_summary=summary,
        steps=[PlanStep(**s) for s in steps],
    )
