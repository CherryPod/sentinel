"""Tests for the Qwen-based request classifier."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.router.classifier import Classifier, ClassificationResult, Route
from sentinel.router.templates import Template, TemplateRegistry


@pytest.fixture
def registry() -> TemplateRegistry:
    """Minimal registry with a couple of templates for testing."""
    reg = TemplateRegistry()
    reg.register(
        Template(
            name="calendar_add",
            description="Create a new calendar event",
            tool="calendar_create_event",
            required_params=["summary", "start"],
            optional_params=["end", "location"],
            param_aliases={"title": "summary"},
            side_effect=True,
        )
    )
    reg.register(
        Template(
            name="web_search",
            description="Search the web",
            tool="web_search",
            required_params=["query"],
        )
    )
    return reg


@pytest.fixture
def mock_worker() -> AsyncMock:
    """Mock OllamaWorker with async generate method."""
    worker = AsyncMock()
    worker.generate = AsyncMock(return_value=("", None))
    return worker


@pytest.fixture
def classifier(mock_worker: AsyncMock, registry: TemplateRegistry) -> Classifier:
    return Classifier(worker=mock_worker, registry=registry, timeout=5.0)


# --- 1. Valid fast route ---

@pytest.mark.asyncio
async def test_valid_fast_route(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Qwen returns a valid fast-route JSON — classifier returns is_fast with correct fields."""
    mock_worker.generate.return_value = (
        json.dumps({"route": "fast", "template": "calendar_add", "params": {"summary": "Dentist", "start": "2026-03-06T10:00"}}),
        None,
    )
    result = await classifier.classify("Add a dentist appointment tomorrow at 10am")

    assert result.is_fast
    assert not result.is_planner
    assert result.route == Route.FAST
    assert result.template_name == "calendar_add"
    assert result.params["summary"] == "Dentist"
    assert result.params["start"] == "2026-03-06T10:00"


# --- 2. Valid planner route ---

@pytest.mark.asyncio
async def test_valid_planner_route(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Qwen returns a planner route — classifier returns is_planner with reason."""
    mock_worker.generate.return_value = (
        json.dumps({"route": "planner", "reason": "Multi-step task requiring several tools"}),
        None,
    )
    result = await classifier.classify("Research AI safety papers and summarise them")

    assert result.is_planner
    assert not result.is_fast
    assert result.route == Route.PLANNER
    assert "Multi-step" in result.reason


# --- 3. Invalid JSON → planner fallback ---

@pytest.mark.asyncio
async def test_invalid_json_falls_back_to_planner(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Malformed JSON from Qwen → planner fallback with reason mentioning 'parse'."""
    mock_worker.generate.return_value = ("This is not valid JSON at all!", None)
    result = await classifier.classify("Do something")

    assert result.is_planner
    assert "parse" in result.reason.lower()


# --- 4. Unknown template → planner fallback ---

@pytest.mark.asyncio
async def test_unknown_template_falls_back_to_planner(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Qwen returns a template name that doesn't exist → planner fallback."""
    mock_worker.generate.return_value = (
        json.dumps({"route": "fast", "template": "nonexistent_tool", "params": {}}),
        None,
    )
    result = await classifier.classify("Do a thing")

    assert result.is_planner
    assert "unknown" in result.reason.lower()


# --- 5. Missing required params → planner fallback ---

@pytest.mark.asyncio
async def test_missing_required_params_falls_back_to_planner(
    classifier: Classifier, mock_worker: AsyncMock
) -> None:
    """Qwen returns calendar_add but omits required 'start' → planner fallback."""
    mock_worker.generate.return_value = (
        json.dumps({"route": "fast", "template": "calendar_add", "params": {"summary": "Dentist"}}),
        None,
    )
    result = await classifier.classify("Add dentist appointment")

    assert result.is_planner
    assert "param" in result.reason.lower()


# --- 6. Worker timeout → planner fallback ---

@pytest.mark.asyncio
async def test_worker_timeout_falls_back_to_planner(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Worker raises asyncio.TimeoutError → planner fallback with 'timeout' in reason."""
    mock_worker.generate.side_effect = asyncio.TimeoutError()
    result = await classifier.classify("Search the web for cats")

    assert result.is_planner
    assert "timeout" in result.reason.lower()


# --- 7. Worker generic error → planner fallback ---

@pytest.mark.asyncio
async def test_worker_error_falls_back_to_planner(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Worker raises a generic exception → planner fallback."""
    mock_worker.generate.side_effect = RuntimeError("Ollama connection refused")
    result = await classifier.classify("Search for something")

    assert result.is_planner


# --- 8. Thinking tags stripped ---

@pytest.mark.asyncio
async def test_thinking_tags_stripped(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """<think>...</think> blocks before JSON are stripped, JSON parsed correctly."""
    response = '<think>The user wants to search the web for cats.</think>\n' + json.dumps(
        {"route": "fast", "template": "web_search", "params": {"query": "cats"}}
    )
    mock_worker.generate.return_value = (response, None)
    result = await classifier.classify("Search the web for cats")

    assert result.is_fast
    assert result.template_name == "web_search"
    assert result.params["query"] == "cats"


# --- 9. Param aliases resolved ---

@pytest.mark.asyncio
async def test_param_aliases_resolved(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Qwen returns {"title": "Dentist"} — alias resolved to {"summary": "Dentist"}."""
    mock_worker.generate.return_value = (
        json.dumps({
            "route": "fast",
            "template": "calendar_add",
            "params": {"title": "Dentist", "start": "2026-03-06T10:00"},
        }),
        None,
    )
    result = await classifier.classify("Add dentist appointment tomorrow at 10")

    assert result.is_fast
    assert result.params["summary"] == "Dentist"
    # Alias key should not remain
    assert "title" not in result.params


# --- 10. System prompt includes current datetime ---

@pytest.mark.asyncio
async def test_system_prompt_includes_datetime(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """The system_prompt passed to worker.generate contains a datetime string."""
    mock_worker.generate.return_value = (
        json.dumps({"route": "planner", "reason": "complex"}),
        None,
    )
    await classifier.classify("Do something")

    # worker.generate was called — inspect the system_prompt kwarg
    call_kwargs = mock_worker.generate.call_args
    # system_prompt is passed as keyword arg
    system_prompt = call_kwargs.kwargs.get("system_prompt") or call_kwargs.args[1] if len(call_kwargs.args) > 1 else call_kwargs.kwargs.get("system_prompt", "")
    assert "Current date/time:" in system_prompt
    # Should contain a year-like string
    assert "202" in system_prompt


# --- 11. Explicit planner override — "use the planner" ---

@pytest.mark.asyncio
async def test_planner_override_use_the_planner(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """'use the planner' in message → planner route, worker NOT called."""
    result = await classifier.classify("use the planner to search for weather")

    assert result.is_planner
    mock_worker.generate.assert_not_called()


# --- 12. Other planner override phrases ---

@pytest.mark.asyncio
async def test_planner_override_plan_this(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """'plan this' in message → planner route, worker NOT called."""
    result = await classifier.classify("plan this grocery shopping trip")

    assert result.is_planner
    mock_worker.generate.assert_not_called()


@pytest.mark.asyncio
async def test_planner_override_think_about_this(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """'think about this' in message → planner route, worker NOT called."""
    result = await classifier.classify("think about this problem for me")

    assert result.is_planner
    mock_worker.generate.assert_not_called()


# --- Edge: empty response → planner fallback ---

@pytest.mark.asyncio
async def test_empty_response_falls_back_to_planner(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Worker returns empty string → planner fallback."""
    mock_worker.generate.return_value = ("", None)
    result = await classifier.classify("Hello")

    assert result.is_planner
    assert "parse" in result.reason.lower() or "empty" in result.reason.lower()


# --- Edge: JSON wrapped in prose (regex fallback) ---

@pytest.mark.asyncio
async def test_json_wrapped_in_prose_regex_fallback(classifier: Classifier, mock_worker: AsyncMock) -> None:
    """Qwen wraps JSON in prose — regex extraction recovers it."""
    response = 'Here is my analysis:\n```json\n' + json.dumps(
        {"route": "fast", "template": "web_search", "params": {"query": "cats"}}
    ) + '\n```\nHope that helps!'
    mock_worker.generate.return_value = (response, None)
    result = await classifier.classify("Search the web for cats")

    assert result.is_fast
    assert result.template_name == "web_search"
