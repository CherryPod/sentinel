"""Edge case tests for the router classifier."""

import json
from unittest.mock import AsyncMock

import pytest

from sentinel.router.classifier import Classifier
from sentinel.router.templates import TemplateRegistry


def _make_classifier(response: str) -> Classifier:
    worker = AsyncMock()
    worker.generate.return_value = (response, None)
    return Classifier(worker=worker, registry=TemplateRegistry.default())


@pytest.mark.asyncio
async def test_json_embedded_in_prose():
    """Qwen sometimes wraps JSON in explanation text."""
    raw = (
        'Here is my classification:\n'
        '{"route": "fast", "template": "web_search", "params": {"query": "test"}}\n'
        'Hope that helps!'
    )
    clf = _make_classifier(raw)
    result = await clf.classify("test")
    assert result.is_fast
    assert result.template_name == "web_search"


@pytest.mark.asyncio
async def test_empty_response():
    clf = _make_classifier("")
    result = await clf.classify("test")
    assert result.is_planner


@pytest.mark.asyncio
async def test_route_field_missing():
    clf = _make_classifier('{"template": "web_search"}')
    result = await clf.classify("test")
    assert result.is_planner


@pytest.mark.asyncio
async def test_extra_fields_ignored():
    raw = json.dumps({
        "route": "fast",
        "template": "web_search",
        "params": {"query": "test"},
        "confidence": 0.95,
        "extra_junk": True,
    })
    clf = _make_classifier(raw)
    result = await clf.classify("test")
    assert result.is_fast


@pytest.mark.asyncio
async def test_plan_this_triggers_planner():
    clf = _make_classifier("should not be called")
    result = await clf.classify("plan this: check weather and add to calendar")
    assert result.is_planner
    clf._worker.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_think_about_this_triggers_planner():
    clf = _make_classifier("should not be called")
    result = await clf.classify("think about this carefully and search X")
    assert result.is_planner
    clf._worker.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_use_the_planner_mid_sentence():
    clf = _make_classifier("should not be called")
    result = await clf.classify("I want you to use the planner to find restaurants")
    assert result.is_planner
    clf._worker.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_planner_override_case_insensitive():
    clf = _make_classifier("should not be called")
    result = await clf.classify("USE THE PLANNER to do something")
    assert result.is_planner


@pytest.mark.asyncio
async def test_nested_json_in_thinking_block():
    """Qwen puts JSON after a thinking block."""
    raw = (
        '<think>\nThis looks like a calendar request.\n'
        'Let me classify it as calendar_add.\n</think>\n'
        '{"route": "fast", "template": "calendar_add", '
        '"params": {"summary": "Lunch", "start": "2026-03-06T12:00:00Z"}}'
    )
    clf = _make_classifier(raw)
    result = await clf.classify("add lunch tomorrow noon")
    assert result.is_fast
    assert result.template_name == "calendar_add"
    assert result.params["summary"] == "Lunch"


@pytest.mark.asyncio
async def test_route_value_not_fast_or_planner():
    """Unknown route value falls back to planner."""
    raw = json.dumps({"route": "unknown", "template": "web_search"})
    clf = _make_classifier(raw)
    result = await clf.classify("test")
    assert result.is_planner


@pytest.mark.asyncio
async def test_params_not_a_dict():
    """If params is a string or list, treat as empty dict."""
    raw = json.dumps({
        "route": "fast",
        "template": "web_search",
        "params": "not a dict",
    })
    clf = _make_classifier(raw)
    result = await clf.classify("test")
    # web_search requires "query" — missing, so falls back to planner
    assert result.is_planner
