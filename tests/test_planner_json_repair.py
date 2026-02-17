"""Test JSON repair for truncated planner output."""

import json
import pytest
from sentinel.planner.planner import _repair_truncated_json


def test_repair_truncated_object():
    truncated = '{"plan_summary": "test", "steps": [{"id": "1", "type": "tool_call"'
    result = _repair_truncated_json(truncated)
    assert result is not None
    parsed = json.loads(result)
    assert parsed["plan_summary"] == "test"


def test_repair_truncated_array():
    truncated = '{"steps": [{"id": "1"}, {"id": "2"'
    result = _repair_truncated_json(truncated)
    assert result is not None
    parsed = json.loads(result)
    assert len(parsed["steps"]) >= 1


def test_repair_truncated_string_value():
    truncated = '{"plan_summary": "do something with the fi'
    result = _repair_truncated_json(truncated)
    assert result is not None
    parsed = json.loads(result)
    assert "plan_summary" in parsed


def test_repair_valid_json_passthrough():
    valid = '{"plan_summary": "test", "steps": []}'
    result = _repair_truncated_json(valid)
    assert result == valid


def test_repair_hopeless_garbage():
    garbage = "This is not JSON at all, just plain text"
    result = _repair_truncated_json(garbage)
    assert result is None


def test_repair_truncated_after_comma():
    truncated = '{"steps": [{"id": "1"},'
    result = _repair_truncated_json(truncated)
    assert result is not None
    parsed = json.loads(result)
    assert len(parsed["steps"]) == 1
