"""F3: Worker turn buffer unit tests."""

import time
import pytest
from sentinel.worker.context import WorkerTurn, WorkerContext


class TestWorkerTurn:
    """WorkerTurn dataclass construction."""

    def test_construction(self):
        t = WorkerTurn(
            turn_number=1,
            prompt_summary="Generate a bitcoin tracker",
            response_summary="<!DOCTYPE html>...",
            step_outcome={"output_size": 2847, "output_language": "html"},
            timestamp=time.time(),
        )
        assert t.turn_number == 1
        assert t.prompt_summary == "Generate a bitcoin tracker"
        assert t.step_outcome["output_size"] == 2847


class TestWorkerContextAddTurn:
    """Ring buffer eviction behaviour."""

    def test_add_within_limit(self):
        ctx = WorkerContext(session_id="s1", max_turns=3)
        for i in range(3):
            ctx.add_turn(_make_turn(i + 1))
        assert len(ctx.turns) == 3

    def test_evict_oldest_at_limit(self):
        ctx = WorkerContext(session_id="s1", max_turns=3)
        for i in range(5):
            ctx.add_turn(_make_turn(i + 1))
        assert len(ctx.turns) == 3
        assert ctx.turns[0].turn_number == 3
        assert ctx.turns[-1].turn_number == 5


class TestWorkerContextFormat:
    """format_context() output."""

    def test_format_with_metadata(self):
        ctx = WorkerContext(session_id="s1")
        ctx.add_turn(_make_turn(1, outcome={
            "output_size": 2847,
            "output_language": "html",
            "syntax_valid": True,
            "scanner_result": "clean",
        }))
        result = ctx.format_context()
        assert "[Previous work in this session:]" in result
        assert "Turn 1" in result
        assert "2847B" in result
        assert "html" in result
        assert "syntax ok" in result

    def test_format_empty_returns_empty(self):
        ctx = WorkerContext(session_id="s1")
        assert ctx.format_context() == ""

    def test_format_token_budget_truncation(self):
        """When total exceeds token budget, oldest turns are dropped."""
        ctx = WorkerContext(session_id="s1", max_tokens=100)
        for i in range(10):
            ctx.add_turn(_make_turn(
                i + 1,
                response="A" * 200,  # force large entries
            ))
        result = ctx.format_context()
        assert "[... earlier turns truncated ...]" in result

    def test_format_syntax_error_shown(self):
        ctx = WorkerContext(session_id="s1")
        ctx.add_turn(_make_turn(1, outcome={
            "output_size": 500,
            "syntax_valid": False,
        }))
        result = ctx.format_context()
        assert "SYNTAX ERROR" in result

    def test_format_blocked_step_empty_response(self):
        """Blocked steps have empty response_summary."""
        ctx = WorkerContext(session_id="s1")
        ctx.add_turn(WorkerTurn(
            turn_number=1,
            prompt_summary="Write exploit code",
            response_summary="",
            step_outcome={"status": "blocked", "scanner_result": "blocked"},
            timestamp=time.time(),
        ))
        result = ctx.format_context()
        assert "Turn 1" in result
        assert "blocked" in result

    def test_clear(self):
        ctx = WorkerContext(session_id="s1")
        ctx.add_turn(_make_turn(1))
        ctx.clear()
        assert len(ctx.turns) == 0
        assert ctx.format_context() == ""


def _make_turn(num, outcome=None, prompt="test prompt", response="test response"):
    return WorkerTurn(
        turn_number=num,
        prompt_summary=prompt[:200],
        response_summary=response[:500],
        step_outcome=outcome or {"output_size": 100, "status": "success"},
        timestamp=time.time(),
    )
