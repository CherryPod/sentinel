"""Tests for Step 1.5: every-turn cross-session context injection.

Verifies that the len(session.turns) == 0 gate has been removed,
so build_cross_session_context is called on every planner invocation.
"""

import inspect

import pytest


def test_no_turns_zero_gate_in_handle_task_inner():
    """The _handle_task_inner code must NOT gate cross-session on len(turns)==0."""
    from sentinel.planner.orchestrator import Orchestrator
    source = inspect.getsource(Orchestrator._handle_task_inner)

    assert "len(session.turns) == 0" not in source, (
        "Step 1.5: the len(session.turns) == 0 gate should be removed "
        "so cross-session context is injected on every planner call"
    )


def test_build_cross_session_called_unconditionally():
    """build_cross_session_context should be called when session is not None.

    Verifies the cross-session section doesn't have turns length check.
    """
    from sentinel.planner.orchestrator import Orchestrator
    source = inspect.getsource(Orchestrator._handle_task_inner)

    assert "build_cross_session_context" in source

    lines = source.split("\n")
    for i, line in enumerate(lines):
        if "build_cross_session_context" in line:
            context = "\n".join(lines[max(0, i - 5):i + 1])
            assert "len(session.turns)" not in context, (
                "build_cross_session_context should not be gated on session.turns length"
            )
            break


def test_comment_reflects_every_call():
    """The comment should say 'every planner call', not 'first turn'."""
    from sentinel.planner.orchestrator import Orchestrator
    source = inspect.getsource(Orchestrator._handle_task_inner)

    assert "on every planner call" in source
    assert "on first turn of new session" not in source
