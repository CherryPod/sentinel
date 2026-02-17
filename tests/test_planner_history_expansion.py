"""Tests for _format_enriched_history() most-recent-turn expansion.

Step 0.2 of the Episodic Learning Layer plan: the most recent turn's
step_outcomes are always expanded (even on success), so the planner has
diagnostic context for follow-up requests like "fix it".
"""

from unittest.mock import MagicMock


def _make_planner():
    """Create a ClaudePlanner instance, bypassing __init__ (no API key needed)."""
    from sentinel.planner.planner import ClaudePlanner

    planner = ClaudePlanner.__new__(ClaudePlanner)
    planner._client = MagicMock()
    return planner


def _make_turn(turn_num, outcome="success", step_outcomes=None):
    """Build a minimal conversation history entry."""
    entry = {
        "turn": turn_num,
        "request": f"Turn {turn_num} request",
        "outcome": outcome,
        "summary": f"summary {turn_num}",
    }
    if step_outcomes is not None:
        entry["step_outcomes"] = step_outcomes
    return entry


# Reusable step_outcomes fixture with diagnostic detail
STEP_OUTCOMES_WITH_DETAIL = [
    {
        "step_type": "file_write",
        "status": "completed",
        "output_size": 1024,
        "output_language": "python",
        "syntax_valid": True,
        "file_path": "/workspace/script.py",
        "file_size_after": 1024,
        "exit_code": 0,
        "stderr_preview": "DeprecationWarning: use new_api()",
    },
]


class TestMostRecentTurnExpansion:
    """Most recent turn step_outcomes are always expanded."""

    def test_most_recent_success_turn_expanded(self):
        """(a) The last turn's step_outcomes appear even when status is success."""
        planner = _make_planner()
        history = [
            _make_turn(1, "success", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(2, "success", STEP_OUTCOMES_WITH_DETAIL),
        ]
        result = planner._format_enriched_history(history)

        # Turn 2 (most recent) should have expanded step detail
        assert "Step 1 [file_write]" in result
        # The stderr preview from the step should be visible
        assert "stderr=DeprecationWarning" in result

    def test_older_success_turns_still_collapsed(self):
        """(b) Older successful turns remain collapsed (one-liner only)."""
        planner = _make_planner()
        history = [
            _make_turn(1, "success", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(2, "success", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(3, "success", STEP_OUTCOMES_WITH_DETAIL),
        ]
        result = planner._format_enriched_history(history)
        lines = result.split("\n")

        # Turn 1 header present, but no step detail line after it
        assert any("Turn 1:" in l for l in lines)
        # Count how many "Step 1 [file_write]" lines — should be exactly 1
        # (from the last turn only)
        step_lines = [l for l in lines if "Step 1 [file_write]" in l]
        assert len(step_lines) == 1

    def test_empty_history(self):
        """(c) Empty or None history returns empty string."""
        planner = _make_planner()
        assert planner._format_enriched_history([]) == ""
        assert planner._format_enriched_history(None) == ""

    def test_multi_turn_only_expands_last(self):
        """(d) In a 4-turn history, only the last turn is expanded."""
        planner = _make_planner()
        history = [
            _make_turn(1, "success", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(2, "completed", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(3, "success", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(4, "success", STEP_OUTCOMES_WITH_DETAIL),
        ]
        result = planner._format_enriched_history(history)
        lines = result.split("\n")

        # Only 1 step detail line (from turn 4)
        step_lines = [l for l in lines if "Step 1 [file_write]" in l]
        assert len(step_lines) == 1

        # All 4 turn headers present
        for t in range(1, 5):
            assert any(f"Turn {t}:" in l for l in lines)

    def test_failed_older_turns_still_expanded(self):
        """Failed/blocked older turns keep their expansion (existing behaviour)."""
        planner = _make_planner()
        history = [
            _make_turn(1, "failed", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(2, "success", STEP_OUTCOMES_WITH_DETAIL),
        ]
        result = planner._format_enriched_history(history)
        lines = result.split("\n")

        # Both turns should have step detail — turn 1 because it failed,
        # turn 2 because it's the most recent
        step_lines = [l for l in lines if "Step 1 [file_write]" in l]
        assert len(step_lines) == 2

    def test_single_success_turn_expanded(self):
        """A single successful turn is both first and last — should expand."""
        planner = _make_planner()
        history = [_make_turn(1, "success", STEP_OUTCOMES_WITH_DETAIL)]
        result = planner._format_enriched_history(history)

        assert "Step 1 [file_write]" in result
        assert "stderr=DeprecationWarning" in result

    def test_last_turn_without_step_outcomes_no_crash(self):
        """Last turn with no step_outcomes (pre-F1) doesn't crash."""
        planner = _make_planner()
        history = [
            _make_turn(1, "success", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(2, "success"),  # no step_outcomes
        ]
        result = planner._format_enriched_history(history)

        # Turn 2 header present, no step detail (none to expand)
        assert "Turn 2:" in result
        # Turn 1 collapsed (older success, not last)
        step_lines = [l for l in result.split("\n") if "Step 1 [file_write]" in l]
        assert len(step_lines) == 0

    def test_completed_most_recent_also_expanded(self):
        """'completed' outcome (not just 'success') also gets expanded when last."""
        planner = _make_planner()
        history = [
            _make_turn(1, "success", STEP_OUTCOMES_WITH_DETAIL),
            _make_turn(2, "completed", STEP_OUTCOMES_WITH_DETAIL),
        ]
        result = planner._format_enriched_history(history)
        lines = result.split("\n")

        # Turn 2 (completed, most recent) should be expanded
        step_lines = [l for l in lines if "Step 1 [file_write]" in l]
        assert len(step_lines) == 1
        assert "stderr=DeprecationWarning" in result
