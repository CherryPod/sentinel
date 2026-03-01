"""Tests for _format_enriched_history on ClaudePlanner."""


class TestFormatEnrichedHistory:
    def _make_planner(self):
        from unittest.mock import MagicMock
        from sentinel.planner.planner import ClaudePlanner
        planner = ClaudePlanner.__new__(ClaudePlanner)
        planner._client = MagicMock()
        return planner

    def test_enriched_format_with_step_outcomes(self):
        """Non-success turns get full F1 enriched step detail."""
        planner = self._make_planner()
        history = [
            {
                "turn": 1,
                "request": "write a hello.py file",
                "outcome": "error",
                "summary": "Failed to create hello.py",
                "step_outcomes": [
                    {
                        "step_type": "llm_task",
                        "status": "success",
                        "output_size": 150,
                        "output_language": "python",
                        "syntax_valid": True,
                        "scanner_result": "clean",
                        "duration_s": 1.2,
                        "defined_symbols": ["main"],
                        "imports": ["os"],
                        "complexity_max": 2,
                        "complexity_function": "main",
                        "token_usage_ratio": 0.06,
                    },
                    {
                        "step_type": "tool_call",
                        "status": "error",
                        "file_path": "/workspace/hello.py",
                        "file_size_before": None,
                        "file_size_after": 150,
                        "diff_stats": "+8/-0 lines",
                        "duration_s": 0.1,
                        "error_detail": "write failed",
                    },
                ],
            }
        ]
        result = planner._format_enriched_history(history)
        assert "Turn 1:" in result
        assert "llm_task" in result
        assert "tool_call" in result
        assert "hello.py" in result
        assert "+8/-0 lines" in result

    def test_successful_turn_is_one_liner(self):
        """Successful turns are tiered to one-liner — no step detail."""
        planner = self._make_planner()
        history = [
            {
                "turn": 1,
                "request": "write a hello.py file",
                "outcome": "success",
                "summary": "Created hello.py",
                "step_outcomes": [
                    {
                        "step_type": "llm_task",
                        "status": "success",
                        "output_size": 150,
                    },
                ],
            }
        ]
        result = planner._format_enriched_history(history)
        assert "Turn 1:" in result
        assert "success" in result
        # Step detail suppressed for successful turns
        assert "llm_task" not in result
        assert "output=150B" not in result

    def test_bare_format_fallback_when_no_outcomes(self):
        """Pre-F1 turns have no step_outcomes — fall back to bare format."""
        planner = self._make_planner()
        history = [
            {
                "turn": 1,
                "request": "old request",
                "outcome": "success",
                "summary": "Did a thing",
                "step_outcomes": None,
            }
        ]
        result = planner._format_enriched_history(history)
        assert "Turn 1:" in result
        assert "old request" in result
        assert "success" in result

    def test_mixed_enriched_and_bare_turns(self):
        """Mix of pre-F1 and F1 turns."""
        planner = self._make_planner()
        history = [
            {
                "turn": 1,
                "request": "old turn",
                "outcome": "success",
                "summary": "Old thing",
                "step_outcomes": None,
            },
            {
                "turn": 2,
                "request": "new turn",
                "outcome": "success",
                "summary": "New thing",
                "step_outcomes": [
                    {"step_type": "llm_task", "status": "success", "output_size": 100},
                ],
            },
        ]
        result = planner._format_enriched_history(history)
        assert "Turn 1:" in result
        assert "Turn 2:" in result

    def test_blocked_step_shows_blocked_without_detail(self):
        """scanner_details redacted — planner sees BLOCKED, not scanner name."""
        planner = self._make_planner()
        history = [
            {
                "turn": 1,
                "request": "write something",
                "outcome": "blocked",
                "summary": "",
                "step_outcomes": [
                    {
                        "step_type": "llm_task",
                        "status": "blocked",
                        "scanner_result": "blocked",
                        "error_detail": "scan blocked",
                    },
                ],
            }
        ]
        result = planner._format_enriched_history(history)
        assert "BLOCKED" in result
        # Must NOT contain scanner implementation details
        assert "Semgrep" not in result
        assert "sensitive_path" not in result

    def test_empty_history_returns_empty_string(self):
        planner = self._make_planner()
        result = planner._format_enriched_history([])
        assert result == ""
