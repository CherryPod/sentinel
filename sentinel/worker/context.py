"""F3: Worker turn buffer — per-session ring buffer of prior worker output summaries.

Provides Qwen with awareness of its own prior work within a session for
debugging and iterative refinement. Context is local only — never persisted
to DB, never sent to the planner (which uses F1 step_outcomes instead).

Privacy boundary: summaries are constructed by the orchestrator (trusted),
but the content is UNTRUSTED because it summarises Qwen's prior output.
Each call still goes through the full security pipeline.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from sentinel.core.config import settings


@dataclass
class WorkerTurn:
    """One turn of worker interaction."""

    turn_number: int
    prompt_summary: str        # First 200 chars of the resolved prompt
    response_summary: str      # First 500 chars of Qwen's response
    step_outcome: dict         # F1 metadata (file_path, output_size, language, etc.)
    timestamp: float


@dataclass
class WorkerContext:
    """Per-session ring buffer of recent worker turns.

    Injected into Qwen's prompt when the planner sets
    include_worker_history=true on an llm_task step.
    """

    session_id: str
    turns: list[WorkerTurn] = field(default_factory=list)
    max_turns: int = field(default_factory=lambda: settings.worker_turn_buffer_size)
    max_tokens: int = field(default_factory=lambda: settings.worker_context_token_budget)

    def add_turn(self, turn: WorkerTurn) -> None:
        """Append a turn, evicting the oldest if over max."""
        self.turns.append(turn)
        if len(self.turns) > self.max_turns:
            self.turns.pop(0)

    def format_context(self) -> str:
        """Produce compact text block for prompt injection, within token budget."""
        if not self.turns:
            return ""

        budget = self.max_tokens * 4  # approximate char budget at ~4 chars/token
        lines = ["[Previous work in this session:]"]

        for turn in self.turns:
            entry = f"Turn {turn.turn_number}: {turn.prompt_summary}"

            # Key metadata from step_outcome
            meta_parts = []
            so = turn.step_outcome
            if so.get("output_size"):
                meta_parts.append(f"{so['output_size']}B")
            if so.get("output_language"):
                meta_parts.append(so["output_language"])
            if so.get("syntax_valid") is not None:
                meta_parts.append(
                    "syntax ok" if so["syntax_valid"] else "SYNTAX ERROR"
                )
            if so.get("scanner_result"):
                meta_parts.append(f"scanner: {so['scanner_result']}")
            if so.get("status") == "blocked":
                meta_parts.append("BLOCKED")
            if meta_parts:
                entry += f" ({', '.join(meta_parts)})"

            # Response summary (skip if empty — blocked steps)
            if turn.response_summary:
                entry += f"\n  Output: {turn.response_summary}"

            candidate = "\n".join(lines) + "\n" + entry
            if len(candidate) > budget:
                lines.insert(1, "[... earlier turns truncated ...]")
                break
            lines.append(entry)

        return "\n".join(lines)

    def clear(self) -> None:
        """Drop all buffered turns."""
        self.turns.clear()
