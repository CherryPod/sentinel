"""Shared intake types — breaks circular dependency between intake modules.

IntakeResult is used by both intake.py (bind_session) and
conversation_gate.py (analyze_conversation). Placing it here avoids
a circular import chain.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.core.models import ConversationInfo, TaskResult
from sentinel.session.store import Session


@dataclass
class IntakeResult:
    """Result of the session-binding intake stage."""

    session: Session | None = None
    conv_info: ConversationInfo | None = None
    blocked: bool = False
    task_result: TaskResult | None = None  # set when blocked
    # Security-critical: when True, the orchestrator MUST skip input scanning
    # because the router already scanned. When False, S1 scan is mandatory.
    input_pre_scanned: bool = False
