from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class DataSource(str, Enum):
    USER = "user"
    CLAUDE = "claude"
    QWEN = "qwen"
    WEB = "web"
    FILE = "file"
    TOOL = "tool"


class PolicyResult(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"


class ValidationResult(BaseModel):
    status: PolicyResult
    path: str = ""
    reason: str = ""
    resolved_path: str = ""


class ScanMatch(BaseModel):
    pattern_name: str
    matched_text: str
    position: int = 0


class ScanResult(BaseModel):
    found: bool = False
    matches: list[ScanMatch] = Field(default_factory=list)
    scanner_name: str = ""


class TaggedData(BaseModel):
    id: str
    content: str
    trust_level: TrustLevel
    source: DataSource
    originated_from: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_results: dict[str, ScanResult] = Field(default_factory=dict)
    derived_from: list[str] = Field(default_factory=list)


# ── Phase 3 models ──────────────────────────────────────────────


class PlanStep(BaseModel):
    id: str                              # "step_1", "step_2"
    type: str                            # "llm_task" or "tool_call"
    description: str
    prompt: str | None = None            # For llm_task
    tool: str | None = None              # For tool_call
    args: dict = Field(default_factory=dict)
    output_var: str | None = None        # "$var_name" to store result
    expects_code: bool = False
    requires_approval: bool = False
    input_vars: list[str] = Field(default_factory=list)
    output_format: str | None = None  # "json", "tagged", or None (freeform)


class Plan(BaseModel):
    plan_summary: str
    steps: list[PlanStep]


class StepResult(BaseModel):
    step_id: str
    status: str                          # "success", "blocked", "error", "skipped"
    data_id: str | None = None           # TaggedData ID
    content: str = ""
    error: str = ""
    # Verbose fields — populated when SENTINEL_VERBOSE_RESULTS=true.
    # Exposes defence internals; never enable in production.
    planner_prompt: str | None = None    # Claude's raw plan step prompt
    resolved_prompt: str | None = None   # What Qwen actually receives (after spotlighting/tags/sandwich)
    worker_response: str | None = None   # Qwen's raw response (before output scanning)


class ConversationInfo(BaseModel):
    session_id: str
    turn_number: int
    risk_score: float
    action: str                          # "allow", "warn", "block"
    warnings: list[str] = Field(default_factory=list)


class TaskResult(BaseModel):
    task_id: str = ""                    # UUID for event bus correlation
    status: str                          # "success", "blocked", "denied", "refused", "error"
    plan_summary: str = ""
    step_results: list[StepResult] = Field(default_factory=list)
    reason: str = ""
    approval_id: str = ""
    conversation: ConversationInfo | None = None
