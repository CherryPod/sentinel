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
    SANDBOX = "sandbox"


class OutputDestination(str, Enum):
    DISPLAY = "display"      # Output goes to human (UI, Signal, API response)
    EXECUTION = "execution"  # Output feeds into a downstream tool_call


class PolicyResult(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"


class TaskStatus(str, Enum):
    """Task-level outcome status for F1 enriched history."""
    SUCCESS = "success"
    PARTIAL = "partial"
    SCAN_BLOCKED = "scan_blocked"
    WORKER_ERROR = "worker_error"
    EXECUTION_ERROR = "execution_error"
    PLANNER_ERROR = "planner_error"
    REFUSED = "refused"
    DENIED = "denied"
    TIMEOUT = "timeout"
    LOCKED = "locked"


class StepStatus(str, Enum):
    """Step-level outcome status for F1 enriched history."""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    ERROR = "error"
    SKIPPED = "skipped"
    SCAN_BLOCKED = "scan_blocked"
    TRUST_BLOCKED = "trust_blocked"
    FORMAT_ERROR = "format_error"


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
    degraded: bool = False  # F-004: True when scanner skipped due to unavailable model


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
    description: str = ""
    prompt: str | None = None            # For llm_task
    tool: str | None = None              # For tool_call
    args: dict = Field(default_factory=dict)
    output_var: str | None = None        # "$var_name" to store result
    expects_code: bool = False
    input_vars: list[str] = Field(default_factory=list)
    output_format: str | None = None  # "json", "tagged", or None (freeform)
    # D5: Plan-policy constraints (TL4+, tool_call steps only)
    # None = no constraints, use legacy scanning (backward compat)
    # []   = explicitly no commands/paths allowed (blocks everything)
    allowed_commands: list[str] | None = None
    allowed_paths: list[str] | None = None
    # F3: Worker-side context — planner sets this to inject prior worker turn
    # summaries into the worker prompt for debugging/refinement steps
    include_worker_history: bool = False
    # Dynamic replanning: pause execution after this step and call the planner
    # again with results, so it can plan remaining steps with actual data
    replan_after: bool = False


class Plan(BaseModel):
    plan_summary: str
    steps: list[PlanStep]
    continuation: bool = False  # True when this plan continues a prior replan phase


class StepResult(BaseModel):
    step_id: str
    status: str                          # "success", "soft_failed", "blocked", "error", "skipped"
    data_id: str | None = None           # TaggedData ID
    content: str = ""
    error: str = ""
    # Per-step token usage from the worker LLM (Ollama/Qwen)
    worker_usage: dict | None = None
    # Verbose fields — populated when SENTINEL_VERBOSE_RESULTS=true.
    # Exposes defence internals; never enable in production.
    planner_prompt: str | None = None    # Claude's raw plan step prompt
    resolved_prompt: str | None = None   # What Qwen actually receives (after spotlighting/tags/sandwich)
    worker_response: str | None = None   # Qwen's raw response (before output scanning)
    # R7: Quality gate warnings — populated after code extraction on every llm_task step.
    # Empty list means no quality issues. Never None (always initialised).
    quality_warnings: list[str] = Field(default_factory=list)


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
    response: str = ""                   # Fast-path response text (router)
    approval_id: str = ""
    conversation: ConversationInfo | None = None
    # Per-task token usage from the planner (Claude API)
    planner_usage: dict | None = None
    # F1: Structured step outcome metadata for enriched planner history
    step_outcomes: list[dict] = Field(default_factory=list)
    # Dynamic replanning: number of replan calls made during execution
    replan_count: int = 0
