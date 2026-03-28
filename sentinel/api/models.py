"""Pydantic request models and input validation for the Sentinel API.

All models use shared validation via _normalize_text() to enforce:
- NFC unicode normalisation
- Consecutive newline collapse
- Length bounds
- Non-empty after stripping
"""

import re
import unicodedata

from pydantic import BaseModel, field_validator

from sentinel.core.config import settings

# ── Input validation constants ────────────────────────────────────
MAX_TEXT_LENGTH = 50_000
MIN_TASK_REQUEST_LENGTH = 3
MAX_REASON_LENGTH = 1_000
_CONSECUTIVE_NEWLINES = re.compile(r"\n{3,}")

# Valid source values for task requests. Unknown values default to "api"
# to prevent session-key rotation (different source = different session = reset risk scores).
_VALID_TASK_SOURCES = frozenset({"api", "signal", "telegram", "webhook", "websocket", "mcp", "a2a"})


def _normalize_text(v: str, *, min_length: int = 1, max_length: int = MAX_TEXT_LENGTH, field_name: str = "Text") -> str:
    """Shared validation: strip, NFC normalize, collapse newlines, enforce length."""
    v = v.strip()
    v = unicodedata.normalize("NFC", v)
    v = _CONSECUTIVE_NEWLINES.sub("\n\n", v)
    if not v:
        raise ValueError(f"{field_name} must not be empty")
    if len(v) < min_length:
        raise ValueError(f"{field_name} too short (minimum {min_length} characters)")
    if len(v) > max_length:
        raise ValueError(f"{field_name} too long (maximum {max_length:,} characters)")
    return v


class ScanRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")


class ProcessRequest(BaseModel):
    text: str
    untrusted_data: str | None = None

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")

    @field_validator("untrusted_data")
    @classmethod
    def validate_untrusted_data(cls, v: str | None) -> str | None:
        if v is None:
            return v
        # No minimum — can be empty string if explicitly provided, but enforce max
        v = unicodedata.normalize("NFC", v)
        if len(v) > MAX_TEXT_LENGTH:
            raise ValueError(f"Untrusted data too long (maximum {MAX_TEXT_LENGTH:,} characters)")
        return v


class TaskRequest(BaseModel):
    request: str
    source: str = "api"
    session_id: str | None = None  # Accepted but ignored — server assigns sessions

    @field_validator("request")
    @classmethod
    def validate_request(cls, v: str) -> str:
        return _normalize_text(v, min_length=MIN_TASK_REQUEST_LENGTH, field_name="Request")

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        # In benchmark mode, allow arbitrary source values so the stress test
        # can create unique sessions per prompt (bypasses H-003 restriction).
        if settings.benchmark_mode:
            return v
        if v not in _VALID_TASK_SOURCES:
            return "api"
        return v


class ApprovalDecision(BaseModel):
    granted: bool
    reason: str = ""

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        if len(v) > MAX_REASON_LENGTH:
            raise ValueError(f"Reason too long (maximum {MAX_REASON_LENGTH:,} characters)")
        return v


class MemoryStoreRequest(BaseModel):
    text: str
    source: str = ""
    metadata: dict | None = None

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")


class CreateRoutineRequest(BaseModel):
    name: str
    trigger_type: str
    trigger_config: dict
    action_config: dict
    description: str = ""
    enabled: bool = True
    cooldown_s: int = 0

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, max_length=200, field_name="Name")

    @field_validator("trigger_type")
    @classmethod
    def validate_trigger_type(cls, v: str) -> str:
        if v not in ("cron", "event", "interval"):
            raise ValueError("trigger_type must be 'cron', 'event', or 'interval'")
        return v

    @field_validator("action_config")
    @classmethod
    def validate_action_config(cls, v: dict) -> dict:
        if "prompt" not in v or not v["prompt"]:
            raise ValueError("action_config must contain a non-empty 'prompt' key")
        # Finding #9: Validate max_iterations at creation time
        max_iter = v.get("max_iterations")
        if max_iter is not None:
            if not isinstance(max_iter, int) or max_iter < 1 or max_iter > 50:
                raise ValueError("max_iterations must be an integer between 1 and 50")
        # Finding #1: Validate approval_mode values
        approval = v.get("approval_mode")
        if approval is not None and approval not in ("auto", "full"):
            raise ValueError("approval_mode must be 'auto' or 'full'")
        return v


class UpdateRoutineRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    trigger_type: str | None = None
    trigger_config: dict | None = None
    action_config: dict | None = None
    enabled: bool | None = None
    cooldown_s: int | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            return _normalize_text(v, min_length=1, max_length=200, field_name="Name")
        return v

    @field_validator("trigger_type")
    @classmethod
    def validate_trigger_type(cls, v: str | None) -> str | None:
        if v is not None and v not in ("cron", "event", "interval"):
            raise ValueError("trigger_type must be 'cron', 'event', or 'interval'")
        return v

    @field_validator("action_config")
    @classmethod
    def validate_action_config(cls, v: dict | None) -> dict | None:
        if v is not None:
            if "prompt" not in v or not v["prompt"]:
                raise ValueError("action_config must contain a non-empty 'prompt' key")
            # Finding #9: Validate max_iterations at update time
            max_iter = v.get("max_iterations")
            if max_iter is not None:
                if not isinstance(max_iter, int) or max_iter < 1 or max_iter > 50:
                    raise ValueError("max_iterations must be an integer between 1 and 50")
            # Finding #1: Validate approval_mode values
            approval = v.get("approval_mode")
            if approval is not None and approval not in ("auto", "full"):
                raise ValueError("approval_mode must be 'auto' or 'full'")
        return v


class RegisterWebhookRequest(BaseModel):
    name: str
    secret: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, max_length=200, field_name="Name")

    @field_validator("secret")
    @classmethod
    def validate_secret(cls, v: str) -> str:
        if len(v) < 16:
            raise ValueError("Secret must be at least 16 characters")
        return v
