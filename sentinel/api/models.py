"""Pydantic request models and input validation for the Sentinel API.

All models use shared validation via _normalize_text() to enforce:
- NFC unicode normalisation
- Consecutive newline collapse
- Length bounds
- Non-empty after stripping
"""

import logging
import re
import unicodedata

from pydantic import BaseModel, field_validator

from sentinel.core.config import settings

logger = logging.getLogger(__name__)


# ── Input validation constants ────────────────────────────────────
MAX_TEXT_LENGTH = 50_000
MIN_TASK_REQUEST_LENGTH = 3
MAX_REASON_LENGTH = 1_000
MIN_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 7_200
MIN_SECRET_LENGTH = 16
MAX_ROUTINE_ITERATIONS = 50
_CONSECUTIVE_NEWLINES = re.compile(r"\n{3,}")

# Valid source values for task requests. Unknown values default to "api"
# to prevent session-key rotation (different source = different session = reset risk scores).
_VALID_TASK_SOURCES = frozenset(
    {"api", "signal", "telegram", "webhook", "websocket", "mcp", "a2a"}
)


def _normalize_text(
    v: str,
    *,
    min_length: int = 1,
    max_length: int = MAX_TEXT_LENGTH,
    field_name: str = "Text",
) -> str:
    """Shared validation: strip, NFC normalize, collapse newlines, enforce length."""
    logger.debug(
        "_normalize_text called",
        extra={"event": "models._normalize_text", "v_length": len(v)},
    )
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
            raise ValueError(
                f"Untrusted data too long (maximum {MAX_TEXT_LENGTH:,} characters)"
            )
        return v


class TaskRequest(BaseModel):
    request: str
    source: str = "api"
    session_id: str | None = None  # Accepted but ignored — server assigns sessions

    @field_validator("request")
    @classmethod
    def validate_request(cls, v: str) -> str:
        return _normalize_text(
            v, min_length=MIN_TASK_REQUEST_LENGTH, field_name="Request"
        )

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        # Q3-F3: always enforce the allowlist so a caller cannot craft a prefix
        # that collides with another transport's source_key shape. Benchmark
        # harnesses need unique sessions per prompt, so non-allowlisted values
        # in benchmark mode are namespaced under "benchmark:" rather than passed
        # through raw — preserves stress-test uniqueness without reopening the
        # attacker-controlled prefix surface.
        if v in _VALID_TASK_SOURCES:
            return v
        if settings.benchmark_mode:
            return f"benchmark:{v}"
        return "api"


class LoopRequest(BaseModel):
    request: str
    max_iterations: int = 5
    timeout_seconds: int = 3600

    @field_validator("request")
    @classmethod
    def validate_request(cls, v: str) -> str:
        return _normalize_text(
            v, min_length=MIN_TASK_REQUEST_LENGTH, field_name="Request"
        )

    @field_validator("max_iterations")
    @classmethod
    def validate_max_iterations(cls, v: int) -> int:
        if v < 1 or v > settings.loop_max_per_request:
            raise ValueError(
                f"max_iterations must be 1-{settings.loop_max_per_request}"
            )
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v < MIN_TIMEOUT_SECONDS or v > MAX_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout_seconds must be {MIN_TIMEOUT_SECONDS}-{MAX_TIMEOUT_SECONDS}"
            )
        return v


class ApprovalDecision(BaseModel):
    granted: bool
    reason: str = ""

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        if len(v) > MAX_REASON_LENGTH:
            raise ValueError(
                f"Reason too long (maximum {MAX_REASON_LENGTH:,} characters)"
            )
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
        logger.debug(
            "validate_action_config called",
            extra={
                "event": "models.validate_action_config",
                "v_len": len(v) if hasattr(v, "__len__") else 0,
            },
        )
        if "prompt" not in v or not v["prompt"]:
            raise ValueError("action_config must contain a non-empty 'prompt' key")
        # Finding #9: Validate max_iterations at creation time
        max_iter = v.get("max_iterations")
        if max_iter is not None:
            if (
                not isinstance(max_iter, int)
                or max_iter < 1
                or max_iter > MAX_ROUTINE_ITERATIONS
            ):
                raise ValueError(
                    f"max_iterations must be an integer between 1 and {MAX_ROUTINE_ITERATIONS}"
                )
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
                if (
                    not isinstance(max_iter, int)
                    or max_iter < 1
                    or max_iter > MAX_ROUTINE_ITERATIONS
                ):
                    raise ValueError(
                        f"max_iterations must be an integer between 1 and {MAX_ROUTINE_ITERATIONS}"
                    )
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
        if len(v) < MIN_SECRET_LENGTH:
            raise ValueError(f"Secret must be at least {MIN_SECRET_LENGTH} characters")
        return v
