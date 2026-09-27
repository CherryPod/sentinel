"""Security audit event definitions and category registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field, field_validator

_VALID_OUTCOMES = frozenset(
    {
        "CLEAN",
        "BLOCKED",
        "DEGRADED",
        "ERROR",
        "SKIPPED",
        "SUCCESS",
        "FAILED",
        "BYPASSED",
        "APPROVED",
        "DENIED",
        "EXPIRED",
        "LOCKED",
        "ALLOWED",
        "WARNED",
        "TIMEOUT",
    }
)

_VALID_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH"})


@dataclass(frozen=True, slots=True)
class SecurityAuditEvent:
    """Immutable audit record constructed by category emitters.

    Top-level keys in ``details`` MUST be constant string literals registered
    in ``tests/test_audit_details_keys_drift.py::KNOWN_DETAILS_KEYS``.  Keys
    are caller-controlled identifiers exposed to both runtime sinks: the DB
    happy path (``security_audit_log.details`` JSONB column, GIN-indexed,
    queryable by operators with DB-read access) and the F2 fallback path
    (``audit/emitter.py::_write_to_file_fallback`` redacts values but not
    keys; ``audit_record`` is JSON-serialised into the rotated
    ``audit-YYYY-MM-DD.jsonl`` file).  Values may be untrusted and are
    redacted by the F2 fallback.
    """

    event_type: str
    source_component: str
    outcome: str
    severity: str = "INFO"
    action_taken: str | None = None
    duration_ms: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def event_category(self) -> str:
        return self.event_type.split(".", maxsplit=1)[0]

    def __post_init__(self) -> None:
        if "." not in self.event_type:
            msg = f"event_type must be dot-separated (got {self.event_type!r})"
            raise ValueError(msg)
        if self.severity not in _VALID_SEVERITIES:
            msg = f"severity must be one of {_VALID_SEVERITIES} (got {self.severity!r})"
            raise ValueError(msg)
        if self.outcome not in _VALID_OUTCOMES:
            msg = f"outcome must be one of {_VALID_OUTCOMES} (got {self.outcome!r})"
            raise ValueError(msg)


class AuditCategoryConfig(BaseModel):
    """Per-category audit configuration."""

    enabled: bool = True
    capture_level: str = Field(default="full")
    retention_days: int = Field(default=90, ge=1)

    @field_validator("capture_level")
    @classmethod
    def validate_capture_level(cls, value: str) -> str:
        allowed = {"full", "outcomes_only", "violations_only", "off"}
        if value not in allowed:
            msg = f"capture_level must be one of {allowed}"
            raise ValueError(msg)
        return value


CATEGORY_DEFAULTS: dict[str, AuditCategoryConfig] = {
    "scan": AuditCategoryConfig(retention_days=90),
    "auth": AuditCategoryConfig(retention_days=365),
    "trust": AuditCategoryConfig(retention_days=90),
    "approval": AuditCategoryConfig(retention_days=365),
    "conversation": AuditCategoryConfig(retention_days=90),
    "tool": AuditCategoryConfig(retention_days=90),
    "access": AuditCategoryConfig(retention_days=90),
    "system": AuditCategoryConfig(retention_days=365),
    "crypto": AuditCategoryConfig(retention_days=365),
    "routine": AuditCategoryConfig(retention_days=90),
}
