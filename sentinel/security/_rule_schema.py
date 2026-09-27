"""Pydantic models for YAML rule file validation.

All YAML rule files are validated at load time.  If any rule fails
validation (missing id, malformed regex, invalid severity/platform
string), the scanner refuses to start.  Fail-closed — a typo in YAML
is a startup error, not silent broken detection.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, field_validator

from sentinel.security._enums import Phase, Platform, Severity


class SuppressionRef(BaseModel):
    """Reference to a named suppression handler in a rule definition."""

    handler: str
    params: dict[str, Any] | None = None


class RuleDefinition(BaseModel):
    """A single detection rule loaded from YAML.

    ``pattern`` is compiled and validated at load time — malformed regex
    causes a Pydantic validation error.  ``confidence`` defaults to 0.5
    (mid-low) to force rule authors to consciously set high confidence
    for exact-format patterns.
    """

    id: str
    pattern: str
    severity: Severity
    confidence: float = 0.5
    platforms: list[Platform]
    phases: list[Phase]
    tags: list[str] = []
    suppressions: list[SuppressionRef] = []

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        """Verify the pattern compiles as a valid regex."""
        try:
            re.compile(v)
        except re.error as exc:
            msg = f"invalid regex pattern: {exc}"
            raise ValueError(msg) from exc
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is in the valid 0.0–1.0 range."""
        if not 0.0 <= v <= 1.0:
            msg = f"confidence must be 0.0-1.0, got {v}"
            raise ValueError(msg)
        return v


class RuleFile(BaseModel):
    """Top-level schema for a YAML rule file.

    ``version`` is a monotonic integer included in scan results and logs.
    Increment when rules change for FP benchmark traceability.
    """

    scanner: str
    description: str
    version: int = 1
    rules: list[RuleDefinition]
