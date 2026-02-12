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
