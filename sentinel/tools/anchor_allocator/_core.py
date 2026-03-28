"""Core data models and utilities for the anchor allocator."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class AnchorTier(Enum):
    """Granularity tiers for anchor placement."""

    SECTION = 1   # head, body, style blocks, import blocks
    BLOCK = 2     # functions, classes, elements with IDs, media queries
    DETAIL = 3    # individual CSS rules, inner blocks

    @classmethod
    def from_string(cls, value: str) -> AnchorTier:
        """Convert string to AnchorTier, raising ValueError if invalid."""
        try:
            return cls[value.upper()]
        except KeyError:
            valid = ", ".join(t.name.lower() for t in cls)
            raise ValueError(f"Invalid tier '{value}'. Valid: {valid}")


@dataclass
class AnchorEntry:
    """A single anchor point in a file."""

    name: str
    line: int
    tier: AnchorTier
    description: str
    has_end: bool
    end_line: int | None = None  # Last line of the block (for inserting end markers)

    @property
    def end_name(self) -> str | None:
        """Return the end-pair anchor name, or None if no end pair."""
        return f"{self.name}-end" if self.has_end else None


@dataclass
class AnchorResult:
    """Result of anchor allocation on a file."""

    content: str
    changed: bool = False
    anchors: list[AnchorEntry] = field(default_factory=list)
    file_hash: str = ""
    parse_failed: bool = False
    error: str | None = None


# Extension -> comment format mapping
_MARKER_FORMATS: dict[str, str] = {
    ".html": "<!-- anchor: {name} -->",
    ".htm":  "<!-- anchor: {name} -->",
    ".py":   "# anchor: {name}",
    ".sh":   "# anchor: {name}",
    ".bash": "# anchor: {name}",
    ".yaml": "# anchor: {name}",
    ".yml":  "# anchor: {name}",
    ".toml": "# anchor: {name}",
    ".js":   "// anchor: {name}",
    ".ts":   "// anchor: {name}",
    ".css":  "/* anchor: {name} */",
}


def build_marker(path: str, name: str) -> str | None:
    """Build the full anchor marker comment for a given file type.

    Returns None for file types that don't support comments (JSON).
    """
    ext = Path(path).suffix.lower()
    if ext == ".json":
        return None
    fmt = _MARKER_FORMATS.get(ext, "# anchor: {name}")
    return fmt.format(name=name)


def content_hash(content: str) -> str:
    """SHA-256 hash of file content for staleness detection."""
    return hashlib.sha256(content.encode()).hexdigest()
