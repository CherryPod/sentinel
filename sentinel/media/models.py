"""Attachment metadata model and validation helpers.

This module defines the data structures for media attachments and the
MIME-type allowlist that controls which file types Sentinel will accept.
The allowlist is intentionally narrow (media + PDF) — expand it as new
processors are added (e.g. add application/vnd.* for office docs).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sentinel.core.decorators import no_audit_log

logger = logging.getLogger(__name__)


_MAX_FILENAME_LEN = 100

# Filename regex matching the existing website tool pattern.
_SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$")
_UNSAFE_CHAR_RE = re.compile(r"[^a-zA-Z0-9._-]")

# MIME types Sentinel will accept.  Intentionally narrow — add types as
# new processors are wired in (e.g. application/vnd.openxmlformats for
# Office docs, text/plain for notes).
MIME_ALLOWLIST: set[str] = {
    # Images
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    # NOTE: image/svg+xml intentionally excluded — SVGs can contain
    # <script> tags and are served with their own MIME type, bypassing
    # the HTML CSP.  Re-add behind a sanitiser if needed.
    "image/bmp",
    "image/tiff",
    # Video
    "video/mp4",
    "video/webm",
    "video/quicktime",
    "video/x-matroska",
    # Audio
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/flac",
    "audio/aac",
    "audio/x-m4a",
    "audio/webm",
    # Documents
    "application/pdf",
}


def is_mime_allowed(mime_type: str) -> bool:
    """Check whether a MIME type is in the accept list."""
    return mime_type.lower().strip() in MIME_ALLOWLIST


@no_audit_log
def sanitise_filename(name: str, fallback_ext: str = ".bin") -> str:
    """Return a safe filename that matches the website tool's regex.

    Strips path components, replaces unsafe characters with hyphens,
    truncates to _MAX_FILENAME_LEN chars, and ensures the name starts
    with an alphanumeric character.
    """
    logger.debug(
        "sanitise_filename called",
        extra={
            "event": "models.sanitise_filename",
            "record_name": name,
            "fallback_ext": fallback_ext,
        },
    )
    # Strip any path components.
    name = os.path.basename(name)

    if not name:
        return f"attachment{fallback_ext}"

    # Replace unsafe characters.
    name = _UNSAFE_CHAR_RE.sub("-", name)

    # Collapse consecutive hyphens.
    name = re.sub(r"-{2,}", "-", name)

    # Ensure starts with alphanumeric.
    if not name[0].isalnum():
        name = "f" + name

    # Truncate (preserve extension if possible).
    if len(name) > _MAX_FILENAME_LEN:
        stem, dot, ext = name.rpartition(".")
        if dot and len(ext) <= 10:
            name = stem[: _MAX_FILENAME_LEN - len(ext) - 1] + "." + ext
        else:
            name = name[:_MAX_FILENAME_LEN]

    return name


@dataclass
class AttachmentMeta:
    """Metadata for a received media attachment.

    This is a lightweight data-transfer object that flows through the
    pipeline.  The actual file bytes live on disk — this just describes
    where and what.
    """

    attachment_id: str
    mime_type: str
    original_filename: str
    file_size: int  # bytes
    source_channel: str  # "signal", "telegram", "email"

    # Filesystem path (set after ingestion writes the file).
    workspace_path: str = ""

    # Safe filename (after sanitisation).  Falls back to original.
    safe_filename: str = ""

    # Optional: channel-specific source ID (signal attachment id,
    # telegram file_id, email Content-ID).
    channel_file_id: str = ""

    # Extra metadata (channel-specific, e.g. telegram caption).
    extra: dict = field(default_factory=dict)

    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )

    # SHA-256 hex digest of file content, set during ingestion.
    content_sha256: str = ""

    def __post_init__(self) -> None:
        if not self.safe_filename:
            self.safe_filename = sanitise_filename(self.original_filename)
