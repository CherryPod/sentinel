"""AttachmentIngester — shared logic for receiving media from any channel.

Responsible for:
- MIME validation against the allowlist
- File size enforcement
- Saving bytes to the user's workspace (media/inbox/{id}/{filename})
- Recording metadata in MediaStore
- Computing content hashes for provenance

This module is channel-agnostic.  Each channel adapter calls ingest()
or ingest_from_path() with the raw data and metadata.  Downstream
consumers (website tool, media_process, etc.) receive an AttachmentMeta
with a workspace_path they can reference.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import uuid

from sentinel.core.context import current_user_id
from sentinel.media.models import AttachmentMeta, is_mime_allowed, sanitise_filename
from sentinel.media.store import MediaStore

logger = logging.getLogger(__name__)

_MAX_FILE_BYTES_DEFAULT = 52_428_800  # 50 MB
_HASH_CHUNK_SIZE = 65_536  # 64 KB


class AttachmentIngester:
    """Receives media from channels and saves to user workspace."""

    def __init__(
        self,
        workspace_root: str,
        media_store: MediaStore,
        max_file_bytes: int = _MAX_FILE_BYTES_DEFAULT,
    ):
        self._workspace_root = workspace_root
        self._store = media_store
        self._max_file_bytes = max_file_bytes

    def _user_media_dir(self, user_id: int, attachment_id: str) -> str:
        """Build the target directory for an attachment."""
        return os.path.join(
            self._workspace_root,
            str(user_id),
            "media",
            "inbox",
            attachment_id,
        )

    async def ingest(
        self,
        data: bytes,
        mime_type: str,
        original_filename: str,
        source_channel: str,
        channel_file_id: str = "",
        extra: dict | None = None,
    ) -> AttachmentMeta:
        """Ingest raw bytes into the user's workspace.

        Validates MIME type and size, writes to disk, records metadata.
        Returns AttachmentMeta with workspace_path populated.
        """
        uid = current_user_id.get()
        if uid == 0:
            raise RuntimeError("media.ingestion: ingest requires user context")
        attachment_id = str(uuid.uuid4())

        logger.debug(
            "attachment ingest start",
            extra={
                "event": "attachment.ingest_start",
                "attachment_id": attachment_id,
                "mime_type": mime_type,
                "file_size": len(data),
                "original_filename": original_filename,
                "source_channel": source_channel,
                "user_id": uid,
            },
        )

        # Validate MIME type.
        if not is_mime_allowed(mime_type):
            logger.warning(
                "attachment rejected: MIME type not allowed",
                extra={
                    "event": "attachment.mime_rejected",
                    "mime_type": mime_type,
                    "original_filename": original_filename,
                    "source_channel": source_channel,
                    "user_id": uid,
                },
            )
            raise ValueError(
                f"MIME type not allowed: {mime_type}. "
                f"Accepted types: images, video, audio, PDF."
            )
        logger.debug(
            "ingest: not_is_mime_allowed_mime_type_passed",
            extra={
                "event": "attachment.mime_rejected.passed",
                "reason": "not_is_mime_allowed_mime_type_passed",
            },
        )  # auto:neg

        # Validate size.
        if len(data) > self._max_file_bytes:
            logger.warning(
                "attachment rejected: file too large",
                extra={
                    "event": "attachment.size_rejected",
                    "file_size": len(data),
                    "max_bytes": self._max_file_bytes,
                    "original_filename": original_filename,
                    "user_id": uid,
                },
            )
            raise ValueError(
                f"File size ({len(data)} bytes) exceeds maximum "
                f"({self._max_file_bytes} bytes)."
            )

        # Sanitise filename and build target path.
        safe_name = sanitise_filename(original_filename)
        target_dir = self._user_media_dir(uid, attachment_id)
        os.makedirs(target_dir, exist_ok=True)
        target_path = os.path.join(target_dir, safe_name)

        # Write binary file.
        with open(target_path, "wb") as f:
            f.write(data)

        content_hash = hashlib.sha256(data).hexdigest()

        logger.info(
            "attachment ingested",
            extra={
                "event": "attachment.ingested",
                "attachment_id": attachment_id,
                "mime_type": mime_type,
                "file_size": len(data),
                "safe_filename": safe_name,
                "target_path": target_path,
                "content_sha256_prefix": content_hash[:16],
                "source_channel": source_channel,
                "user_id": uid,
            },
        )

        meta = AttachmentMeta(
            attachment_id=attachment_id,
            mime_type=mime_type,
            original_filename=original_filename,
            safe_filename=safe_name,
            file_size=len(data),
            source_channel=source_channel,
            channel_file_id=channel_file_id,
            workspace_path=target_path,
            extra=extra or {},
        )
        meta.content_sha256 = content_hash

        # Persist metadata.
        await self._store.save(meta)

        return meta

    async def ingest_from_path(
        self,
        source_path: str,
        mime_type: str,
        original_filename: str,
        source_channel: str,
        channel_file_id: str = "",
        extra: dict | None = None,
    ) -> AttachmentMeta:
        """Ingest a file by copying from a source path.

        Used when the channel daemon (e.g. signal-cli) has already saved
        the file to disk.  Copies (not moves) so the source is preserved.
        """
        uid = current_user_id.get()
        if uid == 0:
            raise RuntimeError(
                "media.ingestion: ingest_from_path requires user context"
            )
        attachment_id = str(uuid.uuid4())

        logger.debug(
            "attachment ingest_from_path start",
            extra={
                "event": "attachment.ingest_path_start",
                "attachment_id": attachment_id,
                "source_path": source_path,
                "mime_type": mime_type,
                "source_channel": source_channel,
                "user_id": uid,
            },
        )

        if not os.path.isfile(source_path):
            logger.warning(
                "attachment rejected (path): source file not found",
                extra={
                    "event": "attachment.source_not_found",
                    "source_path": source_path,
                    "source_channel": source_channel,
                    "user_id": uid,
                },
            )
            raise FileNotFoundError(f"Source file not found: {source_path}")
        logger.debug(
            "ingest_from_path: not_isfile_source_path_passed",
            extra={
                "event": "attachment.source_not_found.passed",
                "reason": "not_isfile_source_path_passed",
            },
        )  # auto:neg

        file_size = os.path.getsize(source_path)

        # Validate MIME type.
        if not is_mime_allowed(mime_type):
            logger.warning(
                "attachment rejected (path): MIME type not allowed",
                extra={
                    "event": "attachment.mime_rejected",
                    "mime_type": mime_type,
                    "original_filename": original_filename,
                    "source_channel": source_channel,
                    "user_id": uid,
                },
            )
            raise ValueError(
                f"MIME type not allowed: {mime_type}. "
                f"Accepted types: images, video, audio, PDF."
            )
        logger.debug(
            "ingest_from_path: not_is_mime_allowed_mime_type_passed",
            extra={
                "event": "attachment.mime_rejected.passed",
                "reason": "not_is_mime_allowed_mime_type_passed",
            },
        )  # auto:neg

        # Validate size.
        if file_size > self._max_file_bytes:
            logger.warning(
                "attachment rejected (path): file too large",
                extra={
                    "event": "attachment.size_rejected",
                    "file_size": file_size,
                    "max_bytes": self._max_file_bytes,
                    "original_filename": original_filename,
                    "user_id": uid,
                },
            )
            raise ValueError(
                f"File size ({file_size} bytes) exceeds maximum "
                f"({self._max_file_bytes} bytes)."
            )

        # Sanitise filename and build target path.
        safe_name = sanitise_filename(original_filename)
        target_dir = self._user_media_dir(uid, attachment_id)
        os.makedirs(target_dir, exist_ok=True)
        target_path = os.path.join(target_dir, safe_name)

        # Copy file (preserves source for signal-cli's own management).
        shutil.copy2(source_path, target_path)

        # Compute hash from the copied file.
        sha = hashlib.sha256()
        with open(target_path, "rb") as f:
            for chunk in iter(lambda: f.read(_HASH_CHUNK_SIZE), b""):
                sha.update(chunk)
        content_hash = sha.hexdigest()

        logger.info(
            "attachment ingested from path",
            extra={
                "event": "attachment.ingested_from_path",
                "attachment_id": attachment_id,
                "mime_type": mime_type,
                "file_size": file_size,
                "safe_filename": safe_name,
                "target_path": target_path,
                "source_path": source_path,
                "content_sha256_prefix": content_hash[:16],
                "source_channel": source_channel,
                "user_id": uid,
            },
        )

        meta = AttachmentMeta(
            attachment_id=attachment_id,
            mime_type=mime_type,
            original_filename=original_filename,
            safe_filename=safe_name,
            file_size=file_size,
            source_channel=source_channel,
            channel_file_id=channel_file_id,
            workspace_path=target_path,
            extra=extra or {},
        )
        meta.content_sha256 = content_hash

        # Persist metadata.
        await self._store.save(meta)

        return meta
