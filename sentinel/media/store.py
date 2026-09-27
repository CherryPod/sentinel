"""MediaStore — Postgres CRUD for the media_attachments table.

Supports in-memory fallback (pool=None) for tests and environments
without Postgres.  In-memory mode mimics RLS by filtering on
current_user_id.
"""

from __future__ import annotations

import json
import logging

from sentinel.core.context import require_user_id
from sentinel.core.decorators import no_audit_log
from sentinel.media.models import AttachmentMeta

logger = logging.getLogger(__name__)


class MediaStore:
    """Persistent storage for attachment metadata."""

    def __init__(self, pool=None):
        self._pool = pool
        # In-memory fallback: dict keyed by (attachment_id, user_id).
        self._mem: dict[tuple[str, int], dict] = {} if pool is None else None

    @property
    def _in_memory(self) -> bool:
        return self._mem is not None

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    async def save(self, meta: AttachmentMeta, user_id: int | None = None) -> None:
        """Persist attachment metadata."""
        uid = require_user_id(user_id, "MediaStore.save")
        logger.debug(
            "media_store save",
            extra={
                "event": "media.store_save",
                "attachment_id": meta.attachment_id,
                "mime_type": meta.mime_type,
                "file_size": meta.file_size,
                "source_channel": meta.source_channel,
                "user_id": uid,
            },
        )

        row = {
            "attachment_id": meta.attachment_id,
            "user_id": uid,
            "mime_type": meta.mime_type,
            "original_filename": meta.original_filename,
            "safe_filename": meta.safe_filename,
            "file_size": meta.file_size,
            "file_path": meta.workspace_path,
            "content_sha256": meta.content_sha256,
            "source_channel": meta.source_channel,
            "channel_file_id": meta.channel_file_id,
            "metadata": meta.extra,
            "created_at": meta.timestamp,
        }

        if self._in_memory:
            self._mem[(meta.attachment_id, uid)] = row
            return

        async with self._pool.acquire() as conn:
            # Q4-F19 Coord review follow-up: RETURNING + WARN-on-None detects
            # cross-user attachment_id collisions that the ON CONFLICT WHERE
            # clause filters out. Caller still sees success from save() to
            # preserve the "silent no-op" semantic (Q4 fail-closed), but an
            # audit event fires so operators can spot collision anomalies.
            row = await conn.fetchrow(
                "INSERT INTO media_attachments "
                "(attachment_id, user_id, mime_type, original_filename, "
                " safe_filename, file_size, file_path, content_sha256, "
                " source_channel, channel_file_id, metadata, created_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12) "
                "ON CONFLICT (attachment_id) DO UPDATE SET "
                "file_path = EXCLUDED.file_path, "
                "metadata = EXCLUDED.metadata "
                # Q4-F19: silently no-op cross-user collisions on the UUID PK
                # so a stolen/guessed attachment_id can't overwrite another
                # user's metadata. Composite (attachment_id, user_id) PK is
                # the structural cure (umbrella Q4-U2).
                "WHERE media_attachments.user_id = EXCLUDED.user_id "
                "RETURNING attachment_id",
                meta.attachment_id,
                uid,
                meta.mime_type,
                meta.original_filename,
                meta.safe_filename,
                meta.file_size,
                meta.workspace_path,
                meta.content_sha256,
                meta.source_channel,
                meta.channel_file_id,
                json.dumps(meta.extra),
                meta.timestamp,
            )
            if row is None:
                # Cross-user attachment_id collision blocked by the ON CONFLICT
                # WHERE clause. No row written under the caller's user_id.
                # Caller sees save() return normally (Q4 fail-closed semantic),
                # but the collision is surfaced for audit.
                logger.warning(
                    "Media store attachment_id collision blocked — cross-user or no-op",
                    extra={
                        "event": "media.store_conflict_blocked",
                        "attachment_id": meta.attachment_id,
                        "user_id": uid,
                    },
                )

    # ------------------------------------------------------------------
    # Get
    # ------------------------------------------------------------------

    async def get(
        self,
        attachment_id: str,
        user_id: int | None = None,
    ) -> dict | None:
        """Retrieve a single attachment by ID (user-scoped)."""
        uid = require_user_id(user_id, "MediaStore.get")
        logger.debug(
            "media_store get",
            extra={
                "event": "media.store_get",
                "attachment_id": attachment_id,
                "user_id": uid,
            },
        )

        if self._in_memory:
            return self._mem.get((attachment_id, uid))

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM media_attachments "
                "WHERE attachment_id = $1 AND user_id = $2",
                attachment_id,
                uid,
            )
            return dict(row) if row else None

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    @no_audit_log
    async def list_recent(
        self,
        limit: int = 20,
        mime_prefix: str = "",
        user_id: int | None = None,
    ) -> list[dict]:
        """List recent attachments for the current user.

        Optional mime_prefix filters by type (e.g. "image/", "video/").
        """
        uid = require_user_id(user_id, "MediaStore.list_recent")
        logger.debug(
            "media_store list_recent",
            extra={
                "event": "media.store_list",
                "user_id": uid,
                "mime_prefix": mime_prefix,
                "limit_count": limit,
            },
        )

        if self._in_memory:
            rows = [
                v
                for (_, u), v in self._mem.items()
                if u == uid
                and (not mime_prefix or v["mime_type"].startswith(mime_prefix))
            ]
            rows.sort(key=lambda r: r["created_at"], reverse=True)
            return rows[:limit]

        async with self._pool.acquire() as conn:
            if mime_prefix:
                rows = await conn.fetch(
                    "SELECT * FROM media_attachments "
                    "WHERE user_id = $1 AND mime_type LIKE $2 "
                    "ORDER BY created_at DESC LIMIT $3",
                    uid,
                    mime_prefix + "%",
                    limit,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM media_attachments "
                    "WHERE user_id = $1 "
                    "ORDER BY created_at DESC LIMIT $2",
                    uid,
                    limit,
                )
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def delete(
        self,
        attachment_id: str,
        user_id: int | None = None,
    ) -> bool:
        """Delete attachment metadata.  Returns True if a row was removed."""
        uid = require_user_id(user_id, "MediaStore.delete")
        logger.debug(
            "media_store delete",
            extra={
                "event": "media.store_delete",
                "attachment_id": attachment_id,
                "user_id": uid,
            },
        )

        if self._in_memory:
            key = (attachment_id, uid)
            if key in self._mem:
                del self._mem[key]
                return True
            return False

        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM media_attachments "
                "WHERE attachment_id = $1 AND user_id = $2",
                attachment_id,
                uid,
            )
            return result == "DELETE 1"
