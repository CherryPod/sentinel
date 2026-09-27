"""Episodic memory integration for anchor maps."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid

from sentinel.core.context import require_user_id
from sentinel.tools.anchor_allocator._core import AnchorEntry

logger = logging.getLogger(__name__)


async def write_anchor_map(
    path: str,
    anchors: list[AnchorEntry],
    file_hash: str,
    tier: str,
    episodic_store,
    user_id: int | None = None,
) -> None:
    """Write (upsert) an anchor map to episodic memory.

    Creates a minimal parent episodic record, then attaches the anchor
    map as an EpisodicFact.  Uses INSERT ... ON CONFLICT to atomically
    upsert against the idx_anchor_map_unique partial index — no
    search_facts/delete dance required.
    """
    user_id = require_user_id(user_id, "anchor_allocator.write_anchor_map")

    # Create minimal parent record
    try:
        path_hash = hashlib.md5(path.encode(), usedforsecurity=False).hexdigest()[:8]
        record_id = await episodic_store.create(
            session_id=f"anchor-{path_hash}",
            task_id=f"anchor-{path_hash}",
            user_request=f"Anchor allocation for {path}",
            task_status="anchor_allocation",
            plan_summary=f"Anchor map for {path}",
            step_count=0,
            success_count=0,
            file_paths=[path],
            user_id=user_id,
        )
    except Exception as exc:  # catch-all: episodic store best-effort
        logger.warning(
            "anchor_map_record_create_failed",
            extra={
                "event": "memory.record_create_failed",
                "path": path,
                "error": str(exc),
            },
            exc_info=True,
        )
        return

    # Build fact content
    anchor_data = {
        "file_hash": file_hash,
        "anchor_count": len(anchors),
        "default_tier": tier,
        "anchors": [
            {
                "name": a.name,
                "line": a.line,
                "tier": a.tier.name.lower(),
                "has_end": a.has_end,
                "description": a.description,
            }
            for a in anchors
        ],
    }

    fact_id = str(uuid.uuid4())
    content = json.dumps(anchor_data)

    try:
        await episodic_store.upsert_anchor_map(
            fact_id=fact_id,
            record_id=record_id,
            content=content,
            file_path=path,
            user_id=user_id,
        )
        logger.debug(
            "anchor_map_written",
            extra={
                "event": "memory.anchor_map_written",
                "path": path,
                "fact_id": fact_id,
                "file_hash": file_hash,
                "anchor_count": len(anchors),
            },
        )
    except Exception as exc:  # catch-all: episodic store best-effort
        logger.warning(
            "anchor_map_write_failed",
            extra={
                "event": "memory.anchor_map_write_failed",
                "path": path,
                "error": str(exc),
            },
            exc_info=True,
        )


async def read_anchor_map(
    path: str,
    current_hash: str,
    episodic_store,
    user_id: int | None = None,
) -> list[dict] | None:
    """Read anchor map from episodic memory, checking staleness.

    Returns the anchor list if the stored hash matches current_hash,
    None if stale or missing.  Uses exact file_path lookup — not
    full-text search — for reliable retrieval.
    """
    user_id = require_user_id(user_id, "anchor_allocator.read_anchor_map")
    try:
        fact = await episodic_store.get_anchor_map(
            file_path=path,
            user_id=user_id,
        )
    except Exception as exc:  # catch-all: episodic store best-effort
        logger.warning(
            "anchor_map_read_failed",
            extra={
                "event": "memory.anchor_map_read_failed",
                "path": path,
                "error": str(exc),
            },
            exc_info=True,
        )
        return None

    if fact is None:
        return None

    try:
        data = json.loads(fact.content)
    except (json.JSONDecodeError, AttributeError):
        logger.warning(
            "read_anchor_map: malformed anchor data",
            extra={"event": "memory.read_anchor_map.decode_failed"},
            exc_info=True,
        )
        return None

    stored_hash = data.get("file_hash", "")
    if stored_hash != current_hash:
        logger.warning(
            "anchor_map_stale",
            extra={
                "event": "memory.anchor_map_stale",
                "path": path,
                "stored_hash": stored_hash,
                "current_hash": current_hash,
            },
        )
        return None

    logger.debug(
        "anchor_map_fresh",
        extra={
            "event": "memory.anchor_map_fresh",
            "path": path,
            "anchor_count": data.get("anchor_count", 0),
        },
    )
    return data.get("anchors", [])


async def clear_anchor_map(
    path: str,
    episodic_store,
    user_id: int | None = None,
) -> None:
    """Delete the anchor map for a file (used when file is corrupted).

    Uses exact file_path match — not full-text search — to reliably
    find the record.
    """
    user_id = require_user_id(user_id, "anchor_allocator.clear_anchor_map")
    try:
        deleted = await episodic_store.delete_anchor_map(
            file_path=path,
            user_id=user_id,
        )
        if deleted:
            logger.info(
                "anchor_map_cleared",
                extra={"event": "memory.anchor_map_cleared", "path": path},
            )
    except Exception as exc:  # catch-all: anchor map clear best-effort
        logger.warning(
            "anchor_map_clear_failed",
            extra={
                "event": "memory.anchor_map_clear_failed",
                "path": path,
                "error": str(exc),
            },
            exc_info=True,
        )
