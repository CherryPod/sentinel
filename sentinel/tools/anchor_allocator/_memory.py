"""Episodic memory integration for anchor maps."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid

from sentinel.tools.anchor_allocator._core import AnchorEntry

logger = logging.getLogger(__name__)


async def write_anchor_map(
    path: str,
    anchors: list[AnchorEntry],
    file_hash: str,
    tier: str,
    episodic_store,
    user_id: int = 1,
) -> None:
    """Write (upsert) an anchor map to episodic memory.

    Creates a minimal parent episodic record, then attaches the anchor
    map as an EpisodicFact. Existing maps for the same file + user are
    found via search_facts for logging purposes. The DB partial unique
    index (idx_anchor_map_unique) handles upsert at the storage layer.
    """
    from sentinel.memory.episodic import EpisodicFact

    # Check for existing map (for logging)
    try:
        existing = await episodic_store.search_facts(
            query=path,
            fact_type="anchor_map",
            user_id=user_id,
            limit=1,
        )
        if existing:
            logger.debug(
                "anchor_map_upsert path=%s old_fact_id=%s",
                path, existing[0].fact_id,
            )
    except Exception:
        pass  # Non-fatal — proceed with write

    # Create minimal parent record
    try:
        path_hash = hashlib.md5(path.encode()).hexdigest()[:8]
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
    except Exception as exc:
        logger.warning("anchor_map_record_create_failed path=%s error=%s", path, exc)
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

    fact = EpisodicFact(
        fact_id=str(uuid.uuid4()),
        record_id=record_id,
        fact_type="anchor_map",
        content=json.dumps(anchor_data),
        file_path=path,
        created_at="",
        user_id=user_id,
    )

    try:
        await episodic_store.store_facts(record_id, [fact], user_id=user_id)
        logger.debug(
            "anchor_map_written path=%s fact_id=%s file_hash=%s",
            path, fact.fact_id, file_hash,
        )
    except Exception as exc:
        logger.warning("anchor_map_write_failed path=%s error=%s", path, exc)


async def read_anchor_map(
    path: str,
    current_hash: str,
    episodic_store,
    user_id: int = 1,
) -> list[dict] | None:
    """Read anchor map from episodic memory, checking staleness.

    Returns the anchor list if the stored hash matches current_hash,
    None if stale or missing.
    """
    try:
        facts = await episodic_store.search_facts(
            query=path,
            fact_type="anchor_map",
            user_id=user_id,
            limit=1,
        )
    except Exception as exc:
        logger.warning("anchor_map_read_failed path=%s error=%s", path, exc)
        return None

    if not facts:
        return None

    try:
        data = json.loads(facts[0].content)
    except (json.JSONDecodeError, AttributeError):
        return None

    stored_hash = data.get("file_hash", "")
    if stored_hash != current_hash:
        logger.warning(
            "anchor_map_stale path=%s expected=%s actual=%s",
            path, stored_hash, current_hash,
        )
        return None

    logger.debug("anchor_map_fresh path=%s", path)
    return data.get("anchors", [])


async def clear_anchor_map(
    path: str,
    episodic_store,
    user_id: int = 1,
) -> None:
    """Delete the anchor map for a file (used when file is corrupted)."""
    try:
        facts = await episodic_store.search_facts(
            query=path,
            fact_type="anchor_map",
            user_id=user_id,
            limit=1,
        )
        if facts:
            # Delete the parent record — facts cascade via FK
            await episodic_store.delete(facts[0].record_id, user_id=user_id)
            logger.info("anchor_map_cleared path=%s", path)
    except Exception as exc:
        logger.warning("anchor_map_clear_failed path=%s error=%s", path, exc)
