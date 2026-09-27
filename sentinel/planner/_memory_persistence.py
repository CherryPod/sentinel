"""Memory persistence — auto-store and pre-pruning flush.

Best-effort persistence of task summaries and pruned conversation turns
to the MemoryStore. Called by orchestrator.py after task completion and
before turn pruning.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.memory.chunks import MemoryStore
    from sentinel.worker.base import EmbeddingBase

logger = logging.getLogger(__name__)


async def auto_store_memory(
    user_request: str,
    plan_summary: str,
    memory_store: MemoryStore,
    embedding_client: EmbeddingBase | None,
) -> None:
    """Store a brief summary of a completed task in persistent memory.

    The summary is the user's request + the plan summary — not a full
    conversation replay. Keeps chunks small and useful for future context.
    """
    logger.debug(
        "auto_store_memory called",
        extra={
            "event": "auto.store_memory_entry",
            "request_len": len(user_request) if user_request else 0,
            "summary_len": len(plan_summary) if plan_summary else 0,
        },
    )
    summary = f"Task: {user_request}\nResult: {plan_summary}"
    try:
        # Store without embedding — the enriched episodic pipeline
        # (orchestrator._store_episodic_record) handles embeddings with
        # richer step-level data. Auto-memory stays for FTS keyword fallback.
        await memory_store.store(
            content=summary,
            source="conversation",
            metadata={"auto": True},
        )
        logger.info(
            "Auto-memory stored",
            extra={
                "event": "auto.memory_stored",
                "summary_length": len(summary),
            },
        )
    except Exception as exc:  # catch-all: auto-memory best-effort
        # Auto-memory is best-effort — never fail the task because of it
        logger.warning(
            "Auto-memory storage failed",
            extra={
                "event": "auto.memory_failed",
                "error": str(exc),
                "error_category": "memory_store",
            },
            exc_info=True,
        )


async def flush_pruned_turns(
    session_id: str,
    pruned_turns: list[dict],
    memory_store: MemoryStore | None,
) -> None:
    """Persist a summary of pruned turns to MemoryStore.

    Source: system:session_prune (protected from user deletion).
    Deduplication: check metadata for existing flush of same session+range.
    """
    logger.debug(
        "flush_pruned_turns called",
        extra={
            "event": "flush.pruned_turns_entry",
            "session_id": session_id,
            "pruned_count": len(pruned_turns) if pruned_turns else 0,
            "has_memory_store": memory_store is not None,
        },
    )
    if not pruned_turns or memory_store is None:
        logger.debug(
            "flush_pruned_turns skipped — no pruned_turns or no memory_store",
            extra={
                "event": "flush.pruned_turns_skip",
                "has_pruned_turns": bool(pruned_turns),
                "has_memory_store": memory_store is not None,
            },
        )
        return

    first_turn = pruned_turns[0].get("turn", "?")
    last_turn = pruned_turns[-1].get("turn", "?")
    pruned_range = f"{first_turn}-{last_turn}"

    # Deduplication: check if we already flushed this range.
    # Source filter avoids scanning ALL chunks (O(n) → O(1) with index).
    try:
        existing = await memory_store.list_chunks(
            source="system:session_prune",
        )
        for chunk in existing:
            if (
                chunk.source == "system:session_prune"
                and chunk.metadata.get("session_id") == session_id
                and chunk.metadata.get("pruned_range") == pruned_range
            ):
                logger.debug(
                    "flush_pruned_turns dedup match — already flushed",
                    extra={
                        "event": "flush.pruned_turns_dedup",
                        "session_id": session_id,
                        "pruned_range": pruned_range,
                    },
                )
                return  # already flushed
    except Exception as exc:  # catch-all: dedup check best-effort
        logger.debug(
            "flush_pruned_turns dedup check failed (best-effort)",
            extra={
                "event": "prune.dedup_error",
                "error": str(exc),
                "error_category": "dedup_check",
            },
        )

    # Build summary text — compact format for full-text searchability
    lines = [f"Session [{session_id}] context (turns {pruned_range}):"]
    for turn in pruned_turns:
        request = turn.get("request", "?")[:200]
        outcome = turn.get("outcome", "?")
        summary = turn.get("summary", "")
        turn_num = turn.get("turn", "?")

        detail = f'- Turn {turn_num}: "{request}" \u2192 {outcome}'
        if summary:
            detail += f" ({summary})"

        # Extract file paths from step_outcomes for searchability
        step_outcomes = turn.get("step_outcomes") or []
        file_paths = [so["file_path"] for so in step_outcomes if so.get("file_path")]
        if file_paths:
            detail += f" [{', '.join(file_paths)}]"

        lines.append(detail)

    content = "\n".join(lines)
    metadata = {"session_id": session_id, "pruned_range": pruned_range}

    try:
        await memory_store.store(
            content=content,
            source="system:session_prune",
            metadata=metadata,
        )
        logger.info(
            "Pre-pruning memory flush",
            extra={
                "event": "session.prune_flush",
                "session_id": session_id,
                "pruned_range": pruned_range,
                "content_length": len(content),
            },
        )
    except Exception as exc:  # catch-all: pre-pruning flush best-effort
        logger.warning(
            "Pre-pruning flush failed (non-fatal)",
            extra={
                "event": "session.prune_flush_failed",
                "error": str(exc),
                "error_category": "memory_store",
            },
            exc_info=True,
        )
