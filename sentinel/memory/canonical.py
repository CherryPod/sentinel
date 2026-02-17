"""Canonical trajectory extraction and storage.

Identifies the best-performing strategy pattern per domain and stores it
as a memory chunk for planner context injection. Canonical trajectories
are the system's "learned best practices" — high success-rate patterns
with enough examples to be statistically meaningful.

All operations are deterministic (no LLM). Fire-and-forget compatible —
errors are logged, never crash.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

logger = logging.getLogger("sentinel.audit")

if TYPE_CHECKING:
    from sentinel.memory.chunks import MemoryStore
    from sentinel.memory.domain_summary import DomainSummaryStore
    from sentinel.memory.episodic import EpisodicStore
    from sentinel.memory.strategy_store import StrategyPatternStore
    from sentinel.worker.base import EmbeddingBase


@dataclass
class CanonicalTrajectory:
    """A proven strategy pattern promoted to canonical status."""

    domain: str
    strategy_name: str
    step_sequence: list[str]
    success_rate: float
    example_count: int
    generated_at: str
    expires_at: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _expiry_iso(days: int = 30) -> str:
    """Return ISO timestamp for expiry days from now."""
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def generate_canonical_trajectory(
    domain: str,
    user_id: int,
    strategy_store: StrategyPatternStore,
    episodic_store: EpisodicStore | None = None,
) -> CanonicalTrajectory | None:
    """Generate a canonical trajectory for a domain.

    Returns the highest success-rate strategy with >= 3 examples and
    success_rate >= 0.6, but only if the domain has >= 10 total tasks.
    Returns None if criteria are not met.
    """
    pattern = await strategy_store.get_canonical(domain, user_id=user_id)
    if pattern is None:
        return None

    if pattern.success_rate < 0.6 or pattern.occurrence_count < 3:
        return None

    return CanonicalTrajectory(
        domain=domain,
        strategy_name=pattern.strategy_name,
        step_sequence=pattern.step_sequence,
        success_rate=pattern.success_rate,
        example_count=pattern.occurrence_count,
        generated_at=_now_iso(),
        expires_at=_expiry_iso(30),
    )


async def store_canonical_as_chunk(
    trajectory: CanonicalTrajectory,
    memory_store: MemoryStore,
    embedding_client: EmbeddingBase | None = None,
    user_id: int = 1,
) -> str:
    """Store a canonical trajectory as a memory chunk.

    Source: "system:canonical" — protected from user deletion.
    Metadata includes domain, strategy, expiry for retrieval filtering.
    """
    # Build content text for embedding + FTS
    steps_str = " → ".join(trajectory.step_sequence) if trajectory.step_sequence else trajectory.strategy_name
    content = (
        f"[CANONICAL] {trajectory.domain}: "
        f"best approach is {trajectory.strategy_name} "
        f"({trajectory.success_rate:.0%} success, {trajectory.example_count} examples). "
        f"Steps: {steps_str}"
    )

    metadata = {
        "domain": trajectory.domain,
        "strategy": trajectory.strategy_name,
        "success_rate": trajectory.success_rate,
        "example_count": trajectory.example_count,
        "generated_at": trajectory.generated_at,
        "expires_at": trajectory.expires_at,
    }

    # Embed with search_document prefix for retrieval
    if embedding_client is not None:
        try:
            embedding = await embedding_client.embed(
                content, prefix="search_document: ",
            )
            chunk_id = await memory_store.store_with_embedding(
                content=content,
                embedding=embedding,
                source="system:canonical",
                metadata=metadata,
                user_id=user_id,
                task_domain=trajectory.domain,
            )
            logger.info(
                "Canonical trajectory stored with embedding",
                extra={
                    "event": "canonical_stored",
                    "domain": trajectory.domain,
                    "chunk_id": chunk_id,
                },
            )
            return chunk_id
        except Exception as exc:
            logger.warning(
                "Canonical embedding failed, storing without",
                extra={"event": "canonical_embed_failed", "error": str(exc)},
            )

    # Fallback: store without embedding
    chunk_id = await memory_store.store(
        content=content,
        source="system:canonical",
        metadata=metadata,
        user_id=user_id,
        task_domain=trajectory.domain,
    )
    logger.info(
        "Canonical trajectory stored (no embedding)",
        extra={
            "event": "canonical_stored",
            "domain": trajectory.domain,
            "chunk_id": chunk_id,
        },
    )
    return chunk_id


async def refresh_canonical_trajectories(
    user_id: int,
    strategy_store: StrategyPatternStore,
    episodic_store: EpisodicStore | None,
    memory_store: MemoryStore,
    embedding_client: EmbeddingBase | None,
    domain_summary_store: DomainSummaryStore | None = None,
) -> int:
    """Refresh canonical trajectories for all domains with enough data.

    For each domain with a summary, checks if canonical should be regenerated
    and generates + stores if criteria are met. Fire-and-forget compatible —
    logs errors, never crashes.

    Returns the number of canonicals refreshed.
    """
    refreshed = 0

    # Get domains from domain_summary_store
    if domain_summary_store is None:
        return 0

    try:
        summaries = await domain_summary_store.list_all(user_id=user_id)
    except Exception as exc:
        logger.warning(
            "Canonical refresh: failed to list domains",
            extra={"event": "canonical_refresh_failed", "error": str(exc)},
        )
        return 0

    for summary in summaries:
        try:
            # Check existing canonical chunk for this domain
            existing = await memory_store.list_chunks(
                user_id=user_id,
                source="system:canonical",
            )
            existing_canonical = None
            for chunk in existing:
                if chunk.metadata.get("domain") == summary.domain:
                    existing_canonical = chunk
                    break

            # Determine if we should regenerate
            last_generated = None
            if existing_canonical and existing_canonical.metadata.get("generated_at"):
                try:
                    last_generated = datetime.fromisoformat(
                        existing_canonical.metadata["generated_at"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

            should_regen = await strategy_store.should_regenerate_canonical(
                domain=summary.domain,
                user_id=user_id,
                last_generated=last_generated,
                tasks_since=summary.last_task_count,
            )

            if not should_regen:
                continue

            # Generate canonical trajectory
            trajectory = await generate_canonical_trajectory(
                domain=summary.domain,
                user_id=user_id,
                strategy_store=strategy_store,
                episodic_store=episodic_store,
            )

            if trajectory is None:
                continue

            # Delete old canonical chunk for this domain (if exists)
            if existing_canonical:
                try:
                    await memory_store.delete(
                        existing_canonical.chunk_id, user_id=user_id,
                    )
                except ValueError:
                    # system: source is protected — use update instead
                    await memory_store.update(
                        existing_canonical.chunk_id,
                        content="[SUPERSEDED]",
                        user_id=user_id,
                    )

            # Store new canonical
            await store_canonical_as_chunk(
                trajectory, memory_store, embedding_client, user_id,
            )
            refreshed += 1

            logger.info(
                "Canonical trajectory refreshed",
                extra={
                    "event": "canonical_refreshed",
                    "domain": summary.domain,
                    "strategy": trajectory.strategy_name,
                    "success_rate": trajectory.success_rate,
                },
            )

        except Exception as exc:
            logger.warning(
                "Canonical refresh failed for domain (non-fatal)",
                extra={
                    "event": "canonical_refresh_domain_failed",
                    "domain": summary.domain,
                    "error": str(exc),
                },
            )

    return refreshed
