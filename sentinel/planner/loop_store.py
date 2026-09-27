"""PostgreSQL persistence for loop_runs.

CRUD operations for the loop controller's persistent state.
Follows the same patterns as EpisodicStore: asyncpg pool,
user_id scoping, JSONB for structured sub-documents.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel.core.context import require_user_id

logger = logging.getLogger(__name__)

# Default timeout for a loop run before it's marked timed_out (seconds)
_DEFAULT_LOOP_TIMEOUT = 3600


@dataclass
class LoopState:
    """Persistent state for a loop run."""

    loop_id: str
    user_id: int
    original_request: str
    max_iterations: int
    timeout_seconds: int
    status: str  # running | succeeded | failed | timed_out | cancelled
    iteration_count: int
    cancelled_at_iteration: int | None
    iterations: list[dict]
    created_at: datetime
    finished_at: datetime | None


def _row_to_state(row) -> LoopState:
    """Convert an asyncpg Record to a LoopState dataclass."""
    logger.debug(
        "_row_to_state called",
        extra={"event": "row.to_state", "loop_id": row["loop_id"]},
    )
    iterations_raw = row["iterations"]
    if isinstance(iterations_raw, str):
        logger.debug(
            "_row_to_state — parsing iterations from JSON string",
            extra={"event": "row.to_state_str_branch", "loop_id": row["loop_id"]},
        )
        try:
            iterations = json.loads(iterations_raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "_row_to_state: invalid JSON in iterations column",
                extra={
                    "event": "row.to_state_json_error",
                    "loop_id": row["loop_id"],
                    "error": str(exc),
                },
                exc_info=True,
            )
            iterations = []
    else:
        logger.debug(
            "_row_to_state — using iterations as native type",
            extra={"event": "row.to_state_native_branch", "loop_id": row["loop_id"]},
        )
        iterations = iterations_raw or []

    logger.debug(
        "_row_to_state completed",
        extra={
            "event": "row.to_state_exit",
            "loop_id": row["loop_id"],
            "iteration_count": len(iterations),
        },
    )
    return LoopState(
        loop_id=row["loop_id"],
        user_id=row["user_id"],
        original_request=row["original_request"],
        max_iterations=row["max_iterations"],
        timeout_seconds=row["timeout_seconds"],
        status=row["status"],
        iteration_count=row["iteration_count"],
        cancelled_at_iteration=row["cancelled_at_iteration"],
        iterations=iterations,
        created_at=row["created_at"],
        finished_at=row["finished_at"],
    )


class LoopStore:
    """PostgreSQL CRUD for loop_runs table."""

    def __init__(self, pool) -> None:
        self.pool = pool

    async def create(
        self,
        loop_id: str,
        user_id: int,
        original_request: str,
        max_iterations: int = 5,
        timeout_seconds: int = _DEFAULT_LOOP_TIMEOUT,
    ) -> str:
        """Insert a new loop_run record. Returns loop_id."""
        user_id = require_user_id(user_id, "LoopStore.create")
        logger.debug(
            "loop_store.create called — inserting new loop_run",
            extra={
                "event": "loop_store.create_entry",
                "loop_id": loop_id,
                "user_id": user_id,
                "max_iterations": max_iterations,
                "timeout_seconds": timeout_seconds,
            },
        )
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO loop_runs (loop_id, user_id, original_request,
                                       max_iterations, timeout_seconds)
                VALUES ($1, $2, $3, $4, $5)
                """,
                loop_id,
                user_id,
                original_request,
                max_iterations,
                timeout_seconds,
            )
        logger.info(
            "loop_store: created %s for user %d",
            loop_id,
            user_id,
            extra={
                "event": "loop_store.create",
                "loop_id": loop_id,
                "user_id": user_id,
            },
        )
        return loop_id

    async def get(self, loop_id: str, user_id: int) -> LoopState | None:
        """Fetch a loop run by ID, scoped to user."""
        user_id = require_user_id(user_id, "LoopStore.get")
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT loop_id, user_id, original_request, max_iterations,
                       timeout_seconds, status, iteration_count,
                       cancelled_at_iteration, iterations, created_at, finished_at
                FROM loop_runs
                WHERE loop_id = $1 AND user_id = $2
                """,
                loop_id,
                user_id,
            )
        if row is None:
            logger.debug(
                "loop_store.get: no record found",
                extra={"event": "loop_store.get_miss", "loop_id": loop_id},
            )
            return None
        state = _row_to_state(row)
        logger.debug(
            "loop_store.get found record",
            extra={
                "event": "loop_store.get_hit",
                "loop_id": loop_id,
                "status": state.status,
            },
        )
        return state

    async def append_iteration(
        self,
        loop_id: str,
        user_id: int,
        iteration: dict,
    ) -> None:
        """Append an iteration record and bump iteration_count."""
        user_id = require_user_id(user_id, "LoopStore.append_iteration")
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE loop_runs
                SET iterations = iterations || $3::jsonb,
                    iteration_count = iteration_count + 1
                WHERE loop_id = $1 AND user_id = $2
                """,
                loop_id,
                user_id,
                json.dumps(iteration),
            )
        logger.debug(
            "append_iteration completed",
            extra={
                "event": "append.iteration_exit",
                "loop_id": loop_id,
                "user_id": user_id,
            },
        )

    async def set_status(
        self,
        loop_id: str,
        user_id: int,
        status: str,
        cancelled_at_iteration: int | None = None,
    ) -> None:
        """Set terminal status and finished_at timestamp."""
        user_id = require_user_id(user_id, "LoopStore.set_status")
        now = datetime.now(UTC)
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE loop_runs
                SET status = $3, finished_at = $4, cancelled_at_iteration = $5
                WHERE loop_id = $1 AND user_id = $2
                """,
                loop_id,
                user_id,
                status,
                now,
                cancelled_at_iteration,
            )
        logger.debug(
            "set_status completed",
            extra={
                "event": "set.status_exit",
                "loop_id": loop_id,
                "status": status,
            },
        )

    async def is_cancelled(
        self,
        loop_id: str,
        user_id: int | None = None,
    ) -> bool:
        """Check if a loop has been cancelled (fast path — single column)."""
        user_id = require_user_id(user_id, "LoopStore.is_cancelled")
        logger.debug(
            "is_cancelled called",
            extra={"event": "is.cancelled", "loop_id": loop_id},
        )
        async with self.pool.acquire() as conn:
            status = await conn.fetchval(
                "SELECT status FROM loop_runs WHERE loop_id = $1 AND user_id = $2",
                loop_id,
                user_id,
            )
        result = status == "cancelled"
        logger.debug(
            "is_cancelled completed",
            extra={
                "event": "is.cancelled_exit",
                "loop_id": loop_id,
                "cancelled": result,
            },
        )
        return result

    async def has_active_loop(self, user_id: int) -> bool:
        """Check if user has a running loop (concurrency guard)."""
        user_id = require_user_id(user_id, "LoopStore.has_active_loop")
        logger.debug(
            "has_active_loop called",
            extra={"event": "has.active_loop", "user_id": user_id},
        )
        async with self.pool.acquire() as conn:
            active = await conn.fetchval(
                "SELECT loop_id FROM loop_runs WHERE user_id = $1 AND status = 'running' LIMIT 1",
                user_id,
            )
        result = active is not None
        logger.debug(
            "has_active_loop completed",
            extra={
                "event": "has.active_loop_exit",
                "user_id": user_id,
                "has_active": result,
            },
        )
        return result

    async def list_by_user(self, user_id: int, limit: int = 20) -> list[LoopState]:
        """List recent loops for a user, newest first."""
        user_id = require_user_id(user_id, "LoopStore.list_by_user")
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT loop_id, user_id, original_request, max_iterations,
                       timeout_seconds, status, iteration_count,
                       cancelled_at_iteration, iterations, created_at, finished_at
                FROM loop_runs
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                user_id,
                limit,
            )
        results = [_row_to_state(r) for r in rows]
        logger.debug(
            "list_by_user completed",
            extra={
                "event": "list.by_user_exit",
                "user_id": user_id,
                "result_count": len(results),
            },
        )
        return results
