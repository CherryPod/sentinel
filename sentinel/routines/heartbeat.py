"""Heartbeat system — periodic health checks stored in memory.

Tracks system health over time by running periodic checks and storing
results in the memory system with protected source tags.
"""

import logging
from datetime import UTC, datetime

from sentinel.core.context import require_user_id
from sentinel.memory.chunks import MemoryStore
from sentinel.routines.engine import compute_next_run_at

logger = logging.getLogger(__name__)

HEARTBEAT_SOURCE = "system:heartbeat"
HEARTBEAT_ROUTINE_NAME = "System Heartbeat"


class HeartbeatManager:
    """Manages periodic heartbeat checks and health status tracking."""

    def __init__(self, memory_store: MemoryStore, health_check_fn, db=None):
        self._memory_store = memory_store
        self._health_check_fn = health_check_fn
        self._db = db  # retained for backward compatibility; unused internally
        self._consecutive_failures = 0
        self._last_check_at = None
        self._last_health_data = None

    async def run_heartbeat(self) -> dict:
        """Run a health check and store the result in memory."""
        try:
            health_data = await self._health_check_fn()
            self._consecutive_failures = 0
            self._last_check_at = datetime.now(UTC).isoformat()
            self._last_health_data = health_data

            # Build summary string
            degraded = self._detect_degraded(health_data)
            status = "degraded" if degraded else "healthy"
            summary = f"Heartbeat at {self._last_check_at}: {status}"
            if degraded:
                summary += f" — degraded: {', '.join(degraded)}"

            # Store in memory with protected source
            try:
                await self._memory_store.store(
                    content=summary,
                    source=HEARTBEAT_SOURCE,
                    metadata={"health": health_data, "degraded": degraded},
                )
            except Exception as store_exc:  # catch-all: heartbeat store best-effort
                logger.warning(
                    "Heartbeat memory store failed: %s",
                    store_exc,
                    extra={
                        "event": "heartbeat.store_failed",
                        "error": str(store_exc),
                    },
                    exc_info=True,
                )

            logger.info(
                "Heartbeat completed",
                extra={
                    "event": "heartbeat.check",
                    "status": status,
                    "degraded": degraded,
                },
            )
            return health_data

        except Exception as exc:
            self._consecutive_failures += 1
            self._last_check_at = datetime.now(UTC).isoformat()
            logger.warning(
                "Heartbeat check failed",
                extra={
                    "event": "heartbeat.failure",
                    "consecutive_failures": self._consecutive_failures,
                    "error": str(exc),
                },
                exc_info=True,
            )
            raise

    async def get_latest(self, user_id: int | None = None) -> dict | None:
        """Get the most recent heartbeat entry from memory."""
        user_id = require_user_id(user_id, "HeartbeatManager.get_latest")
        chunk = await self._memory_store.get_latest_by_source(
            HEARTBEAT_SOURCE,
            user_id=user_id,
        )
        if chunk is None:
            return None
        return {
            "chunk_id": chunk.chunk_id,
            "content": chunk.content,
            "source": chunk.source,
            "created_at": chunk.created_at,
        }

    def get_status_summary(self) -> dict:
        """Return current heartbeat status summary."""
        degraded = []
        if self._last_health_data:
            logger.debug(
                "get_status_summary: last_health_data",
                extra={
                    "event": "heartbeat.get_status_summary.match",
                    "reason": "last_health_data",
                },
            )  # auto:neg
            degraded = self._detect_degraded(self._last_health_data)

        if self._last_check_at is None:
            status = "unknown"
        elif degraded:
            status = "degraded"
        else:
            status = "healthy"

        logger.debug(
            "Status summary: %s",
            status,
            extra={
                "event": "heartbeat.status_summary",
                "status": status,
                "degraded_count": len(degraded),
            },
        )

        return {
            "status": status,
            "last_check_at": self._last_check_at,
            "consecutive_failures": self._consecutive_failures,
            "degraded_components": degraded,
            "components": self._last_health_data or {},
        }

    def _detect_degraded(self, health_data: dict) -> list[str]:
        """Identify degraded components from health check data."""
        logger.debug(
            "_detect_degraded called",
            extra={
                "event": "heartbeat._detect_degraded",
                "health_data_len": len(health_data)
                if hasattr(health_data, "__len__")
                else 0,
            },
        )
        degraded = []
        if not health_data.get("planner_available", True):
            degraded.append("planner")
        if not health_data.get("semgrep_loaded", True):
            degraded.append("semgrep")
        if not health_data.get("prompt_guard_loaded", True):
            degraded.append("prompt_guard")
        if health_data.get("sidecar") == "stopped":
            degraded.append("sidecar")
        if health_data.get("signal") == "stopped":
            degraded.append("signal")
        return degraded


async def seed_heartbeat_routine(
    routine_store, user_id: int | None = None
) -> str | None:
    """Create the heartbeat routine if it doesn't already exist.

    Returns the routine_id if created, None if it already exists.
    """
    user_id = require_user_id(user_id, "routines.seed_heartbeat_routine")
    existing = await routine_store.list(user_id=user_id)
    for r in existing:
        if r.name == HEARTBEAT_ROUTINE_NAME:
            return None

    routine = await routine_store.create(
        name=HEARTBEAT_ROUTINE_NAME,
        trigger_type="cron",
        trigger_config={"cron": "*/30 * * * *"},
        action_config={
            "prompt": "Run system heartbeat check and store results.",
            "approval_mode": "auto",
        },
        user_id=user_id,
        description="Periodic system health check — stores results in protected memory.",
        cooldown_s=1200,
        next_run_at=compute_next_run_at("cron", {"cron": "*/30 * * * *"}, enabled=True),
    )

    logger.info(
        "Seeded heartbeat routine",
        extra={
            "event": "heartbeat.routine_seeded",
            "routine_id": routine.routine_id,
        },
    )
    return routine.routine_id
