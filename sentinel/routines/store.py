"""CRUD store for routines.

PostgreSQL-backed via asyncpg.  When pool=None, falls back to an in-memory
dict for tests.  Implements RoutineStoreProtocol.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from sentinel.core.context import require_user_id

logger = logging.getLogger(__name__)


@dataclass
class Routine:
    routine_id: str
    user_id: int
    name: str
    description: str
    trigger_type: str  # "cron" | "event" | "interval"
    trigger_config: dict  # {"cron": "0 9 * * MON"} | {"event": "task.*.completed"} | {"seconds": 3600}
    action_config: dict  # {"prompt": "...", "approval_mode": "auto"}
    enabled: bool
    last_run_at: str | None
    next_run_at: str | None
    cooldown_s: int
    created_at: str
    updated_at: str


_TIMESTAMP_FIELDS = {"updated_at", "last_run_at", "next_run_at", "created_at"}

_UPDATABLE_FIELDS = {
    "name",
    "description",
    "trigger_type",
    "trigger_config",
    "action_config",
    "enabled",
    "cooldown_s",
    # Q4-F16 Coord review follow-up: `user_id` removed. The new update()
    # signature hoists user_id to a named param that binds to the WHERE
    # principal clause, so kwargs can no longer smuggle it into the SET
    # whitelist. Pinned by test_update_user_id_not_in_updatable_fields.
    "last_run_at",
    "next_run_at",
    "updated_at",
}


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _iso_to_dt(iso: str | None) -> datetime | None:
    """Parse ISO 8601 string back to datetime for asyncpg TIMESTAMPTZ params."""
    if iso is None:
        return None
    return datetime.fromisoformat(iso)


def _row_to_routine(row: Any) -> Routine:
    """Convert an asyncpg Record to a Routine dataclass."""
    logger.debug(
        "_row_to_routine called",
        extra={"event": "store._row_to_routine", "row_type": type(row).__name__},
    )
    trigger_config = row["trigger_config"]
    if isinstance(trigger_config, str):
        trigger_config = json.loads(trigger_config)

    action_config = row["action_config"]
    if isinstance(action_config, str):
        action_config = json.loads(action_config)

    return Routine(
        routine_id=row["routine_id"],
        user_id=row["user_id"],
        name=row["name"],
        description=row["description"],
        trigger_type=row["trigger_type"],
        trigger_config=trigger_config,
        action_config=action_config,
        enabled=row["enabled"],
        last_run_at=_dt_to_iso(row["last_run_at"]),
        next_run_at=_dt_to_iso(row["next_run_at"]),
        cooldown_s=row["cooldown_s"],
        created_at=_dt_to_iso(row["created_at"]) or _now_iso(),
        updated_at=_dt_to_iso(row["updated_at"]) or _now_iso(),
    )


class RoutineStore:
    """CRUD operations for the routines table."""

    def __init__(self, pool: Any = None):
        self._pool = pool
        # In-memory fallback for tests
        self._mem: dict[str, Routine] = {}

    async def count_for_user(self, user_id: int) -> int:
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                return await conn.fetchval(
                    "SELECT COUNT(*) FROM routines WHERE user_id = $1",
                    user_id,
                )
        return sum(1 for r in self._mem.values() if r.user_id == user_id)

    async def create(
        self,
        name: str,
        trigger_type: str,
        trigger_config: dict,
        action_config: dict,
        user_id: int | None = None,
        description: str = "",
        enabled: bool = True,
        cooldown_s: int = 0,
        next_run_at: str | None = None,
        max_per_user: int = 0,
    ) -> Routine:
        user_id = require_user_id(user_id, "RoutineStore.create")
        logger.debug(
            "create called",
            extra={
                "event": "store.create",
                "record_name": name,
                "trigger_type": trigger_type,
                "trigger_config_len": len(trigger_config)
                if hasattr(trigger_config, "__len__")
                else 0,
            },
        )
        if max_per_user > 0:
            logger.debug(
                "Checking per-user routine limit",
                extra={
                    "event": "store.create.limit_check",
                    "max_per_user": max_per_user,
                },
            )
            current = await self.count_for_user(user_id)
            if current >= max_per_user:
                logger.debug(
                    "Per-user routine limit reached",
                    extra={"event": "store.create.limit_reached", "current": current},
                )
                raise ValueError(
                    f"User {user_id!r} already has {max_per_user} routines (limit reached)"
                )

        routine_id = str(uuid.uuid4())
        now = _now_iso()

        routine = Routine(
            routine_id=routine_id,
            user_id=user_id,
            name=name,
            description=description,
            trigger_type=trigger_type,
            trigger_config=trigger_config,
            action_config=action_config,
            enabled=enabled,
            last_run_at=None,
            next_run_at=next_run_at,
            cooldown_s=cooldown_s,
            created_at=now,
            updated_at=now,
        )

        if self._pool is not None:
            logger.debug(
                "Creating routine in database",
                extra={"event": "store.create.db"},
            )
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO routines "
                    "(routine_id, user_id, name, description, trigger_type, "
                    "trigger_config, action_config, enabled, next_run_at, "
                    "cooldown_s, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, "
                    "NOW(), NOW())",
                    routine_id,
                    user_id,
                    name,
                    description,
                    trigger_type,
                    json.dumps(trigger_config),
                    json.dumps(action_config),
                    enabled,
                    _iso_to_dt(next_run_at),
                    cooldown_s,
                )
        else:
            logger.debug(
                "Creating routine in memory",
                extra={"event": "store.create.mem"},
            )
            self._mem[routine_id] = routine

        return routine

    async def get(
        self,
        routine_id: str,
        user_id: int | None = None,
    ) -> Routine | None:
        logger.debug(
            "get called",
            extra={
                "event": "routines.store.get",
                "routine_id": routine_id,
                "user_id": user_id,
            },
        )  # auto:entry
        user_id = require_user_id(user_id, "RoutineStore.get")
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM routines WHERE routine_id = $1 AND user_id = $2",
                    routine_id,
                    user_id,
                )
                return _row_to_routine(row) if row else None
        routine = self._mem.get(routine_id)
        if routine is None or routine.user_id != user_id:
            return None
        return routine

    async def list(
        self,
        user_id: int | None = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Routine]:
        user_id = require_user_id(user_id, "RoutineStore.list")
        logger.debug(
            "list called",
            extra={
                "event": "store.list",
                "user_id": user_id,
                "enabled_only": enabled_only,
                "limit": limit,
            },
        )
        if self._pool is not None:
            logger.debug(
                "Listing routines from database",
                extra={"event": "store.list.db", "enabled_only": enabled_only},
            )
            async with self._pool.acquire() as conn:
                if enabled_only:
                    logger.debug(
                        "list: enabled_only",
                        extra={"event": "store.list.match", "reason": "enabled_only"},
                    )  # auto:neg
                    rows = await conn.fetch(
                        "SELECT * FROM routines WHERE user_id = $1 AND enabled = TRUE "
                        "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                        user_id,
                        limit,
                        offset,
                    )
                else:
                    logger.debug(
                        "list: enabled_only",
                        extra={"event": "store.list.clean", "reason": "enabled_only"},
                    )  # auto:neg
                    rows = await conn.fetch(
                        "SELECT * FROM routines WHERE user_id = $1 "
                        "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                        user_id,
                        limit,
                        offset,
                    )
                return [_row_to_routine(r) for r in rows]

        # In-memory fallback
        routines = [r for r in self._mem.values() if r.user_id == user_id]
        if enabled_only:
            logger.debug(
                "list: enabled_only",
                extra={"event": "store.list.match", "reason": "enabled_only"},
            )  # auto:neg
            routines = [r for r in routines if r.enabled]
        routines.sort(key=lambda r: r.created_at, reverse=True)
        return routines[offset : offset + limit]

    async def list_due(
        self,
        now_iso: str,
        user_id: int | None = None,
    ) -> list[Routine]:
        user_id = require_user_id(user_id, "RoutineStore.list_due")
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM routines "
                    "WHERE enabled = TRUE AND next_run_at IS NOT NULL "
                    "AND next_run_at <= $1 AND user_id = $2",
                    _iso_to_dt(now_iso),
                    user_id,
                )
                return [_row_to_routine(r) for r in rows]

        # In-memory fallback
        return [
            r
            for r in self._mem.values()
            if r.user_id == user_id
            and r.enabled
            and r.next_run_at is not None
            and r.next_run_at <= now_iso
        ]

    async def list_due_all_users(self, now_iso: str, admin_pool=None) -> list[Routine]:
        """List all due routines across ALL users (bypasses RLS).

        Used by the scheduler tick — discovery is cross-user, execution is per-user.
        Uses admin_pool if provided (bypasses RLS), else falls back to self._pool.
        """
        pool = admin_pool or self._pool
        if pool is not None:
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM routines "
                    "WHERE enabled = TRUE AND next_run_at IS NOT NULL "
                    "AND next_run_at <= $1",
                    _iso_to_dt(now_iso),
                )
                return [_row_to_routine(r) for r in rows]

        # In-memory fallback — returns all users' routines
        return [
            r
            for r in self._mem.values()
            if r.enabled and r.next_run_at is not None and r.next_run_at <= now_iso
        ]

    async def update(
        self,
        routine_id: str,
        user_id: int | None = None,
        **kwargs,
    ) -> Routine | None:
        user_id = require_user_id(user_id, "RoutineStore.update")
        logger.debug(
            "update called", extra={"event": "store.update", "routine_id": routine_id}
        )
        routine = await self.get(routine_id, user_id=user_id)
        if routine is None:
            return None

        bad_keys = set(kwargs.keys()) - _UPDATABLE_FIELDS
        if bad_keys:
            raise ValueError(f"Invalid update fields: {bad_keys}")

        now = _now_iso()
        kwargs["updated_at"] = now

        for key, value in kwargs.items():
            if hasattr(routine, key):
                setattr(routine, key, value)

        if self._pool is not None:
            # Build SET clause with numbered $N parameters
            set_parts = []
            values = []
            param_idx = 1
            for key, value in kwargs.items():
                if key in ("trigger_config", "action_config"):
                    set_parts.append(f"{key} = ${param_idx}::jsonb")
                    values.append(json.dumps(value))
                elif key in _TIMESTAMP_FIELDS and isinstance(value, str):
                    set_parts.append(f"{key} = ${param_idx}")
                    values.append(_iso_to_dt(value))
                else:
                    set_parts.append(f"{key} = ${param_idx}")
                    values.append(value)
                param_idx += 1
            values.append(routine_id)
            values.append(user_id)

            async with self._pool.acquire() as conn:
                await conn.execute(
                    f"UPDATE routines SET {', '.join(set_parts)} "  # nosec B608 — column names from _UPDATABLE_FIELDS constant; values parameterised via asyncpg
                    f"WHERE routine_id = ${param_idx} "
                    f"AND user_id = ${param_idx + 1}",
                    *values,
                )
        else:
            self._mem[routine_id] = routine

        return routine

    async def precancel_cascade(
        self,
        routine_id: str,
        user_id: int | None = None,
    ) -> None:
        """Clear pending approvals/confirmations for a routine BEFORE cancelling tasks.

        Q5.fix.e D3d §1: runs before ``RoutineEngine.cancel_routine_executions``
        so that a task caught between "request_plan_approval INSERT" and
        "observe CancelledError" has its already-written approval rows cleaned
        by the subsequent post-wait TX cascade in ``delete()``. Split-cascade
        shape per Q5.fix.design §D3 (Codex round 2 adjudication, thread
        019db531).

        Sessions are NOT deleted here: ``SessionStore.add_turn`` FK-references
        ``conversation_turns`` → pre-deleting the session row would raise FK
        exceptions on still-running tasks. Sessions are cleaned in ``delete()``
        inside the post-wait TX (together with any straggler approvals).

        Cascade predicate (D3b): ``source_key = 'routine:{id}' OR source_key
        LIKE 'routine:{id}:%'`` — NOT ``LIKE 'routine:{id}%'`` (that would
        match ``routine:abcd`` when deleting ``abc``).
        """
        logger.debug(
            "precancel_cascade called",
            extra={
                "event": "routines.store.precancel_cascade",
                "routine_id": routine_id,
                "user_id": user_id,
            },
        )  # auto:entry
        user_id = require_user_id(user_id, "RoutineStore.precancel_cascade")
        if self._pool is None:
            # In-memory path: approvals / confirmations aren't mirrored into
            # RoutineStore._mem; callers using the memory fallback operate
            # without approvals/confirmations backends. No-op is correct.
            logger.debug(
                "precancel_cascade: match",
                extra={
                    "event": "routines.store.precancel_cascade.match",
                    "reason": "in_memory_path",
                    "routine_id": routine_id,
                },
            )  # auto:neg
            return
        prefix_bare = f"routine:{routine_id}"
        prefix_colon = f"routine:{routine_id}:%"
        async with self._pool.acquire() as conn, conn.transaction():
            # C34 Q5-FL2: cascade DELETEs are SQL-enforced cross-user safe via
            # ``AND user_id = $3``. Parens around the OR are load-bearing —
            # without them precedence binds AND only to the LIKE arm and the
            # bare-equals arm becomes un-user-scoped, silently re-introducing
            # the gap on the canonical ``routine:{id}`` source_key match.
            approvals_result = await conn.execute(
                "DELETE FROM approvals "
                "WHERE (source_key = $1 OR source_key LIKE $2) AND user_id = $3",
                prefix_bare,
                prefix_colon,
                user_id,
            )
            confirmations_result = await conn.execute(
                "DELETE FROM confirmations "
                "WHERE (source_key = $1 OR source_key LIKE $2) AND user_id = $3",
                prefix_bare,
                prefix_colon,
                user_id,
            )
        logger.info(
            "Routine pre-cancel cascade deleted pending approvals/confirmations",
            extra={
                "event": "routines.store.precancel_cascade.done",
                "routine_id": routine_id,
                "approvals_result": approvals_result,
                "confirmations_result": confirmations_result,
            },
        )

    async def delete(
        self,
        routine_id: str,
        user_id: int | None = None,
    ) -> bool:
        """Delete a routine with cascade-cancel in-flight executions.

        Q5.fix.e D3d §3+: post-wait single-TX cascade over approvals,
        confirmations, sessions, and the routine row itself. FK cascade on
        ``routine_executions.routine_id`` fires automatically inside the same
        transaction. Returns True iff the routine row existed and was deleted.

        Caller (HTTP handler) is expected to have already:
          (1) called ``precancel_cascade(routine_id)``,
          (2) called ``engine.cancel_routine_executions(routine_id)``,
          (3) awaited that method's bounded 5s wait.

        Residual windows (both user-approved — accept as expanded residual,
        backstopped by ApprovalManager.purge_old(days=7) via F7 scheduler):

          (1) µs-scale TX-internal window (2026-04-22 lock): between the
              post-wait cascade's DELETE statements and the final
              DELETE FROM routines within the same TX, a concurrent approval
              INSERT on another connection could commit and produce an
              orphaned 'routine:{id}:...' row.

          (2) Seconds-scale scheduler-visible window (2026-04-24 lock, Option
              B per Codex thread `019dc075-92d2-7352-b203-1c4590f77fe4`):
              between cancel_routine_executions returning (≤5s after snapshot)
              and DELETE FROM routines committing, the engine's scheduler tick
              / event-trigger / manual-trigger paths can spawn a fresh
              execution that was not in the cancel snapshot. Its approval
              INSERTs keyed on 'routine:{id}:{new_exec_id}' become orphans
              once the routine row is gone. Same end state as (1), larger
              window (5–20s typical). Option A (mark routine "deleting" /
              disabled upfront) rejected as borderline structural refactor —
              deleting-state enum would bleed into every scheduler/event/
              manual-trigger reader.

        Neither residual is worth advisory-lock serialisation: precedent
        Q10.fix.design D8 (thread `019db1af`) — accept + document + rely
        on 7-day purge backstop.

        See hardening-Q5-ttl-coupling-findings.md §Design D3 trade-offs for
        full rationale; Q5-FL4 in Deferred cleanup for pass-closure review.
        """
        logger.debug(
            "delete called",
            extra={
                "event": "routines.store.delete",
                "routine_id": routine_id,
                "user_id": user_id,
            },
        )  # auto:entry
        user_id = require_user_id(user_id, "RoutineStore.delete")
        if self._pool is not None:
            prefix_bare = f"routine:{routine_id}"
            prefix_colon = f"routine:{routine_id}:%"
            async with self._pool.acquire() as conn, conn.transaction():
                # C34 Q5-FL2: cascade DELETEs are SQL-enforced cross-user safe
                # via ``AND user_id = $3``. Parens around the OR are
                # load-bearing — see precancel_cascade for rationale.
                approvals_result = await conn.execute(
                    "DELETE FROM approvals "
                    "WHERE (source_key = $1 OR source_key LIKE $2) AND user_id = $3",
                    prefix_bare,
                    prefix_colon,
                    user_id,
                )
                confirmations_result = await conn.execute(
                    "DELETE FROM confirmations "
                    "WHERE (source_key = $1 OR source_key LIKE $2) AND user_id = $3",
                    prefix_bare,
                    prefix_colon,
                    user_id,
                )
                sessions_result = await conn.execute(
                    "DELETE FROM sessions "
                    "WHERE (source = $1 OR source LIKE $2) AND user_id = $3",
                    prefix_bare,
                    prefix_colon,
                    user_id,
                )
                routines_result = await conn.execute(
                    "DELETE FROM routines WHERE routine_id = $1 AND user_id = $2",
                    routine_id,
                    user_id,
                )
            deleted = routines_result == "DELETE 1"
            logger.info(
                "Routine delete TX cascade complete",
                extra={
                    "event": "routines.store.delete.done",
                    "routine_id": routine_id,
                    "deleted": deleted,
                    "approvals_result": approvals_result,
                    "confirmations_result": confirmations_result,
                    "sessions_result": sessions_result,
                    "routines_result": routines_result,
                },
            )
            return deleted

        existing = self._mem.get(routine_id)
        if existing is None or existing.user_id != user_id:
            return False
        del self._mem[routine_id]
        return True

    async def list_event_triggered(
        self,
        enabled_only: bool = True,
        user_id: int | None = None,
    ) -> list[Routine]:
        logger.debug(
            "list_event_triggered called",
            extra={
                "event": "routines.store.list_event_triggered",
                "enabled_only": enabled_only,
                "user_id": user_id,
            },
        )  # auto:entry
        user_id = require_user_id(user_id, "RoutineStore.list_event_triggered")
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if enabled_only:
                    logger.debug(
                        "list_event_triggered: enabled_only",
                        extra={
                            "event": "routines.store.list_event_triggered.match",
                            "reason": "enabled_only",
                        },
                    )  # auto:neg
                    rows = await conn.fetch(
                        "SELECT * FROM routines "
                        "WHERE trigger_type = 'event' AND enabled = TRUE "
                        "AND user_id = $1",
                        user_id,
                    )
                else:
                    logger.debug(
                        "list_event_triggered: enabled_only",
                        extra={
                            "event": "routines.store.list_event_triggered.clean",
                            "reason": "enabled_only",
                        },
                    )  # auto:neg
                    rows = await conn.fetch(
                        "SELECT * FROM routines "
                        "WHERE trigger_type = 'event' AND user_id = $1",
                        user_id,
                    )
                return [_row_to_routine(r) for r in rows]

        routines = [
            r
            for r in self._mem.values()
            if r.trigger_type == "event" and r.user_id == user_id
        ]
        if enabled_only:
            logger.debug(
                "list_event_triggered: enabled_only",
                extra={
                    "event": "routines.store.list_event_triggered.match",
                    "reason": "enabled_only",
                },
            )  # auto:neg
            routines = [r for r in routines if r.enabled]
        return routines

    async def list_event_triggered_all_users(
        self,
        enabled_only: bool = True,
        admin_pool=None,
    ) -> list[Routine]:
        """List event-triggered routines across ALL users (bypasses RLS)."""
        logger.debug(
            "list_event_triggered_all_users called",
            extra={
                "event": "store.list_event_triggered_all_users",
                "enabled_only": enabled_only,
                "admin_pool_type": type(admin_pool).__name__,
            },
        )
        pool = admin_pool or self._pool
        if pool is not None:
            async with pool.acquire() as conn:
                if enabled_only:
                    logger.debug(
                        "list_event_triggered_all_users: enabled_only",
                        extra={
                            "event": "store.list_event_triggered_all_users.match",
                            "reason": "enabled_only",
                        },
                    )  # auto:neg
                    rows = await conn.fetch(
                        "SELECT * FROM routines "
                        "WHERE trigger_type = 'event' AND enabled = TRUE",
                    )
                else:
                    logger.debug(
                        "list_event_triggered_all_users: enabled_only",
                        extra={
                            "event": "store.list_event_triggered_all_users.clean",
                            "reason": "enabled_only",
                        },
                    )  # auto:neg
                    rows = await conn.fetch(
                        "SELECT * FROM routines WHERE trigger_type = 'event'",
                    )
                return [_row_to_routine(r) for r in rows]

        routines = [r for r in self._mem.values() if r.trigger_type == "event"]
        if enabled_only:
            logger.debug(
                "list_event_triggered_all_users: enabled_only",
                extra={
                    "event": "store.list_event_triggered_all_users.match",
                    "reason": "enabled_only",
                },
            )  # auto:neg
            routines = [r for r in routines if r.enabled]
        return routines

    async def update_run_state(
        self,
        routine_id: str,
        last_run_at: str,
        next_run_at: str | None,
        user_id: int | None = None,
    ) -> None:
        user_id = require_user_id(user_id, "RoutineStore.update_run_state")
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE routines SET last_run_at = $1, next_run_at = $2, "
                    "updated_at = NOW() WHERE routine_id = $3 AND user_id = $4",
                    _iso_to_dt(last_run_at),
                    _iso_to_dt(next_run_at),
                    routine_id,
                    user_id,
                )
        else:
            routine = self._mem.get(routine_id)
            if routine is not None and routine.user_id == user_id:
                routine.last_run_at = last_run_at
                routine.next_run_at = next_run_at
                routine.updated_at = _now_iso()


if TYPE_CHECKING:
    from sentinel.core.store_protocols import RoutineStoreProtocol

    _: RoutineStoreProtocol = cast("RoutineStoreProtocol", RoutineStore(None))
