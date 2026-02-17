"""CRUD store for routines.

PostgreSQL-backed via asyncpg.  When pool=None, falls back to an in-memory
dict for tests.  Implements RoutineStoreProtocol.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast


@dataclass
class Routine:
    routine_id: str
    user_id: int
    name: str
    description: str
    trigger_type: str       # "cron" | "event" | "interval"
    trigger_config: dict    # {"cron": "0 9 * * MON"} | {"event": "task.*.completed"} | {"seconds": 3600}
    action_config: dict     # {"prompt": "...", "approval_mode": "auto"}
    enabled: bool
    last_run_at: str | None
    next_run_at: str | None
    cooldown_s: int
    created_at: str
    updated_at: str


_UPDATABLE_FIELDS = {
    "name", "description", "trigger_type", "trigger_config",
    "action_config", "enabled", "cooldown_s", "user_id",
    "last_run_at", "next_run_at", "updated_at",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _iso_to_dt(iso: str | None) -> datetime | None:
    """Parse ISO 8601 string back to datetime for asyncpg TIMESTAMPTZ params."""
    if iso is None:
        return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _row_to_routine(row: Any) -> Routine:
    """Convert an asyncpg Record to a Routine dataclass."""
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
                    "SELECT COUNT(*) FROM routines WHERE user_id = $1", user_id,
                )
        return sum(1 for r in self._mem.values() if r.user_id == user_id)

    async def create(
        self,
        name: str,
        trigger_type: str,
        trigger_config: dict,
        action_config: dict,
        user_id: int = 1,
        description: str = "",
        enabled: bool = True,
        cooldown_s: int = 0,
        next_run_at: str | None = None,
        max_per_user: int = 0,
    ) -> Routine:
        if max_per_user > 0:
            current = await self.count_for_user(user_id)
            if current >= max_per_user:
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
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO routines "
                    "(routine_id, user_id, name, description, trigger_type, "
                    "trigger_config, action_config, enabled, next_run_at, "
                    "cooldown_s, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, "
                    "NOW(), NOW())",
                    routine_id, user_id, name, description, trigger_type,
                    json.dumps(trigger_config), json.dumps(action_config),
                    enabled, _iso_to_dt(next_run_at), cooldown_s,
                )
        else:
            self._mem[routine_id] = routine

        return routine

    async def get(self, routine_id: str) -> Routine | None:
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM routines WHERE routine_id = $1", routine_id,
                )
                return _row_to_routine(row) if row else None
        return self._mem.get(routine_id)

    async def list(
        self,
        user_id: int = 1,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Routine]:
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if enabled_only:
                    rows = await conn.fetch(
                        "SELECT * FROM routines WHERE user_id = $1 AND enabled = TRUE "
                        "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                        user_id, limit, offset,
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT * FROM routines WHERE user_id = $1 "
                        "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                        user_id, limit, offset,
                    )
                return [_row_to_routine(r) for r in rows]

        # In-memory fallback
        routines = [r for r in self._mem.values() if r.user_id == user_id]
        if enabled_only:
            routines = [r for r in routines if r.enabled]
        routines.sort(key=lambda r: r.created_at, reverse=True)
        return routines[offset:offset + limit]

    async def list_due(self, now_iso: str) -> list[Routine]:
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM routines "
                    "WHERE enabled = TRUE AND next_run_at IS NOT NULL "
                    "AND next_run_at <= $1",
                    _iso_to_dt(now_iso),
                )
                return [_row_to_routine(r) for r in rows]

        # In-memory fallback
        return [
            r for r in self._mem.values()
            if r.enabled and r.next_run_at is not None and r.next_run_at <= now_iso
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
            r for r in self._mem.values()
            if r.enabled and r.next_run_at is not None and r.next_run_at <= now_iso
        ]

    async def update(self, routine_id: str, **kwargs) -> Routine | None:
        routine = await self.get(routine_id)
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
            _TS_FIELDS = {"updated_at", "last_run_at", "next_run_at", "created_at"}
            set_parts = []
            values = []
            param_idx = 1
            for key, value in kwargs.items():
                if key in ("trigger_config", "action_config"):
                    set_parts.append(f"{key} = ${param_idx}::jsonb")
                    values.append(json.dumps(value))
                elif key in _TS_FIELDS and isinstance(value, str):
                    set_parts.append(f"{key} = ${param_idx}")
                    values.append(_iso_to_dt(value))
                else:
                    set_parts.append(f"{key} = ${param_idx}")
                    values.append(value)
                param_idx += 1
            values.append(routine_id)

            async with self._pool.acquire() as conn:
                await conn.execute(
                    f"UPDATE routines SET {', '.join(set_parts)} "
                    f"WHERE routine_id = ${param_idx}",
                    *values,
                )
        else:
            self._mem[routine_id] = routine

        return routine

    async def delete(self, routine_id: str) -> bool:
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM routines WHERE routine_id = $1", routine_id,
                )
                return result == "DELETE 1"

        return self._mem.pop(routine_id, None) is not None

    async def list_event_triggered(self, enabled_only: bool = True) -> list[Routine]:
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if enabled_only:
                    rows = await conn.fetch(
                        "SELECT * FROM routines "
                        "WHERE trigger_type = 'event' AND enabled = TRUE",
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT * FROM routines WHERE trigger_type = 'event'",
                    )
                return [_row_to_routine(r) for r in rows]

        routines = [r for r in self._mem.values() if r.trigger_type == "event"]
        if enabled_only:
            routines = [r for r in routines if r.enabled]
        return routines

    async def list_event_triggered_all_users(
        self, enabled_only: bool = True, admin_pool=None,
    ) -> list[Routine]:
        """List event-triggered routines across ALL users (bypasses RLS)."""
        pool = admin_pool or self._pool
        if pool is not None:
            async with pool.acquire() as conn:
                if enabled_only:
                    rows = await conn.fetch(
                        "SELECT * FROM routines "
                        "WHERE trigger_type = 'event' AND enabled = TRUE",
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT * FROM routines WHERE trigger_type = 'event'",
                    )
                return [_row_to_routine(r) for r in rows]

        routines = [r for r in self._mem.values() if r.trigger_type == "event"]
        if enabled_only:
            routines = [r for r in routines if r.enabled]
        return routines

    async def update_run_state(
        self,
        routine_id: str,
        last_run_at: str,
        next_run_at: str | None,
    ) -> None:
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE routines SET last_run_at = $1, next_run_at = $2, "
                    "updated_at = NOW() WHERE routine_id = $3",
                    _iso_to_dt(last_run_at), _iso_to_dt(next_run_at), routine_id,
                )
        else:
            routine = self._mem.get(routine_id)
            if routine is not None:
                routine.last_run_at = last_run_at
                routine.next_run_at = next_run_at
                routine.updated_at = _now_iso()


if TYPE_CHECKING:
    from sentinel.core.store_protocols import RoutineStoreProtocol

    _: RoutineStoreProtocol = cast(RoutineStoreProtocol, RoutineStore(None))
