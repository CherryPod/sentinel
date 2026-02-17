"""CRUD store for routines.

Follows the MemoryStore dual-mode pattern: SQLite-backed when a db connection
is provided, in-memory dict fallback for tests without a database.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Routine:
    routine_id: str
    user_id: str
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class RoutineStore:
    """CRUD operations for the routines table."""

    def __init__(self, db: sqlite3.Connection | None = None):
        self._db = db
        # In-memory fallback for tests
        self._mem: dict[str, Routine] = {} if db is None else {}

    # -- helpers --

    def _row_to_routine(self, row: tuple) -> Routine:
        return Routine(
            routine_id=row[0],
            user_id=row[1],
            name=row[2],
            description=row[3],
            trigger_type=row[4],
            trigger_config=json.loads(row[5]),
            action_config=json.loads(row[6]),
            enabled=bool(row[7]),
            last_run_at=row[8],
            next_run_at=row[9],
            cooldown_s=row[10],
            created_at=row[11],
            updated_at=row[12],
        )

    # -- CRUD --

    def count_for_user(self, user_id: str) -> int:
        """Return the number of routines owned by a user."""
        if self._db is not None:
            row = self._db.execute(
                "SELECT COUNT(*) FROM routines WHERE user_id = ?", (user_id,)
            ).fetchone()
            return row[0]
        return sum(1 for r in self._mem.values() if r.user_id == user_id)

    def create(
        self,
        name: str,
        trigger_type: str,
        trigger_config: dict,
        action_config: dict,
        user_id: str = "default",
        description: str = "",
        enabled: bool = True,
        cooldown_s: int = 0,
        next_run_at: str | None = None,
        max_per_user: int = 0,
    ) -> Routine:
        """Create a new routine and return it.

        If max_per_user > 0, raises ValueError when the user already owns
        that many routines.
        """
        if max_per_user > 0 and self.count_for_user(user_id) >= max_per_user:
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

        if self._db is not None:
            self._db.execute(
                """INSERT INTO routines
                   (routine_id, user_id, name, description, trigger_type,
                    trigger_config, action_config, enabled, next_run_at,
                    cooldown_s, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    routine_id, user_id, name, description, trigger_type,
                    json.dumps(trigger_config), json.dumps(action_config),
                    int(enabled), next_run_at, cooldown_s, now, now,
                ),
            )
            self._db.commit()
        else:
            self._mem[routine_id] = routine

        return routine

    def get(self, routine_id: str) -> Routine | None:
        """Fetch a single routine by ID."""
        if self._db is not None:
            row = self._db.execute(
                "SELECT * FROM routines WHERE routine_id = ?", (routine_id,)
            ).fetchone()
            return self._row_to_routine(row) if row else None
        return self._mem.get(routine_id)

    def list(
        self,
        user_id: str = "default",
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Routine]:
        """List routines for a user."""
        if self._db is not None:
            if enabled_only:
                rows = self._db.execute(
                    "SELECT * FROM routines WHERE user_id = ? AND enabled = 1 "
                    "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (user_id, limit, offset),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM routines WHERE user_id = ? "
                    "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (user_id, limit, offset),
                ).fetchall()
            return [self._row_to_routine(r) for r in rows]

        # In-memory fallback
        routines = [r for r in self._mem.values() if r.user_id == user_id]
        if enabled_only:
            routines = [r for r in routines if r.enabled]
        routines.sort(key=lambda r: r.created_at, reverse=True)
        return routines[offset:offset + limit]

    def list_due(self, now_iso: str) -> list[Routine]:
        """Find enabled routines whose next_run_at <= now.

        Used by the scheduler to find routines ready to execute.
        """
        if self._db is not None:
            rows = self._db.execute(
                "SELECT * FROM routines "
                "WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?",
                (now_iso,),
            ).fetchall()
            return [self._row_to_routine(r) for r in rows]

        # In-memory fallback
        return [
            r for r in self._mem.values()
            if r.enabled and r.next_run_at is not None and r.next_run_at <= now_iso
        ]

    def update(self, routine_id: str, **kwargs) -> Routine | None:
        """Update routine fields. Returns updated routine or None if not found.

        Accepts any Routine field name as a keyword argument.
        """
        routine = self.get(routine_id)
        if routine is None:
            return None

        now = _now_iso()
        kwargs["updated_at"] = now

        # Apply updates to a copy of the routine
        for key, value in kwargs.items():
            if hasattr(routine, key):
                setattr(routine, key, value)

        if self._db is not None:
            # Build SET clause from kwargs
            set_parts = []
            values = []
            for key, value in kwargs.items():
                if key in ("trigger_config", "action_config"):
                    set_parts.append(f"{key} = ?")
                    values.append(json.dumps(value))
                elif key == "enabled":
                    set_parts.append(f"{key} = ?")
                    values.append(int(value))
                else:
                    set_parts.append(f"{key} = ?")
                    values.append(value)
            values.append(routine_id)
            self._db.execute(
                f"UPDATE routines SET {', '.join(set_parts)} WHERE routine_id = ?",
                values,
            )
            self._db.commit()
        else:
            self._mem[routine_id] = routine

        return routine

    def delete(self, routine_id: str) -> bool:
        """Delete a routine. Returns True if it existed."""
        if self._db is not None:
            cursor = self._db.execute(
                "DELETE FROM routines WHERE routine_id = ?", (routine_id,)
            )
            self._db.commit()
            return cursor.rowcount > 0

        return self._mem.pop(routine_id, None) is not None

    def update_run_state(
        self,
        routine_id: str,
        last_run_at: str,
        next_run_at: str | None,
    ) -> None:
        """Update last_run_at and next_run_at after an execution."""
        if self._db is not None:
            self._db.execute(
                "UPDATE routines SET last_run_at = ?, next_run_at = ?, "
                "updated_at = ? WHERE routine_id = ?",
                (last_run_at, next_run_at, _now_iso(), routine_id),
            )
            self._db.commit()
        else:
            routine = self._mem.get(routine_id)
            if routine is not None:
                routine.last_run_at = last_run_at
                routine.next_run_at = next_run_at
                routine.updated_at = _now_iso()
