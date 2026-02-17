"""Session store with PostgreSQL backend and in-memory fallback.

Implements SessionStoreProtocol using asyncpg when a pool is provided.
When pool=None, operates entirely in-memory (for tests and backward compat).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

from sentinel.core.config import settings
from sentinel.core.context import current_user_id, get_task_id

logger = logging.getLogger("sentinel.audit")


# ── Shared helpers ────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _elapsed_seconds(iso_timestamp: str) -> float:
    """Seconds elapsed since an ISO-8601 timestamp (UTC)."""
    try:
        then = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - then).total_seconds())
    except (ValueError, AttributeError):
        return 0.0


def _dt_to_iso(dt: datetime | None) -> str:
    """Convert an asyncpg datetime to ISO 8601 string."""
    if dt is None:
        return _now_iso()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ── Data models ───────────────────────────────────────────────


@dataclass
class ConversationTurn:
    request_text: str
    result_status: str = ""          # "success", "blocked", "error", etc.
    blocked_by: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    timestamp: str = field(default_factory=_now_iso)
    plan_summary: str = ""           # What this turn did (for conversation history)
    auto_approved: bool = False      # True if plan was auto-approved at TL1+
    elapsed_s: float | None = None   # Task processing time in seconds
    step_outcomes: list[dict] | None = None  # F1: per-step metadata


@dataclass
class Session:
    session_id: str
    source: str = ""
    user_id: int = 0
    turns: list[ConversationTurn] = field(default_factory=list)
    cumulative_risk: float = 0.0
    violation_count: int = 0
    is_locked: bool = False
    task_in_progress: bool = False      # F2: crash-recovery flag (not a concurrency lock — see SYS-4/RACE-2)
    created_at: str = field(default_factory=_now_iso)
    last_active: str = field(default_factory=_now_iso)

    def add_turn(self, turn: ConversationTurn) -> None:
        """Mutate in-memory state only. Caller must persist via SessionStore.add_turn()."""
        self.turns.append(turn)
        self.last_active = _now_iso()
        if turn.result_status == "blocked":
            self.violation_count += 1

    def lock(self) -> None:
        """Mutate in-memory state only. Caller must persist via SessionStore.lock_session()."""
        self.is_locked = True
        logger.warning(
            "Session locked",
            extra={
                "event": "session_locked",
                "session_id": self.session_id,
                "violation_count": self.violation_count,
                "cumulative_risk": self.cumulative_risk,
                "task_id": get_task_id(),
            },
        )

    def set_task_in_progress(self, value: bool) -> None:
        """Mutate in-memory state only. Caller must persist via SessionStore.set_task_in_progress().

        NOTE (SYS-4/RACE-2): This is a crash-recovery flag, NOT a concurrency
        lock. It detects tasks that were running when the process died (set True
        before execution, cleared in finally). For mutual exclusion of concurrent
        requests on the same session, use SessionStore.get_lock() instead.
        """
        self.task_in_progress = value

    def apply_decay(
        self, elapsed_seconds: float, decay_per_minute: float, lock_timeout_s: int,
    ) -> bool:
        """Apply time-based risk decay (in-memory only).

        - If locked and elapsed >= lock_timeout: unlock, reset risk and violations.
        - Otherwise if risk > 0: decay risk. When risk hits 0, reset violations.

        Returns True if any values changed. Caller must persist via SessionStore.apply_decay().
        """
        if elapsed_seconds <= 1.0:
            return False

        changed = False

        if self.is_locked and elapsed_seconds >= lock_timeout_s:
            # Auto-unlock after timeout — full reset including turn history.
            # Turns must be cleared because rules like retry_after_block
            # compare new requests against blocked turns directly — leaving
            # stale blocked turns would re-trigger the same lock immediately.
            self.is_locked = False
            self.cumulative_risk = 0.0
            self.violation_count = 0
            self.turns.clear()
            changed = True
            logger.info(
                "Session auto-unlocked after timeout",
                extra={
                    "event": "session_auto_unlock",
                    "session_id": self.session_id,
                    "elapsed_s": elapsed_seconds,
                },
            )
        elif not self.is_locked and self.cumulative_risk > 0:
            # Decay risk proportionally to inactivity
            decay_amount = (elapsed_seconds / 60.0) * decay_per_minute
            new_risk = max(0.0, self.cumulative_risk - decay_amount)
            if new_risk != self.cumulative_risk:
                self.cumulative_risk = new_risk
                changed = True
                # Reset violations when risk fully decays
                if self.cumulative_risk == 0.0 and self.violation_count > 0:
                    self.violation_count = 0

        return changed


# ── Store ─────────────────────────────────────────────────────


class SessionStore:
    """PostgreSQL-backed session store with TTL eviction.

    When no pool is provided, operates in-memory (for tests).
    """

    def __init__(
        self,
        pool: Any = None,
        ttl: int | None = None,
        max_count: int | None = None,
    ):
        self._pool = pool
        self._in_memory = pool is None
        self._ttl = ttl if ttl is not None else settings.session_ttl
        self._max_count = max_count if max_count is not None else settings.session_max_count
        self._settings = settings

        # In-memory fallback for tests
        if self._in_memory:
            self._sessions: dict[str, Session] = {}

        # SYS-4: Per-session asyncio locks
        self._session_locks: dict[str, asyncio.Lock] = {}

    def get_lock(self, session_id: str) -> asyncio.Lock:
        # Intentionally cross-user — concurrency primitive, not data ownership.
        # Security is inherited: callers can only lock sessions they can see
        # (via user-scoped get_or_create/get).
        if session_id not in self._session_locks:
            self._session_locks[session_id] = asyncio.Lock()
        return self._session_locks[session_id]

    def _get_channel_ttl(self, source: str) -> int:
        channel_map = {
            "signal": self._settings.session_ttl_signal,
            "websocket": self._settings.session_ttl_websocket,
            "ws": self._settings.session_ttl_websocket,
            "api": self._settings.session_ttl_api,
            "mcp": self._settings.session_ttl_mcp,
            "routine": self._settings.session_ttl_routine,
        }
        return channel_map.get(source, self._ttl)

    # ── Core CRUD ──────────────────────────────────────────────

    async def get_or_create(self, session_id: str | None, source: str = "") -> Session:
        resolved_user_id = current_user_id.get()
        if session_id is None:
            session_id = f"ephemeral-{uuid.uuid4()}"

        if self._in_memory:
            return self._get_or_create_mem(session_id, source, resolved_user_id)

        async with self._pool.acquire() as conn:
            # Eviction runs under RLS — scoped to current user (correct for single-user)
            await self._evict_expired(conn)

            row = await conn.fetchrow(
                "SELECT session_id, source, user_id, cumulative_risk, violation_count, "
                "is_locked, created_at, last_active, task_in_progress "
                "FROM sessions WHERE session_id = $1 AND user_id = $2",
                session_id, resolved_user_id,
            )

            if row is not None:
                now = datetime.now(timezone.utc)
                await conn.execute(
                    "UPDATE sessions SET last_active = $1 "
                    "WHERE session_id = $2 AND user_id = $3",
                    now, session_id, resolved_user_id,
                )
                return await self._row_to_session(conn, row, last_active_override=now)

            # Count runs under RLS — scoped to current user (correct for single-user)
            count = await conn.fetchval("SELECT COUNT(*) FROM sessions")
            if count >= self._max_count:
                await self._evict_oldest(conn)

            now = datetime.now(timezone.utc)
            await conn.execute(
                "INSERT INTO sessions (session_id, source, user_id, created_at, last_active) "
                "VALUES ($1, $2, $3, $4, $5)",
                session_id, source, resolved_user_id, now, now,
            )
            logger.info(
                "Session created",
                extra={"event": "session_created", "session_id": session_id, "source": source},
            )
            return Session(
                session_id=session_id, source=source, user_id=resolved_user_id,
                created_at=_dt_to_iso(now), last_active=_dt_to_iso(now),
            )

    def _resolve_user_id(self, user_id: int | None) -> int:
        """Resolve user_id: explicit parameter wins, then ContextVar."""
        return user_id if user_id is not None else current_user_id.get()

    async def get(self, session_id: str, user_id: int | None = None) -> Session | None:
        resolved_user_id = self._resolve_user_id(user_id)
        if self._in_memory:
            return self._get_mem(session_id, resolved_user_id)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT session_id, source, user_id, cumulative_risk, violation_count, "
                "is_locked, created_at, last_active, task_in_progress "
                "FROM sessions WHERE session_id = $1 AND user_id = $2",
                session_id, resolved_user_id,
            )
            if row is None:
                return None

            # Per-channel TTL check
            source = row["source"]
            ttl = self._get_channel_ttl(source)
            if ttl > 0:
                deadline = datetime.now(timezone.utc) - timedelta(seconds=ttl)
                if row["last_active"] < deadline:
                    await conn.execute(
                        "DELETE FROM sessions WHERE session_id = $1", session_id,
                    )
                    return None

            return await self._row_to_session(conn, row)

    async def accumulate_risk(self, session_id: str, new_risk: float) -> None:
        if self._in_memory:
            session = self._sessions.get(session_id)
            if session is not None and new_risk > session.cumulative_risk:
                session.cumulative_risk = new_risk
            return

        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE sessions SET cumulative_risk = GREATEST(cumulative_risk, $1) "
                "WHERE session_id = $2",
                new_risk, session_id,
            )

    async def add_turn(
        self, session_id: str, turn: ConversationTurn,
        session: Session | None = None,
    ) -> None:
        if self._in_memory:
            # In-memory mode: no-op — Session.add_turn() already mutated the object
            return

        resolved_user_id = current_user_id.get()
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO conversation_turns "
                    "(session_id, user_id, request_text, result_status, blocked_by, risk_score, "
                    "plan_summary, auto_approved, elapsed_s, step_outcomes) "
                    "VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10::jsonb)",
                    session_id,
                    resolved_user_id,
                    turn.request_text,
                    turn.result_status,
                    json.dumps(turn.blocked_by),
                    turn.risk_score,
                    turn.plan_summary,
                    turn.auto_approved,
                    turn.elapsed_s,
                    json.dumps(turn.step_outcomes) if turn.step_outcomes is not None else None,
                )
                if session is not None:
                    await conn.execute(
                        "UPDATE sessions SET last_active = $1, violation_count = $2, "
                        "cumulative_risk = $3 WHERE session_id = $4",
                        datetime.now(timezone.utc), session.violation_count,
                        session.cumulative_risk, session_id,
                    )

    async def lock_session(self, session_id: str, user_id: int | None = None) -> None:
        resolved_user_id = self._resolve_user_id(user_id)
        if self._in_memory:
            session = self._sessions.get(session_id)
            if session is not None and session.user_id == resolved_user_id:
                session.is_locked = True
            return

        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE sessions SET is_locked = TRUE "
                "WHERE session_id = $1 AND user_id = $2",
                session_id, resolved_user_id,
            )

    async def set_task_in_progress(
        self, session_id: str, value: bool, user_id: int | None = None,
    ) -> None:
        resolved_user_id = self._resolve_user_id(user_id)
        if self._in_memory:
            session = self._sessions.get(session_id)
            if session is not None and session.user_id == resolved_user_id:
                session.task_in_progress = value
            return

        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE sessions SET task_in_progress = $1 "
                "WHERE session_id = $2 AND user_id = $3",
                value, session_id, resolved_user_id,
            )

    async def apply_decay(
        self, session_id: str, decay_per_min: float, lock_timeout_s: int,
        user_id: int | None = None,
    ) -> bool:
        resolved_user_id = self._resolve_user_id(user_id)
        if self._in_memory:
            session = self._sessions.get(session_id)
            if session is None or session.user_id != resolved_user_id:
                return False
            elapsed = _elapsed_seconds(session.last_active)
            return session.apply_decay(elapsed, decay_per_min, lock_timeout_s)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT cumulative_risk, violation_count, is_locked, last_active "
                "FROM sessions WHERE session_id = $1 AND user_id = $2",
                session_id, resolved_user_id,
            )
            if row is None:
                return False

            last_active_dt = row["last_active"]
            elapsed = max(0.0, (datetime.now(timezone.utc) - last_active_dt).total_seconds())

            temp = Session(
                session_id=session_id,
                cumulative_risk=row["cumulative_risk"],
                violation_count=row["violation_count"],
                is_locked=row["is_locked"],
                last_active=_dt_to_iso(last_active_dt),
            )
            was_locked = temp.is_locked
            changed = temp.apply_decay(elapsed, decay_per_min, lock_timeout_s)

            if changed:
                async with conn.transaction():
                    await conn.execute(
                        "UPDATE sessions SET cumulative_risk = $1, violation_count = $2, "
                        "is_locked = $3 WHERE session_id = $4 AND user_id = $5",
                        temp.cumulative_risk, temp.violation_count,
                        temp.is_locked, session_id, resolved_user_id,
                    )
                    if was_locked and not temp.is_locked:
                        await conn.execute(
                            "DELETE FROM conversation_turns WHERE session_id = $1",
                            session_id,
                        )
            return changed

    async def clear_turns(self, session_id: str) -> None:
        if self._in_memory:
            session = self._sessions.get(session_id)
            if session is not None:
                session.turns.clear()
            return

        async with self._pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM conversation_turns WHERE session_id = $1",
                session_id,
            )

    async def get_count(self) -> int:
        """Count active sessions.

        NOTE: Runs under RLS — returns count for current user only.
        For system-wide metrics in multi-user, use admin pool.
        """
        if self._in_memory:
            return len(self._sessions)

        async with self._pool.acquire() as conn:
            return await conn.fetchval("SELECT COUNT(*) FROM sessions")

    async def close(self) -> None:
        if self._in_memory:
            self._sessions = {}
            return
        # Pool lifecycle is managed by app.py lifespan, not by the store
        self._pool = None

    # ── PG row mapping ─────────────────────────────────────────

    async def _row_to_session(
        self, conn: Any, row: Any,
        last_active_override: datetime | None = None,
    ) -> Session:
        last_active_dt = row["last_active"]
        session = Session(
            session_id=row["session_id"],
            source=row["source"],
            user_id=row.get("user_id", 0),
            cumulative_risk=row["cumulative_risk"],
            violation_count=row["violation_count"],
            is_locked=row["is_locked"],
            task_in_progress=row["task_in_progress"],
            created_at=_dt_to_iso(row["created_at"]),
            last_active=_dt_to_iso(last_active_override or last_active_dt),
        )

        # Apply time-based risk decay
        elapsed = max(0.0, (datetime.now(timezone.utc) - last_active_dt).total_seconds())
        was_locked = session.is_locked
        changed = session.apply_decay(
            elapsed,
            self._settings.session_risk_decay_per_minute,
            self._settings.session_lock_timeout_s,
        )
        if changed:
            await conn.execute(
                "UPDATE sessions SET cumulative_risk = $1, violation_count = $2, "
                "is_locked = $3 WHERE session_id = $4",
                session.cumulative_risk, session.violation_count,
                session.is_locked, row["session_id"],
            )
            if was_locked and not session.is_locked:
                await conn.execute(
                    "DELETE FROM conversation_turns WHERE session_id = $1",
                    row["session_id"],
                )

        # Load recent turns (capped at 200)
        turn_rows = await conn.fetch(
            "SELECT request_text, result_status, blocked_by, risk_score, "
            "plan_summary, created_at, step_outcomes "
            "FROM conversation_turns WHERE session_id = $1 "
            "ORDER BY id DESC LIMIT 200",
            row["session_id"],
        )
        for tr in reversed(turn_rows):
            blocked = tr["blocked_by"] if tr["blocked_by"] else []
            if isinstance(blocked, str):
                blocked = json.loads(blocked)
            outcomes = tr["step_outcomes"]
            if isinstance(outcomes, str):
                outcomes = json.loads(outcomes)
            session.turns.append(ConversationTurn(
                request_text=tr["request_text"],
                result_status=tr["result_status"],
                blocked_by=blocked,
                risk_score=tr["risk_score"],
                plan_summary=tr["plan_summary"],
                timestamp=_dt_to_iso(tr["created_at"]),
                step_outcomes=outcomes,
            ))
        return session

    # ── PG eviction ────────────────────────────────────────────

    async def _evict_expired(self, conn: Any) -> None:
        # Runs under RLS — only evicts current user's expired sessions.
        # This is correct for single-user. For multi-user admin maintenance,
        # use the admin pool (sentinel_owner) to evict across all users.
        #
        # Uses global TTL (self._ttl) rather than per-channel TTL. This is
        # intentional: eviction is a coarse sweep for old sessions. Per-channel
        # TTL is applied at read time in get() for finer-grained expiry.
        deadline = datetime.now(timezone.utc) - timedelta(seconds=self._ttl)

        # Clean orphaned approvals for sessions being evicted
        evicted_ids = await conn.fetch(
            "SELECT session_id FROM sessions WHERE last_active < $1",
            deadline,
        )
        if evicted_ids:
            id_list = [r["session_id"] for r in evicted_ids]
            await conn.execute(
                "DELETE FROM approvals WHERE source_key = ANY($1)",
                id_list,
            )

        result = await conn.execute(
            "DELETE FROM sessions WHERE last_active < $1",
            deadline,
        )
        # asyncpg returns "DELETE N" string
        deleted = int(result.split()[-1]) if result else 0
        if deleted > 0:
            logger.info(
                "Sessions evicted (TTL)",
                extra={"event": "session_evict_ttl", "count": deleted},
            )

    async def _evict_oldest(self, conn: Any) -> None:
        # Runs under RLS — only evicts current user's oldest session.
        # This is correct for single-user. For multi-user admin maintenance,
        # use the admin pool (sentinel_owner) to evict across all users.
        oldest = await conn.fetchrow(
            "SELECT session_id FROM sessions ORDER BY last_active ASC LIMIT 1",
        )
        if oldest:
            sid = oldest["session_id"]
            await conn.execute("DELETE FROM approvals WHERE source_key = $1", sid)
            await conn.execute("DELETE FROM sessions WHERE session_id = $1", sid)
            logger.info(
                "Session evicted (capacity)",
                extra={"event": "session_evict_capacity", "evicted_session_id": sid},
            )

    # ── In-memory implementation ───────────────────────────────

    def _get_or_create_mem(self, session_id: str, source: str, user_id: int) -> Session:
        self._evict_expired_mem()

        session = self._sessions.get(session_id)
        if session is not None and session.user_id == user_id:
            # Apply risk decay before updating last_active
            elapsed = _elapsed_seconds(session.last_active)
            session.apply_decay(
                elapsed,
                self._settings.session_risk_decay_per_minute,
                self._settings.session_lock_timeout_s,
            )
            session.last_active = _now_iso()
            return session

        if len(self._sessions) >= self._max_count:
            self._evict_oldest_mem()

        session = Session(session_id=session_id, source=source, user_id=user_id)
        self._sessions[session_id] = session
        logger.info(
            "Session created",
            extra={"event": "session_created", "session_id": session_id, "source": source},
        )
        return session

    def _get_mem(self, session_id: str, user_id: int) -> Session | None:
        session = self._sessions.get(session_id)
        if session is None or session.user_id != user_id:
            return None
        # Apply risk decay
        elapsed = _elapsed_seconds(session.last_active)
        session.apply_decay(
            elapsed,
            self._settings.session_risk_decay_per_minute,
            self._settings.session_lock_timeout_s,
        )
        # Per-channel TTL check using ISO timestamps
        ttl = self._get_channel_ttl(session.source)
        if ttl == 0:
            # TTL=0 means never expires (e.g. routine sessions)
            return session
        now = datetime.now(timezone.utc)
        try:
            last = datetime.fromisoformat(session.last_active.replace("Z", "+00:00"))
            if (now - last).total_seconds() > ttl:
                del self._sessions[session_id]
                return None
        except (ValueError, AttributeError):
            pass
        return session

    def _evict_expired_mem(self) -> None:
        # Intentionally cross-user — system maintenance, must evict all expired sessions
        now = datetime.now(timezone.utc)
        expired = []
        for sid, s in self._sessions.items():
            ttl = self._get_channel_ttl(s.source)
            if ttl == 0:
                # TTL=0 means never expires (e.g. routine sessions)
                continue
            try:
                last = datetime.fromisoformat(s.last_active.replace("Z", "+00:00"))
                if (now - last).total_seconds() > ttl:
                    expired.append(sid)
            except (ValueError, AttributeError):
                continue
        if expired:
            logger.info(
                "Sessions evicted (TTL)",
                extra={"event": "session_evict_ttl", "count": len(expired)},
            )
        for sid in expired:
            del self._sessions[sid]

    def _evict_oldest_mem(self) -> None:
        # Intentionally cross-user — system maintenance
        if not self._sessions:
            return
        oldest_id = min(self._sessions, key=lambda sid: self._sessions[sid].last_active)
        logger.info(
            "Session evicted (capacity)",
            extra={
                "event": "session_evict_capacity",
                "evicted_session_id": oldest_id,
                "sessions_count": len(self._sessions),
            },
        )
        del self._sessions[oldest_id]

    # ── Metrics query methods ─────────────────────────────────

    async def get_auto_approved_count(self, cutoff: str | None = None) -> int:
        if self._in_memory:
            count = 0
            for session in self._sessions.values():
                for turn in session.turns:
                    if turn.auto_approved:
                        count += 1
            return count

        async with self._pool.acquire() as conn:
            if cutoff is not None:
                row = await conn.fetchval(
                    "SELECT COUNT(*) FROM conversation_turns "
                    "WHERE created_at >= $1::timestamptz AND auto_approved = TRUE",
                    cutoff,
                )
            else:
                row = await conn.fetchval(
                    "SELECT COUNT(*) FROM conversation_turns WHERE auto_approved = TRUE",
                )
            return row or 0

    async def get_turn_outcome_counts(self, cutoff: str | None = None) -> dict[str, int]:
        if self._in_memory:
            counts: dict[str, int] = {}
            for session in self._sessions.values():
                for turn in session.turns:
                    counts[turn.result_status] = counts.get(turn.result_status, 0) + 1
            return counts

        async with self._pool.acquire() as conn:
            if cutoff is not None:
                rows = await conn.fetch(
                    "SELECT result_status, COUNT(*) AS cnt FROM conversation_turns "
                    "WHERE created_at >= $1::timestamptz GROUP BY result_status",
                    cutoff,
                )
            else:
                rows = await conn.fetch(
                    "SELECT result_status, COUNT(*) AS cnt FROM conversation_turns "
                    "GROUP BY result_status",
                )
            return {r["result_status"]: r["cnt"] for r in rows}

    async def get_blocked_by_counts(self, cutoff: str | None = None) -> list[dict]:
        if self._in_memory:
            scanner_counts: dict[str, int] = {}
            for session in self._sessions.values():
                for turn in session.turns:
                    if turn.result_status == "blocked":
                        for scanner in turn.blocked_by:
                            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
            return [
                {"scanner": name, "count": count}
                for name, count in sorted(scanner_counts.items(), key=lambda x: -x[1])
            ]

        async with self._pool.acquire() as conn:
            if cutoff is not None:
                rows = await conn.fetch(
                    "SELECT blocked_by FROM conversation_turns "
                    "WHERE created_at >= $1::timestamptz AND result_status = 'blocked'",
                    cutoff,
                )
            else:
                rows = await conn.fetch(
                    "SELECT blocked_by FROM conversation_turns "
                    "WHERE result_status = 'blocked'",
                )

            scanner_counts_pg: dict[str, int] = {}
            for row in rows:
                blocked = row["blocked_by"]
                if isinstance(blocked, str):
                    try:
                        blocked = json.loads(blocked)
                    except (json.JSONDecodeError, TypeError):
                        continue
                if not blocked:
                    continue
                for scanner in blocked:
                    scanner_counts_pg[scanner] = scanner_counts_pg.get(scanner, 0) + 1

            return [
                {"scanner": name, "count": count}
                for name, count in sorted(scanner_counts_pg.items(), key=lambda x: -x[1])
            ]

    async def get_session_health(self) -> dict:
        """Aggregate session health metrics.

        NOTE: Runs under RLS — returns metrics for current user only.
        For system-wide health in multi-user, use admin pool.
        """
        if self._in_memory:
            if self._sessions:
                sessions = list(self._sessions.values())
                active = len(sessions)
                locked = sum(1 for s in sessions if s.is_locked)
                avg_risk = sum(s.cumulative_risk for s in sessions) / active
                total_violations = sum(s.violation_count for s in sessions)
                return {
                    "active": active,
                    "locked": locked,
                    "avg_risk": round(avg_risk, 3),
                    "total_violations": total_violations,
                }
            return {"active": 0, "locked": 0, "avg_risk": 0.0, "total_violations": 0}

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN is_locked THEN 1 ELSE 0 END) AS locked, "
                "AVG(cumulative_risk) AS avg_risk, "
                "SUM(violation_count) AS total_violations "
                "FROM sessions",
            )
            return {
                "active": row["total"] or 0,
                "locked": row["locked"] or 0,
                "avg_risk": round(float(row["avg_risk"] or 0.0), 3),
                "total_violations": row["total_violations"] or 0,
            }

    async def get_response_time_stats(self, cutoff: str | None = None) -> dict:
        from statistics import median

        if self._in_memory:
            values = []
            for session in self._sessions.values():
                for turn in session.turns:
                    if turn.elapsed_s is not None:
                        values.append(turn.elapsed_s)
            values.sort()
        else:
            async with self._pool.acquire() as conn:
                if cutoff is not None:
                    rows = await conn.fetch(
                        "SELECT elapsed_s FROM conversation_turns "
                        "WHERE created_at >= $1::timestamptz AND elapsed_s IS NOT NULL "
                        "ORDER BY elapsed_s",
                        cutoff,
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT elapsed_s FROM conversation_turns "
                        "WHERE elapsed_s IS NOT NULL ORDER BY elapsed_s",
                    )
                values = [r["elapsed_s"] for r in rows]

        count = len(values)
        if count == 0:
            return {"avg_s": 0.0, "p50_s": 0.0, "p95_s": 0.0, "count": 0}

        avg = round(sum(values) / count, 1)
        p50 = round(median(values), 1)
        p95_idx = min(int(0.95 * count + 0.5), count - 1)
        p95 = round(values[p95_idx], 1)

        return {"avg_s": avg, "p50_s": p50, "p95_s": p95, "count": count}


if TYPE_CHECKING:
    from sentinel.core.store_protocols import SessionStoreProtocol

    _: SessionStoreProtocol = cast(SessionStoreProtocol, SessionStore(None))
