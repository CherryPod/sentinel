"""Session store with PostgreSQL backend and in-memory fallback.

Implements SessionStoreProtocol using asyncpg when a pool is provided.
When pool=None, operates entirely in-memory (for tests and backward compat).
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cached_property
from statistics import median
from typing import TYPE_CHECKING, Any, cast

import asyncpg.exceptions

from sentinel.core.config import settings
from sentinel.core.context import current_user_id, get_task_id, require_user_id

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────

_MAX_TURNS_PER_SESSION = 200

# Q5-FL7 (C35.fix): deadlock-retry policy for ``_evict_expired``. PG SQLSTATE
# 40P01 raised inside the inner SAVEPOINT is recoverable via ROLLBACK TO
# SAVEPOINT (locks acquired since the savepoint are released; outer
# RLSPool.acquire() TX + LOCAL ``app.current_user_id`` survive). ``2`` retries
# = 3 total attempts. Backoff is full-jitter ``random.uniform(0, base * 2**n)``
# capped at ``_DEADLOCK_BACKOFF_CAP_S``. With the default 2 retries the cap is
# dormant (max raw backoff is 25 ms * 2 = 50 ms < 500 ms) — the cap exists as a
# defensive policy bound if ``_MAX_DEADLOCK_RETRIES`` is ever raised.
_MAX_DEADLOCK_RETRIES: int = 2
_DEADLOCK_BACKOFF_BASE_S: float = 0.025
_DEADLOCK_BACKOFF_CAP_S: float = 0.5

# ── Shared helpers ────────────────────────────────────────────


def _iso_to_dt(iso: str | None) -> datetime | None:
    """Parse ISO 8601 string to datetime for asyncpg TIMESTAMPTZ params."""
    if iso is None:
        return None
    return datetime.fromisoformat(iso)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _elapsed_seconds(iso_timestamp: str) -> float:
    """Seconds elapsed since an ISO-8601 timestamp (UTC)."""
    try:
        then = datetime.fromisoformat(iso_timestamp)
        return max(0.0, (datetime.now(UTC) - then).total_seconds())
    except (ValueError, AttributeError):
        logger.warning(
            "_elapsed_seconds: ValueError | AttributeError",
            extra={"event": "store._elapsed_seconds_error"},
            exc_info=True,
        )
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
    result_status: str = ""  # "success", "blocked", "error", etc.
    blocked_by: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    timestamp: str = field(default_factory=_now_iso)
    plan_summary: str = ""  # What this turn did (for conversation history)
    auto_approved: bool = False  # True if plan was auto-approved at TL1+
    elapsed_s: float | None = None  # Task processing time in seconds
    step_outcomes: list[dict] | None = None  # F1: per-step metadata
    # MTM fields — default to zero/empty so existing code is unaffected
    mtm_turn_score: float = 0.0
    mtm_signal_categories: list[str] = field(default_factory=list)


@dataclass
class Session:
    session_id: str
    source: str = ""
    user_id: int = 0
    turns: list[ConversationTurn] = field(default_factory=list)
    cumulative_risk: float = 0.0
    violation_count: int = 0
    is_locked: bool = False
    task_in_progress: bool = (
        False  # F2: crash-recovery flag (not a concurrency lock — see SYS-4/RACE-2)
    )
    success_forgives_used: int = 0  # Fix-cycle decay: how many security blocks have been forgiven by subsequent successes
    created_at: str = field(default_factory=_now_iso)
    last_active: str = field(default_factory=_now_iso)
    # MTM field — highest single-turn MTM score in session
    mtm_peak_score: float = 0.0

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
                "event": "session.locked",
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
        self,
        elapsed_seconds: float,
        decay_per_minute: float,
        lock_timeout_s: int,
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
            self.success_forgives_used = 0
            # mtm_peak_score reset: peak refers to a turn that no longer exists after
            # turns.clear() + DELETE FROM conversation_turns. Keeping a non-zero peak
            # with no turns would produce stale velocity calculations. D4.
            self.mtm_peak_score = 0.0
            self.turns.clear()
            changed = True
            logger.info(
                "Session auto-unlocked after timeout",
                extra={
                    "event": "session.auto_unlock",
                    "session_id": self.session_id,
                    "elapsed_s": elapsed_seconds,
                },
            )
        elif not self.is_locked and self.cumulative_risk > 0:
            # Decay risk proportionally to inactivity
            logger.debug(
                "apply_decay: risk decay entered",
                extra={"event": "store.apply_decay.entered"},
            )
            decay_amount = (elapsed_seconds / 60.0) * decay_per_minute
            new_risk = max(0.0, self.cumulative_risk - decay_amount)
            if new_risk != self.cumulative_risk:
                logger.debug(
                    "apply_decay: risk decayed",
                    extra={"event": "store.apply_decay.risk_changed"},
                )
                self.cumulative_risk = new_risk
                changed = True
                # Reset violations when risk fully decays
                if self.cumulative_risk == 0.0 and self.violation_count > 0:
                    logger.debug(
                        "apply_decay: violations reset",
                        extra={"event": "store.apply_decay.violations_reset"},
                    )
                    self.violation_count = 0
                    self.success_forgives_used = 0

        return changed


# ── Crash-reconciliation result ───────────────────────────────


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """Result of an atomic crash-reconciliation transaction (Property-D-honest).

    See cleanup-C48 design §3 Component 1 + Q17 design doc §D6 (re-adjudicated).
    Counts are observed-pending at clear-time — pending approvals/confirmations
    remain ``status='pending'`` and remain executable; cleanup is delegated to
    the existing 7-day periodic ``purge_old`` sweep.
    """

    session_id: str
    user_id: int
    cleared_at: str
    pending_approvals_observed_at_clear: int
    pending_confirmations_observed_at_clear: int
    session_age_s: int


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
        *,
        event_bus: Any,
    ):
        """Construct a session store.

        Q5-F6: ``event_bus`` is a **required keyword-only parameter** —
        deliberately NOT Optional, NOT None-defaultable. The D1 cascade
        design (Q5.fix.c / 9d) will publish ``session.evicted`` at each
        of the PG eviction call sites from this store; an Optional /
        None-default contract silently swallows the missing-dependency
        bug class (Q4-U1 lesson). Callers must pass a live
        :class:`~sentinel.core.bus.EventBus` instance at construction.
        Tests should inject a stub / real EventBus, not ``None``.
        """
        if event_bus is None:
            # Defence-in-depth: keyword-only + no default should make this
            # unreachable, but reject explicitly-passed ``None`` too so the
            # contract is loud rather than silent.
            raise TypeError(
                "SessionStore requires a non-None event_bus (Q5-F6); "
                "construct a sentinel.core.bus.EventBus() and pass it."
            )
        self._pool = pool
        self._in_memory = pool is None
        self._ttl = ttl if ttl is not None else settings.session_ttl
        self._max_count = (
            max_count if max_count is not None else settings.session_max_count
        )
        self._settings = settings
        self._event_bus = event_bus

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

    def _discard_lock_if_idle(self, session_id: str) -> None:
        """Drop the lock entry for an evicted session, but only when idle.

        Called from every session-eviction path (TTL, capacity) to prevent
        unbounded growth of ``_session_locks`` when producers generate
        unique-per-invocation source_keys (e.g. MCP's per-RPC task UUID,
        webhook's per-delivery UUID). Without this cleanup, `get_lock()`
        accumulates one entry per distinct source_key for process lifetime
        even after the underlying session row is TTL/capacity-evicted.

        Q5C-R1 amendment: the previous unconditional ``pop`` was a
        concurrency bug. If a live task held ``get_lock(source_key)`` when
        eviction ran on the same id, ``pop`` would orphan the holder's
        ``asyncio.Lock`` object while the holder still owned it. A second
        caller then hit ``get_lock()``, created a fresh ``Lock``, and
        bypassed serialisation — two in-flight tasks operating on the
        same session without mutual exclusion. ``.locked()`` guards
        against that: idle locks are popped (the common case for
        evicted-and-stale sessions); held locks stay until the holder
        releases, after which the next eviction sweep will pop them.
        Worst case is a one-cycle delay in memory reclamation — not a
        leak (eviction sweeps are recurring).
        """
        lock = self._session_locks.get(session_id)
        if lock is not None and not lock.locked():
            self._session_locks.pop(session_id, None)

    @cached_property
    def _channel_ttl_map(self) -> dict[str, int]:
        # Single source of truth for source-prefix → resolved TTL seconds.
        #
        # Keys are SOURCE PREFIXES — strings matched against the message's
        # ``source`` field after ``source.split(":", 1)[0]`` (see
        # ``_get_channel_ttl``). They are NOT settings attribute names.
        # E.g. the ``"signal"`` key matches ``source="signal"`` (not
        # ``source="session_ttl_signal"``).
        #
        # Values are RESOLVED TTL INTS read from ``self._settings`` — the
        # ``int`` value of ``session_ttl_<channel>``, in seconds. They are
        # NOT settings attribute names either; they are the ints those
        # attributes hold.
        #
        # Used by ``_get_channel_ttl`` (read-time lookup) and
        # ``_evict_expired`` (PG bucket sweep) so the two paths cannot
        # drift on which channels they recognise. Adding a new
        # operator-configurable channel TTL only requires extending this
        # map.
        #
        # Q5-FL6: cached on first access. ``self._settings`` is the
        # ``sentinel.core.config.settings`` singleton captured in
        # ``__init__``; production never mutates per-channel TTLs after
        # store construction. Caching is intentionally instance-scoped via
        # ``functools.cached_property`` so each store reads ``settings``
        # once at first access (not at import time, so test fixtures that
        # patch settings before constructing the store still observe the
        # patched values). Tests that mutate ``store._settings.session_ttl_*``
        # AFTER first access will see stale TTLs — none do today.
        return {
            "signal": self._settings.session_ttl_signal,
            "websocket": self._settings.session_ttl_websocket,
            "ws": self._settings.session_ttl_websocket,
            "api": self._settings.session_ttl_api,
            "mcp": self._settings.session_ttl_mcp,
            "routine": self._settings.session_ttl_routine,
        }

    def _get_channel_ttl(self, source: str) -> int:
        # Q5-F3: routine sessions bind via ``source=f"routine:{routine_id}"``
        # (sentinel/routines/engine.py:552,641) — never as bare "routine".
        # An exact-match lookup on the raw source would fall through to the
        # global default (3600s), silently ignoring ``session_ttl_routine=0``
        # ("never expire"). Split on ":" and use the prefix so both
        # ``"routine:{id}"`` and ``"routine:{id}:{exec_id}"`` bucket-match
        # against the ``"routine"`` key. Non-routine sources (``"signal"``,
        # ``"api"``, etc.) have no colon so ``split(":", 1)[0]`` == source.
        prefix = source.split(":", 1)[0] if source else ""
        return self._channel_ttl_map.get(prefix, self._ttl)

    # ── Core CRUD ──────────────────────────────────────────────

    async def get_or_create(self, session_id: str | None, source: str = "") -> Session:
        resolved_user_id = require_user_id(
            current_user_id.get(), "SessionStore.get_or_create"
        )
        if session_id is None:
            session_id = f"ephemeral-{uuid.uuid4()}"

        if self._in_memory:
            logger.debug(
                "get_or_create: in_memory",
                extra={
                    "event": "session.store.get_or_create.match",
                    "reason": "in_memory",
                },
            )  # auto:neg
            return self._get_or_create_mem(session_id, source, resolved_user_id)

        # Q5C-R1: outer RLSPool.acquire() wraps this entire block in a real
        # transaction. Publishes + lock-discards must happen only after the
        # outer commit — else a later failure inside the block (the INSERT,
        # for example) rolls back the eviction while the event has already
        # fired. ``_evict_expired`` / ``_evict_oldest`` now return the ids
        # actually deleted; we stash them and emit after ``acquire()`` exits.
        result: Session
        evicted_ttl: list[str] = []
        evicted_capacity: list[str] = []

        async with self._pool.acquire() as conn:
            # Eviction runs under RLS — scoped to current user (correct for single-user)
            evicted_ttl = await self._evict_expired(conn)

            row = await conn.fetchrow(
                "SELECT session_id, source, user_id, cumulative_risk, violation_count, "
                "is_locked, created_at, last_active, task_in_progress, "
                "success_forgives_used, mtm_peak_score "
                "FROM sessions WHERE session_id = $1 AND user_id = $2",
                session_id,
                resolved_user_id,
            )

            if row is not None:
                now = datetime.now(UTC)
                await conn.execute(
                    "UPDATE sessions SET last_active = $1 "
                    "WHERE session_id = $2 AND user_id = $3",
                    now,
                    session_id,
                    resolved_user_id,
                )
                result = await self._row_to_session(conn, row, last_active_override=now)
            else:
                # Count runs under RLS — scoped to current user (correct for single-user)
                count = await conn.fetchval("SELECT COUNT(*) FROM sessions")
                if count >= self._max_count:
                    logger.debug(
                        "get_or_create: count_gte_max_count",
                        extra={
                            "event": "session.store.get_or_create.match",
                            "reason": "count_gte_max_count",
                        },
                    )  # auto:neg
                    evicted_capacity = await self._evict_oldest(conn)

                now = datetime.now(UTC)
                await conn.execute(
                    "INSERT INTO sessions (session_id, source, user_id, created_at, last_active) "
                    "VALUES ($1, $2, $3, $4, $5)",
                    session_id,
                    source,
                    resolved_user_id,
                    now,
                    now,
                )
                logger.info(
                    "Session created",
                    extra={
                        "event": "session.created",
                        "session_id": session_id,
                        "source": source,
                    },
                )
                result = Session(
                    session_id=session_id,
                    source=source,
                    user_id=resolved_user_id,
                    created_at=_dt_to_iso(now),
                    last_active=_dt_to_iso(now),
                )
        # Outer acquire() committed here — now safe to publish + discard locks.

        for sid in evicted_ttl:
            self._discard_lock_if_idle(sid)
        if evicted_ttl:
            logger.info(
                "Sessions evicted (TTL)",
                extra={"event": "session.evict_ttl", "count": len(evicted_ttl)},
            )
            await self._event_bus.publish(
                "session.evicted",
                {"session_ids": evicted_ttl, "reason": "ttl_sweep"},
            )

        for sid in evicted_capacity:
            self._discard_lock_if_idle(sid)
        if evicted_capacity:
            logger.info(
                "Session evicted (capacity)",
                extra={
                    "event": "session.evict_capacity",
                    "evicted_session_id": evicted_capacity[0],
                },
            )
            await self._event_bus.publish(
                "session.evicted",
                {"session_ids": evicted_capacity, "reason": "capacity"},
            )

        return result

    def _resolve_user_id(self, user_id: int | None) -> int:
        """Resolve user_id: explicit parameter wins, then ContextVar. Q4 fail-closed on 0.

        Ripples PrincipalRequiredError to every caller that routes through
        this helper (lock_session, set_task_in_progress, apply_decay, get).
        """
        return require_user_id(user_id, "SessionStore._resolve_user_id")

    async def get(
        self,
        session_id: str,
        user_id: int | None = None,
        *,
        conn: Any | None = None,
    ) -> Session | None:
        logger.debug(
            "get called",
            extra={
                "event": "session.store.get",
                "session_id_len": len(session_id)
                if hasattr(session_id, "__len__")
                else 0,
                "user_id": user_id,
            },
        )  # auto:entry
        resolved_user_id = self._resolve_user_id(user_id)
        if self._in_memory:
            logger.debug(
                "get: in_memory",
                extra={"event": "session.store.get.match", "reason": "in_memory"},
            )  # auto:neg
            return self._get_mem(session_id, resolved_user_id)

        if conn is not None:
            # CRIT-11: caller already holds a pool connection; use it directly
            # to avoid a nested pool acquire that deadlocks on small pools.
            # _row_to_session is intentionally NOT called here: it persists
            # decay writes (UPDATE sessions, DELETE conversation_turns) and
            # loads conversation_turns — none of which belong inside the
            # caller's approval/confirmation transaction. Decay is applied
            # in-memory only to give the correct is_locked value.
            row = await conn.fetchrow(
                "SELECT session_id, source, user_id, cumulative_risk, violation_count, "
                "is_locked, created_at, last_active, task_in_progress, "
                "success_forgives_used, mtm_peak_score "
                "FROM sessions WHERE session_id = $1 AND user_id = $2",
                session_id,
                resolved_user_id,
            )
            if row is None:
                return None
            source = row["source"]
            ttl = self._get_channel_ttl(source)
            last_active_dt = row["last_active"]
            if ttl > 0 and last_active_dt < (datetime.now(UTC) - timedelta(seconds=ttl)):
                # Cascade-delete approvals and confirmations for the expired
                # session (SAVEPOINT inside the caller's transaction) so the
                # caller's subsequent UPDATE finds 0 rows and fails closed —
                # matching the non-conn path where _cascade_evicted_sessions
                # runs before returning None. Q5C-R1: session-level DELETE and
                # event publish are still deferred to the next normal get() to
                # avoid publishing before the outer transaction commits.
                logger.debug(
                    "get: conn_path_ttl_expired",
                    extra={
                        "event": "session.store.get.match",
                        "reason": "conn_path_ttl_expired",
                    },
                )  # auto:neg
                try:
                    async with conn.transaction():
                        await self._cascade_evicted_sessions(conn, [session_id])
                except Exception:
                    # Cascade failed (transient DB error). Log for observability
                    # and re-raise — the exception propagates to
                    # recheck_pending_action's except block which returns
                    # allow=False (fail-closed). Do NOT suppress: returning None
                    # here while the approval row is still present would allow
                    # the caller's UPDATE to succeed (security regression).
                    logger.warning(
                        "get: conn_path_cascade_failed — re-raising for fail-closed",
                        extra={
                            "event": "session.store.get.conn_path_cascade_error",
                            "error_category": "cascade_exception",
                        },
                        exc_info=True,
                    )
                    raise
                return None
            session = Session(
                session_id=row["session_id"],
                source=source,
                user_id=row.get("user_id", 0),
                cumulative_risk=row["cumulative_risk"],
                violation_count=row["violation_count"],
                is_locked=row["is_locked"],
                task_in_progress=row["task_in_progress"],
                success_forgives_used=row["success_forgives_used"],
                created_at=_dt_to_iso(row["created_at"]),
                last_active=_dt_to_iso(last_active_dt),
                mtm_peak_score=row["mtm_peak_score"],
            )
            elapsed = max(0.0, (datetime.now(UTC) - last_active_dt).total_seconds())
            session.apply_decay(
                elapsed,
                self._settings.session_risk_decay_per_minute,
                self._settings.session_lock_timeout_s,
            )
            return session

        # Q5C-R1: outer RLSPool.acquire() wraps this entire block in a
        # real transaction. Any publish / lock-discard inside the block
        # would fire even if the outer commit failed and the DELETE was
        # rolled back. So we collect ``read_time_ttl_evicted`` inside
        # and perform the publish + _discard_lock_if_idle after the
        # ``async with`` exits successfully. ``DELETE ... RETURNING`` is
        # preserved so the collected list is ``actually deleted by THIS
        # caller`` (not ``matched predicate`` — see
        # test_no_publish_when_returning_is_empty).
        result: Session | None = None
        read_time_ttl_evicted: list[str] = []

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT session_id, source, user_id, cumulative_risk, violation_count, "
                "is_locked, created_at, last_active, task_in_progress, "
                "success_forgives_used, mtm_peak_score "
                "FROM sessions WHERE session_id = $1 AND user_id = $2",
                session_id,
                resolved_user_id,
            )
            if row is None:
                return None

            # Per-channel TTL check
            source = row["source"]
            ttl = self._get_channel_ttl(source)
            if ttl > 0 and row["last_active"] < (
                datetime.now(UTC) - timedelta(seconds=ttl)
            ):
                # Q5-F2 (D1): atomic read-time cascade. The savepoint
                # gives us atomicity between cascade + session DELETE
                # within the outer TX (prevents half-cascade state
                # visible to orchestrator's read-before-lock at
                # planner/orchestrator.py).
                logger.debug(
                    "get: ttl_gt_0",
                    extra={"event": "session.store.get.match", "reason": "ttl_gt_0"},
                )  # auto:neg
                async with conn.transaction():
                    await self._cascade_evicted_sessions(conn, [session_id])
                    deleted_rows = await conn.fetch(
                        "DELETE FROM sessions WHERE session_id = $1 "
                        "RETURNING session_id",
                        session_id,
                    )
                read_time_ttl_evicted = [r["session_id"] for r in deleted_rows]
                # Fall through; result stays None. Publish + lock discard
                # happen after the outer acquire() commits.
            else:
                logger.debug(
                    "get: ttl_gt_0",
                    extra={"event": "session.store.get.clean", "reason": "ttl_gt_0"},
                )  # auto:neg
                result = await self._row_to_session(conn, row)
        # Outer acquire() committed here — it is now safe to publish.

        for sid in read_time_ttl_evicted:
            self._discard_lock_if_idle(sid)
        if read_time_ttl_evicted:
            logger.debug(
                "get: read_time_ttl_evicted",
                extra={
                    "event": "session.store.get.match",
                    "reason": "read_time_ttl_evicted",
                },
            )  # auto:neg
            await self._event_bus.publish(
                "session.evicted",
                {
                    "session_ids": read_time_ttl_evicted,
                    "reason": "read_time_ttl",
                },
            )
        return result

    async def accumulate_risk(
        self,
        session_id: str,
        new_risk: float,
        user_id: int | None = None,
    ) -> None:
        resolved_user_id = require_user_id(user_id, "SessionStore.accumulate_risk")
        if self._in_memory:
            session = self._sessions.get(session_id)
            if (
                session is not None
                and session.user_id == resolved_user_id
                and new_risk > session.cumulative_risk
            ):
                session.cumulative_risk = new_risk
            return

        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE sessions SET cumulative_risk = GREATEST(cumulative_risk, $1) "
                "WHERE session_id = $2 AND user_id = $3",
                new_risk,
                session_id,
                resolved_user_id,
            )

    async def add_turn(
        self,
        session_id: str,
        turn: ConversationTurn,
        session: Session | None = None,
    ) -> None:
        if self._in_memory:
            # In-memory mode: no-op — Session.add_turn() already mutated the object
            return

        resolved_user_id = require_user_id(
            current_user_id.get(), "SessionStore.add_turn"
        )
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO conversation_turns "
                    "(session_id, user_id, request_text, result_status, blocked_by, risk_score, "
                    "plan_summary, auto_approved, elapsed_s, step_outcomes, "
                    "mtm_turn_score, mtm_signal_categories) "
                    "VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10::jsonb, "
                    "$11, $12::jsonb)",
                    session_id,
                    resolved_user_id,
                    turn.request_text,
                    turn.result_status,
                    json.dumps(turn.blocked_by),
                    turn.risk_score,
                    turn.plan_summary,
                    turn.auto_approved,
                    turn.elapsed_s,
                    json.dumps(turn.step_outcomes)
                    if turn.step_outcomes is not None
                    else None,
                    turn.mtm_turn_score,
                    json.dumps(turn.mtm_signal_categories),
                )
                if session is not None:
                    await conn.execute(
                        "UPDATE sessions SET last_active = $1, violation_count = $2, "
                        "cumulative_risk = $3, success_forgives_used = $4, "
                        "mtm_peak_score = $5 WHERE session_id = $6 AND user_id = $7",
                        datetime.now(UTC),
                        session.violation_count,
                        session.cumulative_risk,
                        session.success_forgives_used,
                        session.mtm_peak_score,
                        session_id,
                        resolved_user_id,
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
                session_id,
                resolved_user_id,
            )

    async def set_task_in_progress(
        self,
        session_id: str,
        value: bool,
        user_id: int | None = None,
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
                value,
                session_id,
                resolved_user_id,
            )

    async def reconcile_crashed_session(
        self,
        session_id: str,
        user_id: int,
    ) -> ReconciliationResult | None:
        """Atomic check-and-clear of a session's stale ``task_in_progress`` flag.

        Property-D-honest semantics (cleanup-C48 design §3): observe + clear,
        do NOT invalidate pending approvals/confirmations. The two ``COUNT(*)``
        queries snapshot pending-row counts inside the same transaction as the
        flag-clear ``UPDATE``; rows are not modified.

        Returns ``ReconciliationResult`` only on the first successful clear of
        a stale flag. Returns ``None`` if (a) the flag wasn't ``TRUE`` (no
        crash), (b) another concurrent invocation already cleared it (predicate
        loses the race), or (c) the store is in-memory.

        Caller's in-memory ``Session.task_in_progress`` Python attribute is NOT
        mutated — the existing intake warning seam at
        ``_intake_processing._bind_and_validate_session`` reads the stale-True
        in-memory value and fires ``build_interrupted_task_warning`` before
        the new task overwrites the flag.
        """
        logger.debug(
            "reconcile_crashed_session called",
            extra={
                "event": "session.store.reconcile_crashed_session",
                "session_id_len": len(session_id)
                if hasattr(session_id, "__len__")
                else 0,
                "user_id": user_id,
            },
        )  # auto:entry
        if self._in_memory:
            return None

        async with self._pool.acquire() as conn, conn.transaction():
            cleared = await conn.fetchrow(
                "UPDATE sessions SET task_in_progress = FALSE "
                "WHERE session_id = $1 AND user_id = $2 "
                "AND task_in_progress = TRUE "
                "RETURNING session_id, created_at",
                session_id,
                user_id,
            )
            if cleared is None:
                return None
            approvals_count = await conn.fetchval(
                "SELECT COUNT(*) FROM approvals "
                "WHERE source_key = $1 AND user_id = $2 "
                "AND status = 'pending'",
                session_id,
                user_id,
            )
            confirmations_count = await conn.fetchval(
                "SELECT COUNT(*) FROM confirmations "
                "WHERE source_key = $1 AND user_id = $2 "
                "AND status = 'pending'",
                session_id,
                user_id,
            )

        cleared_at = _now_iso()
        session_age_s = int(_elapsed_seconds(_dt_to_iso(cleared["created_at"])))
        return ReconciliationResult(
            session_id=session_id,
            user_id=user_id,
            cleared_at=cleared_at,
            pending_approvals_observed_at_clear=int(approvals_count or 0),
            pending_confirmations_observed_at_clear=int(confirmations_count or 0),
            session_age_s=session_age_s,
        )

    async def apply_decay(
        self,
        session_id: str,
        decay_per_min: float,
        lock_timeout_s: int,
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
                "SELECT cumulative_risk, violation_count, is_locked, last_active, "
                "success_forgives_used, mtm_peak_score "
                "FROM sessions WHERE session_id = $1 AND user_id = $2",
                session_id,
                resolved_user_id,
            )
            if row is None:
                return False

            last_active_dt = row["last_active"]
            elapsed = max(0.0, (datetime.now(UTC) - last_active_dt).total_seconds())

            temp = Session(
                session_id=session_id,
                cumulative_risk=row["cumulative_risk"],
                violation_count=row["violation_count"],
                is_locked=row["is_locked"],
                last_active=_dt_to_iso(last_active_dt),
                success_forgives_used=row["success_forgives_used"],
                mtm_peak_score=row["mtm_peak_score"],
            )
            was_locked = temp.is_locked
            changed = temp.apply_decay(elapsed, decay_per_min, lock_timeout_s)

            if changed:
                async with conn.transaction():
                    await conn.execute(
                        "UPDATE sessions SET cumulative_risk = $1, violation_count = $2, "
                        "is_locked = $3, success_forgives_used = $4, mtm_peak_score = $5 "
                        "WHERE session_id = $6 AND user_id = $7",
                        temp.cumulative_risk,
                        temp.violation_count,
                        temp.is_locked,
                        temp.success_forgives_used,
                        temp.mtm_peak_score,
                        session_id,
                        resolved_user_id,
                    )
                    if was_locked and not temp.is_locked:
                        await conn.execute(
                            "DELETE FROM conversation_turns WHERE session_id = $1",
                            session_id,
                        )
            return changed

    async def clear_turns(
        self,
        session_id: str,
        user_id: int | None = None,
    ) -> None:
        resolved_user_id = require_user_id(user_id, "SessionStore.clear_turns")
        if self._in_memory:
            session = self._sessions.get(session_id)
            if session is not None and session.user_id == resolved_user_id:
                session.turns.clear()
            return

        async with self._pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM conversation_turns WHERE session_id = $1 AND user_id = $2",
                session_id,
                resolved_user_id,
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
        self,
        conn: Any,
        row: Any,
        last_active_override: datetime | None = None,
    ) -> Session:
        logger.debug(
            "_row_to_session called",
            extra={
                "event": "store._row_to_session",
                "session_id": row["session_id"],
            },
        )
        last_active_dt = row["last_active"]
        session = Session(
            session_id=row["session_id"],
            source=row["source"],
            user_id=row.get("user_id", 0),
            cumulative_risk=row["cumulative_risk"],
            violation_count=row["violation_count"],
            is_locked=row["is_locked"],
            task_in_progress=row["task_in_progress"],
            success_forgives_used=row["success_forgives_used"],
            created_at=_dt_to_iso(row["created_at"]),
            last_active=_dt_to_iso(last_active_override or last_active_dt),
            mtm_peak_score=row["mtm_peak_score"],
        )

        # Apply time-based risk decay
        elapsed = max(0.0, (datetime.now(UTC) - last_active_dt).total_seconds())
        was_locked = session.is_locked
        changed = session.apply_decay(
            elapsed,
            self._settings.session_risk_decay_per_minute,
            self._settings.session_lock_timeout_s,
        )
        if changed:
            await conn.execute(
                "UPDATE sessions SET cumulative_risk = $1, violation_count = $2, "
                "is_locked = $3, success_forgives_used = $4, mtm_peak_score = $5 "
                "WHERE session_id = $6 AND user_id = $7",
                session.cumulative_risk,
                session.violation_count,
                session.is_locked,
                session.success_forgives_used,
                session.mtm_peak_score,
                row["session_id"],
                row["user_id"],
            )
            if was_locked and not session.is_locked:
                await conn.execute(
                    "DELETE FROM conversation_turns WHERE session_id = $1",
                    row["session_id"],
                )

        # Load recent turns (capped at 200)
        turn_rows = await conn.fetch(
            "SELECT request_text, result_status, blocked_by, risk_score, "
            "plan_summary, created_at, step_outcomes, "
            "mtm_turn_score, mtm_signal_categories "
            "FROM conversation_turns WHERE session_id = $1 "
            f"ORDER BY id DESC LIMIT {_MAX_TURNS_PER_SESSION}",  # nosec B608 — _MAX_TURNS_PER_SESSION is an integer constant
            row["session_id"],
        )
        for tr in reversed(turn_rows):
            blocked = tr["blocked_by"] or []
            if isinstance(blocked, str):
                blocked = json.loads(blocked)
            outcomes = tr["step_outcomes"]
            if isinstance(outcomes, str):
                outcomes = json.loads(outcomes)
            categories = tr["mtm_signal_categories"] or []
            if isinstance(categories, str):
                categories = json.loads(categories)
            session.turns.append(
                ConversationTurn(
                    request_text=tr["request_text"],
                    result_status=tr["result_status"],
                    blocked_by=blocked,
                    risk_score=tr["risk_score"],
                    plan_summary=tr["plan_summary"],
                    timestamp=_dt_to_iso(tr["created_at"]),
                    step_outcomes=outcomes,
                    mtm_turn_score=tr["mtm_turn_score"],
                    mtm_signal_categories=categories,
                )
            )
        return session

    # ── PG eviction ────────────────────────────────────────────

    async def _cascade_evicted_sessions(
        self,
        conn: Any,
        session_ids: Sequence[str],
    ) -> None:
        """Delete approvals + confirmations keyed by evicted session ids.

        Q5-F2 (D1): called from the 3 PG eviction paths — read-time TTL hit
        in :meth:`get`, :meth:`_evict_expired`, and :meth:`_evict_oldest`
        — to purge approvals + confirmations whose ``source_key`` equals
        an evicted ``session_id``. The ``source_key == session_id``
        invariant is established at the binding sites, not at the schema:

        - session binding: ``sentinel/planner/intake.py:26-73``
          (``session_store.get_or_create(source_key, source=...)``)
        - plan approvals: ``sentinel/planner/_approval_gate.py:87-101``
          (persists ``ctx.source_key`` as ``source_key``)
        - confirmations: ``sentinel/router/fast_path.py:272-292``
          (``source_key = session.session_id``)

        Helper is a no-op on empty ``session_ids``. Callers must wrap
        their overall eviction in ``async with conn.transaction():`` so
        external observers see either the full pre-cascade state or the
        full post-cascade state (Q5-F2 atomicity — see orchestrator
        read-before-lock at ``planner/orchestrator.py:785-809``).
        """
        if not session_ids:
            return
        ids = list(session_ids)
        await conn.execute(
            "DELETE FROM approvals WHERE source_key = ANY($1)",
            ids,
        )
        await conn.execute(
            "DELETE FROM confirmations WHERE source_key = ANY($1)",
            ids,
        )

    def _cascade_evicted_sessions_mem(self, session_ids: Sequence[str]) -> None:
        """No-op stub — in-memory cascade deferred to umbrella Q5-U1.

        :class:`SessionStore` does not hold references to
        :class:`~sentinel.core.approval.ApprovalManager` or
        :class:`~sentinel.core.confirmation.ConfirmationGate` in-memory
        state, so the in-memory path cannot cascade without DI wiring.
        Wiring those refs into ``SessionStore.__init__`` would require
        touching startup / orchestrator constructors for a dev/test-only
        path — bad trade per precedent (Q4-U2 RLS-only reliance, Q4-U4
        admin-pool documentation without code guard). Production uses
        PG; in-memory is dev/test-only. Deferred as post-pass cleanup
        under umbrella Q5-U1.
        """
        # Intentionally no-op; see docstring for Q5-U1 deferral.
        return

    async def _evict_expired(self, conn: Any) -> list[str]:
        # Runs under RLS — only evicts current user's expired sessions.
        # This is correct for single-user. For multi-user admin maintenance,
        # use the admin pool (sentinel_owner) to evict across all users.
        #
        # Q5-F4 (Q5.fix.d / D2): per-channel-bucket sweep. Mirrors the
        # in-memory path's per-session TTL lookup (``_evict_expired_mem``
        # uses ``_get_channel_ttl`` and skips ``ttl == 0``) so PG and
        # in-memory eviction agree on which sessions are expired:
        #   - Each known channel (``signal``, ``websocket``/``ws``, ``api``,
        #     ``mcp``) selects with its own deadline. ``signal``'s
        #     ``session_ttl_signal=7200`` would otherwise be cut short by
        #     the global ``session_ttl=3600`` "coarse sweep".
        #   - Routine sessions (``source LIKE 'routine:%'`` or bare
        #     ``'routine'``) get ``session_ttl_routine=0`` ("never expire")
        #     and are explicitly excluded from every bucket — both via the
        #     ``ttl <= 0`` skip on the ``routine`` key and the default
        #     bucket's ``NOT LIKE 'routine:%'``/``!= 'routine'`` filters.
        #   - Anything else (``telegram``, ``email``, ``matrix``, ``a2a``,
        #     ``webhook``, …) falls into the default bucket and uses the
        #     global ``self._ttl`` deadline.
        #
        # Q5C-R1 contract: returns the ids actually deleted by THIS caller
        # (from DELETE ... RETURNING). Does NOT publish session.evicted and
        # does NOT discard session locks — both are deferred to the caller's
        # post-RLSPool-commit tail, because the RLSPool outer transaction
        # ``async with self._pool.acquire()`` wraps this helper. Publishing
        # inside the outer TX would fire even if a subsequent step in the
        # caller's acquire block raised and rolled back the DELETE. See
        # ``sentinel/core/rls.py`` RLSPool.acquire for outer-TX semantics.
        #
        # Q5D-R1 (merge-gate fix): per-channel preselects use ``FOR UPDATE``
        # row locks INSIDE the inner SAVEPOINT so a concurrent ``UPDATE
        # sessions SET last_active = ...`` (e.g. from another async task's
        # ``add_turn`` or ``get_or_create``) blocks until our outer TX
        # commits or rolls back — closes a refresh-after-preselect race
        # where a ``DELETE ... WHERE session_id = ANY($1)`` would otherwise
        # delete a session that was refreshed between preselect and delete.
        # The previous deadline-rechecking ``DELETE ... WHERE last_active <
        # deadline`` shape (pre-Q5.fix.d) had the same race for the cascade
        # helper but at least left the session row alive after a refresh;
        # the new id-keyed DELETE needs the row lock to preserve correctness.
        # Lock lifetime extends to OUTER ``RLSPool.acquire()`` commit (PG
        # row locks span the current transaction; a SAVEPOINT only releases
        # locks acquired inside it on rollback) — concurrent updaters wait
        # through the rest of ``get_or_create`` (later SELECT/COUNT/INSERT)
        # before unblocking. Acceptable: eviction runs at-most once per
        # ``get_or_create`` call, volume is low.
        #
        # Q5-FL7 (C35.fix): on PG SQLSTATE 40P01 (DeadlockDetectedError)
        # raised inside the inner SAVEPOINT, asyncpg issues ROLLBACK TO
        # SAVEPOINT, releasing all FOR UPDATE row locks held since the
        # savepoint. The retry loop re-enters a fresh savepoint via
        # ``_evict_expired_once`` with fresh ``now``, fresh per-channel
        # preselects, and fresh ``expired_ids``. The outer
        # ``RLSPool.acquire()`` TX, the LOCAL ``app.current_user_id`` config,
        # and the connection state are preserved. After
        # ``_MAX_DEADLOCK_RETRIES`` retries the original exception re-raises,
        # ``RLSPool.acquire()`` rolls back, and callers see today's behaviour
        # on persistent contention (intake → 503 IntakeResult; router →
        # propagated 500 via FastAPI handler).
        logger.debug(
            "_evict_expired called",
            extra={
                "event": "session.store._evict_expired",
                "conn_type": type(conn).__name__,
            },
        )  # auto:entry

        for attempt in range(_MAX_DEADLOCK_RETRIES + 1):
            try:
                result = await self._evict_expired_once(conn)
            except asyncpg.exceptions.DeadlockDetectedError:
                # Terminal attempt re-raises. Coding rules
                # forbids logging on except blocks that immediately
                # re-raise (no log + raise). Per-attempt observability
                # comes from the ``outcome=retry`` log below; the
                # success-after-retry path logs ``outcome=recovered_after_retry``
                # so the 3-branch decision (succeed-immediate /
                # succeed-after-retry / exhaust) is reconstructable.
                # Persistent-deadlock visibility is via the asyncpg
                # exception propagating to the caller's structured error
                # log (intake.bind_session at intake.py:91-104 already
                # logs ``event=db.error`` with ``exc_info=True``, which
                # captures DeadlockDetectedError + SQLSTATE on
                # exhaustion).
                if attempt >= _MAX_DEADLOCK_RETRIES:
                    raise
                backoff = min(
                    _DEADLOCK_BACKOFF_CAP_S,
                    random.uniform(0, _DEADLOCK_BACKOFF_BASE_S * (2**attempt)),
                )
                logger.info(
                    "_evict_expired deadlock — retrying",
                    extra={
                        "event": "session.store.evict_deadlock_retry",
                        "attempt": attempt + 1,
                        "max_attempts": _MAX_DEADLOCK_RETRIES + 1,
                        "backoff_s": backoff,
                        "outcome": "retry",
                    },
                )
                await asyncio.sleep(backoff)
                continue
            else:
                # Decision-branch logging on the recovered-after-retry
                # path (decision-branch logging on 3+ branch
                # chains"). Three branches:
                #   - succeed-immediate (attempt 0; debug entry log above)
                #   - succeed-after-retry (attempt > 0; this log)
                #   - exhaust (re-raise above; caller's db.error log)
                if attempt > 0:
                    logger.info(
                        "_evict_expired succeeded after deadlock retry",
                        extra={
                            "event": "session.store.evict_deadlock_retry",
                            "attempt": attempt + 1,
                            "max_attempts": _MAX_DEADLOCK_RETRIES + 1,
                            "outcome": "recovered_after_retry",
                        },
                    )
                return result

        # Unreachable — the loop body always returns or re-raises.
        # ``raise RuntimeError`` survives ``python -O`` (``assert`` strips
        # under -O leaving ``raise None`` → ``TypeError``).
        raise RuntimeError("_evict_expired retry loop exited without return or raise")

    async def _evict_expired_once(self, conn: Any) -> list[str]:
        """Run one attempt of the eviction body. Caller (``_evict_expired``)
        owns the deadlock-retry envelope; this helper raises
        ``DeadlockDetectedError`` to it on PG SQLSTATE 40P01.
        """
        now = datetime.now(UTC)
        channel_ttls = self._channel_ttl_map

        # The inner ``conn.transaction()`` is a SAVEPOINT under RLSPool's
        # outer TX — it gives atomicity between cascade + DELETE and scopes
        # the row locks acquired by ``FOR UPDATE`` preselects. Lock lifetime
        # extends to outer-TX commit (see Q5D-R1 comment on caller).
        async with conn.transaction():
            expired_ids: list[str] = []
            for source, ttl in channel_ttls.items():
                if ttl <= 0:
                    # Routine TTL=0 ("never expire") — never sweep via PG.
                    continue
                deadline = now - timedelta(seconds=ttl)
                rows = await conn.fetch(
                    "SELECT session_id FROM sessions "
                    "WHERE source = $1 AND last_active < $2 "
                    "FOR UPDATE",
                    source,
                    deadline,
                )
                expired_ids.extend(r["session_id"] for r in rows)

            # Default bucket: any source not in the per-channel map and
            # not a routine source. Examples today: telegram, email, matrix,
            # a2a, webhook, plus the empty string from
            # ``get_or_create(source="")``.
            default_deadline = now - timedelta(seconds=self._ttl)
            default_rows = await conn.fetch(
                "SELECT session_id FROM sessions "
                "WHERE source != ALL($1::text[]) "
                "AND source NOT LIKE 'routine:%' "
                "AND source != 'routine' "
                "AND last_active < $2 "
                "FOR UPDATE",
                list(channel_ttls.keys()),
                default_deadline,
            )
            expired_ids.extend(r["session_id"] for r in default_rows)

            if not expired_ids:
                return []

            await self._cascade_evicted_sessions(conn, expired_ids)
            deleted_rows = await conn.fetch(
                "DELETE FROM sessions WHERE session_id = ANY($1) RETURNING session_id",
                expired_ids,
            )

        return [r["session_id"] for r in deleted_rows]

    async def _evict_oldest(self, conn: Any) -> list[str]:
        # Runs under RLS — only evicts current user's oldest session.
        # This is correct for single-user. For multi-user admin maintenance,
        # use the admin pool (sentinel_owner) to evict across all users.
        #
        # Q5C-R1 contract: returns the id actually deleted by THIS caller
        # (from DELETE ... RETURNING). Does NOT publish session.evicted and
        # does NOT discard session locks — both are deferred to the caller's
        # post-RLSPool-commit tail (see ``_evict_expired`` docstring for the
        # outer-TX rationale).
        async with conn.transaction():
            oldest = await conn.fetchrow(
                "SELECT session_id FROM sessions ORDER BY last_active ASC LIMIT 1",
            )
            if oldest is None:
                return []
            sid = oldest["session_id"]
            await self._cascade_evicted_sessions(conn, [sid])
            deleted_rows = await conn.fetch(
                "DELETE FROM sessions WHERE session_id = $1 RETURNING session_id",
                sid,
            )

        return [r["session_id"] for r in deleted_rows]

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
            extra={
                "event": "session.created",
                "session_id": session_id,
                "source": source,
            },
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
        now = datetime.now(UTC)
        try:
            last = datetime.fromisoformat(session.last_active)
            if (now - last).total_seconds() > ttl:
                del self._sessions[session_id]
                self._discard_lock_if_idle(session_id)
                return None
        except (ValueError, AttributeError):
            logger.debug(
                "_get_mem: ValueError | AttributeError suppressed",
                extra={"event": "store._get_mem.suppressed"},
                exc_info=True,
            )
        return session

    def _evict_expired_mem(self) -> None:
        # Intentionally cross-user — system maintenance, must evict all expired sessions
        now = datetime.now(UTC)
        expired = []
        for sid, s in self._sessions.items():
            ttl = self._get_channel_ttl(s.source)
            if ttl == 0:
                # TTL=0 means never expires (e.g. routine sessions)
                continue
            try:
                last = datetime.fromisoformat(s.last_active)
                if (now - last).total_seconds() > ttl:
                    expired.append(sid)
            except (ValueError, AttributeError):
                logger.debug(
                    "Skipping session with unparseable last_active",
                    extra={
                        "event": "store.evict_expired.parse_error",
                        "session_id": sid,
                    },
                    exc_info=True,
                )
                continue
        if expired:
            logger.info(
                "Sessions evicted (TTL)",
                extra={"event": "session.evict_ttl", "count": len(expired)},
            )
        for sid in expired:
            del self._sessions[sid]
            self._discard_lock_if_idle(sid)

    def _evict_oldest_mem(self) -> None:
        # Intentionally cross-user — system maintenance
        if not self._sessions:
            return
        oldest_id = min(self._sessions, key=lambda sid: self._sessions[sid].last_active)
        logger.info(
            "Session evicted (capacity)",
            extra={
                "event": "session.evict_capacity",
                "evicted_session_id": oldest_id,
                "sessions_count": len(self._sessions),
            },
        )
        del self._sessions[oldest_id]
        self._discard_lock_if_idle(oldest_id)

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
                    _iso_to_dt(cutoff),
                )
            else:
                row = await conn.fetchval(
                    "SELECT COUNT(*) FROM conversation_turns WHERE auto_approved = TRUE",
                )
            return row or 0

    async def get_turn_outcome_counts(
        self, cutoff: str | None = None
    ) -> dict[str, int]:
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
                    _iso_to_dt(cutoff),
                )
            else:
                rows = await conn.fetch(
                    "SELECT result_status, COUNT(*) AS cnt FROM conversation_turns "
                    "GROUP BY result_status",
                )
            return {r["result_status"]: r["cnt"] for r in rows}

    async def get_blocked_by_counts(self, cutoff: str | None = None) -> list[dict]:
        if self._in_memory:
            logger.debug(
                "get_blocked_by_counts: in_memory",
                extra={
                    "event": "store.get_blocked_by_counts.match",
                    "reason": "in_memory",
                },
            )  # auto:neg
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
                    _iso_to_dt(cutoff),
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
                        logger.debug(
                            "get_blocked_by_counts: unparseable blocked_by",
                            extra={"event": "store.get_blocked_by_counts.parse_error"},
                            exc_info=True,
                        )
                        continue
                if not blocked:
                    continue
                for scanner in blocked:
                    scanner_counts_pg[scanner] = scanner_counts_pg.get(scanner, 0) + 1

            return [
                {"scanner": name, "count": count}
                for name, count in sorted(
                    scanner_counts_pg.items(), key=lambda x: -x[1]
                )
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
        logger.debug(
            "get_response_time_stats called",
            extra={"event": "store.get_response_time_stats", "cutoff": cutoff},
        )
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
                        _iso_to_dt(cutoff),
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
    from sentinel.core.bus import EventBus as _EventBus
    from sentinel.core.store_protocols import SessionStoreProtocol

    # Q5-F6: event_bus is a required ctor param — pass a stub EventBus for the
    # protocol-compliance type check.
    _: SessionStoreProtocol = cast(
        "SessionStoreProtocol", SessionStore(None, event_bus=_EventBus())
    )
