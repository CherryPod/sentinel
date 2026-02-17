import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.core.config import settings

logger = logging.getLogger("sentinel.audit")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class ConversationTurn:
    request_text: str
    result_status: str = ""          # "success", "blocked", "error", etc.
    blocked_by: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    timestamp: str = field(default_factory=_now_iso)
    plan_summary: str = ""           # What this turn did (for conversation history)


@dataclass
class Session:
    session_id: str
    source: str = ""
    turns: list[ConversationTurn] = field(default_factory=list)
    cumulative_risk: float = 0.0
    violation_count: int = 0
    is_locked: bool = False
    created_at: str = field(default_factory=_now_iso)
    last_active: str = field(default_factory=_now_iso)
    _db: sqlite3.Connection | None = field(default=None, repr=False)

    def add_turn(self, turn: ConversationTurn) -> None:
        self.turns.append(turn)
        self.last_active = _now_iso()
        if turn.result_status == "blocked":
            self.violation_count += 1
        # Write through to SQLite if db is available
        if self._db is not None:
            self._db.execute(
                "INSERT INTO conversation_turns "
                "(session_id, request_text, result_status, blocked_by, risk_score, plan_summary) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    self.session_id,
                    turn.request_text,
                    turn.result_status,
                    json.dumps(turn.blocked_by),
                    turn.risk_score,
                    turn.plan_summary,
                ),
            )
            self._db.execute(
                "UPDATE sessions SET last_active = ?, violation_count = ?, "
                "cumulative_risk = ? WHERE session_id = ?",
                (self.last_active, self.violation_count, self.cumulative_risk, self.session_id),
            )
            self._db.commit()

    def lock(self) -> None:
        self.is_locked = True
        logger.warning(
            "Session locked",
            extra={
                "event": "session_locked",
                "session_id": self.session_id,
                "violation_count": self.violation_count,
                "cumulative_risk": self.cumulative_risk,
            },
        )
        if self._db is not None:
            self._db.execute(
                "UPDATE sessions SET is_locked = 1 WHERE session_id = ?",
                (self.session_id,),
            )
            self._db.commit()


class SessionStore:
    """SQLite-backed session store with TTL eviction.

    When no db is provided, operates in-memory (for backward compatibility in tests).
    """

    def __init__(
        self,
        db: sqlite3.Connection | None = None,
        ttl: int | None = None,
        max_count: int | None = None,
    ):
        self._db = db
        self._ttl = ttl if ttl is not None else settings.session_ttl
        self._max_count = max_count if max_count is not None else settings.session_max_count

        # In-memory fallback for tests that don't pass a db
        self._sessions: dict[str, Session] | None = None if db is not None else {}

    def get_or_create(self, session_id: str | None, source: str = "") -> Session:
        """Get an existing session or create a new one."""
        if session_id is None:
            session_id = f"ephemeral-{uuid.uuid4()}"

        if self._db is not None:
            return self._get_or_create_sql(session_id, source)
        return self._get_or_create_mem(session_id, source)

    def get(self, session_id: str) -> Session | None:
        """Get a session by ID, or None if not found/expired."""
        if self._db is not None:
            return self._get_sql(session_id)
        return self._get_mem(session_id)

    @property
    def count(self) -> int:
        if self._db is not None:
            row = self._db.execute("SELECT COUNT(*) FROM sessions").fetchone()
            return row[0]
        return len(self._sessions)

    # ── SQLite implementation ──────────────────────────────────

    def _get_or_create_sql(self, session_id: str, source: str) -> Session:
        self._evict_expired_sql()

        row = self._db.execute(
            "SELECT session_id, source, cumulative_risk, violation_count, is_locked, "
            "created_at, last_active FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        if row is not None:
            # Update last_active
            now = _now_iso()
            self._db.execute(
                "UPDATE sessions SET last_active = ? WHERE session_id = ?",
                (now, session_id),
            )
            self._db.commit()
            return self._row_to_session(row, last_active_override=now)

        # Evict oldest if at capacity
        count = self._db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        if count >= self._max_count:
            self._evict_oldest_sql()

        now = _now_iso()
        self._db.execute(
            "INSERT INTO sessions (session_id, source, created_at, last_active) VALUES (?, ?, ?, ?)",
            (session_id, source, now, now),
        )
        self._db.commit()
        logger.info(
            "Session created",
            extra={"event": "session_created", "session_id": session_id, "source": source},
        )
        return Session(session_id=session_id, source=source, created_at=now, last_active=now, _db=self._db)

    def _get_sql(self, session_id: str) -> Session | None:
        row = self._db.execute(
            "SELECT session_id, source, cumulative_risk, violation_count, is_locked, "
            "created_at, last_active FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None

        # Check TTL
        is_expired = self._db.execute(
            "SELECT ? < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
            (row[6], f"-{self._ttl} seconds"),
        ).fetchone()[0]
        if is_expired:
            self._db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            self._db.commit()
            return None

        return self._row_to_session(row)

    def _row_to_session(self, row, last_active_override: str | None = None) -> Session:
        sid, source, cum_risk, viol_count, is_locked, created_at, last_active = row
        session = Session(
            session_id=sid,
            source=source,
            cumulative_risk=cum_risk,
            violation_count=viol_count,
            is_locked=bool(is_locked),
            created_at=created_at,
            last_active=last_active_override or last_active,
            _db=self._db,
        )
        # Load turns from db
        turn_rows = self._db.execute(
            "SELECT request_text, result_status, blocked_by, risk_score, plan_summary, created_at "
            "FROM conversation_turns WHERE session_id = ? ORDER BY id",
            (sid,),
        ).fetchall()
        for tr in turn_rows:
            session.turns.append(ConversationTurn(
                request_text=tr[0],
                result_status=tr[1],
                blocked_by=json.loads(tr[2]) if tr[2] else [],
                risk_score=tr[3],
                plan_summary=tr[4],
                timestamp=tr[5],
            ))
        return session

    def _evict_expired_sql(self) -> None:
        result = self._db.execute(
            "DELETE FROM sessions WHERE last_active < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
            (f"-{self._ttl} seconds",),
        )
        if result.rowcount > 0:
            self._db.commit()
            logger.info(
                "Sessions evicted (TTL)",
                extra={"event": "session_evict_ttl", "count": result.rowcount},
            )

    def _evict_oldest_sql(self) -> None:
        oldest = self._db.execute(
            "SELECT session_id FROM sessions ORDER BY last_active ASC LIMIT 1",
        ).fetchone()
        if oldest:
            self._db.execute("DELETE FROM sessions WHERE session_id = ?", (oldest[0],))
            self._db.commit()
            logger.info(
                "Session evicted (capacity)",
                extra={"event": "session_evict_capacity", "evicted_session_id": oldest[0]},
            )

    # ── In-memory implementation (backward compat for tests) ───

    def _get_or_create_mem(self, session_id: str, source: str) -> Session:
        self._evict_expired_mem()

        session = self._sessions.get(session_id)
        if session is not None:
            session.last_active = _now_iso()
            return session

        if len(self._sessions) >= self._max_count:
            self._evict_oldest_mem()

        session = Session(session_id=session_id, source=source)
        self._sessions[session_id] = session
        logger.info(
            "Session created",
            extra={"event": "session_created", "session_id": session_id, "source": source},
        )
        return session

    def _get_mem(self, session_id: str) -> Session | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        # TTL check using ISO timestamps
        now = datetime.now(timezone.utc)
        try:
            last = datetime.fromisoformat(session.last_active.replace("Z", "+00:00"))
            if (now - last).total_seconds() > self._ttl:
                del self._sessions[session_id]
                return None
        except (ValueError, AttributeError):
            pass
        return session

    def _evict_expired_mem(self) -> None:
        now = datetime.now(timezone.utc)
        expired = []
        for sid, s in self._sessions.items():
            try:
                last = datetime.fromisoformat(s.last_active.replace("Z", "+00:00"))
                if (now - last).total_seconds() > self._ttl:
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
