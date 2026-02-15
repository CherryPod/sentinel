import logging
import time
import threading
import uuid
from dataclasses import dataclass, field

from .config import settings

logger = logging.getLogger("sentinel.audit")


@dataclass
class ConversationTurn:
    request_text: str
    result_status: str = ""          # "success", "blocked", "error", etc.
    blocked_by: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    timestamp: float = field(default_factory=time.monotonic)
    plan_summary: str = ""           # What this turn did (for conversation history)


@dataclass
class Session:
    session_id: str
    source: str = ""
    turns: list[ConversationTurn] = field(default_factory=list)
    cumulative_risk: float = 0.0
    violation_count: int = 0
    is_locked: bool = False
    created_at: float = field(default_factory=time.monotonic)
    last_active: float = field(default_factory=time.monotonic)

    def add_turn(self, turn: ConversationTurn) -> None:
        self.turns.append(turn)
        self.last_active = time.monotonic()
        if turn.result_status == "blocked":
            self.violation_count += 1

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


class SessionStore:
    """Thread-safe in-memory session store with TTL eviction."""

    def __init__(
        self,
        ttl: int | None = None,
        max_count: int | None = None,
    ):
        self._ttl = ttl if ttl is not None else settings.session_ttl
        self._max_count = max_count if max_count is not None else settings.session_max_count
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str | None, source: str = "") -> Session:
        """Get an existing session or create a new one.

        If session_id is None, generates an ephemeral session ID.
        """
        if session_id is None:
            session_id = f"ephemeral-{uuid.uuid4()}"

        with self._lock:
            self._evict_expired()

            session = self._sessions.get(session_id)
            if session is not None:
                session.last_active = time.monotonic()
                return session

            # Evict oldest if at capacity
            if len(self._sessions) >= self._max_count:
                self._evict_oldest()

            session = Session(session_id=session_id, source=source)
            self._sessions[session_id] = session
            logger.info(
                "Session created",
                extra={
                    "event": "session_created",
                    "session_id": session_id,
                    "source": source,
                },
            )
            return session

    def get(self, session_id: str) -> Session | None:
        """Get a session by ID, or None if not found/expired."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if time.monotonic() - session.last_active > self._ttl:
                del self._sessions[session_id]
                return None
            return session

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _evict_expired(self) -> None:
        """Remove sessions that have exceeded TTL. Must be called with lock held."""
        now = time.monotonic()
        expired = [
            sid for sid, s in self._sessions.items()
            if now - s.last_active > self._ttl
        ]
        if expired:
            logger.info(
                "Sessions evicted (TTL)",
                extra={"event": "session_evict_ttl", "count": len(expired)},
            )
        for sid in expired:
            del self._sessions[sid]

    def _evict_oldest(self) -> None:
        """Remove the oldest session by last_active. Must be called with lock held."""
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
