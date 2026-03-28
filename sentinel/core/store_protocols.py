"""Protocol definitions for all store interfaces.

These define the contracts that the PostgreSQL backend (and in-memory dict
fallback for tests) must satisfy. Used for type checking and abstraction.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import asyncio

    from sentinel.channels.webhook import WebhookConfig
    from sentinel.core.confirmation import ConfirmationEntry
    from sentinel.core.models import DataSource, Plan, TaggedData, TrustLevel
    from sentinel.memory.chunks import MemoryChunk
    from sentinel.memory.episodic import EpisodicFact, EpisodicRecord
    from sentinel.routines.store import Routine
    from sentinel.session.store import ConversationTurn, Session


# ---------------------------------------------------------------------------
# SessionStore
# ---------------------------------------------------------------------------


@runtime_checkable
class SessionStoreProtocol(Protocol):
    """Manages sessions and conversation turns."""

    def get_lock(self, session_id: str) -> asyncio.Lock: ...

    async def get_or_create(self, session_id: str | None, source: str = "") -> Session: ...

    async def get(self, session_id: str, user_id: int | None = None) -> Session | None: ...

    async def accumulate_risk(self, session_id: str, new_risk: float) -> None: ...

    async def add_turn(
        self,
        session_id: str,
        turn: ConversationTurn,
        session: Session | None = None,
    ) -> None: ...

    async def lock_session(self, session_id: str, user_id: int | None = None) -> None: ...

    async def set_task_in_progress(
        self, session_id: str, value: bool, user_id: int | None = None,
    ) -> None: ...

    async def apply_decay(
        self, session_id: str, decay_per_min: float, lock_timeout_s: int,
        user_id: int | None = None,
    ) -> bool: ...

    async def clear_turns(self, session_id: str) -> None: ...

    async def get_count(self) -> int: ...

    async def close(self) -> None: ...

    # -- Metrics methods --

    async def get_auto_approved_count(self, cutoff: str | None = None) -> int: ...

    async def get_turn_outcome_counts(
        self, cutoff: str | None = None
    ) -> dict[str, int]: ...

    async def get_blocked_by_counts(
        self, cutoff: str | None = None
    ) -> list[dict]: ...

    async def get_session_health(self) -> dict: ...

    async def get_response_time_stats(self, cutoff: str | None = None) -> dict: ...


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------


@runtime_checkable
class MemoryStoreProtocol(Protocol):
    """Manages memory chunks with optional FTS and vector storage."""

    async def store(
        self,
        content: str,
        source: str = "",
        metadata: dict | None = None,
        user_id: int = 1,
    ) -> str: ...

    async def store_with_embedding(
        self,
        content: str,
        embedding: list[float],
        source: str = "",
        metadata: dict | None = None,
        user_id: int = 1,
    ) -> str: ...

    async def get(self, chunk_id: str, user_id: int = 1) -> MemoryChunk | None: ...

    async def list_chunks(
        self,
        user_id: int = 1,
        limit: int = 50,
        offset: int = 0,
        source: str | None = None,
    ) -> list[MemoryChunk]: ...

    async def update(
        self,
        chunk_id: str,
        content: str,
        metadata: dict | None = None,
        user_id: int = 1,
    ) -> bool: ...

    async def delete(self, chunk_id: str, user_id: int = 1) -> bool: ...

    async def get_latest_by_source(self, source: str, user_id: int = 1) -> MemoryChunk | None: ...

    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# ProvenanceStore
# ---------------------------------------------------------------------------


@runtime_checkable
class ProvenanceStoreProtocol(Protocol):
    """Tracks data provenance and trust levels."""

    async def create_tagged_data(
        self,
        content: str,
        source: DataSource,
        trust_level: TrustLevel,
        originated_from: str = "",
        parent_ids: list[str] | None = None,
        user_id: int | None = None,
    ) -> TaggedData: ...

    async def get_tagged_data(self, data_id: str, user_id: int | None = None) -> TaggedData | None: ...

    async def update_content(self, data_id: str, content: str, user_id: int | None = None) -> bool: ...

    async def get_provenance_chain(
        self, data_id: str, max_depth: int = 50, user_id: int | None = None
    ) -> list[TaggedData]: ...

    async def is_trust_safe_for_execution(self, data_id: str) -> bool: ...

    async def record_file_write(self, path: str, data_id: str, content: str | bytes = "", user_id: int | None = None) -> None: ...

    async def get_file_writer(self, path: str, user_id: int | None = None) -> tuple[str, str] | None: ...

    async def cleanup_old(self, days: int = 7, user_id: int | None = None) -> int: ...

    async def reset_store(self) -> None: ...


# ---------------------------------------------------------------------------
# ApprovalManager
# ---------------------------------------------------------------------------


@runtime_checkable
class ApprovalManagerProtocol(Protocol):
    """Manages plan approval workflows."""

    async def cleanup_and_notify(self) -> list[dict]: ...

    async def request_plan_approval(
        self,
        plan: Plan,
        source_key: str = "",
        user_request: str = "",
    ) -> str: ...

    async def check_approval(self, approval_id: str) -> dict: ...

    async def submit_approval(
        self,
        approval_id: str,
        granted: bool,
        reason: str = "",
        approved_by: str = "api",
    ) -> bool: ...

    async def get_plan(self, approval_id: str) -> Plan | None: ...

    async def is_approved(self, approval_id: str) -> bool | None: ...

    async def get_pending(self, approval_id: str) -> dict | None: ...

    async def get_pending_by_source_key(self, source_key: str) -> dict | None: ...

    async def purge_old(self, days: int = 7, user_id: int | None = None) -> int: ...

    async def get_status_counts(self, cutoff: str | None = None) -> dict[str, int]: ...

    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# ConfirmationGate
# ---------------------------------------------------------------------------


@runtime_checkable
class ConfirmationGateProtocol(Protocol):
    """Action-level confirmation gate for outbound side effects."""

    async def create(
        self,
        user_id: int,
        channel: str,
        source_key: str,
        tool_name: str,
        tool_params: dict,
        preview_text: str,
        original_request: str,
        task_id: str,
    ) -> str: ...

    async def get_pending(self, source_key: str) -> ConfirmationEntry | None: ...

    async def confirm(self, confirmation_id: str) -> ConfirmationEntry | None: ...

    async def cancel(self, confirmation_id: str) -> None: ...

    async def cleanup_expired(self) -> int: ...

    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# RoutineStore
# ---------------------------------------------------------------------------


@runtime_checkable
class RoutineStoreProtocol(Protocol):
    """CRUD for routine definitions."""

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
    ) -> Routine: ...

    async def get(self, routine_id: str) -> Routine | None: ...

    async def list(
        self,
        user_id: int = 1,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Routine]: ...

    async def update(self, routine_id: str, **kwargs) -> Routine | None: ...

    async def delete(self, routine_id: str) -> bool: ...

    async def list_due(self, now_iso: str) -> list[Routine]: ...

    async def list_event_triggered(self, enabled_only: bool = True) -> list[Routine]: ...

    async def update_run_state(
        self, routine_id: str, last_run_at: str, next_run_at: str | None
    ) -> None: ...

    async def count_for_user(self, user_id: int) -> int: ...


# ---------------------------------------------------------------------------
# RoutineEngine (DB-facing methods only)
# ---------------------------------------------------------------------------


@runtime_checkable
class RoutineEngineProtocol(Protocol):
    """DB-facing methods of the routine execution engine."""

    async def get_execution_history(
        self,
        routine_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]: ...

    async def get_execution_stats(self, cutoff: str | None = None) -> dict: ...


# ---------------------------------------------------------------------------
# EpisodicStore
# ---------------------------------------------------------------------------


@runtime_checkable
class EpisodicStoreProtocol(Protocol):
    """Manages episodic memory records and facts."""

    async def create(
        self,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: int = 1,
    ) -> str: ...

    async def get(self, record_id: str, user_id: int | None = None) -> EpisodicRecord | None: ...

    async def list_by_session(
        self, session_id: str, user_id: int | None = None, limit: int = 50,
    ) -> list[EpisodicRecord]: ...

    async def list_by_file(
        self, file_path: str, user_id: int = 1, limit: int = 50
    ) -> list[EpisodicRecord]: ...

    async def delete(self, record_id: str, user_id: int | None = None) -> bool: ...

    async def find_linked_records(
        self, file_paths: list[str], user_id: int = 1, exclude_record_id: str = ""
    ) -> list[str]: ...

    async def prune_stale(
        self, threshold: float = 0.05, min_age_days: int = 30, user_id: int | None = None
    ) -> int: ...

    async def update_access(self, record_id: str, user_id: int | None = None) -> None: ...

    async def batch_update_access(self, record_ids: list[str], user_id: int | None = None) -> None: ...

    async def set_memory_chunk_id(self, record_id: str, chunk_id: str, user_id: int | None = None) -> None: ...

    async def create_with_shadow(
        self,
        memory_store,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: int = 1,
        embedding: list[float] | None = None,
    ) -> str: ...

    async def store_facts(
        self, record_id: str, facts: list[EpisodicFact], user_id: int = 1
    ) -> None: ...

    async def search_facts(
        self,
        query: str,
        fact_type: str | None = None,
        user_id: int = 1,
        limit: int = 20,
    ) -> list[EpisodicFact]: ...


# ---------------------------------------------------------------------------
# WebhookRegistry
# ---------------------------------------------------------------------------


@runtime_checkable
class WebhookRegistryProtocol(Protocol):
    """Manages webhook registrations."""

    async def register(
        self,
        name: str,
        secret: str,
        user_id: int = 1,
    ) -> WebhookConfig: ...

    async def get(self, webhook_id: str) -> WebhookConfig | None: ...

    async def delete(self, webhook_id: str) -> bool: ...

    async def list(self, user_id: int | None = None) -> list[WebhookConfig]: ...
