"""Safe tool wrappers — planner-side tool execution with trust gating.

Provides SafeToolHandlers, a set of tool methods the planner can call
directly without going through the worker. Each method enforces trust
level checks, validates arguments, and wraps results as TaggedData with
appropriate provenance. These are "safe" because they run in the
controller process (not in the sandboxed worker) and produce data the
planner is allowed to see.

Facade: handler methods live in category mixins (_safe_memory_tools,
_safe_session_tools). This module provides the class, __init__, setters,
get_descriptions, and re-exports SAFE_HANDLERS for backward compatibility.
"""

import logging

from sentinel.memory.episodic import EpisodicStore
from sentinel.worker.base import EmbeddingBase

from ._safe_memory_tools import MemoryToolsMixin
from ._safe_session_tools import SessionToolsMixin
from ._safe_tool_registry import SAFE_HANDLERS

__all__ = ["SAFE_HANDLERS", "SafeToolHandlers"]

logger = logging.getLogger(__name__)


class SafeToolHandlers(MemoryToolsMixin, SessionToolsMixin):
    """Handlers for SAFE internal tools (no Qwen involvement, no scanning needed).

    These are tools the planner can invoke directly — health checks, memory
    operations, session info, routine queries. They never touch the worker
    or the security pipeline.
    """

    def __init__(
        self,
        *,
        planner=None,
        pipeline=None,
        memory_store=None,
        embedding_client: EmbeddingBase | None = None,
        session_store=None,
        event_bus=None,
        routine_store=None,
        routine_engine=None,
        episodic_store: EpisodicStore | None = None,
    ):
        self._planner = planner
        self._pipeline = pipeline
        self._memory_store = memory_store
        self._embedding_client = embedding_client
        self._session_store = session_store
        self._event_bus = event_bus
        self._routine_store = routine_store
        self._routine_engine = routine_engine
        self._episodic_store = episodic_store

    def set_routine_engine(self, engine) -> None:
        """Update routine engine after construction."""
        logger.debug(
            "set_routine_engine called",
            extra={
                "event": "set.routine_engine",
                "engine_type": type(engine).__name__ if engine else "None",
            },
        )
        self._routine_engine = engine

    def set_episodic_store(self, store: EpisodicStore | None) -> None:
        """Update episodic store after construction."""
        logger.debug(
            "set_episodic_store called",
            extra={
                "event": "set.episodic_store",
                "store_type": type(store).__name__ if store else "None",
            },
        )
        self._episodic_store = store

    def get_descriptions(self) -> list[dict]:
        """Return tool description dicts for SAFE internal tools.

        Routine tools are conditionally included based on whether
        _routine_store / _routine_engine are available.
        """
        tools = [
            {
                "name": "health_check",
                "description": "Check component availability (planner, Semgrep, Prompt Guard, sidecar, signal). Returns JSON status dict.",
                "args": {},
            },
            {
                "name": "session_info",
                "description": "Get current session state: risk score, turn count, lock status, violation count.",
                "args": {
                    "session_id": "Session ID to look up (optional — uses current session if omitted)"
                },
            },
            {
                "name": "memory_search",
                "description": "Search persistent memory using hybrid full-text keyword + vector semantic search with RRF fusion. Returns ranked results.",
                "args": {
                    "query": "Search query text",
                    "k": "Number of results (default 10, max 100)",
                },
            },
            {
                "name": "memory_list",
                "description": "List memory chunks, newest first. Paginated.",
                "args": {
                    "limit": "Number of chunks (default 50)",
                    "offset": "Pagination offset (default 0)",
                },
            },
            {
                "name": "memory_store",
                "description": "Store text in persistent memory with optional metadata. Splits large texts into chunks automatically.",
                "args": {
                    "text": "Text to store",
                    "source": "Source label (optional)",
                    "metadata": "JSON metadata (optional)",
                },
            },
        ]

        if self._episodic_store is not None:
            tools.append(
                {
                    "name": "memory_recall_file",
                    "description": "Query episodic memory by file path. Returns structured history of tasks that created, modified, or read the specified file. Use when the user references a specific file.",
                    "args": {
                        "path": "File path to look up (e.g. /workspace/app.py)",
                        "limit": "Max results (default 20)",
                    },
                }
            )
            tools.append(
                {
                    "name": "memory_recall_session",
                    "description": "Query episodic memory by session ID. Returns structured summary of what happened in that session: tasks, outcomes, files affected. Use when the user references a previous session.",
                    "args": {
                        "session_id": "Session ID to look up",
                        "limit": "Max results (default 20)",
                    },
                }
            )

        if self._routine_store is not None:
            tools.append(
                {
                    "name": "routine_list",
                    "description": "List all routines. Supports filtering by enabled status.",
                    "args": {
                        "enabled_only": "Only return enabled routines (default false)",
                        "limit": "Max results (default 100)",
                    },
                }
            )
            tools.append(
                {
                    "name": "routine_get",
                    "description": "Get a single routine by ID with full config details.",
                    "args": {"routine_id": "Routine ID to look up"},
                }
            )

        if self._routine_engine is not None:
            tools.append(
                {
                    "name": "routine_history",
                    "description": "Get execution history for a routine — past runs, statuses, errors.",
                    "args": {
                        "routine_id": "Routine ID",
                        "limit": "Max records (default 20)",
                    },
                }
            )

        return tools
