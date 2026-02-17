import json

from sentinel.core.context import current_user_id
from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.memory.episodic import EpisodicStore
from sentinel.security.provenance import create_tagged_data
from sentinel.worker.base import EmbeddingBase

# Handler mapping: tool name -> method name on SafeToolHandlers
SAFE_HANDLERS: dict[str, str] = {
    "health_check": "health_check",
    "session_info": "session_info",
    "memory_search": "memory_search",
    "memory_list": "memory_list",
    "memory_store": "memory_store",
    "routine_list": "routine_list",
    "routine_get": "routine_get",
    "routine_history": "routine_history",
    "memory_recall_file": "memory_recall_file",
    "memory_recall_session": "memory_recall_session",
}


class SafeToolHandlers:
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
        self._routine_engine = engine

    def set_episodic_store(self, store: EpisodicStore | None) -> None:
        """Update episodic store after construction."""
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
                "args": {"session_id": "Session ID to look up (optional — uses current session if omitted)"},
            },
            {
                "name": "memory_search",
                "description": "Search persistent memory using hybrid full-text keyword + vector semantic search with RRF fusion. Returns ranked results.",
                "args": {"query": "Search query text", "k": "Number of results (default 10, max 100)"},
            },
            {
                "name": "memory_list",
                "description": "List memory chunks, newest first. Paginated.",
                "args": {"limit": "Number of chunks (default 50)", "offset": "Pagination offset (default 0)"},
            },
            {
                "name": "memory_store",
                "description": "Store text in persistent memory with optional metadata. Splits large texts into chunks automatically.",
                "args": {"text": "Text to store", "source": "Source label (optional)", "metadata": "JSON metadata (optional)"},
            },
        ]

        if self._episodic_store is not None:
            tools.append({
                "name": "memory_recall_file",
                "description": "Query episodic memory by file path. Returns structured history of tasks that created, modified, or read the specified file. Use when the user references a specific file.",
                "args": {"path": "File path to look up (e.g. /workspace/app.py)", "limit": "Max results (default 20)"},
            })
            tools.append({
                "name": "memory_recall_session",
                "description": "Query episodic memory by session ID. Returns structured summary of what happened in that session: tasks, outcomes, files affected. Use when the user references a previous session.",
                "args": {"session_id": "Session ID to look up", "limit": "Max results (default 20)"},
            })

        if self._routine_store is not None:
            tools.append({
                "name": "routine_list",
                "description": "List all routines. Supports filtering by enabled status.",
                "args": {"enabled_only": "Only return enabled routines (default false)", "limit": "Max results (default 100)"},
            })
            tools.append({
                "name": "routine_get",
                "description": "Get a single routine by ID with full config details.",
                "args": {"routine_id": "Routine ID to look up"},
            })

        if self._routine_engine is not None:
            tools.append({
                "name": "routine_history",
                "description": "Get execution history for a routine — past runs, statuses, errors.",
                "args": {"routine_id": "Routine ID", "limit": "Max records (default 20)"},
            })

        return tools

    async def health_check(self, args: dict) -> TaggedData:
        """Check component availability and return status dict."""
        from sentinel.security import semgrep_scanner as sg, prompt_guard as pg
        status = {
            "planner_available": self._planner is not None,
            "pipeline_available": self._pipeline is not None,
            "semgrep_loaded": sg.is_loaded(),
            "prompt_guard_loaded": pg.is_loaded() if hasattr(pg, "is_loaded") else False,
            "memory_store": self._memory_store is not None,
            "session_store": self._session_store is not None,
            "routine_store": self._routine_store is not None,
            "routine_engine": self._routine_engine is not None,
            "event_bus": self._event_bus is not None,
        }
        content = json.dumps(status, indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def session_info(self, args: dict) -> TaggedData:
        """Get session state: risk score, turns, lock status."""
        if self._session_store is None:
            raise RuntimeError("Session store not available")
        session_id = args.get("session_id", "")
        if not session_id:
            raise RuntimeError("No session_id provided")
        session = await self._session_store.get(session_id)
        if session is None:
            content = json.dumps({"error": "Session not found"})
        else:
            content = json.dumps({
                "session_id": session.session_id,
                "turn_count": len(session.turns),
                "cumulative_risk": session.cumulative_risk,
                "violation_count": session.violation_count,
                "is_locked": session.is_locked,
            })
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def memory_search(self, args: dict) -> TaggedData:
        """Hybrid search across memory — full-text + optional vector."""
        if self._memory_store is None or self._memory_store.pool is None:
            raise RuntimeError("Memory store not available")
        from sentinel.memory.search import hybrid_search
        query = args.get("query", "")
        if not query:
            raise RuntimeError("No query provided")
        try:
            k = min(int(args.get("k", 10)), 100)
        except (TypeError, ValueError):
            k = 10

        # Try vector embedding for hybrid search
        query_embedding = None
        if self._embedding_client is not None:
            try:
                query_embedding = await self._embedding_client.embed(query)
            except Exception:
                pass  # graceful fallback to full-text-only

        results = await hybrid_search(
            pool=self._memory_store.pool,
            query=query,
            embedding=query_embedding,
            k=k,
        )
        content = json.dumps([
            {
                "chunk_id": r.chunk_id,
                "content": r.content,
                "source": r.source,
                "score": round(r.score, 6),
                "match_type": r.match_type,
            }
            for r in results
        ], indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def memory_list(self, args: dict) -> TaggedData:
        """List memory chunks, newest first."""
        if self._memory_store is None:
            raise RuntimeError("Memory store not available")
        try:
            limit = min(int(args.get("limit", 50)), 100)
        except (TypeError, ValueError):
            limit = 50
        try:
            offset = int(args.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
        chunks = await self._memory_store.list_chunks(limit=limit, offset=offset)
        content = json.dumps([
            {
                "chunk_id": c.chunk_id,
                "content": c.content,
                "source": c.source,
                "created_at": c.created_at,
            }
            for c in chunks
        ], indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def memory_store(self, args: dict) -> TaggedData:
        """Store text in persistent memory.

        D-004: Source is hardcoded to "planner:auto" regardless of what the
        planner passes.  This prevents the undeletable-entry attack where a
        compromised plan sets source="system:heartbeat" (system: entries are
        protected from deletion by MemoryStore.delete()).
        """
        if self._memory_store is None:
            raise RuntimeError("Memory store not available")
        text = args.get("text", "")
        if not text:
            raise RuntimeError("No text provided")
        # D-004: Hardcode source — never allow planner to set system:* prefix
        source = "planner:auto"
        metadata = args.get("metadata")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (json.JSONDecodeError, ValueError):
                metadata = None

        # Store with embedding if available
        if self._embedding_client is not None:
            try:
                embedding = await self._embedding_client.embed(text)
                chunk_id = await self._memory_store.store_with_embedding(
                    content=text,
                    embedding=embedding,
                    source=source,
                    metadata=metadata,
                )
            except Exception:
                chunk_id = await self._memory_store.store(
                    content=text,
                    source=source,
                    metadata=metadata,
                )
        else:
            chunk_id = await self._memory_store.store(
                content=text,
                source=source,
                metadata=metadata,
            )

        content = json.dumps({"chunk_id": chunk_id, "stored": True})
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def memory_recall_file(self, args: dict) -> TaggedData:
        """Query episodic records by file path — structured timeline."""
        if self._episodic_store is None:
            raise RuntimeError("Episodic store not available")
        path = args.get("path", "")
        if not path:
            raise RuntimeError("No path provided")
        try:
            limit = min(int(args.get("limit", 20)), 100)
        except (TypeError, ValueError):
            limit = 20

        # Use ContextVar for user_id — never trust planner-controlled args
        user_id = current_user_id.get()
        records = await self._episodic_store.list_by_file(path, user_id=user_id, limit=limit)

        # Bump access count in a single transaction
        record_ids = [r.record_id for r in records]
        if record_ids:
            await self._episodic_store.batch_update_access(record_ids)

        content = json.dumps([
            {
                "record_id": r.record_id,
                "session_id": r.session_id,
                "user_request": r.user_request[:200],
                "task_status": r.task_status,
                "plan_summary": r.plan_summary[:200],
                "step_count": r.step_count,
                "success_count": r.success_count,
                "file_paths": r.file_paths,
                "created_at": r.created_at,
            }
            for r in records
        ], indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def memory_recall_session(self, args: dict) -> TaggedData:
        """Query episodic records by session ID — structured summary."""
        if self._episodic_store is None:
            raise RuntimeError("Episodic store not available")
        session_id = args.get("session_id", "")
        if not session_id:
            raise RuntimeError("No session_id provided")
        try:
            limit = min(int(args.get("limit", 20)), 100)
        except (TypeError, ValueError):
            limit = 20

        # Use ContextVar for user_id — never trust planner-controlled args
        user_id = current_user_id.get()

        records = await self._episodic_store.list_by_session(
            session_id, user_id=user_id, limit=limit,
        )

        # Bump access count in a single transaction
        record_ids = [r.record_id for r in records]
        if record_ids:
            await self._episodic_store.batch_update_access(record_ids, user_id=user_id)

        content = json.dumps([
            {
                "record_id": r.record_id,
                "task_id": r.task_id,
                "user_request": r.user_request[:200],
                "task_status": r.task_status,
                "plan_summary": r.plan_summary[:200],
                "step_count": r.step_count,
                "success_count": r.success_count,
                "file_paths": r.file_paths,
                "error_patterns": r.error_patterns,
                "created_at": r.created_at,
            }
            for r in records
        ], indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def routine_list(self, args: dict) -> TaggedData:
        """List all routines."""
        if self._routine_store is None:
            raise RuntimeError("Routine store not available")
        enabled_only = str(args.get("enabled_only", "false")).lower() == "true"
        try:
            limit = min(int(args.get("limit", 100)), 100)
        except (TypeError, ValueError):
            limit = 100
        routines = await self._routine_store.list(enabled_only=enabled_only, limit=limit)
        content = json.dumps([
            {
                "routine_id": r.routine_id,
                "name": r.name,
                "trigger_type": r.trigger_type,
                "enabled": r.enabled,
                "last_run_at": r.last_run_at,
                "next_run_at": r.next_run_at,
            }
            for r in routines
        ], indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def routine_get(self, args: dict) -> TaggedData:
        """Get a single routine by ID."""
        if self._routine_store is None:
            raise RuntimeError("Routine store not available")
        routine_id = args.get("routine_id", "")
        if not routine_id:
            raise RuntimeError("No routine_id provided")
        routine = await self._routine_store.get(routine_id)
        if routine is None:
            content = json.dumps({"error": "Routine not found"})
        else:
            content = json.dumps({
                "routine_id": routine.routine_id,
                "name": routine.name,
                "description": routine.description,
                "trigger_type": routine.trigger_type,
                "trigger_config": routine.trigger_config,
                "action_config": routine.action_config,
                "enabled": routine.enabled,
                "cooldown_s": routine.cooldown_s,
                "last_run_at": routine.last_run_at,
                "next_run_at": routine.next_run_at,
            })
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def routine_history(self, args: dict) -> TaggedData:
        """Get execution history for a routine."""
        if self._routine_engine is None:
            raise RuntimeError("Routine engine not available")
        routine_id = args.get("routine_id", "")
        if not routine_id:
            raise RuntimeError("No routine_id provided")
        try:
            limit = min(int(args.get("limit", 20)), 100)
        except (TypeError, ValueError):
            limit = 20
        executions = await self._routine_engine.get_execution_history(
            routine_id, limit=limit,
        )
        content = json.dumps(executions, indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )
