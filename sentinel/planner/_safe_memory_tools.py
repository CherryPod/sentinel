"""Safe memory tool handlers — memory search, list, store, and episodic recall.

Mixin providing handler methods for memory-related safe tools. These share
``_memory_store``, ``_embedding_client``, and ``_episodic_store`` dependencies.
Mixed into SafeToolHandlers by the facade (safe_tools.py).
"""

import asyncio
import json
import logging

from sentinel.core.context import current_user_id
from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.security.provenance import create_tagged_data

from ._safe_tool_registry import EMBEDDING_TIMEOUT

logger = logging.getLogger(__name__)


class MemoryToolsMixin:
    """Handlers for memory-related SAFE tools."""

    _memory_store: object
    _embedding_client: object
    _episodic_store: object

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
            logger.warning(
                "memory_search: invalid k parameter, using default",
                exc_info=True,
                extra={"event": "safe_tools.memory_search_fallback"},
            )
            k = 10

        # Try vector embedding for hybrid search
        query_embedding = None
        if self._embedding_client is not None:
            try:
                query_embedding = await asyncio.wait_for(
                    self._embedding_client.embed(query),
                    timeout=EMBEDDING_TIMEOUT,
                )
            except Exception as exc:  # catch-all: embedding fallback to FTS-only
                logger.debug(
                    "memory_search embedding fallback to FTS-only",
                    extra={"event": "memory.embed_fallback", "error": str(exc)},
                )

        results = await hybrid_search(
            pool=self._memory_store.pool,
            query=query,
            embedding=query_embedding,
            k=k,
        )
        content = json.dumps(
            [
                {
                    "chunk_id": r.chunk_id,
                    "content": r.content,
                    "source": r.source,
                    "score": round(r.score, 6),
                    "match_type": r.match_type,
                }
                for r in results
            ],
            indent=2,
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
        )

    async def memory_list(self, args: dict) -> TaggedData:
        """List memory chunks, newest first."""
        if self._memory_store is None:
            raise RuntimeError("Memory store not available")
        try:
            limit = min(int(args.get("limit", 50)), 100)
        except (TypeError, ValueError):
            logger.warning(
                "memory_list: invalid limit parameter, using default",
                exc_info=True,
                extra={"event": "safe_tools.memory_list_fallback"},
            )
            limit = 50
        try:
            offset = int(args.get("offset", 0))
        except (TypeError, ValueError):
            logger.warning(
                "memory_list: invalid offset parameter, using default",
                exc_info=True,
                extra={"event": "safe_tools.memory_list_fallback"},
            )
            offset = 0
        chunks = await self._memory_store.list_chunks(limit=limit, offset=offset)
        content = json.dumps(
            [
                {
                    "chunk_id": c.chunk_id,
                    "content": c.content,
                    "source": c.source,
                    "created_at": c.created_at,
                }
                for c in chunks
            ],
            indent=2,
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
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
            logger.debug(
                "memory_store: not_text",
                extra={"event": "safe_tools.memory_store.match", "reason": "not_text"},
            )  # auto:neg
            raise RuntimeError("No text provided")
        # D-004: Hardcode source — never allow planner to set system:* prefix
        source = "planner:auto"
        metadata = args.get("metadata")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (json.JSONDecodeError, ValueError):
                logger.warning(
                    "memory_store: invalid metadata JSON, ignoring",
                    exc_info=True,
                    extra={"event": "safe_tools.memory_store_fallback"},
                )
                metadata = None

        # Store with embedding if available
        if self._embedding_client is not None:
            try:
                embedding = await asyncio.wait_for(
                    self._embedding_client.embed(text),
                    timeout=EMBEDDING_TIMEOUT,
                )
                chunk_id = await self._memory_store.store_with_embedding(
                    content=text,
                    embedding=embedding,
                    source=source,
                    metadata=metadata,
                )
            except Exception as exc:  # catch-all: embedding fallback to plain store
                logger.debug(
                    "memory_store: embedding fallback to plain store",
                    extra={"event": "memory.store_error", "error": str(exc)},
                )
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
            logger.warning(
                "memory_recall_file: invalid limit parameter, using default",
                exc_info=True,
                extra={"event": "safe_tools.memory_recall_file_fallback"},
            )
            limit = 20

        # Use ContextVar for user_id — never trust planner-controlled args
        user_id = current_user_id.get()
        records = await self._episodic_store.list_by_file(
            path, user_id=user_id, limit=limit
        )

        # Bump access count in a single transaction
        record_ids = [r.record_id for r in records]
        if record_ids:
            await self._episodic_store.batch_update_access(record_ids)

        content = json.dumps(
            [
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
            ],
            indent=2,
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
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
            logger.warning(
                "memory_recall_session: invalid limit parameter, using default",
                exc_info=True,
                extra={"event": "safe_tools.memory_recall_session_fallback"},
            )
            limit = 20

        # Use ContextVar for user_id — never trust planner-controlled args
        user_id = current_user_id.get()

        records = await self._episodic_store.list_by_session(
            session_id,
            user_id=user_id,
            limit=limit,
        )

        # Bump access count in a single transaction
        record_ids = [r.record_id for r in records]
        if record_ids:
            await self._episodic_store.batch_update_access(record_ids, user_id=user_id)

        content = json.dumps(
            [
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
            ],
            indent=2,
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
        )
