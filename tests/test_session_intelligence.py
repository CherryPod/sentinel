"""Tests for F2: Session Intelligence features."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from sentinel.memory.chunks import MemoryStore
from sentinel.planner.builders import (
    build_cross_session_context,
    build_interrupted_task_warning,
    flush_pruned_turns,
)
from sentinel.planner.orchestrator import Orchestrator
from sentinel.planner.planner import ClaudePlanner
from sentinel.session.store import Session, SessionStore, ConversationTurn


class TestPerChannelTTL:
    """Per-channel idle timeouts (F2 section 1)."""

    def test_signal_gets_7200s_ttl(self):
        store = SessionStore()
        assert store._get_channel_ttl("signal") == 7200

    def test_websocket_gets_1800s_ttl(self):
        store = SessionStore()
        assert store._get_channel_ttl("websocket") == 1800

    def test_ws_alias_gets_websocket_ttl(self):
        store = SessionStore()
        assert store._get_channel_ttl("ws") == 1800

    def test_api_gets_3600s_ttl(self):
        store = SessionStore()
        assert store._get_channel_ttl("api") == 3600

    def test_mcp_gets_3600s_ttl(self):
        store = SessionStore()
        assert store._get_channel_ttl("mcp") == 3600

    def test_routine_gets_0_ttl(self):
        store = SessionStore()
        assert store._get_channel_ttl("routine") == 0

    def test_unknown_channel_gets_default_ttl(self):
        store = SessionStore()
        assert store._get_channel_ttl("telegram") == 3600

    async def test_routine_never_expires(self):
        """Routine sessions with TTL=0 should never expire from in-memory store."""
        store = SessionStore(ttl=1)  # 1 second TTL default
        session = await store.get_or_create("routine-1", source="routine")

        # Make session look old (24 hours ago)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        session.last_active = old_time

        # Should NOT be expired because routine TTL=0 (never)
        retrieved = await store.get("routine-1")
        assert retrieved is not None

    async def test_non_routine_does_expire(self):
        """Non-routine sessions with TTL>0 should expire normally."""
        store = SessionStore(ttl=1)  # 1 second TTL default
        session = await store.get_or_create("api-1", source="api")

        # Make session look old (2 hours ago, well past api's 3600s TTL)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        session.last_active = old_time

        # Should be expired because api TTL=3600 and session is 7200s old
        retrieved = await store.get("api-1")
        assert retrieved is None

    async def test_routine_survives_eviction_sweep(self):
        """Routine sessions should survive _evict_expired_mem even when very old."""
        store = SessionStore(ttl=1)
        session = await store.get_or_create("routine-sweep", source="routine")

        # Make session look old
        old_time = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        session.last_active = old_time

        # Trigger eviction sweep by creating another session
        await store.get_or_create("fresh-session", source="api")

        # Routine session should still exist
        assert await store.get("routine-sweep") is not None


class TestTaskInProgress:
    """Interrupted task detection (F2 section 5) — session-level flag."""

    async def test_flag_defaults_to_false(self):
        store = SessionStore()
        session = await store.get_or_create("test-1", source="api")
        assert session.task_in_progress is False

    async def test_flag_set_and_clear(self):
        store = SessionStore()
        session = await store.get_or_create("test-2", source="api")

        session.set_task_in_progress(True)
        assert session.task_in_progress is True

        session.set_task_in_progress(False)
        assert session.task_in_progress is False

    async def test_flag_persists_across_reload(self):
        store = SessionStore()
        session = await store.get_or_create("persist-1", source="api")
        session.set_task_in_progress(True)
        await store.set_task_in_progress("persist-1", True)

        reloaded = await store.get("persist-1")
        assert reloaded is not None
        assert reloaded.task_in_progress is True

        session.set_task_in_progress(False)
        await store.set_task_in_progress("persist-1", False)
        reloaded2 = await store.get("persist-1")
        assert reloaded2 is not None
        assert reloaded2.task_in_progress is False

    async def test_flag_default_in_memory(self):
        """New sessions should have task_in_progress=False."""
        store = SessionStore()
        session = await store.get_or_create("mem-default-1", source="api")
        assert session.task_in_progress is False


class TestHistoryPruning:
    """Head-and-tail pruning (F2 section 2)."""

    def _make_history(self, n: int) -> list[dict]:
        """Create n mock conversation history entries."""
        return [
            {
                "turn": i + 1,
                "request": f"request {i + 1}",
                "outcome": "success",
                "summary": f"did thing {i + 1}",
                "step_outcomes": None,
            }
            for i in range(n)
        ]

    def test_under_threshold_unchanged(self):
        """History with fewer turns than threshold passes through intact."""
        planner = ClaudePlanner.__new__(ClaudePlanner)
        history = self._make_history(15)
        result = planner._format_enriched_history(history, max_turns=20)
        for i in range(1, 16):
            assert f'Turn {i}:' in result
        assert "pruned" not in result.lower()

    def test_over_threshold_keeps_head_and_tail(self):
        """History over threshold keeps first 3 and last 10 turns."""
        planner = ClaudePlanner.__new__(ClaudePlanner)
        history = self._make_history(25)
        result = planner._format_enriched_history(history, max_turns=20)
        # Head: turns 1-3
        assert 'Turn 1:' in result
        assert 'Turn 2:' in result
        assert 'Turn 3:' in result
        # Tail: turns 16-25
        for i in range(16, 26):
            assert f'Turn {i}:' in result
        # Middle: turns 4-15 should NOT appear
        for i in range(4, 16):
            assert f'Turn {i}:' not in result

    def test_pruned_marker_inserted(self):
        """A marker indicating pruned turns should appear between head and tail."""
        planner = ClaudePlanner.__new__(ClaudePlanner)
        history = self._make_history(25)
        result = planner._format_enriched_history(history, max_turns=20)
        assert "12 turns pruned" in result
        assert "summary persisted to memory" in result

    def testprune_history_returns_pruned_turns(self):
        """prune_history returns the correct pruned turn entries."""
        history = self._make_history(25)
        kept, pruned = ClaudePlanner.prune_history(history, max_turns=20)
        assert len(kept) == 13  # 3 head + 10 tail
        assert len(pruned) == 12  # turns 4-15
        assert pruned[0]["turn"] == 4
        assert pruned[-1]["turn"] == 15
        assert kept[0]["turn"] == 1
        assert kept[2]["turn"] == 3
        assert kept[3]["turn"] == 16  # first tail entry

    def test_no_pruning_when_max_turns_zero(self):
        """max_turns=0 means no pruning (backward compat)."""
        planner = ClaudePlanner.__new__(ClaudePlanner)
        history = self._make_history(25)
        result = planner._format_enriched_history(history, max_turns=0)
        for i in range(1, 26):
            assert f'Turn {i}:' in result
        assert "pruned" not in result.lower()

    def test_exact_threshold_no_pruning(self):
        """History exactly at threshold should not be pruned."""
        history = self._make_history(20)
        kept, pruned = ClaudePlanner.prune_history(history, max_turns=20)
        assert len(kept) == 20
        assert len(pruned) == 0


class TestPrePruningFlush:
    """Pre-pruning memory flush (F2 section 3)."""

    def _make_history(self, n: int, with_step_outcomes: bool = False) -> list[dict]:
        """Create n mock conversation history entries."""
        entries = []
        for i in range(n):
            entry = {
                "turn": i + 1,
                "request": f"request {i + 1}",
                "outcome": "success",
                "summary": f"did thing {i + 1}",
                "step_outcomes": None,
            }
            if with_step_outcomes:
                entry["step_outcomes"] = [
                    {"file_path": f"/workspace/file_{i + 1}.py"},
                ]
            entries.append(entry)
        return entries

    async def test_pruned_turns_written_to_memory(self):
        """Pruned turns should be flushed to MemoryStore with source 'system:session_prune'."""
        memory_store = MemoryStore()

        # Build pruned turns (turns 4-15 from a 25-turn history)
        history = self._make_history(25)
        _, pruned = ClaudePlanner.prune_history(history, max_turns=20)
        assert len(pruned) == 12  # sanity check

        await flush_pruned_turns("sess-001", pruned, memory_store=memory_store)

        chunks = await memory_store.list_chunks()
        assert len(chunks) == 1
        chunk = chunks[0]
        assert chunk.source == "system:session_prune"
        assert chunk.metadata["session_id"] == "sess-001"
        assert chunk.metadata["pruned_range"] == "4-15"
        assert "request 4" in chunk.content
        assert "request 15" in chunk.content

    async def test_duplicate_flush_deduplicated(self):
        """Flushing the same session+range twice should not create duplicate entries."""
        memory_store = MemoryStore()

        history = self._make_history(25)
        _, pruned = ClaudePlanner.prune_history(history, max_turns=20)

        # Flush twice with the same session and range
        await flush_pruned_turns("sess-dup", pruned, memory_store=memory_store)
        await flush_pruned_turns("sess-dup", pruned, memory_store=memory_store)

        chunks = await memory_store.list_chunks()
        prune_chunks = [c for c in chunks if c.source == "system:session_prune"]
        assert len(prune_chunks) == 1

    async def test_flush_content_contains_file_paths(self):
        """Flushed content should include file paths from step_outcomes for full-text searchability."""
        memory_store = MemoryStore()

        history = self._make_history(25, with_step_outcomes=True)
        _, pruned = ClaudePlanner.prune_history(history, max_turns=20)

        await flush_pruned_turns("sess-paths", pruned, memory_store=memory_store)

        chunks = await memory_store.list_chunks()
        assert len(chunks) == 1
        content = chunks[0].content
        # File paths from pruned turns (turns 4-15) should appear
        assert "/workspace/file_4.py" in content
        assert "/workspace/file_15.py" in content


class TestCrossSessionInjection:
    """Cross-session context injection (F2 section 4)."""

    def test_build_cross_session_formats_results(self):
        """Results from hybrid_search should be formatted into a context block."""
        import asyncio
        from unittest.mock import MagicMock, patch
        from sentinel.memory.search import SearchResult

        mock_db = MagicMock()
        mock_memory = MagicMock()
        mock_memory.db = mock_db

        results = [
            SearchResult(
                chunk_id="c1",
                content="Task 'fix CSS' completed",
                source="auto",
                score=0.9,
                match_type="fts",
            ),
            SearchResult(
                chunk_id="c2",
                content="Created /workspace/app.py",
                source="auto",
                score=0.8,
                match_type="fts",
            ),
        ]

        with patch(
            "sentinel.memory.search.hybrid_search", return_value=results
        ):
            ctx = asyncio.run(build_cross_session_context(
                user_request="fix the layout",
                memory_store=mock_memory,
                embedding_client=None,
                cross_session_token_budget=500,
            ))

        assert "[EPISODIC CONTEXT" in ctx
        assert "[END EPISODIC CONTEXT]" in ctx
        assert "fix CSS" in ctx
        assert "/workspace/app.py" in ctx

    def test_build_cross_session_empty_when_no_results(self):
        """Returns empty string when no search results."""
        import asyncio
        from unittest.mock import MagicMock, patch

        mock_memory = MagicMock()
        mock_memory.db = MagicMock()

        with patch("sentinel.memory.search.hybrid_search", return_value=[]):
            ctx = asyncio.run(build_cross_session_context(
                user_request="hello",
                memory_store=mock_memory,
                embedding_client=None,
                cross_session_token_budget=500,
            ))

        assert ctx == ""

    def test_build_cross_session_no_memory_store(self):
        """Returns empty string when memory_store is None."""
        import asyncio

        ctx = asyncio.run(build_cross_session_context(
            user_request="hello",
            memory_store=None,
            embedding_client=None,
            cross_session_token_budget=500,
        ))
        assert ctx == ""

    def test_build_cross_session_respects_token_budget(self):
        """Results exceeding token budget should be truncated."""
        import asyncio
        from unittest.mock import MagicMock, patch
        from sentinel.memory.search import SearchResult

        mock_memory = MagicMock()
        mock_memory.db = MagicMock()

        # Create large results that would exceed budget
        big_content = "x" * 5000
        results = [
            SearchResult(
                chunk_id="c1",
                content="small result",
                source="auto",
                score=0.9,
                match_type="fts",
            ),
            SearchResult(
                chunk_id="c2",
                content=big_content,
                source="auto",
                score=0.8,
                match_type="fts",
            ),
        ]

        with patch("sentinel.memory.search.hybrid_search", return_value=results):
            ctx = asyncio.run(build_cross_session_context(
                user_request="test",
                memory_store=mock_memory,
                embedding_client=None,
                cross_session_token_budget=100,  # 400 chars budget
            ))

        assert "small result" in ctx
        assert big_content not in ctx  # should be truncated


class TestInterruptedTaskRecovery:
    """Interrupted task detection and recovery (F2 section 5)."""

    def test_build_interrupted_warning_with_step_outcomes(self):
        """Warning should include request text, step count, and file paths."""
        session = Session(session_id="int-1", source="api")
        turn = ConversationTurn(
            request_text="fix the login page",
            result_status="success",
            step_outcomes=[
                {"status": "success", "file_path": "/workspace/login.py"},
                {"status": "error", "file_path": "/workspace/auth.py"},
                {"status": "pending"},
            ],
        )
        session.turns.append(turn)

        warning = build_interrupted_task_warning(session)
        assert "[WARNING: Previous task was interrupted" in warning
        assert "fix the login page" in warning
        assert "1 of 3 steps completed" in warning
        assert "/workspace/login.py" in warning
        assert "/workspace/auth.py" in warning
        assert "[Verify file state" in warning

    def test_build_interrupted_warning_no_turns(self):
        """Returns empty string for sessions with no turns."""
        session = Session(session_id="int-2", source="api")
        warning = build_interrupted_task_warning(session)
        assert warning == ""

    def test_build_interrupted_warning_no_step_outcomes(self):
        """Works when last turn has no step_outcomes."""
        session = Session(session_id="int-3", source="api")
        turn = ConversationTurn(
            request_text="deploy the app",
            result_status="success",
            step_outcomes=None,
        )
        session.turns.append(turn)

        warning = build_interrupted_task_warning(session)
        assert "[WARNING:" in warning
        assert "deploy the app" in warning
        # No step count or file paths when step_outcomes is None
        assert "steps completed" not in warning
        assert "Files possibly" not in warning
        assert "[Verify file state" in warning

    async def test_flag_cleared_in_finally(self):
        """task_in_progress should be cleared even when handle_task encounters an error."""
        from unittest.mock import MagicMock, AsyncMock

        # Create a session store with a real session
        session = Session(session_id="finally-1", source="api")

        mock_session_store = MagicMock()
        mock_session_store.get_or_create = AsyncMock(return_value=session)

        mock_analyzer = MagicMock()
        mock_analyzer.analyze = MagicMock(
            return_value=MagicMock(
                total_score=0.0, action="allow", warnings=[]
            )
        )

        # Pipeline that passes input scan
        mock_pipeline = MagicMock()
        mock_scan_result = MagicMock()
        mock_scan_result.is_clean = True
        mock_pipeline.scan_input = MagicMock(return_value=mock_scan_result)

        # Planner that raises an error
        mock_planner = MagicMock()
        mock_planner.create_plan = AsyncMock(
            side_effect=Exception("simulated crash")
        )

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            session_store=mock_session_store,
            conversation_analyzer=mock_analyzer,
        )

        # Run handle_task — it should raise or return error, but clear the flag
        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.conversation_enabled = True
            mock_settings.trust_level = 0
            mock_settings.session_max_history_turns = 20
            mock_settings.cross_session_token_budget = 2000

            try:
                await orch.handle_task(
                    "test", source="api", source_key="test-key"
                )
            except Exception:
                pass

        # The flag should be cleared even though an error occurred
        assert session.task_in_progress is False
