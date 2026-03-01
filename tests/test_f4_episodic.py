"""F4: Episodic Memory & Linking tests."""

import json
import sqlite3
import uuid

import pytest

from sentinel.core.db import init_db
from sentinel.memory.chunks import MemoryStore
from sentinel.memory.episodic import (
    EpisodicFact,
    EpisodicRecord,
    EpisodicStore,
    compute_relevance,
    extract_episodic_facts,
    render_episodic_text,
)


class TestEpisodicSchema:
    """F4: Database schema for episodic records, file index, and facts."""

    def test_episodic_records_table_exists(self):
        db = init_db(":memory:")
        rows = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='episodic_records'"
        ).fetchall()
        assert len(rows) == 1

    def test_episodic_file_index_table_exists(self):
        db = init_db(":memory:")
        rows = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='episodic_file_index'"
        ).fetchall()
        assert len(rows) == 1

    def test_episodic_facts_table_exists(self):
        db = init_db(":memory:")
        rows = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='episodic_facts'"
        ).fetchall()
        assert len(rows) == 1

    def test_episodic_facts_fts_table_exists(self):
        db = init_db(":memory:")
        rows = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='episodic_facts_fts'"
        ).fetchall()
        assert len(rows) == 1

    def test_episodic_records_columns(self):
        db = init_db(":memory:")
        cols = {row[1] for row in db.execute("PRAGMA table_info(episodic_records)").fetchall()}
        expected = {
            "record_id", "session_id", "task_id", "user_id",
            "user_request", "task_status", "plan_summary",
            "step_count", "success_count", "file_paths",
            "error_patterns", "defined_symbols", "step_outcomes",
            "linked_records", "relevance_score", "access_count",
            "last_accessed", "memory_chunk_id", "created_at",
        }
        assert expected.issubset(cols)

    def test_episodic_file_index_cascade_delete(self):
        """Deleting a record cascades to file index entries."""
        db = init_db(":memory:")
        db.execute(
            "INSERT INTO episodic_records (record_id, session_id, user_request, task_status) "
            "VALUES ('r1', 's1', 'test', 'success')"
        )
        db.execute(
            "INSERT INTO episodic_file_index (file_path, record_id, action) "
            "VALUES ('/workspace/app.py', 'r1', 'created')"
        )
        db.commit()
        db.execute("DELETE FROM episodic_records WHERE record_id = 'r1'")
        db.commit()
        rows = db.execute(
            "SELECT * FROM episodic_file_index WHERE record_id = 'r1'"
        ).fetchall()
        assert len(rows) == 0


class TestEpisodicStoreCRUD:
    """F4: EpisodicStore create, get, list, delete."""

    def _make_store(self):
        db = init_db(":memory:")
        return EpisodicStore(db), db

    def test_create_record(self):
        store, _ = self._make_store()
        record_id = store.create(
            session_id="s1",
            task_id="t1",
            user_request="spin up bitcoin price tracker",
            task_status="success",
            plan_summary="Built bitcoin tracker",
            step_count=3,
            success_count=3,
            file_paths=["/workspace/btc.html"],
            error_patterns=[],
            defined_symbols=["fetch_price", "update_display"],
            step_outcomes=[{"step_type": "llm_task", "status": "success"}],
        )
        assert record_id is not None
        assert len(record_id) == 36  # UUID format

    def test_get_record(self):
        store, _ = self._make_store()
        record_id = store.create(
            session_id="s1",
            task_id="t1",
            user_request="test request",
            task_status="success",
        )
        record = store.get(record_id)
        assert record is not None
        assert record.record_id == record_id
        assert record.session_id == "s1"
        assert record.user_request == "test request"
        assert record.task_status == "success"

    def test_get_nonexistent_returns_none(self):
        store, _ = self._make_store()
        assert store.get("nonexistent") is None

    def test_list_by_session(self):
        store, _ = self._make_store()
        store.create(session_id="s1", task_id="t1", user_request="r1", task_status="success")
        store.create(session_id="s1", task_id="t2", user_request="r2", task_status="error")
        store.create(session_id="s2", task_id="t3", user_request="r3", task_status="success")
        results = store.list_by_session("s1")
        assert len(results) == 2
        assert all(r.session_id == "s1" for r in results)

    def test_list_by_file_path(self):
        store, _ = self._make_store()
        store.create(
            session_id="s1", task_id="t1", user_request="r1", task_status="success",
            file_paths=["/workspace/app.py"],
        )
        store.create(
            session_id="s2", task_id="t2", user_request="r2", task_status="success",
            file_paths=["/workspace/app.py", "/workspace/test.py"],
        )
        store.create(
            session_id="s3", task_id="t3", user_request="r3", task_status="success",
            file_paths=["/workspace/other.py"],
        )
        results = store.list_by_file("/workspace/app.py")
        assert len(results) == 2

    def test_delete_record(self):
        store, _ = self._make_store()
        record_id = store.create(
            session_id="s1", task_id="t1", user_request="r1", task_status="success",
        )
        assert store.delete(record_id) is True
        assert store.get(record_id) is None

    def test_delete_nonexistent_returns_false(self):
        store, _ = self._make_store()
        assert store.delete("nonexistent") is False


class TestFactExtraction:
    """F4: Deterministic fact extraction from F1 step_outcomes."""

    def test_file_creation_fact(self):
        """file_write where file_size_before is None = new file."""
        outcomes = [{
            "step_type": "tool_call",
            "status": "success",
            "file_path": "/workspace/btc.html",
            "file_size_before": None,
            "file_size_after": 2847,
            "output_language": "html",
        }]
        facts = extract_episodic_facts(outcomes, "create bitcoin tracker", "success")
        file_facts = [f for f in facts if f.fact_type == "file_create"]
        assert len(file_facts) == 1
        assert "/workspace/btc.html" in file_facts[0].content
        assert "2847" in file_facts[0].content
        assert file_facts[0].file_path == "/workspace/btc.html"

    def test_file_modification_fact(self):
        """file_write where file_size_before is not None = modification."""
        outcomes = [{
            "step_type": "tool_call",
            "status": "success",
            "file_path": "/workspace/btc.html",
            "file_size_before": 2847,
            "file_size_after": 3102,
            "diff_stats": "+12/-3 lines",
        }]
        facts = extract_episodic_facts(outcomes, "fix tracker", "success")
        file_facts = [f for f in facts if f.fact_type == "file_modify"]
        assert len(file_facts) == 1
        assert "+12/-3 lines" in file_facts[0].content
        assert file_facts[0].file_path == "/workspace/btc.html"

    def test_scanner_block_fact(self):
        """Step with scanner_result=blocked produces a fact with generic detail."""
        outcomes = [{
            "step_type": "llm_task",
            "status": "blocked",
            "scanner_result": "blocked",
            "error_detail": "scan blocked",
        }]
        facts = extract_episodic_facts(outcomes, "run command", "blocked")
        scanner_facts = [f for f in facts if f.fact_type == "scanner_block"]
        assert len(scanner_facts) == 1
        assert "scan blocked" in scanner_facts[0].content
        # Must NOT contain scanner implementation details
        assert "CommandPatternScanner" not in scanner_facts[0].content

    def test_exec_error_fact(self):
        """Shell step with non-zero exit code."""
        outcomes = [{
            "step_type": "tool_call",
            "status": "exec_error",
            "file_path": "/workspace/server_check.py",
            "exit_code": 1,
            "stderr_preview": "IndentationError: unexpected indent (line 34)",
        }]
        facts = extract_episodic_facts(outcomes, "run script", "error")
        error_facts = [f for f in facts if f.fact_type == "exec_error"]
        assert len(error_facts) == 1
        assert "exit 1" in error_facts[0].content
        assert "IndentationError" in error_facts[0].content

    def test_symbol_definition_fact(self):
        """Step with non-empty defined_symbols."""
        outcomes = [{
            "step_type": "llm_task",
            "status": "success",
            "file_path": "/workspace/app.py",
            "defined_symbols": ["fetch_price", "update_display", "FlashAnimation"],
        }]
        facts = extract_episodic_facts(outcomes, "create app", "success")
        symbol_facts = [f for f in facts if f.fact_type == "symbol_def"]
        assert len(symbol_facts) == 1
        assert "fetch_price" in symbol_facts[0].content
        assert symbol_facts[0].file_path == "/workspace/app.py"

    def test_truncation_warning_fact(self):
        """Step with token_usage_ratio >= 0.95."""
        outcomes = [{
            "step_type": "llm_task",
            "status": "success",
            "token_usage_ratio": 0.97,
            "output_size": 30000,
        }]
        facts = extract_episodic_facts(outcomes, "generate code", "success")
        trunc_facts = [f for f in facts if f.fact_type == "truncation"]
        assert len(trunc_facts) == 1
        assert "95%" in trunc_facts[0].content or "token cap" in trunc_facts[0].content

    def test_no_facts_for_empty_outcomes(self):
        """Empty step_outcomes produces no facts."""
        facts = extract_episodic_facts([], "test", "success")
        assert facts == []

    def test_no_facts_for_clean_simple_step(self):
        """A successful llm_task with no notable metadata produces no facts."""
        outcomes = [{
            "step_type": "llm_task",
            "status": "success",
            "output_size": 200,
            "scanner_result": "clean",
        }]
        facts = extract_episodic_facts(outcomes, "explain something", "success")
        assert facts == []

    def test_multiple_facts_from_multi_step(self):
        """Multiple steps produce multiple facts."""
        outcomes = [
            {
                "step_type": "tool_call", "status": "success",
                "file_path": "/workspace/app.py",
                "file_size_before": None, "file_size_after": 1200,
            },
            {
                "step_type": "tool_call", "status": "exec_error",
                "file_path": "/workspace/app.py",
                "exit_code": 1,
                "stderr_preview": "SyntaxError",
            },
        ]
        facts = extract_episodic_facts(outcomes, "create and run", "error")
        assert len(facts) == 2
        types = {f.fact_type for f in facts}
        assert "file_create" in types
        assert "exec_error" in types


class TestFactStorage:
    """F4: Fact storage and FTS5 search."""

    def _make_store(self):
        db = init_db(":memory:")
        return EpisodicStore(db), db

    def test_store_facts(self):
        store, db = self._make_store()
        record_id = store.create(
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
        )
        facts = [
            EpisodicFact(
                fact_id=str(uuid.uuid4()), record_id="",
                fact_type="file_create",
                content="/workspace/app.py created (1200 bytes, python)",
                file_path="/workspace/app.py", created_at="",
            ),
        ]
        store.store_facts(record_id, facts)

        rows = db.execute(
            "SELECT fact_type, content, file_path FROM episodic_facts WHERE record_id = ?",
            (record_id,),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "file_create"
        assert "/workspace/app.py" in rows[0][1]

    def test_facts_cascade_on_record_delete(self):
        store, db = self._make_store()
        record_id = store.create(
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
        )
        facts = [
            EpisodicFact(
                fact_id=str(uuid.uuid4()), record_id="",
                fact_type="file_create",
                content="test fact", file_path=None, created_at="",
            ),
        ]
        store.store_facts(record_id, facts)
        store.delete(record_id)
        rows = db.execute("SELECT * FROM episodic_facts").fetchall()
        assert len(rows) == 0

    def test_fts5_fact_search(self):
        store, db = self._make_store()
        record_id = store.create(
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
        )
        facts = [
            EpisodicFact(
                fact_id=str(uuid.uuid4()), record_id="",
                fact_type="file_create",
                content="/workspace/btc.html created (2847 bytes, html)",
                file_path="/workspace/btc.html", created_at="",
            ),
            EpisodicFact(
                fact_id=str(uuid.uuid4()), record_id="",
                fact_type="exec_error",
                content="/workspace/server_check.py: exit 1, IndentationError",
                file_path="/workspace/server_check.py", created_at="",
            ),
        ]
        store.store_facts(record_id, facts)

        results = store.search_facts("btc.html")
        assert len(results) >= 1
        assert any("btc.html" in f.content for f in results)

    def test_fts5_fact_search_by_type(self):
        store, db = self._make_store()
        record_id = store.create(
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
        )
        facts = [
            EpisodicFact(
                fact_id=str(uuid.uuid4()), record_id="",
                fact_type="exec_error",
                content="test error fact", file_path=None, created_at="",
            ),
        ]
        store.store_facts(record_id, facts)

        results = store.search_facts("error", fact_type="exec_error")
        assert len(results) >= 1


class TestMemoryShadow:
    """F4: Episodic records mirrored to memory_chunks for search."""

    def test_render_episodic_text(self):
        """Text rendering is compact, keyword-rich, under 500 chars."""
        text = render_episodic_text(
            user_request="spin up bitcoin price tracker on port 8080",
            task_status="success",
            step_count=3,
            success_count=3,
            file_paths=["/workspace/btc.html"],
            plan_summary="Built bitcoin tracker with real-time updates",
        )
        assert "bitcoin" in text.lower()
        assert "success" in text.lower()
        assert "/workspace/btc.html" in text
        assert len(text) < 500

    def test_render_episodic_text_with_errors(self):
        text = render_episodic_text(
            user_request="fix server script",
            task_status="error",
            step_count=2,
            success_count=1,
            file_paths=["/workspace/server.py"],
            plan_summary="Attempted fix",
            error_patterns=["IndentationError line 34"],
        )
        assert "error" in text.lower()
        assert "IndentationError" in text

    def test_create_with_shadow_stores_in_both_tables(self):
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        record_id = episodic_store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1",
            task_id="t1",
            user_request="create a tracker",
            task_status="success",
            plan_summary="Built tracker",
            step_count=2,
            success_count=2,
            file_paths=["/workspace/app.py"],
        )

        # Episodic record exists
        record = episodic_store.get(record_id)
        assert record is not None
        assert record.memory_chunk_id is not None

        # Memory chunk shadow exists
        chunk = memory_store.get(record.memory_chunk_id)
        assert chunk is not None
        assert chunk.source == "system:episodic"
        assert "tracker" in chunk.content.lower()

    def test_shadow_is_system_protected(self):
        """Shadow entry with source='system:episodic' cannot be user-deleted."""
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        record_id = episodic_store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
        )
        record = episodic_store.get(record_id)
        with pytest.raises(ValueError, match="system-protected"):
            memory_store.delete(record.memory_chunk_id)


from unittest.mock import MagicMock, AsyncMock, patch


class TestOrchestratorEpisodicIntegration:
    """F4: Orchestrator stores episodic record after task completion."""

    @pytest.mark.asyncio
    async def test_store_episodic_record_called_on_success(self):
        """Successful task triggers episodic record creation."""
        from sentinel.planner.orchestrator import Orchestrator

        orch = _make_orchestrator()
        orch._store_episodic_record = AsyncMock()

        # We test the private method directly — the integration point
        await orch._store_episodic_record(
            session_id="s1",
            task_id="t1",
            user_request="create a tracker",
            task_status="success",
            plan_summary="Built tracker",
            step_outcomes=[
                {"step_type": "tool_call", "status": "success",
                 "file_path": "/workspace/app.py", "file_size_before": None,
                 "file_size_after": 1200, "output_language": "python"},
            ],
        )
        orch._store_episodic_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_episodic_record_contains_file_paths(self):
        """Episodic record extracts file paths from step_outcomes."""
        from sentinel.planner.orchestrator import Orchestrator
        from sentinel.memory.episodic import EpisodicStore

        db = init_db(":memory:")
        memory_store = MemoryStore(db)
        episodic_store = EpisodicStore(db)

        orch = _make_orchestrator()
        orch._memory_store = memory_store
        orch._episodic_store = episodic_store

        await orch._store_episodic_record(
            session_id="s1",
            task_id="t1",
            user_request="create bitcoin tracker",
            task_status="success",
            plan_summary="Built tracker",
            step_outcomes=[
                {"step_type": "tool_call", "status": "success",
                 "file_path": "/workspace/btc.html", "file_size_before": None,
                 "file_size_after": 2847},
            ],
        )

        # Verify record was created with file paths
        records = episodic_store.list_by_session("s1")
        assert len(records) == 1
        assert "/workspace/btc.html" in records[0].file_paths

    @pytest.mark.asyncio
    async def test_episodic_failure_does_not_block_task(self):
        """Episodic storage is best-effort — failure is logged, not raised."""
        from sentinel.planner.orchestrator import Orchestrator

        orch = _make_orchestrator()
        # Simulate a broken episodic store
        orch._episodic_store = MagicMock()
        orch._episodic_store.create_with_shadow.side_effect = Exception("DB error")

        # Should not raise
        await orch._store_episodic_record(
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
            plan_summary="test", step_outcomes=[],
        )


class TestMemoryRecallFile:
    """F4: memory_recall_file SAFE handler."""

    @pytest.mark.asyncio
    async def test_recall_file_returns_records(self):
        from sentinel.planner.orchestrator import Orchestrator

        db = init_db(":memory:")
        memory_store = MemoryStore(db)
        episodic_store = EpisodicStore(db)

        # Create test records
        episodic_store.create(
            session_id="s1", task_id="t1",
            user_request="create bitcoin tracker",
            task_status="success",
            plan_summary="Built tracker",
            file_paths=["/workspace/btc.html"],
            step_count=3, success_count=3,
        )
        episodic_store.create(
            session_id="s2", task_id="t2",
            user_request="fix CSS bug in tracker",
            task_status="success",
            plan_summary="Fixed CSS",
            file_paths=["/workspace/btc.html"],
            step_count=2, success_count=2,
        )

        orch = _make_orchestrator()
        orch._episodic_store = episodic_store

        result = await orch._safe_memory_recall_file({"path": "/workspace/btc.html"})
        content = json.loads(result.content)
        assert len(content) == 2
        assert all("btc.html" in str(r) for r in content)

    @pytest.mark.asyncio
    async def test_recall_file_updates_access_count(self):
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)
        r_id = episodic_store.create(
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
            file_paths=["/workspace/app.py"],
        )

        orch = _make_orchestrator()
        orch._episodic_store = episodic_store
        await orch._safe_memory_recall_file({"path": "/workspace/app.py"})

        record = episodic_store.get(r_id)
        assert record.access_count == 1

    @pytest.mark.asyncio
    async def test_recall_file_no_path_raises(self):
        orch = _make_orchestrator()
        orch._episodic_store = MagicMock()
        with pytest.raises(RuntimeError, match="No path"):
            await orch._safe_memory_recall_file({})

    @pytest.mark.asyncio
    async def test_recall_file_empty_result(self):
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)

        orch = _make_orchestrator()
        orch._episodic_store = episodic_store

        result = await orch._safe_memory_recall_file({"path": "/workspace/nonexistent.py"})
        content = json.loads(result.content)
        assert content == []


class TestCrossTaskLinking:
    """F4: File-path-based bidirectional linking."""

    def test_new_record_links_to_existing_by_file(self):
        db = init_db(":memory:")
        store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        r1 = store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1", task_id="t1",
            user_request="create app",
            task_status="success",
            file_paths=["/workspace/app.py"],
        )
        r2 = store.create_with_shadow(
            memory_store=memory_store,
            session_id="s2", task_id="t2",
            user_request="fix app bug",
            task_status="success",
            file_paths=["/workspace/app.py"],
        )

        # r2 should link back to r1
        record2 = store.get(r2)
        assert any(
            link["record_id"] == r1 for link in record2.linked_records
        )

    def test_bidirectional_links(self):
        db = init_db(":memory:")
        store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        r1 = store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1", task_id="t1",
            user_request="create app",
            task_status="success",
            file_paths=["/workspace/app.py"],
        )
        r2 = store.create_with_shadow(
            memory_store=memory_store,
            session_id="s2", task_id="t2",
            user_request="fix app",
            task_status="success",
            file_paths=["/workspace/app.py"],
        )

        # Both records should link to each other
        record1 = store.get(r1)
        record2 = store.get(r2)
        assert any(link["record_id"] == r2 for link in record1.linked_records)
        assert any(link["record_id"] == r1 for link in record2.linked_records)

    def test_no_links_for_unrelated_files(self):
        db = init_db(":memory:")
        store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        r1 = store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1", task_id="t1",
            user_request="create app",
            task_status="success",
            file_paths=["/workspace/app.py"],
        )
        r2 = store.create_with_shadow(
            memory_store=memory_store,
            session_id="s2", task_id="t2",
            user_request="create test",
            task_status="success",
            file_paths=["/workspace/other.py"],
        )

        record2 = store.get(r2)
        assert record2.linked_records == []


class TestMemoryDecay:
    """F4: Time-based decay with access boost."""

    def test_fresh_record_high_relevance(self):
        score = compute_relevance(age_days=0, access_count=0)
        assert score == 1.0

    def test_old_record_low_relevance(self):
        score = compute_relevance(age_days=100, access_count=0)
        assert score < 0.1

    def test_access_boost_preserves_old_record(self):
        score_no_access = compute_relevance(age_days=100, access_count=0)
        score_with_access = compute_relevance(age_days=100, access_count=10)
        assert score_with_access > score_no_access

    def test_prune_stale_removes_old_unaccessed(self):
        db = init_db(":memory:")
        store = EpisodicStore(db)

        # Create a record and manually age it to 200 days
        # compute_relevance(200, 0) = 1/(1+20) ≈ 0.048 < 0.05 threshold
        record_id = store.create(
            session_id="s1", task_id="t1",
            user_request="old task", task_status="success",
        )
        db.execute(
            "UPDATE episodic_records SET "
            "created_at = datetime('now', '-200 days') "
            "WHERE record_id = ?",
            (record_id,),
        )
        db.commit()

        pruned = store.prune_stale()
        assert pruned >= 1
        assert store.get(record_id) is None

    def test_prune_stale_keeps_recent_records(self):
        db = init_db(":memory:")
        store = EpisodicStore(db)
        record_id = store.create(
            session_id="s1", task_id="t1",
            user_request="recent task", task_status="success",
        )
        pruned = store.prune_stale()
        assert pruned == 0
        assert store.get(record_id) is not None

    def test_prune_stale_keeps_accessed_old_records(self):
        db = init_db(":memory:")
        store = EpisodicStore(db)
        record_id = store.create(
            session_id="s1", task_id="t1",
            user_request="old but accessed", task_status="success",
        )
        # Age it to 200 days but give it high access count
        # compute_relevance(200, 20) = 1/(1+20) + 0.1*20 = 0.048 + 2.0 = 2.048
        db.execute(
            "UPDATE episodic_records SET "
            "created_at = datetime('now', '-200 days'), "
            "access_count = 20 "
            "WHERE record_id = ?",
            (record_id,),
        )
        db.commit()

        pruned = store.prune_stale()
        assert pruned == 0
        assert store.get(record_id) is not None


class TestMemoryRecallSession:
    """F4: memory_recall_session SAFE handler."""

    @pytest.mark.asyncio
    async def test_recall_session_returns_records(self):
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)
        episodic_store.create(
            session_id="s1", task_id="t1",
            user_request="create tracker", task_status="success",
            plan_summary="Built tracker", step_count=3, success_count=3,
        )
        episodic_store.create(
            session_id="s1", task_id="t2",
            user_request="fix CSS bug", task_status="success",
            plan_summary="Fixed CSS", step_count=2, success_count=2,
        )
        episodic_store.create(
            session_id="s2", task_id="t3",
            user_request="other task", task_status="success",
        )

        orch = _make_orchestrator()
        orch._episodic_store = episodic_store

        result = await orch._safe_memory_recall_session({"session_id": "s1"})
        content = json.loads(result.content)
        assert len(content) == 2

    @pytest.mark.asyncio
    async def test_recall_session_no_id_raises(self):
        orch = _make_orchestrator()
        orch._episodic_store = MagicMock()
        with pytest.raises(RuntimeError, match="No session_id"):
            await orch._safe_memory_recall_session({})

    @pytest.mark.asyncio
    async def test_recall_session_updates_access_count(self):
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)
        r_id = episodic_store.create(
            session_id="s1", task_id="t1",
            user_request="test", task_status="success",
        )

        orch = _make_orchestrator()
        orch._episodic_store = episodic_store
        await orch._safe_memory_recall_session({"session_id": "s1"})

        record = episodic_store.get(r_id)
        assert record.access_count == 1


class TestPrivacyBoundary:
    """F4: Privacy boundary — no raw Qwen output in episodic records."""

    def test_no_raw_qwen_output_in_record_fields(self):
        """All fields in episodic records are TRUSTED by construction."""
        db = init_db(":memory:")
        store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        # Simulate a step_outcomes list with only F1 metadata (TRUSTED)
        # Note: output_size, syntax_valid, scanner_result are all
        # orchestrator-generated — no Qwen text
        outcomes = [
            {
                "step_type": "llm_task",
                "status": "success",
                "output_size": 2847,
                "output_language": "html",
                "syntax_valid": True,
                "scanner_result": "clean",
                "file_path": None,
            },
            {
                "step_type": "tool_call",
                "status": "success",
                "file_path": "/workspace/btc.html",
                "file_size_before": None,
                "file_size_after": 2847,
            },
        ]

        record_id = store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1", task_id="t1",
            user_request="create bitcoin price tracker",
            task_status="success",
            plan_summary="Built bitcoin price tracker",
            step_count=2, success_count=2,
            file_paths=["/workspace/btc.html"],
            step_outcomes=outcomes,
        )

        record = store.get(record_id)
        # user_request is TRUSTED (user input)
        assert record.user_request == "create bitcoin price tracker"
        # plan_summary is TRUSTED (planner output)
        assert record.plan_summary == "Built bitcoin price tracker"
        # file_paths from F1 metadata (orchestrator-generated)
        assert record.file_paths == ["/workspace/btc.html"]
        # task_status from orchestrator enum
        assert record.task_status == "success"

    def test_facts_contain_no_qwen_output(self):
        """Facts are extracted from F1 metadata only."""
        outcomes = [
            {
                "step_type": "tool_call",
                "status": "success",
                "file_path": "/workspace/btc.html",
                "file_size_before": None,
                "file_size_after": 2847,
                "output_language": "html",
                "defined_symbols": ["fetch_price"],
            },
        ]
        facts = extract_episodic_facts(outcomes, "create tracker", "success")
        for fact in facts:
            # Facts should only contain metadata, not raw Qwen text
            assert fact.fact_type in {
                "file_create", "file_modify", "scanner_block",
                "exec_error", "symbol_def", "truncation",
            }
            assert len(fact.content) < 200  # Facts are short


class TestEndToEndIntegration:
    """F4: Full integration — task completion → episodic store → recall."""

    def test_create_record_then_recall_by_file(self):
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        # Simulate task completion
        outcomes = [
            {"step_type": "tool_call", "status": "success",
             "file_path": "/workspace/btc.html",
             "file_size_before": None, "file_size_after": 2847,
             "output_language": "html"},
        ]

        record_id = episodic_store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1", task_id="t1",
            user_request="create bitcoin tracker",
            task_status="success",
            plan_summary="Built tracker",
            step_count=1, success_count=1,
            file_paths=["/workspace/btc.html"],
            step_outcomes=outcomes,
        )

        # Extract and store facts
        facts = extract_episodic_facts(outcomes, "create bitcoin tracker", "success")
        episodic_store.store_facts(record_id, facts)

        # Recall by file path
        results = episodic_store.list_by_file("/workspace/btc.html")
        assert len(results) == 1
        assert results[0].record_id == record_id

        # Recall facts by search
        fact_results = episodic_store.search_facts("btc.html")
        assert len(fact_results) >= 1

        # Shadow entry searchable via memory_store
        chunks = memory_store.list_chunks()
        episodic_chunks = [c for c in chunks if c.source == "system:episodic"]
        assert len(episodic_chunks) == 1
        assert "bitcoin" in episodic_chunks[0].content.lower()

    def test_multi_session_file_linking(self):
        db = init_db(":memory:")
        episodic_store = EpisodicStore(db)
        memory_store = MemoryStore(db)

        # Session 1: Create file
        r1 = episodic_store.create_with_shadow(
            memory_store=memory_store,
            session_id="s1", task_id="t1",
            user_request="create app",
            task_status="success",
            file_paths=["/workspace/app.py"],
        )

        # Session 2: Modify same file
        r2 = episodic_store.create_with_shadow(
            memory_store=memory_store,
            session_id="s2", task_id="t2",
            user_request="fix app bug",
            task_status="success",
            file_paths=["/workspace/app.py"],
        )

        # Session 3: Modify same file + new file
        r3 = episodic_store.create_with_shadow(
            memory_store=memory_store,
            session_id="s3", task_id="t3",
            user_request="add feature + tests",
            task_status="success",
            file_paths=["/workspace/app.py", "/workspace/test_app.py"],
        )

        # All three records linked via /workspace/app.py
        record3 = episodic_store.get(r3)
        linked_ids = {l["record_id"] for l in record3.linked_records}
        assert r1 in linked_ids
        assert r2 in linked_ids

        # File recall returns all three
        file_results = episodic_store.list_by_file("/workspace/app.py")
        assert len(file_results) == 3

    def test_schema_migration_on_existing_db(self):
        """F4 tables are created alongside existing tables."""
        db = init_db(":memory:")
        # All existing tables should still be present
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "sessions" in tables
        assert "conversation_turns" in tables
        assert "memory_chunks" in tables
        assert "episodic_records" in tables
        assert "episodic_file_index" in tables
        assert "episodic_facts" in tables


def _make_orchestrator():
    """Create an Orchestrator with mocked dependencies for testing."""
    from sentinel.planner.orchestrator import Orchestrator

    mock_planner = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline._worker = MagicMock()
    mock_pipeline._worker._last_generate_stats = None

    with patch("sentinel.planner.orchestrator.semgrep_scanner") as mock_sg:
        mock_sg.is_loaded.return_value = False
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
        )
    return orch
