"""Tests for F1 schema migration and store persistence."""

import json
import sqlite3

from sentinel.core.db import init_db


class TestStepOutcomesMigration:
    def test_step_outcomes_column_exists_after_init(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        conn = init_db(db_path)
        cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(conversation_turns)").fetchall()
        }
        assert "step_outcomes" in cols
        conn.close()

    def test_migration_idempotent(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        conn = init_db(db_path)
        conn2 = init_db(db_path)
        cols = {
            row[1]
            for row in conn2.execute("PRAGMA table_info(conversation_turns)").fetchall()
        }
        assert "step_outcomes" in cols
        conn.close()
        conn2.close()


class TestConversationTurnStepOutcomes:
    def test_default_none(self):
        from sentinel.session.store import ConversationTurn
        turn = ConversationTurn(request_text="test")
        assert turn.step_outcomes is None

    def test_accepts_list_of_dicts(self):
        from sentinel.session.store import ConversationTurn
        outcomes = [{"step_type": "llm_task", "status": "success"}]
        turn = ConversationTurn(request_text="test", step_outcomes=outcomes)
        assert turn.step_outcomes == outcomes


class TestStoreRoundTrip:
    def test_step_outcomes_persisted_and_loaded(self, tmp_path):
        from sentinel.session.store import ConversationTurn, SessionStore
        db_path = str(tmp_path / "test.db")
        conn = init_db(db_path)
        store = SessionStore(db=conn)

        session = store.get_or_create("test-key")
        outcomes = [
            {"step_type": "llm_task", "status": "success", "output_size": 150},
            {"step_type": "tool_call", "status": "blocked", "error_detail": "policy"},
        ]
        turn = ConversationTurn(
            request_text="write hello.py",
            result_status="success",
            step_outcomes=outcomes,
        )
        session.add_turn(turn)

        # Reload session from DB
        store2 = SessionStore(db=conn)
        loaded = store2.get("test-key")
        assert len(loaded.turns) == 1
        assert loaded.turns[0].step_outcomes == outcomes

    def test_null_step_outcomes_loaded_as_none(self, tmp_path):
        """Pre-F1 turns have NULL step_outcomes — should load as None."""
        from sentinel.session.store import SessionStore
        db_path = str(tmp_path / "test.db")
        conn = init_db(db_path)
        store = SessionStore(db=conn)
        session = store.get_or_create("test-key")

        # Insert a turn the old way (no step_outcomes column value)
        conn.execute(
            "INSERT INTO conversation_turns "
            "(session_id, request_text, result_status, blocked_by, risk_score, "
            "plan_summary, auto_approved, elapsed_s) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session.session_id, "old turn", "success", "[]", 0.0, "summary", 0, 1.5),
        )
        conn.commit()

        store2 = SessionStore(db=conn)
        loaded = store2.get("test-key")
        # Find the old turn (skip any turns from session creation)
        old_turns = [t for t in loaded.turns if t.request_text == "old turn"]
        assert len(old_turns) == 1
        assert old_turns[0].step_outcomes is None
