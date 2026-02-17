"""Tests for SessionStore write methods (Phase 1.2 — Session DTO migration).

Tests the in-memory path for:
- add_turn()
- lock_session()
- set_task_in_progress()
- apply_decay()
- clear_turns()
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.core.context import current_user_id
from sentinel.session.store import ConversationTurn, SessionStore, _now_iso


# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def mem_store():
    return SessionStore(pool=None, ttl=3600, max_count=100)


# -- add_turn ---------------------------------------------------------------


class TestAddTurnMem:
    async def test_turn_persists_in_memory(self, mem_store):
        session = await mem_store.get_or_create("s1")
        turn = ConversationTurn(
            request_text="hello",
            result_status="success",
            risk_score=1.5,
            plan_summary="greeting",
            auto_approved=True,
            elapsed_s=0.42,
        )
        session.add_turn(turn)
        await mem_store.add_turn("s1", turn, session=session)

        s2 = await mem_store.get("s1")
        assert len(s2.turns) == 1
        assert s2.turns[0].request_text == "hello"
        assert s2.turns[0].result_status == "success"
        assert s2.turns[0].risk_score == 1.5
        assert s2.turns[0].plan_summary == "greeting"
        assert s2.turns[0].auto_approved is True
        assert s2.turns[0].elapsed_s == 0.42

    async def test_updates_session_state(self, mem_store):
        session = await mem_store.get_or_create("s1")
        session.cumulative_risk = 2.5
        session.violation_count = 1
        turn = ConversationTurn(
            request_text="bad", result_status="blocked", blocked_by=["scanner"],
        )
        session.add_turn(turn)
        await mem_store.add_turn("s1", turn, session=session)

        s2 = await mem_store.get("s1")
        assert s2.violation_count == 2  # incremented by session.add_turn
        assert s2.cumulative_risk == 2.5

    async def test_blocked_by_roundtrip(self, mem_store):
        session = await mem_store.get_or_create("s1")
        turn = ConversationTurn(
            request_text="bad", result_status="blocked",
            blocked_by=["scanner", "prompt_guard"],
        )
        session.add_turn(turn)
        await mem_store.add_turn("s1", turn, session=session)

        s2 = await mem_store.get("s1")
        assert s2.turns[0].blocked_by == ["scanner", "prompt_guard"]

    async def test_step_outcomes_roundtrip(self, mem_store):
        session = await mem_store.get_or_create("s1")
        outcomes = [{"step_id": "1", "status": "ok"}]
        turn = ConversationTurn(
            request_text="test", result_status="success",
            step_outcomes=outcomes,
        )
        session.add_turn(turn)
        await mem_store.add_turn("s1", turn, session=session)

        s2 = await mem_store.get("s1")
        assert s2.turns[0].step_outcomes == outcomes

    async def test_persists_session_fields_for_reload(self, mem_store):
        """Turn data survives a get() reload."""
        session = await mem_store.get_or_create("s1")
        turn = ConversationTurn(request_text="hello", result_status="success")
        session.add_turn(turn)
        await mem_store.add_turn("s1", turn, session=session)

        s2 = await mem_store.get("s1")
        assert len(s2.turns) == 1
        assert s2.turns[0].request_text == "hello"

    async def test_no_op_for_missing_session(self, mem_store):
        """add_turn for nonexistent session doesn't crash."""
        turn = ConversationTurn(request_text="hello", result_status="success")
        await mem_store.add_turn("nonexistent", turn)  # should not raise


# -- lock_session -----------------------------------------------------------


class TestLockSessionMem:
    async def test_locks_in_memory_session(self, mem_store):
        session = await mem_store.get_or_create("s1")
        await mem_store.lock_session("s1")

        s2 = await mem_store.get("s1")
        assert s2.is_locked is True

    async def test_lock_survives_reload(self, mem_store):
        await mem_store.get_or_create("s1")
        await mem_store.lock_session("s1")

        s2 = await mem_store.get("s1")
        assert s2.is_locked is True

    async def test_no_op_for_missing_session(self, mem_store):
        await mem_store.lock_session("nonexistent")  # should not raise


# -- set_task_in_progress ---------------------------------------------------


class TestSetTaskInProgressMem:
    async def test_sets_in_memory(self, mem_store):
        await mem_store.get_or_create("s1")
        await mem_store.set_task_in_progress("s1", True)

        s2 = await mem_store.get("s1")
        assert s2.task_in_progress is True

    async def test_clears_back_to_false(self, mem_store):
        await mem_store.get_or_create("s1")
        await mem_store.set_task_in_progress("s1", True)
        await mem_store.set_task_in_progress("s1", False)

        s2 = await mem_store.get("s1")
        assert s2.task_in_progress is False

    async def test_no_op_for_missing(self, mem_store):
        await mem_store.set_task_in_progress("nonexistent", True)  # should not raise


# -- apply_decay ------------------------------------------------------------


class TestApplyDecayMem:
    async def test_decays_risk_in_memory(self, mem_store):
        session = await mem_store.get_or_create("s1")
        session.cumulative_risk = 4.0
        session.violation_count = 2
        # Simulate 3 minutes of inactivity
        old = (datetime.now(timezone.utc) - timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        session.last_active = old

        changed = await mem_store.apply_decay("s1", decay_per_min=1.0, lock_timeout_s=300)
        assert changed is True
        assert session.cumulative_risk < 4.0

    async def test_auto_unlock_clears_turns(self, mem_store):
        session = await mem_store.get_or_create("s1")
        turn = ConversationTurn(request_text="bad", result_status="blocked")
        session.add_turn(turn)
        session.lock()
        await mem_store.lock_session("s1")

        # Backdate to trigger auto-unlock
        old = (datetime.now(timezone.utc) - timedelta(minutes=6)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        session.last_active = old

        changed = await mem_store.apply_decay("s1", decay_per_min=1.0, lock_timeout_s=300)
        assert changed is True
        assert session.is_locked is False
        assert session.cumulative_risk == 0.0
        assert session.violation_count == 0
        assert len(session.turns) == 0

    async def test_no_change_when_recent(self, mem_store):
        session = await mem_store.get_or_create("s1")
        session.cumulative_risk = 2.0

        # last_active is just now — elapsed < 1s
        changed = await mem_store.apply_decay("s1", decay_per_min=1.0, lock_timeout_s=300)
        assert changed is False

    async def test_returns_false_for_missing_session(self, mem_store):
        changed = await mem_store.apply_decay("nonexistent", decay_per_min=1.0, lock_timeout_s=300)
        assert changed is False


# -- clear_turns ------------------------------------------------------------


class TestClearTurnsMem:
    async def test_clears_in_memory_turns(self, mem_store):
        session = await mem_store.get_or_create("s1")
        session.turns.append(
            ConversationTurn(request_text="hello", result_status="success")
        )
        assert len(session.turns) == 1

        await mem_store.clear_turns("s1")
        assert len(session.turns) == 0

    async def test_no_error_for_missing_session(self, mem_store):
        await mem_store.clear_turns("nonexistent")  # should not raise


# -- user_id filtering ------------------------------------------------------


class TestSessionStoreUserIdFiltering:
    """F7: Session store queries filter by user_id."""

    async def test_get_returns_none_for_wrong_user(self, mem_store):
        """get() with wrong user_id returns None."""
        token = current_user_id.set(1)
        try:
            await mem_store.get_or_create("test-session", source="test")
        finally:
            current_user_id.reset(token)
        # Should not be visible to user_id=99
        result = await mem_store.get("test-session", user_id=99)
        assert result is None

    async def test_get_returns_session_for_correct_user(self, mem_store):
        """get() with matching user_id returns the session."""
        token = current_user_id.set(1)
        try:
            await mem_store.get_or_create("test-session", source="test")
            result = await mem_store.get("test-session", user_id=1)
            assert result is not None
            assert result.session_id == "test-session"
        finally:
            current_user_id.reset(token)

    async def test_lock_session_noop_for_wrong_user(self, mem_store):
        """lock_session() with wrong user_id doesn't lock the session."""
        token = current_user_id.set(1)
        try:
            await mem_store.get_or_create("test-session", source="test")
        finally:
            current_user_id.reset(token)
        # Try to lock as wrong user — should be a no-op
        await mem_store.lock_session("test-session", user_id=99)
        # Session should still be unlocked for the correct user
        token = current_user_id.set(1)
        try:
            session = await mem_store.get("test-session", user_id=1)
            assert session is not None
            assert session.is_locked is False
        finally:
            current_user_id.reset(token)
