"""Tests for ConfirmationGate — action-level confirmation store."""

from __future__ import annotations

import asyncio

import pytest

from sentinel.core.confirmation import ConfirmationGate, ConfirmationEntry
from sentinel.core.context import current_user_id


@pytest.fixture(autouse=True)
def _set_user_id():
    """Set current_user_id to 1 for all tests (matches user_id=1 in creates)."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


class TestConfirmationGateCreate:
    async def test_create_returns_id(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        cid = await gate.create(
            user_id=1,
            channel="signal",
            source_key="signal:abc-123",
            tool_name="signal_send",
            tool_params={"message": "hello", "recipient": "alice"},
            preview_text="Send via Signal to Alice: hello",
            original_request="tell alice hello on signal",
            task_id="task-001",
        )
        assert isinstance(cid, str)
        assert len(cid) > 0

    async def test_create_stores_all_fields(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        cid = await gate.create(
            user_id=1,
            channel="signal",
            source_key="signal:abc-123",
            tool_name="signal_send",
            tool_params={"message": "hi"},
            preview_text="Send via Signal: hi",
            original_request="say hi",
            task_id="task-002",
        )
        entry = await gate.get_pending("signal:abc-123")
        assert entry is not None
        assert entry.confirmation_id == cid
        assert entry.tool_name == "signal_send"
        assert entry.tool_params == {"message": "hi"}
        assert entry.original_request == "say hi"
        assert entry.status == "pending"


class TestConfirmationGatePending:
    async def test_get_pending_returns_none_when_empty(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        assert await gate.get_pending("signal:nobody") is None

    async def test_get_pending_returns_entry(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        cid = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="calendar_create_event",
            tool_params={"summary": "Dentist", "start": "2026-03-10T14:00"},
            preview_text="Add to calendar: Dentist -- 2026-03-10 14:00",
            original_request="add dentist thursday 2pm",
            task_id="task-003",
        )
        entry = await gate.get_pending("signal:abc")
        assert entry is not None
        assert entry.confirmation_id == cid
        assert entry.status == "pending"

    async def test_one_pending_per_source_key(self):
        """Creating a new confirmation auto-cancels the old one."""
        gate = ConfirmationGate(pool=None, timeout=600)
        cid1 = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "first"},
            preview_text="first", original_request="first",
            task_id="task-004",
        )
        cid2 = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "second"},
            preview_text="second", original_request="second",
            task_id="task-005",
        )
        entry = await gate.get_pending("signal:abc")
        assert entry is not None
        assert entry.confirmation_id == cid2
        # Old one is cancelled
        assert gate._mem[cid1].status == "cancelled"


class TestConfirmationGateConfirm:
    async def test_confirm_returns_entry_with_payload(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        cid = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send",
            tool_params={"message": "hello", "recipient": "alice"},
            preview_text="preview", original_request="request",
            task_id="task-006",
        )
        entry = await gate.confirm(cid)
        assert entry is not None
        assert entry.status == "confirmed"
        assert entry.tool_name == "signal_send"
        assert entry.tool_params == {"message": "hello", "recipient": "alice"}

    async def test_confirm_clears_pending(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        cid = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "hi"},
            preview_text="preview", original_request="request",
            task_id="task-007",
        )
        await gate.confirm(cid)
        assert await gate.get_pending("signal:abc") is None

    async def test_confirm_nonexistent_returns_none(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        assert await gate.confirm("nonexistent") is None

    async def test_confirm_already_cancelled_returns_none(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        cid = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "hi"},
            preview_text="preview", original_request="request",
            task_id="task-008",
        )
        await gate.cancel(cid)
        assert await gate.confirm(cid) is None


class TestConfirmationGateCancel:
    async def test_cancel_marks_cancelled(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        cid = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "hi"},
            preview_text="preview", original_request="request",
            task_id="task-009",
        )
        await gate.cancel(cid)
        assert gate._mem[cid].status == "cancelled"
        assert await gate.get_pending("signal:abc") is None

    async def test_cancel_nonexistent_is_noop(self):
        gate = ConfirmationGate(pool=None, timeout=600)
        await gate.cancel("nonexistent")  # should not raise


class TestConfirmationGateExpiry:
    async def test_expired_entries_not_returned(self):
        gate = ConfirmationGate(pool=None, timeout=0)  # instant expiry
        await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "hi"},
            preview_text="preview", original_request="request",
            task_id="task-010",
        )
        # TTL=0 means already expired
        assert await gate.get_pending("signal:abc") is None

    async def test_cleanup_expired_marks_and_counts(self):
        gate = ConfirmationGate(pool=None, timeout=0)
        await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "hi"},
            preview_text="preview", original_request="request",
            task_id="task-011",
        )
        count = await gate.cleanup_expired()
        assert count >= 1

    async def test_confirm_expired_returns_none(self):
        gate = ConfirmationGate(pool=None, timeout=0)
        cid = await gate.create(
            user_id=1, channel="signal", source_key="signal:abc",
            tool_name="signal_send", tool_params={"message": "hi"},
            preview_text="preview", original_request="request",
            task_id="task-012",
        )
        assert await gate.confirm(cid) is None


class TestConfirmationUserIdIsolation:
    """F17/F18: Confirmation gate filters by user_id."""

    async def test_create_cancel_scoped_to_user(self):
        """Auto-cancel on create only cancels same user's pending confirmations."""
        gate = ConfirmationGate(pool=None, timeout=600)

        # User 1 creates confirmation
        token = current_user_id.set(1)
        try:
            cid1 = await gate.create(
                user_id=1, channel="signal", source_key="task-1",
                tool_name="email_send", tool_params={},
                preview_text="Send email", original_request="send it",
                task_id="task-100",
            )
        finally:
            current_user_id.reset(token)

        # User 2 creates confirmation with same source_key
        token = current_user_id.set(2)
        try:
            cid2 = await gate.create(
                user_id=2, channel="signal", source_key="task-1",
                tool_name="email_send", tool_params={},
                preview_text="Send email", original_request="send it",
                task_id="task-101",
            )
        finally:
            current_user_id.reset(token)

        # User 1's confirmation should still be pending (not cancelled by user 2's create)
        token = current_user_id.set(1)
        try:
            pending = await gate.get_pending("task-1")
            assert pending is not None
            assert pending.confirmation_id == cid1
        finally:
            current_user_id.reset(token)

    async def test_get_pending_scoped_to_user(self):
        """get_pending returns None for wrong user."""
        gate = ConfirmationGate(pool=None, timeout=600)

        token = current_user_id.set(1)
        try:
            await gate.create(
                user_id=1, channel="signal", source_key="task-1",
                tool_name="email_send", tool_params={},
                preview_text="Send email", original_request="send it",
                task_id="task-102",
            )
        finally:
            current_user_id.reset(token)

        # Wrong user sees nothing
        token = current_user_id.set(99)
        try:
            pending = await gate.get_pending("task-1")
            assert pending is None
        finally:
            current_user_id.reset(token)

    async def test_confirm_scoped_to_user(self):
        """confirm() fails for wrong user."""
        gate = ConfirmationGate(pool=None, timeout=600)

        token = current_user_id.set(1)
        try:
            cid = await gate.create(
                user_id=1, channel="signal", source_key="task-1",
                tool_name="email_send", tool_params={},
                preview_text="Send email", original_request="send it",
                task_id="task-103",
            )
        finally:
            current_user_id.reset(token)

        # Wrong user tries to confirm
        token = current_user_id.set(99)
        try:
            result = await gate.confirm(cid)
            assert result is None
        finally:
            current_user_id.reset(token)
