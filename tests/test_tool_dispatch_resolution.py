"""Tests for recipient resolution in tool dispatch and fast path.

Covers:
- resolve_tool_recipient() shared helper (messaging + non-messaging tools)
- Error handling (unknown contact, missing channel entry)
- Fast path integration
- Security ordering (resolution after S3→resolve→S4→S5)
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.contacts.resolver import resolve_tool_recipient


# -- Fixtures ----------------------------------------------------------------

@pytest.fixture
def contact_store():
    """ContactStore mock with one contact (id=3) that has signal, telegram, email."""
    store = AsyncMock()
    # get_channels returns all channel entries for a contact
    async def get_channels(contact_id):
        if contact_id == 3:
            return [
                {"channel": "signal", "identifier": "uuid-signal-3", "is_default": True},
                {"channel": "telegram", "identifier": "12345", "is_default": True},
                {"channel": "email", "identifier": "alice@example.com", "is_default": True},
            ]
        return []
    store.get_channels = AsyncMock(side_effect=get_channels)
    return store


@pytest.fixture
def contact_store_no_email():
    """ContactStore mock where contact 3 has signal but NOT email."""
    store = AsyncMock()
    async def get_channels(contact_id):
        if contact_id == 3:
            return [
                {"channel": "signal", "identifier": "uuid-signal-3", "is_default": True},
            ]
        return []
    store.get_channels = AsyncMock(side_effect=get_channels)
    return store


# -- Resolution logic --------------------------------------------------------

@pytest.mark.asyncio
async def test_signal_send_resolves_recipient(contact_store):
    """signal_send with recipient='user 3' resolves to Signal UUID."""
    args = {"message": "hello", "recipient": "user 3"}
    result = await resolve_tool_recipient(contact_store, "signal_send", args)
    assert result["recipient"] == "uuid-signal-3"
    assert result["message"] == "hello"


@pytest.mark.asyncio
async def test_telegram_send_resolves_recipient(contact_store):
    """telegram_send with recipient='user 3' resolves to Telegram chat ID."""
    args = {"message": "hello", "recipient": "user 3"}
    result = await resolve_tool_recipient(contact_store, "telegram_send", args)
    assert result["recipient"] == "12345"


@pytest.mark.asyncio
async def test_email_send_resolves_recipient(contact_store):
    """email_send with recipient='user 3' resolves to email address."""
    args = {"message": "hello", "recipient": "user 3"}
    result = await resolve_tool_recipient(contact_store, "email_send", args)
    assert result["recipient"] == "alice@example.com"


@pytest.mark.asyncio
async def test_non_messaging_tool_unchanged(contact_store):
    """Non-messaging tool args pass through unchanged, no store call."""
    args = {"command": "ls", "path": "/workspace"}
    result = await resolve_tool_recipient(contact_store, "shell_exec", args)
    assert result is args  # Same object, untouched
    contact_store.get_channels.assert_not_called()


@pytest.mark.asyncio
async def test_raw_identifier_passes_through(contact_store):
    """Recipient that's already a real identifier (no 'user' prefix) passes through."""
    args = {"message": "hello", "recipient": "00000000-0000-0000-0000-000000000000"}
    result = await resolve_tool_recipient(contact_store, "signal_send", args)
    assert result["recipient"] == "00000000-0000-0000-0000-000000000000"
    contact_store.get_channels.assert_not_called()


@pytest.mark.asyncio
async def test_bare_integer_resolves(contact_store):
    """Bare integer '3' (without 'user' prefix) also resolves."""
    args = {"message": "hello", "recipient": "3"}
    result = await resolve_tool_recipient(contact_store, "signal_send", args)
    assert result["recipient"] == "uuid-signal-3"


@pytest.mark.asyncio
async def test_missing_recipient_passes_through(contact_store):
    """Missing recipient arg passes through (handler default applies)."""
    args = {"message": "hello"}
    result = await resolve_tool_recipient(contact_store, "signal_send", args)
    assert result is args
    contact_store.get_channels.assert_not_called()


@pytest.mark.asyncio
async def test_none_recipient_passes_through(contact_store):
    """None recipient passes through unchanged."""
    args = {"message": "hello", "recipient": None}
    result = await resolve_tool_recipient(contact_store, "signal_send", args)
    assert result is args
    contact_store.get_channels.assert_not_called()


# -- Error handling ----------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_contact_raises(contact_store):
    """Unknown contact_id raises ValueError with actionable message."""
    args = {"message": "hello", "recipient": "user 999"}
    with pytest.raises(ValueError, match=r"No signal identifier found for contact 999"):
        await resolve_tool_recipient(contact_store, "signal_send", args)


@pytest.mark.asyncio
async def test_contact_missing_channel_raises(contact_store_no_email):
    """Contact exists but has no email channel entry → ValueError."""
    args = {"message": "hello", "recipient": "user 3"}
    with pytest.raises(ValueError, match=r"No email identifier found for contact 3"):
        await resolve_tool_recipient(contact_store_no_email, "email_send", args)


@pytest.mark.asyncio
async def test_error_mentions_contacts_api(contact_store):
    """Error message includes actionable guidance about the contacts API."""
    args = {"message": "hello", "recipient": "user 999"}
    with pytest.raises(ValueError, match=r"contacts API"):
        await resolve_tool_recipient(contact_store, "signal_send", args)


@pytest.mark.asyncio
async def test_no_store_raises():
    """If contact_store is None, resolution raises ValueError."""
    args = {"message": "hello", "recipient": "user 3"}
    with pytest.raises(ValueError, match=r"contact store not available"):
        await resolve_tool_recipient(None, "signal_send", args)


# -- Fast path integration --------------------------------------------------

@pytest.mark.asyncio
async def test_fast_path_resolves_recipient(contact_store):
    """FastPathExecutor resolves recipients before tool execution."""
    from sentinel.router.fast_path import FastPathExecutor
    from sentinel.router.templates import TemplateRegistry

    # Build executor with contact_store
    tool_executor = AsyncMock()
    tagged = MagicMock()
    tagged.content = "Message sent"
    tool_executor.execute.return_value = (tagged, None)

    pipeline = AsyncMock()
    scan_result = MagicMock()
    scan_result.is_clean = True
    pipeline.scan_output.return_value = scan_result

    registry = TemplateRegistry.default()
    session = MagicMock()
    session.session_id = "test-session"

    executor = FastPathExecutor(
        tool_executor=tool_executor,
        pipeline=pipeline,
        event_bus=None,
        registry=registry,
        contact_store=contact_store,
    )

    result = await executor.execute(
        "signal_send",
        {"message": "hello", "recipient": "user 3"},
        session,
        "task-1",
    )

    assert result["status"] == "success"
    # Verify the tool executor received the resolved UUID
    call_args = tool_executor.execute.call_args
    # _execute_single calls execute(tool_name, params) positionally
    actual_params = call_args[0][1]
    assert actual_params["recipient"] == "uuid-signal-3"


@pytest.mark.asyncio
async def test_fast_path_resolution_error(contact_store):
    """FastPathExecutor returns error when resolution fails."""
    from sentinel.router.fast_path import FastPathExecutor
    from sentinel.router.templates import TemplateRegistry

    registry = TemplateRegistry.default()
    session = MagicMock()
    session.session_id = "test-session"

    executor = FastPathExecutor(
        tool_executor=AsyncMock(),
        pipeline=AsyncMock(),
        event_bus=None,
        registry=registry,
        contact_store=contact_store,
    )

    result = await executor.execute(
        "signal_send",
        {"message": "hello", "recipient": "user 999"},
        session,
        "task-1",
    )

    assert result["status"] == "error"
    assert "contact 999" in result["reason"]


@pytest.mark.asyncio
async def test_fast_path_non_messaging_no_resolution():
    """Fast path non-messaging template doesn't attempt resolution."""
    from sentinel.router.fast_path import FastPathExecutor
    from sentinel.router.templates import TemplateRegistry

    tool_executor = AsyncMock()
    tagged = MagicMock()
    tagged.content = '{"results": []}'
    tool_executor.execute.return_value = (tagged, None)

    pipeline = AsyncMock()
    scan_result = MagicMock()
    scan_result.is_clean = True
    pipeline.scan_output.return_value = scan_result

    registry = TemplateRegistry.default()
    session = MagicMock()
    session.session_id = "test-session"

    # No contact_store needed — non-messaging tool
    executor = FastPathExecutor(
        tool_executor=tool_executor,
        pipeline=pipeline,
        event_bus=None,
        registry=registry,
        contact_store=None,
    )

    result = await executor.execute(
        "web_search",
        {"query": "weather"},
        session,
        "task-1",
    )

    assert result["status"] == "success"


# -- Security ordering -------------------------------------------------------

@pytest.mark.asyncio
async def test_resolution_does_not_break_safety_net():
    """Resolution is plumbing after S3→S4→S5. Verify safety net tests still pass.

    This is a meta-test — the actual safety net tests are in
    test_refactor_safety_net.py. This test just confirms that
    resolve_tool_recipient doesn't interfere with non-messaging tools
    (which is the majority of what the safety net covers).
    """
    # For a non-messaging tool, resolution is a no-op
    args = {"command": "echo hello"}
    result = await resolve_tool_recipient(None, "shell_exec", args)
    assert result is args  # Unchanged, no store needed
