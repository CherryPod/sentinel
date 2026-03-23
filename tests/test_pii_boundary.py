"""PII boundary tests — proves the core invariant: no PII reaches the planner.

Tests the full contact resolution pipeline end-to-end:
- Intake rewrites names to opaque IDs before planner sees the text
- Pronouns are resolved to user-scoped opaque references
- No UUIDs, phone numbers, email addresses, or chat IDs leak upstream
- Tool dispatch resolves opaque IDs back to real identifiers on the way out
- Routine prompts flow through the same contact resolution path
- Deleted contacts produce clear errors, not cryptic failures

Uses pool=None ContactStore (in-memory mode, no DB needed).
"""

import asyncio
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.contacts.resolver import resolve_tool_recipient
from sentinel.contacts.store import ContactStore
from sentinel.core.bus import EventBus
from sentinel.core.context import current_user_id
from sentinel.core.models import TaskResult
from sentinel.planner.intake import resolve_contacts
from sentinel.routines.engine import RoutineEngine
from sentinel.routines.store import RoutineStore


# ── Fixtures ───────────────────────────────────────────────────────


# Real PII patterns — these must NEVER appear in planner-facing text
_PII_PATTERNS = [
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE),  # UUID
    re.compile(r"\+\d{10,15}"),           # phone number
    re.compile(r"\b\d{7,13}\b"),          # chat ID (7-13 digit number)
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"),  # email
]


def _contains_pii(text: str) -> list[str]:
    """Return list of PII matches found in text. Empty = clean."""
    found = []
    for pat in _PII_PATTERNS:
        matches = pat.findall(text)
        found.extend(matches)
    return found


@pytest.fixture(autouse=True)
def _set_user_context():
    """Set current_user_id=1 — matches user_id used in contact creation."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


@pytest.fixture
def store():
    return ContactStore(pool=None)


@pytest.fixture
async def full_store(store):
    """Store with realistic contacts and channel identifiers.

    User 1 (Keith): self-contact with Signal UUID and Telegram chat ID.
    Contact "Sarah" with Signal UUID.
    Contact "Dave" with email address.
    Contact "Mia" with Telegram chat ID.
    """
    await store.create_user("Keith")  # user_id=1

    # Self-contact — links Keith's Signal UUID to user_id=1
    keith = await store.create_contact(
        1, "Keith", linked_user_id=1, is_user=True,
    )
    await store.create_channel(
        keith["contact_id"], "signal",
        "00000000-0000-0000-0000-000000000000", is_default=True,
    )
    await store.create_channel(
        keith["contact_id"], "telegram", "0000000000",
    )

    # Sarah — Signal contact
    sarah = await store.create_contact(1, "Sarah")
    await store.create_channel(
        sarah["contact_id"], "signal",
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890", is_default=True,
    )

    # Dave — email contact
    dave = await store.create_contact(1, "Dave")
    await store.create_channel(
        dave["contact_id"], "email",
        "dave@example.com", is_default=True,
    )

    # Mia — Telegram contact
    mia = await store.create_contact(1, "Mia")
    await store.create_channel(
        mia["contact_id"], "telegram",
        "9876543210", is_default=True,
    )

    return store


# ── PII boundary: planner never sees real identifiers ──────────────


class TestPIIBoundary:
    """Core invariant: text that reaches the planner contains NO PII."""

    @pytest.mark.asyncio
    async def test_signal_name_replaced_with_opaque_id(self, full_store):
        """'message Sarah on Signal' → planner sees 'user {N}', not 'Sarah'."""
        result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Message Sarah on Signal about the meeting",
        )

        assert "Sarah" not in result.rewritten_text
        assert "user 2" in result.rewritten_text
        assert "about the meeting" in result.rewritten_text

        # No PII leaked
        pii = _contains_pii(result.rewritten_text)
        assert pii == [], f"PII found in planner text: {pii}"

    @pytest.mark.asyncio
    async def test_email_name_replaced_with_opaque_id(self, full_store):
        """'email Dave the report' → planner sees 'user {N}', not 'Dave'."""
        result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Email Dave the weekly report",
        )

        assert "Dave" not in result.rewritten_text
        assert "dave@example.com" not in result.rewritten_text
        assert "user 3" in result.rewritten_text
        assert "the weekly report" in result.rewritten_text

        pii = _contains_pii(result.rewritten_text)
        assert pii == [], f"PII found in planner text: {pii}"

    @pytest.mark.asyncio
    async def test_multiple_names_all_replaced(self, full_store):
        """All contact names replaced, no PII from any channel identifier."""
        result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Tell Sarah about the plan, then email Dave and message Mia on Telegram",
        )

        # No names remain
        assert "Sarah" not in result.rewritten_text
        assert "Dave" not in result.rewritten_text
        assert "Mia" not in result.rewritten_text

        # Opaque IDs present
        assert "user 2" in result.rewritten_text  # Sarah
        assert "user 3" in result.rewritten_text  # Dave
        assert "user 4" in result.rewritten_text  # Mia

        # No PII leaked (UUIDs, emails, phone numbers, chat IDs)
        pii = _contains_pii(result.rewritten_text)
        assert pii == [], f"PII found in planner text: {pii}"

    @pytest.mark.asyncio
    async def test_pronouns_resolved_to_opaque_user(self, full_store):
        """'check my email' → 'check user 1's email' (sender is user 1)."""
        result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Check my email",
        )

        assert result.user_id == 1
        assert "my email" not in result.rewritten_text
        assert "user 1's email" in result.rewritten_text


# ── End-to-end resolution: name in, identifier out ─────────────────


class TestEndToEndResolution:
    """Full pipeline: raw input → intake rewrite → (planner) → tool dispatch → real identifier."""

    @pytest.mark.asyncio
    async def test_signal_path_full_pipeline(self, full_store):
        """Signal: name → opaque ID (intake) → real UUID (tool dispatch)."""
        # Step 1: Intake rewrites name to opaque ID
        intake_result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Send Sarah a message on Signal saying hello",
        )

        assert "Sarah" not in intake_result.rewritten_text
        assert "user 2" in intake_result.rewritten_text

        # Step 2: Planner would plan with "user 2" — simulate planner output
        # by passing "user 2" as the recipient in tool args
        tool_args = {"message": "hello", "recipient": "user 2"}

        # Step 3: Tool dispatch resolves opaque ID to real Signal UUID
        resolved = await resolve_tool_recipient(
            full_store, "signal_send", tool_args,
        )
        assert resolved["recipient"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    @pytest.mark.asyncio
    async def test_email_path_full_pipeline(self, full_store):
        """Email: name → opaque ID (intake) → real email address (tool dispatch)."""
        intake_result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Email Dave the report",
        )

        assert "Dave" not in intake_result.rewritten_text
        assert "user 3" in intake_result.rewritten_text

        tool_args = {"message": "the report", "recipient": "user 3"}
        resolved = await resolve_tool_recipient(
            full_store, "email_send", tool_args,
        )
        assert resolved["recipient"] == "dave@example.com"

    @pytest.mark.asyncio
    async def test_telegram_path_full_pipeline(self, full_store):
        """Telegram: name → opaque ID (intake) → real chat ID (tool dispatch)."""
        intake_result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Message Mia on Telegram",
        )

        assert "Mia" not in intake_result.rewritten_text
        assert "user 4" in intake_result.rewritten_text

        tool_args = {"message": "hello", "recipient": "user 4"}
        resolved = await resolve_tool_recipient(
            full_store, "telegram_send", tool_args,
        )
        assert resolved["recipient"] == "9876543210"

    @pytest.mark.asyncio
    async def test_cross_channel_resolution(self, full_store):
        """Message arrives on Telegram, references a Signal contact by name."""
        # Keith's Telegram channel already created in fixture (contact_id=1)
        intake_result = await resolve_contacts(
            full_store,
            "telegram:0000000000",
            "Signal Sarah about the meeting",
        )

        # Sender resolved from Telegram
        assert intake_result.user_id == 1

        # Sarah rewritten to opaque ID
        assert "Sarah" not in intake_result.rewritten_text
        assert "user 2" in intake_result.rewritten_text

        # Tool dispatch resolves Sarah's Signal UUID
        tool_args = {"message": "about the meeting", "recipient": "user 2"}
        resolved = await resolve_tool_recipient(
            full_store, "signal_send", tool_args,
        )
        assert resolved["recipient"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


# ── Routine execution with contact resolution ──────────────────────


class TestRoutineContactResolution:
    """Routines flow through handle_task → resolve_contacts → planner."""

    @pytest.fixture
    def routine_store(self):
        return RoutineStore()

    @pytest.fixture
    def mock_orchestrator(self):
        orch = AsyncMock()
        orch.handle_task = AsyncMock(return_value=TaskResult(
            status="success",
            plan_summary="Message sent",
            task_id="test-task",
        ))
        return orch

    @pytest.fixture
    def engine(self, routine_store, mock_orchestrator):
        return RoutineEngine(
            store=routine_store,
            orchestrator=mock_orchestrator,
            event_bus=EventBus(),
            pool=None,
            tick_interval=1,
            execution_timeout=5,
        )

    @pytest.mark.asyncio
    async def test_routine_prompt_reaches_orchestrator(
        self, engine, routine_store, mock_orchestrator,
    ):
        """Routine prompt is passed to orchestrator.handle_task as user_request.

        Contact resolution happens inside handle_task (verified by orchestrator
        code at line 524), so the routine prompt goes through the same path
        as any user message.
        """
        routine = await routine_store.create(
            name="Signal Sarah",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={
                "prompt": "Send Sarah a daily summary on Signal",
                "approval_mode": "auto",
            },
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.1)

        mock_orchestrator.handle_task.assert_called_once()
        call_kwargs = mock_orchestrator.handle_task.call_args
        # The prompt is passed as user_request positional or keyword arg
        user_request = call_kwargs.kwargs.get(
            "user_request", call_kwargs.args[0] if call_kwargs.args else None,
        )
        assert user_request == "Send Sarah a daily summary on Signal"

    @pytest.mark.asyncio
    async def test_routine_source_identifies_routine(
        self, engine, routine_store, mock_orchestrator,
    ):
        """Routine execution passes source='routine:{id}' to orchestrator."""
        routine = await routine_store.create(
            name="Test",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Do something"},
            next_run_at="2020-01-01T00:00:00.000Z",
        )

        await engine._check_due_routines()
        await asyncio.sleep(0.1)

        call_kwargs = mock_orchestrator.handle_task.call_args
        source = call_kwargs.kwargs.get("source", "")
        assert source.startswith("routine:")


class TestDeletedContactInRoutine:
    """Deleted contacts produce clear errors, not cryptic failures."""

    @pytest.mark.asyncio
    async def test_deleted_contact_tool_dispatch_error(self, full_store):
        """If contact is deleted, tool dispatch raises a clear ValueError."""
        # Sarah is contact_id=2 — delete her
        await full_store.delete_contact(2)

        # Tool dispatch tries to resolve "user 2" → should fail clearly
        tool_args = {"message": "hello", "recipient": "user 2"}
        with pytest.raises(ValueError, match=r"No signal identifier found for contact 2"):
            await resolve_tool_recipient(full_store, "signal_send", tool_args)

    @pytest.mark.asyncio
    async def test_deleted_contact_name_passes_through_intake(self, full_store):
        """Deleted contact name passes through intake unchanged (not in contact list)."""
        # Sarah is contact_id=2 — delete her
        await full_store.delete_contact(2)

        result = await resolve_contacts(
            full_store,
            "signal:00000000-0000-0000-0000-000000000000",
            "Message Sarah about the meeting",
        )

        # Sarah is no longer in contacts, so the name passes through
        assert "Sarah" in result.rewritten_text


# ── Settings migration verification ────────────────────────────────


class TestSettingsMigration:
    """Verify allowed_senders/allowed_chat_ids are only used for incoming validation."""

    def test_allowed_senders_not_in_tool_dispatch(self):
        """Tool dispatch (orchestrator tool_dispatch module) does not reference
        allowed_senders — recipient resolution uses the contact registry.
        """
        import inspect
        from sentinel.planner import tool_dispatch
        source = inspect.getsource(tool_dispatch)
        assert "allowed_senders" not in source
        assert "allowed_chat_ids" not in source

    def test_allowed_senders_not_in_resolver(self):
        """Contact resolver does not reference allowed_senders."""
        import inspect
        from sentinel.contacts import resolver
        source = inspect.getsource(resolver)
        assert "allowed_senders" not in source
        assert "allowed_chat_ids" not in source
