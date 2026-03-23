"""Tests for contact resolution in the intake pipeline.

Verifies resolve_contacts() wiring: sender identity resolution,
recipient name rewriting, pipeline ordering (S1 before resolution),
and end-to-end integration.

Uses pool=None ContactStore (in-memory mode, no DB needed).
"""

import logging

import pytest

from sentinel.contacts.store import ContactStore
from sentinel.planner.intake import (
    ContactResolutionResult,
    _parse_source_key,
    resolve_contacts,
)


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def store():
    return ContactStore(pool=None)


@pytest.fixture
async def populated_store(store):
    """Store with user, contacts, and channels for resolution tests.

    User 1 (Keith): self-contact (contact_id=1, is_user, linked_user_id=1)
                     with Signal channel "keith-uuid-123".
                     Contact "Sarah" (contact_id=2) with Signal "sarah-uuid".
                     Contact "Sam" (contact_id=3) with email.
    """
    await store.create_user("Keith")  # user_id=1

    # Self-contact — links Signal UUID to user_id=1
    keith_self = await store.create_contact(
        1, "Keith", linked_user_id=1, is_user=True,
    )
    await store.create_channel(
        keith_self["contact_id"], "signal", "keith-uuid-123", is_default=True,
    )

    # Contacts in Keith's address book
    sarah = await store.create_contact(1, "Sarah")
    await store.create_channel(
        sarah["contact_id"], "signal", "sarah-uuid", is_default=True,
    )

    sam = await store.create_contact(1, "Sam")
    await store.create_channel(
        sam["contact_id"], "email", "sam@example.com", is_default=True,
    )

    return store


# ── _parse_source_key ──────────────────────────────────────────────


class TestParseSourceKey:
    def test_signal_key(self):
        assert _parse_source_key("signal:keith-uuid-123") == ("signal", "keith-uuid-123")

    def test_telegram_key(self):
        assert _parse_source_key("telegram:12345") == ("telegram", "12345")

    def test_api_key(self):
        """API requests have source_key like 'api:127.0.0.1' — still parseable."""
        assert _parse_source_key("api:127.0.0.1") == ("api", "127.0.0.1")

    def test_none(self):
        assert _parse_source_key(None) == (None, None)

    def test_empty(self):
        assert _parse_source_key("") == (None, None)

    def test_no_colon(self):
        assert _parse_source_key("websocket") == (None, None)

    def test_colon_with_colons_in_identifier(self):
        """IPv6 or other identifiers with colons — only first colon splits."""
        assert _parse_source_key("api:::1") == ("api", "::1")


# ── Sender identity resolution ─────────────────────────────────────


class TestSenderResolution:
    @pytest.mark.asyncio
    async def test_known_signal_uuid_resolves_to_user(self, populated_store):
        """Known Signal UUID resolves to the correct user_id."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123", "hello",
        )
        assert result.user_id == 1

    @pytest.mark.asyncio
    async def test_unknown_channel_sender_rejected(self, populated_store, caplog):
        """F15: Unknown channel sender is rejected, not defaulted to user 1."""
        with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
            result = await resolve_contacts(
                populated_store, "signal:unknown-uuid-999", "hello",
            )
        # Must be rejected — NOT silently assigned to user 1
        assert result.rejected is True
        assert result.user_id == 0
        assert result.error is not None
        assert "not registered" in result.error.lower() or "unknown" in result.error.lower()
        # Log should contain warning with truncated identifier
        assert any("unknown_sender" in r.message.lower() or
                    "Unknown" in r.message
                    for r in caplog.records)

    @pytest.mark.asyncio
    async def test_api_request_no_channel_defaults_to_1(self, populated_store):
        """API request (no channel match) defaults to user_id=1, no error."""
        result = await resolve_contacts(
            populated_store, "api:127.0.0.1", "hello",
        )
        assert result.user_id == 1
        assert result.rewritten_text == "hello"

    @pytest.mark.asyncio
    async def test_no_source_key_defaults_to_1(self, populated_store):
        """No source_key at all (direct API) defaults to user_id=1."""
        result = await resolve_contacts(
            populated_store, None, "hello",
        )
        assert result.user_id == 1
        assert result.rewritten_text == "hello"


# ── Unknown sender rejection (F15) ────────────────────────────────


class TestUnknownSenderRejection:
    """F15: Unknown channel senders are rejected, not defaulted to user 1."""

    @pytest.mark.asyncio
    async def test_unknown_channel_sender_rejected(self, populated_store):
        """Channel message from unknown sender returns rejected result."""
        result = await resolve_contacts(
            populated_store, "signal:unknown-uuid", "hello",
        )
        assert result.rejected is True
        assert result.user_id == 0
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_api_request_defaults_to_user_1(self, populated_store):
        """API request with no channel context defaults to user 1."""
        result = await resolve_contacts(
            populated_store, "api:127.0.0.1", "hello",
        )
        assert result.rejected is False
        assert result.user_id == 1

    @pytest.mark.asyncio
    async def test_known_channel_sender_resolved(self, populated_store):
        """Known channel sender resolves to correct user_id."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123", "hello",
        )
        assert result.rejected is False
        assert result.user_id == 1

    @pytest.mark.asyncio
    async def test_websocket_request_defaults_to_user_1(self, populated_store):
        """WebSocket request defaults to user 1, not rejected."""
        result = await resolve_contacts(
            populated_store, "websocket:127.0.0.1", "hello",
        )
        assert result.rejected is False
        assert result.user_id == 1

    @pytest.mark.asyncio
    async def test_no_source_key_defaults_to_user_1(self, populated_store):
        """No source_key (None) defaults to user 1."""
        result = await resolve_contacts(
            populated_store, None, "hello",
        )
        assert result.rejected is False
        assert result.user_id == 1

    @pytest.mark.asyncio
    async def test_rejection_error_message(self, populated_store):
        """Rejected result has meaningful error message."""
        result = await resolve_contacts(
            populated_store, "telegram:unknown-chat-id", "hello",
        )
        assert result.rejected is True
        assert "not registered" in result.error.lower()

    @pytest.mark.asyncio
    async def test_sender_resolution_exception_rejects(self, populated_store):
        """If sender resolution raises, channel messages are rejected (fail-closed)."""
        # Corrupt the store's method to raise
        original = populated_store.get_by_identifier

        async def broken(*a, **kw):
            raise RuntimeError("DB error")

        populated_store.get_by_identifier = broken
        try:
            result = await resolve_contacts(
                populated_store, "signal:keith-uuid-123", "hello",
            )
            assert result.rejected is True
            assert result.user_id == 0
        finally:
            populated_store.get_by_identifier = original


# ── Recipient rewriting ───────────────────────────────────────────


class TestRecipientRewriting:
    @pytest.mark.asyncio
    async def test_known_name_rewritten_to_opaque_id(self, populated_store):
        """Contact name 'Sarah' is replaced with 'user 2'."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123",
            "Send a message to Sarah",
        )
        assert "Sarah" not in result.rewritten_text
        assert "user 2" in result.rewritten_text

    @pytest.mark.asyncio
    async def test_pronoun_rewritten(self, populated_store):
        """First-person pronoun 'my email' rewritten to 'user 1's email'."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123",
            "Check my email",
        )
        assert "my email" not in result.rewritten_text
        assert "user 1's email" in result.rewritten_text

    @pytest.mark.asyncio
    async def test_unknown_name_passes_through(self, populated_store):
        """Names not in the contact list pass through unchanged."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123",
            "Send a message to Alice",
        )
        assert "Alice" in result.rewritten_text

    @pytest.mark.asyncio
    async def test_rewriting_preserves_rest_of_message(self, populated_store):
        """Only names change — the rest of the message is preserved."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123",
            "Tell Sarah that the meeting is at 3pm tomorrow",
        )
        assert "user 2" in result.rewritten_text
        assert "meeting is at 3pm tomorrow" in result.rewritten_text

    @pytest.mark.asyncio
    async def test_audit_log_produced(self, populated_store):
        """Rewriting produces an audit trail with original/replacement."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123",
            "Message Sarah about my calendar",
        )
        assert len(result.audit_log) >= 2  # name + pronoun
        patterns = {entry["pattern"] for entry in result.audit_log}
        assert "name_resolution" in patterns


# ── Pipeline ordering ──────────────────────────────────────────────


class TestPipelineOrdering:
    @pytest.mark.asyncio
    async def test_resolution_does_not_alter_original_for_scanning(self, populated_store):
        """resolve_contacts returns rewritten text but does NOT modify the
        original string passed in — the caller (orchestrator) is responsible
        for calling scan_input on the original text FIRST, then passing it
        to resolve_contacts. This test verifies the function is pure.
        """
        original = "Send Sarah a secret"
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123", original,
        )
        # Original string is unmodified (Python strings are immutable, but
        # verify the contract: resolve_contacts doesn't need the scanner)
        assert original == "Send Sarah a secret"
        assert "user 2" in result.rewritten_text

    @pytest.mark.asyncio
    async def test_rewritten_text_is_what_reaches_downstream(self, populated_store):
        """The rewritten_text field is the one intended for the planner."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123",
            "Ask Sarah about my calendar",
        )
        # Planner sees opaque IDs, not names
        assert "Sarah" not in result.rewritten_text
        assert "my calendar" not in result.rewritten_text
        assert "user 2" in result.rewritten_text
        assert "user 1's calendar" in result.rewritten_text


# ── Edge cases ─────────────────────────────────────────────────────


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_no_store_passes_through(self):
        """When contact_store is None, text passes through unchanged."""
        result = await resolve_contacts(None, "signal:foo", "Hello Sarah")
        assert result.user_id == 1
        assert result.rewritten_text == "Hello Sarah"
        assert result.audit_log == []

    @pytest.mark.asyncio
    async def test_empty_text_passes_through(self, populated_store):
        """Empty message text passes through without error."""
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123", "",
        )
        assert result.user_id == 1
        assert result.rewritten_text == ""

    @pytest.mark.asyncio
    async def test_no_contacts_for_user(self, store):
        """User with no contacts — text passes through unchanged."""
        await store.create_user("Lonely")  # user_id=1, no contacts
        # Self-contact to resolve sender
        lone = await store.create_contact(1, "Lonely", linked_user_id=1, is_user=True)
        await store.create_channel(lone["contact_id"], "signal", "lone-uuid")

        result = await resolve_contacts(
            store, "signal:lone-uuid", "Hello world",
        )
        assert result.user_id == 1
        assert result.rewritten_text == "Hello world"
        assert result.audit_log == []


# ── Integration ────────────────────────────────────────────────────


class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_pipeline_resolves_to_opaque_ids(self, populated_store):
        """Full pipeline: raw message → sender resolved → names rewritten → opaque IDs."""
        raw = "Tell Sarah to check my email and ask Sam about the report"
        result = await resolve_contacts(
            populated_store, "signal:keith-uuid-123", raw,
        )

        # Sender resolved
        assert result.user_id == 1

        # All known names replaced with opaque IDs
        assert "Sarah" not in result.rewritten_text
        assert "Sam" not in result.rewritten_text
        assert "user 2" in result.rewritten_text  # Sarah
        assert "user 3" in result.rewritten_text  # Sam

        # Pronoun rewritten
        assert "my email" not in result.rewritten_text
        assert "user 1's email" in result.rewritten_text

        # Rest of message preserved
        assert "about the report" in result.rewritten_text

        # Audit trail captures all rewrites
        assert len(result.audit_log) >= 3  # Sarah + Sam + pronoun
