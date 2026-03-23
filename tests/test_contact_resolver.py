"""Tests for sentinel.contacts.resolver — contact resolution functions.

Uses pool=None ContactStore (in-memory mode, no DB needed).
"""

import pytest

from sentinel.contacts.store import ContactStore
from sentinel.contacts.resolver import (
    resolve_sender,
    resolve_recipient_name,
    resolve_recipient_to_channel,
    rewrite_pronouns,
    rewrite_message,
)
from sentinel.core.context import current_user_id


# ── Fixtures ───────────────────────────────────────────────────────


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
async def populated_store(store):
    """Store with two users, contacts, and channels pre-loaded.

    User 1 (Keith): has contact "Sarah" (contact_id=1) with Signal + Telegram,
                     and contact "Sam" (contact_id=2) with email only.
                     Also has a self-contact (contact_id=3) linked back to user 1.
    User 2 (Jane):  has contact "Sarah" (contact_id=4) — different from user 1's Sarah.
    """
    # Users
    await store.create_user("Keith")      # user_id=1
    await store.create_user("Jane")       # user_id=2

    # User 1's contacts
    sarah = await store.create_contact(1, "Sarah")                        # contact_id=1
    sam = await store.create_contact(1, "Sam")                            # contact_id=2
    keith_self = await store.create_contact(                              # contact_id=3
        1, "Keith", linked_user_id=1, is_user=True,
    )

    # User 2's contacts
    sarah2 = await store.create_contact(2, "Sarah")                       # contact_id=4

    # Channels for Sarah (user 1's contact)
    await store.create_channel(sarah["contact_id"], "signal", "aaa-bbb-ccc", is_default=True)
    await store.create_channel(sarah["contact_id"], "telegram", "12345", is_default=True)

    # Channels for Sam (user 1's contact)
    await store.create_channel(sam["contact_id"], "email", "sam@example.com", is_default=True)

    # Channel for Keith's self-contact (user 1)
    await store.create_channel(keith_self["contact_id"], "signal", "keith-uuid-123", is_default=True)
    await store.create_channel(keith_self["contact_id"], "telegram", "99999", is_default=True)

    # Channel for Jane's Sarah (user 2)
    await store.create_channel(sarah2["contact_id"], "signal", "jane-sarah-uuid", is_default=True)

    return store


# ── resolve_sender ─────────────────────────────────────────────────


class TestResolveSender:
    async def test_known_signal_uuid(self, populated_store):
        """Keith's Signal UUID resolves to user_id 1."""
        result = await resolve_sender(populated_store, "signal", "keith-uuid-123")
        assert result == 1

    async def test_known_telegram_id(self, populated_store):
        """Keith's Telegram chat ID resolves to user_id 1."""
        result = await resolve_sender(populated_store, "telegram", "99999")
        assert result == 1

    async def test_unknown_identifier(self, populated_store):
        """Unknown identifier returns None."""
        result = await resolve_sender(populated_store, "signal", "unknown-uuid")
        assert result is None

    async def test_contact_not_a_user(self, populated_store):
        """Sarah has a Signal channel but is_user=False — returns None."""
        result = await resolve_sender(populated_store, "signal", "aaa-bbb-ccc")
        assert result is None

    async def test_contact_no_linked_user_id(self, populated_store):
        """Contact with is_user=False and no linked_user_id — returns None."""
        result = await resolve_sender(populated_store, "email", "sam@example.com")
        assert result is None


# ── resolve_recipient_name ─────────────────────────────────────────


class TestResolveRecipientName:
    async def test_exact_match(self, populated_store):
        """Exact name match returns contact_id."""
        result = await resolve_recipient_name(populated_store, "Sarah", 1)
        assert result == 1  # contact_id=1 (user 1's Sarah)

    async def test_case_insensitive(self, populated_store):
        """Case-insensitive match works."""
        result = await resolve_recipient_name(populated_store, "sarah", 1)
        assert result == 1

    async def test_not_found(self, populated_store):
        """Name not in contacts returns None."""
        result = await resolve_recipient_name(populated_store, "Bob", 1)
        assert result is None

    async def test_scoped_to_user(self, populated_store):
        """Same name owned by different users returns correct contact_id."""
        result_user1 = await resolve_recipient_name(populated_store, "Sarah", 1)
        result_user2 = await resolve_recipient_name(populated_store, "Sarah", 2)
        assert result_user1 == 1   # user 1's Sarah
        assert result_user2 == 4   # user 2's Sarah
        assert result_user1 != result_user2


# ── resolve_recipient_to_channel ───────────────────────────────────


class TestResolveRecipientToChannel:
    async def test_signal_channel(self, populated_store):
        """Contact with signal channel returns UUID."""
        result = await resolve_recipient_to_channel(populated_store, 1, "signal")
        assert result == "aaa-bbb-ccc"

    async def test_correct_channel_type(self, populated_store):
        """Returns the right identifier for the requested channel type."""
        signal = await resolve_recipient_to_channel(populated_store, 1, "signal")
        telegram = await resolve_recipient_to_channel(populated_store, 1, "telegram")
        assert signal == "aaa-bbb-ccc"
        assert telegram == "12345"

    async def test_no_matching_channel(self, populated_store):
        """Contact with no channel for requested type returns None."""
        result = await resolve_recipient_to_channel(populated_store, 2, "signal")
        assert result is None  # Sam only has email

    async def test_prefers_default(self, populated_store):
        """When multiple entries exist for same channel, prefers is_default=True."""
        # Add a non-default signal channel to Sarah
        await populated_store.create_channel(1, "signal", "secondary-uuid", is_default=False)
        result = await resolve_recipient_to_channel(populated_store, 1, "signal")
        assert result == "aaa-bbb-ccc"  # The default one

    async def test_falls_back_to_non_default(self, store):
        """When no default exists, returns the first match."""
        await store.create_user("Test")
        contact = await store.create_contact(1, "Someone")
        await store.create_channel(contact["contact_id"], "signal", "only-uuid", is_default=False)
        result = await resolve_recipient_to_channel(store, contact["contact_id"], "signal")
        assert result == "only-uuid"


# ── rewrite_pronouns ──────────────────────────────────────────────


class TestRewritePronouns:
    def test_my_email(self):
        text, audit = rewrite_pronouns("check my email", 1)
        assert text == "check user 1's email"
        assert len(audit) == 1
        assert audit[0]["pattern"] == "my email"

    def test_send_me(self):
        text, audit = rewrite_pronouns("send me a summary", 1)
        assert text == "send user 1 a summary"
        assert len(audit) == 1
        assert audit[0]["pattern"] == "send me"

    def test_remind_me(self):
        text, audit = rewrite_pronouns("remind me tomorrow", 1)
        assert text == "remind user 1 tomorrow"
        assert len(audit) == 1

    def test_unrecognised_pronoun_unchanged(self):
        text, audit = rewrite_pronouns("I think this is fine", 1)
        assert text == "I think this is fine"
        assert audit == []

    def test_multiple_patterns(self):
        text, audit = rewrite_pronouns("check my email and send me the results", 1)
        assert text == "check user 1's email and send user 1 the results"
        assert len(audit) == 2

    def test_case_insensitivity(self):
        text, audit = rewrite_pronouns("Check My Email", 1)
        assert text == "Check user 1's email"
        assert len(audit) == 1


# ── rewrite_message ───────────────────────────────────────────────


class TestRewriteMessage:
    async def test_name_replacement(self, populated_store):
        text, audit = await rewrite_message(
            populated_store, "send Sarah a message on Signal", 1,
        )
        assert text == "send user 1 a message on Signal"
        assert any(a["pattern"] == "name_resolution" for a in audit)

    async def test_name_and_pronoun(self, populated_store):
        text, audit = await rewrite_message(
            populated_store, "send my calendar to Sarah", 1,
        )
        assert "user 1's calendar" in text
        assert "user 1" in text  # Sarah replaced with user 1 (contact_id)
        # Both name and pronoun rewrites should be in audit
        patterns = [a["pattern"] for a in audit]
        assert "name_resolution" in patterns
        assert "my calendar" in patterns

    async def test_unknown_name_unchanged(self, populated_store):
        text, audit = await rewrite_message(
            populated_store, "send Bob a message", 1,
        )
        assert "Bob" in text
        assert not any(a["original"] == "Bob" for a in audit)

    async def test_whole_word_matching(self, populated_store):
        """'Sam' must not match inside 'Sample'."""
        text, audit = await rewrite_message(
            populated_store, "Send a Sample to Sam", 1,
        )
        assert "Sample" in text  # Sample unchanged
        assert "user 2" in text  # Sam replaced

    async def test_longer_names_first(self, store):
        """'Sarah Jane' should be replaced before 'Sarah'."""
        await store.create_user("Owner")
        await store.create_contact(1, "Sarah")        # contact_id=1
        await store.create_contact(1, "Sarah Jane")   # contact_id=2
        text, audit = await rewrite_message(
            store, "message Sarah Jane about the meeting", 1,
        )
        assert "user 2" in text  # Sarah Jane (contact_id=2) matched
        assert "Sarah Jane" not in text
