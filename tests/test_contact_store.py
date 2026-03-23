"""Tests for ContactStore CRUD operations.

Verifies:
- Users: create, get, list, update, deactivate
- Contacts: create, get, list, update, delete (cascade), unique constraint
- Contact Channels: create, get, reverse lookup, update, delete, unique constraint
- All tests use in-memory mode (pool=None)
"""

import pytest

from sentinel.contacts.store import ContactStore
from sentinel.core.context import current_user_id


@pytest.fixture(autouse=True)
def _set_user_context():
    """Set current_user_id=1 for all tests — matches user_id used in create_contact."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


@pytest.fixture
def store():
    """ContactStore using in-memory dict (no database)."""
    return ContactStore(pool=None)


# ── Users ─────────────────────────────────────────────────────────


class TestUsers:
    async def test_create_and_get(self, store):
        user = await store.create_user("Keith")
        assert user["user_id"] == 1
        assert user["display_name"] == "Keith"
        assert user["is_active"] is True
        assert user["pin_hash"] is None
        assert user["created_at"]

        fetched = await store.get_user(user["user_id"])
        assert fetched is not None
        assert fetched["display_name"] == "Keith"

    async def test_create_with_pin_hash(self, store):
        user = await store.create_user("Alice", pin_hash="$2b$12$fakehash")
        assert user["pin_hash"] == "$2b$12$fakehash"

    async def test_get_nonexistent_returns_none(self, store):
        assert await store.get_user(999) is None

    async def test_list_active_only(self, store):
        await store.create_user("Active")
        u2 = await store.create_user("Inactive")
        await store.deactivate_user(u2["user_id"])

        active = await store.list_users(active_only=True)
        assert len(active) == 1
        assert active[0]["display_name"] == "Active"

    async def test_list_all(self, store):
        await store.create_user("Active")
        u2 = await store.create_user("Inactive")
        await store.deactivate_user(u2["user_id"])

        all_users = await store.list_users(active_only=False)
        assert len(all_users) == 2

    async def test_update(self, store):
        user = await store.create_user("Original")
        updated = await store.update_user(
            user["user_id"], display_name="Renamed",
        )
        assert updated is not None
        assert updated["display_name"] == "Renamed"

        # Verify persisted
        fetched = await store.get_user(user["user_id"])
        assert fetched["display_name"] == "Renamed"

    async def test_update_rejects_unknown_fields(self, store):
        user = await store.create_user("Test")
        with pytest.raises(ValueError, match="Invalid update fields"):
            await store.update_user(user["user_id"], evil_column="DROP TABLE")

    async def test_update_nonexistent_returns_none(self, store):
        assert await store.update_user(999, display_name="x") is None

    async def test_deactivate(self, store):
        user = await store.create_user("ToDisable")
        assert await store.deactivate_user(user["user_id"]) is True

        fetched = await store.get_user(user["user_id"])
        assert fetched["is_active"] is False

    async def test_deactivate_nonexistent_returns_false(self, store):
        assert await store.deactivate_user(999) is False

    async def test_users_can_share_names(self, store):
        """Users table has no unique constraint on display_name."""
        u1 = await store.create_user("Keith")
        u2 = await store.create_user("Keith")
        assert u1["user_id"] != u2["user_id"]


# ── Contacts ──────────────────────────────────────────────────────


class TestContacts:
    async def test_create_and_get(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        assert contact["contact_id"] == 1
        assert contact["display_name"] == "Sarah"
        assert contact["user_id"] == user["user_id"]
        assert contact["is_user"] is False
        assert contact["linked_user_id"] is None

        fetched = await store.get_contact(contact["contact_id"])
        assert fetched is not None
        assert fetched["display_name"] == "Sarah"

    async def test_create_with_linked_user(self, store):
        u1 = await store.create_user("Keith")
        u2 = await store.create_user("Sarah")
        contact = await store.create_contact(
            u1["user_id"], "Sarah", linked_user_id=u2["user_id"], is_user=True,
        )
        assert contact["linked_user_id"] == u2["user_id"]
        assert contact["is_user"] is True

    async def test_get_nonexistent_returns_none(self, store):
        assert await store.get_contact(999) is None

    async def test_list_by_user(self, store):
        u1 = await store.create_user("Keith")
        u2 = await store.create_user("Other")
        await store.create_contact(u1["user_id"], "Alice")
        await store.create_contact(u1["user_id"], "Bob")
        await store.create_contact(u2["user_id"], "Charlie")

        keith_contacts = await store.list_contacts(u1["user_id"])
        assert len(keith_contacts) == 2
        # Sorted by display_name
        assert keith_contacts[0]["display_name"] == "Alice"
        assert keith_contacts[1]["display_name"] == "Bob"

    async def test_update(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "OldName")
        updated = await store.update_contact(
            contact["contact_id"], display_name="NewName",
        )
        assert updated is not None
        assert updated["display_name"] == "NewName"

    async def test_update_rejects_unknown_fields(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Test")
        with pytest.raises(ValueError, match="Invalid update fields"):
            await store.update_contact(contact["contact_id"], evil="DROP TABLE")

    async def test_update_nonexistent_returns_none(self, store):
        assert await store.update_contact(999, display_name="x") is None

    async def test_delete_cascades_to_channels(self, store):
        """Deleting a contact removes its channel entries."""
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        await store.create_channel(contact["contact_id"], "signal", "uuid-123")
        await store.create_channel(contact["contact_id"], "email", "s@test.com")

        # Verify channels exist
        channels = await store.get_channels(contact["contact_id"])
        assert len(channels) == 2

        # Delete contact — channels should cascade
        assert await store.delete_contact(contact["contact_id"]) is True
        assert await store.get_contact(contact["contact_id"]) is None
        channels_after = await store.get_channels(contact["contact_id"])
        assert len(channels_after) == 0

    async def test_delete_nonexistent_returns_false(self, store):
        assert await store.delete_contact(999) is False

    async def test_unique_name_per_owner(self, store):
        """UNIQUE(user_id, display_name) prevents duplicate contact names."""
        user = await store.create_user("Keith")
        await store.create_contact(user["user_id"], "Sarah")
        with pytest.raises(ValueError, match="Duplicate contact"):
            await store.create_contact(user["user_id"], "Sarah")

    async def test_same_name_different_owners(self, store):
        """Different users can have contacts with the same name."""
        u1 = await store.create_user("Keith")
        u2 = await store.create_user("Alice")
        c1 = await store.create_contact(u1["user_id"], "Sarah")
        c2 = await store.create_contact(u2["user_id"], "Sarah")
        assert c1["contact_id"] != c2["contact_id"]


# ── Contact Channels ──────────────────────────────────────────────


class TestContactChannels:
    async def test_create_and_get(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        ch = await store.create_channel(
            contact["contact_id"], "signal", "uuid-abc-123",
        )
        assert ch["id"] == 1
        assert ch["channel"] == "signal"
        assert ch["identifier"] == "uuid-abc-123"
        assert ch["is_default"] is True
        assert ch["contact_id"] == contact["contact_id"]

        channels = await store.get_channels(contact["contact_id"])
        assert len(channels) == 1
        assert channels[0]["identifier"] == "uuid-abc-123"

    async def test_create_non_default(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        ch = await store.create_channel(
            contact["contact_id"], "email", "alt@test.com", is_default=False,
        )
        assert ch["is_default"] is False

    async def test_multiple_channels_per_contact(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        await store.create_channel(contact["contact_id"], "signal", "uuid-1")
        await store.create_channel(contact["contact_id"], "email", "s@test.com")
        await store.create_channel(contact["contact_id"], "telegram", "12345")

        channels = await store.get_channels(contact["contact_id"])
        assert len(channels) == 3
        # Sorted by channel name
        channel_types = [ch["channel"] for ch in channels]
        assert channel_types == ["email", "signal", "telegram"]

    async def test_get_by_identifier_reverse_lookup(self, store):
        """Reverse lookup — find contact by channel identifier."""
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        await store.create_channel(contact["contact_id"], "signal", "uuid-abc")

        result = await store.get_by_identifier("signal", "uuid-abc")
        assert result is not None
        assert result["contact_id"] == contact["contact_id"]
        assert result["contact_name"] == "Sarah"
        assert result["user_id"] == user["user_id"]

    async def test_get_by_identifier_not_found(self, store):
        assert await store.get_by_identifier("signal", "nonexistent") is None

    async def test_update(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        ch = await store.create_channel(
            contact["contact_id"], "email", "old@test.com",
        )
        updated = await store.update_channel(
            ch["id"], identifier="new@test.com",
        )
        assert updated is not None
        assert updated["identifier"] == "new@test.com"

    async def test_update_rejects_unknown_fields(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        ch = await store.create_channel(contact["contact_id"], "email", "a@b.c")
        with pytest.raises(ValueError, match="Invalid update fields"):
            await store.update_channel(ch["id"], evil="DROP TABLE")

    async def test_update_nonexistent_returns_none(self, store):
        assert await store.update_channel(999, identifier="x") is None

    async def test_delete(self, store):
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        ch = await store.create_channel(contact["contact_id"], "signal", "uuid-1")

        assert await store.delete_channel(ch["id"]) is True
        channels = await store.get_channels(contact["contact_id"])
        assert len(channels) == 0

    async def test_delete_nonexistent_returns_false(self, store):
        assert await store.delete_channel(999) is False

    async def test_unique_channel_identifier(self, store):
        """UNIQUE(channel, identifier) prevents two contacts claiming same ID."""
        user = await store.create_user("Keith")
        c1 = await store.create_contact(user["user_id"], "Sarah")
        c2 = await store.create_contact(user["user_id"], "Bob")
        await store.create_channel(c1["contact_id"], "signal", "uuid-shared")

        with pytest.raises(ValueError, match="Duplicate channel"):
            await store.create_channel(c2["contact_id"], "signal", "uuid-shared")

    async def test_same_identifier_different_channels(self, store):
        """Same identifier string is allowed across different channel types."""
        user = await store.create_user("Keith")
        contact = await store.create_contact(user["user_id"], "Sarah")
        ch1 = await store.create_channel(contact["contact_id"], "signal", "12345")
        ch2 = await store.create_channel(contact["contact_id"], "telegram", "12345")
        assert ch1["id"] != ch2["id"]


# ── User ID Filtering (F12) ─────────────────────────────────────


class TestContactStoreUserIdFiltering:
    """F12: Contact store methods filter by user_id — belt and suspenders over RLS."""

    async def test_get_contact_filters_by_user_id(self, store):
        """get_contact returns None for wrong user."""
        contact = await store.create_contact(user_id=1, display_name="Alice")
        # Correct user can fetch
        assert await store.get_contact(contact["contact_id"], user_id=1) is not None
        # Wrong user gets None
        assert await store.get_contact(contact["contact_id"], user_id=99) is None

    async def test_delete_contact_filters_by_user_id(self, store):
        """delete_contact returns False for wrong user."""
        contact = await store.create_contact(user_id=1, display_name="Alice")
        # Wrong user can't delete
        assert await store.delete_contact(contact["contact_id"], user_id=99) is False
        # Contact still exists
        assert await store.get_contact(contact["contact_id"], user_id=1) is not None

    async def test_update_contact_filters_by_user_id(self, store):
        """update_contact returns None for wrong user."""
        contact = await store.create_contact(user_id=1, display_name="Alice")
        result = await store.update_contact(
            contact["contact_id"], user_id=99, display_name="Bob",
        )
        assert result is None
        # Original unchanged
        fetched = await store.get_contact(contact["contact_id"], user_id=1)
        assert fetched["display_name"] == "Alice"

    async def test_get_channels_filters_by_user_id(self, store):
        """get_channels returns [] if contact belongs to different user."""
        contact = await store.create_contact(user_id=1, display_name="Alice")
        await store.create_channel(contact["contact_id"], "signal", "uuid-1")
        # Wrong user gets empty list
        assert await store.get_channels(contact["contact_id"], user_id=99) == []

    async def test_update_channel_filters_by_user_id(self, store):
        """update_channel returns None if parent contact belongs to different user."""
        contact = await store.create_contact(user_id=1, display_name="Alice")
        ch = await store.create_channel(contact["contact_id"], "email", "a@b.c")
        # Wrong user can't update
        result = await store.update_channel(ch["id"], user_id=99, identifier="x@y.z")
        assert result is None
        # Original unchanged
        channels = await store.get_channels(contact["contact_id"], user_id=1)
        assert channels[0]["identifier"] == "a@b.c"

    async def test_delete_channel_filters_by_user_id(self, store):
        """delete_channel returns False if parent contact belongs to different user."""
        contact = await store.create_contact(user_id=1, display_name="Alice")
        ch = await store.create_channel(contact["contact_id"], "signal", "uuid-2")
        # Wrong user can't delete
        assert await store.delete_channel(ch["id"], user_id=99) is False
        # Channel still exists
        channels = await store.get_channels(contact["contact_id"], user_id=1)
        assert len(channels) == 1
