"""Tests for contact registry API endpoints — users, contacts, channels.

Uses a minimal FastAPI app with real ContactStore (in-memory) + RoutineStore (in-memory)
to avoid full lifespan dependencies.
"""

import asyncio
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from sentinel.api.contacts import router, init_stores
from sentinel.contacts.store import ContactStore
from sentinel.core.context import current_user_id
from sentinel.routines.store import RoutineStore


def _run(coro):
    """Run an async coroutine synchronously (for use with TestClient-based tests)."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(autouse=True)
def _set_user_context():
    """Set current_user_id=1 — matches user_id used in contact creation."""
    token = current_user_id.set(1)
    yield
    current_user_id.reset(token)


@pytest.fixture
def contact_store():
    store = ContactStore(pool=None)
    # Seed user 1 as owner so role guard checks pass
    store._users[1] = {
        "user_id": 1, "display_name": "Admin", "pin_hash": None,
        "is_active": True, "role": "owner", "trust_level": 4,
        "created_at": "2026-01-01T00:00:00.000Z",
    }
    store._next_user_id = 2
    return store


@pytest.fixture
def routine_store():
    return RoutineStore(pool=None)


@pytest.fixture
def client(contact_store, routine_store):
    from fastapi import FastAPI
    app = FastAPI()
    init_stores(contact_store, routine_store)
    app.include_router(router)
    return TestClient(app)


# ── User endpoints ───────────────────────────────────────────────


class TestUserEndpoints:

    def test_create_user(self, client):
        resp = client.post("/api/users", json={"display_name": "Alice"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["display_name"] == "Alice"
        assert data["is_active"] is True
        assert "pin_hash" not in data
        assert "pin" not in data

    def test_create_user_with_pin_not_exposed(self, client):
        resp = client.post("/api/users", json={"display_name": "Bob", "pin": "1234"})
        assert resp.status_code == 201
        data = resp.json()
        assert "pin_hash" not in data
        assert "pin" not in data

    def test_get_user(self, client):
        resp = client.post("/api/users", json={"display_name": "Alice"})
        user_id = resp.json()["user_id"]
        resp = client.get(f"/api/users/{user_id}")
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "Alice"
        assert "pin_hash" not in resp.json()

    def test_get_nonexistent_user(self, client):
        resp = client.get("/api/users/9999")
        assert resp.status_code == 404

    def test_list_users_active_only(self, client):
        client.post("/api/users", json={"display_name": "Active"})
        resp2 = client.post("/api/users", json={"display_name": "Inactive"})
        user_id = resp2.json()["user_id"]
        client.delete(f"/api/users/{user_id}")

        # Default: active_only=true
        resp = client.get("/api/users")
        names = [u["display_name"] for u in resp.json()]
        assert "Active" in names
        assert "Inactive" not in names

        # active_only=false shows both
        resp = client.get("/api/users", params={"active_only": False})
        names = [u["display_name"] for u in resp.json()]
        assert "Active" in names
        assert "Inactive" in names

    def test_deactivate_user(self, client):
        resp = client.post("/api/users", json={"display_name": "ToDeactivate"})
        user_id = resp.json()["user_id"]
        resp = client.delete(f"/api/users/{user_id}")
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    def test_update_user(self, client):
        resp = client.post("/api/users", json={"display_name": "OldName"})
        user_id = resp.json()["user_id"]
        resp = client.put(f"/api/users/{user_id}", json={"display_name": "NewName"})
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "NewName"
        assert "pin_hash" not in resp.json()


# ── Contact endpoints ────────────────────────────────────────────


class TestContactEndpoints:

    def test_create_contact(self, client):
        # Contact is created under current_user_id (=1), not a passed user_id
        resp = client.post("/api/contacts", json={
            "display_name": "Alice",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["display_name"] == "Alice"
        assert data["user_id"] == 1  # current_user_id from fixture

    def test_get_contact_includes_channels(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Alice"))
        _run(contact_store.create_channel(contact["contact_id"], "signal", "uuid-123"))

        resp = client.get(f"/api/contacts/{contact['contact_id']}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["display_name"] == "Alice"
        assert len(data["channels"]) == 1
        assert data["channels"][0]["channel"] == "signal"

    def test_list_contacts_by_user(self, client, contact_store):
        # Create contacts under user 1 (current_user_id) and user 2
        _run(contact_store.create_contact(1, "Alice"))
        _run(contact_store.create_contact(1, "Bob"))
        # User 2's contacts won't be visible to user 1
        user2 = _run(contact_store.create_user("User2"))
        _run(contact_store.create_contact(user2["user_id"], "Charlie"))

        resp = client.get("/api/contacts")
        assert resp.status_code == 200
        names = [c["display_name"] for c in resp.json()]
        assert "Alice" in names
        assert "Bob" in names
        assert "Charlie" not in names

    def test_get_nonexistent_contact(self, client):
        resp = client.get("/api/contacts/9999")
        assert resp.status_code == 404

    def test_update_contact(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "OldName"))

        resp = client.put(
            f"/api/contacts/{contact['contact_id']}",
            json={"display_name": "NewName"},
        )
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "NewName"

    def test_delete_contact_no_routine_refs(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Disposable"))

        resp = client.delete(f"/api/contacts/{contact['contact_id']}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

        # Verify it's gone
        resp = client.get(f"/api/contacts/{contact['contact_id']}")
        assert resp.status_code == 404

    def test_delete_contact_with_routine_refs(self, client, contact_store, routine_store):
        contact = _run(contact_store.create_contact(1, "Alice"))

        # Create a routine that references "Alice" in its prompt
        _run(routine_store.create(
            name="morning-signal",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Send Keith a good morning message via Signal"},
            user_id=1,
        ))

        resp = client.delete(f"/api/contacts/{contact['contact_id']}")
        assert resp.status_code == 200
        data = resp.json()
        assert "warning" in data
        assert "1 routine" in data["warning"]
        assert "morning-signal" in data["warning"]
        assert "confirm_url" in data

        # Contact still exists
        resp = client.get(f"/api/contacts/{contact['contact_id']}")
        assert resp.status_code == 200

    def test_delete_contact_with_confirm(self, client, contact_store, routine_store):
        contact = _run(contact_store.create_contact(1, "Alice"))

        _run(routine_store.create(
            name="morning-signal",
            trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Send Keith a good morning message"},
            user_id=1,
        ))

        # Force delete with confirm=true
        resp = client.delete(
            f"/api/contacts/{contact['contact_id']}",
            params={"confirm": True},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

        # Verify it's gone
        resp = client.get(f"/api/contacts/{contact['contact_id']}")
        assert resp.status_code == 404


# ── Channel endpoints ────────────────────────────────────────────


class TestChannelEndpoints:

    def test_add_channel(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Alice"))

        resp = client.post(
            f"/api/contacts/{contact['contact_id']}/channels",
            json={"channel": "signal", "identifier": "uuid-abc-123"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["channel"] == "signal"
        assert data["identifier"] == "uuid-abc-123"
        assert data["is_default"] is True

    def test_list_channels(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Alice"))
        _run(contact_store.create_channel(contact["contact_id"], "signal", "uuid-1"))
        _run(contact_store.create_channel(contact["contact_id"], "email", "k@example.com"))

        resp = client.get(f"/api/contacts/{contact['contact_id']}/channels")
        assert resp.status_code == 200
        channels = resp.json()
        assert len(channels) == 2
        types = {ch["channel"] for ch in channels}
        assert types == {"signal", "email"}

    def test_duplicate_channel_identifier(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Alice"))

        client.post(
            f"/api/contacts/{contact['contact_id']}/channels",
            json={"channel": "signal", "identifier": "uuid-same"},
        )
        # Same (channel, identifier) should 409
        resp = client.post(
            f"/api/contacts/{contact['contact_id']}/channels",
            json={"channel": "signal", "identifier": "uuid-same"},
        )
        assert resp.status_code == 409

    def test_invalid_channel_type(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Alice"))

        resp = client.post(
            f"/api/contacts/{contact['contact_id']}/channels",
            json={"channel": "singal", "identifier": "typo-test"},
        )
        assert resp.status_code == 422

    def test_delete_channel(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Alice"))
        ch = _run(contact_store.create_channel(contact["contact_id"], "email", "k@example.com"))

        resp = client.delete(
            f"/api/contacts/{contact['contact_id']}/channels/{ch['id']}",
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

        # Verify gone
        resp = client.get(f"/api/contacts/{contact['contact_id']}/channels")
        assert resp.json() == []

    def test_update_channel(self, client, contact_store):
        contact = _run(contact_store.create_contact(1, "Alice"))
        ch = _run(contact_store.create_channel(contact["contact_id"], "email", "old@example.com"))

        resp = client.put(
            f"/api/contacts/{contact['contact_id']}/channels/{ch['id']}",
            json={"identifier": "new@example.com"},
        )
        assert resp.status_code == 200
        assert resp.json()["identifier"] == "new@example.com"

    def test_channel_on_nonexistent_contact(self, client):
        resp = client.get("/api/contacts/9999/channels")
        assert resp.status_code == 404

        resp = client.post(
            "/api/contacts/9999/channels",
            json={"channel": "signal", "identifier": "test"},
        )
        assert resp.status_code == 404
