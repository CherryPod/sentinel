"""Two-user isolation end-to-end test (Phase 2).

Proves that two users on one Sentinel instance have fully isolated data
across contacts, routines, and sessions. Uses in-memory stores (no DB)
to validate the API-level isolation logic.

For full RLS-level isolation, run against a real PG instance after
container rebuild (see Task 2.2 manual checklist).
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinel.api.auth import PinVerifier
from sentinel.api.auth_routes import router as auth_router, init_auth_store
from sentinel.api.contacts import router as contacts_router, init_stores
from sentinel.api.middleware import UserContextMiddleware
from sentinel.api.sessions import create_session_token
from sentinel.contacts.store import ContactStore
from sentinel.core.context import current_user_id
from sentinel.routines.store import RoutineStore


@pytest.fixture
def two_user_app():
    """FastAPI app with two seeded users and in-memory stores."""
    contact_store = ContactStore(pool=None)
    routine_store = RoutineStore(pool=None)

    # Seed user 1 (owner) with hashed PIN
    v1 = PinVerifier("1111")
    contact_store._users[1] = {
        "user_id": 1, "display_name": "Admin", "pin_hash": v1.to_stored(),
        "is_active": True, "role": "owner", "trust_level": 4,
        "created_at": "2026-01-01T00:00:00.000Z",
        "sessions_invalidated_at": None,
    }

    # Seed user 2 (regular user) with hashed PIN
    v2 = PinVerifier("2222")
    contact_store._users[2] = {
        "user_id": 2, "display_name": "Alice", "pin_hash": v2.to_stored(),
        "is_active": True, "role": "user", "trust_level": 2,
        "created_at": "2026-01-01T00:00:00.000Z",
        "sessions_invalidated_at": None,
    }
    contact_store._next_user_id = 3

    app = FastAPI()
    app.add_middleware(UserContextMiddleware)
    init_auth_store(contact_store)
    init_stores(contact_store, routine_store)
    app.include_router(auth_router)
    app.include_router(contacts_router)

    return TestClient(app), contact_store, routine_store


def _login(client, username, pin):
    """Login and return the Bearer token."""
    resp = client.post("/api/auth/login", json={
        "username": username, "pin": pin,
    })
    assert resp.status_code == 200, f"Login failed for {username}: {resp.json()}"
    return resp.json()["token"]


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ── Authentication isolation ──────────────────────────────────────


class TestAuthIsolation:
    """Each user gets their own session token and identity."""

    def test_both_users_can_login(self, two_user_app):
        client, _, _ = two_user_app
        t1 = _login(client, "Admin", "1111")
        t2 = _login(client, "Alice", "2222")
        assert t1 != t2

    def test_wrong_pin_rejected(self, two_user_app):
        client, _, _ = two_user_app
        resp = client.post("/api/auth/login", json={
            "username": "Alice", "pin": "1111",  # Admin's PIN, not Alice's
        })
        assert resp.status_code == 401

    def test_token_identifies_correct_user(self, two_user_app):
        client, _, _ = two_user_app
        from sentinel.api.sessions import verify_session_token
        t1 = _login(client, "Admin", "1111")
        t2 = _login(client, "Alice", "2222")
        p1 = verify_session_token(t1)
        p2 = verify_session_token(t2)
        assert p1["user_id"] == 1
        assert p2["user_id"] == 2
        assert p1["role"] == "owner"
        assert p2["role"] == "user"


# ── Contact isolation ─────────────────────────────────────────────


class TestContactIsolation:
    """Each user's contacts are invisible to the other."""

    def test_user1_contacts_not_visible_to_user2(self, two_user_app):
        client, store, _ = two_user_app
        t1 = _login(client, "Admin", "1111")
        t2 = _login(client, "Alice", "2222")

        # User 1 creates a contact
        resp = client.post("/api/contacts", json={
            "display_name": "Keith",
        }, headers=_auth_headers(t1))
        assert resp.status_code == 201
        keith_id = resp.json()["contact_id"]

        # User 1 can see it
        resp = client.get("/api/contacts", headers=_auth_headers(t1))
        names_1 = [c["display_name"] for c in resp.json()]
        assert "Keith" in names_1

        # User 2 cannot see it
        resp = client.get("/api/contacts", headers=_auth_headers(t2))
        names_2 = [c["display_name"] for c in resp.json()]
        assert "Keith" not in names_2

    def test_user2_contacts_not_visible_to_user1(self, two_user_app):
        client, store, _ = two_user_app
        t1 = _login(client, "Admin", "1111")
        t2 = _login(client, "Alice", "2222")

        # User 2 creates a contact
        resp = client.post("/api/contacts", json={
            "display_name": "Bob",
        }, headers=_auth_headers(t2))
        assert resp.status_code == 201

        # User 2 can see it
        resp = client.get("/api/contacts", headers=_auth_headers(t2))
        names_2 = [c["display_name"] for c in resp.json()]
        assert "Bob" in names_2

        # User 1 cannot see it
        resp = client.get("/api/contacts", headers=_auth_headers(t1))
        names_1 = [c["display_name"] for c in resp.json()]
        assert "Bob" not in names_1

    def test_user2_cannot_delete_user1_contact(self, two_user_app):
        client, store, _ = two_user_app
        t1 = _login(client, "Admin", "1111")
        t2 = _login(client, "Alice", "2222")

        # User 1 creates a contact
        resp = client.post("/api/contacts", json={
            "display_name": "Protected",
        }, headers=_auth_headers(t1))
        contact_id = resp.json()["contact_id"]

        # User 2 tries to delete it — should get 404 (not visible)
        resp = client.delete(f"/api/contacts/{contact_id}", headers=_auth_headers(t2))
        assert resp.status_code == 404


# ── Routine isolation ─────────────────────────────────────────────


class TestRoutineIsolation:
    """Each user's routines are scoped to their user_id."""

    @pytest.mark.asyncio
    async def test_routines_scoped_by_user_id(self, two_user_app):
        _, _, routine_store = two_user_app

        # Create routines for each user
        r1 = await routine_store.create(
            name="user1-morning", trigger_type="cron",
            trigger_config={"cron": "0 9 * * *"},
            action_config={"prompt": "Good morning user 1"},
            user_id=1,
        )
        r2 = await routine_store.create(
            name="user2-evening", trigger_type="cron",
            trigger_config={"cron": "0 21 * * *"},
            action_config={"prompt": "Good evening user 2"},
            user_id=2,
        )

        # List for user 1 — should only see their routine
        u1_routines = await routine_store.list(user_id=1)
        u1_names = [r.name for r in u1_routines]
        assert "user1-morning" in u1_names
        assert "user2-evening" not in u1_names

        # List for user 2 — should only see their routine
        u2_routines = await routine_store.list(user_id=2)
        u2_names = [r.name for r in u2_routines]
        assert "user2-evening" in u2_names
        assert "user1-morning" not in u2_names

    @pytest.mark.asyncio
    async def test_scheduler_sees_all_users_routines(self, two_user_app):
        """Scheduler discovery (list_due_all_users) finds routines from both users."""
        import dataclasses
        _, _, routine_store = two_user_app

        r1 = await routine_store.create(
            name="user1-due", trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "test"}, user_id=1,
        )
        r2 = await routine_store.create(
            name="user2-due", trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "test"}, user_id=2,
        )

        # Make both due
        for rid in list(routine_store._mem):
            r = routine_store._mem[rid]
            routine_store._mem[rid] = dataclasses.replace(
                r, next_run_at="2020-01-01T00:00:00.000Z",
            )

        # Scheduler sees both
        due = await routine_store.list_due_all_users("2026-01-01T00:00:00.000Z")
        due_users = {r.user_id for r in due}
        assert due_users == {1, 2}


# ── Sender resolution ────────────────────────────────────────────


class TestSenderResolutionIsolation:
    """Channel identifier resolves to the correct user."""

    @pytest.mark.asyncio
    async def test_signal_resolves_to_correct_user(self, two_user_app):
        from sentinel.contacts.resolver import resolve_sender
        _, store, _ = two_user_app

        # Set up signal contacts for both users
        store._contacts[1] = {
            "contact_id": 1, "user_id": 1, "display_name": "Admin",
            "linked_user_id": 1, "is_user": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        store._channels[1] = {
            "id": 1, "contact_id": 1, "channel": "signal",
            "identifier": "uuid-admin-123", "is_default": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        store._contacts[2] = {
            "contact_id": 2, "user_id": 2, "display_name": "Alice",
            "linked_user_id": 2, "is_user": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        store._channels[2] = {
            "id": 2, "contact_id": 2, "channel": "signal",
            "identifier": "uuid-alice-456", "is_default": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }

        # Resolve with user 1's context
        token = current_user_id.set(1)
        try:
            uid = await resolve_sender(store, "signal", "uuid-admin-123")
            assert uid == 1
        finally:
            current_user_id.reset(token)

        # Resolve with user 2's context
        token = current_user_id.set(2)
        try:
            uid = await resolve_sender(store, "signal", "uuid-alice-456")
            assert uid == 2
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_unknown_identifier_returns_none(self, two_user_app):
        from sentinel.contacts.resolver import resolve_sender
        _, store, _ = two_user_app

        token = current_user_id.set(1)
        try:
            uid = await resolve_sender(store, "signal", "unknown-uuid")
            assert uid is None
        finally:
            current_user_id.reset(token)


# ── Role guard isolation ──────────────────────────────────────────


class TestRoleGuardIsolation:
    """Non-admin users cannot create/modify/delete users."""

    def test_regular_user_cannot_create_user(self, two_user_app):
        client, _, _ = two_user_app
        t2 = _login(client, "Alice", "2222")

        resp = client.post("/api/users", json={
            "display_name": "Eve",
        }, headers=_auth_headers(t2))
        assert resp.status_code == 403

    def test_admin_can_create_user(self, two_user_app):
        client, _, _ = two_user_app
        t1 = _login(client, "Admin", "1111")

        resp = client.post("/api/users", json={
            "display_name": "Eve", "pin": "3333",
        }, headers=_auth_headers(t1))
        assert resp.status_code == 201
        assert resp.json()["display_name"] == "Eve"

    def test_regular_user_cannot_deactivate_admin(self, two_user_app):
        client, _, _ = two_user_app
        t2 = _login(client, "Alice", "2222")

        resp = client.delete("/api/users/1", headers=_auth_headers(t2))
        assert resp.status_code == 403


# ── Trust level isolation ─────────────────────────────────────────


class TestTrustLevelIsolation:
    """Per-user trust levels resolve correctly."""

    @pytest.mark.asyncio
    async def test_user1_has_tl4(self, two_user_app):
        _, store, _ = two_user_app
        tl = await store.get_user_trust_level(1)
        assert tl == 4

    @pytest.mark.asyncio
    async def test_user2_has_tl2(self, two_user_app):
        _, store, _ = two_user_app
        tl = await store.get_user_trust_level(2)
        assert tl == 2

    def test_effective_tl_uses_per_user_override(self):
        from sentinel.core.context import resolve_trust_level
        # User 2 with TL2 on a system with TL4 default
        assert resolve_trust_level(user_trust_level=2, system_default=4) == 2
