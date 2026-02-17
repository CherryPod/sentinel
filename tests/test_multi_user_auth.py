"""Tests for multi-user auth (Phase 1).

Covers JWT session tokens, login endpoint, role guard on auth routes,
PinVerifier round-trip, middleware Bearer token handling, and
trust level resolution in the orchestrator path.
"""

import time

import jwt
import pytest

from sentinel.api.auth import PinVerifier
from sentinel.api.sessions import (
    SESSION_TTL,
    create_session_token,
    verify_session_token,
    get_secret,
)
from sentinel.core.context import resolve_trust_level


# ── Task 1.1: Session token infrastructure ────────────────────────


class TestSessionTokens:
    """JWT create/verify round-trip."""

    def test_create_and_verify(self):
        token = create_session_token(user_id=1, role="owner")
        payload = verify_session_token(token)
        assert payload["user_id"] == 1
        assert payload["role"] == "owner"
        assert "exp" in payload
        assert "iat" in payload

    def test_expired_token_rejected(self):
        # Create a token that's already expired
        secret = get_secret()
        now = int(time.time())
        payload = {"user_id": 1, "role": "owner", "iat": now - 100, "exp": now - 10}
        token = jwt.encode(payload, secret, algorithm="HS256")
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_session_token(token)

    def test_invalid_token_rejected(self):
        with pytest.raises(jwt.InvalidTokenError):
            verify_session_token("not.a.valid.token")

    def test_wrong_secret_rejected(self):
        token = jwt.encode(
            {"user_id": 1, "iat": int(time.time()), "exp": int(time.time()) + 3600},
            "wrong-secret",
            algorithm="HS256",
        )
        with pytest.raises(jwt.InvalidSignatureError):
            verify_session_token(token)

    def test_token_contains_role(self):
        token = create_session_token(user_id=2, role="admin")
        payload = verify_session_token(token)
        assert payload["role"] == "admin"

    def test_ttl_is_24_hours(self):
        token = create_session_token(user_id=1)
        payload = verify_session_token(token)
        assert payload["exp"] - payload["iat"] == SESSION_TTL


# ── Task 1.2: Login endpoint ──────────────────────────────────────


class TestLoginEndpoint:
    """POST /api/auth/login tests."""

    @pytest.fixture
    def auth_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from sentinel.api.auth_routes import router, init_auth_store
        from sentinel.api.contacts import router as contacts_router, init_stores
        from sentinel.contacts.store import ContactStore
        from sentinel.routines.store import RoutineStore
        from sentinel.core.context import current_user_id

        store = ContactStore(pool=None)
        # Seed user 1 (owner) with a hashed PIN
        verifier = PinVerifier("1234")
        store._users[1] = {
            "user_id": 1, "display_name": "Admin", "pin_hash": verifier.to_stored(),
            "is_active": True, "role": "owner", "trust_level": 4,
            "created_at": "2026-01-01T00:00:00.000Z",
            "sessions_invalidated_at": None,
        }
        store._next_user_id = 2

        app = FastAPI()
        init_auth_store(store)
        init_stores(store, RoutineStore(pool=None))
        app.include_router(router)
        app.include_router(contacts_router)

        # Set user context for admin operations
        token = current_user_id.set(1)
        client = TestClient(app)
        yield client, store
        current_user_id.reset(token)

    def test_login_success(self, auth_app):
        client, store = auth_app
        resp = client.post("/api/auth/login", json={
            "username": "Admin", "pin": "1234",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["user_id"] == 1
        assert data["role"] == "owner"
        assert data["display_name"] == "Admin"

    def test_login_wrong_pin(self, auth_app):
        client, _ = auth_app
        resp = client.post("/api/auth/login", json={
            "username": "Admin", "pin": "0000",
        })
        assert resp.status_code == 401

    def test_login_unknown_user(self, auth_app):
        client, _ = auth_app
        resp = client.post("/api/auth/login", json={
            "username": "Nobody", "pin": "1234",
        })
        assert resp.status_code == 401

    def test_login_case_insensitive(self, auth_app):
        client, _ = auth_app
        resp = client.post("/api/auth/login", json={
            "username": "admin", "pin": "1234",
        })
        assert resp.status_code == 200

    def test_login_deactivated_user(self, auth_app):
        client, store = auth_app
        store._users[1]["is_active"] = False
        resp = client.post("/api/auth/login", json={
            "username": "Admin", "pin": "1234",
        })
        assert resp.status_code == 401
        store._users[1]["is_active"] = True  # restore

    def test_login_pending_user(self, auth_app):
        client, store = auth_app
        store._users[1]["role"] = "pending"
        resp = client.post("/api/auth/login", json={
            "username": "Admin", "pin": "1234",
        })
        assert resp.status_code == 401
        store._users[1]["role"] = "owner"  # restore


# ── Task 1.3: Middleware Bearer token ─────────────────────────────


class TestUserContextMiddleware:
    """UserContextMiddleware extracts user_id from Bearer token."""

    @pytest.fixture
    def mw_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from sentinel.api.middleware import UserContextMiddleware
        from sentinel.core.context import current_user_id

        app = FastAPI()
        app.add_middleware(UserContextMiddleware)

        @app.get("/test/whoami")
        async def whoami():
            return {"user_id": current_user_id.get()}

        return TestClient(app)

    def test_bearer_token_sets_user_id(self, mw_app):
        token = create_session_token(user_id=42, role="user")
        resp = mw_app.get("/test/whoami", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 200
        assert resp.json()["user_id"] == 42

    def test_no_auth_defaults_to_user_1(self, mw_app):
        resp = mw_app.get("/test/whoami")
        assert resp.status_code == 200
        assert resp.json()["user_id"] == 1

    def test_expired_token_returns_401(self, mw_app):
        secret = get_secret()
        now = int(time.time())
        token = jwt.encode(
            {"user_id": 1, "iat": now - 100, "exp": now - 10},
            secret, algorithm="HS256",
        )
        resp = mw_app.get("/test/whoami", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, mw_app):
        resp = mw_app.get("/test/whoami", headers={
            "Authorization": "Bearer garbage",
        })
        assert resp.status_code == 401


# ── Task 1.5: Sender resolution ──────────────────────────────────


class TestSenderResolution:
    """resolve_sender maps channel+identifier to user_id."""

    @pytest.fixture
    def contact_store(self):
        from sentinel.contacts.store import ContactStore
        store = ContactStore(pool=None)
        # User 1 with signal contact
        store._users[1] = {
            "user_id": 1, "display_name": "Admin", "pin_hash": None,
            "is_active": True, "role": "owner", "trust_level": 4,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        store._contacts[1] = {
            "contact_id": 1, "user_id": 1, "display_name": "Admin",
            "linked_user_id": 1, "is_user": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        store._channels[1] = {
            "id": 1, "contact_id": 1, "channel": "signal",
            "identifier": "uuid-admin", "is_default": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        # User 2 with telegram contact
        store._users[2] = {
            "user_id": 2, "display_name": "Bob", "pin_hash": None,
            "is_active": True, "role": "user", "trust_level": None,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        store._contacts[2] = {
            "contact_id": 2, "user_id": 2, "display_name": "Bob",
            "linked_user_id": 2, "is_user": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        store._channels[2] = {
            "id": 2, "contact_id": 2, "channel": "telegram",
            "identifier": "12345", "is_default": True,
            "created_at": "2026-01-01T00:00:00.000Z",
        }
        return store

    @pytest.mark.asyncio
    async def test_resolve_signal_sender(self, contact_store):
        from sentinel.contacts.resolver import resolve_sender
        from sentinel.core.context import current_user_id
        # Must set context so get_contact works with RLS-like scoping
        token = current_user_id.set(1)
        try:
            result = await resolve_sender(contact_store, "signal", "uuid-admin")
            assert result == 1
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_resolve_telegram_sender(self, contact_store):
        from sentinel.contacts.resolver import resolve_sender
        from sentinel.core.context import current_user_id
        token = current_user_id.set(2)
        try:
            result = await resolve_sender(contact_store, "telegram", "12345")
            assert result == 2
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_unknown_sender_returns_none(self, contact_store):
        from sentinel.contacts.resolver import resolve_sender
        from sentinel.core.context import current_user_id
        token = current_user_id.set(1)
        try:
            result = await resolve_sender(contact_store, "signal", "unknown-uuid")
            assert result is None
        finally:
            current_user_id.reset(token)


# ── Task 1.7: Scheduler multi-user routine discovery ─────────────


class TestSchedulerMultiUser:
    """Scheduler discovers routines from all users."""

    @pytest.mark.asyncio
    async def test_list_due_all_users(self):
        from sentinel.routines.store import RoutineStore
        store = RoutineStore(pool=None)
        # Create routines for two different users
        await store.create(
            name="user1-routine", trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "test"}, user_id=1,
        )
        await store.create(
            name="user2-routine", trigger_type="cron",
            trigger_config={"cron": "* * * * *"},
            action_config={"prompt": "test"}, user_id=2,
        )
        # Set next_run_at to the past for both
        import dataclasses
        for rid in list(store._mem):
            r = store._mem[rid]
            store._mem[rid] = dataclasses.replace(
                r, next_run_at="2020-01-01T00:00:00.000Z",
            )

        due = await store.list_due_all_users("2026-01-01T00:00:00.000Z")
        user_ids = {r.user_id for r in due}
        assert 1 in user_ids
        assert 2 in user_ids
        assert len(due) == 2


# ── Task 1.4: Per-user trust level wiring ─────────────────────────


class TestPerUserTrustLevel:
    """Trust level resolution uses per-user override."""

    def test_per_user_tl_overrides_system(self):
        assert resolve_trust_level(2, system_default=4) == 2

    def test_null_tl_uses_system(self):
        assert resolve_trust_level(None, system_default=4) == 4

    def test_zero_is_valid_override(self):
        assert resolve_trust_level(0, system_default=4) == 0
