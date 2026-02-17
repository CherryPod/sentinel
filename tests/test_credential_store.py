"""Tests for per-user credential store (Phase 3).

Covers encryption round-trip, credential CRUD, masking, API endpoints,
and per-user isolation.
"""

import pytest

from sentinel.core.context import current_user_id
from sentinel.core.credential_store import (
    CredentialStore,
    DecryptionError,
    decrypt_credentials,
    encrypt_credentials,
    generate_key,
    mask_sensitive,
)


# ── Task 3.2: Encryption layer ───────────────────────────────────


class TestEncryption:
    """AES-256-GCM encrypt/decrypt round-trip."""

    def test_encrypt_decrypt_roundtrip(self):
        key = generate_key()
        data = {"host": "imap.gmail.com", "user": "alice", "password": "secret"}
        encrypted = encrypt_credentials(data, key)
        decrypted = decrypt_credentials(encrypted, key)
        assert decrypted == data

    def test_decrypt_with_wrong_key_fails(self):
        key1, key2 = generate_key(), generate_key()
        encrypted = encrypt_credentials({"foo": "bar"}, key1)
        with pytest.raises(DecryptionError):
            decrypt_credentials(encrypted, key2)

    def test_encrypted_not_plaintext(self):
        key = generate_key()
        encrypted = encrypt_credentials({"password": "secret123"}, key)
        assert b"secret123" not in encrypted

    def test_different_nonces(self):
        key = generate_key()
        data = {"test": "value"}
        e1 = encrypt_credentials(data, key)
        e2 = encrypt_credentials(data, key)
        assert e1 != e2  # Different nonces → different ciphertext

    def test_short_blob_rejected(self):
        key = generate_key()
        with pytest.raises(DecryptionError):
            decrypt_credentials(b"short", key)


# ── Masking ───────────────────────────────────────────────────────


class TestMasking:
    """Sensitive fields are replaced with '***'."""

    def test_masks_password(self):
        result = mask_sensitive({"host": "imap.gmail.com", "password": "secret"})
        assert result["host"] == "imap.gmail.com"
        assert result["password"] == "***"

    def test_masks_multiple_sensitive_fields(self):
        result = mask_sensitive({
            "host": "mail.example.com",
            "password": "pass1",
            "secret": "sec2",
            "api_key": "key3",
            "token": "tok4",
        })
        assert result["host"] == "mail.example.com"
        assert result["password"] == "***"
        assert result["secret"] == "***"
        assert result["api_key"] == "***"
        assert result["token"] == "***"

    def test_leaves_non_sensitive_fields(self):
        result = mask_sensitive({"host": "example.com", "port": 993, "username": "alice"})
        assert result == {"host": "example.com", "port": 993, "username": "alice"}


# ── Task 3.3: Credential store CRUD ──────────────────────────────


class TestCredentialStore:
    """In-memory CRUD operations."""

    @pytest.fixture
    def store(self):
        key = generate_key()
        return CredentialStore(pool=None, key=key)

    @pytest.mark.asyncio
    async def test_set_and_get(self, store):
        token = current_user_id.set(1)
        try:
            await store.set("imap", {"host": "imap.gmail.com", "password": "secret"})
            cred = await store.get("imap")
            assert cred["host"] == "imap.gmail.com"
            assert cred["password"] == "secret"
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_get_missing_returns_none(self, store):
        token = current_user_id.set(1)
        try:
            assert await store.get("caldav") is None
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_upsert_overwrites(self, store):
        token = current_user_id.set(1)
        try:
            await store.set("imap", {"host": "old.example.com"})
            await store.set("imap", {"host": "new.example.com"})
            cred = await store.get("imap")
            assert cred["host"] == "new.example.com"
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_delete(self, store):
        token = current_user_id.set(1)
        try:
            await store.set("imap", {"host": "example.com"})
            assert await store.delete("imap") is True
            assert await store.get("imap") is None
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_delete_missing_returns_false(self, store):
        token = current_user_id.set(1)
        try:
            assert await store.delete("nonexistent") is False
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_list_services(self, store):
        token = current_user_id.set(1)
        try:
            await store.set("imap", {"host": "a"})
            await store.set("caldav", {"url": "b"})
            services = await store.list_services()
            assert services == ["caldav", "imap"]  # sorted
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_user_isolation(self, store):
        """User 1's credentials are not visible to user 2."""
        t1 = current_user_id.set(1)
        try:
            await store.set("imap", {"host": "user1.example.com"})
        finally:
            current_user_id.reset(t1)

        t2 = current_user_id.set(2)
        try:
            # User 2 should not see user 1's credentials
            assert await store.get("imap") is None
            assert await store.list_services() == []
        finally:
            current_user_id.reset(t2)

    @pytest.mark.asyncio
    async def test_explicit_user_id(self, store):
        """Explicit user_id parameter overrides ContextVar."""
        await store.set("smtp", {"host": "mail.example.com"}, user_id=5)
        cred = await store.get("smtp", user_id=5)
        assert cred["host"] == "mail.example.com"
        # Different user sees nothing
        assert await store.get("smtp", user_id=6) is None


# ── Task 3.3: Credential API ─────────────────────────────────────


class TestCredentialAPI:
    """CRUD endpoints for credentials."""

    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from sentinel.api.credentials import router, init_credential_store
        from sentinel.api.middleware import UserContextMiddleware
        from sentinel.api.sessions import create_session_token

        key = generate_key()
        store = CredentialStore(pool=None, key=key)
        init_credential_store(store)

        app = FastAPI()
        app.add_middleware(UserContextMiddleware)
        app.include_router(router)

        token = create_session_token(user_id=1, role="owner")
        client = TestClient(app)
        client.headers["Authorization"] = f"Bearer {token}"
        return client

    def test_list_empty(self, client):
        resp = client.get("/api/credentials")
        assert resp.status_code == 200
        assert resp.json()["services"] == []

    def test_set_and_list(self, client):
        resp = client.put("/api/credentials/imap", json={
            "host": "imap.gmail.com", "port": 993,
            "username": "alice", "password": "secret",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "stored"

        resp = client.get("/api/credentials")
        assert "imap" in resp.json()["services"]

    def test_get_masks_password(self, client):
        client.put("/api/credentials/imap", json={
            "host": "imap.gmail.com", "password": "secret",
        })
        resp = client.get("/api/credentials/imap")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["host"] == "imap.gmail.com"
        assert data["password"] == "***"

    def test_get_missing_returns_404(self, client):
        resp = client.get("/api/credentials/nonexistent")
        assert resp.status_code == 404

    def test_delete(self, client):
        client.put("/api/credentials/imap", json={"host": "example.com"})
        resp = client.delete("/api/credentials/imap")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

        resp = client.get("/api/credentials/imap")
        assert resp.status_code == 404

    def test_delete_missing_returns_404(self, client):
        resp = client.delete("/api/credentials/nonexistent")
        assert resp.status_code == 404


# ── Task 3.4: Executor credential resolution ─────────────────────


class TestExecutorCredentialResolution:
    """ToolExecutor resolves per-user credentials for email/calendar."""

    @pytest.mark.asyncio
    async def test_resolve_returns_credentials(self):
        from unittest.mock import AsyncMock
        from sentinel.tools.executor import ToolExecutor
        from sentinel.security.policy_engine import PolicyEngine

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._rules = []
        engine._trust_level = 4
        executor = ToolExecutor(policy_engine=engine)

        mock_store = AsyncMock()
        mock_store.get.return_value = {"host": "imap.example.com", "password": "secret"}
        executor.set_credential_store(mock_store)

        creds = await executor._resolve_credentials("imap")
        assert creds["host"] == "imap.example.com"
        mock_store.get.assert_called_once_with("imap")

    @pytest.mark.asyncio
    async def test_resolve_returns_none_without_store(self):
        from sentinel.tools.executor import ToolExecutor
        from sentinel.security.policy_engine import PolicyEngine

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._rules = []
        engine._trust_level = 4
        executor = ToolExecutor(policy_engine=engine)

        creds = await executor._resolve_credentials("imap")
        assert creds is None
