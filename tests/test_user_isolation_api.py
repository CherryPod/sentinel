"""Tests for multi-user API isolation (Task 3).

Verifies that API routes properly scope data by user_id, reject
cross-user access, and enforce role guards on sensitive endpoints.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.context import current_user_id


# ── Routines: .get(1) fallback removed ─────────────────────────────


class TestRoutineUserIdFallback:
    """Verify that routines.py no longer uses current_user_id.get(1)."""

    def test_no_get_1_fallback_in_routines(self):
        """The .get(1) fallback silently maps unauthenticated requests to
        user 1. After the fix, all calls should use .get() (no default)."""
        import inspect
        from sentinel.api.routes import routines

        source = inspect.getsource(routines)
        # Should not contain the dangerous fallback pattern
        assert "current_user_id.get(1)" not in source, (
            "routines.py still contains current_user_id.get(1) — "
            "unauthenticated requests would silently get user 1's data"
        )
        # Should still use current_user_id.get() (without fallback)
        assert "current_user_id.get()" in source


class TestRoutineStoreNoneBypass:
    """Verify that ownership checks always run (not conditional on store)."""

    def test_trigger_routine_store_none_guard_in_source(self):
        """Manual trigger must check for store=None and return 503,
        instead of skipping the ownership check."""
        import inspect
        from sentinel.api.routes import routines

        source = inspect.getsource(routines.trigger_routine)
        # The fix replaces `if store is not None:` with an explicit 503 guard
        assert "store is None" in source
        assert "503" in source

    @pytest.mark.asyncio
    async def test_executions_503_when_store_none(self):
        """Execution history returns 503 when store is unavailable."""
        from sentinel.api.routes.routines import get_routine_executions, init

        init(routine_store=None, routine_engine=AsyncMock())

        token = current_user_id.set(1)
        try:
            result = await get_routine_executions("some-id")
            assert result.status_code == 503
        finally:
            current_user_id.reset(token)


# ── Memory: user_id passed to all store calls ──────────────────────


class TestMemoryUserScoping:
    """Verify memory routes pass current_user_id to store methods."""

    def test_memory_routes_import_current_user_id(self):
        """memory.py must import current_user_id for user scoping."""
        import inspect
        from sentinel.api.routes import memory

        source = inspect.getsource(memory)
        assert "current_user_id" in source

    @pytest.mark.asyncio
    async def test_store_memory_passes_user_id(self):
        """POST /api/memory should pass user_id to store.store()."""
        from sentinel.api.routes.memory import store_memory, init
        from sentinel.api.models import MemoryStoreRequest

        mock_store = AsyncMock()
        mock_store.store.return_value = "chunk-1"
        mock_embed = AsyncMock()
        mock_embed.embed_batch.side_effect = Exception("offline")

        init(memory_store=mock_store, embedding_client=mock_embed)

        token = current_user_id.set(42)
        try:
            req = MemoryStoreRequest(text="hello world", source="test")
            await store_memory(req)
            # Verify store was called with user_id=42
            call_kwargs = mock_store.store.call_args
            assert call_kwargs.kwargs.get("user_id") == 42 or \
                (len(call_kwargs.args) > 0 and 42 in call_kwargs.args)
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_list_memory_passes_user_id(self):
        """GET /api/memory/list should pass user_id to store.list_chunks()."""
        from sentinel.api.routes.memory import list_memory_chunks, init

        mock_store = AsyncMock()
        mock_store.list_chunks.return_value = []

        init(memory_store=mock_store)

        token = current_user_id.set(7)
        try:
            await list_memory_chunks(limit=10, offset=0)
            call_kwargs = mock_store.list_chunks.call_args
            assert call_kwargs.kwargs.get("user_id") == 7
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_get_memory_passes_user_id(self):
        """GET /api/memory/{chunk_id} should pass user_id to store.get()."""
        from sentinel.api.routes.memory import get_memory_chunk, init

        mock_store = AsyncMock()
        mock_store.get.return_value = None  # Not found

        init(memory_store=mock_store)

        token = current_user_id.set(7)
        try:
            await get_memory_chunk("chunk-abc")
            call_kwargs = mock_store.get.call_args
            assert call_kwargs.kwargs.get("user_id") == 7
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_delete_memory_passes_user_id(self):
        """DELETE /api/memory/{chunk_id} should pass user_id to store.delete()."""
        from sentinel.api.routes.memory import delete_memory_chunk, init

        mock_store = AsyncMock()
        mock_store.delete.return_value = True

        init(memory_store=mock_store)

        token = current_user_id.set(7)
        try:
            await delete_memory_chunk("chunk-abc")
            call_kwargs = mock_store.delete.call_args
            assert call_kwargs.kwargs.get("user_id") == 7
        finally:
            current_user_id.reset(token)


# ── Webhooks: user scoping on register/list/delete ──────────────────


class TestWebhookUserScoping:
    """Verify webhook routes scope operations by user_id."""

    def test_register_webhook_passes_user_id_in_source(self):
        """POST /api/webhook should pass user_id to registry.register()."""
        import inspect
        from sentinel.api.routes import webhooks

        source = inspect.getsource(webhooks.register_webhook)
        # Verify user_id is extracted and passed to register
        assert "current_user_id.get()" in source
        assert "user_id=" in source

    @pytest.mark.asyncio
    async def test_list_webhooks_passes_user_id(self):
        """GET /api/webhook should pass user_id to registry.list()."""
        from sentinel.api.routes.webhooks import list_webhooks, init

        mock_registry = AsyncMock()
        mock_registry.list.return_value = []

        init(webhook_registry=mock_registry)

        token = current_user_id.set(5)
        try:
            await list_webhooks()
            call_kwargs = mock_registry.list.call_args
            assert call_kwargs.kwargs.get("user_id") == 5
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_delete_webhook_ownership_check(self):
        """DELETE /api/webhook/{id} should reject if webhook belongs to another user."""
        from sentinel.api.routes.webhooks import delete_webhook, init

        # Webhook belongs to user 99, but current user is 5
        mock_config = MagicMock()
        mock_config.user_id = 99

        mock_registry = AsyncMock()
        mock_registry.get.return_value = mock_config

        init(webhook_registry=mock_registry)

        token = current_user_id.set(5)
        try:
            result = await delete_webhook("wh-1")
            assert result.status_code == 404
            # delete should NOT have been called
            mock_registry.delete.assert_not_called()
        finally:
            current_user_id.reset(token)


# ── Task: session endpoint error codes ──────────────────────────────


class TestTaskSessionEndpoint:
    """Verify task.py session endpoint returns proper status codes."""

    @pytest.mark.asyncio
    async def test_session_store_none_returns_503(self):
        """Session store not initialized should return 503, not 200."""
        from sentinel.api.routes.task import get_session, init

        init(session_store=None)

        result = await get_session("sess-1")
        assert result.status_code == 503

    @pytest.mark.asyncio
    async def test_session_not_found_returns_404(self):
        """Session not found should return 404, not 200."""
        from sentinel.api.routes.task import get_session, init

        mock_store = AsyncMock()
        mock_store.get.return_value = None

        init(session_store=mock_store)

        token = current_user_id.set(1)
        try:
            result = await get_session("sess-1")
            assert result.status_code == 404
        finally:
            current_user_id.reset(token)

    def test_orchestrator_none_returns_503_in_source(self):
        """Orchestrator not initialized should return 503, not 200 with error body."""
        import inspect
        from sentinel.api.routes import task

        source = inspect.getsource(task.handle_task)
        # Verify the orchestrator-None check returns a JSONResponse with 503
        assert "JSONResponse" in source
        assert "503" in source


# ── Contacts: auth guard on user list ───────────────────────────────


class TestContactsAuthGuard:
    """Verify contacts.py has admin role guard on user list/get."""

    def test_list_users_has_role_guard(self):
        """list_users should call require_role('admin', store)."""
        import inspect
        from sentinel.api import contacts

        source = inspect.getsource(contacts.list_users)
        assert "require_role" in source

    def test_get_user_has_role_guard(self):
        """get_user should call require_role('admin', store)."""
        import inspect
        from sentinel.api import contacts

        source = inspect.getsource(contacts.get_user)
        assert "require_role" in source

    def test_pin_max_length_on_create(self):
        """UserCreate.pin should have max_length=128."""
        from sentinel.api.contacts import UserCreate

        schema = UserCreate.model_json_schema()
        pin_schema = schema["properties"]["pin"]
        # Pydantic v2 uses anyOf for Optional[str] with constraints
        if "anyOf" in pin_schema:
            str_variant = next(
                v for v in pin_schema["anyOf"] if v.get("type") == "string"
            )
            assert str_variant["maxLength"] == 128
        else:
            assert pin_schema.get("maxLength") == 128

    def test_pin_max_length_on_update(self):
        """UserUpdate.pin should have max_length=128."""
        from sentinel.api.contacts import UserUpdate

        schema = UserUpdate.model_json_schema()
        pin_schema = schema["properties"]["pin"]
        if "anyOf" in pin_schema:
            str_variant = next(
                v for v in pin_schema["anyOf"] if v.get("type") == "string"
            )
            assert str_variant["maxLength"] == 128
        else:
            assert pin_schema.get("maxLength") == 128


# ── A2A: input length limit ─────────────────────────────────────────


class TestA2AInputValidation:
    """Verify A2A adapter has input length limits."""

    @pytest.mark.asyncio
    async def test_oversized_request_rejected(self):
        """tasks/send should reject requests exceeding MAX_TEXT_LENGTH."""
        from sentinel.api.a2a import handle_tasks_send, MAX_TEXT_LENGTH

        mock_orch = MagicMock()
        # Build a message with text exceeding the limit
        params = {
            "message": {
                "parts": [{"text": "x" * (MAX_TEXT_LENGTH + 1)}],
            },
        }

        with pytest.raises(ValueError, match="too long"):
            await handle_tasks_send(params, mock_orch, "127.0.0.1")

    @pytest.mark.asyncio
    async def test_normal_request_accepted(self):
        """tasks/send should accept requests within MAX_TEXT_LENGTH."""
        from sentinel.api.a2a import handle_tasks_send

        mock_result = MagicMock()
        mock_result.status = "success"
        mock_result.task_id = "t-1"

        mock_orch = AsyncMock()
        mock_orch.handle_task.return_value = mock_result

        params = {
            "message": {
                "parts": [{"text": "What is the weather?"}],
            },
        }

        token = current_user_id.set(1)
        try:
            result = await handle_tasks_send(params, mock_orch, "127.0.0.1")
            assert result == mock_result
        finally:
            current_user_id.reset(token)


# ── Credentials: already uses ContextVar ─────────────────────────────


class TestCredentialStoreContextVar:
    """Verify credential store uses current_user_id ContextVar internally."""

    def test_credential_store_uses_context_var(self):
        """CredentialStore methods should use current_user_id.get() when
        user_id is not explicitly passed."""
        import inspect
        from sentinel.core.credential_store import CredentialStore

        source = inspect.getsource(CredentialStore)
        assert "current_user_id.get()" in source
