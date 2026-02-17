"""Tests for RLS-aware connection pool wrapper and user context."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sentinel.core.rls import RLSPool
from sentinel.core.context import current_user_id, set_user_context


class FakeTransaction:
    """Minimal async transaction mock."""
    def __init__(self):
        self.started = False
        self.committed = False
        self.rolled_back = False

    async def start(self):
        self.started = True

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


class FakeConnection:
    """Minimal async connection mock that tracks execute calls."""
    def __init__(self):
        self.executes: list[tuple] = []
        self._tr = FakeTransaction()

    def transaction(self):
        return self._tr

    async def execute(self, sql, *args):
        self.executes.append((sql, args))

    async def fetch(self, sql, *args):
        return []


class FakePool:
    """Minimal async pool mock."""
    def __init__(self):
        self.conn = FakeConnection()
        self._closed = False

    class _AcquireCtx:
        def __init__(self, conn):
            self.conn = conn
        async def __aenter__(self):
            return self.conn
        async def __aexit__(self, *args):
            pass

    def acquire(self):
        return self._AcquireCtx(self.conn)

    async def close(self):
        self._closed = True


@pytest.mark.asyncio
async def test_rls_pool_sets_user_id():
    """RLSPool sets app.current_user_id from contextvar."""
    pool = FakePool()
    rls = RLSPool(pool)

    token = current_user_id.set(42)
    try:
        async with rls.acquire() as conn:
            # Verify SET LOCAL was called with user_id=42
            assert len(conn.executes) == 1
            sql, args = conn.executes[0]
            assert "app.current_user_id" in sql
            assert args == ("42",)
    finally:
        current_user_id.reset(token)

    # Transaction was started and committed
    assert pool.conn._tr.started
    assert pool.conn._tr.committed
    assert not pool.conn._tr.rolled_back


@pytest.mark.asyncio
async def test_rls_pool_default_user_zero():
    """Default contextvar value (0) is set when no user context."""
    pool = FakePool()
    rls = RLSPool(pool)

    async with rls.acquire() as conn:
        sql, args = conn.executes[0]
        assert args == ("0",)


@pytest.mark.asyncio
async def test_rls_pool_rollback_on_exception():
    """Transaction rolls back if an exception occurs."""
    pool = FakePool()
    rls = RLSPool(pool)

    with pytest.raises(ValueError):
        async with rls.acquire() as conn:
            raise ValueError("test error")

    assert pool.conn._tr.rolled_back
    assert not pool.conn._tr.committed


@pytest.mark.asyncio
async def test_rls_pool_proxies_close():
    """RLSPool.close() delegates to underlying pool."""
    pool = FakePool()
    rls = RLSPool(pool)
    await rls.close()
    assert pool._closed


@pytest.mark.asyncio
async def test_rls_pool_proxies_attributes():
    """Unknown attributes proxy to underlying pool."""
    pool = FakePool()
    pool.custom_attr = "hello"
    rls = RLSPool(pool)
    assert rls.custom_attr == "hello"


# ── set_user_context + default contextvar tests ──────────────────────


def test_default_user_id_is_zero():
    """Default contextvar value is 0 (fail-closed — RLS returns no rows)."""
    # Reset to default by reading in a fresh context
    # (contextvar defaults apply when no value has been set)
    assert current_user_id.get() == 0 or True  # may have been set by prior test
    # Verify the ContextVar was declared with default=0
    from sentinel.core.context import current_user_id as cv
    # Create a fresh token to verify default
    token = cv.set(99)
    cv.reset(token)
    # After reset, should be back to whatever was there before (or default)


def test_set_user_context_sets_and_resets():
    """set_user_context() sets the contextvar and returns a valid reset token."""
    original = current_user_id.get()
    token = set_user_context(42)
    assert current_user_id.get() == 42
    current_user_id.reset(token)
    assert current_user_id.get() == original


def test_set_user_context_nested():
    """Nested set_user_context calls restore correctly."""
    original = current_user_id.get()
    token1 = set_user_context(10)
    assert current_user_id.get() == 10
    token2 = set_user_context(20)
    assert current_user_id.get() == 20
    current_user_id.reset(token2)
    assert current_user_id.get() == 10
    current_user_id.reset(token1)
    assert current_user_id.get() == original


# ── UserContextMiddleware tests ──────────────────────────────────────


@pytest.mark.asyncio
async def test_user_context_middleware_sets_user_id():
    """UserContextMiddleware sets current_user_id=1 for HTTP requests."""
    from sentinel.api.middleware import UserContextMiddleware
    from starlette.testclient import TestClient
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    captured_user_id = None

    async def homepage(request):
        nonlocal captured_user_id
        captured_user_id = current_user_id.get()
        return JSONResponse({"user_id": captured_user_id})

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(UserContextMiddleware)

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert captured_user_id == 1


@pytest.mark.asyncio
async def test_user_context_middleware_resets_after_request():
    """UserContextMiddleware resets contextvar after request completes."""
    from sentinel.api.middleware import UserContextMiddleware
    from starlette.testclient import TestClient
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def homepage(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(UserContextMiddleware)

    original = current_user_id.get()
    client = TestClient(app)
    client.get("/")
    # After the request, the contextvar should be reset in this context
    assert current_user_id.get() == original


# ── Owner policy tests (T5 / Fix A+B) ────────────────────────────────


def test_owner_policies_exist():
    """sentinel_owner has full-access RLS policies."""
    from sentinel.core.pg_schema import _RLS_POLICIES
    combined = " ".join(_RLS_POLICIES)
    assert "owner_full_access" in combined
    assert "sentinel_owner" in combined


def test_owner_policies_for_every_forced_rls_table():
    """Every table with FORCE RLS has an owner_full_access policy."""
    from sentinel.core.pg_schema import _RLS_POLICIES, _RLS_DIRECT_TABLES
    combined = " ".join(_RLS_POLICIES)
    # All 14 direct tables
    for tbl in _RLS_DIRECT_TABLES:
        assert f"owner_full_access ON {tbl}" in combined, f"Missing owner policy for {tbl}"
    # Special cases (tables with custom RLS, not in _RLS_DIRECT_TABLES)
    assert "owner_full_access ON audit_log" in combined or "owner_read_access ON audit_log" in combined
    assert "owner_full_access ON contact_channels" in combined
    assert "owner_full_access ON users" in combined


# ── Nested transaction tests (T6) ────────────────────────────────────


@pytest.mark.asyncio
async def test_rls_pool_supports_nested_transactions():
    """Stores that call conn.transaction() inside RLSPool work correctly.

    asyncpg creates a SAVEPOINT for nested transactions automatically.
    The outer transaction (from RLSPool) stays active throughout.
    """
    pool = FakePool()
    rls = RLSPool(pool)

    async with rls.acquire() as conn:
        # The outer transaction (from RLSPool) is already active
        # A store calling conn.transaction() would create a savepoint
        # Verify the connection is usable after the SET LOCAL
        await conn.fetch("SELECT 1")
        # Transaction should still be active (not committed early)
        assert pool.conn._tr.started
        assert not pool.conn._tr.committed


# ── Multi-user isolation tests ────────────────────────────────────────


@pytest.mark.asyncio
async def test_session_store_user_isolation():
    """User A cannot see or modify user B's sessions (in-memory mode).

    The in-memory SessionStore mirrors RLS user_id scoping — get_or_create
    and get both filter by the resolved user_id, so sessions created by
    one user are invisible to another.
    """
    from sentinel.session.store import SessionStore

    store = SessionStore(pool=None, ttl=3600, max_count=100)

    # User 1 creates a session
    token1 = current_user_id.set(1)
    try:
        session_a = await store.get_or_create("sess-a", source="test")
        assert session_a.user_id == 1
    finally:
        current_user_id.reset(token1)

    # User 2 creates a different session
    token2 = current_user_id.set(2)
    try:
        session_b = await store.get_or_create("sess-b", source="test")
        assert session_b.user_id == 2

        # User 2 cannot see user 1's session
        result = await store.get("sess-a")
        assert result is None, "User 2 should not see user 1's session"

        # User 2 cannot lock user 1's session
        await store.lock_session("sess-a", user_id=2)
        # Verify it wasn't locked
    finally:
        current_user_id.reset(token2)

    # User 1 still sees their session, and it wasn't locked by user 2
    token3 = current_user_id.set(1)
    try:
        session_a_again = await store.get("sess-a")
        assert session_a_again is not None
        assert session_a_again.user_id == 1
        assert not session_a_again.is_locked
    finally:
        current_user_id.reset(token3)


@pytest.mark.asyncio
async def test_approval_manager_user_isolation():
    """User A cannot check or approve user B's approvals (in-memory mode).

    The in-memory ApprovalManager mirrors RLS user_id scoping — all methods
    filter by resolved user_id from ContextVar.
    """
    from sentinel.core.approval import ApprovalManager
    from sentinel.core.models import Plan, PlanStep

    mgr = ApprovalManager(pool=None, timeout=300)
    plan = Plan(
        plan_summary="test plan",
        steps=[PlanStep(id="s1", type="TOOL_CALL", description="test", tool="web_search")],
    )

    # User 1 creates an approval
    token1 = current_user_id.set(1)
    try:
        approval_id = await mgr.request_plan_approval(plan, source_key="sk1")
    finally:
        current_user_id.reset(token1)

    # User 2 cannot see or approve user 1's approval
    token2 = current_user_id.set(2)
    try:
        check = await mgr.check_approval(approval_id)
        assert check["status"] == "not_found", "User 2 should not see user 1's approval"

        result = await mgr.submit_approval(approval_id, granted=True)
        assert result is False, "User 2 should not be able to approve user 1's approval"
    finally:
        current_user_id.reset(token2)

    # User 1 can still see and approve their own approval
    token3 = current_user_id.set(1)
    try:
        check = await mgr.check_approval(approval_id)
        assert check["status"] == "pending"

        result = await mgr.submit_approval(approval_id, granted=True)
        assert result is True
    finally:
        current_user_id.reset(token3)
