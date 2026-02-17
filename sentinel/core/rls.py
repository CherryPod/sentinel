"""RLS-aware connection pool wrapper.

Wraps asyncpg pool.acquire() to inject SET LOCAL app.current_user_id
from the current_user_id contextvar. Every connection acquired through
this wrapper is transaction-scoped with the correct user context.

IMPORTANT: Callers must NOT call conn.commit() or conn.rollback() directly
on connections acquired from RLSPool. The wrapper owns the transaction
lifecycle — it starts a transaction, sets SET LOCAL, and commits/rolls back
on context manager exit. Calling commit() explicitly ends the outer
transaction early, and subsequent queries run without RLS context.

Nested transactions via ``async with conn.transaction():`` are safe — asyncpg
creates SAVEPOINTs inside the outer transaction automatically. This is the
pattern used by SessionStore.add_turn(), SessionStore.apply_decay(),
EpisodicStore.create(), EpisodicStore.store_facts(), and
ProvenanceStore.record().
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.core.rls")


class RLSPool:
    """Wraps an asyncpg pool to inject RLS session context on every acquire.

    Usage is identical to asyncpg pool — stores don't need changes:
        async with pool.acquire() as conn:
            await conn.fetch(...)  # Already scoped to current_user_id

    The wrapper starts a transaction and sets LOCAL app.current_user_id.
    When the context manager exits, the transaction commits (or rolls back
    on exception), and SET LOCAL automatically resets.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    @asynccontextmanager
    async def acquire(self):
        """Acquire a connection with RLS context set."""
        async with self._pool.acquire() as conn:
            uid = current_user_id.get()
            tr = conn.transaction()
            await tr.start()
            try:
                await conn.execute(
                    "SELECT set_config('app.current_user_id', $1, true)",
                    str(uid),
                )
                yield conn
                await tr.commit()
            except BaseException:
                await tr.rollback()
                raise

    async def close(self):
        """Close the underlying pool."""
        await self._pool.close()

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attributes to the underlying pool."""
        return getattr(self._pool, name)
