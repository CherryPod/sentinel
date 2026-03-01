"""Concurrent SQLite access tests.

V-001: All database tests are sequential in-memory. Production serves
concurrent async requests through a single SQLite connection (WAL mode).
These tests verify data integrity under concurrent access.

NOTE: Production uses synchronous SQLite calls within a single asyncio event
loop thread. Concurrency comes from coroutine interleaving at await points,
NOT from multi-threading. These tests simulate that pattern.

FINDING: The stores are NOT thread-safe. Wrapping synchronous SessionStore or
MemoryStore calls in asyncio.to_thread() causes segfaults because Python's
sqlite3.Connection is not thread-safe. If thread-pool execution is ever added,
a threading.Lock must wrap all connection access. Reported in tracker.

Marked @pytest.mark.slow — uses real SQLite file and concurrent coroutines.
"""

import asyncio
import sqlite3

import pytest

from sentinel.core.db import init_db
from sentinel.memory.chunks import MemoryStore
from sentinel.session.store import ConversationTurn, SessionStore


@pytest.fixture
def db(tmp_path):
    """Real SQLite file with WAL mode for concurrent testing."""
    db_path = str(tmp_path / "test_concurrent.db")
    conn = init_db(db_path)
    yield conn
    conn.close()


@pytest.mark.slow
class TestConcurrentSessionWrites:
    """Regression guard: concurrent coroutines writing sessions don't corrupt data.

    Simulates the production pattern: multiple async requests share one
    SessionStore/connection, interleaving at await points.
    """

    @pytest.mark.asyncio
    async def test_concurrent_sessions_write_turns(self, db):
        """10 concurrent coroutines each writing 20 turns.

        After all writes complete, each session should have exactly 20 turns
        with the correct content. No turns should be lost or misattributed.
        """
        store = SessionStore(db=db, ttl=3600, max_count=100)
        num_sessions = 10
        turns_per_session = 20

        async def write_turns(session_id: str):
            """Create a session and write turns — yields between writes."""
            session = store.get_or_create(session_id, "test")
            for i in range(turns_per_session):
                turn = ConversationTurn(
                    request_text=f"session_{session_id}_turn_{i}",
                    result_status="success",
                )
                session.add_turn(turn)
                # Yield to event loop to allow interleaving with other coroutines
                await asyncio.sleep(0)

        # Run all session writers concurrently
        tasks = [
            write_turns(f"concurrent_{i}")
            for i in range(num_sessions)
        ]
        await asyncio.gather(*tasks)

        # Regression guard: each session has exactly the right number of turns
        for i in range(num_sessions):
            session = store.get(f"concurrent_{i}")
            assert session is not None, f"Session concurrent_{i} should exist"
            assert len(session.turns) == turns_per_session, (
                f"Session concurrent_{i} has {len(session.turns)} turns, "
                f"expected {turns_per_session}"
            )
            # Verify all turns belong to this session and are in order
            for j, turn in enumerate(session.turns):
                assert turn.request_text == f"session_concurrent_{i}_turn_{j}", (
                    f"Turn {j} in session concurrent_{i} has wrong content: "
                    f"{turn.request_text}"
                )

        # Verify total session count
        assert store.count == num_sessions

    @pytest.mark.asyncio
    async def test_concurrent_read_write_monotonic(self, db):
        """Concurrent reads while writing — turn count never decreases.

        One coroutine writes turns, another reads the session repeatedly.
        The reader should see a monotonically non-decreasing turn count.
        """
        store = SessionStore(db=db, ttl=3600, max_count=100)
        session = store.get_or_create("readwrite_test", "test")

        num_writes = 30
        observed_counts: list[int] = []
        write_done = asyncio.Event()

        async def writer():
            for i in range(num_writes):
                turn = ConversationTurn(
                    request_text=f"turn_{i}",
                    result_status="success",
                )
                session.add_turn(turn)
                await asyncio.sleep(0)
            write_done.set()

        async def reader():
            while not write_done.is_set():
                s = store.get("readwrite_test")
                if s is not None:
                    observed_counts.append(len(s.turns))
                await asyncio.sleep(0)
            # Final read after writer done
            s = store.get("readwrite_test")
            if s is not None:
                observed_counts.append(len(s.turns))

        await asyncio.gather(writer(), reader())

        # Regression guard: turn count is monotonically non-decreasing
        for i in range(1, len(observed_counts)):
            assert observed_counts[i] >= observed_counts[i - 1], (
                f"Turn count decreased from {observed_counts[i - 1]} to "
                f"{observed_counts[i]} at observation {i}"
            )

        # Final state has all turns
        final = store.get("readwrite_test")
        assert final is not None
        assert len(final.turns) == num_writes

    @pytest.mark.asyncio
    async def test_concurrent_session_creation(self, db):
        """50 coroutines creating sessions simultaneously — none lost."""
        store = SessionStore(db=db, ttl=3600, max_count=200)
        num_sessions = 50

        async def create_session(i: int):
            store.get_or_create(f"bulk_{i}", "test")
            await asyncio.sleep(0)

        await asyncio.gather(*[create_session(i) for i in range(num_sessions)])

        # Regression guard: all sessions exist
        assert store.count == num_sessions
        for i in range(num_sessions):
            s = store.get(f"bulk_{i}")
            assert s is not None, f"Session bulk_{i} missing"


@pytest.mark.slow
class TestConcurrentMemoryStoreWrites:
    """Regression guard: concurrent MemoryStore writes don't corrupt data."""

    @pytest.mark.asyncio
    async def test_concurrent_memory_chunk_writes(self, db):
        """50 coroutines storing memory chunks simultaneously.

        All chunks should be stored and retrievable with correct content.
        """
        store = MemoryStore(db=db)
        num_chunks = 50
        chunk_ids: list[tuple[int, str]] = []

        async def store_chunk(i: int):
            cid = store.store(
                content=f"Concurrent chunk {i}",
                source="test",
            )
            chunk_ids.append((i, cid))
            await asyncio.sleep(0)

        await asyncio.gather(*[store_chunk(i) for i in range(num_chunks)])

        # Regression guard: all chunks stored and retrievable
        assert len(chunk_ids) == num_chunks
        for i, cid in chunk_ids:
            chunk = store.get(cid)
            assert chunk is not None, f"Chunk {cid} for index {i} missing"
            assert chunk.content == f"Concurrent chunk {i}"

    @pytest.mark.asyncio
    async def test_concurrent_store_and_delete(self, db):
        """Store and delete operations running concurrently.

        Verifies no crashes or corruption when stores and deletes interleave.
        """
        store = MemoryStore(db=db)

        # Pre-populate chunks to delete
        to_delete = []
        for i in range(20):
            cid = store.store(content=f"delete_me_{i}", source="test")
            to_delete.append(cid)

        new_ids: list[str] = []

        async def delete_chunk(cid: str):
            store.delete(cid)
            await asyncio.sleep(0)

        async def store_new(i: int):
            cid = store.store(content=f"new_chunk_{i}", source="test")
            new_ids.append(cid)
            await asyncio.sleep(0)

        tasks = (
            [delete_chunk(cid) for cid in to_delete]
            + [store_new(i) for i in range(20)]
        )
        await asyncio.gather(*tasks)

        # Regression guard: deleted chunks are gone, new chunks exist
        for cid in to_delete:
            assert store.get(cid) is None, f"Deleted chunk {cid} still exists"
        for cid in new_ids:
            chunk = store.get(cid)
            assert chunk is not None, f"New chunk {cid} missing"
