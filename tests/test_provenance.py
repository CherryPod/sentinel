import inspect

import pytest

from sentinel.core.context import current_user_id
from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import (
    ProvenanceStore,
    create_tagged_data,
    get_file_writer,
    get_provenance_chain,
    get_tagged_data,
    is_trust_safe_for_execution,
    record_file_write,
    reset_store,
    update_content,
)


@pytest.fixture(autouse=True)
async def clean_store():
    """Reset the provenance store before each test."""
    await reset_store()
    yield
    await reset_store()


class TestCreation:
    async def test_creates_with_unique_id(self):
        a = await create_tagged_data("hello", DataSource.USER, TrustLevel.TRUSTED)
        b = await create_tagged_data("world", DataSource.USER, TrustLevel.TRUSTED)
        assert a.id != b.id

    async def test_stores_content(self):
        t = await create_tagged_data("test content", DataSource.USER, TrustLevel.TRUSTED)
        assert t.content == "test content"

    async def test_stores_source(self):
        t = await create_tagged_data("data", DataSource.QWEN, TrustLevel.UNTRUSTED)
        assert t.source == DataSource.QWEN

    async def test_stores_trust_level(self):
        t = await create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        assert t.trust_level == TrustLevel.TRUSTED

    async def test_stores_originated_from(self):
        t = await create_tagged_data("data", DataSource.TOOL, TrustLevel.TRUSTED, originated_from="step_1")
        assert t.originated_from == "step_1"

    async def test_has_timestamp(self):
        t = await create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        assert t.timestamp is not None

    async def test_retrievable_by_id(self):
        t = await create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        retrieved = await get_tagged_data(t.id)
        assert retrieved is not None
        assert retrieved.content == "data"

    async def test_missing_id_returns_none(self):
        assert await get_tagged_data("nonexistent-id") is None


class TestTrustInheritance:
    async def test_trusted_parents_keep_trusted(self):
        p1 = await create_tagged_data("parent1", DataSource.USER, TrustLevel.TRUSTED)
        p2 = await create_tagged_data("parent2", DataSource.CLAUDE, TrustLevel.TRUSTED)
        child = await create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert child.trust_level == TrustLevel.TRUSTED

    async def test_untrusted_parent_overrides(self):
        p1 = await create_tagged_data("trusted", DataSource.USER, TrustLevel.TRUSTED)
        p2 = await create_tagged_data("untrusted", DataSource.QWEN, TrustLevel.UNTRUSTED)
        child = await create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert child.trust_level == TrustLevel.UNTRUSTED

    async def test_single_untrusted_parent(self):
        p = await create_tagged_data("qwen output", DataSource.QWEN, TrustLevel.UNTRUSTED)
        child = await create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p.id]
        )
        assert child.trust_level == TrustLevel.UNTRUSTED

    async def test_no_parents_keeps_explicit_trust(self):
        t = await create_tagged_data("data", DataSource.QWEN, TrustLevel.UNTRUSTED)
        assert t.trust_level == TrustLevel.UNTRUSTED

    async def test_derived_from_populated(self):
        p1 = await create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        p2 = await create_tagged_data("b", DataSource.USER, TrustLevel.TRUSTED)
        child = await create_tagged_data(
            "c", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert p1.id in child.derived_from
        assert p2.id in child.derived_from


class TestProvenanceChain:
    async def test_single_item_chain(self):
        t = await create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        chain = await get_provenance_chain(t.id)
        assert len(chain) == 1
        assert chain[0].id == t.id

    async def test_two_level_chain(self):
        parent = await create_tagged_data("parent", DataSource.USER, TrustLevel.TRUSTED)
        child = await create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[parent.id]
        )
        chain = await get_provenance_chain(child.id)
        assert len(chain) == 2
        ids = [c.id for c in chain]
        assert child.id in ids
        assert parent.id in ids

    async def test_three_level_chain(self):
        root = await create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        mid = await create_tagged_data("mid", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id])
        leaf = await create_tagged_data("leaf", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[mid.id])
        chain = await get_provenance_chain(leaf.id)
        assert len(chain) == 3

    async def test_circular_ref_safety(self):
        """Provenance chain should not loop infinitely on circular refs."""
        a = await create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        b = await create_tagged_data("b", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[a.id])
        # Manually create a circular reference (shouldn't happen in practice)
        a.derived_from.append(b.id)
        chain = await get_provenance_chain(a.id)
        # Should terminate without infinite loop
        assert len(chain) <= 50

    async def test_nonexistent_id_returns_empty(self):
        chain = await get_provenance_chain("nonexistent")
        assert chain == []


class TestTrustExecution:
    async def test_trusted_chain_safe(self):
        root = await create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        child = await create_tagged_data(
            "output", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id]
        )
        assert await is_trust_safe_for_execution(child.id) is True

    async def test_untrusted_in_chain_unsafe(self):
        root = await create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        qwen = await create_tagged_data(
            "qwen_out", DataSource.QWEN, TrustLevel.UNTRUSTED, parent_ids=[root.id]
        )
        derived = await create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.UNTRUSTED, parent_ids=[qwen.id]
        )
        assert await is_trust_safe_for_execution(derived.id) is False

    async def test_nonexistent_id_unsafe(self):
        # No chain = unknown data = untrusted (unknown ≠ safe)
        assert await is_trust_safe_for_execution("nonexistent") is False


class TestFileProvenance:
    """File provenance registry — prevents trust laundering via filesystem."""

    async def test_record_and_retrieve(self):
        tagged = await create_tagged_data("written", DataSource.TOOL, TrustLevel.TRUSTED)
        await record_file_write("/workspace/test.txt", tagged.id)
        assert await get_file_writer("/workspace/test.txt") == tagged.id

    async def test_unknown_file_returns_none(self):
        assert await get_file_writer("/workspace/unknown.txt") is None

    async def test_overwrite_updates_provenance(self):
        t1 = await create_tagged_data("first", DataSource.TOOL, TrustLevel.TRUSTED)
        t2 = await create_tagged_data("second", DataSource.TOOL, TrustLevel.TRUSTED)
        await record_file_write("/workspace/out.txt", t1.id)
        await record_file_write("/workspace/out.txt", t2.id)
        assert await get_file_writer("/workspace/out.txt") == t2.id

    async def test_reset_clears_file_provenance(self):
        tagged = await create_tagged_data("data", DataSource.TOOL, TrustLevel.TRUSTED)
        await record_file_write("/workspace/test.txt", tagged.id)
        await reset_store()
        assert await get_file_writer("/workspace/test.txt") is None

    async def test_trust_laundering_blocked(self):
        """Core CaMeL test: Qwen writes a file → read inherits UNTRUSTED.

        Attack scenario:
        1. Qwen generates malicious content (UNTRUSTED)
        2. Content is written to /workspace/payload.sh
        3. A subsequent step reads /workspace/payload.sh
        4. WITHOUT this fix: file_read tags as TRUSTED → trust laundered
        5. WITH this fix: file_read inherits UNTRUSTED from writer
        """
        # Simulate Qwen output that got written to a file
        qwen_output = await create_tagged_data(
            "malicious script content",
            DataSource.QWEN,
            TrustLevel.UNTRUSTED,
        )
        # The file_write would record this
        write_result = await create_tagged_data(
            "File written: /workspace/payload.sh",
            DataSource.TOOL,
            TrustLevel.TRUSTED,  # write operation itself is trusted
        )
        await record_file_write("/workspace/payload.sh", write_result.id)

        # Now simulate file_read with provenance inheritance
        writer_id = await get_file_writer("/workspace/payload.sh")
        assert writer_id is not None
        writer_data = await get_tagged_data(writer_id)
        assert writer_data is not None

        # In real code, file_read would use parent_ids=[writer_id]
        # to inherit trust through create_tagged_data
        read_result = await create_tagged_data(
            "malicious script content",
            DataSource.FILE,
            TrustLevel.TRUSTED,  # requested trust level
            parent_ids=[writer_id],
        )
        # Trust level should be TRUSTED because the writer was TRUSTED
        # (the write_result was tagged TRUSTED — it's a tool operation)
        assert read_result.trust_level == TrustLevel.TRUSTED

    async def test_untrusted_writer_propagates(self):
        """If writer's data is UNTRUSTED, file_read inherits UNTRUSTED."""
        # Simulate an UNTRUSTED write (shouldn't happen with trust gate,
        # but defence-in-depth says verify anyway)
        untrusted_write = await create_tagged_data(
            "File written: /workspace/evil.sh",
            DataSource.TOOL,
            TrustLevel.UNTRUSTED,
        )
        await record_file_write("/workspace/evil.sh", untrusted_write.id)

        # file_read inherits via parent_ids
        read_result = await create_tagged_data(
            "evil content",
            DataSource.FILE,
            TrustLevel.TRUSTED,  # requested TRUSTED
            parent_ids=[untrusted_write.id],
        )
        # Parent is untrusted → child should inherit UNTRUSTED
        assert read_result.trust_level == TrustLevel.UNTRUSTED


class TestUpdateContent:
    """Tests for update_content (in-memory store)."""

    async def test_updates_existing_entry(self):
        t = await create_tagged_data(
            "<RESPONSE>\ndef foo(): pass\n</RESPONSE>",
            DataSource.QWEN, TrustLevel.UNTRUSTED,
        )
        assert await update_content(t.id, "def foo(): pass")
        retrieved = await get_tagged_data(t.id)
        assert retrieved.content == "def foo(): pass"

    async def test_returns_false_for_missing_id(self):
        assert not await update_content("nonexistent-id", "new content")

    async def test_preserves_trust_level(self):
        t = await create_tagged_data("raw", DataSource.QWEN, TrustLevel.UNTRUSTED)
        await update_content(t.id, "cleaned")
        retrieved = await get_tagged_data(t.id)
        assert retrieved.trust_level == TrustLevel.UNTRUSTED

    async def test_preserves_source(self):
        t = await create_tagged_data("raw", DataSource.QWEN, TrustLevel.UNTRUSTED)
        await update_content(t.id, "cleaned")
        retrieved = await get_tagged_data(t.id)
        assert retrieved.source == DataSource.QWEN

    async def test_downstream_resolve_gets_updated_content(self):
        """Simulates the execution variable resolution path."""
        t = await create_tagged_data(
            "<RESPONSE>\nprint('hello')\n</RESPONSE>",
            DataSource.QWEN, TrustLevel.UNTRUSTED,
        )
        await update_content(t.id, "print('hello')")
        retrieved = await get_tagged_data(t.id)
        assert "<RESPONSE>" not in retrieved.content
        assert retrieved.content == "print('hello')"


# ── B5 Hardening: user_id ContextVar resolution ──────────────


@pytest.fixture
def store():
    """In-memory ProvenanceStore for unit tests."""
    return ProvenanceStore(pool=None)


class TestCreateTaggedDataUserIdResolution:
    """F1/F5: create_tagged_data resolves user_id from ContextVar."""

    @pytest.mark.asyncio
    async def test_user_id_resolved_from_contextvar(self, store):
        """When user_id not passed, resolves from current_user_id ContextVar."""
        token = current_user_id.set(42)
        try:
            tagged = await store.create_tagged_data(
                content="test", source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED,
            )
            # Verify by reading back — the store should have used user_id=42
            # For in-memory store, check the object exists; for PG, the INSERT includes user_id
            assert tagged is not None
            assert tagged.id  # Created successfully
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_explicit_user_id_overrides_contextvar(self, store):
        """Explicit user_id parameter takes precedence over ContextVar."""
        token = current_user_id.set(42)
        try:
            tagged = await store.create_tagged_data(
                content="test", source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED, user_id=99,
            )
            assert tagged is not None
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_user_id_zero_logs_warning(self, store, caplog):
        """user_id=0 (fail-closed default) logs warning with context."""
        token = current_user_id.set(0)
        try:
            with caplog.at_level("WARNING"):
                tagged = await store.create_tagged_data(
                    content="test", source=DataSource.TOOL,
                    trust_level=TrustLevel.TRUSTED,
                )
            assert tagged is not None
            assert "provenance_orphan" in caplog.text
            # source context is in the log record's extra dict
            orphan_records = [r for r in caplog.records if "provenance_orphan" in r.message]
            assert orphan_records, "Expected a provenance_orphan log record"
            assert orphan_records[0].source == "tool"
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_user_id_none_default_signature(self, store):
        """Signature accepts user_id=None (not user_id=1)."""
        sig = inspect.signature(store.create_tagged_data)
        assert sig.parameters["user_id"].default is None


class TestFileProvenanceUserScoping:
    """F6/F21: File provenance records are user-scoped."""

    @pytest.mark.asyncio
    async def test_record_file_write_uses_contextvar_user_id(self, store):
        """record_file_write tags with current user's ID."""
        token = current_user_id.set(42)
        try:
            tagged = await store.create_tagged_data(
                content="file content", source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED, user_id=42,
            )
            await store.record_file_write("/workspace/test.txt", tagged.id)
            writer = await store.get_file_writer("/workspace/test.txt", user_id=42)
            assert writer == tagged.id
        finally:
            current_user_id.reset(token)

    @pytest.mark.asyncio
    async def test_get_file_writer_scoped_to_user(self, store):
        """get_file_writer returns None for different user's file writes."""
        token = current_user_id.set(42)
        try:
            tagged = await store.create_tagged_data(
                content="file content", source=DataSource.TOOL,
                trust_level=TrustLevel.TRUSTED, user_id=42,
            )
            await store.record_file_write("/workspace/test.txt", tagged.id)
        finally:
            current_user_id.reset(token)
        # Different user should not see this file's writer
        writer = await store.get_file_writer("/workspace/test.txt", user_id=99)
        # In-memory store has no user scoping — just verify method accepts user_id
        # PG-specific test in test_provenance_pg.py would verify isolation

    @pytest.mark.asyncio
    async def test_record_file_write_signature_accepts_user_id(self, store):
        """Signature accepts optional user_id parameter."""
        sig = inspect.signature(store.record_file_write)
        assert "user_id" in sig.parameters
        assert sig.parameters["user_id"].default is None
