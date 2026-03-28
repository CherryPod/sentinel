"""Provenance store in-memory tests.

Tests ProvenanceStore class with pool=None (in-memory dict fallback),
testing chain walking and trust inheritance.
"""

import pytest

from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import ProvenanceStore


@pytest.fixture
def store():
    return ProvenanceStore(pool=None)


class TestProvenanceStoreInMemory:
    async def test_create_and_retrieve(self, store):
        t = await store.create_tagged_data("hello", DataSource.USER, TrustLevel.TRUSTED)
        retrieved = await store.get_tagged_data(t.id)
        assert retrieved is not None
        assert retrieved.content == "hello"
        assert retrieved.trust_level == TrustLevel.TRUSTED
        assert retrieved.source == DataSource.USER

    async def test_unique_ids(self, store):
        a = await store.create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        b = await store.create_tagged_data("b", DataSource.USER, TrustLevel.TRUSTED)
        assert a.id != b.id

    async def test_missing_id_returns_none(self, store):
        assert await store.get_tagged_data("nonexistent") is None

    async def test_trust_inheritance_untrusted_parent(self, store):
        parent = await store.create_tagged_data("qwen out", DataSource.QWEN, TrustLevel.UNTRUSTED)
        child = await store.create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[parent.id]
        )
        assert child.trust_level == TrustLevel.UNTRUSTED

    async def test_trust_inheritance_all_trusted(self, store):
        p1 = await store.create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        p2 = await store.create_tagged_data("b", DataSource.CLAUDE, TrustLevel.TRUSTED)
        child = await store.create_tagged_data(
            "c", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert child.trust_level == TrustLevel.TRUSTED

    async def test_chain_single_item(self, store):
        t = await store.create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        chain = await store.get_provenance_chain(t.id)
        assert len(chain) == 1
        assert chain[0].id == t.id

    async def test_chain_two_levels(self, store):
        parent = await store.create_tagged_data("parent", DataSource.USER, TrustLevel.TRUSTED)
        child = await store.create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[parent.id]
        )
        chain = await store.get_provenance_chain(child.id)
        assert len(chain) == 2
        ids = {c.id for c in chain}
        assert child.id in ids
        assert parent.id in ids

    async def test_chain_three_levels(self, store):
        root = await store.create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        mid = await store.create_tagged_data("mid", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id])
        leaf = await store.create_tagged_data("leaf", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[mid.id])
        chain = await store.get_provenance_chain(leaf.id)
        assert len(chain) == 3

    async def test_chain_nonexistent_returns_empty(self, store):
        chain = await store.get_provenance_chain("nonexistent")
        assert chain == []

    async def test_trust_safe_trusted_chain(self, store):
        root = await store.create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        child = await store.create_tagged_data(
            "output", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id]
        )
        assert await store.is_trust_safe_for_execution(child.id) is True

    async def test_trust_unsafe_with_untrusted_in_chain(self, store):
        root = await store.create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        qwen = await store.create_tagged_data(
            "qwen_out", DataSource.QWEN, TrustLevel.UNTRUSTED, parent_ids=[root.id]
        )
        derived = await store.create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.UNTRUSTED, parent_ids=[qwen.id]
        )
        assert await store.is_trust_safe_for_execution(derived.id) is False

    async def test_file_provenance_roundtrip(self, store):
        t = await store.create_tagged_data("written", DataSource.TOOL, TrustLevel.TRUSTED)
        await store.record_file_write("/workspace/test.txt", t.id)
        result = await store.get_file_writer("/workspace/test.txt")
        assert result is not None
        assert result[0] == t.id

    async def test_file_provenance_overwrite(self, store):
        t1 = await store.create_tagged_data("first", DataSource.TOOL, TrustLevel.TRUSTED)
        t2 = await store.create_tagged_data("second", DataSource.TOOL, TrustLevel.TRUSTED)
        await store.record_file_write("/workspace/out.txt", t1.id)
        await store.record_file_write("/workspace/out.txt", t2.id)
        result = await store.get_file_writer("/workspace/out.txt")
        assert result is not None
        assert result[0] == t2.id

    async def test_file_provenance_unknown(self, store):
        assert await store.get_file_writer("/workspace/unknown.txt") is None

    async def test_reset_clears_everything(self, store):
        t = await store.create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        await store.record_file_write("/workspace/test.txt", t.id)
        await store.reset_store()
        assert await store.get_tagged_data(t.id) is None
        assert await store.get_file_writer("/workspace/test.txt") is None

    async def test_originated_from_stored(self, store):
        t = await store.create_tagged_data(
            "data", DataSource.TOOL, TrustLevel.TRUSTED, originated_from="step_1"
        )
        retrieved = await store.get_tagged_data(t.id)
        assert retrieved.originated_from == "step_1"


class TestUpdateContentInMemory:
    """Tests for update_content with in-memory backend."""

    async def test_updates_content(self, store):
        t = await store.create_tagged_data(
            "<RESPONSE>\ndef foo(): pass\n</RESPONSE>",
            DataSource.QWEN, TrustLevel.UNTRUSTED,
        )
        assert await store.update_content(t.id, "def foo(): pass")
        retrieved = await store.get_tagged_data(t.id)
        assert retrieved.content == "def foo(): pass"

    async def test_returns_false_for_missing_id(self, store):
        assert not await store.update_content("nonexistent-id", "content")

    async def test_preserves_metadata(self, store):
        t = await store.create_tagged_data(
            "raw", DataSource.QWEN, TrustLevel.UNTRUSTED,
            originated_from="qwen_pipeline",
        )
        await store.update_content(t.id, "cleaned")
        retrieved = await store.get_tagged_data(t.id)
        assert retrieved.trust_level == TrustLevel.UNTRUSTED
        assert retrieved.source == DataSource.QWEN
        assert retrieved.originated_from == "qwen_pipeline"

    async def test_downstream_chain_trust_unaffected(self, store):
        """Updating content doesn't change trust inheritance."""
        parent = await store.create_tagged_data(
            "<RESPONSE>evil</RESPONSE>",
            DataSource.QWEN, TrustLevel.UNTRUSTED,
        )
        await store.update_content(parent.id, "evil")
        child = await store.create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.TRUSTED,
            parent_ids=[parent.id],
        )
        assert child.trust_level == TrustLevel.UNTRUSTED
        assert not await store.is_trust_safe_for_execution(child.id)


class TestInMemoryUserIsolation:
    """Verify in-memory backend respects user_id filtering."""

    @pytest.fixture
    def store(self):
        return ProvenanceStore(pool=None)

    @pytest.mark.asyncio
    async def test_get_tagged_data_filters_by_user(self, store):
        tagged = await store.create_tagged_data(
            "content", DataSource.USER, TrustLevel.TRUSTED, user_id=1,
        )
        result = await store.get_tagged_data(tagged.id, user_id=2)
        assert result is None
        result = await store.get_tagged_data(tagged.id, user_id=1)
        assert result is not None
        assert result.id == tagged.id

    @pytest.mark.asyncio
    async def test_get_tagged_data_no_user_returns_any(self, store):
        tagged = await store.create_tagged_data(
            "content", DataSource.USER, TrustLevel.TRUSTED, user_id=1,
        )
        result = await store.get_tagged_data(tagged.id)
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_content_filters_by_user(self, store):
        tagged = await store.create_tagged_data(
            "original", DataSource.USER, TrustLevel.TRUSTED, user_id=1,
        )
        result = await store.update_content(tagged.id, "modified", user_id=2)
        assert result is False
        item = await store.get_tagged_data(tagged.id)
        assert item.content == "original"
        result = await store.update_content(tagged.id, "modified", user_id=1)
        assert result is True

    @pytest.mark.asyncio
    async def test_file_provenance_user_isolation(self, store):
        await store.record_file_write("/workspace/test.txt", "data-1", content="aaa", user_id=1)
        await store.record_file_write("/workspace/test.txt", "data-2", content="bbb", user_id=2)
        result1 = await store.get_file_writer("/workspace/test.txt", user_id=1)
        result2 = await store.get_file_writer("/workspace/test.txt", user_id=2)
        assert result1 is not None
        assert result2 is not None
        assert result1[0] == "data-1"
        assert result2[0] == "data-2"

    @pytest.mark.asyncio
    async def test_file_provenance_no_user_returns_any(self, store):
        await store.record_file_write("/workspace/test.txt", "data-1", content="aaa", user_id=1)
        result = await store.get_file_writer("/workspace/test.txt")
        assert result is not None

    @pytest.mark.asyncio
    async def test_provenance_chain_walks_all_users(self, store):
        """Regression guard — chain walk must cross user boundaries."""
        parent = await store.create_tagged_data(
            "parent", DataSource.USER, TrustLevel.UNTRUSTED, user_id=1,
        )
        child = await store.create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED,
            parent_ids=[parent.id], user_id=2,
        )
        assert child.trust_level == TrustLevel.UNTRUSTED
        chain = await store.get_provenance_chain(child.id)
        assert len(chain) == 2

    @pytest.mark.asyncio
    async def test_provenance_chain_filters_final_result(self, store):
        parent = await store.create_tagged_data(
            "parent", DataSource.USER, TrustLevel.TRUSTED, user_id=1,
        )
        child = await store.create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED,
            parent_ids=[parent.id], user_id=2,
        )
        chain = await store.get_provenance_chain(child.id, user_id=2)
        assert len(chain) == 1
        assert chain[0].id == child.id
