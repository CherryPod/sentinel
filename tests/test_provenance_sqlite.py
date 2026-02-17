"""SQLite-specific provenance tests.

Tests ProvenanceStore class directly with :memory: db,
specifically testing recursive CTE chain walking and trust inheritance via SQL.
"""

import pytest

from sentinel.core.db import init_db
from sentinel.core.models import DataSource, TrustLevel
from sentinel.security.provenance import ProvenanceStore


@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def store(db):
    return ProvenanceStore(db=db)


class TestProvenanceStoreSQLite:
    def test_create_and_retrieve(self, store):
        t = store.create_tagged_data("hello", DataSource.USER, TrustLevel.TRUSTED)
        retrieved = store.get_tagged_data(t.id)
        assert retrieved is not None
        assert retrieved.content == "hello"
        assert retrieved.trust_level == TrustLevel.TRUSTED
        assert retrieved.source == DataSource.USER

    def test_unique_ids(self, store):
        a = store.create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        b = store.create_tagged_data("b", DataSource.USER, TrustLevel.TRUSTED)
        assert a.id != b.id

    def test_missing_id_returns_none(self, store):
        assert store.get_tagged_data("nonexistent") is None

    def test_trust_inheritance_untrusted_parent(self, store):
        parent = store.create_tagged_data("qwen out", DataSource.QWEN, TrustLevel.UNTRUSTED)
        child = store.create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[parent.id]
        )
        assert child.trust_level == TrustLevel.UNTRUSTED

    def test_trust_inheritance_all_trusted(self, store):
        p1 = store.create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        p2 = store.create_tagged_data("b", DataSource.CLAUDE, TrustLevel.TRUSTED)
        child = store.create_tagged_data(
            "c", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert child.trust_level == TrustLevel.TRUSTED

    def test_chain_single_item(self, store):
        t = store.create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        chain = store.get_provenance_chain(t.id)
        assert len(chain) == 1
        assert chain[0].id == t.id

    def test_chain_two_levels(self, store):
        parent = store.create_tagged_data("parent", DataSource.USER, TrustLevel.TRUSTED)
        child = store.create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[parent.id]
        )
        chain = store.get_provenance_chain(child.id)
        assert len(chain) == 2
        ids = {c.id for c in chain}
        assert child.id in ids
        assert parent.id in ids

    def test_chain_three_levels(self, store):
        root = store.create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        mid = store.create_tagged_data("mid", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id])
        leaf = store.create_tagged_data("leaf", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[mid.id])
        chain = store.get_provenance_chain(leaf.id)
        assert len(chain) == 3

    def test_chain_nonexistent_returns_empty(self, store):
        chain = store.get_provenance_chain("nonexistent")
        assert chain == []

    def test_trust_safe_trusted_chain(self, store):
        root = store.create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        child = store.create_tagged_data(
            "output", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id]
        )
        assert store.is_trust_safe_for_execution(child.id) is True

    def test_trust_unsafe_with_untrusted_in_chain(self, store):
        root = store.create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        qwen = store.create_tagged_data(
            "qwen_out", DataSource.QWEN, TrustLevel.UNTRUSTED, parent_ids=[root.id]
        )
        derived = store.create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.UNTRUSTED, parent_ids=[qwen.id]
        )
        assert store.is_trust_safe_for_execution(derived.id) is False

    def test_file_provenance_roundtrip(self, store):
        t = store.create_tagged_data("written", DataSource.TOOL, TrustLevel.TRUSTED)
        store.record_file_write("/workspace/test.txt", t.id)
        assert store.get_file_writer("/workspace/test.txt") == t.id

    def test_file_provenance_overwrite(self, store):
        t1 = store.create_tagged_data("first", DataSource.TOOL, TrustLevel.TRUSTED)
        t2 = store.create_tagged_data("second", DataSource.TOOL, TrustLevel.TRUSTED)
        store.record_file_write("/workspace/out.txt", t1.id)
        store.record_file_write("/workspace/out.txt", t2.id)
        assert store.get_file_writer("/workspace/out.txt") == t2.id

    def test_file_provenance_unknown(self, store):
        assert store.get_file_writer("/workspace/unknown.txt") is None

    def test_reset_clears_everything(self, store):
        t = store.create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        store.record_file_write("/workspace/test.txt", t.id)
        store.reset_store()
        assert store.get_tagged_data(t.id) is None
        assert store.get_file_writer("/workspace/test.txt") is None

    def test_originated_from_stored(self, store):
        t = store.create_tagged_data(
            "data", DataSource.TOOL, TrustLevel.TRUSTED, originated_from="step_1"
        )
        retrieved = store.get_tagged_data(t.id)
        assert retrieved.originated_from == "step_1"

    def test_persistence_across_store_instances(self, db):
        """Data persists even when creating a new ProvenanceStore."""
        s1 = ProvenanceStore(db=db)
        t = s1.create_tagged_data("persistent", DataSource.USER, TrustLevel.TRUSTED)

        s2 = ProvenanceStore(db=db)
        retrieved = s2.get_tagged_data(t.id)
        assert retrieved is not None
        assert retrieved.content == "persistent"
