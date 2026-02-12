import pytest

from app.models import DataSource, TrustLevel
from app.provenance import (
    create_tagged_data,
    get_provenance_chain,
    get_tagged_data,
    is_trust_safe_for_execution,
    reset_store,
)


@pytest.fixture(autouse=True)
def clean_store():
    """Reset the provenance store before each test."""
    reset_store()
    yield
    reset_store()


class TestCreation:
    def test_creates_with_unique_id(self):
        a = create_tagged_data("hello", DataSource.USER, TrustLevel.TRUSTED)
        b = create_tagged_data("world", DataSource.USER, TrustLevel.TRUSTED)
        assert a.id != b.id

    def test_stores_content(self):
        t = create_tagged_data("test content", DataSource.USER, TrustLevel.TRUSTED)
        assert t.content == "test content"

    def test_stores_source(self):
        t = create_tagged_data("data", DataSource.QWEN, TrustLevel.UNTRUSTED)
        assert t.source == DataSource.QWEN

    def test_stores_trust_level(self):
        t = create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        assert t.trust_level == TrustLevel.TRUSTED

    def test_stores_originated_from(self):
        t = create_tagged_data("data", DataSource.TOOL, TrustLevel.TRUSTED, originated_from="step_1")
        assert t.originated_from == "step_1"

    def test_has_timestamp(self):
        t = create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        assert t.timestamp is not None

    def test_retrievable_by_id(self):
        t = create_tagged_data("data", DataSource.USER, TrustLevel.TRUSTED)
        retrieved = get_tagged_data(t.id)
        assert retrieved is not None
        assert retrieved.content == "data"

    def test_missing_id_returns_none(self):
        assert get_tagged_data("nonexistent-id") is None


class TestTrustInheritance:
    def test_trusted_parents_keep_trusted(self):
        p1 = create_tagged_data("parent1", DataSource.USER, TrustLevel.TRUSTED)
        p2 = create_tagged_data("parent2", DataSource.CLAUDE, TrustLevel.TRUSTED)
        child = create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert child.trust_level == TrustLevel.TRUSTED

    def test_untrusted_parent_overrides(self):
        p1 = create_tagged_data("trusted", DataSource.USER, TrustLevel.TRUSTED)
        p2 = create_tagged_data("untrusted", DataSource.QWEN, TrustLevel.UNTRUSTED)
        child = create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert child.trust_level == TrustLevel.UNTRUSTED

    def test_single_untrusted_parent(self):
        p = create_tagged_data("qwen output", DataSource.QWEN, TrustLevel.UNTRUSTED)
        child = create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p.id]
        )
        assert child.trust_level == TrustLevel.UNTRUSTED

    def test_no_parents_keeps_explicit_trust(self):
        t = create_tagged_data("data", DataSource.QWEN, TrustLevel.UNTRUSTED)
        assert t.trust_level == TrustLevel.UNTRUSTED

    def test_derived_from_populated(self):
        p1 = create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        p2 = create_tagged_data("b", DataSource.USER, TrustLevel.TRUSTED)
        child = create_tagged_data(
            "c", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[p1.id, p2.id]
        )
        assert p1.id in child.derived_from
        assert p2.id in child.derived_from


class TestProvenanceChain:
    def test_single_item_chain(self):
        t = create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        chain = get_provenance_chain(t.id)
        assert len(chain) == 1
        assert chain[0].id == t.id

    def test_two_level_chain(self):
        parent = create_tagged_data("parent", DataSource.USER, TrustLevel.TRUSTED)
        child = create_tagged_data(
            "child", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[parent.id]
        )
        chain = get_provenance_chain(child.id)
        assert len(chain) == 2
        ids = [c.id for c in chain]
        assert child.id in ids
        assert parent.id in ids

    def test_three_level_chain(self):
        root = create_tagged_data("root", DataSource.USER, TrustLevel.TRUSTED)
        mid = create_tagged_data("mid", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id])
        leaf = create_tagged_data("leaf", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[mid.id])
        chain = get_provenance_chain(leaf.id)
        assert len(chain) == 3

    def test_circular_ref_safety(self):
        """Provenance chain should not loop infinitely on circular refs."""
        a = create_tagged_data("a", DataSource.USER, TrustLevel.TRUSTED)
        b = create_tagged_data("b", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[a.id])
        # Manually create a circular reference (shouldn't happen in practice)
        a.derived_from.append(b.id)
        chain = get_provenance_chain(a.id)
        # Should terminate without infinite loop
        assert len(chain) <= 50

    def test_nonexistent_id_returns_empty(self):
        chain = get_provenance_chain("nonexistent")
        assert chain == []


class TestTrustExecution:
    def test_trusted_chain_safe(self):
        root = create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        child = create_tagged_data(
            "output", DataSource.TOOL, TrustLevel.TRUSTED, parent_ids=[root.id]
        )
        assert is_trust_safe_for_execution(child.id) is True

    def test_untrusted_in_chain_unsafe(self):
        root = create_tagged_data("input", DataSource.USER, TrustLevel.TRUSTED)
        qwen = create_tagged_data(
            "qwen_out", DataSource.QWEN, TrustLevel.UNTRUSTED, parent_ids=[root.id]
        )
        derived = create_tagged_data(
            "derived", DataSource.TOOL, TrustLevel.UNTRUSTED, parent_ids=[qwen.id]
        )
        assert is_trust_safe_for_execution(derived.id) is False

    def test_nonexistent_id_safe(self):
        # No chain = no untrusted items = vacuously safe
        assert is_trust_safe_for_execution("nonexistent") is True
