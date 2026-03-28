import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.tools.anchor_allocator._memory import (
    write_anchor_map,
    read_anchor_map,
    clear_anchor_map,
)
from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier
from sentinel.tools.anchor_allocator import allocate_anchors


class TestWriteAnchorMap:
    @pytest.mark.asyncio
    async def test_writes_fact_to_store(self):
        store = AsyncMock()
        store.create = AsyncMock(return_value="rec-123")
        store.store_facts = AsyncMock()
        store.search_facts = AsyncMock(return_value=[])

        anchors = [
            AnchorEntry("head-styles", 7, AnchorTier.SECTION, "CSS insertion", True),
            AnchorEntry("el-panel", 20, AnchorTier.BLOCK, "Panel element", True),
        ]

        await write_anchor_map(
            path="/workspace/sites/dashboard.html",
            anchors=anchors,
            file_hash="abc123",
            tier="block",
            episodic_store=store,
            user_id=1,
        )

        store.create.assert_called_once()
        store.store_facts.assert_called_once()

        # Verify the fact content
        call_args = store.store_facts.call_args
        facts = call_args[0][1]  # Second positional arg
        assert len(facts) == 1
        fact = facts[0]
        assert fact.fact_type == "anchor_map"
        assert fact.file_path == "/workspace/sites/dashboard.html"

        data = json.loads(fact.content)
        assert data["file_hash"] == "abc123"
        assert data["anchor_count"] == 2
        assert len(data["anchors"]) == 2

    @pytest.mark.asyncio
    async def test_upsert_searches_existing(self):
        """If an anchor map already exists for this file, search is attempted first."""
        existing_fact = MagicMock()
        existing_fact.fact_id = "old-fact-123"

        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[existing_fact])
        store.create = AsyncMock(return_value="rec-456")
        store.store_facts = AsyncMock()

        await write_anchor_map(
            path="/workspace/test.html",
            anchors=[],
            file_hash="xyz",
            tier="block",
            episodic_store=store,
            user_id=1,
        )

        # Should have attempted to find existing
        store.search_facts.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_failure_does_not_crash(self):
        """If create raises, write_anchor_map returns gracefully."""
        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[])
        store.create = AsyncMock(side_effect=RuntimeError("DB down"))

        # Should not raise
        await write_anchor_map(
            path="/workspace/test.html",
            anchors=[],
            file_hash="xyz",
            tier="block",
            episodic_store=store,
            user_id=1,
        )

    @pytest.mark.asyncio
    async def test_store_facts_failure_does_not_crash(self):
        """If store_facts raises, write_anchor_map returns gracefully."""
        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[])
        store.create = AsyncMock(return_value="rec-789")
        store.store_facts = AsyncMock(side_effect=RuntimeError("DB down"))

        # Should not raise
        await write_anchor_map(
            path="/workspace/test.html",
            anchors=[],
            file_hash="xyz",
            tier="block",
            episodic_store=store,
            user_id=1,
        )


class TestReadAnchorMap:
    @pytest.mark.asyncio
    async def test_returns_anchors_when_fresh(self):
        fact = MagicMock()
        fact.content = json.dumps({
            "file_hash": "abc123",
            "anchor_count": 2,
            "default_tier": "block",
            "anchors": [
                {"name": "head-styles", "line": 7, "tier": "section",
                 "has_end": True, "description": "CSS insertion"},
            ],
        })

        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[fact])

        result = await read_anchor_map(
            path="/workspace/test.html",
            current_hash="abc123",
            episodic_store=store,
            user_id=1,
        )

        assert result is not None
        assert len(result) == 1
        assert result[0]["name"] == "head-styles"

    @pytest.mark.asyncio
    async def test_returns_none_when_stale(self):
        fact = MagicMock()
        fact.content = json.dumps({
            "file_hash": "old-hash",
            "anchor_count": 1,
            "anchors": [],
        })

        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[fact])

        result = await read_anchor_map(
            path="/workspace/test.html",
            current_hash="new-hash",
            episodic_store=store,
            user_id=1,
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_map(self):
        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[])

        result = await read_anchor_map(
            path="/workspace/test.html",
            current_hash="abc123",
            episodic_store=store,
            user_id=1,
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_invalid_json(self):
        fact = MagicMock()
        fact.content = "not valid json"

        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[fact])

        result = await read_anchor_map(
            path="/workspace/test.html",
            current_hash="abc123",
            episodic_store=store,
            user_id=1,
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_search_error(self):
        store = AsyncMock()
        store.search_facts = AsyncMock(side_effect=RuntimeError("DB down"))

        result = await read_anchor_map(
            path="/workspace/test.html",
            current_hash="abc123",
            episodic_store=store,
            user_id=1,
        )

        assert result is None


class TestClearAnchorMap:
    @pytest.mark.asyncio
    async def test_deletes_existing_map(self):
        fact = MagicMock()
        fact.record_id = "rec-123"

        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[fact])
        store.delete = AsyncMock(return_value=True)

        await clear_anchor_map(
            path="/workspace/test.html",
            episodic_store=store,
            user_id=1,
        )

        store.delete.assert_called_once_with("rec-123", user_id=1)

    @pytest.mark.asyncio
    async def test_no_op_when_no_map(self):
        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[])

        await clear_anchor_map(
            path="/workspace/test.html",
            episodic_store=store,
            user_id=1,
        )

        store.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_clear_failure_does_not_crash(self):
        store = AsyncMock()
        store.search_facts = AsyncMock(side_effect=RuntimeError("DB down"))

        # Should not raise
        await clear_anchor_map(
            path="/workspace/test.html",
            episodic_store=store,
            user_id=1,
        )


class TestAllocateWithEpisodicStore:
    @pytest.mark.asyncio
    async def test_writes_to_store_when_provided(self):
        """allocate_anchors writes to episodic store when one is provided."""
        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[])
        store.create = AsyncMock(return_value="rec-100")
        store.store_facts = AsyncMock()

        html = (
            '<!DOCTYPE html>\n<html>\n<head>\n'
            '<style>body { margin: 0; }</style>\n'
            '</head>\n<body>\n'
            '<div id="panel"><p>Test</p></div>\n'
            '</body>\n</html>'
        )
        result = await allocate_anchors(
            "dashboard.html", html,
            episodic_store=store, user_id=1,
        )

        assert result.changed is True
        store.store_facts.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_store_no_write(self):
        """Without episodic store, no memory write is attempted."""
        html = (
            '<!DOCTYPE html>\n<html>\n<head></head>\n<body>\n'
            '<div id="panel"><p>Test</p></div>\n'
            '</body>\n</html>'
        )
        # No episodic_store argument — should work without error
        result = await allocate_anchors("page.html", html)
        assert result.changed is True

    @pytest.mark.asyncio
    async def test_store_failure_still_returns_result(self):
        """If episodic store fails, allocator still returns the anchored content."""
        store = AsyncMock()
        store.search_facts = AsyncMock(return_value=[])
        store.create = AsyncMock(side_effect=RuntimeError("DB down"))

        code = "import os\n\ndef main():\n    pass\n"
        result = await allocate_anchors(
            "script.py", code,
            episodic_store=store, user_id=1,
        )

        # Anchors should still be placed even though memory write failed
        assert result.changed is True
        assert "# anchor: imports" in result.content
