"""Tests for the file_patch tool (insert_after/insert_before/replace/delete)."""
import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.tools.executor import ToolExecutor, ToolBlockedError, ToolError


def _make_executor(workspace_path):
    """Create a ToolExecutor with permissive policy engine."""
    engine = MagicMock()
    engine.check_command.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_read.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_write.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine._workspace_path = workspace_path
    return ToolExecutor(policy_engine=engine)


class TestFilePatchInsertAfter:
    @pytest.mark.asyncio
    async def test_insert_after_unique_anchor(self, tmp_path):
        """insert_after places content immediately after the anchor string."""
        f = tmp_path / "test.html"
        f.write_text('<div id="header">Header</div>\n<div id="footer">Footer</div>\n')
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "insert_after",
            "anchor": '<div id="header">Header</div>',
            "content": '\n<div id="content">New content</div>',
        })
        text = f.read_text()
        assert "File patched" in result.content
        assert text.index("content") < text.index("footer")
        assert meta["patch_operation"] == "insert_after"
        assert meta["file_size_after"] > meta["file_size_before"]

    @pytest.mark.asyncio
    async def test_insert_before_unique_anchor(self, tmp_path):
        """insert_before places content immediately before the anchor string."""
        f = tmp_path / "test.html"
        f.write_text('<div id="header">Header</div>\n<div id="footer">Footer</div>\n')
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "insert_before",
            "anchor": '<div id="footer">Footer</div>',
            "content": '<div id="content">New content</div>\n',
        })
        text = f.read_text()
        assert text.index("content") < text.index("footer")
        assert text.index("header") < text.index("content")


class TestFilePatchReplace:
    @pytest.mark.asyncio
    async def test_replace_swaps_anchor_for_content(self, tmp_path):
        """replace removes the anchor and inserts content in its place."""
        f = tmp_path / "test.css"
        f.write_text("body { color: red; }\nh1 { font-size: 2em; }\np { margin: 0; }\n")
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "replace",
            "anchor": "h1 { font-size: 2em; }",
            "content": "h1 { font-size: 3em; font-weight: bold; }",
        })
        text = f.read_text()
        assert "font-size: 3em" in text
        assert "font-size: 2em" not in text
        assert "body { color: red; }" in text  # unchanged content preserved
        assert "p { margin: 0; }" in text  # unchanged content preserved


class TestFilePatchDelete:
    @pytest.mark.asyncio
    async def test_delete_removes_anchor(self, tmp_path):
        """delete removes the anchor text from the file."""
        f = tmp_path / "test.js"
        f.write_text("const a = 1;\nconst debug = true; // REMOVE ME\nconst b = 2;\n")
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "delete",
            "anchor": "const debug = true; // REMOVE ME\n",
        })
        text = f.read_text()
        assert "debug" not in text
        assert "const a = 1;" in text
        assert "const b = 2;" in text
        assert meta["patch_operation"] == "delete"


class TestFilePatchErrors:
    @pytest.mark.asyncio
    async def test_anchor_not_found_raises(self, tmp_path):
        """Raises ToolError when anchor doesn't exist in file."""
        f = tmp_path / "test.html"
        f.write_text("<p>Hello</p>")
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="Anchor not found"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "insert_after",
                "anchor": "NONEXISTENT",
                "content": "new stuff",
            })

    @pytest.mark.asyncio
    async def test_anchor_multiple_matches_raises(self, tmp_path):
        """Raises ToolError when anchor matches multiple locations."""
        f = tmp_path / "test.html"
        f.write_text('<div class="panel">A</div>\n<div class="panel">B</div>\n')
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="matches 2 locations"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "replace",
                "anchor": '<div class="panel">',
                "content": "replacement",
            })

    @pytest.mark.asyncio
    async def test_invalid_operation_raises(self, tmp_path):
        """Raises ToolError for unrecognised operation."""
        f = tmp_path / "test.html"
        f.write_text("<p>Hello</p>")
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="Invalid operation"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "append",
                "anchor": "<p>",
                "content": "new",
            })

    @pytest.mark.asyncio
    async def test_replace_missing_content_raises(self, tmp_path):
        """Raises ToolError when replace has no content."""
        f = tmp_path / "test.html"
        f.write_text("<p>Hello</p>")
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="requires content"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "replace",
                "anchor": "<p>Hello</p>",
            })

    @pytest.mark.asyncio
    async def test_replace_large_anchor_warns(self, tmp_path):
        """Anchor >500 chars on replace logs a warning in exec_meta."""
        f = tmp_path / "test.html"
        large_anchor = "<div>" + "x" * 600 + "</div>"
        f.write_text(f"<body>{large_anchor}</body>")
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "replace",
            "anchor": large_anchor,
            "content": "<div>replaced</div>",
        })
        assert "anchor_size_warning" in meta

    @pytest.mark.asyncio
    async def test_replace_very_large_anchor_blocks(self, tmp_path):
        """Anchor >2000 chars on replace raises ToolError."""
        f = tmp_path / "test.html"
        huge_anchor = "<div>" + "x" * 2100 + "</div>"
        f.write_text(f"<body>{huge_anchor}</body>")
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="too large"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "replace",
                "anchor": huge_anchor,
                "content": "<div>replaced</div>",
            })


class TestFilePatchBackup:
    @pytest.mark.asyncio
    async def test_backup_created_before_patch(self, tmp_path):
        """A backup file is created before the patch is applied."""
        f = tmp_path / "test.html"
        original = "<p>Original</p>"
        f.write_text(original)
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "replace",
            "anchor": "Original",
            "content": "Modified",
        })
        backup_dir = tmp_path / ".patch_backups"
        assert backup_dir.exists()
        backups = list(backup_dir.iterdir())
        assert len(backups) == 1
        assert backups[0].read_text() == original
        assert "backup_path" in meta

    @pytest.mark.asyncio
    async def test_backup_cleanup_keeps_five(self, tmp_path):
        """Only the 5 most recent backups are retained per file."""
        f = tmp_path / "test.html"
        f.write_text("<p>v0</p>")
        executor = _make_executor(str(tmp_path))
        for i in range(7):
            f.write_text(f"<p>v{i}</p>")
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "replace",
                "anchor": f"v{i}",
                "content": f"v{i+1}",
            })
        backup_dir = tmp_path / ".patch_backups"
        backups = list(backup_dir.iterdir())
        assert len(backups) == 5


class TestFilePatchPolicy:
    @pytest.mark.asyncio
    async def test_policy_block_raises(self, tmp_path):
        """file_patch respects policy engine blocks."""
        engine = MagicMock()
        engine.check_file_write.return_value = ValidationResult(
            status=PolicyResult.BLOCKED, reason="path not allowed"
        )
        engine._workspace_path = str(tmp_path)
        executor = ToolExecutor(policy_engine=engine)
        f = tmp_path / "test.html"
        f.write_text("<p>Hello</p>")
        with pytest.raises(ToolBlockedError):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "insert_after",
                "anchor": "<p>Hello</p>",
                "content": "<p>World</p>",
            })


class TestFilePatchMetadata:
    @pytest.mark.asyncio
    async def test_exec_meta_contains_patch_fields(self, tmp_path):
        """exec_meta includes patch-specific fields."""
        f = tmp_path / "test.html"
        f.write_text("<p>Hello</p>")
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "insert_after",
            "anchor": "<p>Hello</p>",
            "content": "<p>World</p>",
        })
        assert "patch_operation" in meta
        assert "patch_anchor_length" in meta
        assert "file_size_before" in meta
        assert "file_size_after" in meta
        assert "backup_path" in meta
        assert meta["patch_operation"] == "insert_after"
        assert meta["patch_anchor_length"] == len("<p>Hello</p>")


class TestFileWriteAfterReadWarning:
    @pytest.mark.asyncio
    async def test_file_write_after_read_logs_warning(self, tmp_path):
        """file_write on a previously-read file adds a warning to exec_meta."""
        f = tmp_path / "test.html"
        f.write_text("<p>Hello</p>")
        executor = _make_executor(str(tmp_path))
        # First read the file
        await executor.execute("file_read", {"path": str(f)})
        # Then write to it — should produce a warning
        result, meta = await executor.execute("file_write", {
            "path": str(f),
            "content": "<p>Goodbye</p>",
        })
        assert "file_write_after_read_warning" in meta


class TestFilePatchCssSelector:
    """CSS selector anchor resolution for HTML files (design doc §4.4)."""

    @pytest.mark.asyncio
    async def test_css_id_selector_replace(self, tmp_path):
        """css:#id resolves to the element and replaces it."""
        f = tmp_path / "page.html"
        f.write_text(
            '<div id="header">Old Header</div>\n'
            '<div id="content">Body</div>\n'
        )
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "replace",
            "anchor": "css:#header",
            "content": '<div id="header">New Header</div>',
        })
        text = f.read_text()
        assert "New Header" in text
        assert "Old Header" not in text
        assert "Body" in text  # other content preserved
        assert meta.get("css_selector") == "#header"

    @pytest.mark.asyncio
    async def test_css_class_selector_insert_after(self, tmp_path):
        """css:.class resolves and inserts after the matched element."""
        f = tmp_path / "page.html"
        f.write_text(
            '<nav class="top-nav">Nav</nav>\n'
            '<main>Content</main>\n'
        )
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "insert_after",
            "anchor": "css:.top-nav",
            "content": '\n<div class="banner">Hello</div>',
        })
        text = f.read_text()
        assert text.index("Nav") < text.index("banner") < text.index("Content")

    @pytest.mark.asyncio
    async def test_css_selector_no_match_error(self, tmp_path):
        """css: selector with no matching element raises ToolError."""
        f = tmp_path / "page.html"
        f.write_text('<div id="exists">Content</div>\n')
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="matched no elements"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "replace",
                "anchor": "css:#nonexistent",
                "content": "replacement",
            })

    @pytest.mark.asyncio
    async def test_css_selector_multiple_match_error(self, tmp_path):
        """css: selector matching multiple elements raises ToolError."""
        f = tmp_path / "page.html"
        f.write_text(
            '<div class="panel">One</div>\n'
            '<div class="panel">Two</div>\n'
        )
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="matched 2 elements"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "replace",
                "anchor": "css:.panel",
                "content": "replacement",
            })

    @pytest.mark.asyncio
    async def test_css_on_non_html_treated_as_literal(self, tmp_path):
        """css: prefix on non-HTML file is treated as literal text anchor."""
        f = tmp_path / "config.yaml"
        f.write_text("css:#panel-weather\nother: value\n")
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "replace",
            "anchor": "css:#panel-weather",
            "content": "replaced-line",
        })
        text = f.read_text()
        assert "replaced-line" in text
        assert "css:#panel-weather" not in text
        # No css_selector in meta — it fell through to literal matching
        assert "css_selector" not in meta

    @pytest.mark.asyncio
    async def test_css_empty_selector_error(self, tmp_path):
        """css: with no selector raises ToolError."""
        f = tmp_path / "page.html"
        f.write_text('<div>Content</div>\n')
        executor = _make_executor(str(tmp_path))
        with pytest.raises(ToolError, match="requires a CSS selector"):
            await executor.execute("file_patch", {
                "path": str(f),
                "operation": "replace",
                "anchor": "css:",
                "content": "replacement",
            })

    @pytest.mark.asyncio
    async def test_css_delete_operation(self, tmp_path):
        """css: selector with delete operation removes the element."""
        f = tmp_path / "page.html"
        f.write_text(
            '<div id="keep">Keep</div>\n'
            '<div id="remove">Remove Me</div>\n'
            '<div id="also-keep">Also Keep</div>\n'
        )
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "delete",
            "anchor": "css:#remove",
        })
        text = f.read_text()
        assert "Keep" in text
        assert "Remove Me" not in text
        assert "Also Keep" in text

    @pytest.mark.asyncio
    async def test_css_unique_selector_with_repeated_html(self, tmp_path):
        """css: selector matches 1 element but its HTML appears in multiple panels."""
        f = tmp_path / "dashboard.html"
        # 3 panels with identical inner structure — only IDs differ
        f.write_text(
            '<div id="panel-weather"><div class="panel-content"><p>NO DATA</p></div></div>\n'
            '<div id="panel-markets"><div class="panel-content"><p>NO DATA</p></div></div>\n'
            '<div id="panel-news"><div class="panel-content"><p>NO DATA</p></div></div>\n'
        )
        executor = _make_executor(str(tmp_path))
        result, meta = await executor.execute("file_patch", {
            "path": str(f),
            "operation": "replace",
            "anchor": "css:#panel-markets",
            "content": '<div id="panel-markets"><div class="panel-content"><p>BTC: 50000</p></div></div>',
        })
        text = f.read_text()
        # Only the markets panel should be updated
        assert text.count("BTC: 50000") == 1
        assert text.count("NO DATA") == 2  # weather + news still untouched
        assert meta.get("css_selector") == "#panel-markets"
