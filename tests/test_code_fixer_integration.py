"""Integration tests: code_fixer wired into executor._file_write() and
executor._file_patch().

Verifies that the code fixer runs during file writes and patches, that its
metadata appears in exec_meta, and that a fixer crash doesn't block the
write/patch.
"""

import pytest
from unittest.mock import MagicMock, patch

from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.tools.executor import ToolExecutor


def _make_executor():
    """Create a ToolExecutor with a permissive mock policy engine."""
    engine = MagicMock()
    engine.check_command.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_read.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    engine.check_file_write.return_value = ValidationResult(status=PolicyResult.ALLOWED)
    return ToolExecutor(policy_engine=engine)


class TestCodeFixerAppliesFixes:
    """Code fixer runs on file writes and applies fixes."""

    @pytest.mark.asyncio
    async def test_trailing_newline_added_to_py_file(self, tmp_path):
        """A .py file without trailing newline gets one via code fixer."""
        executor = _make_executor()
        target = str(tmp_path / "hello.py")
        # Content without trailing newline — fixer should add it
        _, meta = await executor.execute(
            "file_write", {"path": target, "content": "print('hello')"}
        )
        # File on disk should have the trailing newline
        with open(target) as f:
            written = f.read()
        assert written.endswith("\n")
        # exec_meta should reflect the fix
        assert meta["code_fixer_changed"] is True
        assert any("trailing newline" in fix.lower() for fix in meta["code_fixer_fixes"])

    @pytest.mark.asyncio
    async def test_clean_file_no_changes(self, tmp_path):
        """A file that needs no fixing should pass through unchanged."""
        executor = _make_executor()
        target = str(tmp_path / "clean.py")
        content = "print('hello')\n"
        _, meta = await executor.execute(
            "file_write", {"path": target, "content": content}
        )
        with open(target) as f:
            written = f.read()
        assert written == content
        assert meta["code_fixer_changed"] is False
        assert meta["code_fixer_fixes"] == []

    @pytest.mark.asyncio
    async def test_crlf_normalised(self, tmp_path):
        """CRLF line endings should be normalised to LF."""
        executor = _make_executor()
        target = str(tmp_path / "crlf.py")
        content = "line1\r\nline2\r\n"
        _, meta = await executor.execute(
            "file_write", {"path": target, "content": content}
        )
        with open(target) as f:
            written = f.read()
        assert "\r\n" not in written
        assert meta["code_fixer_changed"] is True
        assert any("crlf" in fix.lower() for fix in meta["code_fixer_fixes"])


class TestCodeFixerExecMeta:
    """Code fixer metadata appears in exec_meta."""

    @pytest.mark.asyncio
    async def test_meta_keys_present(self, tmp_path):
        """All four code_fixer_* keys are present in exec_meta."""
        executor = _make_executor()
        target = str(tmp_path / "meta.txt")
        _, meta = await executor.execute(
            "file_write", {"path": target, "content": "hello"}
        )
        assert "code_fixer_changed" in meta
        assert "code_fixer_fixes" in meta
        assert "code_fixer_errors" in meta
        assert "code_fixer_warnings" in meta

    @pytest.mark.asyncio
    async def test_meta_types(self, tmp_path):
        """Metadata values have correct types."""
        executor = _make_executor()
        target = str(tmp_path / "types.py")
        _, meta = await executor.execute(
            "file_write", {"path": target, "content": "x = 1\n"}
        )
        assert isinstance(meta["code_fixer_changed"], bool)
        assert isinstance(meta["code_fixer_fixes"], list)
        assert isinstance(meta["code_fixer_errors"], list)
        assert isinstance(meta["code_fixer_warnings"], list)


class TestCodeFixerCrashSafety:
    """Code fixer crash must never block a file write."""

    @pytest.mark.asyncio
    async def test_crash_still_writes_file(self, tmp_path):
        """If code_fixer_fix raises, the file is still written with original content."""
        executor = _make_executor()
        target = str(tmp_path / "crash.py")
        content = "print('hello')"

        with patch(
            "sentinel.tools.executor.code_fixer_fix",
            side_effect=RuntimeError("fixer exploded"),
        ):
            _, meta = await executor.execute(
                "file_write", {"path": target, "content": content}
            )

        # File should be written with original content (no fixer modifications)
        with open(target) as f:
            written = f.read()
        assert written == content

        # Meta should have safe defaults (fix_result was None)
        assert meta["code_fixer_changed"] is False
        assert meta["code_fixer_fixes"] == []
        assert meta["code_fixer_errors"] == []
        assert meta["code_fixer_warnings"] == []

    @pytest.mark.asyncio
    async def test_crash_preserves_other_meta(self, tmp_path):
        """A fixer crash doesn't corrupt the standard exec_meta fields."""
        executor = _make_executor()
        target = str(tmp_path / "crash2.py")

        with patch(
            "sentinel.tools.executor.code_fixer_fix",
            side_effect=ValueError("boom"),
        ):
            _, meta = await executor.execute(
                "file_write", {"path": target, "content": "data"}
            )

        assert meta["file_size_before"] is None  # new file
        assert meta["file_size_after"] == 4  # len("data")
        assert meta["file_content_before"] is None


# ===================================================================
# file_patch: FULL-FILE CODE FIXER
# ===================================================================


class TestFilePatchFullFileFixer:
    """Full-file code fixer runs on the patched result before writing."""

    @pytest.mark.asyncio
    async def test_css_outside_style_fixed_after_patch(self, tmp_path):
        """Patching CSS outside <style> in HTML triggers cross-language fix.

        Defence-in-depth: the fragment-level fixer may catch this first
        (it sees the fragment as HTML content with CSS patterns), so the
        full-file fixer may find nothing left to fix. We verify that the
        CSS gets wrapped by EITHER layer.
        """
        executor = _make_executor()
        target = str(tmp_path / "dashboard.html")

        # Write initial HTML file with a <style> block
        initial = (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            "<style>\nbody { margin: 0; }\n</style>\n"
            "</head>\n<body></body>\n</html>\n"
        )
        with open(target, "w") as f:
            f.write(initial)

        # Patch: insert CSS OUTSIDE the <style> block (simulates LLM error)
        _, meta = await executor.execute(
            "file_patch",
            {
                "path": target,
                "operation": "insert_after",
                "anchor": "</style>",
                "content": "\n#panel { color: red; }\n.widget { padding: 5px; }",
            },
        )

        with open(target) as f:
            result = f.read()

        # CSS should be wrapped by either fragment or full-file fixer
        all_fixes = (
            meta.get("code_fixer_fixes", [])
            + meta.get("full_file_fixer_fixes", [])
        )
        assert any("CSS" in f for f in all_fixes), (
            f"Expected CSS wrapping fix in either layer, got: {all_fixes}"
        )
        # Full-file fixer metadata should be present
        assert "full_file_fixer_changed" in meta
        # The CSS should be present in the output
        assert "#panel" in result

    @pytest.mark.asyncio
    async def test_full_file_fixer_metadata_present(self, tmp_path):
        """Full-file fixer metadata keys are present in exec_meta."""
        executor = _make_executor()
        target = str(tmp_path / "test.py")

        initial = "x = 1\n"
        with open(target, "w") as f:
            f.write(initial)

        _, meta = await executor.execute(
            "file_patch",
            {
                "path": target,
                "operation": "insert_after",
                "anchor": "x = 1",
                "content": "\ny = 2",
            },
        )

        # All four metadata keys should be present
        assert "full_file_fixer_changed" in meta
        assert "full_file_fixer_fixes" in meta
        assert "full_file_fixer_errors" in meta
        assert "full_file_fixer_warnings" in meta

    @pytest.mark.asyncio
    async def test_full_file_fixer_crash_doesnt_block_patch(self, tmp_path):
        """Full-file fixer crash still writes the patched file."""
        executor = _make_executor()
        target = str(tmp_path / "test.html")

        initial = "<html>\n<body>\n<p>Hello</p>\n</body>\n</html>\n"
        with open(target, "w") as f:
            f.write(initial)

        # Track calls to crash only the full-file pass (second call)
        from sentinel.security.code_fixer import fix_code as real_fix
        call_count = 0

        def crash_on_second(path, content):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise RuntimeError("boom")
            return real_fix(path, content)

        with patch(
            "sentinel.tools.executor.code_fixer_fix",
            side_effect=crash_on_second,
        ):
            _, meta = await executor.execute(
                "file_patch",
                {
                    "path": target,
                    "operation": "insert_after",
                    "anchor": "<p>Hello</p>",
                    "content": "\n<p>World</p>",
                },
            )

        with open(target) as f:
            result = f.read()

        # File should still be written despite full-file fixer crash
        assert "<p>World</p>" in result
        assert meta.get("full_file_fixer_changed") is False
