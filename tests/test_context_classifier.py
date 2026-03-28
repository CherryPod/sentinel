"""Tests for sentinel.security.context_classifier module."""

import re

from sentinel.security.context_classifier import (
    CodeBlockInfo,
    ContextRegion,
    build_code_blocks,
    build_indented_ranges,
    classify,
    prepare_text,
)


class TestBuildCodeBlocks:
    def test_extracts_single_block(self):
        text = "before\n```python\ncode here\n```\nafter"
        blocks = build_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].language == "python"
        assert text[blocks[0].content_start:blocks[0].content_end] == "code here\n"

    def test_extracts_multiple_blocks(self):
        text = "```bash\necho hi\n```\n```python\nprint(1)\n```"
        blocks = build_code_blocks(text)
        assert len(blocks) == 2
        assert blocks[0].language == "bash"
        assert blocks[1].language == "python"

    def test_bare_fence_empty_language(self):
        text = "```\nsome text\n```"
        blocks = build_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].language == ""


class TestClassify:
    def _classify_at(self, text, substring):
        """Helper: classify at the position of a substring in text."""
        pos = text.find(substring)
        assert pos != -1, f"'{substring}' not found in text"
        blocks = build_code_blocks(text)
        indented = build_indented_ranges(text)
        return classify(text, pos, blocks, indented)

    def test_python_block_content(self):
        text = "```python\nprint('hello')\n```"
        ctx = self._classify_at(text, "print")
        assert ctx.kind == "fenced_code"
        assert ctx.language == "python"
        assert ctx.is_shell is False

    def test_bash_block_is_shell(self):
        text = "```bash\necho hello\n```"
        ctx = self._classify_at(text, "echo")
        assert ctx.kind == "fenced_code"
        assert ctx.language == "bash"
        assert ctx.is_shell is True

    def test_fence_line_is_fenced(self):
        text = "```python\ncode\n```"
        ctx = self._classify_at(text, "python")
        assert ctx.kind == "fenced_code"
        assert ctx.language == "python"

    def test_cmd_line_prefix(self):
        text = "Some text\n$ cat /etc/passwd\nMore text"
        ctx = self._classify_at(text, "cat")
        assert ctx.kind == "cmd_line"
        assert ctx.is_shell is True

    def test_prose_context(self):
        text = "The /etc/shadow file stores password hashes."
        ctx = self._classify_at(text, "/etc/shadow")
        assert ctx.kind == "prose"
        assert ctx.is_shell is False

    def test_indented_code(self):
        text = "Example:\n    rm -rf /tmp/cache\nEnd."
        ctx = self._classify_at(text, "rm")
        assert ctx.kind == "indented_code"

    def test_shell_prefix_in_nonshell_block(self):
        text = "```python\ncat = 'animal'\n```"
        ctx = self._classify_at(text, "cat")
        assert ctx.kind == "fenced_code"
        assert ctx.language == "python"
        # "cat " matches shell prefix, so is_shell is True even in python block
        assert ctx.is_shell is True

    def test_powershell_block_is_shell(self):
        text = "```powershell\nGet-Process\n```"
        ctx = self._classify_at(text, "Get-Process")
        assert ctx.kind == "fenced_code"
        assert ctx.is_shell is True

    def test_javascript_block_not_shell(self):
        text = "```javascript\nconsole.log('hi')\n```"
        ctx = self._classify_at(text, "console")
        assert ctx.kind == "fenced_code"
        assert ctx.language == "javascript"
        assert ctx.is_shell is False

    def test_block_content_excludes_fence(self):
        text = "```python\nprint(1)\n```"
        ctx = self._classify_at(text, "print")
        assert "```" not in ctx.block_content
        assert "print(1)" in ctx.block_content


class TestPrepareText:
    def test_calls_strip_and_normalise(self):
        called = []

        def fake_strip(t):
            called.append("strip")
            return t

        result = prepare_text("hello", fake_strip)
        assert "strip" in called
        # normalise_homoglyphs should not change plain ASCII
        assert result == "hello"
