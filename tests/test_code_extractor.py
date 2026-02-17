from sentinel.security.code_extractor import (
    CodeBlock,
    extract_code_blocks,
    strip_emoji_from_code_blocks,
)


class TestFencedBlockExtraction:
    def test_single_python_block(self):
        text = 'Here is some code:\n\n```python\nimport os\nos.listdir(".")\n```\n\nThat was it.'
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].language == "python"
        assert "import os" in blocks[0].code

    def test_multiple_blocks(self):
        text = (
            "First block:\n\n```python\nprint('hello')\n```\n\n"
            "Second block:\n\n```javascript\nconsole.log('hi')\n```\n"
        )
        blocks = extract_code_blocks(text)
        assert len(blocks) == 2
        assert blocks[0].language == "python"
        assert blocks[1].language == "javascript"

    def test_no_blocks_fallback(self):
        """No fenced blocks → returns full text as single entry."""
        text = "The use of eval() is dangerous because it executes arbitrary code."
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].code == text
        assert blocks[0].language is None

    def test_empty_block_skipped(self):
        """Empty code blocks are ignored."""
        text = "Empty:\n\n```python\n\n```\n\nReal:\n\n```python\nprint('ok')\n```\n"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert "print" in blocks[0].code

    def test_all_empty_blocks_fallback(self):
        """If all blocks are empty, falls back to full text."""
        text = "All empty:\n\n```python\n\n```\n\n```js\n\n```\n"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].code == text


class TestLanguageTagMapping:
    def test_python_variants(self):
        for tag in ("python", "py", "python3"):
            text = f"```{tag}\nprint('hi')\n```\n"
            blocks = extract_code_blocks(text)
            assert blocks[0].language == "python", f"Failed for tag: {tag}"

    def test_javascript_variants(self):
        for tag in ("javascript", "js"):
            text = f"```{tag}\nconsole.log('hi')\n```\n"
            blocks = extract_code_blocks(text)
            assert blocks[0].language == "javascript", f"Failed for tag: {tag}"

    def test_typescript_maps_to_javascript(self):
        """TypeScript maps to javascript (CodeShield uses JS rules for TS)."""
        for tag in ("typescript", "ts"):
            text = f"```{tag}\nconst x: number = 1;\n```\n"
            blocks = extract_code_blocks(text)
            assert blocks[0].language == "javascript", f"Failed for tag: {tag}"

    def test_rust_variants(self):
        for tag in ("rust", "rs"):
            text = f"```{tag}\nfn main() {{}}\n```\n"
            blocks = extract_code_blocks(text)
            assert blocks[0].language == "rust", f"Failed for tag: {tag}"

    def test_java(self):
        text = "```java\npublic class Main {}\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "java"

    def test_c_and_cpp(self):
        text = "```c\n#include <stdio.h>\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "c"

        text = "```cpp\n#include <iostream>\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "cpp"

    def test_csharp(self):
        for tag in ("csharp", "cs"):
            text = f"```{tag}\nConsole.WriteLine();\n```\n"
            blocks = extract_code_blocks(text)
            assert blocks[0].language == "csharp", f"Failed for tag: {tag}"

    def test_php(self):
        text = "```php\n<?php echo 'hi'; ?>\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "php"

    def test_unknown_tag_no_heuristic(self):
        """Unknown tag (e.g. bash) with no detectable heuristic → None."""
        text = "```bash\necho hello\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language is None

    def test_unknown_tag_with_heuristic(self):
        """Unknown tag but code has Python heuristic markers."""
        text = "```text\nimport os\nos.listdir('.')\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "python"

    def test_no_tag_with_heuristic(self):
        """No language tag → heuristic detection kicks in."""
        text = "```\nimport os\nos.listdir('.')\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "python"


class TestLanguageDetectionHeuristics:
    def test_python_import(self):
        text = "```\nimport json\ndata = json.loads(s)\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "python"

    def test_python_from_import(self):
        text = "```\nfrom os import path\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "python"

    def test_python_def(self):
        text = "```\ndef hello():\n    return 'world'\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "python"

    def test_python_class(self):
        text = "```\nclass MyClass:\n    pass\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "python"

    def test_js_const(self):
        text = "```\nconst x = 42;\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "javascript"

    def test_js_function(self):
        text = "```\nfunction hello() { return 'world'; }\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "javascript"

    def test_js_require(self):
        text = "```\nrequire('fs').readFileSync('file.txt')\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "javascript"

    def test_rust_fn(self):
        text = "```\nfn main() {\n    println!(\"hello\");\n}\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "rust"

    def test_rust_let_mut(self):
        text = "```\nlet mut x = 5;\nx += 1;\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "rust"

    def test_java_public_class(self):
        text = "```\npublic class Main {\n    public static void main(String[] args) {}\n}\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "java"

    def test_c_include(self):
        text = '```\n#include <stdio.h>\nint main() { return 0; }\n```\n'
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "c"

    def test_php_tag(self):
        text = "```\n<?php\necho 'hello';\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language == "php"

    def test_no_heuristic_match(self):
        """Plain text with no language markers → None."""
        text = "```\nhello world\n```\n"
        blocks = extract_code_blocks(text)
        assert blocks[0].language is None

    def test_fallback_text_with_python_markers(self):
        """No fenced blocks but text has Python markers → detected."""
        text = "import os\nos.system('ls')"
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].language == "python"


class TestMixedContent:
    def test_prose_with_eval_and_code_block(self):
        """The key scenario: prose mentioning eval + code block with eval.

        The extractor should return only the code block, not the prose.
        """
        text = (
            "The use of eval() is dangerous because it allows arbitrary code.\n\n"
            "```python\nresult = eval(user_input)\n```\n\n"
            "Never use eval() in production."
        )
        blocks = extract_code_blocks(text)
        assert len(blocks) == 1
        assert blocks[0].language == "python"
        assert "eval(user_input)" in blocks[0].code
        assert "dangerous" not in blocks[0].code

    def test_multiple_languages_in_one_response(self):
        """Response with both Python and JS code blocks."""
        text = (
            "Python version:\n\n```python\nimport os\nos.system('ls')\n```\n\n"
            "JavaScript version:\n\n```javascript\n"
            "const { exec } = require('child_process');\nexec('ls');\n```\n"
        )
        blocks = extract_code_blocks(text)
        assert len(blocks) == 2
        assert blocks[0].language == "python"
        assert blocks[1].language == "javascript"
        assert "child_process" in blocks[1].code


class TestStripEmojiFromCodeBlocks:
    def test_emoji_in_code_comment_stripped(self):
        """The actual Qwen quirk: ✅ in Python code comments."""
        text = "Here's the code:\n\n```python\n# Check passed ✅\nprint('ok')\n```\n"
        result = strip_emoji_from_code_blocks(text)
        assert "\u2705" not in result  # ✅ removed
        assert "print('ok')" in result
        assert "Here's the code:" in result  # prose preserved

    def test_emoji_in_prose_preserved(self):
        """Emoji in prose text (outside code blocks) should be left alone."""
        text = "Great job! ✅ Here's your code:\n\n```python\nprint('ok')\n```\n"
        result = strip_emoji_from_code_blocks(text)
        assert "Great job! \u2705" in result  # prose emoji kept
        assert "print('ok')" in result

    def test_multiple_emoji_types_stripped(self):
        """Various emoji types are all stripped from code."""
        text = "```python\n# Working 🚀 fast ⚡ good ✨\nx = 1\n```\n"
        result = strip_emoji_from_code_blocks(text)
        assert "\U0001F680" not in result  # 🚀
        assert "\u26A1" not in result      # ⚡
        assert "\u2728" not in result      # ✨
        assert "x = 1" in result

    def test_no_code_blocks_unchanged(self):
        """Text without code blocks is returned unchanged."""
        text = "Just prose with emoji ✅ and no code."
        result = strip_emoji_from_code_blocks(text)
        assert result == text

    def test_ascii_code_unchanged(self):
        """Code blocks without emoji are not modified."""
        text = "```python\ndef hello():\n    return 'world'\n```\n"
        result = strip_emoji_from_code_blocks(text)
        assert "def hello():" in result
        assert "return 'world'" in result

    def test_language_tag_preserved(self):
        """Language tag on the code block is preserved."""
        text = "```python\n# Done ✅\nprint('ok')\n```\n"
        result = strip_emoji_from_code_blocks(text)
        assert "```python\n" in result

    def test_multiple_code_blocks(self):
        """Emoji stripped from all code blocks independently."""
        text = (
            "```python\n# Step 1 ✅\nx = 1\n```\n\n"
            "```javascript\n// Step 2 🎉\nlet y = 2;\n```\n"
        )
        result = strip_emoji_from_code_blocks(text)
        assert "\u2705" not in result
        assert "\U0001F389" not in result
        assert "x = 1" in result
        assert "let y = 2;" in result
