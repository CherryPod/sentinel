"""Tests for sentinel/security/quality_gate.py — R7 post-generation quality gate."""

from sentinel.core.config import OLLAMA_NUM_PREDICT
from sentinel.security.code_extractor import CodeBlock
from sentinel.security.quality_gate import (
    _TOKEN_CAP_THRESHOLD,
    _check_python_syntax,
    _check_truncation,
    _is_likely_python,
    check_code_quality,
)


class TestCheckPythonSyntax:
    """Unit tests for _check_python_syntax() — the dedent-then-raw strategy."""

    def test_valid_simple(self):
        valid, msg = _check_python_syntax("x = 1\nprint(x)\n")
        assert valid is True
        assert msg == ""

    def test_valid_function(self):
        valid, _ = _check_python_syntax("def foo(x):\n    return x + 1\n")
        assert valid is True

    def test_valid_class(self):
        code = "class Foo:\n    def bar(self):\n        return self.x\n"
        valid, _ = _check_python_syntax(code)
        assert valid is True

    def test_valid_dedent_fixes_indentation(self):
        # Method body snippet with consistent leading indent — dedent fixes it
        code = "    def foo(self):\n        return self.x\n"
        valid, _ = _check_python_syntax(code)
        assert valid is True

    def test_syntax_error_unterminated_string(self):
        # Token-cap dominant failure: Qwen cuts off mid-docstring
        code = 'def foo():\n    """This docstring was cut off by the token cap\n'
        valid, msg = _check_python_syntax(code)
        assert valid is False
        assert "Line" in msg

    def test_syntax_error_missing_colon(self):
        code = "def foo()\n    return 1\n"
        valid, msg = _check_python_syntax(code)
        assert valid is False
        assert "Line 1" in msg

    def test_syntax_error_unclosed_bracket(self):
        code = "result = func(\n    arg1,\n    arg2\n"
        valid, msg = _check_python_syntax(code)
        assert valid is False

    def test_empty_string_is_valid(self):
        # ast.parse("") succeeds — empty module is valid Python
        valid, _ = _check_python_syntax("")
        assert valid is True

    def test_multiline_valid(self):
        code = (
            "import os\n\nclass Foo:\n    def bar(self):\n"
            "        return os.path.join('a', 'b')\n"
        )
        valid, _ = _check_python_syntax(code)
        assert valid is True


class TestIsLikelyPython:
    """Unit tests for _is_likely_python() — heuristic for untagged blocks.

    Note: _is_likely_python is only called when code_extractor._detect_language()
    returned None — meaning no import/from/def/class at line start.  Tests use
    inputs that realistically reach this function (no bare import/def/class).
    """

    def test_two_markers_try_except(self):
        # try: + except — 2 markers, clearly Python
        code = "try:\n    x = int(s)\nexcept ValueError:\n    x = 0\n"
        assert _is_likely_python(code) is True

    def test_two_markers_self_and_print(self):
        # self. + print( — 2 markers
        code = "self.value = 42\nprint(self.value)\n"
        assert _is_likely_python(code) is True

    def test_two_markers_raise_and_elif(self):
        # raise + elif — 2 markers
        code = "if x > 0:\n    pass\nelif x < 0:\n    raise ValueError('negative')\n"
        assert _is_likely_python(code) is True

    def test_single_marker_below_threshold(self):
        # Only 1 marker (self.), 0 colon lines — not enough evidence
        code = "self.value = 42\nself.update()\n"
        assert _is_likely_python(code) is False

    def test_single_marker_with_colon_lines(self):
        # 1 marker (raise) + 2 colon-terminated lines — qualifies
        code = "if condition:\n    for x in items:\n        raise StopIteration\n"
        assert _is_likely_python(code) is True

    def test_rust_excluded(self):
        code = "fn main() {\n    let x = 5;\n    println!(\"{}\", x);\n}\n"
        assert _is_likely_python(code) is False

    def test_c_excluded(self):
        code = '#include <stdio.h>\nint main() {\n    printf("hello");\n    return 0;\n}\n'
        assert _is_likely_python(code) is False

    def test_cpp_excluded(self):
        code = '#include <iostream>\nvoid foo() {\n    std::cout << "hi";\n}\n'
        assert _is_likely_python(code) is False

    def test_rust_negative_overrides_positive(self):
        # Has "self." (positive) but "impl " (negative) → not Python
        code = "impl Foo {\n    pub fn bar(&self) -> i32 {\n        self.x\n    }\n}\n"
        assert _is_likely_python(code) is False

    def test_empty_string_is_false(self):
        assert _is_likely_python("") is False

    def test_plain_prose_not_python(self):
        assert _is_likely_python("This is a plain English sentence.") is False

    def test_await_and_self(self):
        # await + self. — 2 markers, async Python code
        code = "result = await self.fetch_data()\nself.process(result)\n"
        assert _is_likely_python(code) is True

    def test_lambda_and_print(self):
        # lambda + print( — 2 markers
        code = "transform = lambda x: x * 2\nprint(transform(5))\n"
        assert _is_likely_python(code) is True


class TestCheckTruncation:
    """Unit tests for _check_truncation() — token cap detection."""

    def test_none_usage_returns_none(self):
        assert _check_truncation(None) is None

    def test_below_threshold_no_warning(self):
        # 7500 / 8192 ≈ 0.916 — below 0.95
        assert _check_truncation({"eval_count": 7500}) is None

    def test_at_threshold_warns(self):
        count = int(OLLAMA_NUM_PREDICT * _TOKEN_CAP_THRESHOLD) + 1
        result = _check_truncation({"eval_count": count})
        assert result is not None
        assert "truncated" in result.lower()
        assert str(count) in result

    def test_at_cap_warns(self):
        result = _check_truncation({"eval_count": 8192})
        assert result is not None
        assert "8192" in result

    def test_missing_eval_count_key_returns_none(self):
        assert _check_truncation({"prompt_eval_count": 500}) is None

    def test_zero_eval_count_returns_none(self):
        assert _check_truncation({"eval_count": 0}) is None

    def test_non_int_eval_count_returns_none(self):
        assert _check_truncation({"eval_count": "8192"}) is None

    def test_warning_contains_ratio(self):
        result = _check_truncation({"eval_count": 8192})
        assert "100.0%" in result


class TestCheckCodeQuality:
    """Integration tests for check_code_quality() — the public API."""

    def test_empty_blocks_no_warnings(self):
        assert check_code_quality([]) == []

    def test_valid_python_block_no_warnings(self):
        blocks = [CodeBlock(code="def foo():\n    return 1\n", language="python")]
        assert check_code_quality(blocks) == []

    def test_syntax_error_in_python_block(self):
        code = 'def foo():\n    """unterminated\n'
        blocks = [CodeBlock(code=code, language="python")]
        warnings = check_code_quality(blocks)
        assert len(warnings) == 1
        assert "syntax error" in warnings[0].lower()

    def test_non_python_block_skipped(self):
        blocks = [CodeBlock(code="fn main() {}\n", language="rust")]
        assert check_code_quality(blocks) == []

    def test_untagged_python_block_checked(self):
        # language=None but looks like Python — should be syntax checked
        code = 'import os\ndef foo():\n    """unterminated\n'
        blocks = [CodeBlock(code=code, language=None)]
        warnings = check_code_quality(blocks)
        assert any("syntax error" in w.lower() for w in warnings)

    def test_untagged_non_python_not_checked(self):
        # language=None and looks like Rust — should not be syntax checked
        code = "fn main() {\n    let x = 5;\n    println!(\"{}\", x);\n}\n"
        blocks = [CodeBlock(code=code, language=None)]
        assert check_code_quality(blocks) == []

    def test_truncation_warning_included(self):
        blocks = [CodeBlock(code="x = 1\n", language="python")]
        warnings = check_code_quality(blocks, worker_usage={"eval_count": 8192})
        assert any("truncated" in w.lower() for w in warnings)

    def test_no_usage_no_truncation_warning(self):
        blocks = [CodeBlock(code="x = 1\n", language="python")]
        warnings = check_code_quality(blocks, worker_usage=None)
        assert not any("truncated" in w.lower() for w in warnings)

    def test_multiple_blocks_multiple_warnings(self):
        bad_code = 'def foo():\n    """cut off\n'
        blocks = [
            CodeBlock(code=bad_code, language="python"),
            CodeBlock(code=bad_code, language="python"),
        ]
        warnings = check_code_quality(blocks)
        # 2 syntax errors (one per block)
        assert len(warnings) == 2

    def test_truncation_plus_syntax_error(self):
        # Both failure modes at once — the dominant real-world case
        bad_code = 'def foo():\n    """cut off\n'
        blocks = [CodeBlock(code=bad_code, language="python")]
        warnings = check_code_quality(blocks, worker_usage={"eval_count": 8192})
        assert len(warnings) == 2  # truncation + syntax error
        assert any("truncated" in w.lower() for w in warnings)
        assert any("syntax error" in w.lower() for w in warnings)

    def test_warning_includes_block_number(self):
        code = 'def foo():\n    """unterminated\n'
        blocks = [
            CodeBlock(code="x = 1\n", language="python"),
            CodeBlock(code=code, language="python"),
        ]
        warnings = check_code_quality(blocks)
        assert len(warnings) == 1
        assert "block 2" in warnings[0]  # 1-indexed

    def test_warning_includes_snippet(self):
        code = 'long_variable_name = some_function_call(\n    arg1,\n'
        blocks = [CodeBlock(code=code, language="python")]
        warnings = check_code_quality(blocks)
        assert len(warnings) == 1
        assert "long_variable_name" in warnings[0]

    def test_javascript_block_not_syntax_checked(self):
        # JS with syntax that would fail ast.parse — should be skipped
        blocks = [CodeBlock(code="const x = () => { return 1; };", language="javascript")]
        assert check_code_quality(blocks) == []

    def test_valid_python_no_warnings_with_normal_usage(self):
        blocks = [CodeBlock(code="x = 1\nprint(x)\n", language="python")]
        warnings = check_code_quality(blocks, worker_usage={"eval_count": 500})
        assert warnings == []
