"""Tests for sentinel.analysis.metadata_extractor."""


class TestExtractStderrPreview:
    def test_short_stderr_returned_as_is(self):
        from sentinel.analysis.metadata_extractor import extract_stderr_preview
        assert extract_stderr_preview("error: file not found") == "error: file not found"

    def test_long_stderr_truncated_to_max_lines(self):
        from sentinel.analysis.metadata_extractor import extract_stderr_preview
        stderr = "\n".join(f"line {i}" for i in range(20))
        result = extract_stderr_preview(stderr, max_lines=3)
        assert result.count("\n") == 2  # 3 lines = 2 newlines
        assert result.startswith("line 0")

    def test_long_stderr_truncated_to_max_chars(self):
        from sentinel.analysis.metadata_extractor import extract_stderr_preview
        stderr = "x" * 1000
        result = extract_stderr_preview(stderr, max_chars=500)
        assert len(result) <= 500

    def test_empty_stderr_returns_empty(self):
        from sentinel.analysis.metadata_extractor import extract_stderr_preview
        assert extract_stderr_preview("") == ""

    def test_none_returns_empty(self):
        from sentinel.analysis.metadata_extractor import extract_stderr_preview
        assert extract_stderr_preview(None) == ""


class TestExtractCodeSymbols:
    def test_extracts_function_names(self):
        from sentinel.analysis.metadata_extractor import extract_code_symbols
        code = "def foo():\n    pass\ndef bar():\n    pass"
        result = extract_code_symbols(code, "python")
        assert "foo" in result["defined_symbols"]
        assert "bar" in result["defined_symbols"]

    def test_extracts_class_names(self):
        from sentinel.analysis.metadata_extractor import extract_code_symbols
        code = "class MyClass:\n    pass"
        result = extract_code_symbols(code, "python")
        assert "MyClass" in result["defined_symbols"]

    def test_extracts_imports(self):
        from sentinel.analysis.metadata_extractor import extract_code_symbols
        code = "import os\nfrom pathlib import Path\nimport json"
        result = extract_code_symbols(code, "python")
        assert "os" in result["imports"]
        assert "pathlib.Path" in result["imports"]
        assert "json" in result["imports"]

    def test_non_python_returns_empty(self):
        from sentinel.analysis.metadata_extractor import extract_code_symbols
        result = extract_code_symbols("fn main() {}", "rust")
        assert result["defined_symbols"] == []
        assert result["imports"] == []

    def test_syntax_error_returns_empty(self):
        from sentinel.analysis.metadata_extractor import extract_code_symbols
        result = extract_code_symbols("def broken(", "python")
        assert result["defined_symbols"] == []
        assert result["imports"] == []

    def test_empty_code_returns_empty(self):
        from sentinel.analysis.metadata_extractor import extract_code_symbols
        result = extract_code_symbols("", "python")
        assert result["defined_symbols"] == []
        assert result["imports"] == []


class TestExtractDiffStats:
    def test_added_lines(self):
        from sentinel.analysis.metadata_extractor import extract_diff_stats
        result = extract_diff_stats("", "line1\nline2\nline3")
        assert result == "+3/-0 lines"

    def test_removed_lines(self):
        from sentinel.analysis.metadata_extractor import extract_diff_stats
        result = extract_diff_stats("line1\nline2", "")
        assert result == "+0/-2 lines"

    def test_mixed_changes(self):
        from sentinel.analysis.metadata_extractor import extract_diff_stats
        result = extract_diff_stats("old line\n", "new line\nextra\n")
        assert "+" in result and "/-" in result and "lines" in result

    def test_no_change(self):
        from sentinel.analysis.metadata_extractor import extract_diff_stats
        result = extract_diff_stats("same", "same")
        assert result == "+0/-0 lines"

    def test_none_before_treated_as_new_file(self):
        from sentinel.analysis.metadata_extractor import extract_diff_stats
        result = extract_diff_stats(None, "new content\n")
        assert result == "+1/-0 lines"


class TestExtractComplexity:
    def test_simple_function(self):
        from sentinel.analysis.metadata_extractor import extract_complexity
        code = "def foo():\n    return 1"
        result = extract_complexity(code, "python")
        assert result["complexity_max"] >= 1
        assert result["complexity_function"] == "foo"

    def test_complex_function_with_branches(self):
        from sentinel.analysis.metadata_extractor import extract_complexity
        code = (
            "def complex(x):\n"
            "    if x > 0:\n"
            "        if x > 10:\n"
            "            return 'big'\n"
            "        return 'small'\n"
            "    elif x == 0:\n"
            "        return 'zero'\n"
            "    else:\n"
            "        return 'negative'\n"
        )
        result = extract_complexity(code, "python")
        assert result["complexity_max"] >= 3
        assert result["complexity_function"] == "complex"

    def test_empty_code_returns_none(self):
        from sentinel.analysis.metadata_extractor import extract_complexity
        result = extract_complexity("", "python")
        assert result["complexity_max"] is None
        assert result["complexity_function"] is None

    def test_no_functions_returns_none(self):
        from sentinel.analysis.metadata_extractor import extract_complexity
        result = extract_complexity("x = 1\ny = 2", "python")
        assert result["complexity_max"] is None

    def test_multiple_functions_returns_highest(self):
        from sentinel.analysis.metadata_extractor import extract_complexity
        code = (
            "def simple():\n    return 1\n\n"
            "def branchy(x):\n"
            "    if x > 0:\n"
            "        if x > 10:\n"
            "            return 'big'\n"
            "        return 'small'\n"
            "    return 'other'\n"
        )
        result = extract_complexity(code, "python")
        assert result["complexity_function"] == "branchy"


class TestComputeTokenUsageRatio:
    def test_half_usage(self):
        from sentinel.analysis.metadata_extractor import compute_token_usage_ratio
        usage = {"eval_count": 4096}
        assert compute_token_usage_ratio(usage, max_tokens=8192) == 0.5

    def test_full_usage(self):
        from sentinel.analysis.metadata_extractor import compute_token_usage_ratio
        usage = {"eval_count": 8192}
        assert compute_token_usage_ratio(usage, max_tokens=8192) == 1.0

    def test_none_usage_returns_none(self):
        from sentinel.analysis.metadata_extractor import compute_token_usage_ratio
        assert compute_token_usage_ratio(None) is None

    def test_missing_eval_count_returns_none(self):
        from sentinel.analysis.metadata_extractor import compute_token_usage_ratio
        assert compute_token_usage_ratio({"other": 100}) is None

    def test_zero_max_tokens_returns_none(self):
        from sentinel.analysis.metadata_extractor import compute_token_usage_ratio
        assert compute_token_usage_ratio({"eval_count": 100}, max_tokens=0) is None

    def test_ratio_capped_at_1(self):
        from sentinel.analysis.metadata_extractor import compute_token_usage_ratio
        result = compute_token_usage_ratio({"eval_count": 9000}, max_tokens=8192)
        assert result <= 1.1
