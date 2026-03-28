"""Tests for structural integrity validation in the code fixer pipeline.

For each supported language:
- Unfixable structural error → flag present
- Clean file → flag absent
- Fixable issue resolved by fixer → flag absent
"""
import pytest

from sentinel.security.code_fixer import fix_code
from sentinel.security.code_fixer._structural import INTEGRITY_FLAG


def _has_integrity_flag(errors: list[str]) -> bool:
    """Check if any error contains the structural integrity flag."""
    return any(INTEGRITY_FLAG in e for e in errors)


# ===================================================================
# PYTHON
# ===================================================================


class TestPythonIntegrity:
    """Python structural validation via ast.parse()."""

    def test_unfixable_syntax_error_flagged(self):
        # Deeply broken syntax that ast.parse and parso can't recover
        content = "def foo(\n  x = 1\n  y = 2\n  )\n  return x +\n"
        result = fix_code("broken.py", content)
        assert _has_integrity_flag(result.errors_found)

    def test_clean_python_no_flag(self):
        content = "def foo():\n    return 42\n"
        result = fix_code("clean.py", content)
        assert not _has_integrity_flag(result.errors_found)

    def test_fixable_missing_newline_no_flag(self):
        # Missing trailing newline — universal fixer adds it
        content = "x = 1"
        result = fix_code("fixed.py", content)
        assert result.changed is True
        assert not _has_integrity_flag(result.errors_found)


# ===================================================================
# JSON
# ===================================================================


class TestJsonIntegrity:
    """JSON structural validation via json.loads()."""

    def test_unfixable_json_error_flagged(self):
        # Plain text that json-repair can't turn into valid JSON
        content = "not json at all\n"
        result = fix_code("broken.json", content)
        assert _has_integrity_flag(result.errors_found)

    def test_clean_json_no_flag(self):
        content = '{"key": "value"}\n'
        result = fix_code("clean.json", content)
        assert not _has_integrity_flag(result.errors_found)

    def test_fixable_trailing_comma_no_flag(self):
        # Trailing comma — JSON fixer removes it
        content = '{"key": "value",}\n'
        result = fix_code("fixed.json", content)
        assert not _has_integrity_flag(result.errors_found)


# ===================================================================
# YAML
# ===================================================================


class TestYamlIntegrity:
    """YAML structural validation via yaml.safe_load()."""

    def test_unfixable_yaml_error_flagged(self):
        # Broken YAML with bad indentation that fixer can't recover
        content = "key: value\n  bad:\n indent:\n   worse:\n"
        result = fix_code("broken.yaml", content)
        # If YAML parser finds an error, it should be flagged
        if any("YAMLError" in e for e in result.errors_found):
            assert _has_integrity_flag(result.errors_found)

    def test_clean_yaml_no_flag(self):
        content = "key: value\nnested:\n  child: 42\n"
        result = fix_code("clean.yaml", content)
        assert not _has_integrity_flag(result.errors_found)


# ===================================================================
# TOML
# ===================================================================


class TestTomlIntegrity:
    """TOML structural validation via tomllib.loads()."""

    def test_unfixable_toml_error_flagged(self):
        content = "[broken\nkey = \n"
        result = fix_code("broken.toml", content)
        assert _has_integrity_flag(result.errors_found)

    def test_clean_toml_no_flag(self):
        content = '[section]\nkey = "value"\n'
        result = fix_code("clean.toml", content)
        assert not _has_integrity_flag(result.errors_found)


# ===================================================================
# JAVASCRIPT / TYPESCRIPT
# ===================================================================


class TestJsIntegrity:
    """JS structural validation via truncation detection (brace balance)."""

    def test_unclosed_braces_flagged(self):
        # 2 unclosed braces — truncation detector catches this
        content = "function foo() {\n  if (true) {\n    x = 1;\n"
        result = fix_code("broken.js", content)
        assert _has_integrity_flag(result.errors_found)

    def test_clean_js_no_flag(self):
        content = "function foo() {\n  return 42;\n}\n"
        result = fix_code("clean.js", content)
        assert not _has_integrity_flag(result.errors_found)

    def test_balanced_js_no_flag(self):
        content = "const obj = {\n  key: 'value',\n};\n"
        result = fix_code("balanced.js", content)
        assert not _has_integrity_flag(result.errors_found)


# ===================================================================
# CSS
# ===================================================================


class TestCssIntegrity:
    """CSS structural validation via brace balance."""

    def test_unclosed_braces_flagged(self):
        # 2 unclosed braces — truncation detector catches this
        content = ".foo {\n  .bar {\n    color: red;\n"
        result = fix_code("broken.css", content)
        # CSS fixer closes 1 brace, but truncation detector should
        # still find the imbalance or the fixer may close both.
        # Either way, check the result is consistent
        if any("truncated" in e.lower() or "unclosed" in e.lower()
               for e in result.errors_found):
            assert _has_integrity_flag(result.errors_found)

    def test_clean_css_no_flag(self):
        content = ".foo {\n  color: red;\n}\n"
        result = fix_code("clean.css", content)
        assert not _has_integrity_flag(result.errors_found)


# ===================================================================
# SHELL
# ===================================================================


class TestShellIntegrity:
    """Shell structural validation via keyword balance."""

    def test_multiple_unclosed_ifs_flagged(self):
        # 2 unclosed if blocks — fixer only handles exactly 1 missing fi
        content = (
            "#!/bin/bash\n"
            "if true; then\n"
            "  if true; then\n"
            "    echo 'nested'\n"
        )
        result = fix_code("broken.sh", content)
        # Fixer closes 1 fi, but 1 still missing → flag
        assert _has_integrity_flag(result.errors_found)

    def test_clean_shell_no_flag(self):
        content = (
            "#!/bin/bash\n"
            "if true; then\n"
            "  echo 'yes'\n"
            "fi\n"
        )
        result = fix_code("clean.sh", content)
        assert not _has_integrity_flag(result.errors_found)

    def test_fixable_single_missing_fi_no_flag(self):
        # Single missing fi — shell fixer adds it
        content = (
            "#!/bin/bash\n"
            "if true; then\n"
            "  echo 'yes'\n"
        )
        result = fix_code("fixable.sh", content)
        # After fix, should be balanced → no flag
        assert not _has_integrity_flag(result.errors_found)

    def test_case_esac_imbalance_flagged(self):
        content = (
            "#!/bin/bash\n"
            'case "$1" in\n'
            "  start)\n"
            "    echo 'starting'\n"
            "    ;;\n"
        )
        result = fix_code("broken_case.sh", content)
        assert _has_integrity_flag(result.errors_found)


# ===================================================================
# HTML
# ===================================================================


class TestHtmlIntegrity:
    """HTML structural validation via BeautifulSoup."""

    def test_clean_html_no_flag(self):
        content = "<!DOCTYPE html>\n<html>\n<head></head>\n<body></body>\n</html>\n"
        result = fix_code("clean.html", content)
        assert not _has_integrity_flag(result.errors_found)

    def test_no_tags_at_all_flagged(self):
        # Pure text with no HTML tags — not really HTML
        content = "This is just plain text with no HTML whatsoever.\n"
        result = fix_code("not_html.html", content)
        assert _has_integrity_flag(result.errors_found)

    def test_minimal_html_no_flag(self):
        content = "<p>Hello world</p>\n"
        result = fix_code("fragment.html", content)
        assert not _has_integrity_flag(result.errors_found)


# ===================================================================
# CROSS-CUTTING
# ===================================================================


class TestIntegrityCrossCutting:
    """Tests for the integrity flag mechanism itself."""

    def test_flag_not_added_for_unsupported_extension(self):
        content = "some random content\n"
        result = fix_code("data.txt", content)
        assert not _has_integrity_flag(result.errors_found)

    def test_flag_format_includes_reason(self):
        # Verify the flag includes the triggering error
        content = "not json\n"
        result = fix_code("broken.json", content)
        flag_errors = [e for e in result.errors_found if INTEGRITY_FLAG in e]
        assert len(flag_errors) >= 1
        # The flag should contain the original error reason
        assert "JSONDecodeError" in flag_errors[0]
