"""Unit tests for cross-language content detection and repair.

Tests the _cross_language module which detects:
- CSS <style> wrappers on .css files
- JS <script> wrappers on .js/.ts files
- CSS/JS outside container tags in HTML/SVG files
"""
import pytest
from unittest.mock import patch

from sentinel.security.code_fixer._cross_language import (
    fix_cross_language,
    _fix_css_wrapper_tags,
    _fix_js_wrapper_tags,
    _fix_html_misplaced_content,
    _is_css_line,
    _is_js_line,
)
from sentinel.security.code_fixer._core import _current_filename


@pytest.fixture(autouse=True)
def _set_filename():
    """Set a default filename for tests that use _current_filename."""
    token = _current_filename.set("test.css")
    yield
    _current_filename.reset(token)


# ===================================================================
# CSS WRAPPER STRIPPING
# ===================================================================


class TestCssWrapperStripping:
    """CSS files wrapped in <style> tags should have wrappers removed."""

    def test_style_wrapper_stripped(self):
        content = "<style>\n.foo { color: red; }\n</style>\n"
        result = _fix_css_wrapper_tags(content)
        assert "<style>" not in result.content
        assert "</style>" not in result.content
        assert ".foo { color: red; }" in result.content
        assert result.changed is True
        assert any("Stripped" in f for f in result.fixes_applied)

    def test_style_wrapper_with_attributes_stripped(self):
        content = '<style type="text/css">\n.foo { color: red; }\n</style>\n'
        result = _fix_css_wrapper_tags(content)
        assert "<style" not in result.content
        assert ".foo { color: red; }" in result.content
        assert result.changed is True

    def test_no_wrapper_unchanged(self):
        content = ".foo { color: red; }\n"
        result = _fix_css_wrapper_tags(content)
        assert result.content == content
        assert result.changed is False

    def test_partial_wrapper_warns(self):
        content = "<style>\n.foo { color: red; }\n"
        result = _fix_css_wrapper_tags(content)
        assert any("no </style>" in w for w in result.warnings)
        assert result.changed is False

    def test_trailing_newline_preserved(self):
        content = "<style>\nbody { margin: 0; }\n</style>\n"
        result = _fix_css_wrapper_tags(content)
        assert result.content.endswith("\n")

    def test_multiline_css_preserved(self):
        content = (
            "<style>\n"
            ".foo { color: red; }\n"
            ".bar { margin: 10px; }\n"
            "#baz { padding: 5px; }\n"
            "</style>\n"
        )
        result = _fix_css_wrapper_tags(content)
        assert result.changed is True
        assert ".foo { color: red; }" in result.content
        assert ".bar { margin: 10px; }" in result.content
        assert "#baz { padding: 5px; }" in result.content

    def test_dispatched_via_fix_cross_language(self):
        """fix_cross_language routes .css files to CSS wrapper stripping."""
        token = _current_filename.set("dashboard.css")
        try:
            content = "<style>\n.foo { color: red; }\n</style>\n"
            result = fix_cross_language(content)
            assert result.changed is True
            assert "<style>" not in result.content
        finally:
            _current_filename.reset(token)


# ===================================================================
# JS WRAPPER STRIPPING
# ===================================================================


class TestJsWrapperStripping:
    """JS/TS files wrapped in <script> tags should have wrappers removed."""

    @pytest.fixture(autouse=True)
    def _set_js_filename(self):
        token = _current_filename.set("app.js")
        yield
        _current_filename.reset(token)

    def test_script_wrapper_stripped(self):
        content = "<script>\nconst x = 1;\nconsole.log(x);\n</script>\n"
        result = _fix_js_wrapper_tags(content)
        assert "<script>" not in result.content
        assert "</script>" not in result.content
        assert "const x = 1;" in result.content
        assert result.changed is True
        assert any("Stripped" in f for f in result.fixes_applied)

    def test_script_wrapper_with_attributes_stripped(self):
        content = '<script type="text/javascript">\nconst x = 1;\n</script>\n'
        result = _fix_js_wrapper_tags(content)
        assert "<script" not in result.content
        assert "const x = 1;" in result.content
        assert result.changed is True

    def test_no_wrapper_unchanged(self):
        content = "const x = 1;\n"
        result = _fix_js_wrapper_tags(content)
        assert result.content == content
        assert result.changed is False

    def test_partial_wrapper_warns(self):
        content = "<script>\nconst x = 1;\n"
        result = _fix_js_wrapper_tags(content)
        assert any("no </script>" in w for w in result.warnings)
        assert result.changed is False

    def test_typescript_dispatched(self):
        """fix_cross_language routes .ts files to JS wrapper stripping."""
        token = _current_filename.set("utils.ts")
        try:
            content = "<script>\nconst x: number = 1;\n</script>\n"
            result = fix_cross_language(content)
            assert result.changed is True
            assert "<script>" not in result.content
        finally:
            _current_filename.reset(token)

    def test_jsx_dispatched(self):
        """fix_cross_language routes .jsx files to JS wrapper stripping."""
        token = _current_filename.set("App.jsx")
        try:
            content = "<script>\nconst App = () => {};\n</script>\n"
            result = fix_cross_language(content)
            assert result.changed is True
        finally:
            _current_filename.reset(token)


# ===================================================================
# LINE CLASSIFIERS
# ===================================================================


class TestLineClassifiers:
    """Unit tests for _is_css_line and _is_js_line helpers."""

    def test_css_selector_with_brace(self):
        assert _is_css_line("#panel {") is True
        assert _is_css_line(".widget {") is True
        assert _is_css_line("body {") is True

    def test_css_property(self):
        assert _is_css_line("  color: red;") is True
        assert _is_css_line("  margin: 10px;") is True
        assert _is_css_line("  background-color: #fff;") is True

    def test_css_at_rule(self):
        assert _is_css_line("@media (max-width: 768px) {") is True
        assert _is_css_line("@keyframes fade {") is True
        assert _is_css_line("@import url('fonts.css');") is True

    def test_not_css(self):
        assert _is_css_line("<div>hello</div>") is False
        assert _is_css_line("") is False
        assert _is_css_line("Hello world") is False
        assert _is_css_line("// comment") is False

    def test_js_declaration(self):
        assert _is_js_line("function init() {") is True
        assert _is_js_line("const x = 1;") is True
        assert _is_js_line("let y = 2;") is True
        assert _is_js_line("var z = 3;") is True

    def test_js_async_function(self):
        assert _is_js_line("async function fetchData() {") is True

    def test_js_class(self):
        assert _is_js_line("class MyWidget {") is True
        assert _is_js_line("export class MyWidget {") is True

    def test_js_dom_access(self):
        assert _is_js_line("  document.getElementById('app');") is True
        assert _is_js_line("  window.addEventListener('load', fn);") is True
        assert _is_js_line("  document.querySelector('.panel');") is True

    def test_js_listener(self):
        assert _is_js_line("  btn.addEventListener('click', handler);") is True

    def test_not_js(self):
        assert _is_js_line("<p>text</p>") is False
        assert _is_js_line("") is False
        assert _is_js_line("Some text content") is False


# ===================================================================
# HTML MISPLACED CONTENT DETECTION
# ===================================================================


class TestHtmlMisplacedContent:
    """CSS/JS outside container tags in HTML should be detected and wrapped."""

    @pytest.fixture(autouse=True)
    def _set_html_filename(self):
        token = _current_filename.set("dashboard.html")
        yield
        _current_filename.reset(token)

    def test_css_outside_style_wrapped(self):
        content = (
            "<html>\n<head>\n"
            "<style>\nbody { margin: 0; }\n</style>\n"
            "#panel { color: red; }\n.widget { padding: 5px; }\n"
            "</head>\n<body></body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is True
        assert any("CSS" in f for f in result.fixes_applied)
        # The CSS lines should now be inside <style> tags
        idx_style_open = result.content.rfind("<style>")
        idx_panel = result.content.index("#panel")
        idx_style_close = result.content.find("</style>", idx_panel)
        assert idx_style_open < idx_panel < idx_style_close

    def test_css_inside_style_unchanged(self):
        content = (
            "<html>\n<head>\n"
            "<style>\n#panel { color: red; }\n.widget { padding: 5px; }\n</style>\n"
            "</head>\n<body></body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is False

    def test_js_outside_script_wrapped(self):
        content = (
            "<html>\n<body>\n"
            "<script>\nalert('hi');\n</script>\n"
            "function init() {\n  document.getElementById('app');\n}\n"
            "</body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is True
        assert any("JS" in f for f in result.fixes_applied)

    def test_js_inside_script_unchanged(self):
        content = (
            "<html>\n<body>\n"
            "<script>\nfunction init() {\n"
            "  document.getElementById('app');\n}\n</script>\n"
            "</body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is False

    def test_template_file_skipped(self):
        content = (
            "<html>\n<head>\n{{ if .Styles }}\n"
            "#panel { color: red; }\n.widget { padding: 5px; }\n"
            "{{ end }}\n</head>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is False

    def test_jinja_template_skipped(self):
        content = (
            "<html>\n<head>\n{% block styles %}\n"
            "#panel { color: red; }\n.widget { padding: 5px; }\n"
            "{% endblock %}\n</head>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is False

    def test_single_css_line_not_wrapped(self):
        """Single CSS-like line should not trigger wrapping (FP protection)."""
        content = (
            "<html>\n<head>\n"
            "color: red;\n"
            "</head>\n<body></body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is False

    def test_svg_css_outside_style_detected(self):
        """SVG files get the same HTML treatment."""
        token = _current_filename.set("icon.svg")
        try:
            content = (
                '<svg xmlns="http://www.w3.org/2000/svg">\n'
                ".cls-1 { fill: red; }\n.cls-2 { stroke: blue; }\n"
                '<circle r="10"/>\n</svg>\n'
            )
            result = fix_cross_language(content)
            assert result.changed is True
            assert any("CSS" in f for f in result.fixes_applied)
        finally:
            _current_filename.reset(token)

    def test_pre_content_not_flagged(self):
        """Content inside <pre> should not be flagged."""
        content = (
            "<html>\n<body>\n"
            "<pre>\n#panel { color: red; }\n.widget { padding: 5px; }\n</pre>\n"
            "</body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is False

    def test_code_content_not_flagged(self):
        """Content inside <code> should not be flagged."""
        content = (
            "<html>\n<body>\n"
            "<code>\nfunction init() {\n"
            "  document.getElementById('app');\n}\n</code>\n"
            "</body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is False

    def test_multiple_misplaced_blocks(self):
        """Multiple misplaced blocks should each be wrapped separately."""
        content = (
            "<html>\n<head>\n"
            "#panel { color: red; }\n.widget { padding: 5px; }\n"
            "</head>\n<body>\n"
            "function init() {\n  document.getElementById('app');\n}\n"
            "</body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is True
        # Both CSS and JS should be wrapped
        css_fixes = [f for f in result.fixes_applied if "CSS" in f]
        js_fixes = [f for f in result.fixes_applied if "JS" in f]
        assert len(css_fixes) >= 1
        assert len(js_fixes) >= 1

    def test_unsupported_extension_returns_unchanged(self):
        """Python files should not trigger any cross-language checks."""
        token = _current_filename.set("test.py")
        try:
            content = "print('hello')\n"
            result = fix_cross_language(content)
            assert result.changed is False
            assert result.content == content
        finally:
            _current_filename.reset(token)

    def test_stormwatch_case_study(self):
        """Reproduces the StormWatch dashboard incident from the design doc.

        CSS was dumped into <head> outside <style> after a patch, causing
        anchor corruption in subsequent patches.
        """
        content = (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            "<style>\n"
            "body { margin: 0; font-family: sans-serif; }\n"
            ".dashboard { display: grid; }\n"
            "</style>\n"
            "#weather-panel {\n"
            "  background: linear-gradient(135deg, #1a1a2e, #16213e);\n"
            "  border-radius: 12px;\n"
            "}\n"
            ".forecast-item {\n"
            "  padding: 8px;\n"
            "  border-bottom: 1px solid rgba(255,255,255,0.1);\n"
            "}\n"
            "</head>\n<body>\n"
            '<div class="dashboard">...</div>\n'
            "</body>\n</html>\n"
        )
        result = _fix_html_misplaced_content(content)
        assert result.changed is True
        assert any("CSS" in f for f in result.fixes_applied)
        # Verify the CSS is now wrapped
        assert "<style>" in result.content.split("#weather-panel")[0].split("</style>")[-1] or \
               result.content.count("<style>") > 1


# ===================================================================
# END-TO-END: fix_code() INTEGRATION
# ===================================================================


class TestFixCodeIntegration:
    """Cross-language detection wired into the fix_code() pipeline."""

    def test_css_wrapper_stripped_via_fix_code(self):
        from sentinel.security.code_fixer import fix_code
        content = "<style>\n.foo { color: red; }\n</style>\n"
        result = fix_code("test.css", content)
        assert "<style>" not in result.content
        assert ".foo { color: red; }" in result.content
        assert any("Stripped" in f for f in result.fixes_applied)

    def test_js_wrapper_stripped_via_fix_code(self):
        from sentinel.security.code_fixer import fix_code
        content = "<script>\nconst x = 1;\nconsole.log(x);\n</script>\n"
        result = fix_code("test.js", content)
        assert "<script>" not in result.content
        assert "const x = 1;" in result.content

    def test_html_css_outside_style_via_fix_code(self):
        from sentinel.security.code_fixer import fix_code
        content = (
            "<html>\n<head>\n"
            "<style>\nbody { margin: 0; }\n</style>\n"
            "#panel { color: red; }\n.widget { padding: 5px; }\n"
            "</head>\n<body></body>\n</html>\n"
        )
        result = fix_code("dashboard.html", content)
        assert any("CSS" in f for f in result.fixes_applied)

    def test_svg_routed_correctly(self):
        from sentinel.security.code_fixer import fix_code
        content = (
            '<svg xmlns="http://www.w3.org/2000/svg">\n'
            ".cls-1 { fill: red; }\n.cls-2 { stroke: blue; }\n"
            '<circle r="10"/>\n</svg>\n'
        )
        result = fix_code("icon.svg", content)
        assert any("CSS" in f for f in result.fixes_applied)

    def test_cross_language_crash_is_failsafe(self):
        """If the cross-language detector crashes, fix_code still returns."""
        from sentinel.security.code_fixer import fix_code
        with patch(
            "sentinel.security.code_fixer.fix_cross_language",
            side_effect=RuntimeError("boom"),
        ):
            content = ".foo { color: red; }\n"
            result = fix_code("test.css", content)
            assert result.content is not None
            assert any("Cross-language" in w for w in result.warnings)

    def test_normal_python_file_unaffected(self):
        """Python files should not trigger cross-language fixes."""
        from sentinel.security.code_fixer import fix_code
        content = "print('hello')\n"
        result = fix_code("test.py", content)
        assert "Stripped" not in str(result.fixes_applied)
        assert "Wrapped" not in str(result.fixes_applied)
