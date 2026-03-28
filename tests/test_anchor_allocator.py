import pytest
from sentinel.tools.anchor_allocator._core import (
    AnchorEntry, AnchorResult, AnchorTier, build_marker,
)


class TestAnchorTier:
    def test_section_is_lowest(self):
        assert AnchorTier.SECTION.value < AnchorTier.BLOCK.value

    def test_block_is_middle(self):
        assert AnchorTier.SECTION.value < AnchorTier.BLOCK.value < AnchorTier.DETAIL.value

    def test_tier_from_string(self):
        assert AnchorTier.from_string("section") == AnchorTier.SECTION
        assert AnchorTier.from_string("block") == AnchorTier.BLOCK
        assert AnchorTier.from_string("detail") == AnchorTier.DETAIL

    def test_tier_from_string_invalid(self):
        with pytest.raises(ValueError):
            AnchorTier.from_string("invalid")


class TestAnchorEntry:
    def test_basic_creation(self):
        entry = AnchorEntry(
            name="head-styles",
            line=7,
            tier=AnchorTier.SECTION,
            description="Before <style> block",
            has_end=True,
        )
        assert entry.name == "head-styles"
        assert entry.has_end is True

    def test_end_pair_name(self):
        entry = AnchorEntry(
            name="func-main", line=10, tier=AnchorTier.BLOCK,
            description="Main function", has_end=True,
        )
        assert entry.end_name == "func-main-end"

    def test_no_end_pair(self):
        entry = AnchorEntry(
            name="imports", line=1, tier=AnchorTier.SECTION,
            description="Import block", has_end=False,
        )
        assert entry.end_name is None


class TestBuildMarker:
    def test_html(self):
        assert build_marker("page.html", "head-styles") == "<!-- anchor: head-styles -->"

    def test_htm(self):
        assert build_marker("page.htm", "body-start") == "<!-- anchor: body-start -->"

    def test_python(self):
        assert build_marker("script.py", "imports") == "# anchor: imports"

    def test_javascript(self):
        assert build_marker("app.js", "func-main") == "// anchor: func-main"

    def test_typescript(self):
        assert build_marker("app.ts", "func-main") == "// anchor: func-main"

    def test_css(self):
        assert build_marker("style.css", "reset") == "/* anchor: reset */"

    def test_shell(self):
        assert build_marker("deploy.sh", "func-cleanup") == "# anchor: func-cleanup"

    def test_yaml(self):
        assert build_marker("config.yaml", "key-db") == "# anchor: key-db"

    def test_toml(self):
        assert build_marker("config.toml", "section-db") == "# anchor: section-db"

    def test_json_returns_none(self):
        assert build_marker("data.json", "key-name") is None

    def test_unknown_defaults_to_hash(self):
        assert build_marker("README.txt", "section-1") == "# anchor: section-1"


class TestAnchorResult:
    def test_unchanged_result(self):
        result = AnchorResult(
            content="original",
            changed=False,
            anchors=[],
            file_hash="abc123",
            parse_failed=False,
            error=None,
        )
        assert result.changed is False
        assert result.anchors == []

    def test_failed_result(self):
        result = AnchorResult(
            content="original",
            changed=False,
            anchors=[],
            file_hash="abc123",
            parse_failed=True,
            error="SyntaxError at line 5",
        )
        assert result.parse_failed is True
        assert "SyntaxError" in result.error


from sentinel.tools.anchor_allocator._strip import strip_anchors


class TestStripAnchors:
    def test_strip_html_anchors(self):
        content = (
            '<head>\n'
            '<!-- anchor: head-meta -->\n'
            '<meta charset="UTF-8">\n'
            '<!-- anchor: head-styles -->\n'
            '<style>body { margin: 0; }</style>\n'
            '<!-- anchor: head-styles-end -->\n'
            '</head>\n'
        )
        stripped, count = strip_anchors(content)
        assert count == 3
        assert "anchor:" not in stripped
        assert '<meta charset="UTF-8">' in stripped
        assert "<style>" in stripped

    def test_strip_python_anchors(self):
        content = (
            '# anchor: imports\n'
            'import os\n'
            '# anchor: func-main\n'
            'def main():\n'
            '    pass\n'
            '# anchor: func-main-end\n'
        )
        stripped, count = strip_anchors(content)
        assert count == 3
        assert "anchor:" not in stripped
        assert "import os" in stripped
        assert "def main():" in stripped

    def test_strip_javascript_anchors(self):
        content = (
            '// anchor: imports\n'
            'import { foo } from "./bar.js";\n'
            '// anchor: func-main\n'
            'function main() {}\n'
            '// anchor: func-main-end\n'
        )
        stripped, count = strip_anchors(content)
        assert count == 3
        assert "anchor:" not in stripped

    def test_strip_css_anchors(self):
        content = (
            '/* anchor: reset */\n'
            '* { margin: 0; }\n'
            '/* anchor: layout */\n'
            'body { display: flex; }\n'
        )
        stripped, count = strip_anchors(content)
        assert count == 2
        assert "anchor:" not in stripped

    def test_does_not_strip_anchor_in_string(self):
        content = 'x = "# anchor: fake"\nprint(x)\n'
        stripped, count = strip_anchors(content)
        assert count == 0
        assert stripped == content

    def test_preserves_indented_anchor(self):
        content = (
            'class Foo:\n'
            '    # anchor: Foo.__init__\n'
            '    def __init__(self):\n'
            '        pass\n'
            '    # anchor: Foo.__init__-end\n'
        )
        stripped, count = strip_anchors(content)
        assert count == 2
        assert "def __init__" in stripped

    def test_idempotent_no_anchors(self):
        content = "just plain text\nno anchors here\n"
        stripped, count = strip_anchors(content)
        assert count == 0
        assert stripped == content

    def test_strip_removes_blank_lines_left_by_anchors(self):
        """Stripping an anchor line should not leave double blank lines."""
        content = (
            'import os\n'
            '\n'
            '# anchor: func-main\n'
            'def main():\n'
            '    pass\n'
        )
        stripped, count = strip_anchors(content)
        assert count == 1
        assert "\n\n\n" not in stripped


from sentinel.tools.anchor_allocator._html import parse_html_anchors


class TestHtmlParser:
    def test_head_section_anchors(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head>\n'
            '<meta charset="UTF-8">\n'
            '<title>Test</title>\n'
            '<style>body { margin: 0; }</style>\n'
            '</head>\n<body></body>\n</html>'
        )
        anchors = parse_html_anchors(html)
        names = [a.name for a in anchors]
        assert "head-styles" in names
        # head-styles-end is generated by _insert_anchors from has_end=True,
        # not as a separate parser entry
        assert "head-styles-end" not in names
        assert "body-start" in names
        assert "body-end" in names

    def test_elements_with_ids(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head></head>\n<body>\n'
            '<div id="panel-weather"><p>Weather</p></div>\n'
            '<div id="panel-markets"><p>Markets</p></div>\n'
            '</body>\n</html>'
        )
        anchors = parse_html_anchors(html)
        names = [a.name for a in anchors]
        assert "el-panel-weather" in names
        # end markers are generated by _insert_anchors, not as parser entries
        assert "el-panel-weather-end" not in names
        assert "el-panel-markets" in names
        assert "el-panel-markets-end" not in names

    def test_structural_elements_without_ids(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head></head>\n<body>\n'
            '<nav><a href="/">Home</a></nav>\n'
            '<main><p>Content</p></main>\n'
            '<footer><p>Footer</p></footer>\n'
            '</body>\n</html>'
        )
        anchors = parse_html_anchors(html)
        names = [a.name for a in anchors]
        assert "el-nav-1" in names
        assert "el-main-1" in names
        assert "el-footer-1" in names

    def test_script_block_anchors(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head></head>\n<body>\n'
            '<script>\n'
            'function fetchWeather() { return null; }\n'
            'function updatePanel() { return null; }\n'
            '</script>\n'
            '</body>\n</html>'
        )
        anchors = parse_html_anchors(html)
        names = [a.name for a in anchors]
        assert "scripts" in names
        # scripts-end is generated by _insert_anchors, not as a parser entry
        assert "scripts-end" not in names

    def test_tier_filtering_section_only(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head>\n'
            '<style>body { margin: 0; }</style>\n'
            '</head>\n<body>\n'
            '<div id="panel-weather"><p>Weather</p></div>\n'
            '</body>\n</html>'
        )
        section_anchors = [a for a in parse_html_anchors(html)
                          if a.tier == AnchorTier.SECTION]
        block_anchors = [a for a in parse_html_anchors(html)
                        if a.tier == AnchorTier.BLOCK]
        # Section tier should have head-styles, body-start, body-end etc
        assert len(section_anchors) > 0
        # Block tier should have el-panel-weather
        assert any(a.name == "el-panel-weather" for a in block_anchors)

    def test_has_end_on_block_elements(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head></head>\n<body>\n'
            '<div id="sidebar"><p>Side</p></div>\n'
            '</body>\n</html>'
        )
        anchors = parse_html_anchors(html)
        sidebar = next(a for a in anchors if a.name == "el-sidebar")
        assert sidebar.has_end is True

    def test_empty_html(self):
        anchors = parse_html_anchors("")
        assert anchors == []

    def test_malformed_html_returns_empty(self):
        """Parser should not crash on malformed HTML — return empty list."""
        anchors = parse_html_anchors("<<<not html at all{{{")
        assert isinstance(anchors, list)


from sentinel.tools.anchor_allocator._python import parse_python_anchors


class TestPythonParser:
    def test_import_block(self):
        code = "import os\nimport sys\n\ndef main():\n    pass\n"
        anchors = parse_python_anchors(code)
        names = [a.name for a in anchors]
        assert "imports" in names

    def test_module_function(self):
        code = "def process(data):\n    return data\n"
        anchors = parse_python_anchors(code)
        names = [a.name for a in anchors]
        assert "func-process" in names
        assert any(a.has_end and a.name == "func-process" for a in anchors)

    def test_class_and_methods(self):
        code = (
            "class DataProcessor:\n"
            "    def __init__(self):\n"
            "        pass\n"
            "\n"
            "    def process(self, data):\n"
            "        return data\n"
        )
        anchors = parse_python_anchors(code)
        names = [a.name for a in anchors]
        assert "class-DataProcessor" in names
        assert "DataProcessor.__init__" in names
        assert "DataProcessor.process" in names

    def test_constants(self):
        code = "MAX_RETRIES = 3\nTIMEOUT = 30\n\ndef main():\n    pass\n"
        anchors = parse_python_anchors(code)
        names = [a.name for a in anchors]
        assert "constants" in names

    def test_empty_file(self):
        anchors = parse_python_anchors("")
        assert anchors == []

    def test_syntax_error_returns_empty(self):
        anchors = parse_python_anchors("def broken(:\n    pass\n")
        assert anchors == []

    def test_class_has_end(self):
        code = "class Foo:\n    pass\n"
        anchors = parse_python_anchors(code)
        foo = next(a for a in anchors if a.name == "class-Foo")
        assert foo.has_end is True

    def test_imports_no_end(self):
        code = "import os\n\ndef main():\n    pass\n"
        anchors = parse_python_anchors(code)
        imp = next(a for a in anchors if a.name == "imports")
        assert imp.has_end is False


from sentinel.tools.anchor_allocator._css import parse_css_anchors


class TestCssParser:
    def test_rule_groups_by_blank_line(self):
        css = (
            '* { margin: 0; }\n'
            '\n'
            'body { display: flex; }\n'
            '.container { max-width: 1200px; }\n'
            '\n'
            '#panel-weather { color: white; }\n'
        )
        anchors = parse_css_anchors(css)
        names = [a.name for a in anchors]
        assert "styles-panel-weather" in names

    def test_media_query(self):
        css = '@media (max-width: 768px) {\n  body { font-size: 14px; }\n}\n'
        anchors = parse_css_anchors(css)
        names = [a.name for a in anchors]
        assert any(n.startswith("media-") for n in names)

    def test_keyframes(self):
        css = '@keyframes fadeIn {\n  from { opacity: 0; }\n  to { opacity: 1; }\n}\n'
        anchors = parse_css_anchors(css)
        names = [a.name for a in anchors]
        assert "keyframes-fadeIn" in names

    def test_empty_css(self):
        assert parse_css_anchors("") == []

    def test_comment_named_section(self):
        css = '/* Reset */\n* { margin: 0; }\n\n/* Layout */\nbody { display: flex; }\n'
        anchors = parse_css_anchors(css)
        names = [a.name for a in anchors]
        assert "reset" in names or "section-1" in names


from sentinel.tools.anchor_allocator._shell import parse_shell_anchors


class TestShellParser:
    def test_function_detection(self):
        script = '#!/bin/bash\n\ncleanup() {\n  rm -rf /tmp/work\n}\n\nmain() {\n  cleanup\n}\n'
        anchors = parse_shell_anchors(script)
        names = [a.name for a in anchors]
        assert "func-cleanup" in names
        assert "func-main" in names

    def test_shebang(self):
        script = '#!/bin/bash\necho hello\n'
        anchors = parse_shell_anchors(script)
        names = [a.name for a in anchors]
        assert "shebang" in names

    def test_empty_script(self):
        assert parse_shell_anchors("") == []

    def test_function_has_end(self):
        script = 'cleanup() {\n  echo done\n}\n'
        anchors = parse_shell_anchors(script)
        cleanup = next(a for a in anchors if a.name == "func-cleanup")
        assert cleanup.has_end is True


from sentinel.tools.anchor_allocator._config import (
    parse_yaml_anchors,
    parse_json_anchors,
    parse_toml_anchors,
)


class TestYamlParser:
    def test_top_level_keys(self):
        yaml_content = 'database:\n  host: localhost\n  port: 5432\nlogging:\n  level: INFO\n'
        anchors = parse_yaml_anchors(yaml_content)
        names = [a.name for a in anchors]
        assert "key-database" in names
        assert "key-logging" in names

    def test_empty_yaml(self):
        assert parse_yaml_anchors("") == []

    def test_invalid_yaml_returns_empty(self):
        assert parse_yaml_anchors(":\n  - :\n    :\n") == []


class TestJsonParser:
    def test_top_level_keys(self):
        json_content = '{"name": "test", "version": "1.0", "scripts": {}}'
        anchors = parse_json_anchors(json_content)
        names = [a.name for a in anchors]
        assert "key-name" in names
        assert "key-version" in names
        assert "key-scripts" in names

    def test_no_markers_in_content(self):
        """JSON anchors describe structure but don't modify content."""
        json_content = '{"name": "test"}'
        anchors = parse_json_anchors(json_content)
        assert len(anchors) > 0
        # Confirm these are map-only (no has_end, no modification)
        for a in anchors:
            assert a.has_end is False

    def test_empty_json(self):
        assert parse_json_anchors("") == []


class TestTomlParser:
    def test_sections(self):
        toml_content = '[database]\nhost = "localhost"\n\n[logging]\nlevel = "INFO"\n'
        anchors = parse_toml_anchors(toml_content)
        names = [a.name for a in anchors]
        assert "section-database" in names
        assert "section-logging" in names

    def test_empty_toml(self):
        assert parse_toml_anchors("") == []


from sentinel.tools.anchor_allocator import allocate_anchors


class TestAllocateAnchors:
    @pytest.mark.asyncio
    async def test_html_file_gets_anchors(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head>\n'
            '<style>body { margin: 0; }</style>\n'
            '</head>\n<body>\n'
            '<div id="panel-weather"><p>Weather</p></div>\n'
            '</body>\n</html>'
        )
        result = await allocate_anchors("test.html", html)
        assert result.changed is True
        assert "<!-- anchor: head-styles -->" in result.content
        assert "<!-- anchor: el-panel-weather -->" in result.content
        assert "<!-- anchor: el-panel-weather-end -->" in result.content
        assert len(result.anchors) > 0
        assert result.file_hash != ""
        assert result.parse_failed is False

    @pytest.mark.asyncio
    async def test_python_file_gets_anchors(self):
        code = "import os\n\ndef main():\n    pass\n"
        result = await allocate_anchors("script.py", code)
        assert result.changed is True
        assert "# anchor: imports" in result.content
        assert "# anchor: func-main" in result.content
        assert "# anchor: func-main-end" in result.content

    @pytest.mark.asyncio
    async def test_json_file_no_markers_but_has_map(self):
        """JSON files get an anchor map but no markers in content."""
        json_content = '{"name": "test", "version": "1.0"}'
        result = await allocate_anchors("data.json", json_content)
        assert result.changed is False  # No markers inserted
        assert result.content == json_content  # Content unchanged
        assert len(result.anchors) > 0  # But map exists

    @pytest.mark.asyncio
    async def test_idempotent(self):
        html = (
            '<!DOCTYPE html>\n<html>\n<head></head>\n<body>\n'
            '<div id="main"><p>Content</p></div>\n'
            '</body>\n</html>'
        )
        result1 = await allocate_anchors("page.html", html)
        result2 = await allocate_anchors("page.html", result1.content)
        assert result1.content == result2.content
        assert len(result1.anchors) == len(result2.anchors)

    @pytest.mark.asyncio
    async def test_unsupported_extension_returns_unchanged(self):
        result = await allocate_anchors("image.png", "binary content")
        assert result.changed is False
        assert result.content == "binary content"
        assert result.anchors == []

    @pytest.mark.asyncio
    async def test_tier_filtering(self):
        """With section tier, only section-level anchors should appear."""
        html = (
            '<!DOCTYPE html>\n<html>\n<head>\n'
            '<style>body { margin: 0; }</style>\n'
            '</head>\n<body>\n'
            '<div id="panel"><p>Content</p></div>\n'
            '</body>\n</html>'
        )
        result = await allocate_anchors("page.html", html, tier="section")
        # el-panel is BLOCK tier -- should not appear at section filtering
        assert "<!-- anchor: el-panel -->" not in result.content
        # head-styles is SECTION tier -- should appear
        assert "<!-- anchor: head-styles -->" in result.content

    @pytest.mark.asyncio
    async def test_parse_failure_returns_original(self):
        """Malformed content should return unchanged with parse_failed=True."""
        result = await allocate_anchors("broken.py", "def broken(:\n")
        assert result.changed is False
        assert result.content == "def broken(:\n"
        assert result.parse_failed is True

    @pytest.mark.asyncio
    async def test_python_idempotent(self):
        """Python anchor insertion should be idempotent."""
        code = "import os\nimport sys\n\ndef process(data):\n    return data\n\ndef main():\n    process(42)\n"
        result1 = await allocate_anchors("app.py", code)
        result2 = await allocate_anchors("app.py", result1.content)
        assert result1.content == result2.content

    @pytest.mark.asyncio
    async def test_css_file_gets_anchors(self):
        css = (
            '/* Reset */\n* { margin: 0; }\n\n'
            '#panel-weather { color: white; }\n\n'
            '@media (max-width: 768px) {\n  body { font-size: 14px; }\n}\n'
        )
        result = await allocate_anchors("style.css", css)
        assert result.changed is True
        assert "/* anchor:" in result.content

    @pytest.mark.asyncio
    async def test_shell_file_gets_anchors(self):
        script = '#!/bin/bash\n\ncleanup() {\n  rm -rf /tmp/work\n}\n'
        result = await allocate_anchors("deploy.sh", script)
        assert result.changed is True
        assert "# anchor: shebang" in result.content
        assert "# anchor: func-cleanup" in result.content
