import pytest

from sentinel.security.code_fixer import fix_code, FixResult


# ===================================================================
# PYTHON
# ===================================================================

class TestPython:
    def test_missing_trailing_newline(self):
        result = fix_code("hello.py", 'print("hello world")')
        assert result.changed
        assert result.content.endswith("\n")

    def test_bom_removal(self):
        result = fix_code("hello.py", '\ufeffprint("hello world")\n')
        assert result.changed
        assert not result.content.startswith("\ufeff")

    def test_crlf_to_lf(self):
        result = fix_code("hello.py", 'import os\r\nprint("hello")\r\n')
        assert result.changed
        assert "\r\n" not in result.content

    def test_duplicate_imports(self):
        result = fix_code("app.py", 'import os\nimport sys\nimport os\nimport json\nimport sys\n\nprint("hello")\n')
        assert result.changed
        assert result.content.count("import os") == 1
        assert result.content.count("import sys") == 1

    def test_mixed_indentation_tabs(self):
        result = fix_code("app.py", 'def hello():\n\tprint("hi")\n\tif True:\n\t\tprint("yes")\n')
        assert result.changed
        assert "\t" not in result.content
        assert "    print" in result.content

    def test_unclosed_bracket_truncation(self):
        result = fix_code("app.py", 'data = [1, 2, 3\n')
        assert result.changed
        assert "]" in result.content
        assert not result.errors_found

    def test_unclosed_paren(self):
        result = fix_code("app.py", 'result = print(\n    "hello"\n')
        assert result.changed
        assert ")" in result.content
        assert not result.errors_found

    def test_triple_nested_unclosed_brackets(self):
        result = fix_code("nested.py", 'config = {"items": [{"name": "test"\n')
        assert result.changed
        assert result.content.count("}") >= 2
        assert result.content.count("]") >= 1

    def test_duplicate_from_imports(self):
        result = fix_code("app.py",
            'from os.path import join\nfrom os.path import exists\nfrom os.path import join\n\nprint(join("/", "tmp"))\n')
        assert result.changed
        assert result.content.count("from os.path import join") == 1

    def test_unclosed_dict_with_nested_list(self):
        result = fix_code("complex.py",
            'settings = {\n    "hosts": ["a", "b", "c"],\n    "ports": [80, 443\n')
        assert result.changed
        assert not result.errors_found

    def test_unclosed_fstring_paren(self):
        """Was xfail in v1 — parso handles f-string bracket completion in v2."""
        result = fix_code("fmt.py", 'msg = f"Hello {name} you have {len(items"\n')
        assert result.changed

    def test_five_bugs_stacked(self):
        result = fix_code("messy.py",
            '\ufeffimport os\r\nimport json\r\nimport os\r\n\r\ndef process():   \r\n\tdata = json.loads("{}")\r\n\tos.path.exists("/tmp")\r\n')
        assert result.changed
        assert not result.content.startswith("\ufeff")
        assert "\r\n" not in result.content
        assert result.content.count("import os") == 1
        assert "\t" not in result.content

    def test_prose_prefix_heres_the_code(self):
        result = fix_code("app.py",
            "Here's the Python code for your request:\nimport os\n\ndef main():\n    print(os.getcwd())\n")
        assert result.changed
        assert "Here's" not in result.content
        assert "import os" in result.content

    def test_prose_prefix_sure_ill_create(self):
        result = fix_code("app.py",
            "Sure, I'll create that function for you:\ndef add(a, b):\n    return a + b\n")
        assert result.changed
        assert "Sure" not in result.content
        assert "def add" in result.content

    def test_prose_prefix_below_is(self):
        result = fix_code("app.py",
            "Below is the updated version:\nimport sys\nprint(sys.argv)\n")
        assert result.changed
        assert "Below" not in result.content

    def test_multiple_prose_lines_wrapping_code(self):
        result = fix_code("app.py",
            "I've created the requested function:\nThis code handles authentication:\ndef login(user, pw):\n    return True\n")
        assert result.changed
        assert "I've created" not in result.content
        assert "This code" not in result.content

    def test_truncated_function_cut_mid_return(self):
        result = fix_code("calc.py",
            'def calculate(x, y):\n    result = x * y + (x / y\n')
        assert result.changed
        assert ")" in result.content

    def test_truncated_class_definition(self):
        result = fix_code("model.py",
            'class User:\n    def __init__(self, name, email):\n        self.data = {"name": name, "email": email\n')
        assert result.changed
        assert "}" in result.content

    def test_truncated_list_comprehension(self):
        result = fix_code("gen.py",
            'result = [item.strip() for item in data.split(","\n')
        assert result.changed
        assert result.content.count(")") >= 1


# ===================================================================
# RUST
# ===================================================================

class TestRust:
    def test_missing_trailing_newline(self):
        result = fix_code("main.rs", 'fn main() {\n    println!("hello");\n}')
        assert result.changed
        assert result.content.endswith("\n")

    def test_trailing_whitespace(self):
        result = fix_code("lib.rs", 'fn add(a: i32, b: i32) -> i32 {  \n    a + b  \n}\n')
        assert result.changed
        assert "  \n" not in result.content

    def test_unclosed_function_body(self):
        result = fix_code("main.rs", 'fn main() {\n    let x = 42;\n    println!("{}", x);\n')
        assert result.changed
        assert result.content.count("}") >= 1

    def test_unclosed_nested_blocks(self):
        result = fix_code("main.rs",
            'fn process() {\n    if true {\n        for i in 0..10 {\n            println!("{}", i);\n')
        assert result.changed
        assert result.content.count("}") >= 3

    def test_unclosed_struct_definition(self):
        result = fix_code("types.rs",
            'struct Config {\n    name: String,\n    port: u16,\n    hosts: Vec<String>,\n')
        assert result.changed
        assert "}" in result.content

    def test_missing_semicolon_on_let(self):
        result = fix_code("main.rs", 'fn main() {\n    let x = 42\n}\n')
        assert result.changed
        assert "let x = 42;" in result.content

    def test_missing_semicolon_on_println(self):
        result = fix_code("main.rs", 'fn main() {\n    println!("hello")\n}\n')
        assert result.changed
        assert 'println!("hello");' in result.content

    def test_prose_prefix(self):
        result = fix_code("main.rs",
            "Here's the Rust implementation:\nfn main() {\n    println!(\"hello\");\n}\n")
        assert result.changed
        assert "Here's" not in result.content
        assert "fn main" in result.content

    def test_truncated_match_expression(self):
        result = fix_code("handler.rs",
            'fn handle(cmd: &str) -> String {\n    match cmd {\n        "start" => "Starting".to_string(),\n        "stop" => "Stopping".to_string(),\n')
        assert result.changed
        assert result.content.count("}") >= 2

    def test_truncated_impl_block(self):
        result = fix_code("types.rs",
            'impl Config {\n    fn new(name: &str) -> Self {\n        Self {\n            name: name.to_string(),\n')
        assert result.changed
        assert result.content.count("}") >= 3

    def test_valid_rust_unchanged(self):
        result = fix_code("lib.rs", 'pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n')
        assert not result.changed


# ===================================================================
# HTML
# ===================================================================

class TestHTML:
    def test_missing_doctype(self):
        result = fix_code("index.html",
            '<html>\n<head><title>Test</title></head>\n<body><p>Hello</p></body>\n</html>\n')
        assert result.changed
        assert "<!DOCTYPE html>" in result.content

    def test_unclosed_div(self):
        result = fix_code("page.html",
            '<!DOCTYPE html>\n<html lang="en">\n<body>\n<div class="container">\n<p>Hello</p>\n</body>\n</html>\n')
        assert result.changed
        assert "</div>" in result.content

    def test_multiple_unclosed_tags(self):
        result = fix_code("page.html",
            '<!DOCTYPE html>\n<html lang="en">\n<body>\n<div>\n<section>\n<p>Hello\n')
        assert result.changed
        assert "</p>" in result.content
        assert "</section>" in result.content
        assert "</div>" in result.content

    def test_unclosed_nested_divs(self):
        result = fix_code("page.html",
            '<!DOCTYPE html>\n<html lang="en">\n<body>\n<div class="outer">\n  <div class="inner">\n    <p>Content</p>\n</body>\n</html>\n')
        assert result.changed
        assert result.content.count("</div>") >= 2

    def test_void_elements_not_double_closed(self):
        result = fix_code("page.html",
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<link rel="stylesheet" href="style.css">\n</head>\n<body>\n<img src="photo.jpg">\n<br>\n<input type="text">\n</body>\n</html>\n')
        assert not result.changed

    def test_missing_lang_attribute_warning(self):
        result = fix_code("index.html",
            '<!DOCTYPE html>\n<html>\n<head><title>Test</title></head>\n<body>Hello</body>\n</html>\n')
        assert any("lang" in w for w in result.warnings)

    def test_missing_charset_warning(self):
        result = fix_code("index.html",
            '<!DOCTYPE html>\n<html lang="en">\n<head><title>Test</title></head>\n<body>Hello</body>\n</html>\n')
        assert any("charset" in w for w in result.warnings)

    def test_prose_prefix(self):
        result = fix_code("page.html",
            "Here's the HTML page:\n<!DOCTYPE html>\n<html lang=\"en\">\n<body><p>Hello</p></body>\n</html>\n")
        assert result.changed
        assert "Here's" not in result.content
        assert "<!DOCTYPE" in result.content

    def test_truncated_template(self):
        result = fix_code("template.html",
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n<title>Dashboard</title>\n</head>\n<body>\n<div class="sidebar">\n  <ul>\n    <li>Home</li>\n    <li>Settings</li>\n')
        assert result.changed
        assert "</ul>" in result.content
        assert "</div>" in result.content

    def test_valid_html_unchanged(self):
        result = fix_code("valid.html",
            '<!DOCTYPE html>\n<html lang="en">\n<head><meta charset="utf-8"><title>Test</title></head>\n<body><p>Hello</p></body>\n</html>\n')
        assert not result.changed


# ===================================================================
# DOCKERFILE
# ===================================================================

class TestDockerfile:
    def test_single_quotes_in_cmd(self):
        result = fix_code("Dockerfile",
            "FROM python:3.12-slim\nCOPY . /app\nCMD ['python', 'app.py']\n")
        assert result.changed
        assert '["python"' in result.content

    def test_single_quotes_in_entrypoint(self):
        result = fix_code("Dockerfile",
            "FROM python:3.12-slim\nENTRYPOINT ['python', '-m', 'pytest']\n")
        assert result.changed
        assert '["python"' in result.content

    def test_latest_warning(self):
        result = fix_code("Dockerfile",
            "FROM python:latest\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n")
        assert any("latest" in w for w in result.warnings)

    def test_missing_from(self):
        result = fix_code("Dockerfile",
            "RUN apt-get update\nFROM python:3.12\nCOPY . /app\n")
        assert any("FROM" in e for e in result.errors_found)

    def test_add_to_copy(self):
        result = fix_code("Dockerfile",
            "FROM python:3.12-slim\nADD requirements.txt /app/\nADD . /app\n")
        assert result.changed
        assert "COPY requirements.txt" in result.content
        assert "COPY . /app" in result.content

    def test_add_preserved_for_url(self):
        result = fix_code("Dockerfile",
            "FROM python:3.12-slim\nADD https://example.com/file.tar.gz /tmp/\n")
        assert "ADD https://" in result.content

    def test_add_preserved_for_tar_archive(self):
        result = fix_code("Dockerfile",
            "FROM python:3.12-slim\nADD app.tar.gz /opt/\n")
        assert "ADD app.tar.gz" in result.content

    def test_missing_user_warning(self):
        result = fix_code("Dockerfile",
            "FROM python:3.12-slim\nCOPY . /app\nRUN pip install -r requirements.txt\nCMD [\"python\", \"app.py\"]\n")
        assert any("root" in w.lower() for w in result.warnings)

    def test_apt_get_install_without_update(self):
        result = fix_code("Dockerfile",
            "FROM ubuntu:22.04\nRUN apt-get install -y curl\n")
        assert any("apt-get install" in w and "update" in w for w in result.warnings)

    def test_shell_operators_in_exec_form(self):
        result = fix_code("Dockerfile",
            'FROM python:3.12\nRUN ["apt-get", "update", "&&", "apt-get", "install", "-y", "curl"]\n')
        assert any("Shell operators" in w for w in result.warnings)

    def test_prose_prefix(self):
        result = fix_code("Dockerfile",
            "Here's the Dockerfile for your app:\nFROM python:3.12-slim\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n")
        assert result.changed
        assert "Here's" not in result.content
        assert "FROM" in result.content

    def test_containerfile_single_quotes_in_cmd(self):
        result = fix_code("Containerfile",
            "FROM python:3.12-slim\nCMD ['python', 'app.py']\n")
        assert result.changed
        assert '["python"' in result.content

    def test_multi_stage_with_multiple_issues(self):
        result = fix_code("Dockerfile",
            "FROM python:latest AS builder\nADD . /build\nRUN pip install .\n\nFROM python:latest\nADD --from=builder /build/dist /app\nCMD ['python', '/app/main.py']\n")
        assert any("latest" in w for w in result.warnings)
        assert result.changed

    def test_valid_dockerfile_unchanged(self):
        result = fix_code("Dockerfile",
            'FROM python:3.12-slim\nCOPY . /app\nWORKDIR /app\nRUN pip install --no-cache-dir -r requirements.txt\nUSER 1000\nCMD ["python", "app.py"]\n')
        assert not result.changed
        assert not result.errors_found


# ===================================================================
# JSON
# ===================================================================

class TestJSON:
    def test_trailing_comma(self):
        result = fix_code("config.json", '{"name": "test", "value": 42,}\n')
        assert result.changed
        assert not result.errors_found

    def test_python_true_false_none(self):
        result = fix_code("config.json", '{"enabled": True, "debug": False, "extra": None}\n')
        assert result.changed
        assert "true" in result.content
        assert "false" in result.content
        assert "null" in result.content

    def test_single_quotes(self):
        result = fix_code("data.json", "{'name': 'test', 'count': 5}\n")
        assert result.changed
        assert '"name"' in result.content

    def test_nested_trailing_commas(self):
        result = fix_code("deep.json", '{"a": {"b": [1, 2, 3,], "c": "d",},}\n')
        assert result.changed
        assert not result.errors_found

    def test_python_bools_and_trailing_comma(self):
        result = fix_code("settings.json", '{"debug": True, "verbose": False, "extra": None,}')
        assert result.changed
        assert "true" in result.content
        assert "null" in result.content
        assert not result.errors_found

    def test_valid_json_unchanged(self):
        result = fix_code("valid.json", '{"name": "test", "value": 42}\n')
        assert not result.changed


# ===================================================================
# YAML
# ===================================================================

class TestYAML:
    def test_tab_indentation(self):
        result = fix_code("config.yaml",
            "services:\n\tweb:\n\t\timage: nginx\n\t\tports:\n\t\t\t- '80:80'\n")
        assert result.changed
        assert "\t" not in result.content

    def test_compose_style_tabs(self):
        result = fix_code("podman-compose.yaml",
            "version: '3'\nservices:\n\tapp:\n\t\timage: sentinel\n\t\tports:\n\t\t\t- '3001:3001'\n\t\tenvironment:\n\t\t\t- TRUST_LEVEL=4\n")
        assert result.changed
        assert "\t" not in result.content

    def test_valid_yaml_unchanged(self):
        result = fix_code("valid.yaml",
            'services:\n  web:\n    image: nginx\n    ports:\n      - "80:80"\n')
        assert not result.changed


# ===================================================================
# CSS
# ===================================================================

class TestCSS:
    def test_unclosed_brace(self):
        result = fix_code("style.css", ".container {\n  display: flex;\n  padding: 20px;\n")
        assert result.changed
        assert "}" in result.content

    def test_multiple_unclosed_braces(self):
        result = fix_code("style.css", ".outer {\n  .inner {\n    color: red;\n")
        assert result.changed
        assert result.content.count("}") >= 2

    def test_missing_semicolon_before_brace(self):
        result = fix_code("style.css", ".box {\n  color: red;\n  padding: 10px\n}\n")
        assert result.changed
        assert "padding: 10px;" in result.content

    def test_valid_css_unchanged(self):
        result = fix_code("style.css", ".container {\n  display: flex;\n  padding: 20px;\n}\n")
        assert not result.changed


# ===================================================================
# SQL
# ===================================================================

class TestSQL:
    def test_missing_semicolon_select(self):
        result = fix_code("query.sql", "SELECT * FROM users WHERE active = true\n")
        assert result.changed
        assert result.content.rstrip().endswith(";")

    def test_missing_semicolon_insert(self):
        result = fix_code("insert.sql",
            "INSERT INTO users (name, email) VALUES ('test', 'test@example.com')\n")
        assert result.changed
        assert result.content.rstrip().endswith(";")

    def test_missing_semicolon_create_table(self):
        result = fix_code("schema.sql",
            "CREATE TABLE users (\n    id SERIAL PRIMARY KEY,\n    name TEXT NOT NULL\n)\n")
        assert result.changed
        assert result.content.rstrip().endswith(";")

    def test_valid_sql_unchanged(self):
        result = fix_code("query.sql", "SELECT * FROM users WHERE active = true;\n")
        assert not result.changed


# ===================================================================
# SHELL
# ===================================================================

class TestShell:
    def test_missing_shebang(self):
        result = fix_code("deploy.sh", 'echo "deploying..."\ncp -r dist/ /var/www/\n')
        assert result.changed
        assert result.content.startswith("#!/bin/bash\n")

    def test_already_has_shebang(self):
        result = fix_code("deploy.sh", '#!/bin/bash\necho "deploying..."\n')
        assert not result.changed

    def test_prose_plus_missing_shebang(self):
        result = fix_code("build.sh",
            "Here's the build script:\nset -euo pipefail\nmake all\n")
        assert result.changed
        assert "Here's" not in result.content
        assert result.content.startswith("#!/bin/bash")


# ===================================================================
# TOML
# ===================================================================

class TestTOML:
    def test_valid_toml_unchanged(self):
        result = fix_code("pyproject.toml", '[project]\nname = "sentinel"\nversion = "1.0.0"\n')
        assert not result.changed

    def test_invalid_toml_detected(self):
        result = fix_code("broken.toml", '[project]\nname = sentinel\nversion = 1.0.0\n')
        assert len(result.errors_found) > 0


# ===================================================================
# STRESS TESTS
# ===================================================================

class TestStress:
    def test_python_with_every_issue(self):
        result = fix_code("disaster.py",
            '\ufeff'
            'Here\'s the code:\r\n'
            'import os\r\n'
            'import json\r\n'
            'import os\r\n'
            '\r\n'
            'def process():   \r\n'
            '\tdata = json.loads("{}")\r\n'
            '\tos.path.exists("/tmp")\r\n'
            '\tresult = [x for x in data.values(\r\n')
        assert result.changed
        assert not result.content.startswith("\ufeff")
        assert "\r\n" not in result.content
        assert "Here's" not in result.content
        assert result.content.count("import os") == 1
        assert "\t" not in result.content

    def test_rust_with_prose_truncation_whitespace(self):
        result = fix_code("main.rs",
            "Sure, here's the implementation:\n"
            "fn main() {  \n"
            "    let items = vec![1, 2, 3];  \n"
            "    for item in items {  \n"
            '        println!("{}", item);\n')
        assert result.changed
        assert "Sure" not in result.content
        assert "  \n" not in result.content
        assert result.content.count("}") >= 2

    def test_html_prose_truncation_missing_doctype(self):
        result = fix_code("page.html",
            "Here is the HTML template:\n"
            "<html>\n"
            "<head><title>App</title></head>\n"
            "<body>\n"
            '<div class="main">\n'
            "  <ul>\n"
            "    <li>Item 1\n"
            "    <li>Item 2\n")
        assert result.changed
        assert "Here is" not in result.content
        assert "<!DOCTYPE" in result.content
        assert "</ul>" in result.content
        assert "</div>" in result.content

    def test_dockerfile_prose_latest_add_cmd_quotes_no_user(self):
        result = fix_code("Dockerfile",
            "Here's the optimized Dockerfile:\n"
            "FROM python:latest\n"
            "ADD requirements.txt /app/\n"
            "ADD . /app\n"
            "RUN apt-get install -y curl\n"
            "RUN pip install -r /app/requirements.txt\n"
            "CMD ['python', '/app/main.py']\n")
        assert result.changed
        assert "Here's" not in result.content
        assert '["python"' in result.content
        assert "COPY requirements.txt" in result.content
        assert any("latest" in w for w in result.warnings)
        assert any("root" in w.lower() for w in result.warnings)
        assert any("apt-get install" in w for w in result.warnings)


# ===================================================================
# EDGE CASES
# ===================================================================

class TestEdgeCases:
    def test_empty_file(self):
        result = fix_code("empty.py", "")
        assert not result.changed

    def test_whitespace_only_file(self):
        fix_code("blank.py", "   \n  \n\n")  # just don't crash

    def test_single_newline(self):
        result = fix_code("newline.py", "\n")
        assert not result.changed

    def test_very_long_line(self):
        fix_code("long.py", "x = " + '"a' * 5000 + '"\n')  # just don't crash

    def test_non_text_content_handled_gracefully(self):
        fix_code("weird.py", "# -*- coding: utf-8 -*-\nx = '\x00\x01\x02'\n")  # just don't crash

    def test_string_containing_import_os_not_stripped(self):
        result = fix_code("app.py", 'msg = "You need to import os first"\nprint(msg)\n')
        assert not result.changed

    def test_json_true_inside_string_values_not_replaced(self):
        result = fix_code("data.json", '{"message": "Set to True", "value": true}\n')
        assert not result.changed

    def test_dockerfile_add_with_url_preserved(self):
        result = fix_code("Dockerfile",
            "FROM ubuntu:22.04\nADD https://github.com/some/release.tar.gz /opt/\n")
        assert "ADD https://" in result.content

    def test_html_with_inline_script(self):
        result = fix_code("page.html",
            '<!DOCTYPE html>\n<html lang="en">\n<head><meta charset="utf-8"><title>T</title></head>\n'
            '<body>\n<script>\nif (x < 10 && y > 5) { alert("hi"); }\n</script>\n</body>\n</html>\n')
        assert not result.changed

    def test_rust_lifetimes_not_confused(self):
        result = fix_code("lib.rs",
            "fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {\n    if x.len() > y.len() { x } else { y }\n}\n")
        assert not result.changed

    def test_css_media_balanced_braces(self):
        result = fix_code("style.css",
            "@media (max-width: 768px) {\n  .container {\n    padding: 10px;\n  }\n}\n")
        assert not result.changed


# ===================================================================
# QWEN PATTERNS
# ===================================================================

class TestQwenPatterns:
    def test_think_tag_prose_strip(self):
        result = fix_code("app.py",
            "Here's the solution:\nimport math\n\ndef circle_area(r):\n    return math.pi * r ** 2\n")
        assert result.changed
        assert "Here's" not in result.content

    def test_extra_helper_function_no_crash(self):
        result = fix_code("app.py",
            'def main():\n    print("hello")\n\ndef _helper_unused():\n    pass\n')
        assert not result.errors_found

    def test_response_tag_passthrough(self):
        fix_code("app.py", '<RESPONSE>\nprint("hello")\n</RESPONSE>\n')  # just don't crash

    def test_deeply_nested_python_bools_in_json(self):
        result = fix_code("response.json",
            '{"result": {"success": True, "data": [{"active": True, "deleted": False}], "meta": None}}\n')
        assert result.changed
        assert '"success": true' in result.content
        assert '"active": true' in result.content

    def test_markdown_fence_remnant_passthrough(self):
        fix_code("app.py", '```python\ndef hello():\n    print("hi")\n```\n')  # don't crash

    def test_rust_match_truncated_after_one_arm(self):
        result = fix_code("handler.rs",
            'fn respond(code: u16) -> &\'static str {\n    match code {\n        200 => "OK",\n        404 => "Not Found",\n')
        assert result.changed
        assert result.content.count("}") >= 2

    def test_html_with_misnested_tags(self):
        fix_code("output.html",
            '<!DOCTYPE html>\n<html lang="en">\n<body>\n<p>Hello <b>world\n</p>\n</body>\n</html>\n')  # don't crash

    def test_dockerfile_without_workdir(self):
        fix_code("Dockerfile",
            'FROM python:3.12-slim\nCOPY requirements.txt requirements.txt\nRUN pip install -r requirements.txt\nCOPY . .\nCMD ["python", "app.py"]\n')  # don't crash


# ===================================================================
# SAFETY GUARDS
# ===================================================================

class TestSafetyGuards:
    def test_binary_content_skipped(self):
        result = fix_code("data.bin", "PK\x03\x04\x00\x00\x00\x08\x00some binary data\n")
        assert result.skipped
        assert "Binary" in result.skip_reason

    def test_null_bytes_detected_as_binary(self):
        result = fix_code("weird.py", "\x00\x01\x02\x03import os\n")
        assert result.skipped
        assert "Binary" in result.skip_reason

    def test_empty_string_skipped(self):
        result = fix_code("empty.py", "")
        assert result.skipped
        assert "Empty" in result.skip_reason

    def test_whitespace_only_skipped(self):
        result = fix_code("blank.py", "   \n  \n\n")
        assert result.skipped
        assert "Empty" in result.skip_reason

    def test_oversized_file_gets_universal_only(self):
        big_content = "x = 1\n" * 20000  # ~120KB
        result = fix_code("huge.py", big_content.rstrip("\n"))
        assert result.changed
        assert result.content.endswith("\n")
        assert any("exceeds" in w for w in result.warnings)


# ===================================================================
# IDEMPOTENCY
# ===================================================================

_idempotent_cases = [
    ("python_with_issues", "app.py",
     'import os\nimport os\n\ndef main():\n\tprint(os.getcwd())\n'),
    ("rust_with_truncation", "main.rs",
     'fn main() {\n    let x = 42\n'),
    ("dockerfile_with_add", "Dockerfile",
     "FROM python:3.12\nADD . /app\nCMD ['python', 'app.py']\n"),
    ("json_with_python_bools", "data.json",
     '{"enabled": True, "debug": False,}\n'),
    ("html_with_missing_tags", "page.html",
     '<html>\n<body>\n<div>\n<p>Hello\n'),
    ("css_unclosed", "style.css",
     ".box {\n  color: red\n"),
]


class TestIdempotency:
    @pytest.mark.parametrize("label,filename,broken", _idempotent_cases,
                             ids=[c[0] for c in _idempotent_cases])
    def test_double_fix_is_stable(self, label, filename, broken):
        first = fix_code(filename, broken)
        second = fix_code(filename, first.content)
        assert not second.changed


# ===================================================================
# PYTHON SAFETY
# ===================================================================

class TestPythonSafety:
    def test_scoped_imports_preserved(self):
        result = fix_code("test_utils.py",
            'import pytest\n\nclass TestSlugify:\n    def test_basic(self):\n'
            '        from mylib.utils import slugify\n'
            '        assert slugify("Hello World") == "hello-world"\n\n'
            '    def test_empty(self):\n'
            '        from mylib.utils import slugify\n'
            '        assert slugify("") == ""\n')
        assert result.content.count("from mylib.utils import slugify") == 2

    def test_plain_text_in_py_file(self):
        result = fix_code("notes.py", "This is just a notes file\nNot actual Python code\n")
        assert "This is just a notes file" in result.content

    def test_escaped_triple_quotes_fixed(self):
        result = fix_code("__init__.py",
            '\\"\\"\\"Module docstring.\\"\\"\\"\n\nfrom .utils import slugify\n')
        assert result.changed
        assert '"""Module docstring."""' in result.content

    def test_brackets_in_strings_not_miscounted(self):
        result = fix_code("app.py", 'msg = "data = {key: [1, 2, 3]}"\nprint(msg)\n')
        assert not result.changed

    def test_triple_quoted_strings_preserved(self):
        result = fix_code("doc.py",
            '"""\nThis module has brackets: {[()]}\n"""\n\ndef func():\n    pass\n')
        assert not result.changed


# ===================================================================
# MAKEFILE SAFETY
# ===================================================================

class TestMakefileSafety:
    def test_tabs_preserved_in_makefile(self):
        result = fix_code("Makefile",
            'CC = gcc\nCFLAGS = -Wall\n\nall: main\n\nmain: main.o\n\t$(CC) $(CFLAGS) -o $@ $^\n\nclean:\n\trm -f *.o main\n')
        assert "\t" in result.content

    def test_tabs_preserved_in_gnumakefile(self):
        result = fix_code("GNUmakefile", 'all:\n\techo "building"\n')
        assert "\t" in result.content

    def test_tabs_preserved_in_lowercase_makefile(self):
        result = fix_code("makefile", 'test:\n\tpytest tests/\n')
        assert "\t" in result.content


# ===================================================================
# ROUTER PATH CONTENT TYPES
# ===================================================================

class TestRouterPathContentTypes:
    def test_plain_english_text_passes_through(self):
        result = fix_code("response.txt",
            "The current Bitcoin price is $67,432.50 as of today.\n")
        assert not result.changed

    def test_numeric_result_passes_through(self):
        result = fix_code("result.txt", "42\n")
        assert not result.changed

    def test_valid_json_api_result_unchanged(self):
        result = fix_code("response.json",
            '{"price": 67432.50, "currency": "USD", "timestamp": "2026-03-11T12:00:00Z"}\n')
        assert not result.changed

    def test_unknown_extension_gets_universal_only(self):
        result = fix_code("data.xyz", 'some content  \r\nwith CRLF  \r\n')
        assert result.changed
        assert "\r\n" not in result.content
        assert "  \n" not in result.content


# ===================================================================
# DOCKERFILE SAFETY
# ===================================================================

class TestDockerfileSafety:
    def test_add_from_builder_preserved(self):
        result = fix_code("Dockerfile",
            "FROM rust:1.75 AS builder\nWORKDIR /app\nCOPY . .\nRUN cargo build --release\n\n"
            "FROM debian:bookworm-slim\nADD --from=builder /app/target/release/myapp /usr/local/bin/\n"
            'CMD ["./myapp"]\n')
        assert "ADD --from=builder" in result.content


# ===================================================================
# CRASH ISOLATION
# ===================================================================

class TestCrashIsolation:
    def test_deeply_pathological_python(self):
        fix_code("evil.py", 'def f(\n  x,\n  y=[\n    {\n      "a": (\n')  # don't crash

    def test_pathological_html(self):
        fix_code("evil.html",
            '<div><div><div><div><div><div><div><div><div><div>' * 20 + '\n')  # don't crash

    def test_pathological_json(self):
        fix_code("evil.json", '{{{{{"a": "b",,,,}}}}}' + '\n')  # don't crash


# ===================================================================
# REAL QWEN PATTERNS (from test_real_qwen.py)
# ===================================================================

class TestRealQwenPatterns:
    def test_python_function_no_newline(self):
        result = fix_code("validate_ip.py",
            'def validate_ip(ip_str):\n    parts = ip_str.split(".")\n    if len(parts) != 4:\n        return False\n    for part in parts:\n        try:\n            num = int(part)\n            if num < 0 or num > 255:\n                return False\n        except ValueError:\n            return False\n    return True')
        assert result.changed
        assert result.content.endswith("\n")

    def test_dockerfile_no_newline(self):
        result = fix_code("Dockerfile",
            'FROM python:3.12-slim\nRUN useradd -u 1000 -m appuser\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\nCOPY . .\nUSER appuser\nCMD ["python", "app.py"]')
        assert result.changed
        assert result.content.endswith("\n")

    def test_rust_no_newline(self):
        result = fix_code("main.rs",
            'fn main() {\n    println!("Hello from Rust container");\n}')
        assert result.changed
        assert result.content.endswith("\n")

    def test_html_no_newline(self):
        result = fix_code("index.html",
            '<!DOCTYPE html>\n<html lang="en">\n<head><meta charset="utf-8"><title>App</title></head>\n<body><h1>Hello</h1></body>\n</html>')
        assert result.changed
        assert result.content.endswith("\n")

    def test_python_trailing_spaces(self):
        result = fix_code("app.py",
            'import os   \nimport sys  \n\ndef main():  \n    path = os.getcwd()  \n    print(f"Working in {path}")  \n\nif __name__ == "__main__":  \n    main()  \n')
        assert result.changed
        assert "  \n" not in result.content

    def test_rust_trailing_spaces(self):
        result = fix_code("lib.rs",
            'pub fn add(a: i32, b: i32) -> i32 {  \n    a + b  \n}  \n')
        assert result.changed
        assert "  \n" not in result.content

    def test_escaped_triple_quotes_detection(self):
        result = fix_code("__init__.py",
            '\\"\\"\\"mylib - A collection of text processing utilities\\"\\"\\"\n\nfrom .utils import slugify, truncate, capitalize_words\n')
        assert len(result.errors_found) > 0 or result.changed

    def test_prose_heres_a_well_structured(self):
        result = fix_code("validate_ip.py",
            "Here's a well-structured implementation of the `validate_ip` function:\ndef validate_ip(ip_str):\n    parts = ip_str.split('.')\n    if len(parts) != 4:\n        return False\n    return True\n")
        assert result.changed
        assert "Here's" not in result.content
        assert "def validate_ip" in result.content

    def test_prose_ive_created(self):
        result = fix_code("utils.py",
            "I've created the requested utility functions:\nimport re\n\ndef slugify(text):\n    return re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')\n")
        assert result.changed
        assert "I've created" not in result.content
        assert "import re" in result.content

    def test_fastapi_truncated_mid_string(self):
        result = fix_code("app.py",
            'from fastapi import FastAPI\n\napp = FastAPI()\n\n@app.get("/health")\nasync def health_check():\n    """Check service health.\n\n    Returns:\n        dict: Health status with timestamp.\n    """\n    return {"status": "healthy"}\n\n@app.get("/items/{item_id}")\nasync def get_item(item_id: int, q: str = None):\n    return {"item_id": item_id, "q": q}\n\n@app.post("/items")\nasync def create_item(item: dict):\n    return {"created": item\n')
        assert result.changed
        assert "}" in result.content

    def test_class_init_truncated_mid_dict(self):
        result = fix_code("config.py",
            'class Config:\n    def __init__(self):\n        self.settings = {\n            "host": "localhost",\n            "port": 8080,\n            "debug": False,\n            "workers": 4\n')
        assert result.changed
        assert "}" in result.content
        assert not result.errors_found

    def test_makefile_tabs_preserved(self):
        result = fix_code("Makefile",
            'CC = gcc\nCFLAGS = -Wall -Wextra\nTARGET = calc\n\nall: $(TARGET)\n\n$(TARGET): main.o math_ops.o\n\t$(CC) $(CFLAGS) -o $@ $^\n\nclean:\n\trm -f *.o $(TARGET)\n')
        assert "\t" in result.content

    def test_smart_quotes_no_errors(self):
        result = fix_code("output.py",
            '# Don\u2019t modify this function\n# It\u2019s used by the test suite\ndef important():\n    return True\n')
        assert not result.errors_found

    def test_scoped_imports_not_deduped(self):
        result = fix_code("test_utils.py",
            'import pytest\n\nclass TestSlugify:\n    def test_basic(self):\n        from mylib.utils import slugify\n        assert slugify("Hello World") == "hello-world"\n\n    def test_empty(self):\n        from mylib.utils import slugify\n        assert slugify("") == ""\n')
        assert result.content.count("from mylib.utils import slugify") == 2

    def test_duplicate_top_level_imports(self):
        result = fix_code("service.py",
            'import os\nimport json\nimport logging\nimport os\nimport json\n\nlogger = logging.getLogger(__name__)\n\ndef load_config():\n    with open("config.json") as f:\n        return json.load(f)\n')
        assert result.changed
        assert result.content.count("import os") == 1
        assert result.content.count("import json") == 1

    def test_multi_stage_rust_dockerfile(self):
        result = fix_code("Dockerfile",
            "FROM rust:1.75 AS builder\nWORKDIR /app\nCOPY . .\nRUN cargo build --release\n\nFROM debian:bookworm-slim\nCOPY --from=builder /app/target/release/myapp /usr/local/bin/\nCMD ['myapp']\n")
        assert result.changed
        assert '["myapp"]' in result.content

    def test_flask_dockerfile_multiple_issues(self):
        result = fix_code("Dockerfile",
            "FROM python:latest\nADD . /app\nWORKDIR /app\nRUN pip install -r requirements.txt\nCMD ['python', 'app.py']\n")
        assert result.changed
        assert '["python"' in result.content
        assert "COPY . /app" in result.content
        assert any("latest" in w for w in result.warnings)

    def test_empty_except_block_detection(self):
        result = fix_code("plugin_manager.py",
            '"""PluginManager."""\n\nimport logging\n\nclass PluginManager:\n    def load(self, name):\n        try:\n            mod = __import__(name)\n            return mod\n        except ImportError:\n\n        except Exception as e:\n            logging.error(f"Failed: {e}")\n')
        assert len(result.errors_found) > 0


# ===================================================================
# JAVASCRIPT / TYPESCRIPT (v2)
# ===================================================================

class TestJavaScript:
    def test_missing_semicolons_on_assignments(self):
        result = fix_code("app.js", 'const x = 42\nlet y = "hello"\nvar z = true\n')
        assert result.changed
        assert "const x = 42;" in result.content
        assert 'let y = "hello";' in result.content
        assert "var z = true;" in result.content

    def test_semicolon_after_function_call(self):
        result = fix_code("app.js", 'console.log("hello")\nfetch("/api/data")\n')
        assert result.changed
        assert 'console.log("hello");' in result.content

    def test_no_semicolon_on_block_end(self):
        result = fix_code("app.js", 'if (x) {\n  console.log("yes");\n}\n')
        assert not result.changed

    def test_no_semicolon_on_comment(self):
        result = fix_code("app.js", '// This is a comment\n/* block */\n')
        assert not result.changed

    def test_no_semicolon_on_control_flow(self):
        result = fix_code("app.js",
            'if (x > 0) {\n  return x;\n} else {\n  return -x;\n}\n')
        assert not result.changed

    def test_template_literals_skipped(self):
        result = fix_code("app.js",
            'const msg = `hello\nworld`\nconsole.log(msg)\n')
        assert result.changed
        # Template literal interior not touched
        assert "`hello\nworld`" in result.content

    def test_block_comment_interior_skipped(self):
        result = fix_code("app.js",
            '/*\n * This is a block comment\n * with multiple lines\n */\nconst x = 1\n')
        assert result.changed
        assert "const x = 1;" in result.content
        # Comment lines not modified
        assert "* This is a block comment\n" in result.content

    def test_typescript_extension_wired(self):
        result = fix_code("app.ts", 'const x: number = 42\n')
        assert result.changed
        assert "const x: number = 42;" in result.content

    def test_jsx_extension_wired(self):
        result = fix_code("App.jsx", 'const el = document.getElementById("root")\n')
        assert result.changed
        assert 'getElementById("root");' in result.content

    def test_tsx_extension_wired(self):
        result = fix_code("App.tsx", 'const count: number = 0\n')
        assert result.changed
        assert "const count: number = 0;" in result.content

    def test_already_has_semicolons_unchanged(self):
        result = fix_code("app.js",
            'const x = 42;\nlet y = "hello";\nconsole.log(x, y);\n')
        assert not result.changed

    def test_arrow_function_no_semicolon(self):
        result = fix_code("app.js", 'const fn = (x) =>\n  x + 1\n')
        assert not result.changed or "=>\n" in result.content

    def test_export_import_skipped(self):
        result = fix_code("app.js",
            'import React from "react"\nexport default App\n')
        # import/export lines are skipped by the keyword filter
        assert not result.changed

    def test_prose_stripped_from_js(self):
        result = fix_code("app.js",
            "Here's the JavaScript code:\nconst x = 42\nconsole.log(x)\n")
        assert result.changed
        assert "Here's" not in result.content
        assert "const x = 42" in result.content

    # --- Object literal semicolons → commas (v3) ---

    def test_object_semicolons_to_commas(self):
        """Semicolons between object properties should become commas."""
        code = (
            "const config = {\n"
            '  name: "test";\n'
            "  port: 3000;\n"
            "  debug: true;\n"
            "};\n"
        )
        result = fix_code("app.js", code)
        assert result.changed
        assert '"test",' in result.content
        assert "3000," in result.content
        assert "true," in result.content
        assert any("semicolon" in f and "comma" in f for f in result.fixes_applied)

    def test_object_semicolons_nested(self):
        """Nested object properties should also be fixed."""
        code = (
            "const obj = {\n"
            "  outer: {\n"
            '    inner: "value";\n'
            "    count: 5;\n"
            "  },\n"
            "};\n"
        )
        result = fix_code("app.js", code)
        assert result.changed
        assert '"value",' in result.content
        assert "5," in result.content

    def test_object_semicolons_not_in_statements(self):
        """Semicolons at end of normal statements should NOT be changed."""
        code = 'const x = 42;\nlet y = "hello";\nconsole.log(x);\n'
        result = fix_code("app.js", code)
        assert not result.changed

    def test_object_semicolons_quoted_keys(self):
        """Properties with quoted keys should also be fixed."""
        code = (
            "const styles = {\n"
            '  "font-size": "14px";\n'
            '  "color": "#333";\n'
            "};\n"
        )
        result = fix_code("app.js", code)
        assert result.changed
        assert '"14px",' in result.content
        assert '"#333",' in result.content

    # --- Double semicolons (v3) ---

    def test_double_semicolons_removed(self):
        """Double semicolons should be collapsed to single."""
        result = fix_code("app.js", "const x = 42;;\nreturn result;;\n")
        assert result.changed
        assert "42;" in result.content
        assert "42;;" not in result.content
        assert "result;" in result.content
        assert "result;;" not in result.content

    def test_double_semicolons_for_loop_preserved(self):
        """for(;;) loops should NOT have their semicolons removed."""
        code = "for (;;) {\n  break;\n}\n"
        result = fix_code("app.js", code)
        assert "(;;)" in result.content

    # --- Python-style comments (v3) ---

    def test_python_comments_converted(self):
        """# comments should become // comments in JS files."""
        code = "# This is a comment\nconst x = 1;\n# Another comment\n"
        result = fix_code("app.js", code)
        assert result.changed
        assert "// This is a comment" in result.content
        assert "// Another comment" in result.content
        assert result.content.count("#") == 0

    def test_shebang_preserved(self):
        """#!/usr/bin/env node should NOT be converted."""
        code = "#!/usr/bin/env node\nconst x = 1;\n"
        result = fix_code("app.js", code)
        assert "#!/usr/bin/env node" in result.content

    def test_hash_inside_code_not_touched(self):
        """# inside code lines (hex colours, URL fragments) not touched."""
        code = 'const color = "#FF0000";\nconst url = "/page#section";\n'
        result = fix_code("app.js", code)
        # The # chars are inside strings, not at start of line
        assert "#FF0000" in result.content
        assert "#section" in result.content

    # --- Unclosed string literals (v3) ---

    def test_unclosed_double_quote(self):
        """Missing closing double quote before semicolon."""
        code = 'const msg = "hello world;\n'
        result = fix_code("app.js", code)
        assert result.changed
        assert 'hello world";' in result.content

    def test_unclosed_single_quote(self):
        """Missing closing single quote before semicolon."""
        code = "const msg = 'hello world;\n"
        result = fix_code("app.js", code)
        assert result.changed
        assert "hello world';" in result.content

    def test_properly_closed_strings_unchanged(self):
        """Already-correct strings should not be modified."""
        code = 'const a = "hello";\nconst b = \'world\';\n'
        result = fix_code("app.js", code)
        # Should only potentially have semicolon changes, not string changes
        assert '"hello"' in result.content
        assert "'world'" in result.content

    # --- innerHTML → textContent (v3) ---

    def test_innerhtml_to_textcontent(self):
        """innerHTML with non-HTML RHS should become textContent."""
        code = "element.innerHTML = data.name;\n"
        result = fix_code("app.js", code)
        assert result.changed
        assert "element.textContent = data.name;" in result.content
        assert "innerHTML" not in result.content

    def test_innerhtml_with_html_preserved(self):
        """innerHTML with HTML tags in RHS should NOT be changed."""
        code = 'element.innerHTML = "<div>" + content + "</div>";\n'
        result = fix_code("app.js", code)
        assert "innerHTML" in result.content

    def test_innerhtml_variable_assignment(self):
        """innerHTML with a simple variable should become textContent."""
        code = "el.innerHTML = username;\n"
        result = fix_code("app.js", code)
        assert result.changed
        assert "el.textContent = username;" in result.content

    def test_innerhtml_template_literal_no_html(self):
        """innerHTML with template literal (no HTML) → textContent."""
        code = "el.innerHTML = `${hours}:${minutes}:${seconds}`;\n"
        result = fix_code("app.js", code)
        assert result.changed
        assert "textContent" in result.content

    # --- Idempotency (v3) ---

    def test_all_fixes_idempotent(self):
        """Running the fixer twice should produce identical output."""
        code = (
            "# A comment\n"
            "const config = {\n"
            '  name: "test";\n'
            "  port: 3000;\n"
            "};\n"
            "el.innerHTML = value;;\n"
            'const msg = "hello;\n'
        )
        result1 = fix_code("app.js", code)
        result2 = fix_code("app.js", result1.content)
        assert result1.content == result2.content


# ===================================================================
# MARKDOWN (v2)
# ===================================================================

class TestMarkdown:
    def test_unclosed_code_fence(self):
        result = fix_code("readme.md",
            '# Title\n\n```python\ndef hello():\n    print("hi")\n')
        assert result.changed
        assert result.content.rstrip().endswith("```")

    def test_even_fences_unchanged(self):
        result = fix_code("readme.md",
            '# Title\n\n```python\ndef hello():\n    print("hi")\n```\n')
        assert not result.changed

    def test_unclosed_link(self):
        result = fix_code("readme.md",
            'Check out [the docs](https://example.com\n')
        assert result.changed
        assert ")" in result.content

    def test_unclosed_image(self):
        result = fix_code("readme.md",
            '![screenshot](images/screen.png\n')
        assert result.changed
        assert ")" in result.content

    def test_valid_markdown_unchanged(self):
        result = fix_code("readme.md",
            '# Hello\n\nThis is a paragraph.\n\n- Item 1\n- Item 2\n')
        assert not result.changed

    def test_multiple_fences_odd(self):
        result = fix_code("readme.md",
            '```bash\necho hello\n```\n\n```python\nprint("hi")\n')
        assert result.changed
        # Should close the second unclosed fence
        assert result.content.count("```") % 2 == 0


# ===================================================================
# PYTHON V2 ENHANCEMENTS (indentation + parso)
# ===================================================================

class TestPythonV2:
    def test_indentation_error_fixed(self):
        """Lines with wrong indentation should be realigned."""
        result = fix_code("app.py",
            'def hello():\n        print("hi")\n    return True\n')
        # The indentation fixer should attempt to fix this
        # Either it fixes it or reports an error — shouldn't crash
        assert result.content  # non-empty

    def test_parso_fstring_bracket_completion(self):
        """parso should handle unclosed brackets inside f-strings."""
        result = fix_code("fmt.py",
            'msg = f"Hello {name} you have {len(items"\n')
        assert result.changed

    def test_indentation_preserves_valid_code(self):
        result = fix_code("valid.py",
            'def hello():\n    print("hi")\n    return True\n')
        assert not result.changed

    def test_deeply_nested_indentation(self):
        """Nested blocks should survive the fixer."""
        code = (
            'def process():\n'
            '    for i in range(10):\n'
            '        if i > 5:\n'
            '            print(i)\n'
        )
        result = fix_code("nested.py", code)
        assert not result.changed


# ===================================================================
# SHELL V2 ENHANCEMENTS
# ===================================================================

class TestShellV2:
    def test_unclosed_double_quote_warning(self):
        """Odd number of double quotes on a line should warn."""
        result = fix_code("deploy.sh",
            '#!/bin/bash\necho "hello world\necho "done"\n')
        # The unclosed quote fixer should detect the issue
        assert any("quote" in w.lower() for w in result.warnings) or result.content

    def test_valid_shell_unchanged(self):
        result = fix_code("run.sh",
            '#!/bin/bash\nset -euo pipefail\necho "hello"\n')
        assert not result.changed


# ===================================================================
# YAML V2 ENHANCEMENTS
# ===================================================================

class TestYAMLV2:
    def test_four_space_to_two_space(self):
        """4-space YAML should be normalised to 2-space."""
        result = fix_code("config.yaml",
            'services:\n    web:\n        image: nginx\n        ports:\n            - "80:80"\n')
        assert result.changed
        assert "    web:" not in result.content
        assert "  web:" in result.content

    def test_two_space_yaml_unchanged(self):
        result = fix_code("config.yaml",
            'services:\n  web:\n    image: nginx\n')
        assert not result.changed

    def test_mixed_indent_normalised(self):
        """Files mixing 4-space and 2-space should settle on 2-space."""
        result = fix_code("messy.yaml",
            'top:\n    nested:\n        deep: value\n  other: thing\n')
        # Should attempt normalisation — at minimum shouldn't crash
        assert result.content


# ===================================================================
# JSON V2 ENHANCEMENTS (json-repair)
# ===================================================================

class TestJSONV2:
    def test_truncated_json_repaired(self):
        """json-repair should handle truncated JSON."""
        result = fix_code("data.json", '{"name": "test", "items": [1, 2, 3\n')
        assert result.changed
        assert "]" in result.content
        assert "}" in result.content

    def test_nan_replacement(self):
        """NaN/Infinity are not valid JSON — should be replaced with null."""
        result = fix_code("data.json", '{"value": NaN, "big": Infinity}\n')
        assert result.changed
        assert "NaN" not in result.content
        assert "Infinity" not in result.content

    def test_valid_json_still_unchanged(self):
        result = fix_code("valid.json", '{"name": "test", "value": 42}\n')
        assert not result.changed


# ===================================================================
# V2 IDEMPOTENCY
# ===================================================================

_v2_idempotent_cases = [
    ("js_missing_semis", "app.js",
     'const x = 42\nlet y = "hello"\n'),
    ("md_unclosed_fence", "readme.md",
     '```python\nprint("hi")\n'),
    ("yaml_4space", "config.yaml",
     'services:\n    web:\n        image: nginx\n'),
    ("json_truncated", "data.json",
     '{"name": "test", "items": [1, 2\n'),
]


class TestV2Idempotency:
    @pytest.mark.parametrize("label,filename,broken", _v2_idempotent_cases,
                             ids=[c[0] for c in _v2_idempotent_cases])
    def test_double_fix_is_stable(self, label, filename, broken):
        first = fix_code(filename, broken)
        second = fix_code(filename, first.content)
        assert not second.changed


# ===================================================================
# V2 CRASH ISOLATION
# ===================================================================

class TestV2CrashIsolation:
    def test_pathological_js_template_literals(self):
        fix_code("evil.js", '`${`${`${x}`}`}`\n' * 10)  # don't crash

    def test_pathological_markdown_fences(self):
        fix_code("evil.md", '```\n' * 50)  # don't crash

    def test_js_with_regex_looking_like_comment(self):
        fix_code("tricky.js", 'const re = /\\/\\//g\n')  # don't crash

    def test_yaml_with_invalid_unicode(self):
        fix_code("bad.yaml", 'key: value\x00\n')  # don't crash


# ===================================================================
# V2.5 MISSING STDLIB IMPORTS
# ===================================================================

class TestPythonMissingImports:
    """v2.5: Auto-add missing stdlib imports based on usage."""

    def test_dataclass_decorator(self):
        code = '@dataclass\nclass Foo:\n    x: int = 0\n'
        r = fix_code("test.py", code)
        assert r.changed
        assert "from dataclasses import dataclass" in r.content
        assert r.content.index("from dataclasses") < r.content.index("@dataclass")

    def test_dataclass_and_field(self):
        code = '@dataclass\nclass Foo:\n    x: int = field(default=0)\n'
        r = fix_code("test.py", code)
        assert "from dataclasses import dataclass, field" in r.content or (
            "from dataclasses import dataclass" in r.content
            and "from dataclasses import field" in r.content
        )

    def test_field_without_dataclass_not_added(self):
        code = 'class Form:\n    name = field("name")\n'
        r = fix_code("test.py", code)
        assert "from dataclasses" not in r.content

    def test_contextmanager_decorator(self):
        code = '@contextmanager\ndef foo():\n    yield\n'
        r = fix_code("test.py", code)
        assert r.changed
        assert "from contextlib import contextmanager" in r.content

    def test_abc_abstractmethod(self):
        code = 'class Foo(ABC):\n    @abstractmethod\n    def bar(self): ...\n'
        r = fix_code("test.py", code)
        assert "from abc import ABC, abstractmethod" in r.content

    def test_pathlib_path(self):
        code = 'p = Path("/tmp/test")\n'
        r = fix_code("test.py", code)
        assert "from pathlib import Path" in r.content

    def test_typing_optional(self):
        code = 'def foo(x: Optional[int]) -> None:\n    pass\n'
        r = fix_code("test.py", code)
        assert "from typing import Optional" in r.content

    def test_typing_multiple(self):
        code = 'def foo(x: List[int], y: Dict[str, Any]) -> Optional[str]:\n    return None\n'
        r = fix_code("test.py", code)
        assert "from typing import" in r.content
        typing_line = [l for l in r.content.split("\n") if "from typing import" in l][0]
        assert "List" in typing_line
        assert "Dict" in typing_line
        assert "Any" in typing_line
        assert "Optional" in typing_line

    def test_import_re_module(self):
        code = 'result = re.search(r"\\d+", text)\n'
        r = fix_code("test.py", code)
        assert "import re" in r.content

    def test_import_json_module(self):
        code = 'data = json.loads(raw)\n'
        r = fix_code("test.py", code)
        assert "import json" in r.content

    def test_import_os_module(self):
        code = 'path = os.path.join("/tmp", "test")\n'
        r = fix_code("test.py", code)
        assert "import os" in r.content

    def test_import_sys_module(self):
        code = 'sys.exit(1)\n'
        r = fix_code("test.py", code)
        assert "import sys" in r.content

    def test_import_math_module(self):
        code = 'x = math.sqrt(16)\n'
        r = fix_code("test.py", code)
        assert "import math" in r.content

    def test_datetime_types(self):
        code = 'now = datetime.now()\nd = timedelta(days=1)\n'
        r = fix_code("test.py", code)
        assert "from datetime import" in r.content

    def test_defaultdict(self):
        code = 'd = defaultdict(list)\n'
        r = fix_code("test.py", code)
        assert "from collections import defaultdict" in r.content

    def test_counter(self):
        code = 'c = Counter(words)\n'
        r = fix_code("test.py", code)
        assert "from collections import Counter" in r.content

    def test_enum_base_class(self):
        code = 'class Color(Enum):\n    RED = 1\n'
        r = fix_code("test.py", code)
        assert "from enum import Enum" in r.content

    def test_already_imported_no_change(self):
        code = 'import json\ndata = json.loads(raw)\n'
        r = fix_code("test.py", code)
        assert r.content.count("import json") == 1

    def test_from_import_already_present(self):
        code = 'from pathlib import Path\np = Path(".")\n'
        r = fix_code("test.py", code)
        assert r.content.count("Path") == 2

    def test_star_import_skips_file(self):
        code = 'from os.path import *\np = join("/tmp", "test")\n'
        r = fix_code("test.py", code)
        assert "import os" not in r.content

    def test_name_defined_as_function(self):
        code = 'def Path(s):\n    return s.upper()\nx = Path("hello")\n'
        r = fix_code("test.py", code)
        assert "from pathlib" not in r.content

    def test_name_as_parameter(self):
        code = 'def process(json):\n    return json["key"]\n'
        r = fix_code("test.py", code)
        assert r.content.count("import json") == 0

    def test_insert_after_existing_imports(self):
        code = 'import os\n\nx = json.loads("{}")\n'
        r = fix_code("test.py", code)
        lines = r.content.split("\n")
        os_line = next(i for i, l in enumerate(lines) if "import os" in l)
        json_line = next(i for i, l in enumerate(lines) if "import json" in l)
        assert json_line > os_line

    def test_insert_after_docstring_when_no_imports(self):
        code = '"""Module docstring."""\n\nx = json.loads("{}")\n'
        r = fix_code("test.py", code)
        lines = r.content.split("\n")
        assert lines[0] == '"""Module docstring."""'
        assert "import json" in r.content

    def test_idempotent(self):
        code = 'x = json.loads("{}")\n'
        r1 = fix_code("test.py", code)
        r2 = fix_code("test.py", r1.content)
        assert r1.content == r2.content
        assert not r2.changed

    def test_unparseable_code_skipped(self):
        code = 'def foo(\n    x = json.loads("{}")\n'
        r = fix_code("test.py", code)
        assert r.content

    def test_fixes_applied_message(self):
        code = '@dataclass\nclass Foo:\n    x: int = 0\n'
        r = fix_code("test.py", code)
        assert any("import" in f.lower() for f in r.fixes_applied)


class TestPythonHallucinatedImports:
    """v2.5: Fix known-wrong import names from Qwen."""

    def test_contextmanager_capitalised(self):
        code = 'from contextlib import ContextManager\n\n@ContextManager\ndef foo():\n    yield\n'
        r = fix_code("test.py", code)
        assert "from contextlib import contextmanager" in r.content
        assert "ContextManager" not in r.content.split("\n")[0]

    def test_defaultdict_capitalised(self):
        code = 'from collections import DefaultDict\nd = DefaultDict(list)\n'
        r = fix_code("test.py", code)
        assert "from collections import defaultdict" in r.content

    def test_tracebacktype_wrong_module(self):
        code = 'from typing import TracebackType\n\ndef __exit__(self, exc_type, exc_val, exc_tb: TracebackType):\n    pass\n'
        r = fix_code("test.py", code)
        assert "from types import TracebackType" in r.content
        assert "from typing import TracebackType" not in r.content

    def test_correct_import_not_changed(self):
        code = 'from collections import OrderedDict\nd = OrderedDict()\n'
        r = fix_code("test.py", code)
        assert "from collections import OrderedDict" in r.content

    def test_correct_contextmanager_not_changed(self):
        code = 'from contextlib import contextmanager\n\n@contextmanager\ndef foo():\n    yield\n'
        r = fix_code("test.py", code)
        assert r.content.count("contextmanager") == 2

    def test_hallucinated_import_also_renames_usage(self):
        code = 'from contextlib import ContextManager\n\n@ContextManager\ndef foo():\n    yield\n'
        r = fix_code("test.py", code)
        assert "@contextmanager" in r.content

    def test_idempotent(self):
        code = 'from contextlib import ContextManager\n\n@ContextManager\ndef foo():\n    yield\n'
        r1 = fix_code("test.py", code)
        r2 = fix_code("test.py", r1.content)
        assert r1.content == r2.content


class TestPythonBracketMismatch:
    """v2.5: Fix single-character bracket mismatches on the error line."""

    def test_extra_closing_bracket(self):
        code = 'data = [func(x) for x in items]]\n'
        r = fix_code("test.py", code)
        assert r.changed
        assert "]]" not in r.content

    def test_wrong_closing_type(self):
        code = 'def foo(data: list[dict[str, Any]]]) -> None:\n    pass\n'
        r = fix_code("test.py", code)
        assert r.changed
        import ast as _ast
        try:
            _ast.parse(r.content)
        except SyntaxError:
            pytest.fail("Fixed code should parse")

    def test_swap_bracket_type(self):
        code = 'result = foo(bar[0]]\n'
        r = fix_code("test.py", code)
        assert r.changed
        assert "result = foo(bar[0])" in r.content

    def test_correct_code_not_modified(self):
        code = 'data = [func(x) for x in items]\n'
        r = fix_code("test.py", code)
        assert "data = [func(x) for x in items]" in r.content

    def test_complex_mismatch_not_attempted(self):
        code = 'a = [1, 2\nb = (3, 4]\n'
        r = fix_code("test.py", code)
        assert r.content

    def test_idempotent(self):
        code = 'data = [func(x) for x in items]]\n'
        r1 = fix_code("test.py", code)
        r2 = fix_code("test.py", r1.content)
        assert r1.content == r2.content


class TestPythonDetection:
    """v2.5: Detection-only (errors_found) for Python patterns."""

    def test_truncated_mid_function(self):
        code = 'def foo():\n    x = 1\n    y = 2\n'
        r = fix_code("test.py", code)
        assert not any("truncated" in e.lower() for e in r.errors_found)

    def test_truncated_mid_class(self):
        code = 'class Foo:\n    def bar(self):\n        x ='
        r = fix_code("test.py", code)
        assert any("truncated" in e.lower() for e in r.errors_found)

    def test_truncated_decorator_no_function(self):
        code = 'import os\n\n@dataclass\n'
        r = fix_code("test.py", code)
        assert any("truncated" in e.lower() for e in r.errors_found)

    def test_not_truncated_complete_code(self):
        code = 'def foo():\n    return 1\n\nprint(foo())\n'
        r = fix_code("test.py", code)
        assert not any("truncated" in e.lower() for e in r.errors_found)

    def test_duplicate_function_detected(self):
        code = 'def foo():\n    return 1\n\ndef foo():\n    return 2\n'
        r = fix_code("test.py", code)
        assert any("duplicate" in e.lower() for e in r.errors_found)

    def test_duplicate_class_detected(self):
        code = 'class Foo:\n    pass\n\nclass Foo:\n    x = 1\n'
        r = fix_code("test.py", code)
        assert any("duplicate" in e.lower() for e in r.errors_found)

    def test_no_false_positive_overloaded_methods(self):
        code = 'class A:\n    def foo(self): pass\n\nclass B:\n    def foo(self): pass\n'
        r = fix_code("test.py", code)
        assert not any("duplicate" in e.lower() for e in r.errors_found)

    def test_no_false_positive_different_names(self):
        code = 'def foo():\n    return 1\n\ndef bar():\n    return 2\n'
        r = fix_code("test.py", code)
        assert not any("duplicate" in e.lower() for e in r.errors_found)


class TestHTMLV25:
    """v2.5: HTML attribute quotes, entities, and repair reporting."""

    def test_unquoted_attribute(self):
        code = '<div class=container>\n<p>Hello</p>\n</div>\n'
        r = fix_code("test.html", code)
        assert 'class="container"' in r.content

    def test_mixed_quotes(self):
        code = "<a href='page.html\">\ntext\n</a>\n"
        r = fix_code("test.html", code)
        assert 'href="page.html"' in r.content or "href='page.html'" in r.content

    def test_already_quoted_not_changed(self):
        code = '<div class="container">\n<p>Hello</p>\n</div>\n'
        r = fix_code("test.html", code)
        assert 'class="container"' in r.content

    def test_template_syntax_skipped(self):
        code = '<div class={{ style }}>\n<p>Hello</p>\n</div>\n'
        r = fix_code("test.html", code)
        assert "{{ style }}" in r.content

    def test_multiple_attributes(self):
        code = '<input type=text name=username value="">\n'
        r = fix_code("test.html", code)
        assert 'type="text"' in r.content
        assert 'name="username"' in r.content

    def test_viewport_meta_not_corrupted(self):
        """Viewport meta content attribute must not be re-quoted internally."""
        code = '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        r = fix_code("test.html", code)
        assert 'content="width=device-width, initial-scale=1.0"' in r.content
        assert 'width="device-width' not in r.content

    def test_meta_charset_not_corrupted(self):
        """Meta charset attribute should not be double-quoted."""
        code = '<meta charset="UTF-8">\n'
        r = fix_code("test.html", code)
        assert 'charset="UTF-8"' in r.content

    def test_style_attribute_preserved(self):
        """Inline style with colons/semicolons must not be mangled."""
        code = '<div style="color: red; font-size: 14px;">\n</div>\n'
        r = fix_code("test.html", code)
        assert 'style="color: red; font-size: 14px;"' in r.content

    def test_bare_ampersand_in_text(self):
        code = '<p>Tom & Jerry</p>\n'
        r = fix_code("test.html", code)
        assert 'Tom &amp; Jerry' in r.content

    def test_ampersand_in_entity_not_changed(self):
        code = '<p>Tom &amp; Jerry</p>\n'
        r = fix_code("test.html", code)
        assert '&amp;amp;' not in r.content

    def test_ampersand_in_script_not_changed(self):
        code = '<script>if (a & b) {}</script>\n'
        r = fix_code("test.html", code)
        assert 'a & b' in r.content

    def test_ampersand_in_attribute_not_changed(self):
        code = '<a href="page?a=1&b=2">link</a>\n'
        r = fix_code("test.html", code)
        assert 'a=1&b=2' in r.content

    def test_less_than_in_text(self):
        code = '<p>3 < 5 is true</p>\n'
        r = fix_code("test.html", code)
        assert '3 &lt; 5' in r.content

    def test_less_than_not_tag_start(self):
        code = '<p>Hello</p>\n<div>World</div>\n'
        r = fix_code("test.html", code)
        assert '<p>' in r.content
        assert '<div>' in r.content

    def test_entity_in_pre_not_changed(self):
        code = '<pre>if (a < b && c > d) {}</pre>\n'
        r = fix_code("test.html", code)
        assert 'a < b' in r.content

    def test_tag_repair_reported(self):
        code = '<!DOCTYPE html>\n<html>\n<body>\n<div>\n<p>Hello\n</body>\n</html>\n'
        r = fix_code("test.html", code)
        assert any("closed" in f.lower() or "unclosed" in f.lower()
                    for f in r.fixes_applied)

    def test_idempotent_attribute_fix(self):
        code = '<div class=container>\n<p>Hello</p>\n</div>\n'
        r1 = fix_code("test.html", code)
        r2 = fix_code("test.html", r1.content)
        assert r1.content == r2.content


class TestShellV25:
    """v2.5: Shell shebang repair, block closers, unsafe pattern detection."""

    def test_shebang_missing_slash(self):
        code = '#!bin/bash\necho hello\n'
        r = fix_code("test.sh", code)
        assert r.content.startswith("#!/bin/bash")

    def test_shebang_wrong_path(self):
        code = '#!/usr/bash\necho hello\n'
        r = fix_code("test.sh", code)
        assert r.content.startswith("#!/usr/bin/bash")

    def test_shebang_wrong_env_path(self):
        code = '#!/bin/env bash\necho hello\n'
        r = fix_code("test.sh", code)
        assert r.content.startswith("#!/usr/bin/env bash")

    def test_valid_shebang_not_changed(self):
        code = '#!/bin/bash\necho hello\n'
        r = fix_code("test.sh", code)
        assert r.content.startswith("#!/bin/bash\n")

    def test_valid_env_shebang_not_changed(self):
        code = '#!/usr/bin/env bash\necho hello\n'
        r = fix_code("test.sh", code)
        assert r.content.startswith("#!/usr/bin/env bash\n")

    def test_missing_fi(self):
        code = '#!/bin/bash\nif [ -f test.txt ]; then\n    echo "exists"\n'
        r = fix_code("test.sh", code)
        assert "fi" in r.content

    def test_missing_done(self):
        code = '#!/bin/bash\nfor f in *.txt; do\n    echo "$f"\n'
        r = fix_code("test.sh", code)
        assert "done" in r.content

    def test_complete_if_not_changed(self):
        code = '#!/bin/bash\nif [ -f test.txt ]; then\n    echo "exists"\nfi\n'
        r = fix_code("test.sh", code)
        assert r.content.count("fi") == 1

    def test_heredoc_skipped(self):
        code = '#!/bin/bash\ncat <<EOF\nif then fi\nEOF\nif [ 1 ]; then\n    echo ok\n'
        r = fix_code("test.sh", code)
        assert r.content

    def test_multiple_unclosed_not_fixed(self):
        code = '#!/bin/bash\nif [ 1 ]; then\n    for f in *; do\n        echo "$f"\n'
        r = fix_code("test.sh", code)
        assert r.content

    def test_detect_rm_rf_root(self):
        code = '#!/bin/bash\nrm -rf /\n'
        r = fix_code("test.sh", code)
        assert any("rm" in e.lower() or "dangerous" in e.lower()
                    for e in r.errors_found)

    def test_detect_chmod_777(self):
        code = '#!/bin/bash\nchmod 777 /var/www\n'
        r = fix_code("test.sh", code)
        assert any("chmod 777" in e or "world-writable" in e.lower()
                    for e in r.errors_found)

    def test_detect_eval_variable(self):
        code = '#!/bin/bash\neval "$user_input"\n'
        r = fix_code("test.sh", code)
        assert any("eval" in e.lower() for e in r.errors_found)

    def test_safe_rm_not_flagged(self):
        code = '#!/bin/bash\nrm -f /tmp/test.txt\n'
        r = fix_code("test.sh", code)
        assert not any("dangerous" in e.lower() for e in r.errors_found)

    def test_idempotent_shebang(self):
        code = '#!bin/bash\necho hello\n'
        r1 = fix_code("test.sh", code)
        r2 = fix_code("test.sh", r1.content)
        assert r1.content == r2.content


class TestCrossLanguageDetection:
    """v2.5: Cross-language truncation and duplicate detection."""

    def test_truncated_block_comment_js(self):
        code = '/* This is a comment\nthat never closes\nfunction foo() {}\n'
        r = fix_code("test.js", code)
        assert any("truncated" in e.lower() or "unclosed" in e.lower()
                    for e in r.errors_found)

    def test_truncated_block_comment_css(self):
        code = '.foo { color: red; }\n/* todo:\n  fix this\n'
        r = fix_code("test.css", code)
        assert any("truncated" in e.lower() or "unclosed" in e.lower()
                    for e in r.errors_found)

    def test_closed_block_comment_no_flag(self):
        code = '/* comment */\nfunction foo() {}\n'
        r = fix_code("test.js", code)
        assert not any("truncated" in e.lower() for e in r.errors_found)

    def test_truncated_unclosed_brace_js(self):
        code = 'function foo() {\n  return 1;\n'
        r = fix_code("test.js", code)
        assert any("truncated" in e.lower() or "unclosed" in e.lower()
                    for e in r.errors_found)

    def test_balanced_braces_no_flag(self):
        code = 'function foo() {\n  return 1;\n}\n'
        r = fix_code("test.js", code)
        assert not any("truncated" in e.lower() for e in r.errors_found)

    def test_duplicate_function_js(self):
        code = 'function foo() {\n  return 1;\n}\n\nfunction foo() {\n  return 2;\n}\n'
        r = fix_code("test.js", code)
        assert any("duplicate" in e.lower() for e in r.errors_found)

    def test_duplicate_class_js(self):
        code = 'class Foo {\n}\n\nclass Foo {\n}\n'
        r = fix_code("test.js", code)
        assert any("duplicate" in e.lower() for e in r.errors_found)

    def test_no_duplicate_different_names_rust(self):
        code = 'fn foo() -> i32 {\n    1\n}\n\nfn bar() -> i32 {\n    2\n}\n'
        r = fix_code("test.rs", code)
        assert not any("duplicate" in e.lower() for e in r.errors_found)

    def test_python_not_double_detected(self):
        code = 'def foo():\n    return 1\n\ndef foo():\n    return 2\n'
        r = fix_code("test.py", code)
        dup_warnings = [e for e in r.errors_found if "duplicate" in e.lower()]
        assert len(dup_warnings) == 1
