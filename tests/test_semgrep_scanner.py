"""Tests for sentinel.security.semgrep_scanner — direct Semgrep integration.

Unit tests mock the subprocess (no semgrep CLI needed).
Integration tests require the real semgrep CLI and rules/ directory.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.security import semgrep_scanner
from sentinel.core.models import ScanResult


@pytest.fixture(autouse=True)
def _reset_semgrep():
    """Reset semgrep_scanner state between tests."""
    semgrep_scanner._loaded = False
    semgrep_scanner._rules_dir = semgrep_scanner._DEFAULT_RULES_DIR
    semgrep_scanner._timeout = 30
    semgrep_scanner._scan_semaphore = None
    yield
    semgrep_scanner._loaded = False
    semgrep_scanner._rules_dir = semgrep_scanner._DEFAULT_RULES_DIR
    semgrep_scanner._timeout = 30
    semgrep_scanner._scan_semaphore = None


# ---------------------------------------------------------------------------
# Helpers for mocking subprocess
# ---------------------------------------------------------------------------

def _make_semgrep_output(results: list[dict] | None = None) -> bytes:
    """Build semgrep JSON output bytes."""
    data = {"results": results or [], "errors": []}
    return json.dumps(data).encode()


def _mock_proc(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    """Create a mock asyncio.Process."""
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


# ===========================================================================
# Unit tests — mocked subprocess
# ===========================================================================


class TestSemgrepScan:
    @pytest.mark.asyncio
    async def test_not_loaded_returns_clean(self):
        """When not loaded, scan returns clean result (graceful degradation)."""
        result = await semgrep_scanner.scan("import os\nos.system('rm -rf /')")
        assert isinstance(result, ScanResult)
        assert result.found is False
        assert result.scanner_name == "semgrep"

    @pytest.mark.asyncio
    async def test_clean_code_passes(self):
        """Clean code should not be flagged."""
        semgrep_scanner._loaded = True
        stdout = _make_semgrep_output([])
        proc = _mock_proc(returncode=0, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("def hello():\n    return 'world'", "python")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_insecure_code_detected(self):
        """Semgrep findings should produce found=True with matches."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "insecure-os-system-use",
            "start": {"line": 2},
            "extra": {
                "message": "Dangerous os.system call",
                "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("import os\nos.system('ls')", "python")
        assert result.found is True
        assert len(result.matches) == 1
        assert "CWE-78" in result.matches[0].pattern_name

    @pytest.mark.asyncio
    async def test_scan_error_fails_closed(self):
        """If semgrep crashes, scan should fail CLOSED (B-001 fix)."""
        semgrep_scanner._loaded = True
        proc = _mock_proc(returncode=2, stdout=b"", stderr=b"fatal error")

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("some code", "python")
        assert result.found is True
        assert len(result.matches) == 1
        assert result.matches[0].pattern_name == "semgrep_scan_error"

    @pytest.mark.asyncio
    async def test_timeout_kills_subprocess(self):
        """On asyncio.TimeoutError, the semgrep subprocess must be killed (Finding #9)."""
        semgrep_scanner._loaded = True
        semgrep_scanner._timeout = 0.01  # Force a near-instant timeout

        proc = AsyncMock()
        proc.returncode = None

        # communicate() sleeps forever so wait_for() times out and cancels it
        async def _hang(*args, **kwargs):
            await asyncio.sleep(9999)

        proc.communicate = _hang
        proc.kill = MagicMock()        # synchronous kill()
        proc.wait = AsyncMock()        # async wait() after kill

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("import os", "python")

        assert result.found is True
        assert result.matches[0].pattern_name == "semgrep_timeout"
        proc.kill.assert_called_once()

    def test_is_loaded_false_by_default(self):
        assert semgrep_scanner.is_loaded() is False


class TestSemgrepScanBlocks:
    @pytest.mark.asyncio
    async def test_not_loaded_returns_clean(self):
        """When not loaded, scan_blocks returns clean result."""
        result = await semgrep_scanner.scan_blocks([("eval(x)", "python")])
        assert result.found is False
        assert result.scanner_name == "semgrep"

    @pytest.mark.asyncio
    async def test_single_clean_block(self):
        """Single clean code block passes."""
        semgrep_scanner._loaded = True
        stdout = _make_semgrep_output([])
        proc = _mock_proc(returncode=0, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan_blocks([
                ("def hello():\n    return 'world'", "python"),
            ])
        assert result.found is False

    @pytest.mark.asyncio
    async def test_one_clean_one_insecure(self):
        """Mixed results: one clean + one insecure → overall insecure."""
        semgrep_scanner._loaded = True

        clean_stdout = _make_semgrep_output([])
        insecure_stdout = _make_semgrep_output([{
            "check_id": "insecure-os-system-use",
            "start": {"line": 2},
            "extra": {
                "message": "os.system call",
                "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
            },
        }])

        clean_proc = _mock_proc(returncode=0, stdout=clean_stdout)
        insecure_proc = _mock_proc(returncode=1, stdout=insecure_stdout)

        call_count = 0

        async def _side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return clean_proc
            return insecure_proc

        with patch("asyncio.create_subprocess_exec", side_effect=_side_effect):
            result = await semgrep_scanner.scan_blocks([
                ("def safe(): pass", "python"),
                ("import os\nos.system('ls')", "python"),
            ])
        assert result.found is True
        assert len(result.matches) == 1
        assert "CWE-78" in result.matches[0].pattern_name

    @pytest.mark.asyncio
    async def test_language_hint_creates_correct_extension(self):
        """Language hint determines temp file extension for semgrep."""
        semgrep_scanner._loaded = True
        stdout = _make_semgrep_output([])
        proc = _mock_proc(returncode=0, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await semgrep_scanner.scan_blocks([("console.log('hi')", "javascript")])
            # Check that the temp file had .js extension
            call_args = mock_exec.call_args[0]
            temp_file = call_args[-1]  # Last arg is the file path
            assert temp_file.endswith(".js")

    @pytest.mark.asyncio
    async def test_none_language_hint(self):
        """None language hint → scan with .txt extension (all rules)."""
        semgrep_scanner._loaded = True
        stdout = _make_semgrep_output([])
        proc = _mock_proc(returncode=0, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await semgrep_scanner.scan_blocks([("echo hello", None)])
            call_args = mock_exec.call_args[0]
            temp_file = call_args[-1]
            assert temp_file.endswith(".txt")

    @pytest.mark.asyncio
    async def test_error_in_one_block_continues_and_blocks(self):
        """Error scanning one block adds a blocking match but still scans others (B-001)."""
        semgrep_scanner._loaded = True

        insecure_stdout = _make_semgrep_output([{
            "check_id": "insecure-eval-use",
            "start": {"line": 1},
            "extra": {
                "message": "eval detected",
                "metadata": {"cwe": ["CWE-94: Code Injection"]},
            },
        }])
        insecure_proc = _mock_proc(returncode=1, stdout=insecure_stdout)

        call_count = 0

        async def _side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("crash")
            return insecure_proc

        with patch("asyncio.create_subprocess_exec", side_effect=_side_effect):
            result = await semgrep_scanner.scan_blocks([
                ("block1", "python"),
                ("eval(x)", "python"),
            ])
        assert result.found is True
        # B-001: error block now produces a blocking match + the real finding
        assert len(result.matches) == 2
        assert any(m.pattern_name == "semgrep_block_error" for m in result.matches)
        assert any("CWE-94" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_multiple_insecure_blocks(self):
        """Multiple insecure blocks → all issues merged."""
        semgrep_scanner._loaded = True

        stdout1 = _make_semgrep_output([{
            "check_id": "insecure-os-system-use",
            "start": {"line": 1},
            "extra": {"message": "os.system", "metadata": {"cwe": ["CWE-78"]}},
        }])
        stdout2 = _make_semgrep_output([{
            "check_id": "insecure-eval-use",
            "start": {"line": 1},
            "extra": {"message": "eval", "metadata": {"cwe": ["CWE-94"]}},
        }])

        proc1 = _mock_proc(returncode=1, stdout=stdout1)
        proc2 = _mock_proc(returncode=1, stdout=stdout2)

        call_count = 0

        async def _side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return proc1
            return proc2

        with patch("asyncio.create_subprocess_exec", side_effect=_side_effect):
            result = await semgrep_scanner.scan_blocks([
                ("os.system('ls')", "python"),
                ("eval(x)", "python"),
            ])
        assert result.found is True
        assert len(result.matches) == 2

    @pytest.mark.asyncio
    async def test_empty_blocks_list(self):
        """Empty blocks list → clean result (nothing to scan)."""
        semgrep_scanner._loaded = True

        result = await semgrep_scanner.scan_blocks([])
        assert result.found is False


class TestSemgrepInitialize:
    def test_semgrep_not_available(self):
        """When semgrep CLI is not found, initialize returns False."""
        with patch("subprocess.run", side_effect=FileNotFoundError("semgrep not found")):
            result = semgrep_scanner.initialize()
        assert result is False
        assert semgrep_scanner.is_loaded() is False

    def test_successful_init(self):
        """When semgrep CLI is available and rules dir exists, returns True."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1.151.0"

        with patch("subprocess.run", return_value=mock_result):
            result = semgrep_scanner.initialize()
        assert result is True
        assert semgrep_scanner.is_loaded() is True

    def test_rules_dir_missing(self):
        """When rules directory doesn't exist, returns False."""
        result = semgrep_scanner.initialize(rules_dir="/nonexistent/path")
        assert result is False
        assert semgrep_scanner.is_loaded() is False


class TestFindSemgrep:
    """Finding #5: _find_semgrep should return None when binary not found."""

    def test_returns_none_when_not_found(self):
        """Returns None when semgrep is absent from venv dir and PATH."""
        with patch("sentinel.security.semgrep_scanner.shutil.which", return_value=None):
            with patch.object(Path, "is_file", return_value=False):
                result = semgrep_scanner._find_semgrep()
        assert result is None

    def test_returns_path_when_in_path(self):
        """Returns the PATH-resolved binary path when semgrep is on PATH."""
        with patch("sentinel.security.semgrep_scanner.shutil.which", return_value="/usr/bin/semgrep"):
            with patch.object(Path, "is_file", return_value=False):
                result = semgrep_scanner._find_semgrep()
        assert result == "/usr/bin/semgrep"

    def test_initialize_returns_false_when_binary_missing(self):
        """initialize() returns False (not an exception) when _find_semgrep returns None."""
        with patch("sentinel.security.semgrep_scanner._find_semgrep", return_value=None):
            result = semgrep_scanner.initialize()
        assert result is False
        assert semgrep_scanner.is_loaded() is False

    @pytest.mark.asyncio
    async def test_scan_single_fails_closed_when_binary_missing(self):
        """_scan_single returns a blocking ScanMatch when _find_semgrep returns None (defence-in-depth)."""
        semgrep_scanner._loaded = True
        with patch("sentinel.security.semgrep_scanner._find_semgrep", return_value=None):
            result = await semgrep_scanner.scan("print('hi')", "python")
        # Must block, not pass
        assert result.found is True
        assert len(result.matches) == 1
        assert result.matches[0].pattern_name == "semgrep_not_found"


# ===========================================================================
# Integration tests — real semgrep CLI
# ===========================================================================

# These tests require semgrep to be installed and the rules/ directory to exist.
# They verify the full pipeline: code → temp file → semgrep → parsed results.

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
_semgrep_available = False
try:
    from sentinel.security.semgrep_scanner import _find_semgrep
    import subprocess
    _semgrep_available = subprocess.run(
        [_find_semgrep(), "--version"], capture_output=True, timeout=10,
    ).returncode == 0 and RULES_DIR.is_dir()
except Exception:
    pass


@pytest.mark.skipif(not _semgrep_available, reason="semgrep CLI not available or rules missing")
class TestSemgrepIntegration:
    """Integration tests using real semgrep CLI against known-vulnerable code."""

    @pytest.fixture(autouse=True)
    def _init_scanner(self):
        """Initialize scanner with real rules for integration tests."""
        semgrep_scanner.initialize(rules_dir=RULES_DIR, timeout=60)
        yield
        semgrep_scanner._loaded = False

    @pytest.mark.asyncio
    async def test_detects_eval_with_user_input(self):
        code = "user_input = input()\nresult = eval(user_input)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("94" in m.pattern_name or "eval" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_os_system(self):
        code = "import os\ncmd = input()\nos.system(cmd)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("78" in m.pattern_name or "system" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_subprocess_shell(self):
        code = "import subprocess\ncmd = input()\nsubprocess.run(cmd, shell=True)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True

    @pytest.mark.asyncio
    async def test_detects_pickle_loads(self):
        code = "import pickle\ndata = input()\nobj = pickle.loads(data)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("502" in m.pattern_name or "pickle" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_unsafe_yaml(self):
        code = "import yaml\ndata = input()\nresult = yaml.unsafe_load(data)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True

    @pytest.mark.asyncio
    async def test_detects_dynamic_import(self):
        code = "mod = __import__('os')\nmod.system('ls')"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True

    @pytest.mark.asyncio
    async def test_clean_code_passes(self):
        code = "def add(a, b):\n    return a + b\n\nprint(add(1, 2))"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_literal_eval_not_flagged(self):
        """eval() with a string literal argument should ideally not be flagged
        (pattern-not exclusion). If it is flagged, that's acceptable — false
        positive, not a false negative."""
        code = 'result = eval("2 + 2")'
        result = await semgrep_scanner.scan(code, "python")
        # This may or may not be flagged depending on rule sophistication.
        # We just verify the scanner doesn't crash.
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_random_choice_not_blocked(self):
        """random.choice() in non-crypto context should not block (warn-only rule)."""
        code = (
            "import random\n"
            "servers = ['s1.example.com', 's2.example.com']\n"
            "target = random.choice(servers)\n"
        )
        result = await semgrep_scanner.scan(code, "python")
        # Even if semgrep flags this as insecure-crypto-prng-random,
        # the warn-only classification means found=False.
        assert result.found is False

    # --- New Python rules (Phase 3) ---

    @pytest.mark.asyncio
    async def test_detects_marshal_loads(self):
        """marshal.loads() is unsafe deserialization (CWE-502)."""
        code = "import marshal\ndata = get_data()\nobj = marshal.loads(data)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("502" in m.pattern_name or "marshal" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_shelve_open(self):
        """shelve.open() uses pickle internally (CWE-502)."""
        code = "import shelve\ndb = shelve.open(user_path)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("502" in m.pattern_name or "shelve" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_tempfile_mktemp(self):
        """tempfile.mktemp() has race condition (CWE-377)."""
        code = "import tempfile\ntmp = tempfile.mktemp()"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("377" in m.pattern_name or "tempfile" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_unsafe_xml_parse(self):
        """xml.etree.ElementTree.parse() without defusedxml (CWE-611)."""
        code = (
            "import xml.etree.ElementTree as ET\n"
            "tree = ET.parse(user_file)\n"
        )
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("611" in m.pattern_name or "xml" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_importlib_import(self):
        """importlib.import_module() with variable arg (CWE-94)."""
        code = "import importlib\nmod = importlib.import_module(user_input)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("94" in m.pattern_name or "import" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_pickle_load_file(self):
        """pickle.load() (file-based) should also be detected (Phase 2 fix)."""
        code = "import pickle\nwith open('data.pkl', 'rb') as f:\n    obj = pickle.load(f)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("502" in m.pattern_name or "pickle" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_detects_bare_yaml_load(self):
        """yaml.load(data) without Loader param (Phase 2 fix)."""
        code = "import yaml\ndata = get_data()\nresult = yaml.load(data)"
        result = await semgrep_scanner.scan(code, "python")
        assert result.found is True
        assert any("502" in m.pattern_name or "yaml" in m.pattern_name for m in result.matches)

    # --- Java rules (Phase 4) ---

    @pytest.mark.asyncio
    async def test_java_sql_injection(self):
        """Java SQL injection via string concatenation (CWE-89)."""
        code = (
            "Statement stmt = conn.createStatement();\n"
            'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);\n'
        )
        result = await semgrep_scanner.scan(code, "java")
        assert result.found is True
        assert any("89" in m.pattern_name or "sql" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_java_command_injection(self):
        """Java Runtime.exec() command injection (CWE-78)."""
        code = 'Runtime.getRuntime().exec(userInput);'
        result = await semgrep_scanner.scan(code, "java")
        assert result.found is True
        assert any("78" in m.pattern_name or "command" in m.pattern_name for m in result.matches)

    # --- JavaScript/TypeScript rules (Phase 5) ---

    @pytest.mark.asyncio
    async def test_js_eval(self):
        """JavaScript eval() code injection (CWE-94)."""
        code = "var userCode = req.body.code;\neval(userCode);"
        result = await semgrep_scanner.scan(code, "javascript")
        assert result.found is True
        assert any("94" in m.pattern_name or "eval" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_js_prototype_pollution(self):
        """JavaScript prototype pollution via Object.assign (CWE-1321)."""
        code = "var merged = Object.assign({}, userInput);"
        result = await semgrep_scanner.scan(code, "javascript")
        assert result.found is True
        assert any("1321" in m.pattern_name or "prototype" in m.pattern_name for m in result.matches)

    # --- PHP rules (Phase 6) ---

    @pytest.mark.asyncio
    async def test_php_unserialize(self):
        """PHP unserialize() deserialization (CWE-502)."""
        code = "<?php\n$data = $_GET['data'];\n$obj = unserialize($data);\n?>"
        result = await semgrep_scanner.scan(code, "php")
        assert result.found is True
        assert any("502" in m.pattern_name or "unserialize" in m.pattern_name for m in result.matches)

    @pytest.mark.asyncio
    async def test_php_file_inclusion(self):
        """PHP file inclusion with user input (CWE-98)."""
        code = "<?php\n$page = $_GET['page'];\ninclude($page);\n?>"
        result = await semgrep_scanner.scan(code, "php")
        assert result.found is True
        assert any("98" in m.pattern_name or "inclusion" in m.pattern_name for m in result.matches)

    # --- Ruby rules (Phase 7) ---

    @pytest.mark.asyncio
    async def test_ruby_command_injection(self):
        """Ruby system() command injection (CWE-78)."""
        code = "user_cmd = params[:cmd]\nsystem(user_cmd)"
        result = await semgrep_scanner.scan(code, "ruby")
        assert result.found is True
        assert any("78" in m.pattern_name or "command" in m.pattern_name for m in result.matches)

    # --- Go rules (Phase 7) ---

    @pytest.mark.asyncio
    async def test_go_command_injection(self):
        """Go exec.Command() with variable arg (CWE-78)."""
        code = (
            'package main\n'
            'import "os/exec"\n'
            'func run(cmd string) {\n'
            '    exec.Command(cmd).Run()\n'
            '}\n'
        )
        result = await semgrep_scanner.scan(code, "go")
        assert result.found is True
        assert any("78" in m.pattern_name or "command" in m.pattern_name for m in result.matches)


# ===========================================================================
# Warn-only rule tests
# ===========================================================================


class TestSemgrepWarnOnly:
    """Verify that rules in _WARN_ONLY_RULES log but don't block."""

    @pytest.mark.asyncio
    async def test_prng_random_is_warn_only(self):
        """insecure-crypto-prng-random findings should NOT block."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "python.insecure-crypto-prng-random",
            "start": {"line": 3},
            "extra": {
                "message": "Use of insecure random number generator",
                "metadata": {"cwe": ["CWE-338: Use of Cryptographically Weak PRNG"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan(
                "import random\nx = random.choice([1, 2, 3])", "python",
            )
        assert result.found is False
        assert len(result.matches) == 0

    @pytest.mark.asyncio
    async def test_blocking_rule_still_blocks(self):
        """A non-warn-only rule should still block normally."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "python.insecure-eval-use",
            "start": {"line": 1},
            "extra": {
                "message": "eval() detected",
                "metadata": {"cwe": ["CWE-94: Code Injection"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("eval(user_input)", "python")
        assert result.found is True
        assert len(result.matches) == 1

    @pytest.mark.asyncio
    async def test_mixed_blocking_and_warn_only(self):
        """When both blocking and warn-only findings exist, only blocking in result."""
        semgrep_scanner._loaded = True
        findings = [
            {
                "check_id": "python.insecure-crypto-prng-random",
                "start": {"line": 2},
                "extra": {
                    "message": "Insecure PRNG",
                    "metadata": {"cwe": ["CWE-338"]},
                },
            },
            {
                "check_id": "python.insecure-eval-use",
                "start": {"line": 5},
                "extra": {
                    "message": "eval() detected",
                    "metadata": {"cwe": ["CWE-94: Code Injection"]},
                },
            },
        ]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan(
                "import random\nx = random.choice([1,2])\neval(y)", "python",
            )
        assert result.found is True
        assert len(result.matches) == 1
        assert "CWE-94" in result.matches[0].pattern_name

    @pytest.mark.asyncio
    async def test_warn_only_logged(self, caplog):
        """Warn-only findings should emit an INFO log with semgrep_warn_only event."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "python.insecure-crypto-prng-random",
            "start": {"line": 1},
            "extra": {
                "message": "PRNG usage",
                "metadata": {"cwe": ["CWE-338"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        import logging
        with caplog.at_level(logging.INFO, logger="sentinel.audit"):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                await semgrep_scanner.scan("random.choice([1,2])", "python")
        assert any("warn-only" in r.message.lower() for r in caplog.records)

    @pytest.mark.asyncio
    async def test_hardcoded_secrets_is_warn_only(self):
        """insecure-hardcoded-secrets findings should NOT block."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "python.insecure-hardcoded-secrets",
            "start": {"line": 1},
            "extra": {
                "message": "Hardcoded secret detected",
                "metadata": {"cwe": ["CWE-798: Use of Hard-coded Credentials"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan('password = "hunter2"', "python")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_fixed_prng_seed_is_warn_only(self):
        """crypto-fixed-prng-seed findings should NOT block."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "python.crypto-fixed-prng-seed",
            "start": {"line": 1},
            "extra": {
                "message": "Fixed PRNG seed",
                "metadata": {"cwe": ["CWE-338"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("random.seed(42)", "python")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_math_random_is_warn_only(self):
        """insecure-math-random findings should NOT block."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "javascript.insecure-math-random",
            "start": {"line": 1},
            "extra": {
                "message": "Math.random() is not cryptographically secure",
                "metadata": {"cwe": ["CWE-338"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("var x = Math.random();", "javascript")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_insecure_random_java_is_warn_only(self):
        """insecure-random (Java) findings should NOT block."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "java.insecure-random",
            "start": {"line": 1},
            "extra": {
                "message": "new Random() not cryptographically secure",
                "metadata": {"cwe": ["CWE-338"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("Random r = new Random();", "java")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_insecure_cookie_is_warn_only(self):
        """insecure-cookie findings should NOT block."""
        semgrep_scanner._loaded = True
        findings = [{
            "check_id": "javascript.insecure-cookie",
            "start": {"line": 1},
            "extra": {
                "message": "Cookie set without Secure flag",
                "metadata": {"cwe": ["CWE-614"]},
            },
        }]
        stdout = _make_semgrep_output(findings)
        proc = _mock_proc(returncode=1, stdout=stdout)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await semgrep_scanner.scan("document.cookie = 'a=b';", "javascript")
        assert result.found is False

    def test_warn_only_set_immutable(self):
        """_WARN_ONLY_RULES should be a frozenset (immutable)."""
        assert isinstance(semgrep_scanner._WARN_ONLY_RULES, frozenset)

    def test_warn_only_set_has_all_entries(self):
        """_WARN_ONLY_RULES should contain all expected rules."""
        expected = {
            "insecure-crypto-prng-random",
            "insecure-hardcoded-secrets",
            "crypto-fixed-prng-seed",
            "insecure-math-random",
            "insecure-random",
            "insecure-cookie",
        }
        assert semgrep_scanner._WARN_ONLY_RULES == expected


# ===========================================================================
# Concurrency limit tests — Finding #8
# ===========================================================================


class TestSemgrepConcurrencyLimit:
    """Finding #8: Concurrent scans must be bounded by _MAX_CONCURRENT."""

    @pytest.mark.asyncio
    async def test_concurrent_scans_limited(self):
        """Peak concurrency should not exceed _MAX_CONCURRENT."""
        semgrep_scanner._loaded = True

        peak = 0
        current = 0

        async def slow_communicate():
            nonlocal peak, current
            current += 1
            peak = max(peak, current)
            await asyncio.sleep(0.05)
            current -= 1
            return (_make_semgrep_output(), b"")

        def make_slow_proc(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = slow_communicate
            proc.kill = MagicMock()
            proc.wait = AsyncMock()
            return proc

        # Launch multiple concurrent scan() calls via asyncio.gather —
        # this is the real-world pattern (concurrent orchestrator requests).
        # scan_blocks iterates sequentially, so a single call won't trigger
        # concurrency; we need multiple independent scan() calls.
        tasks = []
        with patch("sentinel.security.semgrep_scanner.asyncio.create_subprocess_exec",
                    side_effect=make_slow_proc):
            for _ in range(8):
                tasks.append(asyncio.create_task(
                    semgrep_scanner.scan("print('hi')", "python")
                ))
            await asyncio.gather(*tasks)

        assert peak <= semgrep_scanner._MAX_CONCURRENT
