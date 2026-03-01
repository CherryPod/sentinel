"""Direct Semgrep scanner — replaces the abandoned CodeShield wrapper.

Invokes semgrep CLI directly against curated rule sets, bypassing
CodeShield's broken wrapper (Issue #91, osemgrep pattern-not bug).

Public API matches the old codeshield.py for minimal caller changes:
  initialize(rules_dir, timeout) -> bool
  is_loaded() -> bool
  scan_blocks(blocks) -> ScanResult
  scan(code) -> ScanResult
"""

import asyncio
import json
import logging
import shutil
import sys
import tempfile
import threading
from pathlib import Path

from sentinel.core.models import ScanMatch, ScanResult

logger = logging.getLogger("sentinel.audit")

# Semgrep writes settings/logs to ~/.semgrep — redirect to /tmp for read-only containers
_SEMGREP_ENV = {
    **__import__("os").environ,
    "XDG_CONFIG_HOME": "/tmp",
    "XDG_CACHE_HOME": "/tmp",
    "SEMGREP_SEND_METRICS": "off",
}

# Rules that produce findings but should NOT block the response.
# Matches are still logged (audit trail) but don't set found=True.
_WARN_ONLY_RULES: frozenset[str] = frozenset({
    "insecure-crypto-prng-random",  # CWE-338: flags all random.X(), not just crypto
    "insecure-hardcoded-secrets",   # CWE-798: variable-name matching FPs on test fixtures
    "crypto-fixed-prng-seed",      # CWE-338: FPs on test determinism (random.seed(42))
    "insecure-math-random",        # CWE-338: JS Math.random(), not always crypto context
    "insecure-random",             # CWE-338: Java new Random(), not always crypto context
    "insecure-cookie",             # CWE-614: client-side cookie, high FP rate
})

# Default rules directory relative to project root
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep"


def _find_semgrep() -> str:
    """Find the semgrep binary — checks venv bin dir first, then PATH."""
    # Check alongside the running Python interpreter (handles venv installs)
    venv_bin = Path(sys.executable).parent / "semgrep"
    if venv_bin.is_file():
        return str(venv_bin)
    # Fall back to system PATH
    found = shutil.which("semgrep")
    return found or "semgrep"

# Language → file extension mapping (code_extractor uses similar mapping)
_LANG_EXTENSION: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "csharp": ".cs",
    "php": ".php",
    "ruby": ".rb",
    "go": ".go",
    "rust": ".rs",
    "bash": ".sh",
    "shell": ".sh",
}

# Language → rules subdirectory mapping (some languages share a directory)
_LANG_RULES_DIR: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java": "java",
    "c": "c",
    "cpp": "c",
    "csharp": "csharp",
    "php": "php",
    "ruby": "ruby",
    "go": "go",
}

_loaded: bool = False
_rules_dir: Path = _DEFAULT_RULES_DIR
_timeout: int = 30
_init_lock = threading.Lock()  # B-002: protect module globals during initialization


def initialize(rules_dir: str | Path | None = None, timeout: int = 30) -> bool:
    """Initialize the Semgrep scanner.

    Checks that semgrep CLI is available and rules directory exists.
    Returns True on success, False on failure (graceful degradation).
    """
    global _loaded, _rules_dir, _timeout

    with _init_lock:
        _timeout = timeout

        if rules_dir is not None:
            _rules_dir = Path(rules_dir)
        else:
            _rules_dir = _DEFAULT_RULES_DIR

        if not _rules_dir.is_dir():
            logger.warning(
                "Semgrep rules directory not found: %s",
                _rules_dir,
                extra={"event": "semgrep_rules_missing", "path": str(_rules_dir)},
            )
            _loaded = False
            return False

        # Verify semgrep CLI is available
        try:
            import subprocess
            semgrep_bin = _find_semgrep()
            result = subprocess.run(
                [semgrep_bin, "--version"],
                capture_output=True, text=True, timeout=10,
                env=_SEMGREP_ENV,
            )
            if result.returncode != 0:
                logger.warning(
                    "semgrep --version failed (returncode=%d)",
                    result.returncode,
                    extra={"event": "semgrep_version_failed"},
                )
                _loaded = False
                return False

            version = result.stdout.strip()
            logger.info(
                "Semgrep scanner initialized (v%s, %s)",
                version, _rules_dir,
                extra={
                    "event": "semgrep_loaded",
                    "version": version,
                    "rules_dir": str(_rules_dir),
                },
            )
            _loaded = True
            return True

        except FileNotFoundError:
            logger.warning(
                "semgrep CLI not found — Semgrep scanner disabled",
                extra={"event": "semgrep_not_found"},
            )
            _loaded = False
            return False
        except Exception as exc:
            logger.warning(
                "Semgrep init failed: %s",
                exc,
                extra={"event": "semgrep_init_failed", "error": str(exc)},
            )
            _loaded = False
            return False


def is_loaded() -> bool:
    return _loaded


async def scan_blocks(blocks: list[tuple[str, str | None]]) -> ScanResult:
    """Scan multiple code blocks individually with optional language hints.

    Each block is scanned separately with its language hint used to select
    the appropriate rule set and file extension. If ANY block has findings,
    the overall result is found=True. All matches are merged.

    Args:
        blocks: list of (code_text, language_hint) tuples where
                language_hint is e.g. "python", "javascript", or None.
    """
    if not _loaded:
        logger.debug(
            "Semgrep not loaded, skipping block scan",
            extra={"event": "semgrep_skipped"},
        )
        return ScanResult(found=False, matches=[], scanner_name="semgrep")

    all_blocking: list[ScanMatch] = []
    all_warn_only: list[ScanMatch] = []

    for code, lang_hint in blocks:
        try:
            blocking, warn_only = await _scan_single(code, lang_hint)
            all_blocking.extend(blocking)
            all_warn_only.extend(warn_only)
        except Exception as exc:
            # B-001: Fail CLOSED — add a blocking match for the failed block
            logger.error(
                "Semgrep block scan error: %s",
                exc,
                extra={"event": "semgrep_block_scan_error", "error": str(exc)},
            )
            all_blocking.append(ScanMatch(
                pattern_name="semgrep_block_error",
                matched_text=f"Scan failed for code block: {exc}",
                position=0,
            ))
            continue

    # Log warn-only findings for audit trail (not blocking)
    if all_warn_only:
        logger.info(
            "Semgrep warn-only findings (not blocking): %d",
            len(all_warn_only),
            extra={
                "event": "semgrep_warn_only",
                "count": len(all_warn_only),
                "rules": [m.pattern_name for m in all_warn_only],
            },
        )

    scan_result = ScanResult(
        found=len(all_blocking) > 0,
        matches=all_blocking,
        scanner_name="semgrep",
    )
    logger.info(
        "Semgrep block scan complete",
        extra={
            "event": "semgrep_block_scan_complete",
            "block_count": len(blocks),
            "issues_count": len(all_blocking),
            "warn_only_count": len(all_warn_only),
        },
    )
    return scan_result


async def scan(code: str, language: str | None = None) -> ScanResult:
    """Scan a single code string for security issues.

    Convenience wrapper around scan_blocks() for single-block scanning.
    """
    return await scan_blocks([(code, language)])


async def _scan_single(
    code: str, language: str | None,
) -> tuple[list[ScanMatch], list[ScanMatch]]:
    """Run semgrep on a single code block, return (blocking, warn_only) matches."""
    lang = (language or "").lower().strip()
    # B-007: .txt fallback is intentional — semgrep needs a file extension,
    # and .txt avoids matching language-specific rules while still allowing
    # generic pattern rules to fire.
    extension = _LANG_EXTENSION.get(lang, ".txt")

    # Determine which rule directories to use
    config_dirs = _get_config_dirs(lang)
    if not config_dirs:
        return [], []

    # Write code to temp file with correct extension
    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="sentinel-semgrep-")
        tmp_file = Path(tmp_dir) / f"scan{extension}"
        tmp_file.write_text(code, encoding="utf-8")

        # Build semgrep command — one --config per rule directory
        cmd = [_find_semgrep(), "--json", "--quiet", "--metrics", "off"]
        for config_dir in config_dirs:
            cmd.extend(["--config", str(config_dir)])
        cmd.append(str(tmp_file))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_SEMGREP_ENV,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_timeout,
        )

        if proc.returncode not in (0, 1):
            # returncode 0 = no findings, 1 = findings found, anything else = error
            # B-001: Fail CLOSED — return a blocking match so the pipeline blocks
            logger.warning(
                "Semgrep exited with code %d: %s",
                proc.returncode,
                stderr.decode("utf-8", errors="replace")[:500],
                extra={
                    "event": "semgrep_exit_error",
                    "returncode": proc.returncode,
                },
            )
            return [ScanMatch(
                pattern_name="semgrep_scan_error",
                matched_text=f"Semgrep exited with error code {proc.returncode}",
                position=0,
            )], []

        return _parse_results(stdout.decode("utf-8", errors="replace"))

    except asyncio.TimeoutError:
        # B-001: Fail CLOSED — return a blocking match on timeout
        logger.warning(
            "Semgrep scan timed out after %ds",
            _timeout,
            extra={"event": "semgrep_timeout", "timeout": _timeout},
        )
        return [ScanMatch(
            pattern_name="semgrep_timeout",
            matched_text=f"Semgrep scan timed out after {_timeout}s",
            position=0,
        )], []
    finally:
        # Clean up temp files
        if tmp_dir is not None:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _get_config_dirs(language: str) -> list[str]:
    """Return list of rule directory paths to use for this language."""
    dirs = []

    # Language-specific rules
    rules_subdir = _LANG_RULES_DIR.get(language)
    if rules_subdir:
        lang_dir = _rules_dir / rules_subdir
        if lang_dir.is_dir():
            dirs.append(str(lang_dir))

    # Always include custom rules (language-agnostic extras)
    custom_dir = _rules_dir / "custom"
    if custom_dir.is_dir() and language in ("python", ""):
        # Custom rules are Python-focused — only include for Python or unknown
        dirs.append(str(custom_dir))

    # If no language match and no custom, scan with all rules
    if not dirs:
        # For unknown languages, try all rules — semgrep will skip non-matching
        if _rules_dir.is_dir():
            dirs.append(str(_rules_dir))

    return dirs


def _parse_results(raw_json: str) -> tuple[list[ScanMatch], list[ScanMatch]]:
    """Parse semgrep JSON output into (blocking, warn_only) match lists."""
    if not raw_json.strip():
        return [], []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return [], []

    blocking: list[ScanMatch] = []
    warn_only: list[ScanMatch] = []
    for result in data.get("results", []):
        rule_id = result.get("check_id", "unknown")
        message = result.get("extra", {}).get("message", "security issue detected")
        line = result.get("start", {}).get("line", 0)

        # Extract CWE from metadata if available
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe_id = ""
        if cwe_list:
            first_cwe = cwe_list[0] if isinstance(cwe_list, list) else str(cwe_list)
            # Extract CWE-NNN from strings like "CWE-78: OS Command Injection"
            if "CWE-" in str(first_cwe):
                cwe_id = str(first_cwe).split(":")[0].strip()

        pattern_name = f"semgrep_{cwe_id}" if cwe_id else f"semgrep_{rule_id}"

        match = ScanMatch(
            pattern_name=pattern_name,
            matched_text=message[:500],
            position=line,
        )

        # Strip directory prefix from rule_id (e.g. "python.insecure-crypto-prng-random")
        bare_rule = rule_id.rsplit(".", 1)[-1] if "." in rule_id else rule_id
        if bare_rule in _WARN_ONLY_RULES:
            warn_only.append(match)
        else:
            blocking.append(match)

    return blocking, warn_only
