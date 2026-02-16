import logging

from sentinel.core.models import ScanMatch, ScanResult

logger = logging.getLogger("sentinel.audit")

_cs_class = None
_loaded = False


class CodeShieldError(Exception):
    """Error from CodeShield scanning."""


def initialize() -> bool:
    """Load the CodeShield scanner, patching semgrep to fix osemgrep bug.

    The codeshield package ships with osemgrep --experimental as default,
    which has a bug where patterns + pattern-not rules return zero results.
    We patch SEMGREP_COMMAND to use regular semgrep instead.
    """
    global _cs_class, _loaded

    try:
        # Patch the semgrep command BEFORE any scanning happens
        from codeshield.insecure_code_detector import oss

        oss.SEMGREP_COMMAND = [
            "semgrep", "--json", "--quiet", "--metrics", "off", "--config",
        ]
        logger.info(
            "Patched SEMGREP_COMMAND to use semgrep instead of osemgrep",
            extra={"event": "codeshield_semgrep_patched"},
        )

        from codeshield.cs import CodeShield

        _cs_class = CodeShield
        _loaded = True
        logger.info(
            "CodeShield loaded",
            extra={"event": "codeshield_loaded"},
        )

        return True
    except ImportError as exc:
        logger.warning(
            "codeshield package not installed — CodeShield disabled: %s",
            exc,
            extra={"event": "codeshield_import_failed", "error": str(exc)},
        )
        _loaded = False
        return False
    except Exception as exc:
        logger.warning(
            "CodeShield init failed: %s",
            exc,
            extra={"event": "codeshield_init_failed", "error": str(exc)},
        )
        _loaded = False
        return False


def is_loaded() -> bool:
    return _loaded


async def scan(code: str) -> ScanResult:
    """Scan code for security issues using CodeShield.

    If not loaded, returns a clean result (graceful degradation —
    deterministic scanners still protect the pipeline).
    """
    if not _loaded or _cs_class is None:
        logger.debug(
            "CodeShield not loaded, skipping scan",
            extra={"event": "codeshield_skipped", "code_length": len(code)},
        )
        return ScanResult(
            found=False,
            matches=[],
            scanner_name="codeshield",
        )

    try:
        result = await _cs_class.scan_code(code)
        matches = []

        if result.is_insecure:
            for issue in result.issues_found or []:
                matches.append(
                    ScanMatch(
                        pattern_name=f"codeshield_{getattr(issue, 'cwe_id', 'unknown')}",
                        matched_text=getattr(issue, "description", "security issue detected"),
                        position=getattr(issue, "line", 0),
                    )
                )

            # If flagged but no detailed issues, add a generic match
            if not matches:
                matches.append(
                    ScanMatch(
                        pattern_name="codeshield_insecure",
                        matched_text="Code flagged as insecure by CodeShield",
                        position=0,
                    )
                )

        scan_result = ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="codeshield",
        )
        logger.info(
            "CodeShield scan complete",
            extra={
                "event": "codeshield_scan_complete",
                "code_length": len(code),
                "is_insecure": result.is_insecure,
                "issues_count": len(matches),
                "cwe_ids": [m.pattern_name for m in matches] if matches else [],
            },
        )
        return scan_result
    except Exception as exc:
        logger.error(
            "CodeShield scan error: %s",
            exc,
            extra={"event": "codeshield_scan_error", "error": str(exc)},
        )
        return ScanResult(
            found=False,
            matches=[],
            scanner_name="codeshield",
        )
