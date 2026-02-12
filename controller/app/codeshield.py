import logging

from .models import ScanMatch, ScanResult

logger = logging.getLogger("sentinel.audit")

_scanner = None
_loaded = False


class CodeShieldError(Exception):
    """Error from CodeShield scanning."""


def initialize() -> bool:
    """Load the CodeShield scanner. Returns True on success."""
    global _scanner, _loaded

    try:
        from llamafirewall import CodeShieldScanner

        _scanner = CodeShieldScanner()
        _loaded = True
        logger.info(
            "CodeShield loaded",
            extra={"event": "codeshield_loaded"},
        )
        return True
    except ImportError:
        logger.warning(
            "llamafirewall not installed — CodeShield disabled",
            extra={"event": "codeshield_import_failed"},
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


def scan(code: str) -> ScanResult:
    """Scan code for security issues using CodeShield.

    If not loaded, returns a clean result (graceful degradation —
    deterministic scanners still protect the pipeline).
    """
    if not _loaded or _scanner is None:
        return ScanResult(
            found=False,
            matches=[],
            scanner_name="codeshield",
        )

    try:
        result = _scanner.scan(code)
        matches = []

        if result.is_insecure:
            for issue in getattr(result, "issues", []):
                matches.append(
                    ScanMatch(
                        pattern_name=f"codeshield_{getattr(issue, 'rule', 'unknown')}",
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

        return ScanResult(
            found=len(matches) > 0,
            matches=matches,
            scanner_name="codeshield",
        )
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
