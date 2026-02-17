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


async def scan_blocks(blocks: list[tuple[str, str | None]]) -> ScanResult:
    """Scan multiple code blocks individually with optional language hints.

    Each block is scanned separately with its language hint passed to
    CodeShield.scan_code(). If ANY block is insecure, the overall result
    is insecure. All issues are merged into a single ScanResult.

    Args:
        blocks: list of (code_text, language_hint) tuples where
                language_hint matches CodeShield Language enum values
                (e.g. "python", "javascript") or None.
    """
    if not _loaded or _cs_class is None:
        logger.debug(
            "CodeShield not loaded, skipping block scan",
            extra={"event": "codeshield_skipped"},
        )
        return ScanResult(found=False, matches=[], scanner_name="codeshield")

    # Lazy-import Language enum (only available when codeshield is installed)
    Language = None
    try:
        from codeshield.insecure_code_detector.languages import Language
    except ImportError:
        pass

    all_matches: list[ScanMatch] = []

    for code, lang_hint in blocks:
        try:
            # Convert language string to Language enum if available
            lang_enum = None
            if lang_hint and Language is not None:
                try:
                    lang_enum = Language(lang_hint)
                except ValueError:
                    pass  # Unknown language, scan without hint

            result = await _cs_class.scan_code(code, language=lang_enum)

            if result.is_insecure:
                block_matches = []
                for issue in result.issues_found or []:
                    block_matches.append(
                        ScanMatch(
                            pattern_name=f"codeshield_{getattr(issue, 'cwe_id', 'unknown')}",
                            matched_text=getattr(issue, 'description', 'security issue detected'),
                            position=getattr(issue, 'line', 0),
                        )
                    )
                # If flagged but no detailed issues, add a generic match
                if not block_matches:
                    block_matches.append(
                        ScanMatch(
                            pattern_name="codeshield_insecure",
                            matched_text="Code flagged as insecure by CodeShield",
                            position=0,
                        )
                    )
                all_matches.extend(block_matches)
        except Exception as exc:
            logger.error(
                "CodeShield block scan error: %s",
                exc,
                extra={"event": "codeshield_block_scan_error", "error": str(exc)},
            )
            continue

    scan_result = ScanResult(
        found=len(all_matches) > 0,
        matches=all_matches,
        scanner_name="codeshield",
    )
    logger.info(
        "CodeShield block scan complete",
        extra={
            "event": "codeshield_block_scan_complete",
            "block_count": len(blocks),
            "issues_count": len(all_matches),
        },
    )
    return scan_result


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
