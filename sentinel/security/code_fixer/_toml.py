"""TOML validation module.

No common deterministic fixes for TOML — just detection and reporting.
"""
import logging
import tomllib

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Layer 3: TOML validation
# ---------------------------------------------------------------------------

def fix_toml(content: str) -> FixResult:
    """Validate TOML. No common deterministic fixes — just detection."""
    result = FixResult(content=content)
    try:
        tomllib.loads(content)
    except tomllib.TOMLDecodeError as e:
        result.errors_found.append(f"TOMLDecodeError: {e}")
        logger.debug(
            "TOML validation error detected",
            extra={
                "event": "validation_rejected",
                "fixer": "fix_toml",
                "file": _current_filename.get(),
                "error_summary": str(e),
            },
        )
    return result
