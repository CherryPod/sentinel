"""PromptGuard scanner — ScannerPlugin wrapper.

Wraps the existing ``prompt_guard.scan()`` module-level function in the
unified ScannerPlugin interface.  The underlying ML inference logic is
untouched — this module only adapts the interface and adds fail-closed
timeout handling.

Detection-only: returns raw matches without suppression logic.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from sentinel.security._enums import Phase, Platform, Severity
from sentinel.security._scan_context import MLMatchMeta, ScanMatch
from sentinel.security._scanner_registry import ScannerMeta

if TYPE_CHECKING:
    from sentinel.security._scan_context import ScanContext

logger = logging.getLogger(__name__)

# Default timeout for PromptGuard inference (seconds).
# Configurable via constructor parameter.
_DEFAULT_TIMEOUT_S = 30

# Confidence assigned to PromptGuard ML detections.
# 0.9 reflects high trust in the model's classification output.
_ML_CONFIDENCE = 0.9

# Maximum characters kept in matched_text (no raw content in logs).
_MAX_MATCH_TEXT_LEN = 200


class PromptGuardScanner:
    """ScannerPlugin wrapper for Meta's PromptGuard ML model.

    Delegates to ``sentinel.security.prompt_guard.scan()`` for the actual
    inference.  All four failure modes are fail-closed (Q10-F4 closed the
    degraded fall-through 2026-04-21):

    1. **Model not loaded** — synthetic fail-closed CRITICAL match.
    2. **Inference timeout** — synthetic fail-closed CRITICAL match via
       ``asyncio.wait_for()``.
    3. **Generic scan exception** — synthetic fail-closed CRITICAL match.
    4. **Degraded result** — when the underlying scan returns
       ``degraded=True`` (race between ``is_loaded()`` and ``scan()``
       completing — late unload, reload mid-request), synthetic
       fail-closed CRITICAL match. Pipeline policy may still
       opt to return CLEAN-DEGRADED at a higher layer when
       ``require_prompt_guard=False`` (see
       ``ScanPipeline._synthesize_pg_clean_degraded_result``); the wrapper
       itself never permits the request silently.
    """

    def __init__(self, *, timeout_s: float = _DEFAULT_TIMEOUT_S) -> None:
        logger.debug(
            "prompt guard scanner init",
            extra={
                "event": "security.scanner.prompt_guard.init",
                "timeout_s": timeout_s,
            },
        )
        self._timeout_s = timeout_s
        # Q17-F13a: side-channel consumed by _partition_verdicts_by_scanner
        # so scan.result / scan.summary audit reflects degraded fail-closed
        # state across all 4 PG fail-closed branches (model_not_loaded,
        # timeout, scan_error, legacy-degraded). MONOTONIC: once True the
        # flag never resets (scanner is a singleton reused across concurrent
        # pipelines; a per-scan reset would race with cross-pipeline reads at
        # _phase_shared.py:142). Trade-off: over-reports degraded after the
        # first fail-closed event — per-scan temporal precision is Q17-U1
        # umbrella (ContextVar / match-metadata signalling).
        self._degraded_on_last_scan = False

    @property
    def scanner_meta(self) -> ScannerMeta:
        return ScannerMeta(
            name="prompt_guard",
            order=60,
            phases=frozenset({Phase.INPUT, Phase.OUTPUT}),
            platforms=frozenset({Platform.ALL}),
            description="ML-based injection detection via PromptGuard",
            expensive=True,
            execution_only=False,
        )

    async def scan(self, context: ScanContext) -> list[ScanMatch]:
        """Run PromptGuard inference on the scan context.

        Converts the legacy ``ScanResult`` into ``list[ScanMatch]`` with
        ``MLMatchMeta``.  Returns a synthetic fail-closed match if the
        model is unavailable or inference times out.
        """
        from sentinel.security import prompt_guard as _pg

        logger.debug(
            "prompt guard scan start",
            extra={
                "event": "security.scanner.prompt_guard.scan_start",
                "text_length": len(context.raw_text),
                "model_loaded": _pg.is_loaded(),
            },
        )

        # Fail-closed: model not loaded → synthetic CRITICAL match
        if not _pg.is_loaded():
            self._degraded_on_last_scan = True
            logger.warning(
                "prompt guard model not loaded — fail-closed",
                extra={
                    "event": "security.scanner.fail_closed",
                    "scanner_name": self.scanner_meta.name,
                    "error_type": "model_not_loaded",
                },
            )
            return [self._synthetic_match("model_not_loaded")]
        logger.debug(
            "prompt guard model loaded — proceeding",
            extra={
                "event": "security.scanner.prompt_guard.loaded_check_passed",
            },
        )  # auto:neg

        # Run inference with timeout
        try:
            legacy_result = await asyncio.wait_for(
                _pg.scan(context.raw_text),
                timeout=self._timeout_s,
            )
        except TimeoutError:
            self._degraded_on_last_scan = True
            logger.warning(
                "prompt guard inference timed out after %.1fs — fail-closed",
                self._timeout_s,
                extra={
                    "event": "security.scanner.fail_closed",
                    "scanner_name": self.scanner_meta.name,
                    "error_type": "timeout",
                    "error_category": "scanner_failure",
                    "timeout_s": self._timeout_s,
                },
                exc_info=True,
            )
            return [self._synthetic_match("timeout")]
        except Exception:
            self._degraded_on_last_scan = True
            logger.warning(
                "prompt guard scan failed — fail-closed",
                extra={
                    "event": "security.scanner.fail_closed",
                    "scanner_name": self.scanner_meta.name,
                    "error_type": "scan_error",
                    "error_category": "scanner_failure",
                },
                exc_info=True,
            )
            return [self._synthetic_match("scan_error")]

        # Fail-closed: degraded result → synthetic CRITICAL match.
        # Race window: _pipeline went None between the is_loaded() check
        # at scan-start and inference completion (late unload, reload
        # mid-request, admin reset). Pipeline-level CLEAN-DEGRADED policy
        # is owned by ScanPipeline._synthesize_pg_clean_degraded_result
        # (gated on require_prompt_guard=False); the wrapper itself never
        # permits the request silently.
        if legacy_result.degraded:
            # Q17-F13a: propagate degraded state so scan.result audit
            # reflects the fail-closed condition (without this flag,
            # _partition_verdicts_by_scanner would aggregate this run
            # as non-degraded).
            self._degraded_on_last_scan = True
            logger.warning(
                "prompt guard returned degraded result — fail-closed",
                extra={
                    "event": "security.scanner.fail_closed",
                    "scanner_name": self.scanner_meta.name,
                    "error_type": "degraded",
                    "error_category": "scanner_failure",
                },
            )
            return [self._synthetic_match("degraded")]

        # Convert legacy ScanMatch → new ScanMatch with MLMatchMeta
        matches = _convert_legacy_matches(legacy_result.matches, self.scanner_meta.name)

        logger.debug(
            "prompt guard scan complete",
            extra={
                "event": "security.scanner.prompt_guard.complete",
                "match_count": len(matches),
            },
        )
        return matches

    def _synthetic_match(self, error_type: str) -> ScanMatch:
        """Build a fail-closed synthetic match per design spec."""
        return ScanMatch(
            rule_id=f"ml.timeout.{self.scanner_meta.name}",
            scanner=self.scanner_meta.name,
            severity=Severity.CRITICAL,
            confidence=1.0,
            matched_text="",
            offset=0,
            length=0,
            region=None,
            metadata=MLMatchMeta(
                model_name=self.scanner_meta.name,
                model_confidence=0.0,
            ),
        )


def _convert_legacy_matches(
    legacy_matches: list,
    scanner_name: str,
) -> list[ScanMatch]:
    """Convert legacy ``core.models.ScanMatch`` to new ``ScanMatch``.

    The legacy match has ``pattern_name``, ``matched_text``, ``position``.
    The new match needs ``rule_id``, ``severity``, ``confidence``,
    ``offset``, ``length``, ``metadata``.
    """
    matches: list[ScanMatch] = []
    for lm in legacy_matches:
        # Extract confidence from pattern name where possible.
        # Legacy pattern_name is e.g. "prompt_guard_injection",
        # "prompt_guard_jailbreak", "prompt_guard_inference_error".
        # We use HIGH severity for ML detections.
        matches.append(
            ScanMatch(
                rule_id=lm.pattern_name,
                scanner=scanner_name,
                severity=Severity.HIGH,
                confidence=_ML_CONFIDENCE,
                matched_text=lm.matched_text[:_MAX_MATCH_TEXT_LEN]
                if lm.matched_text
                else "",
                offset=lm.position,
                length=len(lm.matched_text) if lm.matched_text else 0,
                region=None,
                metadata=MLMatchMeta(
                    model_name=scanner_name,
                    model_confidence=_ML_CONFIDENCE,
                ),
            )
        )
    return matches
