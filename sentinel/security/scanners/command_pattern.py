"""Command pattern scanner — ScannerPlugin implementation.

Detection-only: returns raw matches without any suppression logic.
Suppression is handled by the SuppressionEngine (Phase 3).

Scans ``ScanContext.raw_text`` and all ``decoded_variants`` against
YAML-loaded command pattern rules using regex matching with homoglyph
normalisation.

``execution_only=True`` — the pipeline skips this scanner during OUTPUT
when destination is DISPLAY, but always runs it on INPUT.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from sentinel.security._enums import Phase, Platform, Severity
from sentinel.security._scan_context import CommandMatchMeta, ScanMatch
from sentinel.security._scanner_registry import ScannerMeta
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.security.scanners._helpers import find_enclosing_region

if TYPE_CHECKING:
    from sentinel.security._rule_schema import RuleDefinition
    from sentinel.security._scan_context import ScanContext

logger = logging.getLogger(__name__)


class CommandPatternScanner:
    """Regex-based command pattern scanner implementing ScannerPlugin.

    Detection-only — all suppression logic lives in SuppressionEngine
    handlers (build_context for Dockerfile/Makefile exemptions,
    display_context for prose suppression).
    """

    def __init__(self, rules: list[RuleDefinition]) -> None:
        logger.debug(
            "command pattern scanner init",
            extra={
                "event": "security.scanner.command_pattern.init",
                "rule_count": len(rules),
            },
        )
        self._rules = rules
        # Pre-compile all patterns once at construction.
        # Rules are pre-validated by _rule_schema.py Pydantic validators,
        # so re.error here indicates a programming error upstream.
        self._compiled: list[tuple[RuleDefinition, re.Pattern[str]]] = []
        for rule in rules:
            try:
                self._compiled.append((rule, re.compile(rule.pattern)))
            except re.error:
                logger.error(
                    "invalid regex in command rule — skipping",
                    extra={
                        "event": "security.scanner.command_pattern.bad_rule",
                        "error_category": "configuration",
                        "rule_id": rule.id,
                    },
                    exc_info=True,
                )
                raise

    @property
    def scanner_meta(self) -> ScannerMeta:
        return ScannerMeta(
            name="command_pattern",
            order=30,
            phases=frozenset({Phase.INPUT, Phase.OUTPUT}),
            platforms=frozenset({Platform.ALL}),
            description="Shell command attack pattern detection via regex",
            expensive=False,
            execution_only=True,
        )

    async def scan(self, context: ScanContext) -> list[ScanMatch]:
        """Scan raw text and decoded variants for command patterns.

        Returns raw matches — no suppression applied.
        """
        logger.debug(
            "command pattern scanner scan start",
            extra={
                "event": "security.scanner.command_pattern.scan_start",
                "phase": context.metadata.phase.value,
                "text_length": len(context.raw_text),
                "variant_count": len(context.decoded_variants),
            },
        )

        # Use the pre-normalised text from the preprocessor so that scanner
        # offsets and region boundaries share one coordinate space.  Fall
        # back to computing normalisation locally for contexts built outside
        # the preprocessor (benchmark harnesses, synthetic stubs).
        normalised = context.normalised_text if context.normalised_text is not None else normalise_homoglyphs(context.raw_text)
        matches: list[ScanMatch] = []

        # Scan raw text against all rules
        matches.extend(self._scan_text(normalised, context))

        # Scan decoded variants
        for variant in context.decoded_variants:
            normalised_variant = normalise_homoglyphs(variant.decoded_text)
            matches.extend(
                self._scan_decoded_variant(
                    normalised_variant,
                    variant.encoding.value,
                    context,
                )
            )

        logger.debug(
            "command pattern scanner scan complete",
            extra={
                "event": "security.scanner.command_pattern.complete",
                "match_count": len(matches),
                "phase": context.metadata.phase.value,
            },
        )
        return matches

    def _scan_text(
        self,
        text: str,
        context: ScanContext,
    ) -> list[ScanMatch]:
        """Run all compiled rules against text, returning raw matches."""
        matches: list[ScanMatch] = []
        for rule, pattern in self._compiled:
            for hit in pattern.finditer(text):
                region = find_enclosing_region(hit.start(), context.regions)
                matches.append(
                    ScanMatch(
                        rule_id=rule.id,
                        scanner=self.scanner_meta.name,
                        severity=Severity(rule.severity),
                        confidence=rule.confidence,
                        matched_text=hit.group(),
                        offset=hit.start(),
                        length=len(hit.group()),
                        region=region,
                        metadata=CommandMatchMeta(
                            attack_type=_attack_type_from_tags(rule.tags),
                            platform_tags=tuple(Platform(p) for p in rule.platforms),
                        ),
                    )
                )
        return matches

    def _scan_decoded_variant(
        self,
        decoded_text: str,
        encoding: str,
        context: ScanContext,
    ) -> list[ScanMatch]:
        """Scan a decoded variant, prefixing rule_id with encoded:<encoding>:."""
        matches: list[ScanMatch] = []
        for rule, pattern in self._compiled:
            for hit in pattern.finditer(decoded_text):
                matches.append(
                    ScanMatch(
                        rule_id=f"encoded:{encoding}:{rule.id}",
                        scanner=self.scanner_meta.name,
                        severity=Severity(rule.severity),
                        confidence=rule.confidence,
                        matched_text=hit.group(),
                        offset=hit.start(),
                        length=len(hit.group()),
                        region=None,
                        metadata=CommandMatchMeta(
                            attack_type=_attack_type_from_tags(rule.tags),
                            platform_tags=tuple(Platform(p) for p in rule.platforms),
                        ),
                    )
                )
        return matches


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _attack_type_from_tags(tags: list[str]) -> str:
    """Derive attack_type from rule tags.

    Uses the first tag that isn't 'execution' as the type descriptor.
    Falls back to 'generic' if no other tags exist.

    Note: tag ordering in YAML rules matters — the first non-'execution'
    tag becomes the attack_type.  By convention, YAML rules should
    list the primary type tag after 'execution'.
    """
    for tag in tags:
        if tag != "execution":
            return tag
    return "generic"
