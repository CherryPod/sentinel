"""Sensitive path scanner — ScannerPlugin implementation.

Detection-only: returns raw matches without any suppression logic.
Suppression is handled by the SuppressionEngine (Phase 3).

Scans ``ScanContext.raw_text`` and all ``decoded_variants`` against
YAML-loaded sensitive path rules using substring matching with boundary
checking.  The boundary check (``_is_boundary_match``) and env template
detection (``_is_env_template``) are detection-level filtering — they
prevent false matches, not suppress real ones.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from sentinel.security._enums import Phase, Platform, Severity
from sentinel.security._scan_context import PathMatchMeta, ScanMatch
from sentinel.security._scanner_registry import ScannerMeta
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.security.scanners._helpers import find_enclosing_region

if TYPE_CHECKING:
    from sentinel.security._rule_schema import RuleDefinition
    from sentinel.security._scan_context import ScanContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection-level constants
# ---------------------------------------------------------------------------

# Template env file suffixes: .env.example, .env.sample, .env.template
# are placeholder files without real secrets.
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template")

# Regex for comma-separated items that look like file patterns
# (globs, dotfiles, paths) — NOT code syntax.
_FILE_PATTERN_ITEM_RE = re.compile(r"^[a-zA-Z0-9.*_/\[\]{}\-\\]+/?$")


# ---------------------------------------------------------------------------
# SensitivePathScanner
# ---------------------------------------------------------------------------


class SensitivePathScanner:
    """Substring-based sensitive path scanner implementing ScannerPlugin.

    Detection-only — all suppression logic lives in SuppressionEngine
    handlers (educational_context, code_block_safe, display_context, etc.).

    Detection-level filtering (boundary check, env template, ignore listing)
    prevents false matches at the scanner level.  These are NOT suppression
    — they filter out matches that are definitively not sensitive paths.
    """

    def __init__(self, rules: list[RuleDefinition]) -> None:
        logger.debug(
            "sensitive path scanner init",
            extra={
                "event": "security.scanner.sensitive_path.init",
                "rule_count": len(rules),
            },
        )
        self._rules = rules

    @property
    def scanner_meta(self) -> ScannerMeta:
        return ScannerMeta(
            name="sensitive_path",
            order=20,
            phases=frozenset({Phase.INPUT, Phase.OUTPUT}),
            platforms=frozenset({Platform.ALL}),
            description="Sensitive file path detection via substring matching",
            expensive=False,
            execution_only=False,
        )

    async def scan(self, context: ScanContext) -> list[ScanMatch]:
        """Scan raw text and decoded variants for sensitive path patterns.

        Returns raw matches — no suppression applied.  Boundary checking
        and env template filtering are detection-level (prevent false
        matches), not suppression.
        """
        logger.debug(
            "sensitive path scanner scan start",
            extra={
                "event": "security.scanner.sensitive_path.scan_start",
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
            "sensitive path scanner scan complete",
            extra={
                "event": "security.scanner.sensitive_path.complete",
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
        """Run all rules against text using substring matching.

        Applies detection-level filtering:
        - Boundary check: rejects substring matches inside longer tokens
        - Env template: rejects .env.example/.sample/.template
        - Ignore listing: rejects .env in comma-separated file-pattern lists
        """
        matches: list[ScanMatch] = []
        for rule in self._rules:
            pattern = rule.pattern
            idx = 0
            while True:
                pos = text.find(pattern, idx)
                if pos == -1:
                    break
                idx = pos + 1

                # Detection-level filter: boundary check
                if not _is_boundary_match(text, pattern, pos):
                    continue

                # Detection-level filter: env template files
                if _is_env_template(text, pattern, pos):
                    continue

                # Detection-level filter: .env in ignore listings
                if pattern == ".env" and _is_in_ignore_listing(text, pos):
                    continue

                region = find_enclosing_region(pos, context.regions)
                matches.append(
                    ScanMatch(
                        rule_id=rule.id,
                        scanner=self.scanner_meta.name,
                        severity=Severity(rule.severity),
                        confidence=rule.confidence,
                        matched_text=pattern,
                        offset=pos,
                        length=len(pattern),
                        region=region,
                        metadata=PathMatchMeta(
                            path_type=_path_type_from_tags(rule.tags),
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
        for rule in self._rules:
            pattern = rule.pattern
            idx = 0
            while True:
                pos = decoded_text.find(pattern, idx)
                if pos == -1:
                    break
                idx = pos + 1

                if not _is_boundary_match(decoded_text, pattern, pos):
                    continue

                if _is_env_template(decoded_text, pattern, pos):
                    continue

                if pattern == ".env" and _is_in_ignore_listing(decoded_text, pos):
                    continue

                matches.append(
                    ScanMatch(
                        rule_id=f"encoded:{encoding}:{rule.id}",
                        scanner=self.scanner_meta.name,
                        severity=Severity(rule.severity),
                        confidence=rule.confidence,
                        matched_text=pattern,
                        offset=pos,
                        length=len(pattern),
                        region=None,
                        metadata=PathMatchMeta(
                            path_type=_path_type_from_tags(rule.tags),
                            platform_tags=tuple(Platform(p) for p in rule.platforms),
                        ),
                    )
                )

        return matches


# ---------------------------------------------------------------------------
# Detection-level helpers
# ---------------------------------------------------------------------------


def _is_boundary_match(text: str, pattern: str, pos: int) -> bool:
    """Check that the match at *pos* isn't a substring of a longer word.

    Patterns ending with ``/`` (e.g. ``.ssh/``, ``/proc/``) are
    boundary-safe by definition.  For patterns without a trailing
    slash (e.g. ``.env``, ``wallet.dat``), the character immediately
    after the match must **not** be alphabetic.

    Finding #27 — leading boundary: if the pattern doesn't start with
    ``/``, the character immediately *before* the match must not be
    alphanumeric.  This prevents ``.env`` from matching inside tokens
    like ``X.env`` while still allowing ``/path/.env``.
    """
    # Leading boundary check (finding #27)
    if pos > 0 and not pattern.startswith("/"):
        before = text[pos - 1]
        if before.isalnum():
            logger.debug(
                "boundary check rejected: leading alphanumeric",
                extra={
                    "event": "security.scanner.sensitive_path.boundary_rejected",
                    "reason": "leading_alnum",
                },
            )
            return False

    # Trailing boundary check
    if pattern.endswith("/"):
        return True

    end = pos + len(pattern)
    if end < len(text) and text[end].isalpha():
        logger.debug(
            "boundary check rejected: trailing alpha",
            extra={
                "event": "security.scanner.sensitive_path.boundary_rejected",
                "reason": "trailing_alpha",
            },
        )
        return False

    return True


def _is_env_template(text: str, pattern: str, pos: int) -> bool:
    """Check if a .env match is actually a .env.example/sample/template."""
    logger.debug(
        "env template check",
        extra={
            "event": "security.scanner.sensitive_path.env_template_check",
            "text_len": len(text),
            "pattern": pattern,
            "pos": pos,
        },
    )
    if pattern != ".env":
        return False
    end = pos + len(pattern)
    remaining = text[end : end + 12]  # longest suffix is ".template" (9 chars)
    for suffix in _ENV_TEMPLATE_SUFFIXES:
        if remaining.startswith(suffix):
            return True
    logger.debug(
        "env template check clean",
        extra={
            "event": "security.scanner.sensitive_path.env_template_clean",
            "reason": "no_template_suffix",
        },
    )
    return False


def _is_in_ignore_listing(text: str, pos: int) -> bool:
    """Check if a .env match is part of a comma-separated file-pattern list.

    Returns True for prose contexts like:
        "Include entries for: venv/, __pycache__/, .env, *.pyc, dist/"
    where .env is clearly an ignore-pattern reference, not a file access.

    Conservative: requires >=3 file-pattern-like items on the same line.
    """
    logger.debug(
        "ignore listing check",
        extra={
            "event": "security.scanner.sensitive_path.ignore_listing_check",
            "text_len": len(text),
            "pos": pos,
        },
    )
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]

    # Split by commas and strip whitespace / trailing "and"
    items = [item.strip().removeprefix("and ").strip() for item in line.split(",")]
    if len(items) < 3:
        logger.debug(
            "ignore listing check clean",
            extra={
                "event": "security.scanner.sensitive_path.ignore_listing_clean",
                "reason": "fewer_than_3_items",
            },
        )
        return False

    # Count items that look like file patterns (globs, dotfiles, paths)
    pattern_like = sum(
        1 for item in items if _FILE_PATTERN_ITEM_RE.match(item) and len(item) < 30
    )
    if pattern_like >= 3:
        return True
    logger.debug(
        "ignore listing check clean",
        extra={
            "event": "security.scanner.sensitive_path.ignore_listing_clean",
            "reason": "insufficient_pattern_items",
        },
    )
    return False


def _path_type_from_tags(tags: list[str]) -> str:
    """Derive path_type from rule tags.

    Uses the first tag as the type descriptor.
    Falls back to 'generic' if no tags exist.
    """
    if tags:
        return tags[0]
    return "generic"
