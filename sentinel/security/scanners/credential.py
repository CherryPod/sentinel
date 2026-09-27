"""Credential scanner — ScannerPlugin implementation.

Detection-only: returns raw matches without any suppression logic.
Suppression is handled by the SuppressionEngine (Phase 3).

Scans ``ScanContext.raw_text`` and all ``decoded_variants`` against
YAML-loaded credential rules.  Shadow content detection (``/etc/shadow``
file format) is a built-in heuristic independent of YAML rules.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from sentinel.security._enums import Phase, Platform, Severity
from sentinel.security._scan_context import CredentialMatchMeta, ScanMatch
from sentinel.security._scanner_registry import ScannerMeta
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.security.scanners._helpers import find_enclosing_region

if TYPE_CHECKING:
    from sentinel.security._rule_schema import RuleDefinition
    from sentinel.security._scan_context import ScanContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shadow content detection constants
# ---------------------------------------------------------------------------

# Known system account names that appear in /etc/shadow.
# Includes standard Debian/Ubuntu accounts and common Alpine/RHEL service
# accounts so that a single-line shadow dump for any of these is recognised
# without requiring 2+ lines.
_SHADOW_SYSTEM_ACCOUNTS: frozenset[str] = frozenset(
    {
        "root",
        "daemon",
        "bin",
        "sys",
        "sync",
        "games",
        "man",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "www-data",
        "backup",
        "list",
        "irc",
        "gnats",
        "nobody",
        "systemd-network",
        "systemd-resolve",
        "messagebus",
        "systemd-timesync",
        "syslog",
        "sshd",
        "_apt",
        "tss",
        "uuidd",
        "systemd-oom",
        "tcpdump",
        "avahi-autoipd",
        "usbmux",
        "dnsmasq",
        "kernoops",
        "avahi",
        "cups-pk-helper",
        "rtkit",
        "whoopsie",
        "sssd",
        "speech-dispatcher",
        "fwupd-refresh",
        "nm-openvpn",
        "saned",
        "colord",
        "geoclue",
        "gnome-initial-setup",
        "hplip",
        "gdm",
        "polkitd",
        # Common Alpine / RHEL service accounts
        "nginx",
        "postgres",
        "mysql",
        "redis",
        "node",
        "git",
        "docker",
        "www",
        "apache",
        "named",
        "ntp",
    }
)

# Regex: username:hash_or_marker:7 colon-separated numeric fields
_SHADOW_LINE_RE = re.compile(
    r"^([a-z_][a-z0-9_-]*(?:\$[a-z_][a-z0-9_-]*)?):[^\s:]*(?::\d*){7}$",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# CredentialScanner
# ---------------------------------------------------------------------------


class CredentialScanner:
    """Regex-based credential scanner implementing ScannerPlugin.

    Detection-only — all suppression logic lives in SuppressionEngine
    handlers (uri_parsing, placeholder_values, etc.).
    """

    def __init__(self, rules: list[RuleDefinition]) -> None:
        logger.debug(
            "credential scanner init",
            extra={
                "event": "security.scanner.credential.init",
                "rule_count": len(rules),
            },
        )
        self._rules = rules
        # Pre-compile all patterns once at construction.
        # Align with command_pattern.py init-log pattern — structured event +
        # re-raise preserves fail-closed invariant at startup.
        self._compiled: list[tuple[RuleDefinition, re.Pattern[str]]] = []
        for rule in rules:
            try:
                self._compiled.append((rule, re.compile(rule.pattern)))
            except re.error:
                logger.error(
                    "invalid regex in credential rule — fail-closed",
                    extra={
                        "event": "security.scanner.bad_rule",
                        "error_category": "configuration",
                        "scanner": "credential",
                        "rule_id": rule.id,
                    },
                    exc_info=True,
                )
                raise

    @property
    def scanner_meta(self) -> ScannerMeta:
        return ScannerMeta(
            name="credential",
            order=10,
            phases=frozenset({Phase.INPUT, Phase.OUTPUT}),
            platforms=frozenset({Platform.ALL}),
            description="Credential and secret detection via regex + shadow heuristic",
            expensive=False,
            execution_only=False,
        )

    async def scan(self, context: ScanContext) -> list[ScanMatch]:
        """Scan raw text and decoded variants for credential patterns.

        Returns raw matches — no suppression applied.
        """
        logger.debug(
            "credential scanner scan start",
            extra={
                "event": "security.scanner.credential.scan_start",
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

        # Shadow content detection (built-in heuristic, not YAML-driven)
        matches.extend(self._check_shadow_content(normalised, context))

        logger.debug(
            "credential scanner scan complete",
            extra={
                "event": "security.scanner.credential.complete",
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
                        metadata=CredentialMatchMeta(
                            credential_type=_credential_type_from_tags(rule.tags),
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
                        metadata=CredentialMatchMeta(
                            credential_type=_credential_type_from_tags(rule.tags),
                            platform_tags=tuple(Platform(p) for p in rule.platforms),
                        ),
                    )
                )
        return matches

    def _check_shadow_content(
        self,
        text: str,
        context: ScanContext,
    ) -> list[ScanMatch]:
        """Detect /etc/shadow file content by its 9-field colon format.

        Two-tier detection:
        - 2+ matching lines -> always flag (bulk shadow dump)
        - 1 matching line -> flag only if username is a known system account
        """
        hits = list(_SHADOW_LINE_RE.finditer(text))
        if not hits:
            return []

        if len(hits) >= 2:
            logger.debug(
                "shadow content detected",
                extra={
                    "event": "security.scanner.credential.shadow_detected",
                    "line_count": len(hits),
                },
            )
            return [
                ScanMatch(
                    rule_id="cred.shadow_file_content",
                    scanner=self.scanner_meta.name,
                    severity=Severity.HIGH,
                    confidence=0.95,
                    matched_text=m.group(),
                    offset=m.start(),
                    length=len(m.group()),
                    region=find_enclosing_region(m.start(), context.regions),
                    metadata=CredentialMatchMeta(
                        credential_type="shadow_file",
                        platform_tags=(Platform.LINUX,),
                    ),
                )
                for m in hits
            ]
        logger.debug(
            "_check_shadow_content: condition_passed",
            extra={
                "event": "security.scanner.credential.shadow_detected.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        # Single match — only flag known system accounts
        m = hits[0]
        username = m.group(1)
        if username in _SHADOW_SYSTEM_ACCOUNTS:
            logger.debug(
                "shadow content detected (system account)",
                extra={
                    "event": "security.scanner.credential.shadow_detected",
                    "line_count": 1,
                    "username_hash": hash(username),
                },
            )
            return [
                ScanMatch(
                    rule_id="cred.shadow_file_content",
                    scanner=self.scanner_meta.name,
                    severity=Severity.HIGH,
                    confidence=0.95,
                    matched_text=m.group(),
                    offset=m.start(),
                    length=len(m.group()),
                    region=find_enclosing_region(m.start(), context.regions),
                    metadata=CredentialMatchMeta(
                        credential_type="shadow_file",
                        platform_tags=(Platform.LINUX,),
                    ),
                )
            ]

        logger.debug(
            "shadow content check clean",
            extra={
                "event": "security.scanner.credential.shadow_clean",
                "reason": "single_line_non_system_account",
            },
        )
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _credential_type_from_tags(tags: list[str]) -> str:
    """Derive credential_type from rule tags.

    Uses the first tag that isn't 'credential' as the type descriptor.
    Falls back to 'generic' if no other tags exist.

    Note: tag ordering in YAML rules matters — the first non-'credential'
    tag becomes the credential_type.  By convention, YAML rules should
    list the primary type tag immediately after 'credential'.
    """
    for tag in tags:
        if tag != "credential":
            return tag
    return "generic"
