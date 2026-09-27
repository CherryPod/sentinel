"""Factory for wiring the new scanner pipeline.

Loads YAML rules, constructs the preprocessor + suppression engine, and
instantiates all six ``ScannerPlugin`` scanners with their rules.  The
factory is a pure constructor — it touches no app.state and performs no
I/O beyond reading YAML files.

Returns a fully-constructed :class:`ScanPipeline` ready to be wired
into ``app.state``.  Phase 9b-i added the ``preprocessor`` /
``suppression`` / ``rules`` parameters to ``ScanPipeline.__init__``;
Phase 9b-ii flipped this factory to return the pipeline directly rather
than a transitional dataclass.  ``api/init/security.py`` is the primary
caller in production.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from sentinel.core.decorators import no_audit_log
from sentinel.security._encoding_normalizer import EncodingNormalizer
from sentinel.security._phase_preprocessing import Preprocessor
from sentinel.security._rule_loader import (
    RuleLoadError,
    load_rules,
    load_suppressions,
    validate_handler_refs,
)
from sentinel.security._scanner_registry import ScannerPlugin
from sentinel.security._suppression import SuppressionEngine
from sentinel.security.pipeline import ScanPipeline
from sentinel.security.scanners.command_pattern import CommandPatternScanner
from sentinel.security.scanners.credential import CredentialScanner
from sentinel.security.scanners.prompt_guard import PromptGuardScanner
from sentinel.security.scanners.semgrep import SemgrepScanner
from sentinel.security.scanners.sensitive_path import SensitivePathScanner
from sentinel.security.scanners.vulnerability_echo import VulnerabilityEchoScanner

if TYPE_CHECKING:
    from sentinel.audit.emitter import AuditEmitter
    from sentinel.core.config import Settings

logger = logging.getLogger(__name__)

# Canonical rules directory.  Override via ``rules_dir`` for tests.
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
_SUPPRESSIONS_FILENAME = "suppressions.yaml"

# Known scanner names that consume YAML-driven rule sets.  A ``scanner:``
# field in a rule file must match one of these; a typo (e.g.
# ``scanner: credentials``) otherwise boots cleanly and silently hands
# the real scanner an empty rule list.  Validated at factory load time.
_KNOWN_SCANNER_NAMES: frozenset[str] = frozenset(
    {
        "credential",
        "sensitive_path",
        "command_pattern",
        "vulnerability_echo",
    }
)


class PipelineBuildError(Exception):
    """Raised when the pipeline cannot be wired.

    Wraps underlying failures (missing rule files, invalid YAML,
    unresolved handler references) so callers see a single exception
    type at the boundary.
    """


@no_audit_log
def build_pipeline(
    settings: Settings,
    audit_emitter: AuditEmitter | None = None,
    *,
    rules_dir: Path | None = None,
) -> ScanPipeline:
    """Build the complete set of scanner pipeline components.

    Carries ``@no_audit_log`` — this function's logging strategy is
    entry/completion-log at the function level and ``logger.exception``
    in the ``except RuleLoadError`` block.  Per-branch negative-path
    logging inside the try block adds noise and masks the fact that
    error paths are already covered by the except block's structured
    exception log.  Do not remove the decorator unless that strategy
    changes.

    Args:
        settings: Sentinel settings.  ``settings.prompt_guard_enabled``
            controls whether PromptGuard joins the scanner list.
            Semgrep is always registered (its own ``is_loaded()`` check
            gates work at scan time, emitting a fail-closed synthetic
            match when the CLI is missing).
        audit_emitter: Optional audit emitter to attach to the pipeline.
        rules_dir: Override for the YAML rules directory.  Defaults to
            ``sentinel/security/rules`` alongside this module.  Tests
            use this to point at a temporary directory.

    Returns:
        A fully-constructed :class:`ScanPipeline` with the six-scanner
        pipeline wired through the preprocessor + suppression engine.

    Raises:
        PipelineBuildError: if any rule file is missing, fails
            validation, or references a handler that is not declared.
    """
    resolved_rules_dir = rules_dir or _DEFAULT_RULES_DIR

    logger.debug(
        "pipeline factory: build start",
        extra={
            "event": "security.pipeline_factory.build_start",
            "rules_dir": str(resolved_rules_dir),
            "prompt_guard_enabled": settings.prompt_guard_enabled,
        },
    )

    # 1. Load YAML rules, suppression config, cross-validate handler
    #    references, and build the suppression engine.  All of these
    #    raise ``RuleLoadError`` on malformed input or handler-module
    #    import failure — wrap them under ``PipelineBuildError`` so the
    #    factory surfaces a single exception type at the boundary.
    try:
        rules_by_scanner = load_rules(resolved_rules_dir)
        unknown_scanners = set(rules_by_scanner) - _KNOWN_SCANNER_NAMES
        if unknown_scanners:
            msg = (
                "YAML rule file declares unknown scanner name(s): "
                f"{sorted(unknown_scanners)}.  Valid names: "
                f"{sorted(_KNOWN_SCANNER_NAMES)}"
            )
            raise RuleLoadError(msg)
        suppression_config = load_suppressions(
            resolved_rules_dir / _SUPPRESSIONS_FILENAME
        )
        validate_handler_refs(rules_by_scanner, suppression_config)
        suppression = SuppressionEngine.from_config(
            resolved_rules_dir / _SUPPRESSIONS_FILENAME
        )
    except RuleLoadError as exc:
        logger.exception(
            "pipeline factory: rule load failed",
            extra={
                "event": "security.pipeline_factory.rule_load_error",
                "error_category": "rule_load",
            },
        )
        msg = f"Failed to load scanner rules: {exc}"
        raise PipelineBuildError(msg) from exc

    # 2. Build preprocessor (encoding normaliser + context classifier).
    preprocessor = Preprocessor(EncodingNormalizer())

    # 4. Instantiate regex scanners with their rules.
    scanners: list[ScannerPlugin] = [
        CredentialScanner(rules=rules_by_scanner.get("credential", [])),
        SensitivePathScanner(rules=rules_by_scanner.get("sensitive_path", [])),
        CommandPatternScanner(rules=rules_by_scanner.get("command_pattern", [])),
        VulnerabilityEchoScanner(rules=rules_by_scanner.get("vulnerability_echo", [])),
    ]

    # 5. Register PromptGuard only when enabled.
    if settings.prompt_guard_enabled:
        logger.debug(
            "build_pipeline: prompt_guard_enabled",
            extra={
                "event": "security.pipeline_factory.prompt_guard_skipped.clean",
                "reason": "prompt_guard_enabled",
            },
        )  # auto:neg
        scanners.append(PromptGuardScanner())
    else:
        logger.debug(
            "pipeline factory: PromptGuard skipped (disabled by settings)",
            extra={
                "event": "security.pipeline_factory.prompt_guard_skipped",
            },
        )

    # 6. Semgrep is always registered; its own loaded check runs at scan
    #    time and emits a fail-closed synthetic match when the CLI is
    #    missing.
    scanners.append(SemgrepScanner())

    # 7. Flatten the per-scanner rule dict into a single id→RuleDefinition
    #    map for the suppression engine's rule lookup.
    flat_rules = {
        rule.id: rule for rules in rules_by_scanner.values() for rule in rules
    }

    logger.debug(
        "pipeline factory: build complete",
        extra={
            "event": "security.pipeline_factory.build_complete",
            "scanner_count": len(scanners),
            "rule_count": len(flat_rules),
            "handler_count": len(suppression_config.get("handlers", {})),
        },
    )

    return ScanPipeline(
        scanners=tuple(scanners),
        suppression=suppression,
        preprocessor=preprocessor,
        rules=MappingProxyType(flat_rules),
        audit_emitter=audit_emitter,
    )
