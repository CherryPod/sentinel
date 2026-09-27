"""Centralised suppression engine.

Evaluates scanner matches against named handlers loaded from
``rules/suppressions.yaml``.  Each match is run through all handlers
declared in its rule's ``suppressions`` list.  Results are recorded as
``SuppressionVerdict`` objects — every handler that would suppress is
tracked in ``all_reasons`` for FP benchmark traceability.

The engine also manages the global allowlist: rule IDs listed there
are suppressed unconditionally (with mandatory ``reason`` for
auditability).
"""

from __future__ import annotations

import importlib
import logging
import re
from pathlib import Path
from typing import Any

from sentinel.security._enums import Severity
from sentinel.security._rule_loader import RuleLoadError, load_suppressions
from sentinel.security._rule_schema import RuleDefinition
from sentinel.security._scan_context import (
    AllowlistEntry,
    ScanContext,
    ScanMatch,
    SuppressionVerdict,
)

logger = logging.getLogger(__name__)

# Matches the "encoded:<encoding>:" prefix emitted by regex scanners
# for decoded variants (e.g. "encoded:base64:cred.aws_access_key").
_ENCODED_PREFIX_RE = re.compile(r"^encoded:[^:]+:")


def _base_rule_id(rule_id: str) -> str:
    """Strip the ``encoded:<encoding>:`` prefix if present.

    Rules and allowlist entries are keyed by the base rule ID (e.g.
    ``cred.aws_access_key``), but scanners prefix decoded-variant
    matches for audit traceability.  This helper normalises so lookups
    work for both plain and encoded rule IDs.
    """
    return _ENCODED_PREFIX_RE.sub("", rule_id, count=1)


class SuppressionEngine:
    """Evaluate scanner matches against suppression handlers.

    Built via ``from_config()`` at startup.  Immutable after
    construction — handlers and allowlist are fixed for the process
    lifetime.
    """

    def __init__(
        self,
        handlers: dict[str, Any],
        allowlist: tuple[AllowlistEntry, ...],
    ) -> None:
        self._handlers = handlers
        self._allowlist = allowlist
        self._allowlist_by_rule_id: dict[str, AllowlistEntry] = {
            entry.rule_id: entry for entry in allowlist
        }

    @classmethod
    def from_config(cls, suppressions_path: Path) -> SuppressionEngine:
        """Load suppression config, import handlers, build engine.

        Raises ``RuleLoadError`` on missing file, invalid config, or
        handler import failure.
        """
        logger.debug(
            "Loading suppression engine",
            extra={
                "event": "security.suppression.engine_load_start",
                "path": str(suppressions_path),
            },
        )

        raw_config = load_suppressions(suppressions_path)
        handlers = _import_handlers(raw_config["handlers"])
        allowlist = _parse_allowlist(raw_config.get("global_allowlist", []))

        # Log warnings for active allowlist entries
        for entry in allowlist:
            logger.warning(
                "Allowlist entry active",
                extra={
                    "event": "security.suppression.allowlist_active",
                    "rule_id": entry.rule_id,
                    "reason": entry.reason,
                },
            )

        engine = cls(handlers=handlers, allowlist=allowlist)

        logger.info(
            "Suppression engine loaded",
            extra={
                "event": "security.suppression.engine_loaded",
                "handler_count": len(handlers),
                "allowlist_count": len(allowlist),
            },
        )

        return engine

    def evaluate(
        self,
        matches: list[ScanMatch],
        context: ScanContext,
        rules: dict[str, RuleDefinition] | None = None,
        severity_filter: Severity | None = None,
    ) -> list[SuppressionVerdict]:
        """Evaluate all matches against their declared handlers.

        Args:
            matches: Raw matches from scanners.
            context: The scan context (immutable).
            rules: Mapping of rule_id -> RuleDefinition for looking up
                suppression refs.  If None, no handler-based suppression
                is applied (only allowlist).
            severity_filter: If set, only evaluate matches at or above
                this severity level.  Lower-severity matches pass
                through unsuppressed (no handler evaluation).

        Returns:
            A SuppressionVerdict per input match.
        """
        logger.debug(
            "Evaluating suppression",
            extra={
                "event": "security.suppression.evaluate_start",
                "match_count": len(matches),
                "severity_filter": severity_filter.value if severity_filter else None,
            },
        )

        verdicts: list[SuppressionVerdict] = []

        for match in matches:
            # Synthetic fail-closed matches are never suppressed
            if match.rule_id.startswith("ml.timeout."):
                verdicts.append(
                    SuppressionVerdict(
                        match=match,
                        suppressed=False,
                        canonical_reason=None,
                        all_reasons=(),
                    )
                )
                continue

            # Severity filter: skip handler evaluation for lower-severity
            if severity_filter is not None:
                if _severity_rank(match.severity) < _severity_rank(severity_filter):
                    verdicts.append(
                        SuppressionVerdict(
                            match=match,
                            suppressed=False,
                            canonical_reason=None,
                            all_reasons=(),
                        )
                    )
                    continue

            verdict = self._evaluate_single(match, context, rules)
            verdicts.append(verdict)

        suppressed_count = sum(1 for v in verdicts if v.suppressed)
        logger.debug(
            "Suppression evaluation complete",
            extra={
                "event": "security.suppression.complete",
                "total_matches": len(matches),
                "suppressed_count": suppressed_count,
                "unsuppressed_count": len(matches) - suppressed_count,
            },
        )

        return verdicts

    def _evaluate_single(
        self,
        match: ScanMatch,
        context: ScanContext,
        rules: dict[str, RuleDefinition] | None,
    ) -> SuppressionVerdict:
        """Evaluate a single match against all applicable handlers."""
        # Normalise encoded rule IDs (e.g. "encoded:base64:CRED001" → "CRED001")
        # so lookups match the base keys in allowlist and rule dicts.
        base_id = _base_rule_id(match.rule_id)

        # Check global allowlist first (O(1) dict lookup)
        entry = self._allowlist_by_rule_id.get(base_id)
        if entry is not None:
            return SuppressionVerdict(
                match=match,
                suppressed=True,
                canonical_reason=f"allowlist:{entry.reason}",
                all_reasons=(f"allowlist:{entry.reason}",),
            )

        # Look up rule definition for handler refs
        rule = rules.get(base_id) if rules else None
        if rule is None:
            # No rule definition = no handler-based suppression
            return SuppressionVerdict(
                match=match,
                suppressed=False,
                canonical_reason=None,
                all_reasons=(),
            )

        # Run all declared handlers — record every one that would suppress
        all_reasons: list[str] = []
        for sup_ref in rule.suppressions:
            handler = self._handlers.get(sup_ref.handler)
            if handler is None:
                # Missing handler should have been caught at startup
                logger.warning(
                    "Missing handler during evaluation",
                    extra={
                        "event": "security.suppression.missing_handler",
                        "handler_id": sup_ref.handler,
                        "rule_id": match.rule_id,
                    },
                )
                continue

            try:
                if handler.evaluate(match, context, sup_ref.params):
                    all_reasons.append(sup_ref.handler)
            except Exception:
                # Handler crash — log and continue.  The match stays
                # flagged (fail-closed for security) because a crashing
                # handler cannot add itself to all_reasons.
                logger.warning(
                    "Handler evaluation failed",
                    extra={
                        "event": "security.suppression.handler_error",
                        "error_category": "handler_crash",
                        "handler_id": sup_ref.handler,
                        "rule_id": match.rule_id,
                    },
                    exc_info=True,
                )

        suppressed = len(all_reasons) > 0
        canonical = all_reasons[0] if all_reasons else None

        return SuppressionVerdict(
            match=match,
            suppressed=suppressed,
            canonical_reason=canonical,
            all_reasons=tuple(all_reasons),
        )

    @property
    def handler_ids(self) -> frozenset[str]:
        """Return the set of registered handler IDs."""
        return frozenset(self._handlers.keys())

    @property
    def allowlist_entries(self) -> tuple[AllowlistEntry, ...]:
        """Return the global allowlist entries."""
        return self._allowlist


def _import_handlers(
    handler_configs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Import and instantiate all handler modules from config.

    Each handler config must have a ``module`` key pointing to a Python
    module that contains a handler class.  The handler class is the
    first class found with a ``handler_id`` attribute matching the
    config key.

    Raises ``RuleLoadError`` on import failure.
    """
    handlers: dict[str, Any] = {}

    for handler_id, config in handler_configs.items():
        module_path = config["module"]
        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            msg = f"Failed to import handler module '{module_path}': {exc}"
            raise RuleLoadError(msg) from exc

        # Find the handler class — look for a class with matching handler_id
        handler_cls = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and hasattr(attr, "handler_id")
                and getattr(attr, "handler_id", None) == handler_id
            ):
                handler_cls = attr
                break

        if handler_cls is None:
            msg = (
                f"No handler class with handler_id={handler_id!r} "
                f"found in module '{module_path}'"
            )
            raise RuleLoadError(msg)

        handlers[handler_id] = handler_cls()

        logger.debug(
            "Handler imported",
            extra={
                "event": "security.suppression.handler_imported",
                "handler_id": handler_id,
                "module_name": module_path,  # auto:key
            },
        )

    return handlers


def _parse_allowlist(
    raw_entries: list[dict[str, str]],
) -> tuple[AllowlistEntry, ...]:
    """Parse raw allowlist dicts into AllowlistEntry objects."""
    entries = []
    for raw in raw_entries:
        entries.append(
            AllowlistEntry(
                rule_id=raw["rule_id"],
                reason=raw["reason"],
            )
        )
    return tuple(entries)


# Severity ranking for filter comparison
_SEVERITY_RANKS: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _severity_rank(severity: Severity) -> int:
    """Return numeric rank for severity comparison."""
    return _SEVERITY_RANKS.get(severity, 0)
