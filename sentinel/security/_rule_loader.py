"""YAML rule loader with post-load validation.

Loads all rule files from the ``rules/`` directory and the suppression
config.  Three post-load validations run at load time:

1. **Rule ID uniqueness** — duplicate IDs across files = startup error.
2. **Handler cross-validation** — every suppression ref in rules must
   map to a declared handler in ``suppressions.yaml``.
3. **Scanner name validation** — deferred to pipeline init (scanners
   aren't registered at rule-load time).

Fail-closed: any validation error raises at startup.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from sentinel.security._rule_schema import RuleDefinition, RuleFile

logger = logging.getLogger(__name__)

# YAML rule file names (excluding suppressions.yaml which has a different schema)
_RULE_FILES = (
    "credentials.yaml",
    "sensitive_paths.yaml",
    "commands.yaml",
    "vulnerability_echo.yaml",
)


class RuleLoadError(Exception):
    """Raised when rule loading or validation fails."""


def load_rules(rules_dir: Path) -> dict[str, list[RuleDefinition]]:
    """Load and validate all YAML rule files.

    Returns a dict keyed by scanner name (from ``RuleFile.scanner``)
    mapping to the list of validated ``RuleDefinition`` objects.

    Raises ``RuleLoadError`` on any validation failure.
    """
    logger.debug(
        "Loading rules",
        extra={"event": "security.rules.load_start", "rules_dir": str(rules_dir)},
    )

    if not rules_dir.is_dir():
        msg = f"Rules directory does not exist: {rules_dir}"
        raise RuleLoadError(msg)

    all_rule_ids: list[str] = []
    all_handler_refs: set[str] = set()
    result: dict[str, list[RuleDefinition]] = {}

    for filename in _RULE_FILES:
        filepath = rules_dir / filename
        if not filepath.exists():
            msg = f"Required rule file missing: {filepath}"
            raise RuleLoadError(msg)

        raw = _load_yaml_file(filepath)
        rule_file = _validate_rule_file(raw, filepath)

        # Collect IDs for uniqueness check
        for rule in rule_file.rules:
            all_rule_ids.append(rule.id)
            # Collect handler refs for cross-validation
            for sup_ref in rule.suppressions:
                all_handler_refs.add(sup_ref.handler)

        result[rule_file.scanner] = rule_file.rules

        logger.debug(
            "Rule file loaded",
            extra={
                "event": "security.rules.loaded",
                "file": filename,
                "scanner": rule_file.scanner,
                "rule_count": len(rule_file.rules),
                "version": rule_file.version,
            },
        )

    # Post-load validation 1: Rule ID uniqueness
    _validate_id_uniqueness(all_rule_ids)

    # Post-load validation 2: Handler cross-validation
    # (requires suppressions to be loaded separately — caller should
    #  call load_suppressions and then validate_handler_refs)

    total_rules = sum(len(rules) for rules in result.values())
    logger.debug(
        "Rule loading complete",
        extra={
            "event": "security.rules.validation_complete",
            "scanner_count": len(result),
            "total_rules": total_rules,
            "handler_refs": len(all_handler_refs),
        },
    )

    return result


def load_suppressions(suppressions_path: Path) -> dict[str, Any]:
    """Load and validate the suppression configuration.

    Returns the parsed suppression config dict with ``handlers``
    and ``global_allowlist`` keys.

    Raises ``RuleLoadError`` on missing file or invalid structure.
    """
    logger.debug(
        "Loading suppression config",
        extra={
            "event": "security.suppressions.load_start",
            "path": str(suppressions_path),
        },
    )

    if not suppressions_path.exists():
        msg = f"Suppression config missing: {suppressions_path}"
        raise RuleLoadError(msg)

    raw = _load_yaml_file(suppressions_path)

    if not isinstance(raw, dict):
        msg = f"Suppression config must be a mapping, got {type(raw).__name__}"
        raise RuleLoadError(msg)

    # Validate required fields
    if "handlers" not in raw:
        msg = "Suppression config missing required 'handlers' key"
        raise RuleLoadError(msg)

    if not isinstance(raw["handlers"], dict):
        msg = f"'handlers' must be a mapping, got {type(raw['handlers']).__name__}"
        raise RuleLoadError(msg)

    # Validate each handler entry has required fields
    for handler_id, handler_config in raw["handlers"].items():
        if not isinstance(handler_config, dict):
            msg = f"Handler '{handler_id}' config must be a mapping"
            raise RuleLoadError(msg)
        if "module" not in handler_config:
            msg = f"Handler '{handler_id}' missing required 'module' field"
            raise RuleLoadError(msg)

    # Validate global_allowlist structure
    allowlist = raw.get("global_allowlist", [])
    if not isinstance(allowlist, list):
        msg = f"'global_allowlist' must be a list, got {type(allowlist).__name__}"
        raise RuleLoadError(msg)

    for entry in allowlist:
        if not isinstance(entry, dict):
            msg = "Allowlist entry must be a mapping"
            raise RuleLoadError(msg)
        if "rule_id" not in entry:
            msg = "Allowlist entry missing required 'rule_id' field"
            raise RuleLoadError(msg)
        if "reason" not in entry:
            msg = "Allowlist entry missing required 'reason' field"
            raise RuleLoadError(msg)

    handler_count = len(raw["handlers"])
    logger.debug(
        "Suppression config loaded",
        extra={
            "event": "security.suppressions.loaded",
            "handler_count": handler_count,
            "allowlist_count": len(allowlist),
        },
    )

    return raw


def validate_handler_refs(
    rules: dict[str, list[RuleDefinition]],
    suppression_config: dict[str, Any],
) -> None:
    """Cross-validate handler references in rules against declared handlers.

    Every ``SuppressionRef.handler`` in every rule must map to a handler
    declared in the suppression config.

    Raises ``RuleLoadError`` if any reference is unresolved.
    """
    declared_handlers = set(suppression_config.get("handlers", {}).keys())

    missing: list[tuple[str, str]] = []
    for scanner_name, rule_list in rules.items():
        for rule in rule_list:
            for sup_ref in rule.suppressions:
                if sup_ref.handler not in declared_handlers:
                    missing.append((rule.id, sup_ref.handler))

    if missing:
        details = ", ".join(
            f"rule '{rid}' references handler '{hid}'" for rid, hid in missing
        )
        msg = f"Unresolved handler references: {details}"
        raise RuleLoadError(msg)

    logger.debug(
        "Handler cross-validation passed",
        extra={"event": "security.rules.handler_refs_valid"},
    )


# --- Internal helpers ---


def _load_yaml_file(filepath: Path) -> Any:
    """Load a YAML file and return the parsed content."""
    try:
        with filepath.open() as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as exc:
        msg = f"YAML parse error in {filepath}: {exc}"
        raise RuleLoadError(msg) from exc


def _validate_rule_file(raw: Any, filepath: Path) -> RuleFile:
    """Validate raw YAML data against the RuleFile Pydantic model."""
    if not isinstance(raw, dict):
        msg = f"Rule file must be a mapping, got {type(raw).__name__}: {filepath}"
        raise RuleLoadError(msg)

    try:
        return RuleFile(**raw)
    except ValidationError as exc:
        msg = f"Rule validation failed in {filepath}: {exc}"
        raise RuleLoadError(msg) from exc


def _validate_id_uniqueness(all_ids: list[str]) -> None:
    """Check that all rule IDs are unique across all loaded files."""
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule_id in all_ids:
        if rule_id in seen:
            duplicates.append(rule_id)
        seen.add(rule_id)

    if duplicates:
        msg = f"Duplicate rule IDs: {', '.join(sorted(set(duplicates)))}"
        raise RuleLoadError(msg)
