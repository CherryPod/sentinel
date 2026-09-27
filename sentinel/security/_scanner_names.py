"""Legacy scanner-name mapping — single source of truth for audit shape.

The production pipeline constructs ``ScannerPlugin`` scanners with
canonical meta names (e.g. ``credential``).  External consumers —
audit events, ``PipelineScanResult.results``/``violations`` keys, the
``scanner_config_hash`` — still expect the legacy ``_scanner``-suffixed
form (e.g. ``credential_scanner``).  Changing those names would be a
caller-visible break.

This module centralises the mapping in ONE place.  Every touch point
that emits a scanner name into caller-visible state MUST go through
``legacy_name()``:

- ``pipeline.py`` — ``_scanner_config_hash`` input, ``scanner_names``
  log extras, order-conflict diagnostic messages
- ``_phase_input`` / ``_phase_output`` — audit event construction
  (``scan.manifest.scanners_expected``, ``scan.summary.scanners_completed``,
  ``scan.result.scanner_name``)

The map goes away in Phase 9d-ii when the public API switches to the
new ``ScanResult`` shape (scanner naming is a public contract at that
point, decoupled from internal scanner identifiers).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

_LEGACY_NAME_MAP: dict[str, str] = {
    # Regex scanners (Phase 1) — use ``_scanner`` suffix in legacy audit
    # events and ``PipelineScanResult.results`` keys.
    "credential": "credential_scanner",
    "sensitive_path": "sensitive_path_scanner",
    "command_pattern": "command_pattern_scanner",
    "vulnerability_echo": "vulnerability_echo_scanner",
    # ML / external scanners (Phase 2) — NO ``_scanner`` suffix in legacy
    # output.  ``prompt_guard`` and ``semgrep`` are the pre-existing
    # audit keys; tests assert them verbatim.  Omitted from the map so
    # ``legacy_name()`` returns identity for these two.
}

LEGACY_NAME_MAP: Mapping[str, str] = MappingProxyType(_LEGACY_NAME_MAP)
"""Read-only view over the mapping — consumers cannot mutate."""


def legacy_name(meta_name: str) -> str:
    """Return the legacy ``_scanner``-suffixed name for a canonical meta name.

    Unknown meta names pass through unchanged — supports future scanners
    added after Phase 9d-ii with no legacy-shape history.
    """
    return LEGACY_NAME_MAP.get(meta_name, meta_name)


def scanner_order(scanner) -> int:
    """Return the scanner's declared order."""
    return scanner.scanner_meta.order


def scanner_legacy_name(scanner) -> str:
    """Return the legacy ``_scanner``-suffixed name for any scanner.

    Scanners emit a canonical meta name (``credential``) that is mapped
    through ``LEGACY_NAME_MAP``.  Audit events, ``_scanner_config_hash``,
    and ``_scanner_by_name`` keys all route through this helper so
    caller-visible names stay stable.
    """
    return legacy_name(scanner.scanner_meta.name)


def scanner_is_security(scanner) -> bool:
    """Return True iff the scanner is classified as a security scanner.

    Every plugin registered by the factory is part of the security
    pipeline, so this is always True.  Kept as a helper so conversation
    analysis can continue to call it symmetrically on a scanner list.
    """
    return True
