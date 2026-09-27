"""Shared types for tool handler modules.

These types were extracted from executor.py during the Phase 1 structural
refactor. They are re-exported from executor.py for backwards compatibility.

Exception classes moved to sentinel.core.exceptions (SH-3) — re-exported here.
"""

from sentinel.core.exceptions import ToolBlockedError, ToolError

__all__ = ["ToolBlockedError", "ToolError", "_CredentialOverlay"]


class _CredentialOverlay:
    """Proxy that overlays per-user credentials onto base settings.

    Looks up attribute names in field_map -> creds dict. Falls through
    to base settings for anything not in the map or not in creds.
    Replaces the per-service inner classes (_UserCalDavConfig, _UserEmailConfig).
    """

    def __init__(self, creds: dict, base, field_map: dict[str, str]):
        self._creds = creds
        self._base = base
        self._field_map = field_map

    def __getattr__(self, name: str):
        if name in self._field_map:
            cred_key = self._field_map[name]
            if cred_key in self._creds:
                return self._creds[cred_key]
        return getattr(self._base, name)
