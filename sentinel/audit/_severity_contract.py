"""Wire-contract registry for SecurityAuditEvent severity (D39 / FL-C19-a2).

Source of truth for allowed severity per event_type.  Adjudicated 2026-05-03.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType

_VALID_SEVERITIES: frozenset[str] = frozenset({"INFO", "LOW", "MEDIUM", "HIGH"})


@dataclass(frozen=True, slots=True)
class EventContract:
    """Closed severity set for one event_type; branch_constraints is documentation only."""

    severities: frozenset[str]
    branch_constraints: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        unknown = self.severities - _VALID_SEVERITIES
        if unknown:
            raise ValueError(f"Unknown severity values in contract: {unknown!r}")
        object.__setattr__(
            self, "branch_constraints", MappingProxyType(dict(self.branch_constraints))
        )


def _ec(sevs: set[str], **bc: str) -> EventContract:
    return EventContract(severities=frozenset(sevs), branch_constraints=bc)


AUDIT_EVENT_CONTRACT: dict[str, EventContract] = {
    # scan.*
    "scan.manifest": _ec({"INFO"}),
    "scan.summary": _ec({"INFO", "MEDIUM", "HIGH"}),
    "scan.gate": _ec({"INFO", "MEDIUM", "HIGH"}),
    "scan.result": _ec({"INFO", "MEDIUM", "HIGH"}),
    # tool.*
    "tool.dispatch": _ec({"INFO"}),
    "tool.completed": _ec({"INFO", "MEDIUM", "HIGH"}),
    "tool.blocked": _ec({"HIGH"}),
    "tool.timeout": _ec({"HIGH"}),
    # access.*
    "access.role_denied": _ec({"MEDIUM"}),
    "access.file_blocked": _ec({"HIGH"}),
    "access.command_blocked": _ec({"HIGH"}),
    # auth.*
    "auth.login": _ec({"INFO", "MEDIUM"}),
    "auth.lockout": _ec({"HIGH"}),
    "auth.logout": _ec({"INFO"}),
    "auth.session_revoke": _ec({"INFO"}),
    "auth.pin_change": _ec({"INFO"}),
    # approval.*
    "approval.requested": _ec({"INFO"}),
    "approval.decided": _ec({"INFO"}),
    "approval.expired": _ec({"INFO"}),
    # D39 Pass 1: MEDIUM (code currently under-emits INFO — fixed by D39-1)
    "approval.submit_session_state_unavailable": _ec({"MEDIUM"}),
    "approval.submit_blocked_session_locked": _ec({"MEDIUM"}),
    "approval.submit_blocked_session_store_error": _ec({"MEDIUM"}),
    # D39 Ask 4: BLOCKED-class → MEDIUM; WARNED state-unavailable → INFO
    "approval.confirmation_submit_source_key_mismatch": _ec({"MEDIUM"}),
    "approval.confirmation_session_state_unavailable": _ec({"INFO"}),
    "approval.confirmation_submit_blocked_session_locked": _ec({"MEDIUM"}),
    "approval.confirmation_submit_blocked_session_store_error": _ec({"MEDIUM"}),
    # trust.*
    # D39-2#D1: code emits INFO-only (CLEAN and BYPASSED branches both default severity);
    # narrowed from {INFO, MEDIUM} to match what tool_dispatch.py actually emits.
    "trust.provenance_check": _ec({"INFO"}),
    # HIGH valid for constitutional-denylist BLOCKED branch only
    "trust.constraint_check": _ec(
        {"INFO", "MEDIUM", "HIGH"},
        HIGH="constitutional-denylist BLOCKED branch only (details['constitutional'] == True)",
    ),
    # Code correctly emits MEDIUM; doc previously claimed HIGH (doc fixed by D39-1)
    "trust.gate_block": _ec({"MEDIUM"}),
    # conversation.*
    "conversation.analysis": _ec({"INFO", "MEDIUM", "HIGH"}),
    "conversation.override_attempt": _ec({"MEDIUM", "HIGH"}),
    "conversation.mtm_shadow": _ec({"LOW"}),
    "conversation.locked": _ec({"HIGH"}),
    # Code correctly emits HIGH for action=block; doc previously claimed INFO/MEDIUM only
    "conversation.mtm_turn": _ec({"INFO", "MEDIUM", "HIGH"}),
    "conversation.mtm_summary": _ec({"INFO", "MEDIUM", "HIGH"}),
    # system.*
    "system.startup": _ec({"INFO"}),
    "system.maintenance": _ec({"INFO", "MEDIUM"}),
    # Code correctly emits INFO or LOW; doc previously claimed INFO/MEDIUM
    "system.telegram_post_migration": _ec({"INFO", "LOW"}),
    "system.session_crash_reconciliation": _ec({"INFO"}),
    # crypto.*
    "crypto.encrypt": _ec({"INFO"}),
    "crypto.decrypt": _ec({"INFO"}),
    "crypto.decrypt_failed": _ec({"HIGH"}),
    "crypto.migration_started": _ec({"INFO", "MEDIUM"}),
    "crypto.migration_progress": _ec({"INFO", "MEDIUM"}),
    "crypto.migration_completed": _ec({"INFO", "MEDIUM"}),
    # routine.*
    # D39 Pass 1+Ask3: MEDIUM (code currently under-emits INFO — fixed by D39-1)
    "routine.delete_blocked": _ec({"MEDIUM"}),
    "routine.deleted": _ec({"INFO"}),
    "routine.delete_denied": _ec({"MEDIUM"}),
    # D30#D1: ownership-denial events for get/update/trigger/executions endpoints
    "routine.get_denied": _ec({"MEDIUM"}),
    "routine.update_denied": _ec({"MEDIUM"}),
    "routine.trigger_denied": _ec({"MEDIUM"}),
    "routine.executions_denied": _ec({"MEDIUM"}),
}
