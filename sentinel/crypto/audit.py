"""Crypto-specific audit event emitter.

Thin wrapper around :class:`~sentinel.audit.emitter.AuditEmitter` that
constructs :class:`~sentinel.audit.events.SecurityAuditEvent` instances
with crypto-specific defaults.  Respects ``crypto_audit_enabled`` and
``crypto_audit_capture_level`` from config.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.decorators import no_audit_log

logger = logging.getLogger(__name__)

# Per-record events suppressed at "key_events_only" capture level.
# Key lifecycle events (loaded, rotated, failed, migration) always pass.
_PER_RECORD_EVENTS = frozenset(
    {
        "crypto.encrypt",
        "crypto.decrypt",
    }
)


def record_id_hash(table: str, primary_key: str) -> str:
    """One-way hash of a record identifier for audit details.

    Returns a truncated hex digest so audit queries can correlate events
    to records without exposing PII.
    """
    raw = f"{table}:{primary_key}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


@no_audit_log  # thin wrapper around emitter — entry logging is noise
async def emit_crypto_event(
    emitter: Any,
    event_type: str,
    *,
    outcome: str,
    severity: str = "INFO",
    details: dict[str, Any] | None = None,
    capture_level: str = "full",
    audit_enabled: bool = True,
) -> None:
    """Emit a crypto audit event via *emitter*.

    Respects *audit_enabled* and *capture_level* to suppress events
    based on the operator's configuration.
    """
    if not audit_enabled:
        return

    if capture_level == "off":
        return

    if capture_level == "key_events_only" and event_type in _PER_RECORD_EVENTS:
        return

    event = SecurityAuditEvent(
        event_type=event_type,
        source_component="crypto",
        outcome=outcome,
        severity=severity,
        details=details or {},
    )
    await emitter.emit(event)
