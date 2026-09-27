"""Shared crypto audit mixin for encrypted stores.

Provides _emit_crypto_event() — the common plumbing for emitting
crypto audit events. Store-specific wrappers supply table/field context.
"""

from __future__ import annotations

from sentinel.crypto.audit import emit_crypto_event, record_id_hash


class CryptoAuditMixin:
    """Crypto audit event emission for any store with an _audit_emitter.

    Composing classes must set on self:
    - _audit_emitter: AuditEmitter | None
    - _key_version: int
    """

    async def _emit_crypto_event(
        self,
        event_type: str,
        *,
        table: str,
        field: str,
        record_id: str,
        outcome: str = "SUCCESS",
        severity: str = "INFO",
    ) -> None:
        """Emit a crypto audit event if an audit_emitter is configured."""
        if self._audit_emitter is None:
            return
        await emit_crypto_event(
            self._audit_emitter,
            event_type,
            outcome=outcome,
            severity=severity,
            details={
                "key_version": self._key_version,
                "target_table": table,
                "target_field": field,
                "record_id_hash": record_id_hash(table, record_id),
            },
        )
