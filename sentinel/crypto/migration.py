"""Migration helpers for encrypting existing database records.

Provides two idempotent migration functions:

- :func:`migrate_credentials` — re-encrypts legacy credential rows
  (single-key AESGCM) to HKDF-derived per-record keys with AAD binding.
- :func:`migrate_contact_identifiers` — encrypts plaintext contact
  channel identifiers and computes HMAC blind indexes.

Both functions are batched, audited, and idempotent.  They are designed
to be run as one-off migration scripts — NOT in the hot path.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.credential_store import decrypt_credentials
from sentinel.core.decorators import no_audit_log
from sentinel.crypto.audit import emit_crypto_event
from sentinel.crypto.blind_index import derive_and_compute
from sentinel.crypto.cipher import encrypt_field_with_salt

logger = logging.getLogger(__name__)

# AAD templates — must match the stores exactly
_AAD_CRED_TEMPLATE = "user_credentials:{uid}:{service}"
_AAD_CHAN_TEMPLATE = "contact_channels:{channel_id}:{channel}"

_DEFAULT_BATCH_SIZE = 100
_DEFAULT_KEY_VERSION = 1


@dataclass
class MigrationResult:
    """Summary of a migration run."""

    table: str
    records_migrated: int = 0
    records_skipped: int = 0
    records_failed: int = 0
    batches_processed: int = 0
    duration_ms: float = 0.0
    errors: list[str] = field(default_factory=list)


# ── Audit helpers ────────────────────────────────────────────────


async def _emit(
    emitter: Any | None,
    event_type: str,
    *,
    outcome: str = "SUCCESS",
    severity: str = "INFO",
    details: dict[str, Any] | None = None,
) -> None:
    """Emit a crypto-migration audit event via ``emit_crypto_event``.

    Q17-F12: routes through the single crypto emit chokepoint so any
    future wiring of ``audit_enabled`` / ``capture_level`` at the caller
    applies uniformly. Migration events are key-lifecycle (not in
    ``_PER_RECORD_EVENTS``) and always pass under
    ``capture_level="key_events_only"``; the defaults here preserve
    pre-fix always-on semantics.
    """
    if emitter is None:
        return
    await emit_crypto_event(
        emitter,
        event_type,
        outcome=outcome,
        severity=severity,
        details=details,
    )


# ── Credential migration ─────────────────────────────────────────


@no_audit_log  # receives master_key — must not be auto-logged
async def migrate_credentials(
    pool: Any,
    master_key: bytes,
    *,
    audit_emitter: Any | None = None,
    batch_size: int = _DEFAULT_BATCH_SIZE,
    key_version: int = _DEFAULT_KEY_VERSION,
) -> MigrationResult:
    """Re-encrypt legacy credentials with HKDF-derived per-record keys.

    Idempotent: rows where ``field_salt IS NOT NULL`` are skipped.
    Processes in batches of *batch_size* rows.
    """
    table = "user_credentials"
    result = MigrationResult(table=table)
    start = time.monotonic()

    # Pre-count for audit event and progress tracking
    async with pool.acquire() as conn:
        total_records = (
            await conn.fetchval(
                "SELECT COUNT(*) FROM user_credentials WHERE field_salt IS NULL",
            )
            or 0
        )

    logger.info(
        "Credential migration starting",
        extra={
            "event": "crypto.migration.credentials_start",
            "batch_size": batch_size,
            "total_records": total_records,
        },
    )
    await _emit(
        audit_emitter,
        "crypto.migration_started",
        details={"target_table": table, "total_records": total_records},
    )

    last_id = 0
    while True:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT credential_id, user_id, service, encrypted_value "
                "FROM user_credentials "
                "WHERE credential_id > $1 AND field_salt IS NULL "
                "ORDER BY credential_id "
                "LIMIT $2",
                last_id,
                batch_size,
            )

        if not rows:
            break

        # Advance keyset cursor past all rows in this batch (including failures)
        # so a persistently broken row can never cause an infinite re-select.
        batch_max_id = rows[-1]["credential_id"]

        # Re-encrypt each row in the batch
        async with pool.acquire() as conn:
            for row in rows:
                uid = row["user_id"]
                service = row["service"]
                blob = bytes(row["encrypted_value"])
                row_id = row["credential_id"]

                try:
                    # Decrypt with legacy single-key path
                    data = decrypt_credentials(blob, master_key)
                    plaintext = json.dumps(data).encode("utf-8")

                    # Re-encrypt with HKDF + AAD
                    aad = _AAD_CRED_TEMPLATE.format(uid=uid, service=service).encode()
                    new_blob, salt = encrypt_field_with_salt(master_key, plaintext, aad)

                    await conn.execute(
                        "UPDATE user_credentials SET "
                        "encrypted_value = $1, field_salt = $2, key_version = $3 "
                        "WHERE credential_id = $4",
                        new_blob,
                        salt,
                        key_version,
                        row_id,
                    )
                    result.records_migrated += 1
                except Exception as exc:
                    logger.warning(
                        "Failed to migrate credential row",
                        extra={
                            "event": "crypto.migration.credential_error",
                            "row_id": row_id,
                            "error_category": type(exc).__name__,
                        },
                        exc_info=True,
                    )
                    result.errors.append(f"row {row_id}: {exc}")
                    result.records_failed += 1

        last_id = batch_max_id

        result.batches_processed += 1
        logger.info(
            "Credential migration batch complete",
            extra={
                "event": "crypto.migration.credentials_progress",
                "records_migrated": result.records_migrated,
                "batch": result.batches_processed,
            },
        )
        records_remaining = max(
            0, total_records - result.records_migrated - len(result.errors)
        )
        await _emit(
            audit_emitter,
            "crypto.migration_progress",
            details={
                "target_table": table,
                "records_processed": result.records_migrated,
                "records_remaining": records_remaining,
                "batch": result.batches_processed,
            },
        )

    # Verify no unmigrated rows remain
    async with pool.acquire() as conn:
        remaining = await conn.fetchval(
            "SELECT COUNT(*) FROM user_credentials WHERE field_salt IS NULL",
        )
    if remaining and remaining > 0:
        logger.warning(
            "Credential migration incomplete — unmigrated rows remain",
            extra={
                "event": "crypto.migration.credentials_incomplete",
                "remaining": remaining,
            },
        )

    result.duration_ms = (time.monotonic() - start) * 1000
    logger.info(
        "Credential migration complete",
        extra={
            "event": "crypto.migration.credentials_complete",
            "records_migrated": result.records_migrated,
            "duration_ms": result.duration_ms,
        },
    )
    await _emit(
        audit_emitter,
        "crypto.migration_completed",
        details={
            "target_table": table,
            "total_records": result.records_migrated,
            "duration_ms": result.duration_ms,
        },
    )

    return result


# ── Contact identifier migration ─────────────────────────────────


@no_audit_log  # receives master_key — must not be auto-logged
async def migrate_contact_identifiers(
    pool: Any,
    master_key: bytes,
    *,
    audit_emitter: Any | None = None,
    batch_size: int = _DEFAULT_BATCH_SIZE,
    key_version: int = _DEFAULT_KEY_VERSION,
) -> MigrationResult:
    """Encrypt plaintext contact identifiers and compute HMAC indexes.

    Idempotent: rows where ``encrypted_identifier IS NOT NULL`` are skipped.
    Processes in batches of *batch_size* rows.
    """
    table = "contact_channels"
    result = MigrationResult(table=table)
    start = time.monotonic()

    # Pre-count for audit event and progress tracking
    async with pool.acquire() as conn:
        total_records = (
            await conn.fetchval(
                "SELECT COUNT(*) FROM contact_channels "
                "WHERE encrypted_identifier IS NULL",
            )
            or 0
        )

    logger.info(
        "Contact identifier migration starting",
        extra={
            "event": "crypto.migration.contacts_start",
            "batch_size": batch_size,
            "total_records": total_records,
        },
    )
    await _emit(
        audit_emitter,
        "crypto.migration_started",
        details={"target_table": table, "total_records": total_records},
    )

    last_id = 0
    while True:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, channel, identifier "
                "FROM contact_channels "
                "WHERE id > $1 AND encrypted_identifier IS NULL "
                "ORDER BY id "
                "LIMIT $2",
                last_id,
                batch_size,
            )

        if not rows:
            break

        # Advance keyset cursor past all rows in this batch (including failures)
        # so a persistently broken row can never cause an infinite re-select.
        batch_max_id = rows[-1]["id"]

        # Encrypt each row in the batch
        async with pool.acquire() as conn:
            for row in rows:
                channel_id = row["id"]
                channel = row["channel"]
                identifier = row["identifier"]

                try:
                    # Encrypt identifier with HKDF + AAD
                    aad = _AAD_CHAN_TEMPLATE.format(
                        channel_id=channel_id, channel=channel
                    ).encode()
                    encrypted, salt = encrypt_field_with_salt(
                        master_key, identifier.encode("utf-8"), aad
                    )

                    # Compute HMAC blind index
                    hmac_value = derive_and_compute(master_key, key_version, identifier)

                    await conn.execute(
                        "UPDATE contact_channels SET "
                        "encrypted_identifier = $1, identifier_salt = $2, "
                        "identifier_hmac = $3, key_version = $4 "
                        "WHERE id = $5",
                        encrypted,
                        salt,
                        hmac_value,
                        key_version,
                        channel_id,
                    )
                    result.records_migrated += 1
                except Exception as exc:
                    logger.warning(
                        "Failed to migrate contact channel row",
                        extra={
                            "event": "crypto.migration.contact_error",
                            "channel_id": channel_id,
                            "error_category": type(exc).__name__,
                        },
                        exc_info=True,
                    )
                    result.errors.append(f"channel {channel_id}: {exc}")
                    result.records_failed += 1

        last_id = batch_max_id

        result.batches_processed += 1
        logger.info(
            "Contact identifier migration batch complete",
            extra={
                "event": "crypto.migration.contacts_progress",
                "records_migrated": result.records_migrated,
                "batch": result.batches_processed,
            },
        )
        records_remaining = max(
            0, total_records - result.records_migrated - len(result.errors)
        )
        await _emit(
            audit_emitter,
            "crypto.migration_progress",
            details={
                "target_table": table,
                "records_processed": result.records_migrated,
                "records_remaining": records_remaining,
                "batch": result.batches_processed,
            },
        )

    # Verify no unmigrated rows remain
    async with pool.acquire() as conn:
        remaining = await conn.fetchval(
            "SELECT COUNT(*) FROM contact_channels WHERE encrypted_identifier IS NULL",
        )
    if remaining and remaining > 0:
        logger.warning(
            "Contact migration incomplete — unmigrated rows remain",
            extra={
                "event": "crypto.migration.contacts_incomplete",
                "remaining": remaining,
            },
        )

    result.duration_ms = (time.monotonic() - start) * 1000
    logger.info(
        "Contact identifier migration complete",
        extra={
            "event": "crypto.migration.contacts_complete",
            "records_migrated": result.records_migrated,
            "duration_ms": result.duration_ms,
        },
    )
    await _emit(
        audit_emitter,
        "crypto.migration_completed",
        details={
            "target_table": table,
            "total_records": result.records_migrated,
            "duration_ms": result.duration_ms,
        },
    )

    return result
