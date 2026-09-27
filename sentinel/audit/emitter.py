"""Fire-and-forget security audit emitter."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from sentinel.audit.events import (
    CATEGORY_DEFAULTS,
    AuditCategoryConfig,
    SecurityAuditEvent,
)
from sentinel.core.context import current_request_id, current_task_id, current_user_id
from sentinel.core.decorators import no_audit_log

logger = logging.getLogger("sentinel.audit")

_SUCCESS_OUTCOMES = frozenset({"CLEAN", "SUCCESS", "APPROVED", "ALLOWED"})

# Reserved key signalling that ``_build_db_payload`` could not iterate the
# producer-supplied ``details`` Mapping. The marker lands INSIDE ``details``
# so it survives both the DB happy path (serialised into the JSONB column)
# and the fallback redaction loop (the redaction descriptor preserves the
# key + a string-length value). Reserved double-underscore-bracketed naming
# avoids collision with KNOWN_DETAILS_KEYS (plain identifiers).
_PAYLOAD_BUILD_FAILED_KEY = "__payload_build_failed__"

# Exact-type-identity dispatch tables for ``_value_descriptor``. Subclasses
# fall through to ``<opaque>`` by design — the bound the design claims
# (zero materialisation, no instance dunder invocation) holds only against
# exact-type identity. ``isinstance`` is unsafe here because it consults
# ``v.__getattribute__("__class__")``, which a hostile instance can intercept.
_DESCRIBED_STRING_TYPES: frozenset[type] = frozenset({str, bytes, bytearray})
_DESCRIBED_CONTAINER_TYPES: frozenset[type] = frozenset(
    {list, tuple, dict, set, frozenset}
)


@no_audit_log
def _safe_type_name(obj: Any) -> str:
    """Defensive type-name extraction.

    ``type(obj).__name__`` is unsafe under a hostile metaclass: a metaclass
    ``__name__`` ``@property`` can raise (or return attacker-controlled
    content). There is no clean reflective bypass — even
    ``type.__getattribute__(type(obj), "__name__")`` triggers descriptor
    resolution. Wrap the lookup in try/except and return a fixed-string
    sentinel on failure (no instance-derived content).

    ``@no_audit_log``: same Q16-FL9 leakage class as ``_safe_error_message`` —
    an auto-injected ``logger.exception`` on the except would materialise
    the hostile-metaclass traceback into the application log stream.
    """
    try:
        return type(obj).__name__
    except Exception:
        return "<unknown>"


@no_audit_log
def _value_descriptor(v: Any) -> str:
    """Strict-bounded type+shape descriptor for fallback redaction.

    Exact-type-identity dispatch over built-in container/string types where
    ``len()`` is cheap and operator-meaningful. The long tail returns
    ``f"{type_name}(<opaque>)"`` — provably zero-materialisation: no
    ``__repr__`` / ``__str__`` / ``__len__`` / ``__getattribute__`` on the
    unknown instance, no ``isinstance`` check (which would itself invoke
    ``v.__getattribute__("__class__")``).

    Subclasses of the dispatched types fall through to ``<opaque>`` by
    design — a ``str`` subclass with a hostile ``__len__`` cannot be
    distinguished safely. The bound depends on the dispatch staying
    identity-keyed.

    ``@no_audit_log``: lives on the audit fallback redaction path. An
    auto-injected entry log here would fire per-key per-fallback emit
    (high-volume noise); a future except block would re-introduce the
    Q16-FL9 traceback-leakage class.
    """
    t = type(v)
    type_name = _safe_type_name(v)
    if t in _DESCRIBED_STRING_TYPES:
        return f"{type_name}({len(v)})"
    if t in _DESCRIBED_CONTAINER_TYPES:
        return f"{type_name}(len={len(v)})"
    return f"{type_name}(<opaque>)"


@no_audit_log
def _safe_error_message(error: BaseException) -> str:
    """Bounded, exception-safe stringification of the originating error.

    Wraps both ``str(error)`` and the ``[:200]`` slice — either step can
    raise on a hostile ``__str__``. On failure returns a sentinel keyed on
    the safe-type-name only (no instance state).

    ``@no_audit_log`` is load-bearing: an auto-injected ``logger.exception``
    on the except below would (a) materialise the traceback containing the
    hostile ``__str__``-raise text, leaking attacker-controlled content into
    the application log stream — the exact Q16-FL9 leakage class — and
    (b) re-introduce a "raises out of fallback" surface if that
    ``logger.exception`` call itself fails. The decorator is the structural
    fix.
    """
    try:
        return str(error)[:200]
    except Exception:
        return f"<error-str-failed:{_safe_type_name(error)}>"


class AuditEmitter:
    """Fire-and-forget audit record writer."""

    def __init__(
        self,
        audit_pool: Any,
        app_pool: Any | None = None,
        pg_pool: Any | None = None,
        category_configs: dict[str, AuditCategoryConfig] | None = None,
        logger: logging.Logger | None = None,
        fallback_logger: logging.Logger | None = None,
        db_write_timeout: float = 5.0,
    ) -> None:
        self._app_pool = app_pool if app_pool is not None else pg_pool
        self._audit_pool = audit_pool
        self._category_configs = category_configs or {
            key: value.model_copy(deep=True) for key, value in CATEGORY_DEFAULTS.items()
        }
        self._logger = logger or globals()["logger"]
        self._fallback_logger = fallback_logger or self._logger
        self._db_write_timeout = db_write_timeout

    @no_audit_log
    async def emit(self, event: SecurityAuditEvent) -> None:
        """Write an audit record without surfacing failures to callers."""
        try:
            if not self._should_capture(event):
                return
            await self._write_to_db(event)
        except Exception as exc:
            try:
                self._write_to_file_fallback(event, exc)
            except Exception:
                self._logger.exception(
                    "Audit fallback write also failed — record lost",
                    extra={
                        "event": "audit.file_fallback_failed",
                        "event_type": event.event_type,
                    },
                )
            else:
                self._logger.warning(
                    "Audit DB write failed, fell back to file",
                    extra={
                        "event": "audit.db_write_failed",
                        "event_type": event.event_type,
                        "error_type": _safe_type_name(exc),
                        "db_write_timeout_s": self._db_write_timeout,
                    },
                    exc_info=True,
                )

    @no_audit_log
    def _should_capture(self, event: SecurityAuditEvent) -> bool:
        config = self._category_configs.get(event.event_category)
        if config is None:
            return True
        if not config.enabled or config.capture_level == "off":
            return False
        if config.capture_level == "full":
            return True
        if config.capture_level == "outcomes_only":
            return event.outcome not in _SUCCESS_OUTCOMES or event.action_taken not in {
                None,
                "ALLOWED",
            }
        return event.outcome not in _SUCCESS_OUTCOMES or event.severity in {
            "MEDIUM",
            "HIGH",
        }

    @no_audit_log
    async def _write_to_db(self, event: SecurityAuditEvent) -> None:
        # D48: bound the entire DB-write path (acquire + RLS setup + INSERT)
        # so audit-DB slowness cannot hold callers beyond audit_db_write_timeout.
        # TimeoutError is an Exception subclass and routes through emit()'s
        # except block to the existing file-fallback warning path.
        await asyncio.wait_for(
            self._write_to_db_unbounded(event),
            timeout=self._db_write_timeout,
        )

    @no_audit_log
    async def _write_to_db_unbounded(self, event: SecurityAuditEvent) -> None:
        payload = self._build_db_payload(event)
        pool = self._select_pool(payload["user_id"])
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO security_audit_log (
                    event_type,
                    event_category,
                    timestamp,
                    user_id,
                    task_id,
                    request_id,
                    source_component,
                    outcome,
                    severity,
                    action_taken,
                    duration_ms,
                    details
                ) VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
                """,
                payload["event_type"],
                payload["event_category"],
                payload["user_id"],
                payload["task_id"],
                payload["request_id"],
                payload["source_component"],
                payload["outcome"],
                payload["severity"],
                payload["action_taken"],
                payload["duration_ms"],
                json.dumps(payload["details"]),
            )

    @no_audit_log
    def _write_to_file_fallback(
        self,
        event: SecurityAuditEvent,
        error: Exception,
    ) -> None:
        # @no_audit_log is load-bearing here: this method writes the
        # last-resort audit record itself, so audit_fix's auto-injected
        # entry/except/negative-path logging would either be redundant
        # (entry log of a fallback firing) or actively harmful.
        # Specifically, an auto-injected ``logger.exception`` on the
        # ``except Exception`` below would (a) leak attacker-controlled
        # ``__str__``-raise text via the traceback, defeating the Q16-F2
        # redaction below, and (b) re-introduce a "raises out of
        # fallback" surface, which is the exact failure mode Q16-FL9
        # was banked to close. The decorator is the structural fix.
        logger.debug(
            "_write_to_file_fallback called",
            extra={
                "event": "audit.emitter._write_to_file_fallback",
                "event_type": _safe_type_name(event),
                "error_type": _safe_type_name(error),
            },
        )
        payload = self._build_db_payload(event)
        # Q16-F2: redact caller-supplied details values. The DB write path
        # carries the raw dict into the audit store (a sensitive-data sink),
        # but the fallback path fans the same dict out through the general
        # logging hierarchy (application log file). Replace each value with
        # a type+length descriptor so operators can reconstruct shape-of-loss
        # without the raw content reaching the log stream.
        # Q16-FL9: hostile/buggy ``__str__`` must not kill the fallback. If
        # ``str(v)`` raises, the audit-trail invariant ("record lands in DB or
        # fallback warning") would otherwise collapse — the outer except in
        # ``emit`` catches the exception and logs ``audit.file_fallback_failed``,
        # losing the record. Per-value containment yields a sentinel string and
        # keeps the surrounding redaction shape stable.
        raw_details = payload["details"]
        redacted_details: dict[str, str] = {}
        for k, v in raw_details.items():
            # D29 / FL-C43-a1: ``_value_descriptor`` is provably bounded
            # (exact-type-identity dispatch + ``<opaque>`` long tail). The
            # try/except containment remains as belt-and-braces against any
            # future addition to the dispatch table that could expose a
            # ``len()`` raise surface.
            try:
                redacted_details[k] = _value_descriptor(v)
            except Exception:
                redacted_details[k] = f"<str-error:{_safe_type_name(v)}>"
        payload["details"] = redacted_details
        payload["_fallback_meta"] = {
            "reason": _safe_type_name(error),
            "error_message": _safe_error_message(error),
            "original_timestamp": datetime.now(UTC).isoformat(),
            "fallback_written_at": datetime.now(UTC).isoformat(),
            "details_redacted": True,
        }
        self._fallback_logger.warning(
            "Security audit fallback record",
            extra={"event": "audit.fallback", "audit_record": payload},
        )

    @no_audit_log
    def _build_db_payload(self, event: SecurityAuditEvent) -> dict[str, Any]:
        # D29 / FL-C22-a1: ``event.details`` is producer-supplied with no
        # runtime-enforced contract (``SecurityAuditEvent`` is a frozen
        # dataclass, not a Pydantic model — type hints are hints). A
        # hostile/buggy ``Mapping`` whose iteration raises would kill this
        # call and break the audit-trail invariant. Surface a single-key
        # marker INSIDE ``details`` so it survives both the DB happy path
        # (serialised into the JSONB column) and the fallback redaction
        # loop (descriptor preserves the marker key + type-name value).
        #
        # ``@no_audit_log`` is load-bearing: an auto-injected
        # ``logger.exception`` on the except below would materialise the
        # traceback containing the hostile ``__iter__``-raise text,
        # leaking attacker-controlled iteration content into the
        # application log stream — the Q16-FL9 leakage class.
        try:
            details = dict(event.details)
        except Exception:
            details = {_PAYLOAD_BUILD_FAILED_KEY: _safe_type_name(event.details)}
        return {
            "event_type": event.event_type,
            "event_category": event.event_category,
            "user_id": current_user_id.get(),
            "task_id": current_task_id.get(),
            "request_id": current_request_id.get(),
            "source_component": event.source_component,
            "outcome": event.outcome,
            "severity": event.severity,
            "action_taken": event.action_taken,
            "duration_ms": event.duration_ms,
            "details": details,
        }

    def _select_pool(self, user_id: int) -> Any:
        if user_id == 0:
            return self._audit_pool
        return self._app_pool
