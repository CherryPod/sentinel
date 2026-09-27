"""CRUD endpoints for per-user service credentials.

Passwords and secrets are write-only — GET returns masked values.
All operations scoped to the authenticated user via current_user_id.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.core.context import current_user_id
from sentinel.core.credential_store import mask_sensitive
from sentinel.security.ssrf import (
    UrlValidationError,
    _parse_allowlist,
    parse_and_check_syntactic,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/credentials")

# ── Store accessor (set during lifespan) ──────────────────────────

_credential_store: Any = None


def init_credential_store(credential_store: Any) -> None:
    """Called from app lifespan to inject store reference."""
    global _credential_store
    _credential_store = credential_store


def _get_store():
    if _credential_store is None:
        raise HTTPException(status_code=503, detail="Credential store not available")
    return _credential_store


# ── Request/Response models ───────────────────────────────────────


class CredentialSet(BaseModel):
    """Credential data to store. Fields vary by service."""

    model_config = {"extra": "allow"}


class CredentialResponse(BaseModel):
    service: str
    data: dict


# ── Endpoints ─────────────────────────────────────────────────────


@router.get("")
async def list_services():
    """List services the current user has credentials for (no values)."""
    store = _get_store()
    services = await store.list_services()
    return {"services": services}


@router.get("/{service}")
async def get_credential(service: str):
    """Get credential for a service (sensitive fields masked)."""
    store = _get_store()
    data = await store.get(service)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No credentials for {service}")
    uid = current_user_id.get()
    logger.info(
        "Credential read for service=%s by user_id=%d",
        service,
        uid,
        extra={"event": "credential.read"},
    )
    return CredentialResponse(service=service, data=mask_sensitive(data))


@router.put("/{service}")
async def set_credential(service: str, req: CredentialSet):
    """Set/update credentials for a service. Encrypts before storing."""
    store = _get_store()
    data = req.model_dump()
    if not data:
        raise HTTPException(status_code=400, detail="No credential data provided")
    _validate_service_credential(service, data)
    await store.set(service, data)
    uid = current_user_id.get()
    logger.info(
        "Credential set for service=%s by user_id=%d",
        service,
        uid,
        extra={"event": "credential.set"},
    )
    return {"status": "stored", "service": service}


def _validate_service_credential(service: str, data: dict) -> None:
    """Per-service syntactic validation before the opaque store.set.

    Q12-F1: CalDAV credentials accept an attacker-controllable URL string
    that flows into ``caldav.DAVClient``. Enforce SSRF policy at PUT so
    operators see a 400 immediately rather than a deferred ToolError.
    Use-time ``resolve_and_check_private`` is the hard enforcement
    boundary (see ``caldav_calendar._get_caldav_client``) — this PUT
    gate is belt-and-braces, not the only line.
    """
    if service != "caldav":
        return
    url = data.get("url")
    if not url or not isinstance(url, str):
        return
    # Deferred import: settings reach here via module import cycle otherwise.
    from sentinel.core.config import Settings

    settings = Settings()
    allowlist = _parse_allowlist(settings.ssrf_caldav_allowlist)
    try:
        parse_and_check_syntactic(
            url,
            allow_http=settings.ssrf_allow_http,
            allowlist=allowlist,
        )
    except UrlValidationError as exc:
        logger.info(
            "Credential PUT rejected by SSRF policy",
            extra={
                "event": "credential.set_rejected",
                "service": service,
                "reason": exc.category,
                "host": exc.host,
            },
        )
        raise HTTPException(
            status_code=400,
            detail=f"caldav url rejected: {exc.reason}",
        ) from exc


@router.delete("/{service}")
async def delete_credential(service: str):
    """Delete credentials for a service."""
    store = _get_store()
    deleted = await store.delete(service)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No credentials for {service}")
    uid = current_user_id.get()
    logger.info(
        "Credential deleted for service=%s by user_id=%d",
        service,
        uid,
        extra={"event": "credential.deleted"},
    )
    return {"status": "deleted", "service": service}
