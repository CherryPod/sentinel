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

logger = logging.getLogger("sentinel.api.credentials")

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
    return CredentialResponse(service=service, data=mask_sensitive(data))


@router.put("/{service}")
async def set_credential(service: str, req: CredentialSet):
    """Set/update credentials for a service. Encrypts before storing."""
    store = _get_store()
    data = req.model_dump()
    if not data:
        raise HTTPException(status_code=400, detail="No credential data provided")
    await store.set(service, data)
    uid = current_user_id.get()
    logger.info("Credential set for service=%s by user_id=%d", service, uid,
                extra={"event": "credential_set"})
    return {"status": "stored", "service": service}


@router.delete("/{service}")
async def delete_credential(service: str):
    """Delete credentials for a service."""
    store = _get_store()
    deleted = await store.delete(service)
    uid = current_user_id.get()
    logger.info("Credential deleted for service=%s by user_id=%d", service, uid,
                extra={"event": "credential_deleted"})
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No credentials for {service}")
    return {"status": "deleted", "service": service}
