"""CRUD endpoints for users, contacts, and contact channels.

Management API for the contact registry — not a chat command.
Used by direct HTTP calls or a future UI.

All contact/channel operations are scoped to the authenticated user via
current_user_id contextvar (set by UserContextMiddleware). This ensures
ownership isolation even though the contact_store methods accept explicit
user_id parameters.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from sentinel.api.role_guard import require_role
from sentinel.core.context import current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


def _require_authenticated_user() -> int:
    # Q4 Rule 1 — handler-level backstop for UserContextMiddleware.
    uid = current_user_id.get()
    if uid == 0:
        logger.warning(
            "contacts handler: zero-principal blocked at Rule 1",
            extra={"event": "contacts.rule1.blocked"},
        )
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )
    return uid


# ── Request / Response models ────────────────────────────────────


class ChannelType(StrEnum):
    signal = "signal"
    telegram = "telegram"
    email = "email"
    phone = "phone"
    caldav = "caldav"


class UserCreate(BaseModel):
    display_name: str
    pin: str | None = Field(None, max_length=128)

    @field_validator("display_name")
    @classmethod
    def display_name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("display_name must not be empty")
        return v


class UserUpdate(BaseModel):
    display_name: str | None = None
    pin: str | None = Field(None, max_length=128)


class UserResponse(BaseModel):
    user_id: int
    display_name: str
    is_active: bool
    created_at: str


class ContactCreate(BaseModel):
    display_name: str
    linked_user_id: int | None = None
    is_user: bool = False

    @field_validator("display_name")
    @classmethod
    def display_name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("display_name must not be empty")
        return v


class ContactUpdate(BaseModel):
    display_name: str | None = None
    linked_user_id: int | None = None
    is_user: bool | None = None


class ContactResponse(BaseModel):
    contact_id: int
    user_id: int
    display_name: str
    linked_user_id: int | None
    is_user: bool
    created_at: str


class ContactWithChannelsResponse(ContactResponse):
    channels: list[ChannelResponse] = []


class ChannelCreate(BaseModel):
    channel: ChannelType
    identifier: str
    is_default: bool = True

    @field_validator("identifier")
    @classmethod
    def identifier_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("identifier must not be empty")
        return v


class ChannelUpdate(BaseModel):
    channel: ChannelType | None = None
    identifier: str | None = None
    is_default: bool | None = None


class ChannelResponse(BaseModel):
    id: int
    contact_id: int
    channel: str
    identifier: str
    is_default: bool
    created_at: str


# Forward ref for ContactWithChannelsResponse
ContactWithChannelsResponse.model_rebuild()


# ── Store accessors (set during lifespan) ────────────────────────

_contact_store: Any = None
_routine_store: Any = None
_audit_emitter: Any = None


def init_stores(
    contact_store: Any, routine_store: Any, audit_emitter: Any = None
) -> None:
    """Called from app lifespan to inject store references."""
    global _contact_store, _routine_store, _audit_emitter
    _contact_store = contact_store
    _routine_store = routine_store
    _audit_emitter = audit_emitter


def _get_contact_store():
    if _contact_store is None:
        raise HTTPException(status_code=503, detail="Contact store not available")
    return _contact_store


def _get_routine_store():
    if _routine_store is None:
        raise HTTPException(status_code=503, detail="Routine store not available")
    return _routine_store


def _user_response(user: dict) -> dict:
    """Strip pin_hash from user dict before returning."""
    return {
        "user_id": user["user_id"],
        "display_name": user["display_name"],
        "role": user.get("role", "user"),
        "trust_level": user.get("trust_level"),
        "is_active": user["is_active"],
        "created_at": user["created_at"],
    }


# ── User endpoints ───────────────────────────────────────────────


@router.get("/users")
async def list_users(active_only: Annotated[bool, Query()] = True):
    store = _get_contact_store()
    await require_role("admin", store, audit_emitter=_audit_emitter)
    users = await store.list_users(active_only=active_only)
    return [_user_response(u) for u in users]


@router.get("/users/{user_id}")
async def get_user(user_id: int):
    logger.debug(
        "get_user called", extra={"event": "contacts.get_user", "user_id": user_id}
    )
    store = _get_contact_store()
    await require_role("admin", store, audit_emitter=_audit_emitter)
    user = await store.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_response(user)


@router.post("/users", status_code=201)
async def create_user(req: UserCreate):
    logger.debug(
        "create_user called",
        extra={"event": "contacts.create_user", "req_type": type(req).__name__},
    )
    store = _get_contact_store()
    await require_role("admin", store, audit_emitter=_audit_emitter)
    # Hash PIN before storing if provided
    pin_stored = None
    if req.pin:
        from sentinel.api.auth import PinVerifier

        pin_stored = PinVerifier(req.pin).to_stored()
    user = await store.create_user(
        display_name=req.display_name,
        pin_hash=pin_stored,
    )
    return _user_response(user)


@router.put("/users/{user_id}")
async def update_user(user_id: int, req: UserUpdate):
    logger.debug(
        "update_user called",
        extra={
            "event": "contacts.update_user",
            "user_id": user_id,
            "req_type": type(req).__name__,
        },
    )
    store = _get_contact_store()
    await require_role("admin", store, audit_emitter=_audit_emitter)
    fields: dict[str, Any] = {}
    if req.display_name is not None:
        fields["display_name"] = req.display_name
    if req.pin is not None:
        # Hash PIN before storing
        from sentinel.api.auth import PinVerifier

        fields["pin_hash"] = PinVerifier(req.pin).to_stored()
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    user = await store.update_user(user_id, **fields)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_response(user)


@router.delete("/users/{user_id}")
async def deactivate_user(user_id: int):
    logger.debug(
        "deactivate_user called",
        extra={"event": "contacts.deactivate_user", "user_id": user_id},
    )
    store = _get_contact_store()
    await require_role("admin", store, audit_emitter=_audit_emitter)
    existed = await store.deactivate_user(user_id)
    if not existed:
        raise HTTPException(status_code=404, detail="User not found")
    user = await store.get_user(user_id)
    return _user_response(user)


# ── Contact endpoints ────────────────────────────────────────────


@router.get("/contacts")
async def list_contacts():
    # Enforce ownership: always use the authenticated user from context, not client input
    uid = _require_authenticated_user()
    store = _get_contact_store()
    contacts = await store.list_contacts(uid)
    return [ContactResponse(**c).model_dump() for c in contacts]


@router.get("/contacts/{contact_id}")
async def get_contact(contact_id: int):
    logger.debug(
        "get_contact called",
        extra={"event": "contacts.get_contact", "contact_id": contact_id},
    )
    uid = _require_authenticated_user()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    channels = await store.get_channels(contact_id, user_id=uid)
    return {
        **ContactResponse(**contact).model_dump(),
        "channels": [ChannelResponse(**ch).model_dump() for ch in channels],
    }


@router.post("/contacts", status_code=201)
async def create_contact(req: ContactCreate):
    # Enforce ownership: always use the authenticated user from context
    uid = _require_authenticated_user()
    store = _get_contact_store()
    try:
        contact = await store.create_contact(
            user_id=uid,
            display_name=req.display_name,
            linked_user_id=req.linked_user_id,
            is_user=req.is_user,
        )
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail="Duplicate contact") from exc
        raise
    return ContactResponse(**contact).model_dump()


@router.put("/contacts/{contact_id}")
async def update_contact(contact_id: int, req: ContactUpdate):
    logger.debug(
        "update_contact called",
        extra={
            "event": "contacts.update_contact",
            "contact_id": contact_id,
            "req_type": type(req).__name__,
        },
    )
    uid = _require_authenticated_user()
    store = _get_contact_store()
    fields: dict[str, Any] = {}
    if req.display_name is not None:
        fields["display_name"] = req.display_name
    if req.linked_user_id is not None:
        fields["linked_user_id"] = req.linked_user_id
    if req.is_user is not None:
        fields["is_user"] = req.is_user
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    contact = await store.update_contact(contact_id, user_id=uid, **fields)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return ContactResponse(**contact).model_dump()


@router.delete("/contacts/{contact_id}")
async def delete_contact(contact_id: int, confirm: Annotated[bool, Query()] = False):
    logger.debug(
        "delete_contact called",
        extra={
            "event": "contacts.delete_contact",
            "contact_id": contact_id,
            "confirm": confirm,
        },
    )
    uid = _require_authenticated_user()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")

    # Check routine references unless confirm=true
    if not confirm:
        routine_store = _get_routine_store()
        routines = await routine_store.list(user_id=uid, limit=1000)
        matching = []
        name = contact["display_name"].lower()
        for r in routines:
            prompt = r.action_config.get("prompt", "")
            if name in prompt.lower():
                matching.append(r.name)
        if matching:
            return {
                "warning": f"Contact referenced in {len(matching)} routine(s): {matching}",
                "confirm_url": f"/api/contacts/{contact_id}?confirm=true",
            }

    deleted = await store.delete_contact(contact_id, user_id=uid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Contact not found")
    return {"status": "deleted", "contact_id": contact_id}


# ── Channel endpoints ────────────────────────────────────────────


@router.get("/contacts/{contact_id}/channels")
async def list_channels(contact_id: int):
    logger.debug(
        "list_channels called",
        extra={"event": "contacts.list_channels", "contact_id": contact_id},
    )
    uid = _require_authenticated_user()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    channels = await store.get_channels(contact_id, user_id=uid)
    return [ChannelResponse(**ch).model_dump() for ch in channels]


@router.post("/contacts/{contact_id}/channels", status_code=201)
async def create_channel(contact_id: int, req: ChannelCreate):
    logger.debug(
        "create_channel called",
        extra={
            "event": "contacts.create_channel",
            "contact_id": contact_id,
            "req_type": type(req).__name__,
        },
    )
    uid = _require_authenticated_user()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    try:
        channel = await store.create_channel(
            contact_id=contact_id,
            channel=req.channel.value,
            identifier=req.identifier,
            is_default=req.is_default,
        )
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            raise HTTPException(
                status_code=409,
                detail="Duplicate channel+identifier combination",
            ) from exc
        raise
    return ChannelResponse(**channel).model_dump()


@router.put("/contacts/{contact_id}/channels/{channel_id}")
async def update_channel(contact_id: int, channel_id: int, req: ChannelUpdate):
    logger.debug(
        "update_channel called",
        extra={
            "event": "contacts.update_channel",
            "contact_id": contact_id,
            "channel_id": channel_id,
            "req_type": type(req).__name__,
        },
    )
    uid = _require_authenticated_user()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    fields: dict[str, Any] = {}
    if req.channel is not None:
        fields["channel"] = req.channel.value
    if req.identifier is not None:
        fields["identifier"] = req.identifier
    if req.is_default is not None:
        fields["is_default"] = req.is_default
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    channel = await store.update_channel(channel_id, user_id=uid, **fields)
    if channel is None:
        raise HTTPException(status_code=404, detail="Channel not found")
    return ChannelResponse(**channel).model_dump()


@router.delete("/contacts/{contact_id}/channels/{channel_id}")
async def delete_channel(contact_id: int, channel_id: int):
    logger.debug(
        "delete_channel called",
        extra={
            "event": "contacts.delete_channel",
            "contact_id": contact_id,
            "channel_id": channel_id,
        },
    )
    uid = _require_authenticated_user()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    deleted = await store.delete_channel(channel_id, user_id=uid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {"status": "deleted", "channel_id": channel_id}
