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
from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from sentinel.api.role_guard import require_role
from sentinel.core.context import current_user_id

logger = logging.getLogger("sentinel.api.contacts")

VALID_CHANNELS = {"signal", "telegram", "email", "phone", "caldav"}

router = APIRouter(prefix="/api")


# ── Request / Response models ────────────────────────────────────


class ChannelType(str, Enum):
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


def init_stores(contact_store: Any, routine_store: Any) -> None:
    """Called from app lifespan to inject store references."""
    global _contact_store, _routine_store
    _contact_store = contact_store
    _routine_store = routine_store


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
async def list_users(active_only: bool = Query(True)):
    store = _get_contact_store()
    await require_role("admin", store)
    users = await store.list_users(active_only=active_only)
    return [_user_response(u) for u in users]


@router.get("/users/{user_id}")
async def get_user(user_id: int):
    store = _get_contact_store()
    await require_role("admin", store)
    user = await store.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_response(user)


@router.post("/users", status_code=201)
async def create_user(req: UserCreate):
    store = _get_contact_store()
    await require_role("admin", store)
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
    store = _get_contact_store()
    await require_role("admin", store)
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
    store = _get_contact_store()
    await require_role("admin", store)
    existed = await store.deactivate_user(user_id)
    if not existed:
        raise HTTPException(status_code=404, detail="User not found")
    user = await store.get_user(user_id)
    return _user_response(user)


# ── Contact endpoints ────────────────────────────────────────────


@router.get("/contacts")
async def list_contacts():
    # Enforce ownership: always use the authenticated user from context, not client input
    uid = current_user_id.get()
    store = _get_contact_store()
    contacts = await store.list_contacts(uid)
    return [ContactResponse(**c).model_dump() for c in contacts]


@router.get("/contacts/{contact_id}")
async def get_contact(contact_id: int):
    uid = current_user_id.get()
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
    uid = current_user_id.get()
    store = _get_contact_store()
    try:
        contact = await store.create_contact(
            user_id=uid,
            display_name=req.display_name,
            linked_user_id=req.linked_user_id,
            is_user=req.is_user,
        )
    except (ValueError, Exception) as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail="Duplicate contact")
        raise
    return ContactResponse(**contact).model_dump()


@router.put("/contacts/{contact_id}")
async def update_contact(contact_id: int, req: ContactUpdate):
    uid = current_user_id.get()
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
async def delete_contact(contact_id: int, confirm: bool = Query(False)):
    uid = current_user_id.get()
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
    uid = current_user_id.get()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    channels = await store.get_channels(contact_id, user_id=uid)
    return [ChannelResponse(**ch).model_dump() for ch in channels]


@router.post("/contacts/{contact_id}/channels", status_code=201)
async def create_channel(contact_id: int, req: ChannelCreate):
    uid = current_user_id.get()
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
    except (ValueError, Exception) as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            raise HTTPException(
                status_code=409,
                detail="Duplicate channel+identifier combination",
            )
        raise
    return ChannelResponse(**channel).model_dump()


@router.put("/contacts/{contact_id}/channels/{channel_id}")
async def update_channel(contact_id: int, channel_id: int, req: ChannelUpdate):
    uid = current_user_id.get()
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
    uid = current_user_id.get()
    store = _get_contact_store()
    contact = await store.get_contact(contact_id, user_id=uid)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    deleted = await store.delete_channel(channel_id, user_id=uid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {"status": "deleted", "channel_id": channel_id}
