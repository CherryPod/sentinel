"""Contact resolution — maps names to opaque IDs and IDs to channel identifiers.

Sits between ContactStore and the rest of the system. Intake calls
resolve_sender() and rewrite_message() on every incoming message.
Tool dispatch calls resolve_recipient_to_channel() on every outbound message.
resolve_tool_recipient() is the shared outbound helper used by both
tool dispatch (planner path) and fast path.

All functions take a ContactStore dependency (injected, not global).
"""

from __future__ import annotations

import logging
import re
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.contacts.store import ContactStore

logger = logging.getLogger("sentinel.audit")

# Patterns for pronoun rewriting — (regex, replacement_template).
# Templates use {user_id} placeholder. Only match recognised action patterns
# tied to tool operations — unrecognised pronoun usage passes through unchanged.
_PRONOUN_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # Possessive: "my <noun>"
    (re.compile(r"\bmy email\b", re.IGNORECASE), "user {user_id}'s email", "my email"),
    (re.compile(r"\bmy calendar\b", re.IGNORECASE), "user {user_id}'s calendar", "my calendar"),
    (re.compile(r"\bmy last message\b", re.IGNORECASE), "user {user_id}'s last message", "my last message"),
    # Verb + me
    (re.compile(r"\bsend me\b", re.IGNORECASE), "send user {user_id}", "send me"),
    (re.compile(r"\bemail me\b", re.IGNORECASE), "email user {user_id}", "email me"),
    (re.compile(r"\bmessage me\b", re.IGNORECASE), "message user {user_id}", "message me"),
    (re.compile(r"\bremind me\b", re.IGNORECASE), "remind user {user_id}", "remind me"),
    (re.compile(r"\bnotify me\b", re.IGNORECASE), "notify user {user_id}", "notify me"),
]


async def resolve_sender(
    store: ContactStore, channel: str, identifier: str,
) -> int | None:
    """Map an incoming channel identifier to a user_id.

    Looks up contact_channels by (channel, identifier), follows the chain
    to the contact, and returns the linked_user_id if the contact is a user.
    Returns None if not found, not a user, or no linked_user_id.
    """
    ch = await store.get_by_identifier(channel, identifier)
    if ch is None:
        return None

    # Pass user_id from channel lookup — belt-and-suspenders in case
    # resolve_sender ever runs before ContextVar is set (channel handlers
    # currently set it to 1 before processing, but this is defensive)
    contact = await store.get_contact(ch["contact_id"], user_id=ch["user_id"])
    if contact is None:
        return None

    if not contact.get("is_user") or contact.get("linked_user_id") is None:
        return None

    return contact["linked_user_id"]


async def resolve_recipient_name(
    store: ContactStore, display_name: str, user_id: int,
) -> int | None:
    """Map a display name to a contact_id, scoped to the owner (user_id).

    Case-insensitive match. Returns contact_id or None.
    DB enforces UNIQUE(user_id, display_name) so at most one match.
    """
    contacts = await store.list_contacts(user_id)
    lower_name = display_name.lower()
    for c in contacts:
        if c["display_name"].lower() == lower_name:
            return c["contact_id"]
    return None


async def resolve_recipient_to_channel(
    store: ContactStore, contact_id: int, channel: str,
) -> str | None:
    """Map a contact_id + channel to the actual channel identifier.

    If multiple entries exist for the same channel, prefers is_default=True.
    Returns the identifier string, or None.
    """
    channels = await store.get_channels(contact_id)
    match: dict | None = None
    for ch in channels:
        if ch["channel"] == channel:
            if ch.get("is_default"):
                return ch["identifier"]
            if match is None:
                match = ch
    return match["identifier"] if match else None


def rewrite_pronouns(text: str, user_id: int) -> tuple[str, list[dict]]:
    """Rewrite first-person pronouns in recognised action patterns.

    Only rewrites patterns tied to tool operations (e.g. "my email",
    "send me"). Unrecognised pronoun usage passes through unchanged.

    Returns (rewritten_text, audit_log).
    """
    audit: list[dict] = []
    result = text
    for pattern, template, pattern_name in _PRONOUN_PATTERNS:
        replacement = template.format(user_id=user_id)
        new_result, count = pattern.subn(replacement, result)
        if count > 0:
            audit.append({
                "original": pattern_name,
                "replacement": replacement,
                "pattern": pattern_name,
            })
            result = new_result
    return result, audit


# Mapping: tool name → (channel, recipient arg name)
_MESSAGING_TOOLS: dict[str, tuple[str, str]] = {
    "signal_send": ("signal", "recipient"),
    "telegram_send": ("telegram", "recipient"),
    "email_send": ("email", "recipient"),
    "email_draft": ("email", "recipient"),
}

# Pattern for "user {N}" or bare integer
_USER_PATTERN = re.compile(r"^(?:user\s+)?(\d+)$", re.IGNORECASE)


async def resolve_tool_recipient(
    store: ContactStore | None,
    tool_name: str,
    args: dict[str, Any],
) -> dict[str, Any]:
    """Resolve opaque recipient IDs in messaging tool args to real identifiers.

    Called from both tool dispatch (planner path) and fast path, AFTER all
    security checks and BEFORE the tool handler executes.

    - Non-messaging tools: returns args unchanged.
    - Recipient missing/None: returns args unchanged (handler defaults apply).
    - Recipient doesn't match "user {N}": returns args unchanged (backwards compat).
    - Resolution failure: raises ValueError with actionable message.
    """
    tool_info = _MESSAGING_TOOLS.get(tool_name)
    if tool_info is None:
        return args

    channel, arg_name = tool_info
    recipient_value = args.get(arg_name)
    if not recipient_value or not isinstance(recipient_value, str):
        return args

    match = _USER_PATTERN.match(recipient_value.strip())
    if match is None:
        # Not an opaque ID — pass through (backwards compat)
        return args

    if store is None:
        raise ValueError(
            f"Cannot resolve contact — contact store not available"
        )

    contact_id = int(match.group(1))
    resolved = await resolve_recipient_to_channel(store, contact_id, channel)
    if resolved is None:
        raise ValueError(
            f"No {channel} identifier found for contact {contact_id}. "
            f"Add one via the contacts API."
        )

    logger.info(
        "Recipient resolved",
        extra={
            "event": "recipient_resolved",
            "tool": tool_name,
            "contact_id": contact_id,
            "channel": channel,
        },
    )
    return {**args, arg_name: resolved}


async def resolve_default_recipient(
    store: ContactStore | None,
    tool_name: str,
    user_id: int,
) -> str | None:
    """Find the requesting user's own channel identifier for a messaging tool.

    Used as a fallback when no explicit recipient is specified — sends the
    message back to the requesting user. Looks up the contact where
    linked_user_id == user_id and is_user == True, then resolves that
    contact's channel identifier for the tool's channel type.

    Returns the resolved identifier string, or None if not found.
    """
    tool_info = _MESSAGING_TOOLS.get(tool_name)
    if tool_info is None or store is None:
        return None

    channel, _ = tool_info

    # Find the user's own contact entry
    contacts = await store.list_contacts(user_id)
    self_contact = None
    for c in contacts:
        if c.get("is_user") and c.get("linked_user_id") == user_id:
            self_contact = c
            break

    if self_contact is None:
        return None

    # Resolve that contact's channel identifier
    resolved = await resolve_recipient_to_channel(
        store, self_contact["contact_id"], channel,
    )
    if resolved:
        logger.info(
            "Default recipient resolved to self",
            extra={
                "event": "default_recipient_resolved",
                "tool": tool_name,
                "contact_id": self_contact["contact_id"],
                "channel": channel,
            },
        )
    return resolved


async def rewrite_message(
    store: ContactStore, text: str, user_id: int,
) -> tuple[str, list[dict]]:
    """Full intake rewriting — name resolution + pronoun rewriting.

    1. Get all contacts for this user_id
    2. Scan text for contact display names (case-insensitive, whole-word)
    3. Replace found names with "user {contact_id}"
    4. Apply pronoun rewriting for sender's own references
    5. Return (rewritten_text, combined_audit_log)

    Longer names are replaced first to avoid partial matches.
    Unresolved names pass through unchanged.
    """
    audit: list[dict] = []
    result = text

    # Step 1-3: Name resolution
    contacts = await store.list_contacts(user_id)
    # Sort by name length descending — replace longer names first
    contacts.sort(key=lambda c: len(c["display_name"]), reverse=True)

    for contact in contacts:
        name = contact["display_name"]
        # Whole-word match, case-insensitive
        pattern = re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
        replacement = f"user {contact['contact_id']}"
        new_result, count = pattern.subn(replacement, result)
        if count > 0:
            audit.append({
                "original": name,
                "replacement": replacement,
                "pattern": "name_resolution",
            })
            result = new_result

    # Step 4: Pronoun rewriting
    result, pronoun_audit = rewrite_pronouns(result, user_id)
    audit.extend(pronoun_audit)

    return result, audit
