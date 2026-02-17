"""Contact registry — resolves human names to channel identifiers."""

from sentinel.contacts.store import ContactStore
from sentinel.contacts.resolver import (
    resolve_sender,
    resolve_recipient_name,
    resolve_recipient_to_channel,
    rewrite_pronouns,
    rewrite_message,
)

__all__ = [
    "ContactStore",
    "resolve_sender",
    "resolve_recipient_name",
    "resolve_recipient_to_channel",
    "rewrite_pronouns",
    "rewrite_message",
]
