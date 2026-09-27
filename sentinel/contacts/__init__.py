"""Contact registry — resolves human names to channel identifiers."""

from sentinel.contacts.resolver import (
    resolve_recipient_name,
    resolve_recipient_to_channel,
    resolve_sender,
    rewrite_message,
    rewrite_pronouns,
)
from sentinel.contacts.store import ContactStore

__all__ = [
    "ContactStore",
    "resolve_recipient_name",
    "resolve_recipient_to_channel",
    "resolve_sender",
    "rewrite_message",
    "rewrite_pronouns",
]
