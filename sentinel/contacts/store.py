"""ContactStore — composed from domain-specific mixins.

All public methods are defined in the mixin modules:
- _users.py: User CRUD (create_user, get_user, list_users, ...)
- _contacts.py: Contact CRUD (create_contact, get_contact, ...)
- _channels.py: Channel CRUD with encryption (create_channel, get_by_identifier, ...)

Shared utilities in _rows.py, channel crypto in _channel_crypto.py.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.contacts._channels import ChannelStoreMixin
from sentinel.contacts._contacts import ContactStoreMixin
from sentinel.contacts._users import UserStoreMixin
from sentinel.crypto.keys import get_master_key

logger = logging.getLogger(__name__)

# C74 Inv-3-app: legacy direct-construction / test-only fallback path.
# Production wiring (sentinel/api/init/database.py) MUST pass
# ``key_path=settings.crypto_key_path`` AND
# ``require_production_key=settings.crypto_require_production_key``
# explicitly per Inv-3-app.  Direct-construction with this constant
# fallback is preserved for test-fixture convenience but should not be
# used in production code paths — production-policy enforcement happens
# at the boot-wiring layer via init_database, not here.
_DEFAULT_KEY_PATH = "/run/secrets/credential_key"
_DEFAULT_KEY_VERSION = 1


class ContactStore(UserStoreMixin, ContactStoreMixin, ChannelStoreMixin):
    """CRUD operations for users, contacts, and contact_channels tables.

    PostgreSQL-backed via asyncpg. When pool=None, falls back to in-memory
    dicts for tests. Channel identifiers encrypted at rest with HKDF
    per-record key derivation, AAD binding, and HMAC blind indexes.

    Composed from:
    - UserStoreMixin: user CRUD
    - ContactStoreMixin: contact CRUD
    - ChannelStoreMixin(CryptoAuditMixin): channel CRUD with encryption
    """

    def __init__(
        self,
        pool: Any = None,
        *,
        key_path: str | None = None,
        require_production_key: bool = False,  # C74 — production-policy threading
        key_version: int = _DEFAULT_KEY_VERSION,
        audit_emitter: Any | None = None,
    ) -> None:
        self._pool = pool
        self._master_key = get_master_key(
            key_path or _DEFAULT_KEY_PATH,
            require_production=require_production_key,  # C74
        )
        self._key_version = key_version
        self._audit_emitter = audit_emitter
        # In-memory fallback for tests — keyed by integer IDs
        self._users: dict[int, dict] = {}
        self._contacts: dict[int, dict] = {}
        self._channels: dict[int, dict] = {}
        # Auto-increment counters for in-memory mode
        self._next_user_id = 1
        self._next_contact_id = 1
        self._next_channel_id = 1
