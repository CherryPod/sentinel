"""Eager validation of production crypto config at startup.

Imported by :func:`sentinel.api.init.database.init_database` BEFORE any
store construction that touches :func:`sentinel.crypto.keys.get_master_key`.
Also imported by the post-deploy migration one-shot command via
``from sentinel.crypto.preflight import validate_production_crypto_key``.

Kept narrow: the only reason this module exists is to give app-boot and
migration commands a single place to call before any consumer runs.  The
check itself is a thin wrapper over :func:`get_master_key` with
``require_production=True``.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.crypto.keys import get_master_key

logger = logging.getLogger(__name__)


def validate_production_crypto_key(settings: Any) -> None:
    """Eagerly validate the production master key.

    No-op when ``settings.crypto_require_production_key`` is ``False``.
    Otherwise calls
    ``get_master_key(settings.crypto_key_path, require_production=True)``
    and propagates the failure mode.

    Failure modes (per C74.design C-F6 narrowing):

    * **Missing key file** — :func:`load_master_key` raises
      :class:`~sentinel.core.exceptions.CryptoConfigError`; this propagates
      and prevents controller startup via the lifespan re-raise at
      ``sentinel/api/lifecycle.py``.
    * **Other I/O errors** (PermissionError, IsADirectoryError, etc.) —
      propagate as their own ``OSError`` subclass; ``load_master_key``
      currently only wraps ``FileNotFoundError`` as
      :class:`CryptoConfigError`.  Both still fail-loud through the
      lifespan re-raise; the only difference is the exception class the
      operator sees.  Uniform-exception-class wrapping is intentionally
      OUT of C74's scope (would require a widen-wrap seam audit per
      cleanup-pass §Guardrails #6).

    Inv-2 contract: this function MUST be called BEFORE any store
    construction that touches ``get_master_key`` (currently
    :class:`~sentinel.contacts.store.ContactStore` at ``init_database``
    Tier 1 and :class:`~sentinel.core.credential_store.CredentialStore`
    at ``init_orchestrator`` Tier 3).
    """
    if not settings.crypto_require_production_key:
        return
    logger.info(
        "Validating production master key",
        extra={
            "event": "crypto.preflight.start",
            "key_path": settings.crypto_key_path,
        },
    )
    get_master_key(
        settings.crypto_key_path,
        require_production=True,
    )
    logger.info(
        "Production master key validated",
        extra={"event": "crypto.preflight.ok"},
    )
