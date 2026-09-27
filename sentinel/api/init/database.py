"""Database initialization: PostgreSQL pools, data stores, owner bootstrap.

Creates the migration connection (superuser), application pool (RLS-wrapped),
admin pool (owner bypass), and all data store instances. Stores are written
to app.state for access by route modules.
"""

import asyncio
import logging
import os
from functools import partial

from fastapi import FastAPI

from sentinel.core.decorators import no_audit_log

logger = logging.getLogger(__name__)


@no_audit_log
async def _init_audit_infrastructure(app: FastAPI, settings, pg_pool):
    """Create the audit-role pool and unified audit emitter."""
    import asyncpg

    from sentinel.audit import AuditEmitter

    audit_pool = await asyncpg.create_pool(
        dsn=f"postgresql://sentinel_audit@/{settings.pg_dbname}",
        host=settings.pg_host,
        port=settings.pg_port,
        min_size=1,
        max_size=2,
        command_timeout=settings.pg_command_timeout,
    )
    audit_emitter = AuditEmitter(
        app_pool=pg_pool,
        audit_pool=audit_pool,
        category_configs=settings.audit_categories,
        db_write_timeout=settings.audit_db_write_timeout,
    )
    app.state.audit_pool = audit_pool
    app.state.audit_emitter = audit_emitter
    return audit_pool, audit_emitter


async def init_database(app: FastAPI, settings, audit) -> tuple:
    """Initialize PostgreSQL pools and all data stores.

    Returns (pg_pool, admin_pool, event_bus, session_store, memory_store,
             episodic_store, domain_summary_store, strategy_store, routine_store,
             contact_store, webhook_registry, hybrid_search_fn, get_metrics_fn,
             loop_store, insight_store).
    Stores are also written to app.state for access by route modules.

    Q5-F6: ``event_bus`` is constructed here (not in Tier 3) so the
    :class:`SessionStore` required-ctor-dep contract holds.

    C74 Inv-2: an eager production crypto-key probe runs at the top of this
    function, BEFORE any store construction that touches
    ``get_master_key`` (currently :class:`ContactStore` below at the
    ``contact_store = ContactStore(...)`` site, plus
    :class:`CredentialStore` in Tier 3 ``init_orchestrator``).  Under
    ``settings.crypto_require_production_key=True`` with a missing key
    file, the probe raises :class:`CryptoConfigError` which propagates
    through the lifespan re-raise and prevents the controller from
    serving any request.
    """
    logger.debug(
        "Initializing database",
        extra={"event": "init.database_start", "pg_host": settings.pg_host},
    )

    # C74 Inv-2: eager production crypto-key probe BEFORE any store
    # construction that touches get_master_key.  Uses the injected
    # settings parameter (NOT a fresh global import — see Codex C-F3
    # carry-forward).  Raises CryptoConfigError under
    # crypto_require_production_key=True + missing key; lifespan re-raises
    # to FastAPI startup-failure (no partial controller, no request serving).
    from sentinel.crypto.preflight import validate_production_crypto_key

    validate_production_crypto_key(settings)

    import asyncpg

    from sentinel.api.auth_routes import init_auth_store
    from sentinel.api.contacts import init_stores as init_contact_stores
    from sentinel.api.metrics import get_metrics
    from sentinel.contacts.store import ContactStore
    from sentinel.core.bus import EventBus
    from sentinel.core.db import run_db_maintenance
    from sentinel.memory.chunks import MemoryStore
    from sentinel.memory.domain_summary import DomainSummaryStore
    from sentinel.memory.episodic import EpisodicStore
    from sentinel.memory.search import hybrid_search
    from sentinel.memory.strategy_store import StrategyPatternStore
    from sentinel.routines.store import RoutineStore
    from sentinel.security.provenance import ProvenanceStore, set_default_store
    from sentinel.session.store import SessionStore

    # Migration connection (runs schema setup as postgres superuser — then closes)
    # Must use superuser for first-run role creation and ownership transfer.
    # Q11-F3: settings-backed connect deadline AND command_timeout; prior bare
    # connect could hang boot indefinitely if the socket was slow, and the
    # subsequent create_pg_schema() DDL sequence ran with asyncpg's default
    # command_timeout=None — boot could still hang after connect succeeded.
    migrate_conn = await asyncpg.connect(
        user="postgres",
        host=settings.pg_host,
        database=settings.pg_dbname,
        timeout=settings.pg_connect_timeout,
        command_timeout=settings.pg_command_timeout,
    )
    from sentinel.core.pg_schema import create_pg_schema

    await create_pg_schema(migrate_conn)
    await migrate_conn.close()

    # Application pool (connects as sentinel_app — subject to RLS)
    pg_pool = await asyncpg.create_pool(
        dsn=f"postgresql://sentinel_app@/{settings.pg_dbname}",
        host=settings.pg_host,
        port=settings.pg_port,
        min_size=settings.pg_pool_min,
        max_size=settings.pg_pool_max,
        max_inactive_connection_lifetime=300.0,
        command_timeout=settings.pg_command_timeout,
    )
    from sentinel.core.rls import RLSPool

    pg_pool = RLSPool(pg_pool)  # Wrap with RLS context injection
    app.state.pg_pool = pg_pool

    # Admin pool (sentinel_owner — bypasses RLS via owner_full_access policy)
    # Used for maintenance operations that need cross-user access (purge, cleanup)
    admin_pool = await asyncpg.create_pool(
        dsn=f"postgresql://sentinel_owner@/{settings.pg_dbname}",
        host=settings.pg_host,
        min_size=1,
        max_size=2,
        command_timeout=settings.pg_command_timeout,
    )
    app.state.admin_pool = admin_pool
    audit_pool, _audit_emitter = await _init_audit_infrastructure(
        app, settings, pg_pool
    )

    audit.info(
        "PostgreSQL pools created",
        extra={
            "event": "pg.pool_init",
            "host": settings.pg_host,
            "dbname": settings.pg_dbname,
            "pool_min": settings.pg_pool_min,
            "pool_max": settings.pg_pool_max,
            "user_app": "sentinel_app",
            "user_admin": "sentinel_owner",
            "user_audit": "sentinel_audit",
        },
    )

    # Q5-F6: EventBus is hoisted to Tier 1 so SessionStore can receive it as
    # a required ctor dep. It used to be built in Tier 3 (init_orchestrator),
    # but that left SessionStore unable to publish ``session.evicted`` at
    # construction time. Plumbing is: build once here, store on app.state,
    # pass through to SessionStore + run_db_maintenance; init_orchestrator
    # receives the same instance via parameter rather than re-constructing.
    event_bus = EventBus()
    app.state.event_bus = event_bus

    # Create store instances — written to app.state only (no module globals)
    session_store = SessionStore(pg_pool, event_bus=event_bus)
    app.state.session_store = session_store
    memory_store = MemoryStore(pg_pool)
    app.state.memory_store = memory_store
    episodic_store = EpisodicStore(pg_pool)
    app.state.episodic_store = episodic_store
    domain_summary_store = DomainSummaryStore(pg_pool)
    app.state.domain_summary_store = domain_summary_store
    strategy_store = StrategyPatternStore(pg_pool)
    app.state.strategy_store = strategy_store
    set_default_store(ProvenanceStore(pg_pool))
    routine_store = RoutineStore(pg_pool)
    app.state.routine_store = routine_store
    contact_store = ContactStore(
        pg_pool,
        key_path=settings.crypto_key_path,  # C74 Inv-3-app: thread settings explicitly
        require_production_key=settings.crypto_require_production_key,  # C74
        audit_emitter=_audit_emitter,
    )
    app.state.contact_store = contact_store
    init_contact_stores(contact_store, routine_store, audit_emitter=_audit_emitter)
    init_auth_store(
        contact_store,
        admin_pool=admin_pool,
        audit_emitter=getattr(app.state, "audit_emitter", None),
    )

    from sentinel.channels.webhook import WebhookRegistry

    webhook_registry = WebhookRegistry(pg_pool)
    app.state.webhook_registry = webhook_registry

    # Loop controller persistence
    from sentinel.planner.loop_store import LoopStore

    loop_store = LoopStore(pg_pool)
    app.state.loop_store = loop_store

    # Insight store (planning heuristics from plan-outcome pairs)
    from sentinel.memory.insights import InsightStore

    insight_store = InsightStore(pg_pool)
    app.state.insight_store = insight_store

    # Function references with pool baked in
    hybrid_search_fn = partial(hybrid_search, pg_pool)
    app.state.hybrid_search_fn = hybrid_search_fn
    get_metrics_fn = get_metrics
    app.state.get_metrics_fn = get_metrics_fn

    # Run DB maintenance (uses admin pool for cross-user access)
    # Q5-F6: thread event_bus so ApprovalManager.cleanup_and_notify can publish.
    maint_results = await run_db_maintenance(
        admin_pool, audit_emitter=_audit_emitter, event_bus=event_bus
    )
    maint_total = sum(maint_results.values())
    if maint_total > 0:
        audit.info(
            "DB maintenance completed",
            extra={"event": "db.maintenance", "purged": maint_results},
        )

    audit.info(
        "PostgreSQL stores initialized",
        extra={"event": "pg.stores_init"},
    )

    logger.debug(
        "Database initialization complete",
        extra={"event": "init.database_done", "store_count": 10},
    )

    return (
        pg_pool,
        admin_pool,
        event_bus,
        session_store,
        memory_store,
        episodic_store,
        domain_summary_store,
        strategy_store,
        routine_store,
        contact_store,
        webhook_registry,
        hybrid_search_fn,
        get_metrics_fn,
        loop_store,
        insight_store,
    )


async def bootstrap_owner(admin_pool) -> None:
    """Seed user 1 (owner) on first run if no users exist.

    Reads the PIN from SENTINEL_PIN_FILE (default: /run/secrets/sentinel_pin),
    hashes it with PinVerifier, and inserts the owner row with must_change_pin=TRUE
    so the first login immediately prompts a PIN change.

    Uses admin_pool (sentinel_owner role) because there is no authenticated user
    context at startup — RLS would block the INSERT via the app pool.
    """
    from sentinel.api.auth import PinVerifier
    from sentinel.core.config import settings

    logger.debug(
        "Checking owner bootstrap",
        extra={"event": "bootstrap.owner_start"},
    )

    # Intentionally cross-user: admin bootstrap checks if ANY user exists
    # globally to determine first-run state. Uses admin_pool (sentinel_owner).
    async with admin_pool.acquire() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM users")
        if count > 0:
            logger.debug(
                "Owner already exists, skipping bootstrap",
                extra={"event": "bootstrap.owner_skip", "user_count": count},
            )
            return  # Already bootstrapped — skip

    pin_path = settings.pin_file
    if not await asyncio.to_thread(os.path.exists, pin_path):
        logger.warning(
            "No PIN file at %s — cannot bootstrap owner",
            pin_path,
            extra={"event": "bootstrap.skipped", "reason": "no_pin_file"},
        )
        return

    try:

        def _read_pin() -> str:
            with open(pin_path) as f:
                return f.read().strip()

        raw_pin = await asyncio.to_thread(_read_pin)
    except OSError as exc:
        logger.exception(
            "Failed to read PIN file at %s — cannot bootstrap owner",
            pin_path,
            extra={"event": "bootstrap.pin_read_failed", "error": str(exc)},
        )
        return

    # Hash immediately — plaintext is never stored (H-002)
    try:
        pin_hash = PinVerifier(raw_pin).to_stored()
    except Exception as exc:
        logger.exception(
            "Failed to hash PIN — cannot bootstrap owner",
            extra={"event": "bootstrap.pin_hash_failed", "error": str(exc)},
        )
        return
    finally:
        del raw_pin

    logger.debug(
        "Inserting owner user into database",
        extra={
            "event": "bootstrap.owner_insert",
            "display_name_len": len(settings.bootstrap_username) if settings.bootstrap_username else 0,
        },
    )
    async with admin_pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO users
               (display_name, pin_hash, role, trust_level, is_active, must_change_pin)
               VALUES ($1, $2, 'owner', 4, TRUE, TRUE)""",
            settings.bootstrap_username,
            pin_hash,
        )
        logger.info(
            "Bootstrapped owner user (must_change_pin=true)",
            extra={
                "event": "owner.bootstrapped",
                "display_name_len": len(settings.bootstrap_username) if settings.bootstrap_username else 0,
            },
        )
