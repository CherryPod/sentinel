"""Application lifecycle: startup initialization and shutdown sequence.

Extracted from app.py as part of the app-py-refactor. Contains all module-level
globals (component references), the _init_* sub-functions, and the lifespan()
async context manager.

Backward compatibility: lifecycle functions that mutate module globals also
sync the values back to sentinel.api.app via lazy import. This keeps
route-module fallbacks (which read _app._shutting_down etc.) and safety-net
test patches (which set app_module._pin_verifier etc.) working without
modifying those consumers.
"""

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from sentinel.core.approval import ApprovalManager
from sentinel.core.bus import EventBus
from sentinel.core.db import run_db_maintenance
from sentinel.audit.logger import setup_audit_logger
from sentinel.core.config import settings
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.api.metrics import get_metrics
from sentinel.planner.orchestrator import Orchestrator
from sentinel.security.pipeline import ScanPipeline
from sentinel.planner.planner import ClaudePlanner, PlannerError
from sentinel.security.policy_engine import PolicyEngine
from sentinel.security import semgrep_scanner, prompt_guard
from sentinel.security.provenance import ProvenanceStore, set_default_store
from sentinel.security.scanner import CommandPatternScanner, CredentialScanner, SensitivePathScanner
from sentinel.memory.chunks import MemoryStore
from sentinel.memory.embeddings import EmbeddingClient
from sentinel.memory.episodic import EpisodicStore
from sentinel.memory.reranker import Reranker
from sentinel.memory.domain_summary import DomainSummaryStore
from sentinel.memory.strategy_store import StrategyPatternStore
from sentinel.memory.search import hybrid_search
from sentinel.session.store import SessionStore
from sentinel.api.auth_routes import init_auth_store
from sentinel.api.contacts import init_stores as init_contact_stores
from sentinel.api.routes import (
    a2a as a2a_routes,
    health as health_routes,
    memory as memory_routes,
    routines as routine_routes,
    security as security_routes,
    streaming as streaming_routes,
    task as task_routes,
    webhooks as webhook_routes,
    websocket as websocket_routes,
)
from sentinel.api.routes.health import HealthState
from sentinel.channels.base import ChannelRouter
from sentinel.channels.signal_channel import SignalChannel, SignalConfig
from sentinel.channels.telegram_channel import TelegramChannel, TelegramConfig
from sentinel.channels.webhook import (
    RateLimiter as WebhookRateLimiter,
    WebhookRegistry,
)
from sentinel.routines.engine import RoutineEngine
from sentinel.routines.heartbeat import HeartbeatManager, seed_heartbeat_routine
from sentinel.routines.store import RoutineStore
from sentinel.contacts.store import ContactStore
from sentinel.tools.executor import ToolExecutor
from sentinel.tools.sandbox import PodmanSandbox
from sentinel.tools.sidecar import SidecarClient
from sentinel.worker.factory import create_embedding_client, create_planner
from .auth import PinVerifier
from .rate_limit import limiter
from .redirect import HTTPSRedirectApp


# ── Module-level globals ──────────────────────────────────────────────
# These assume a single-process deployment (uvicorn --workers 1). With multiple
# workers, each process gets separate globals — duplicating Ollama connections,
# Prompt Guard models, and SQLite connections. Multi-worker would require: shared
# DB connection pool, centralised Ollama client, and Prompt Guard loaded once in
# a parent process. Current deployment: single process inside a container, so
# this is safe.
#
# These module-level attributes are required by test_refactor_app_safety_net.py
# which patches them via patch.object() on sentinel.api.app. They are set during
# lifespan via _init_* functions (dual-write to both globals and app.state).
# The _sync_to_app_module() helper propagates changes back to sentinel.api.app
# for backward compatibility with route-module fallbacks and test patches.

_pin_verifier: PinVerifier | None = None
_engine: PolicyEngine | None = None
_pipeline: ScanPipeline | None = None
_prompt_guard_loaded: bool = False
_semgrep_loaded: bool = False
_planner_available: bool = False
_ollama_reachable: bool = False
_sidecar: SidecarClient | None = None
_sandbox: PodmanSandbox | None = None
_signal_channel: SignalChannel | None = None
_telegram_channel: TelegramChannel | None = None

# Shutdown coordination (SYS-5a)
_shutting_down: bool = False
_background_tasks: set[asyncio.Task] = set()


def _sync_to_app_module(**kwargs) -> None:
    """Push global values back to sentinel.api.app for backward compat.

    Route modules read globals from sentinel.api.app via lazy import fallbacks,
    and safety-net tests patch them via patch.object(app_module, ...). This
    function keeps the app module's attributes in sync after lifecycle functions
    mutate them.
    """
    import sentinel.api.app as _app_mod
    for name, value in kwargs.items():
        setattr(_app_mod, name, value)


def _log_task_exception(task: asyncio.Task) -> None:
    """Log unhandled exceptions from background tasks."""
    if not task.cancelled() and task.exception():
        logging.getLogger("sentinel.audit").error(
            "Background task %s failed: %s",
            task.get_name(),
            task.exception(),
            extra={"event": "background_task_failed", "task_name": task.get_name()},
        )


def _track_task(coro, *, name: str | None = None) -> asyncio.Task:
    """Create an asyncio task and register it for shutdown tracking."""
    task = asyncio.create_task(coro, name=name)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    task.add_done_callback(_log_task_exception)
    return task


def _gather_component_status() -> dict:
    """Build component status dict shared by heartbeat and legacy callers.

    Delegates to health_routes.gather_component_status() using a HealthState
    built from the current module-level globals.
    """
    hs = HealthState(
        prompt_guard_loaded=_prompt_guard_loaded,
        semgrep_loaded=_semgrep_loaded,
        ollama_reachable=_ollama_reachable,
        planner_available=_planner_available,
        sidecar=_sidecar,
        sandbox=_sandbox,
        signal_channel=_signal_channel,
        telegram_channel=_telegram_channel,
        engine=_engine,
        pin_verifier=_pin_verifier,
    )
    return health_routes.gather_component_status(hs)


async def _init_database(app: FastAPI, settings, audit) -> tuple:
    """Initialize PostgreSQL pools and all data stores.

    Returns (pg_pool, admin_pool, session_store, memory_store, episodic_store,
             domain_summary_store, routine_store, contact_store,
             webhook_registry, hybrid_search_fn, get_metrics_fn).
    Stores are also written to app.state for access by route modules.
    """

    import asyncpg
    from functools import partial

    # Migration connection (runs schema setup as postgres superuser — then closes)
    # Must use superuser for first-run role creation and ownership transfer.
    migrate_conn = await asyncpg.connect(
        user="postgres",
        host=settings.pg_host,
        database=settings.pg_dbname,
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
        command_timeout=60.0,
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
        command_timeout=60.0,
    )
    app.state.admin_pool = admin_pool

    audit.info(
        "PostgreSQL pools created",
        extra={
            "event": "pg_pool_init",
            "host": settings.pg_host,
            "dbname": settings.pg_dbname,
            "pool_min": settings.pg_pool_min,
            "pool_max": settings.pg_pool_max,
            "user_app": "sentinel_app",
            "user_admin": "sentinel_owner",
        },
    )

    # Create store instances — written to app.state only (no module globals)
    session_store = SessionStore(pg_pool)
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
    contact_store = ContactStore(pg_pool)
    app.state.contact_store = contact_store
    init_contact_stores(contact_store, routine_store)
    init_auth_store(contact_store)
    webhook_registry = WebhookRegistry(pg_pool)
    app.state.webhook_registry = webhook_registry

    # Function references with pool baked in
    hybrid_search_fn = partial(hybrid_search, pg_pool)
    app.state.hybrid_search_fn = hybrid_search_fn
    get_metrics_fn = get_metrics
    app.state.get_metrics_fn = get_metrics_fn

    # Run DB maintenance (uses admin pool for cross-user access)
    maint_results = await run_db_maintenance(admin_pool)
    maint_total = sum(maint_results.values())
    if maint_total > 0:
        audit.info(
            "DB maintenance completed",
            extra={"event": "db_maintenance", "purged": maint_results},
        )

    audit.info(
        "PostgreSQL stores initialized",
        extra={"event": "pg_stores_init"},
    )

    return (pg_pool, admin_pool, session_store, memory_store, episodic_store,
            domain_summary_store, strategy_store, routine_store, contact_store,
            webhook_registry, hybrid_search_fn, get_metrics_fn)


async def _init_security(app: FastAPI, settings, audit):
    """Initialize PIN auth, policy engine, scanners, and scan pipeline.

    Returns (pipeline, engine, pin_verifier, prompt_guard_loaded, semgrep_loaded).
    """
    global _pin_verifier, _engine, _pipeline, _prompt_guard_loaded, _semgrep_loaded

    # Load PIN for authentication — hash immediately, never store plaintext (H-002)
    if settings.pin_required:
        try:
            with open(settings.pin_file) as f:
                raw_pin = f.read().strip()
            _pin_verifier = PinVerifier(raw_pin)
            app.state.pin_verifier = _pin_verifier
            del raw_pin  # Clear plaintext from local scope
            audit.info("PIN auth enabled (hashed)", extra={"event": "pin_loaded"})
        except FileNotFoundError:
            _pin_verifier = None
            app.state.pin_verifier = None
            audit.warning(
                "PIN file not found, auth disabled",
                extra={"event": "pin_missing", "path": settings.pin_file},
            )
    else:
        _pin_verifier = None
        app.state.pin_verifier = None
        audit.info("PIN auth disabled by config", extra={"event": "pin_disabled"})

    policy_path = settings.policy_file
    _engine = PolicyEngine(
        policy_path,
        workspace_path=settings.workspace_path,
        trust_level=settings.trust_level,
    )
    audit.info(
        "Policy loaded",
        extra={"event": "policy_loaded", "path": policy_path},
    )
    app.state.engine = _engine

    _cred_scanner = CredentialScanner(_engine.policy.get("credential_patterns", []))
    _path_scanner = SensitivePathScanner(_engine.policy.get("sensitive_path_patterns", []))
    _cmd_scanner = CommandPatternScanner()

    # Initialize Prompt Guard (Phase 2)
    if settings.prompt_guard_enabled:
        t0 = time.monotonic()
        _prompt_guard_loaded = prompt_guard.initialize(settings.prompt_guard_model)
        app.state.prompt_guard_loaded = _prompt_guard_loaded
        elapsed = time.monotonic() - t0
        audit.info(
            "Prompt Guard init",
            extra={
                "event": "prompt_guard_init",
                "loaded": _prompt_guard_loaded,
                "elapsed_s": round(elapsed, 2),
            },
        )

    # Initialize scan pipeline (Phase 2)
    _pipeline = ScanPipeline(
        cred_scanner=_cred_scanner,
        path_scanner=_path_scanner,
        cmd_scanner=_cmd_scanner,
    )
    app.state.pipeline = _pipeline

    # Initialize Semgrep scanner (replaces CodeShield)
    t0 = time.monotonic()
    _semgrep_loaded = semgrep_scanner.initialize()
    app.state.semgrep_loaded = _semgrep_loaded
    elapsed = time.monotonic() - t0
    audit.info(
        "Semgrep init",
        extra={
            "event": "semgrep_init",
            "loaded": _semgrep_loaded,
            "elapsed_s": round(elapsed, 2),
        },
    )

    # Sync back to app module for route-module fallbacks and test compat
    _sync_to_app_module(
        _pin_verifier=_pin_verifier,
        _engine=_engine,
        _pipeline=_pipeline,
        _prompt_guard_loaded=_prompt_guard_loaded,
        _semgrep_loaded=_semgrep_loaded,
    )

    return _pipeline, _engine, _pin_verifier, _prompt_guard_loaded, _semgrep_loaded


async def _init_orchestrator(app: FastAPI, settings, audit, pipeline, engine,
                             pg_pool, session_store, memory_store,
                             episodic_store, routine_store, contact_store,
                             track_task_fn):
    """Initialize orchestrator, integrations, and optional services.

    Returns (orchestrator, message_router, event_bus, sidecar, sandbox,
             embedding_client, planner_available, ollama_reachable,
             mcp_server, classifier, fast_path_executor).
    """
    global _ollama_reachable, _sidecar, _sandbox, _planner_available

    # Local defaults for variables that may not be assigned in all code paths
    _orchestrator = None
    _message_router = None
    _mcp_server = None
    _embedding_client = None
    _event_bus = None

    # Ollama health check (BOOT-2) — verify worker LLM is reachable at startup
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ollama_url}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name", "?") for m in models]
                _ollama_reachable = True
                app.state.ollama_reachable = True
                audit.info(
                    "Ollama reachable, %d model(s) loaded: %s",
                    len(model_names), ", ".join(model_names) or "(none)",
                    extra={
                        "event": "ollama_health_ok",
                        "model_count": len(model_names),
                        "models": model_names,
                    },
                )
            else:
                audit.warning(
                    "Ollama health check returned HTTP %d",
                    resp.status_code,
                    extra={"event": "ollama_health_http_error", "status": resp.status_code},
                )
    except Exception as exc:
        audit.warning(
            "Ollama unreachable at startup: %s — worker requests will fail until Ollama is available",
            exc,
            extra={"event": "ollama_health_failed", "error": str(exc)},
        )

    # Initialize conversation analyzer (Phase 5) — session store created above
    conversation_analyzer = ConversationAnalyzer()
    audit.info(
        "Conversation tracking initialized",
        extra={
            "event": "conversation_init",
            "enabled": settings.conversation_enabled,
            "session_ttl": settings.session_ttl,
        },
    )

    # Initialize embedding client (Phase 2) — memory store created above
    _embedding_client = create_embedding_client(settings)
    app.state.embedding_client = _embedding_client
    audit.info(
        "Memory store initialized",
        extra={
            "event": "memory_init",
            "embeddings_model": settings.embeddings_model,
            "auto_memory": settings.auto_memory,
        },
    )

    # Initialize event bus (Phase 3)
    _event_bus = EventBus()
    app.state.event_bus = _event_bus
    audit.info("Event bus initialized", extra={"event": "bus_init"})

    # Initialize WASM sidecar (Phase 4) — opt-in via SENTINEL_SIDECAR_ENABLED
    if settings.sidecar_enabled:
        _sidecar = SidecarClient(
            socket_path=settings.sidecar_socket,
            timeout=settings.sidecar_timeout,
            sidecar_binary_path=settings.sidecar_binary,
            tool_dir=settings.sidecar_tool_dir,
        )
        app.state.sidecar = _sidecar
        audit.info(
            "WASM sidecar client initialized",
            extra={
                "event": "sidecar_init",
                "socket": settings.sidecar_socket,
                "binary": settings.sidecar_binary,
                "tool_dir": settings.sidecar_tool_dir,
            },
        )
    else:
        audit.info("WASM sidecar disabled", extra={"event": "sidecar_disabled"})

    # Initialize Podman sandbox (E5) — opt-in via SENTINEL_SANDBOX_ENABLED
    if settings.sandbox_enabled:
        _sandbox = PodmanSandbox(
            socket_path=settings.sandbox_socket,
            image=settings.sandbox_image,
            default_timeout=settings.sandbox_timeout,
            max_timeout=settings.sandbox_max_timeout,
            memory_limit=settings.sandbox_memory_limit,
            cpu_quota=settings.sandbox_cpu_quota,
            workspace_volume=settings.sandbox_workspace_volume,
            output_limit=settings.sandbox_output_limit,
            api_timeout=settings.sandbox_api_timeout,
        )
        # Health check — verify socket and image are available
        sandbox_healthy = await _sandbox.health_check()
        if sandbox_healthy:
            # Clean up any stale containers from previous runs
            cleaned = await _sandbox.cleanup_stale()
            audit.info(
                "Podman sandbox initialized",
                extra={
                    "event": "sandbox_init",
                    "socket": settings.sandbox_socket,
                    "image": settings.sandbox_image,
                    "stale_cleaned": cleaned,
                },
            )
        else:
            audit.warning(
                "Podman sandbox health check failed — sandbox disabled",
                extra={"event": "sandbox_init_failed"},
            )
            _sandbox = None
    else:
        audit.info("Podman sandbox disabled", extra={"event": "sandbox_disabled"})
    app.state.sandbox = _sandbox

    # Initialize Google OAuth2 manager (B3) — needed by B4 (Gmail) and B5 (Calendar)
    google_oauth = None
    if settings.google_oauth_client_id and settings.google_oauth_client_secret_file:
        try:
            from sentinel.integrations.google_auth import GoogleOAuthManager
            # Read client secret from file
            with open(settings.google_oauth_client_secret_file) as f:
                client_secret = f.read().strip()
            scopes = [s.strip() for s in settings.google_oauth_scopes.split(",") if s.strip()]
            google_oauth = GoogleOAuthManager(
                client_id=settings.google_oauth_client_id,
                client_secret=client_secret,
                refresh_token_file=settings.google_oauth_refresh_token_file,
                scopes=scopes,
            )
            audit.info(
                "Google OAuth2 manager initialized",
                extra={"event": "google_oauth_init", "scopes": len(scopes)},
            )
        except Exception as exc:
            audit.warning(
                "Google OAuth2 init failed: %s",
                exc,
                extra={"event": "google_oauth_init_failed", "error": str(exc)},
            )

    # Routine store created above in backend init block

    # Initialize planner + orchestrator (Phase 3, factory in Phase 5)
    classifier = None
    fast_path_executor = None
    try:
        planner = create_planner(settings)
        approval_mgr = ApprovalManager(pg_pool, event_bus=_event_bus)
        tool_executor = ToolExecutor(
            policy_engine=engine,
            sidecar=_sidecar,
            google_oauth=google_oauth,
            sandbox=_sandbox,
            trust_level=settings.trust_level,
        )
        # Wire per-user credential store for email/calendar tools
        from sentinel.core.credential_store import CredentialStore
        from sentinel.api.credentials import init_credential_store
        _credential_store = CredentialStore(pg_pool)
        tool_executor.set_credential_store(_credential_store)
        init_credential_store(_credential_store)
        _orchestrator = Orchestrator(
            planner=planner,
            pipeline=pipeline,
            tool_executor=tool_executor,
            approval_manager=approval_mgr,
            session_store=session_store,
            conversation_analyzer=conversation_analyzer,
            memory_store=memory_store,
            embedding_client=_embedding_client,
            event_bus=_event_bus,
            routine_store=routine_store,
            contact_store=contact_store,
        )
        app.state.orchestrator = _orchestrator
        _planner_available = True
        app.state.planner_available = True
        audit.info(
            "Claude planner initialized",
            extra={"event": "planner_init", "model": settings.claude_model},
        )

        # Initialize message router (fast-path classification) — opt-in via router_enabled
        if settings.router_enabled:
            from sentinel.router.classifier import Classifier
            from sentinel.router.fast_path import FastPathExecutor
            from sentinel.router.router import MessageRouter
            from sentinel.router.templates import TemplateRegistry

            _template_registry = TemplateRegistry.default()
            classifier = Classifier(
                worker=pipeline._worker,
                registry=_template_registry,
                timeout=settings.router_classifier_timeout,
            )
            from sentinel.core.confirmation import ConfirmationGate
            confirmation_gate = ConfirmationGate(pg_pool)

            fast_path_executor = FastPathExecutor(
                tool_executor=tool_executor,
                pipeline=pipeline,
                event_bus=_event_bus,
                registry=_template_registry,
                session_store=session_store,
                contact_store=contact_store,
                confirmation_gate=confirmation_gate,
            )
            _message_router = MessageRouter(
                classifier=classifier,
                fast_path=fast_path_executor,
                orchestrator=_orchestrator,
                pipeline=pipeline,
                session_store=session_store,
                event_bus=_event_bus,
                enabled=True,
                contact_store=contact_store,
                confirmation_gate=confirmation_gate,
            )
            app.state.message_router = _message_router
            audit.info("Router enabled — fast-path classification active",
                        extra={"event": "router_init"})

            # Pre-warm Ollama so the first real classification doesn't timeout
            # waiting for model load. This is fire-and-forget — if it fails,
            # the first request just falls back to planner as before.
            async def _warm_ollama():
                try:
                    await pipeline._worker.generate(
                        "hi", system_prompt="respond with ok",
                    )
                    audit.info("Ollama model pre-warmed for classifier",
                                extra={"event": "ollama_warmup_ok"})
                except Exception as exc:
                    audit.warning("Ollama warmup failed (non-fatal): %s", exc,
                                   extra={"event": "ollama_warmup_failed"})

            track_task_fn(_warm_ollama(), name="ollama-warmup")

    except PlannerError as exc:
        audit.warning(
            "Claude planner not available: %s",
            exc,
            extra={"event": "planner_init_failed", "error": str(exc)},
        )
        _planner_available = False
        app.state.planner_available = False

    # B2 red team endpoint — register ONLY when explicitly enabled.
    # Route does not exist at all when SENTINEL_RED_TEAM_MODE is false.
    if settings.red_team_mode and _orchestrator is not None:
        from sentinel.api.red_team import create_red_team_router
        _rt_router = create_red_team_router(
            orchestrator=_orchestrator,
            limiter=limiter,
            log_dir=settings.log_dir,
        )
        app.include_router(_rt_router)
        audit.warning(
            "RED TEAM MODE ACTIVE — /api/test/execute-plan registered",
            extra={"event": "red_team_mode_active"},
        )

    # Initialize MCP server (Phase 3)
    if settings.mcp_enabled:
        try:
            from sentinel.channels.mcp_server import create_mcp_server, wrap_mcp_with_auth
            _mcp_server = create_mcp_server(
                orchestrator=_orchestrator,
                memory_store=memory_store,
                embedding_client=_embedding_client,
                event_bus=_event_bus,
            )
            # Mount MCP transport at /mcp/ — streamable HTTP is the modern approach.
            # Bearer token auth enforced via MCPAuthMiddleware wrapper.
            mcp_asgi = _mcp_server.streamable_http_app()
            if not settings.mcp_auth_token:
                audit.warning(
                    "MCP server disabled — no auth token configured "
                    "(set SENTINEL_MCP_AUTH_TOKEN to enable). Fail-closed.",
                    extra={"event": "mcp_no_auth"},
                )
            else:
                mcp_asgi = wrap_mcp_with_auth(mcp_asgi, settings.mcp_auth_token)
                app.mount("/mcp", mcp_asgi)
            audit.info("MCP server initialized", extra={"event": "mcp_init"})
        except Exception as exc:
            audit.warning(
                "MCP server init failed: %s",
                exc,
                extra={"event": "mcp_init_failed", "error": str(exc)},
            )

    # Sync back to app module for route-module fallbacks and test compat
    _sync_to_app_module(
        _ollama_reachable=_ollama_reachable,
        _sidecar=_sidecar,
        _sandbox=_sandbox,
        _planner_available=_planner_available,
    )

    return (_orchestrator, _message_router, _event_bus, _sidecar, _sandbox,
            _embedding_client, _planner_available, _ollama_reachable,
            _mcp_server, classifier, fast_path_executor)


async def _init_channels(app: FastAPI, settings, audit, orchestrator, message_router,
                          event_bus, pipeline, engine, pin_verifier, pg_pool,
                          session_store, memory_store, routine_store, contact_store,
                          webhook_registry, embedding_client, sidecar, sandbox,
                          prompt_guard_loaded, semgrep_loaded, ollama_reachable, planner_available,
                          hybrid_search_fn, get_metrics_fn, track_task_fn,
                          classifier=None, fast_path_executor=None):
    """Initialize channels, routines, heartbeat, and wire route modules.

    Called from lifespan() between current_user_id.set(1) and .reset() — RLS
    context is active for all startup seeding operations (routines, heartbeat).

    Returns the redirect_server (or None) so lifespan shutdown can stop it.
    """
    global _signal_channel, _telegram_channel

    # Local defaults for variables that may not be assigned in all code paths
    _routine_engine = None
    _idempotency_cache = {}

    # Initialize routine engine (Phase 5) — opt-in via SENTINEL_ROUTINE_ENABLED
    if settings.routine_enabled and orchestrator is not None:
        _routine_engine = RoutineEngine(
            store=routine_store,
            orchestrator=orchestrator,
            event_bus=event_bus,
            pool=pg_pool,
            admin_pool=getattr(app.state, 'admin_pool', None),
            tick_interval=settings.routine_scheduler_interval,
            max_concurrent=settings.routine_max_concurrent,
            execution_timeout=settings.routine_execution_timeout,
            classifier=classifier if settings.router_enabled else None,
            fast_path=fast_path_executor if settings.router_enabled else None,
        )
        app.state.routine_engine = _routine_engine
        await _routine_engine.start()
        await _routine_engine.seed_defaults()
        # Wire routine engine into orchestrator (breaks circular dep:
        # RoutineEngine needs Orchestrator, Orchestrator needs RoutineEngine)
        orchestrator.set_routine_engine(_routine_engine)
        audit.info(
            "Routine engine started",
            extra={
                "event": "routine_engine_init",
                "tick_interval": settings.routine_scheduler_interval,
                "max_concurrent": settings.routine_max_concurrent,
            },
        )
    else:
        audit.info(
            "Routine engine disabled",
            extra={
                "event": "routine_engine_disabled",
                "routine_enabled": settings.routine_enabled,
                "orchestrator_available": orchestrator is not None,
            },
        )

    # Initialize webhook rate limiter (C1) — registry created above in backend init block
    _webhook_rate_limiter = WebhookRateLimiter()
    app.state.webhook_rate_limiter = _webhook_rate_limiter
    app.state.idempotency_cache = _idempotency_cache
    audit.info("Webhook registry initialized", extra={"event": "webhook_init"})

    # Initialize heartbeat system (C2)
    async def _health_check() -> dict:
        return _gather_component_status()

    _heartbeat_manager = HeartbeatManager(
        memory_store=memory_store,
        health_check_fn=_health_check,
    )
    app.state.heartbeat_manager = _heartbeat_manager
    if routine_store is not None:
        await seed_heartbeat_routine(routine_store)

    async def _heartbeat_loop() -> None:
        while True:
            await asyncio.sleep(settings.heartbeat_interval)
            try:
                await _heartbeat_manager.run_heartbeat()
            except Exception as e:
                logging.getLogger("sentinel.audit").warning(
                    "Heartbeat error: %s", e,
                    extra={"event": "heartbeat_error", "error": str(e)},
                )

    track_task_fn(_heartbeat_loop(), name="heartbeat")
    app.state.background_tasks = _background_tasks
    audit.info("Heartbeat system initialized", extra={"event": "heartbeat_init"})

    # Initialize Signal channel (A3) — opt-in via SENTINEL_SIGNAL_ENABLED
    if settings.signal_enabled and orchestrator is not None and event_bus is not None:
        allowed = {
            s.strip() for s in settings.signal_allowed_senders.split(",") if s.strip()
        }
        sig_config = SignalConfig(
            signal_cli_path=settings.signal_cli_path,
            signal_cli_config=settings.signal_cli_config,
            socket_path=settings.signal_socket_path,
            account=settings.signal_account,
            allowed_senders=allowed,
            rate_limit=settings.signal_rate_limit,
            max_message_length=settings.signal_max_message_length,
        )
        _signal_channel = SignalChannel(sig_config, event_bus=event_bus)
        app.state.signal_channel = _signal_channel
        await _signal_channel.start()

        # Background task: consume incoming Signal messages and route through orchestrator
        async def _signal_receive_loop() -> None:
            from sentinel.contacts.resolver import resolve_sender
            from sentinel.core.context import current_user_id
            router = ChannelRouter(orchestrator, event_bus, audit, message_router=message_router)
            async for message in _signal_channel.receive():
                # Resolve sender identity from contact registry
                resolved_uid = await resolve_sender(contact_store, "signal", message.channel_id)
                if resolved_uid is None:
                    audit.warning(
                        "Unknown Signal sender — rejecting",
                        extra={"event": "signal_unknown_sender", "sender": message.channel_id},
                    )
                    continue
                ctx_token = current_user_id.set(resolved_uid)
                try:
                    message.metadata["source_key"] = f"signal:{message.channel_id}"
                    await router.handle_message(_signal_channel, message)
                except Exception as exc:
                    audit.error(
                        "Signal message handling failed",
                        extra={"event": "signal_handle_error", "error": str(exc)},
                    )
                finally:
                    current_user_id.reset(ctx_token)

        track_task_fn(_signal_receive_loop(), name="signal-receiver")
        audit.info(
            "Signal channel started",
            extra={
                "event": "signal_channel_init",
                "account": settings.signal_account,
                "allowed_senders": len(allowed),
                "rate_limit": settings.signal_rate_limit,
            },
        )
    else:
        audit.info(
            "Signal channel disabled",
            extra={
                "event": "signal_channel_disabled",
                "signal_enabled": settings.signal_enabled,
                "orchestrator_available": orchestrator is not None,
            },
        )

    # Initialize Telegram channel — opt-in via SENTINEL_TELEGRAM_ENABLED
    if settings.telegram_enabled and orchestrator is not None and event_bus is not None:
        try:
            token = ""
            if settings.telegram_bot_token_file:
                with open(settings.telegram_bot_token_file) as f:
                    token = f.read().strip()

            allowed_chats: set[int] = set()
            if settings.telegram_allowed_chat_ids:
                allowed_chats = {
                    int(c.strip())
                    for c in settings.telegram_allowed_chat_ids.split(",")
                    if c.strip()
                }

            tg_config = TelegramConfig(
                bot_token=token,
                allowed_chat_ids=allowed_chats,
                rate_limit=settings.telegram_rate_limit,
                max_message_length=settings.telegram_max_message_length,
                polling_timeout=settings.telegram_polling_timeout,
            )
            _telegram_channel = TelegramChannel(tg_config, event_bus=event_bus)
            app.state.telegram_channel = _telegram_channel
            await _telegram_channel.start()

            # Background task: consume incoming Telegram messages
            async def _telegram_receive_loop() -> None:
                from sentinel.contacts.resolver import resolve_sender
                from sentinel.core.context import current_user_id
                router = ChannelRouter(orchestrator, event_bus, audit, message_router=message_router)
                async for message in _telegram_channel.receive():
                    # Resolve sender identity from contact registry
                    resolved_uid = await resolve_sender(contact_store, "telegram", message.channel_id)
                    if resolved_uid is None:
                        audit.warning(
                            "Unknown Telegram sender — rejecting",
                            extra={"event": "telegram_unknown_sender", "sender": message.channel_id},
                        )
                        continue
                    ctx_token = current_user_id.set(resolved_uid)
                    try:
                        message.metadata["source_key"] = f"telegram:{message.channel_id}"
                        await router.handle_message(_telegram_channel, message)
                    except Exception as exc:
                        audit.error(
                            "Telegram message handling failed",
                            extra={"event": "telegram_handle_error", "error": str(exc)},
                        )
                    finally:
                        current_user_id.reset(ctx_token)

            track_task_fn(_telegram_receive_loop(), name="telegram-receiver")
            await _telegram_channel.start_polling()

            audit.info(
                "Telegram channel started",
                extra={
                    "event": "telegram_channel_init",
                    "allowed_chats": len(allowed_chats),
                    "rate_limit": settings.telegram_rate_limit,
                },
            )
        except Exception as exc:
            audit.error(
                "Telegram channel failed to start",
                extra={"event": "telegram_channel_error", "error": str(exc)},
            )
    else:
        audit.info(
            "Telegram channel disabled",
            extra={"event": "telegram_channel_disabled"},
        )

    # Wire messaging channels into tool executor for signal_send / telegram_send
    if orchestrator is not None and (_signal_channel is not None or _telegram_channel is not None):
        orchestrator.set_tool_channels(
            signal_channel=_signal_channel,
            telegram_channel=_telegram_channel,
        )
        audit.info(
            "Messaging channels wired to tool executor",
            extra={
                "event": "tool_channels_wired",
                "signal": _signal_channel is not None,
                "telegram": _telegram_channel is not None,
            },
        )

    # Start HTTP→HTTPS redirect server (only when TLS is active)
    redirect_server = None
    if settings.redirect_enabled and settings.tls_cert_file:
        try:
            import uvicorn
            redirect_config = uvicorn.Config(
                app=HTTPSRedirectApp(),
                host=settings.host,
                port=settings.http_port,
                log_level="warning",
            )
            redirect_server = uvicorn.Server(redirect_config)
            track_task_fn(redirect_server.serve(), name="https-redirect")
            audit.info(
                "HTTP redirect server started",
                extra={
                    "event": "redirect_started",
                    "http_port": settings.http_port,
                    "https_port": settings.external_https_port,
                },
            )
        except Exception as exc:
            audit.warning(
                "Failed to start redirect server: %s",
                exc,
                extra={"event": "redirect_failed", "error": str(exc)},
            )

    # ── Initialize health/metrics routes ────────────────────────────
    # HealthState is a live-reference object — the health endpoints read it
    # directly, so fields updated here are reflected immediately.
    _health_state = HealthState(
        prompt_guard_loaded=prompt_guard_loaded,
        semgrep_loaded=semgrep_loaded,
        ollama_reachable=ollama_reachable,
        planner_available=planner_available,
        sidecar=sidecar,
        sandbox=sandbox,
        signal_channel=_signal_channel,
        telegram_channel=_telegram_channel,
        engine=engine,
        pin_verifier=pin_verifier,
    )
    health_routes.init(
        health_state=_health_state,
        session_store=session_store,
        orchestrator=orchestrator,
        routine_engine=_routine_engine,
        get_metrics_fn=get_metrics_fn,
    )
    security_routes.init(
        engine=engine,
        pipeline=pipeline,
        audit=audit,
    )
    task_routes.init(
        orchestrator=orchestrator,
        message_router=message_router,
        session_store=session_store,
        audit=audit,
    )
    memory_routes.init(
        memory_store=memory_store,
        embedding_client=embedding_client,
        hybrid_search_fn=hybrid_search_fn,
        audit=audit,
    )
    routine_routes.init(
        routine_store=routine_store,
        routine_engine=_routine_engine,
    )
    webhook_routes.init(
        webhook_registry=webhook_registry,
        webhook_rate_limiter=_webhook_rate_limiter,
        orchestrator=orchestrator,
        message_router=message_router,
        event_bus=event_bus,
        idempotency_cache=_idempotency_cache,
        audit=audit,
    )
    streaming_routes.init(
        event_bus=event_bus,
        heartbeat_manager=_heartbeat_manager,
        audit=audit,
    )
    websocket_routes.init(
        orchestrator=orchestrator,
        event_bus=event_bus,
        message_router=message_router,
        pin_verifier=pin_verifier,
        audit=audit,
    )
    a2a_routes.init(
        orchestrator=orchestrator,
        event_bus=event_bus,
    )

    # Startup validation gate (BOOT-1) — warn if critical scanners are both offline
    if not prompt_guard_loaded and not semgrep_loaded:
        if settings.trust_level >= 4:
            audit.critical(
                "DEGRADED: Both Prompt Guard and Semgrep failed to initialize at TL%d "
                "— security scanning severely limited",
                settings.trust_level,
                extra={
                    "event": "startup_degraded",
                    "trust_level": settings.trust_level,
                    "prompt_guard_loaded": False,
                    "semgrep_loaded": False,
                },
            )
        else:
            audit.warning(
                "Both Prompt Guard and Semgrep unavailable (TL%d)",
                settings.trust_level,
                extra={
                    "event": "startup_degraded",
                    "trust_level": settings.trust_level,
                },
            )

    # Serve user-created websites from /workspace/sites/
    _sites_dir = Path(settings.workspace_path) / "sites"
    _sites_dir.mkdir(exist_ok=True)
    app.mount(
        "/sites",
        StaticFiles(directory=str(_sites_dir), html=True),
        name="sites",
    )

    # Mount static files LAST — the "/" catch-all must come after every
    # other route (API, WebSocket, MCP, red-team).  Routes added during
    # lifespan (like the B2 red-team endpoint) are appended to app.routes,
    # so any catch-all registered at module level would shadow them.
    if Path(settings.static_dir).is_dir():
        app.mount(
            "/", StaticFiles(directory=settings.static_dir, html=True), name="static",
        )

    # Sync channel globals back to app module
    _sync_to_app_module(
        _signal_channel=_signal_channel,
        _telegram_channel=_telegram_channel,
    )

    return redirect_server


async def _shutdown(app: FastAPI, audit, redirect_server=None):
    """Execute the 11-step shutdown sequence.

    Reads components from app.state (canonical source) with getattr fallback
    for components that may not have been initialized.
    Order is critical — see inline comments for rationale.
    """
    global _shutting_down

    # 1. Set shutdown flag — reject new requests immediately
    _shutting_down = True
    app.state.shutting_down = True
    # Sync to app module so route-module fallbacks see the flag
    _sync_to_app_module(_shutting_down=True)
    audit.info("Shutdown initiated — rejecting new requests", extra={"event": "shutdown_start"})

    # 2. Notify subscribers (channels, routines) so they can flush state
    event_bus = getattr(app.state, "event_bus", None)
    if event_bus is not None:
        try:
            await event_bus.publish("system.shutdown", {"reason": "process_exit"})
        except Exception as exc:
            audit.warning(
                "Failed to publish shutdown event: %s", exc,
                extra={"event": "shutdown_event_failed", "error": str(exc)},
            )

    # 3. Signal the orchestrator to stop accepting new plan steps
    orchestrator = getattr(app.state, "orchestrator", None)
    if orchestrator is not None:
        await orchestrator.shutdown()

    # 4. SYS-5b: Stop routine engine before drain (routines create tasks)
    routine_engine = getattr(app.state, "routine_engine", None)
    if routine_engine is not None:
        await routine_engine.stop()

    # 5. Drain tracked background tasks (30s budget)
    _SHUTDOWN_TIMEOUT = 30
    if _background_tasks:
        audit.info(
            "Draining %d background tasks (timeout=%ds)",
            len(_background_tasks), _SHUTDOWN_TIMEOUT,
            extra={
                "event": "shutdown_drain_start",
                "task_count": len(_background_tasks),
                "task_names": [t.get_name() for t in _background_tasks],
            },
        )
        done, pending = await asyncio.wait(
            _background_tasks, timeout=_SHUTDOWN_TIMEOUT,
        )
        # 6. Cancel stragglers (5s grace)
        if pending:
            audit.warning(
                "Cancelling %d tasks that did not finish in time",
                len(pending),
                extra={
                    "event": "shutdown_cancel",
                    "cancelled_names": [t.get_name() for t in pending],
                },
            )
            for task in pending:
                task.cancel()
            # Give cancelled tasks a moment to handle CancelledError
            await asyncio.wait(pending, timeout=5)
        audit.info(
            "Background task drain complete: %d drained, %d cancelled",
            len(done), len(pending),
            extra={"event": "shutdown_drain_done", "drained": len(done), "cancelled": len(pending)},
        )

    # 7. Shutdown Signal + Telegram channels
    signal_ch = getattr(app.state, "signal_channel", None)
    if signal_ch is not None:
        await signal_ch.stop()

    telegram_ch = getattr(app.state, "telegram_channel", None)
    if telegram_ch is not None:
        await telegram_ch.stop()

    # 8. Shutdown WASM sidecar if running
    sidecar = getattr(app.state, "sidecar", None)
    if sidecar is not None:
        await sidecar.stop_sidecar()

    # 9. Shutdown redirect server if running
    if redirect_server is not None:
        redirect_server.should_exit = True

    # 10. SYS-5b: Cleanup orphaned sandbox containers (after drain — tasks may use containers)
    sandbox = getattr(app.state, "sandbox", None)
    if sandbox is not None:
        try:
            cleaned = await sandbox.cleanup_stale()
            if cleaned:
                audit.info(
                    "Shutdown sandbox cleanup: removed %d containers", cleaned,
                    extra={"event": "shutdown_sandbox_cleanup", "removed": cleaned},
                )
        except Exception as exc:
            audit.warning(
                "Shutdown sandbox cleanup failed: %s", exc,
                extra={"event": "shutdown_sandbox_cleanup_failed", "error": str(exc)},
            )
        # BH3-099: Close httpx client to release connection pool
        await sandbox.close()

    # 11. SYS-5b: Flush and close stores before closing the database
    for store_name in ["session_store", "memory_store"]:
        store_obj = getattr(app.state, store_name, None)
        if store_obj is not None:
            try:
                await store_obj.close()
            except Exception as exc:
                audit.warning(
                    "Store %s close failed: %s", store_name, exc,
                    extra={"event": "shutdown_store_close_failed", "store": store_name, "error": str(exc)},
                )

    # Close PostgreSQL pools
    if getattr(app.state, "admin_pool", None) is not None:
        await app.state.admin_pool.close()
        audit.info("Admin pool closed", extra={"event": "admin_pool_close"})
    if getattr(app.state, "pg_pool", None) is not None:
        await app.state.pg_pool.close()
        audit.info("PostgreSQL pool closed", extra={"event": "pg_pool_close"})

    audit.info("Shutting down sentinel-controller", extra={"event": "shutdown"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    audit = setup_audit_logger(
        log_dir=settings.log_dir,
        log_level=settings.log_level,
    )
    app.state.audit = audit
    app.state.shutting_down = False
    app.state.ws_failure_tracker = websocket_routes._ws_failure_tracker
    audit.info("Starting sentinel-controller", extra={"event": "startup"})

    # Database
    (pg_pool, admin_pool, session_store, memory_store, episodic_store,
     domain_summary_store, strategy_store, routine_store, contact_store,
     webhook_registry, hybrid_search_fn,
     get_metrics_fn) = await _init_database(app, settings, audit)

    # Security pipeline + scanners
    pipeline, engine, pin_verifier, prompt_guard_loaded, semgrep_loaded = await _init_security(app, settings, audit)

    # Orchestrator, integrations, optional services
    (orchestrator, message_router, event_bus, sidecar, sandbox,
     embedding_client, planner_available, ollama_reachable,
     mcp_server, classifier, fast_path_executor) = await _init_orchestrator(
        app, settings, audit, pipeline, engine, pg_pool,
        session_store, memory_store, episodic_store, routine_store,
        contact_store, _track_task)

    # Channels, routines, heartbeat, route wiring
    # RLS context for startup seeding (routines table INSERT requires valid user_id)
    from sentinel.core.context import current_user_id
    _startup_token = current_user_id.set(1)
    redirect_server = await _init_channels(
        app, settings, audit, orchestrator, message_router,
        event_bus, pipeline, engine, pin_verifier, pg_pool,
        session_store, memory_store, routine_store, contact_store,
        webhook_registry, embedding_client, sidecar, sandbox,
        prompt_guard_loaded, semgrep_loaded, ollama_reachable, planner_available,
        hybrid_search_fn, get_metrics_fn, _track_task,
        classifier=classifier, fast_path_executor=fast_path_executor,
    )
    current_user_id.reset(_startup_token)

    # Wire episodic store for enriched step-level memory chunks
    # (must be after _init_channels where orchestrator is fully wired,
    # and in lifespan() where episodic_store is in scope)
    orchestrator.set_episodic_store(episodic_store)

    # Wire domain summary store for hierarchical context injection
    orchestrator.set_domain_summary_store(domain_summary_store)

    # Wire strategy pattern store for strategy tracking
    orchestrator.set_strategy_store(strategy_store)

    # Initialize FlashRank reranker for episodic retrieval re-ranking
    # (~4MB ONNX model, CPU-only, graceful degradation if unavailable)
    reranker = Reranker()
    orchestrator.set_reranker(reranker)

    yield

    await _shutdown(app, audit, redirect_server=redirect_server)
