"""Orchestrator initialization: Ollama health, planner, tool executor, integrations.

Performs the Ollama health check with retry, creates the tool executor,
planner, orchestrator, loop controller, and optional integrations (Google
OAuth, message router, MCP server).
"""

import asyncio
import logging
import os

from fastapi import FastAPI

from sentinel.api.rate_limit import limiter
from sentinel.core.approval import ApprovalManager
from sentinel.core.socket_auth import validate_runtime_dir
from sentinel.planner.orchestrator import Orchestrator
from sentinel.planner.planner import PlannerError
from sentinel.security.conversation import ConversationAnalyzer
from sentinel.tools.executor import ToolExecutor
from sentinel.tools.sandbox import PodmanSandbox
from sentinel.tools.sidecar import SidecarClient
from sentinel.worker.factory import create_embedding_client, create_planner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sub-functions (called only by init_orchestrator)
# ---------------------------------------------------------------------------


async def _check_ollama_health(settings, app, audit) -> None:
    """Verify worker LLM (Ollama) is reachable at startup (BOOT-2).

    Retries up to 3 times with 5s backoff, then raises RuntimeError
    if unreachable — startup cannot proceed without the worker.
    """
    import httpx

    _max_retries = 3
    _retry_delay = 5.0
    ollama_reachable = False

    for attempt in range(1, _max_retries + 1):
        try:
            logger.debug(
                "Ollama health check attempt %d/%d",
                attempt,
                _max_retries,
                extra={
                    "event": "ollama.health_attempt",
                    "attempt": attempt,
                    "url": f"{settings.ollama_url}/api/tags",
                },
            )
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{settings.ollama_url}/api/tags")
                if resp.status_code == 200:
                    models = resp.json().get("models", [])
                    model_names = [m.get("name", "?") for m in models]
                    ollama_reachable = True
                    app.state.ollama_reachable = True
                    configured_model = settings.ollama_model
                    model_loaded = any(configured_model in name for name in model_names)
                    audit.info(
                        "Ollama reachable, %d model(s): %s",
                        len(model_names),
                        ", ".join(model_names) or "(none)",
                        extra={
                            "event": "ollama.health_ok",
                            "attempt": attempt,
                            "model_count": len(model_names),
                            "models": model_names,
                            "configured_model": configured_model,
                            "configured_model_loaded": model_loaded,
                        },
                    )
                    if not model_loaded:
                        audit.warning(
                            "Configured model '%s' not in Ollama "
                            "— first request triggers load",
                            configured_model,
                            extra={
                                "event": "ollama.model_not_loaded",
                                "configured_model": configured_model,
                                "available_models": model_names,
                            },
                        )
                    break
                audit.warning(
                    "Ollama health HTTP %d (attempt %d/%d)",
                    resp.status_code,
                    attempt,
                    _max_retries,
                    extra={
                        "event": "ollama.health_http_error",
                        "status": resp.status_code,
                        "attempt": attempt,
                    },
                )
        except Exception as exc:
            logger.exception(
                "_check_ollama_health: Exception",
                extra={"event": "orchestrator.ollama_health_error"},
            )
            audit.warning(
                "Ollama unreachable (attempt %d/%d): %s",
                attempt,
                _max_retries,
                exc,
                extra={
                    "event": "ollama.health_retry",
                    "attempt": attempt,
                    "error": str(exc),
                },
                exc_info=True,
            )
        if attempt < _max_retries:
            await asyncio.sleep(_retry_delay)

    if not ollama_reachable:
        raise RuntimeError(
            f"Ollama unreachable after {_max_retries} attempts "
            f"(URL: {settings.ollama_url}). Cannot start — worker requests "
            f"would fail. Check sentinel-ollama container."
        )


async def _init_infrastructure(settings, app, audit, *, event_bus):
    """Initialize core infrastructure: conversation analyzer, MTM, embedding client,
    WASM sidecar, and Podman sandbox.

    Q5-F6: ``event_bus`` is passed in from the caller (ultimately
    constructed in ``init_database``) rather than built here — the
    Tier 3 creation was too late for :class:`SessionStore` to receive a
    required-ctor-dep bus. Returned unchanged so the caller tuple is
    compatible.

    Returns (conversation_analyzer, multi_turn_monitor, embedding_client,
    event_bus, sidecar, sandbox).
    """
    # Conversation analyzer (Phase 5)
    logger.debug(
        "_init_infrastructure called",
        extra={
            "event": "orchestrator._init_infrastructure",
            "settings_type": type(settings).__name__,
            "app_type": type(app).__name__,
            "audit_type": type(audit).__name__,
        },
    )  # auto:entry
    conversation_analyzer = ConversationAnalyzer()

    # Multi-Turn Monitor (MTM) — instantiate when enabled or in shadow mode
    multi_turn_monitor = None
    if settings.mtm_enabled in ("true", "shadow"):
        from sentinel.security.conversation.monitor import MultiTurnMonitor

        audit_emitter = getattr(app.state, "audit_emitter", None)
        multi_turn_monitor = MultiTurnMonitor(audit_emitter=audit_emitter)
        audit.info(
            "Multi-Turn Monitor initialized",
            extra={
                "event": "conversation.mtm_init",
                "mtm_mode": settings.mtm_enabled,
                "has_audit_emitter": audit_emitter is not None,
            },
        )
    else:
        audit.info(
            "Multi-Turn Monitor disabled",
            extra={
                "event": "conversation.mtm_disabled",
                "mtm_mode": settings.mtm_enabled,
            },
        )

    audit.info(
        "Conversation tracking initialized",
        extra={
            "event": "conversation.init",
            "enabled": settings.conversation_enabled,
            "session_ttl": settings.session_ttl,
            "mtm_enabled": settings.mtm_enabled,
        },
    )

    # Embedding client (Phase 2)
    embedding_client = create_embedding_client(settings)
    app.state.embedding_client = embedding_client
    audit.info(
        "Memory store initialized",
        extra={
            "event": "memory.init",
            "embeddings_model": settings.embeddings_model,
            "auto_memory": settings.auto_memory,
        },
    )

    # Event bus (Phase 3) — Q5-F6: constructed in init_database (Tier 1) and
    # passed in; ``app.state.event_bus`` was already set there. This log
    # remains so the startup trace still shows the bus activation point in
    # the orchestrator-tier sequence.
    audit.info("Event bus wired", extra={"event": "bus.init"})

    # WASM sidecar (Phase 4) — opt-in via SENTINEL_SIDECAR_ENABLED
    sidecar = None
    if settings.sidecar_enabled:
        # Q13.fix.f — validate settings.runtime_dir at init (0700 perms, owner
        # UID == this process's UID, directory exists). Fail-closed: if the
        # runtime dir is misconfigured, refuse to register the sidecar rather
        # than bind a weaker socket under /tmp/. See design cluster 2 §
        # "Startup validation" and sentinel/core/socket_auth.py.
        try:
            validate_runtime_dir(settings.runtime_dir, os.getuid())
        except RuntimeError as exc:
            logger.exception(
                "_init_infrastructure: RuntimeError",
                extra={
                    "event": "api.init.orchestrator._init_infrastructure_runtimeerror"
                },
            )  # auto:except
            audit.error(
                "runtime_dir validation failed; sidecar registration skipped",
                extra={
                    "event": "orchestrator.runtime_dir_invalid",
                    "runtime_dir": settings.runtime_dir,
                    "error": str(exc),
                },
                exc_info=True,
            )
        else:
            sidecar = SidecarClient(
                socket_path=settings.sidecar_socket,
                timeout=settings.sidecar_timeout,
                sidecar_binary_path=settings.sidecar_binary,
                tool_dir=settings.sidecar_tool_dir,
            )
            app.state.sidecar = sidecar
            audit.info(
                "WASM sidecar client initialized",
                extra={
                    "event": "sidecar.init",
                    "socket": settings.sidecar_socket,
                    "binary": settings.sidecar_binary,
                    "tool_dir": settings.sidecar_tool_dir,
                },
            )
    else:
        logger.debug(
            "_init_infrastructure: sidecar_enabled",
            extra={
                "event": "api.init.orchestrator._init_infrastructure.clean",
                "reason": "sidecar_enabled",
            },
        )  # auto:neg
        audit.info("WASM sidecar disabled", extra={"event": "sidecar.disabled"})

    # Podman sandbox (E5) — opt-in via SENTINEL_SANDBOX_ENABLED
    sandbox = None
    if settings.sandbox_enabled:
        sandbox = PodmanSandbox(
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
        sandbox_healthy = await sandbox.health_check()
        if sandbox_healthy:
            cleaned = await sandbox.cleanup_stale()
            audit.info(
                "Podman sandbox initialized",
                extra={
                    "event": "sandbox.init",
                    "socket": settings.sandbox_socket,
                    "image": settings.sandbox_image,
                    "stale_cleaned": cleaned,
                },
            )
        else:
            audit.warning(
                "Podman sandbox health check failed — sandbox disabled",
                extra={"event": "sandbox.init_failed"},
            )
            sandbox = None
    else:
        audit.info("Podman sandbox disabled", extra={"event": "sandbox.disabled"})
    app.state.sandbox = sandbox

    return (
        conversation_analyzer,
        multi_turn_monitor,
        embedding_client,
        event_bus,
        sidecar,
        sandbox,
    )


def _init_google_oauth(settings, audit):
    """Initialize Google OAuth2 manager (B3) — needed by Gmail and Calendar.

    Returns GoogleOAuthManager or None if not configured or init fails.
    """
    if not (
        settings.google_oauth_client_id and settings.google_oauth_client_secret_file
    ):
        return None

    try:
        from sentinel.integrations.google_auth import GoogleOAuthManager

        logger.debug(
            "Reading Google OAuth client secret",
            extra={
                "event": "google.oauth_file_read",
                "secret_file": settings.google_oauth_client_secret_file,
            },
        )
        with open(settings.google_oauth_client_secret_file) as f:
            client_secret = f.read().strip()
        scopes = [
            s.strip() for s in settings.google_oauth_scopes.split(",") if s.strip()
        ]
        google_oauth = GoogleOAuthManager(
            client_id=settings.google_oauth_client_id,
            client_secret=client_secret,
            refresh_token_file=settings.google_oauth_refresh_token_file,
            scopes=scopes,
            api_timeout=settings.google_api_timeout,
        )
        audit.info(
            "Google OAuth2 manager initialized",
            extra={"event": "google.oauth_init", "scopes": len(scopes)},
        )
        return google_oauth
    except Exception as exc:
        logger.exception(
            "_init_google_oauth: Exception",
            extra={"event": "orchestrator.google_oauth_error"},
        )
        audit.warning(
            "Google OAuth2 init failed: %s",
            exc,
            extra={"event": "google.oauth_init_failed", "error": str(exc)},
            exc_info=True,
        )
        return None


def _init_planner_stack(
    *,
    settings,
    app,
    audit,
    pipeline,
    engine,
    pg_pool,
    session_store,
    memory_store,
    episodic_store,
    routine_store,
    contact_store,
    insight_store,
    loop_store,
    conversation_analyzer,
    multi_turn_monitor,
    embedding_client,
    event_bus,
    sidecar,
    sandbox,
    google_oauth,
):
    """Create planner, tool executor, orchestrator, loop controller, insight extractor.

    Returns (orchestrator, tool_executor).
    Raises PlannerError if the planner API key is missing or invalid.
    """
    logger.debug(
        "_init_planner_stack called",
        extra={"event": "orchestrator._init_planner_stack"},
    )  # auto:entry
    planner = create_planner(settings)
    approval_mgr = ApprovalManager(
        pg_pool,
        event_bus=event_bus,
        audit_emitter=getattr(app.state, "audit_emitter", None),
        session_store=session_store,
    )
    tool_executor = ToolExecutor(
        policy_engine=engine,
        sidecar=sidecar,
        google_oauth=google_oauth,
        sandbox=sandbox,
        trust_level=settings.trust_level,
        audit_emitter=getattr(app.state, "audit_emitter", None),
    )
    # Wire per-user credential store for email/calendar tools
    from sentinel.api.credentials import init_credential_store
    from sentinel.core.credential_store import CredentialStore

    _credential_store = CredentialStore(
        pg_pool,
        key_path=settings.crypto_key_path,  # C74 Inv-3-app: thread settings explicitly
        require_production_key=settings.crypto_require_production_key,  # C74
        audit_emitter=getattr(app.state, "audit_emitter", None),
    )
    tool_executor.set_credential_store(_credential_store)
    init_credential_store(_credential_store)

    orchestrator = Orchestrator(
        planner=planner,
        pipeline=pipeline,
        tool_executor=tool_executor,
        approval_manager=approval_mgr,
        session_store=session_store,
        conversation_analyzer=conversation_analyzer,
        multi_turn_monitor=multi_turn_monitor,
        memory_store=memory_store,
        embedding_client=embedding_client,
        event_bus=event_bus,
        routine_store=routine_store,
        contact_store=contact_store,
        insight_store=insight_store,
    )
    app.state.orchestrator = orchestrator

    # Loop controller — persistent goal-pursuit wrapper over orchestrator
    from sentinel.planner.loop_controller import LoopController

    _loop_controller = LoopController(
        orchestrator=orchestrator,
        loop_store=loop_store,
        event_bus=event_bus,
    )
    app.state.loop_controller = _loop_controller

    # Insight extractor — batch analysis of plan-outcome pairs
    from sentinel.memory.insights import InsightExtractor

    _insight_extractor = InsightExtractor(
        episodic_store=episodic_store,
        insight_store=insight_store,
        planner=planner,
    )
    app.state.insight_extractor = _insight_extractor

    app.state.planner_available = True
    audit.info(
        "Claude planner initialized",
        extra={"event": "planner.init", "model": settings.claude_model},
    )

    return orchestrator, tool_executor


def _init_message_router(
    *,
    settings,
    app,
    audit,
    pipeline,
    pg_pool,
    session_store,
    contact_store,
    event_bus,
    orchestrator,
    tool_executor,
    track_task_fn,
):
    """Initialize fast-path message router with keyword classifier.

    Returns (message_router, classifier, fast_path_executor).
    """
    from sentinel.router.fast_path import FastPathExecutor
    from sentinel.router.keyword_classifier import KeywordClassifier
    from sentinel.router.router import MessageRouter
    from sentinel.router.templates import TemplateRegistry

    _template_registry = TemplateRegistry.default()
    # Deterministic keyword classifier — replaces Qwen-based classifier.
    # Zero GPU, microseconds, deterministic routing.
    # Original Qwen classifier kept in sentinel/router/classifier.py if needed.
    classifier = KeywordClassifier(registry=_template_registry)

    from sentinel.core.confirmation import ConfirmationGate

    confirmation_gate = ConfirmationGate(
        pg_pool,
        audit_emitter=getattr(app.state, "audit_emitter", None),
        session_store=session_store,
    )

    fast_path_executor = FastPathExecutor(
        tool_executor=tool_executor,
        pipeline=pipeline,
        event_bus=event_bus,
        registry=_template_registry,
        session_store=session_store,
        contact_store=contact_store,
        confirmation_gate=confirmation_gate,
    )
    message_router = MessageRouter(
        classifier=classifier,
        fast_path=fast_path_executor,
        orchestrator=orchestrator,
        pipeline=pipeline,
        session_store=session_store,
        event_bus=event_bus,
        enabled=True,
        contact_store=contact_store,
        confirmation_gate=confirmation_gate,
    )
    app.state.message_router = message_router
    audit.info(
        "Router enabled — fast-path classification active",
        extra={"event": "router.init"},
    )

    # Pre-warm Ollama so the first real classification doesn't timeout
    # waiting for model load. Fire-and-forget — failure falls back to planner.
    async def _warm_ollama():
        try:
            await pipeline._worker.generate(
                "hi",
                system_prompt="respond with ok",
            )
            audit.info(
                "Ollama model pre-warmed for classifier",
                extra={"event": "ollama.warmup_ok"},
            )
        except Exception as exc:
            logger.exception(
                "_warm_ollama: Exception",
                extra={"event": "orchestrator._warm_ollama_error"},
            )
            audit.warning(
                "Ollama warmup failed (non-fatal): %s",
                exc,
                extra={"event": "ollama.warmup_failed"},
                exc_info=True,
            )

    track_task_fn(_warm_ollama(), name="ollama-warmup")

    return message_router, classifier, fast_path_executor


def _init_optional_services(
    *,
    settings,
    app,
    audit,
    orchestrator,
    memory_store,
    embedding_client,
    event_bus,
):
    """Register optional services. Returns mcp_server or None."""

    # MCP server (Phase 3)
    mcp_server = None
    if settings.mcp_enabled:
        try:
            from sentinel.channels.mcp_server import (
                create_mcp_server,
                wrap_mcp_with_auth,
            )

            mcp_server = create_mcp_server(
                orchestrator=orchestrator,
                memory_store=memory_store,
                embedding_client=embedding_client,
                event_bus=event_bus,
            )
            # Mount MCP transport at /mcp/ — streamable HTTP is the modern approach.
            # Bearer token auth enforced via MCPAuthMiddleware wrapper.
            mcp_asgi = mcp_server.streamable_http_app()
            if not settings.mcp_auth_token:
                logger.debug(
                    "MCP auth token not configured — server disabled",
                    extra={"event": "mcp.auth_missing"},
                )
                audit.warning(
                    "MCP server disabled — no auth token configured "
                    "(set SENTINEL_MCP_AUTH_TOKEN to enable). Fail-closed.",
                    extra={"event": "mcp.no_auth"},
                )
            else:
                logger.debug(
                    "MCP auth token configured — wrapping with auth",
                    extra={"event": "mcp.auth_configured"},
                )
                mcp_asgi = wrap_mcp_with_auth(mcp_asgi, settings.mcp_auth_token)
                app.mount("/mcp", mcp_asgi)
            audit.info("MCP server initialized", extra={"event": "mcp.init"})
        except Exception as exc:
            logger.exception(
                "_init_optional_services: Exception",
                extra={"event": "orchestrator.mcp_init_error"},
            )
            audit.warning(
                "MCP server init failed: %s",
                exc,
                extra={"event": "mcp.init_failed", "error": str(exc)},
                exc_info=True,
            )

    return mcp_server


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def init_orchestrator(
    app: FastAPI,
    settings,
    audit,
    pipeline,
    engine,
    pg_pool,
    session_store,
    memory_store,
    episodic_store,
    routine_store,
    contact_store,
    track_task_fn,
    *,
    event_bus,
    insight_store=None,
    loop_store=None,
):
    """Initialize orchestrator, integrations, and optional services.

    Returns (orchestrator, message_router, event_bus, sidecar, sandbox,
             embedding_client, planner_available, ollama_reachable,
             mcp_server, classifier, fast_path_executor).
    Does NOT set module-level globals — the caller (lifespan) does that.

    Q5-F6: ``event_bus`` is now constructed in ``init_database`` (Tier 1)
    and passed in here. The orchestrator tier still echoes it back in its
    return tuple so the lifecycle unpacking stays stable for downstream
    tiers (channels).
    """
    logger.debug(
        "Initializing orchestrator",
        extra={"event": "init.orchestrator_start"},
    )

    # BOOT-2: Verify worker LLM is reachable (raises RuntimeError if not)
    await _check_ollama_health(settings, app, audit)

    # Core services: conversation analyzer, embeddings, sidecar, sandbox.
    # Q5-F6: event_bus passed in rather than constructed; _init_infrastructure
    # now echoes it back unchanged so the rest of this function stays stable.
    (
        conversation_analyzer,
        multi_turn_monitor,
        embedding_client,
        _event_bus_echo,
        sidecar,
        sandbox,
    ) = await _init_infrastructure(settings, app, audit, event_bus=event_bus)

    # Google OAuth2 (needed by Gmail and Calendar tools)
    google_oauth = _init_google_oauth(settings, audit)

    # Planner, executor, orchestrator, loop controller, insight extractor
    orchestrator = None
    message_router = None
    classifier = None
    fast_path_executor = None
    planner_available = False

    try:
        orchestrator, tool_executor = _init_planner_stack(
            settings=settings,
            app=app,
            audit=audit,
            pipeline=pipeline,
            engine=engine,
            pg_pool=pg_pool,
            session_store=session_store,
            memory_store=memory_store,
            episodic_store=episodic_store,
            routine_store=routine_store,
            contact_store=contact_store,
            insight_store=insight_store,
            loop_store=loop_store,
            conversation_analyzer=conversation_analyzer,
            multi_turn_monitor=multi_turn_monitor,
            embedding_client=embedding_client,
            event_bus=event_bus,
            sidecar=sidecar,
            sandbox=sandbox,
            google_oauth=google_oauth,
        )
        planner_available = True

        # Fast-path message router (opt-in via router_enabled)
        if settings.router_enabled:
            message_router, classifier, fast_path_executor = _init_message_router(
                settings=settings,
                app=app,
                audit=audit,
                pipeline=pipeline,
                pg_pool=pg_pool,
                session_store=session_store,
                contact_store=contact_store,
                event_bus=event_bus,
                orchestrator=orchestrator,
                tool_executor=tool_executor,
                track_task_fn=track_task_fn,
            )

    except PlannerError as exc:
        logger.exception(
            "init_orchestrator: PlannerError",
            extra={"event": "orchestrator.planner_init_error"},
        )
        audit.warning(
            "Claude planner not available: %s",
            exc,
            extra={
                "event": "planner.init_failed",
                "error": str(exc),
                "error_category": exc.category,
                "error_class": "transient" if exc.retryable else "permanent",
            },
            exc_info=True,
        )
        planner_available = False
        app.state.planner_available = False

    # Optional services: MCP server
    mcp_server = _init_optional_services(
        settings=settings,
        app=app,
        audit=audit,
        orchestrator=orchestrator,
        memory_store=memory_store,
        embedding_client=embedding_client,
        event_bus=event_bus,
    )

    logger.debug(
        "Orchestrator initialization complete",
        extra={
            "event": "init.orchestrator_done",
            "planner_available": planner_available,
            "ollama_reachable": True,
            "sidecar_enabled": sidecar is not None,
            "sandbox_enabled": sandbox is not None,
            "router_enabled": message_router is not None,
        },
    )

    return (
        orchestrator,
        message_router,
        event_bus,
        sidecar,
        sandbox,
        embedding_client,
        planner_available,
        True,  # ollama_reachable — _check_ollama_health raises if not
        mcp_server,
        classifier,
        fast_path_executor,
    )
