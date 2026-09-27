"""Channel initialization: messaging channels, routines, heartbeat, route wiring.

Sets up Signal, Telegram, and email channels, the routine engine, heartbeat
system, webhook rate limiter, HTTP→HTTPS redirect, all route module wiring,
and the static file mount (which MUST be last — catch-all "/" shadows
everything after it).
"""

import asyncio
import logging
import mimetypes
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from sentinel.api.routes import (
    a2a as a2a_routes,
)
from sentinel.api.routes import (
    health as health_routes,
)
from sentinel.api.routes import (
    memory as memory_routes,
)
from sentinel.api.routes import (
    routines as routine_routes,
)
from sentinel.api.routes import (
    security as security_routes,
)
from sentinel.api.routes import (
    streaming as streaming_routes,
)
from sentinel.api.routes import (
    task as task_routes,
)
from sentinel.api.routes import (
    webhooks as webhook_routes,
)
from sentinel.api.routes import (
    websocket as websocket_routes,
)
from sentinel.api.routes.health import HealthState
from sentinel.channels.base import Channel, ChannelRouter
from sentinel.channels.email_channel import EmailChannel
from sentinel.channels.matrix_channel import MatrixChannel
from sentinel.channels.registry import ChannelRegistry
from sentinel.channels.signal_channel import SignalChannel
from sentinel.channels.telegram_channel import TelegramChannel
from sentinel.channels.webhook import RateLimiter as WebhookRateLimiter
from sentinel.core.config import settings
from sentinel.core.socket_auth import validate_runtime_dir
from sentinel.routines.engine import RoutineEngine
from sentinel.routines.heartbeat import HeartbeatManager, seed_heartbeat_routine

# -- Channel class list: add new channels here (1 import + 1 entry) -----------
CHANNEL_CLASSES: list[type[Channel]] = [
    SignalChannel,
    TelegramChannel,
    EmailChannel,
    MatrixChannel,
]

logger = logging.getLogger(__name__)


async def init_channels(
    app: FastAPI,
    settings,
    audit,
    orchestrator,
    message_router,
    event_bus,
    pipeline,
    engine,
    pin_verifier,
    pg_pool,
    session_store,
    memory_store,
    routine_store,
    contact_store,
    webhook_registry,
    embedding_client,
    sidecar,
    sandbox,
    prompt_guard_loaded,
    semgrep_loaded,
    ollama_reachable,
    planner_available,
    hybrid_search_fn,
    get_metrics_fn,
    track_task_fn,
    background_tasks,
    gather_component_status_fn,
    classifier=None,
    fast_path_executor=None,
    loop_store=None,
    insight_store=None,
):
    """Initialize channels, routines, heartbeat, and wire route modules.

    Called from lifespan() between current_user_id.set(1) and .reset() — RLS
    context is active for all startup seeding operations (routines, heartbeat).

    Returns (channel_registry, redirect_server) so the caller can set
    module-level globals and wire shutdown.
    """
    logger.debug(
        "Initializing channels and route wiring",
        extra={"event": "init.channels_start"},
    )

    # ── Phase 1: Core services ──
    _routine_engine = await _init_routine_engine(
        app,
        settings,
        audit,
        orchestrator,
        routine_store,
        event_bus,
        pg_pool,
        classifier=classifier,
        fast_path_executor=fast_path_executor,
    )
    _webhook_rate_limiter = WebhookRateLimiter()
    app.state.webhook_rate_limiter = _webhook_rate_limiter
    audit.info("Webhook registry initialized", extra={"event": "webhook.init"})

    _heartbeat_manager = await _init_heartbeat(
        app,
        settings,
        audit,
        memory_store,
        routine_store,
        gather_component_status_fn,
        track_task_fn,
        background_tasks,
    )

    # ── Phase 2: Messaging channels (registry-based) ──
    channel_registry = await _init_messaging_channels(
        app=app,
        settings=settings,
        audit=audit,
        orchestrator=orchestrator,
        event_bus=event_bus,
        message_router=message_router,
        contact_store=contact_store,
        track_task_fn=track_task_fn,
        loop_store=loop_store,
    )

    # Store registry on app.state for shutdown access
    app.state.channel_registry = channel_registry

    # Wire channel registry into tool executor for dynamic handler registration
    if orchestrator is not None and any(channel_registry.with_tools()):
        orchestrator.set_channel_registry(channel_registry)
        audit.info(
            "Channel registry wired to tool executor",
            extra={
                "event": "tool.channels_wired",
                "channels": [
                    ch.descriptor.name for ch in channel_registry.with_tools()
                ],
            },
        )

    # Register channel tool-to-domain mappings for episodic store
    from sentinel.memory.episodic import register_channel_domains

    register_channel_domains(channel_registry)

    # ── Phase 3: HTTP redirect + route wiring ──
    redirect_server = await _init_redirect_server(
        settings,
        audit,
        track_task_fn,
    )
    _wire_route_modules(
        app=app,
        settings=settings,
        audit=audit,
        orchestrator=orchestrator,
        message_router=message_router,
        event_bus=event_bus,
        pipeline=pipeline,
        engine=engine,
        pin_verifier=pin_verifier,
        session_store=session_store,
        memory_store=memory_store,
        routine_store=routine_store,
        contact_store=contact_store,
        webhook_registry=webhook_registry,
        embedding_client=embedding_client,
        sidecar=sidecar,
        sandbox=sandbox,
        prompt_guard_loaded=prompt_guard_loaded,
        semgrep_loaded=semgrep_loaded,
        ollama_reachable=ollama_reachable,
        planner_available=planner_available,
        hybrid_search_fn=hybrid_search_fn,
        get_metrics_fn=get_metrics_fn,
        loop_store=loop_store,
        insight_store=insight_store,
        channel_registry=channel_registry,
        routine_engine=_routine_engine,
        webhook_rate_limiter=_webhook_rate_limiter,
        heartbeat_manager=_heartbeat_manager,
    )

    # ── Phase 4: Validation + static mount ──
    _validate_startup(settings, audit, prompt_guard_loaded, semgrep_loaded)
    register_sites_route(app)

    # Mount static files LAST — the "/" catch-all must come after every
    # other route (API, WebSocket, MCP).  Routes added during
    # lifespan (such as the MCP mount) are appended to app.routes,
    # so any catch-all registered at module level would shadow them.
    if Path(settings.static_dir).is_dir():
        app.mount(
            "/",
            StaticFiles(directory=settings.static_dir, html=True),
            name="static",
        )

    logger.debug(
        "Channel initialization complete",
        extra={
            "event": "init.channels_done",
            "registered_channels": [
                ch.descriptor.name for ch in channel_registry.enabled()
            ],
            "channel_count": len(channel_registry),
        },
    )

    return (channel_registry, redirect_server)


# ── Extracted sub-functions ─────────────────────────────────────────────


async def _init_routine_engine(
    app: FastAPI,
    settings,
    audit,
    orchestrator,
    routine_store,
    event_bus,
    pg_pool,
    *,
    classifier=None,
    fast_path_executor=None,
) -> RoutineEngine | None:
    """Start the routine engine if enabled, wire into orchestrator.

    Returns the engine instance (or None if disabled).
    """
    logger.debug(
        "_init_routine_engine called",
        extra={
            "event": "channels._init_routine_engine",
            "app_type": type(app).__name__,
            "settings_type": type(settings).__name__,
            "audit_type": type(audit).__name__,
        },
    )  # auto:entry
    if not (settings.routine_enabled and orchestrator is not None):
        audit.info(
            "Routine engine disabled",
            extra={
                "event": "routine.engine_disabled",
                "routine_enabled": settings.routine_enabled,
                "orchestrator_available": orchestrator is not None,
            },
        )
        return None

    engine = RoutineEngine(
        store=routine_store,
        orchestrator=orchestrator,
        event_bus=event_bus,
        pool=pg_pool,
        admin_pool=getattr(app.state, "admin_pool", None),
        tick_interval=settings.routine_scheduler_interval,
        max_concurrent=settings.routine_max_concurrent,
        execution_timeout=settings.routine_execution_timeout,
        classifier=classifier if settings.router_enabled else None,
        fast_path=fast_path_executor if settings.router_enabled else None,
    )
    app.state.routine_engine = engine
    await engine.start()
    await engine.seed_defaults(user_id=1)  # Seed for default user
    # Wire routine engine into orchestrator (breaks circular dep:
    # RoutineEngine needs Orchestrator, Orchestrator needs RoutineEngine)
    orchestrator.set_routine_engine(engine)
    audit.info(
        "Routine engine started",
        extra={
            "event": "routine.engine_init",
            "tick_interval": settings.routine_scheduler_interval,
            "max_concurrent": settings.routine_max_concurrent,
        },
    )
    return engine


async def _init_heartbeat(
    app: FastAPI,
    settings,
    audit,
    memory_store,
    routine_store,
    gather_component_status_fn,
    track_task_fn,
    background_tasks,
) -> HeartbeatManager:
    """Start the heartbeat manager and background loop.

    Returns the HeartbeatManager instance.
    """

    async def _health_check() -> dict:
        return gather_component_status_fn()

    manager = HeartbeatManager(
        memory_store=memory_store,
        health_check_fn=_health_check,
    )
    app.state.heartbeat_manager = manager
    if routine_store is not None:
        await seed_heartbeat_routine(routine_store)

    async def _heartbeat_loop() -> None:
        while True:
            await asyncio.sleep(settings.heartbeat_interval)
            try:
                await manager.run_heartbeat()
            except Exception as e:
                logger.exception(
                    "_heartbeat_loop: Exception",
                    extra={"event": "channels._heartbeat_loop_error"},
                )
                logging.getLogger("sentinel.audit").warning(
                    "Heartbeat error: %s",
                    e,
                    extra={"event": "heartbeat.error", "error": str(e)},
                    exc_info=True,
                )

    track_task_fn(_heartbeat_loop(), name="heartbeat")
    app.state.background_tasks = background_tasks
    audit.info("Heartbeat system initialized", extra={"event": "heartbeat.init"})
    return manager


async def _init_messaging_channels(
    *,
    app: FastAPI,
    settings,
    audit,
    orchestrator,
    event_bus,
    message_router,
    contact_store,
    track_task_fn,
    loop_store=None,
) -> ChannelRegistry:
    """Initialize all messaging channels via the registry pattern.

    Iterates over CHANNEL_CLASSES, calls from_settings() to build each
    channel (returns None if disabled), starts enabled channels, and
    spawns a generic receive loop for each. Returns a populated registry.
    """
    registry = ChannelRegistry()

    if orchestrator is None or event_bus is None:
        logger.info(
            "Skipping messaging channels — no orchestrator/event_bus",
            extra={"event": "channels.skip_no_orchestrator"},
        )
        return registry

    for cls in CHANNEL_CLASSES:
        name = cls.descriptor.name
        # Q13.fix.f — for the signal channel specifically, validate
        # settings.runtime_dir BEFORE from_settings() constructs the channel.
        # The Unix socket path lives under runtime_dir; if perms / owner / dir
        # existence are wrong, refuse to register rather than bind a weaker
        # socket. Other channels (Telegram/Email/Matrix) are HTTP-backed and
        # do not touch runtime_dir, so they remain unaffected. See
        # sentinel/core/socket_auth.py + design cluster 2 §Startup validation.
        if cls is SignalChannel and settings.signal_enabled:
            try:
                validate_runtime_dir(settings.runtime_dir, os.getuid())
            except RuntimeError as exc:
                logger.exception(
                    "_init_messaging_channels: RuntimeError",
                    extra={
                        "event": "api.init.channels._init_messaging_channels_runtimeerror"
                    },
                )  # auto:except
                audit.error(
                    "runtime_dir validation failed; signal channel skipped",
                    extra={
                        "event": "channels.runtime_dir_invalid",
                        "runtime_dir": settings.runtime_dir,
                        "error": str(exc),
                    },
                    exc_info=True,
                )
                continue
        try:
            channel = cls.from_settings(settings)
        except Exception:
            logger.exception(
                "Channel from_settings failed",
                extra={"event": f"{name}.from_settings_error"},
            )
            audit.error(
                f"{name.title()} channel failed to build config",
                extra={"event": f"{name}.channel_error"},
                exc_info=True,
            )
            continue

        if channel is None:
            logger.debug(
                "Channel disabled — skipping",
                extra={"event": f"{name}.channel_disabled.clean"},
            )
            audit.info(
                f"{name.title()} channel disabled",
                extra={"event": f"{name}.channel_disabled"},
            )
            continue

        # Inject event bus (all channels accept it)
        if hasattr(channel, "_bus") and channel._bus is None:
            channel._bus = event_bus

        # Q4.fix.e: Telegram consults the contact store at startup to
        # classify existing enrollments post-migration (Option E passive
        # audit). Optional on other channels — set only if the attribute
        # exists.
        if hasattr(channel, "_contact_store") and contact_store is not None:
            channel._contact_store = contact_store

        try:
            await channel.start()
        except Exception:
            logger.exception(
                "Channel start() failed",
                extra={"event": f"{name}.start_error"},
            )
            audit.error(
                f"{name.title()} channel failed to start",
                extra={"event": f"{name}.channel_error"},
                exc_info=True,
            )
            continue

        # Store on app.state for backward compat
        setattr(app.state, f"{name}_channel", channel)

        # Spawn generic receive loop BEFORE start_polling (original ordering:
        # receive loop must be consuming the queue before polling delivers messages)
        _spawn_receive_loop(
            channel=channel,
            audit=audit,
            orchestrator=orchestrator,
            event_bus=event_bus,
            message_router=message_router,
            contact_store=contact_store,
            track_task_fn=track_task_fn,
            loop_store=loop_store,
            app=app,
        )

        # Telegram has a separate polling step after receive loop is consuming
        if hasattr(channel, "start_polling"):
            try:
                await channel.start_polling()
            except Exception:
                logger.exception(
                    "Channel start_polling() failed",
                    extra={"event": f"{name}.start_polling_error"},
                )
                audit.error(
                    f"{name.title()} channel polling failed",
                    extra={"event": f"{name}.polling_error"},
                    exc_info=True,
                )
                continue

        registry.register(channel)

        # Preserve channel-specific startup metadata that operators use
        # for verification — mirrors the per-channel init functions' logging
        startup_extra: dict = {
            "event": f"{name}.channel_init",
            "channel": name,
        }
        if hasattr(channel, "_config"):
            cfg = channel._config
            if hasattr(cfg, "rate_limit"):
                startup_extra["rate_limit"] = cfg.rate_limit
            if hasattr(cfg, "allowed_senders"):
                startup_extra["allowed_senders"] = len(cfg.allowed_senders)
            if hasattr(cfg, "allowed_chat_ids"):
                startup_extra["allowed_chats"] = len(cfg.allowed_chat_ids)
            if hasattr(cfg, "account"):
                startup_extra["account"] = cfg.account
            if hasattr(cfg, "homeserver_url"):
                startup_extra["homeserver"] = cfg.homeserver_url
            if hasattr(cfg, "poll_interval_seconds"):
                startup_extra["poll_interval"] = cfg.poll_interval_seconds
        audit.info(f"{name.title()} channel started", extra=startup_extra)
        # LOUD warning when an enabled channel has an empty sender allowlist
        # AND the channel treats empty = fail-closed. Caller passes the
        # semantic explicitly — the helper does not infer it from the channel
        # name (coupling hazard) or the config shape. All four messaging
        # channels (Signal/Matrix/Telegram/Email) are fail-closed on empty
        # post-Q13.fix.c + Q13-F14 (cleanup-pass C38).
        _warn_if_empty_allowlist(
            name=name,
            channel=channel,
            audit=audit,
            fail_closed_on_empty=_EMPTY_ALLOWLIST_FAIL_CLOSED.get(name, False),
        )

    return registry


# Per-channel declaration of empty-allowlist semantic. A channel's name maps
# to True when the channel's inbound gate drops every sender on an empty
# allowlist (deny-all), False when empty means allow-all or the channel has
# no inbound-sender allowlist. Unknown channel names default to False (no
# warning); new channels declare their semantic here.
_EMPTY_ALLOWLIST_FAIL_CLOSED: dict[str, bool] = {
    "signal": True,
    "matrix": True,
    "telegram": True,
    "email": True,  # Q13-F14 alignment 2026-04-26 (cleanup-pass C38)
}


def _warn_if_empty_allowlist(
    *,
    name: str,
    channel: Channel,
    audit,
    fail_closed_on_empty: bool,
) -> None:
    """Emit an audit warning if an enabled fail-closed channel has an empty
    allowlist.

    Q13-F8 alignment: Signal/Matrix/Telegram now all fail-closed on empty
    allowlists (deny every sender). That's the right default but it's silent
    — an operator who deploys a channel and forgets to populate the allowlist
    watches the channel drop every message with no feedback. This helper
    fires a LOUD `channel.empty_allowlist` audit event so the misconfiguration
    is visible at startup. The `audit.warning` lands in the audit stream, not
    just application logs, so the signal is preserved even with noisy log
    levels.

    Caller declares `fail_closed_on_empty` per channel — the helper does not
    infer the semantic. This keeps the helper decoupled from channel-name
    strings (adding a new channel means the caller passes True/False; no
    edits here) and prevents false-positive warnings for channels that have
    an `allowed_senders`-shaped config but don't actually fail-closed on
    empty.
    """
    if not fail_closed_on_empty:
        logger.debug(
            "_warn_if_empty_allowlist: caller_not_fail_closed",
            extra={
                "event": "api.init.channels._warn_if_empty_allowlist.skip",
                "channel": name,
                "reason": "caller_not_fail_closed",
            },
        )  # auto:neg
        return
    cfg = getattr(channel, "_config", None)
    if cfg is None:
        return
    allowlist_attr = None
    size = 0
    if hasattr(cfg, "allowed_senders"):
        allowlist_attr = "allowed_senders"
        size = len(cfg.allowed_senders)
    elif hasattr(cfg, "allowed_chat_ids"):
        allowlist_attr = "allowed_chat_ids"
        size = len(cfg.allowed_chat_ids)
    if allowlist_attr is None:
        return
    if size == 0:
        logger.debug(
            "_warn_if_empty_allowlist: size_eq_0",
            extra={
                "event": "api.init.channels._warn_if_empty_allowlist.match",
                "reason": "size_eq_0",
            },
        )  # auto:neg
        audit.warning(
            f"{name.title()} channel enabled with EMPTY allowlist — all inbound"
            " messages will be rejected. Populate the allowlist to accept senders.",
            extra={
                "event": "channel.empty_allowlist",
                "channel": name,
                "allowlist_field": allowlist_attr,
            },
        )
    else:
        logger.debug(
            "Channel allowlist populated",
            extra={
                "event": "channel.empty_allowlist.clean",
                "channel": name,
                "allowlist_field": allowlist_attr,
                "size": size,
                "reason": "non_empty_allowlist",
            },
        )  # auto:neg


def _spawn_receive_loop(
    *,
    channel: Channel,
    audit,
    orchestrator,
    event_bus,
    message_router,
    contact_store,
    track_task_fn,
    loop_store,
    app,
) -> None:
    """Spawn a generic receive loop for any channel.

    Replaces the 4 per-channel _*_receive_loop() functions with a single
    generic implementation. Sender resolution uses channel.get_sender_id()
    and channel.get_source_key() to handle per-channel differences.
    """
    name = channel.descriptor.name

    async def _receive_loop() -> None:
        from sentinel.contacts.resolver import resolve_sender
        from sentinel.core.context import current_user_id

        router = ChannelRouter(
            orchestrator,
            event_bus,
            audit,
            message_router=message_router,
            loop_controller=getattr(app.state, "loop_controller", None),
            loop_store=loop_store,
        )
        async for message in channel.receive():
            sender_id = channel.get_sender_id(message)
            resolved_uid = await resolve_sender(contact_store, name, sender_id)
            if resolved_uid is None:
                audit.warning(
                    f"Unknown {name} sender — rejecting",
                    extra={
                        "event": f"{name}.unknown_sender",
                        "sender": sender_id,
                    },
                )
                continue
            ctx_token = current_user_id.set(resolved_uid)
            try:
                message.metadata["source_key"] = channel.get_source_key(message)
                await router.handle_message(channel, message)
            except Exception as exc:
                logger.exception(
                    f"_{name}_receive_loop: Exception",
                    extra={"event": f"channels._{name}_receive_loop_error"},
                )
                audit.error(
                    f"{name.title()} message handling failed",
                    extra={
                        "event": f"{name}.handle_error",
                        "error": str(exc),
                    },
                    exc_info=True,
                )
            finally:
                current_user_id.reset(ctx_token)

    track_task_fn(_receive_loop(), name=f"{name}-receiver")


async def _init_redirect_server(settings, audit, track_task_fn):
    """Start HTTP→HTTPS redirect server if TLS is active.

    Returns the uvicorn.Server instance (or None if not started).
    """
    if not (settings.redirect_enabled and settings.tls_cert_file):
        return None

    try:
        import uvicorn

        from sentinel.api.redirect import HTTPSRedirectApp

        redirect_config = uvicorn.Config(
            app=HTTPSRedirectApp(),
            host=settings.host,
            port=settings.http_port,
            log_level="warning",
        )
        server = uvicorn.Server(redirect_config)
        track_task_fn(server.serve(), name="https-redirect")
        audit.info(
            "HTTP redirect server started",
            extra={
                "event": "redirect.started",
                "http_port": settings.http_port,
                "https_port": settings.external_https_port,
            },
        )
        return server
    except Exception as exc:
        logger.exception(
            "_init_redirect_server: Exception",
            extra={"event": "channels.redirect_init_error"},
        )
        audit.warning(
            "Failed to start redirect server: %s",
            exc,
            extra={"event": "redirect.failed", "error": str(exc)},
            exc_info=True,
        )
        return None


def _wire_route_modules(
    *,
    app: FastAPI,
    settings,
    audit,
    orchestrator,
    message_router,
    event_bus,
    pipeline,
    engine,
    pin_verifier,
    session_store,
    memory_store,
    routine_store,
    contact_store,
    webhook_registry,
    embedding_client,
    sidecar,
    sandbox,
    prompt_guard_loaded,
    semgrep_loaded,
    ollama_reachable,
    planner_available,
    hybrid_search_fn,
    get_metrics_fn,
    loop_store,
    insight_store,
    channel_registry,
    routine_engine,
    webhook_rate_limiter,
    heartbeat_manager,
) -> None:
    """Wire all route modules to their dependencies.

    Each route module exposes an init() function that receives the objects it
    needs. This function calls all of them in the correct order.
    """
    # HealthState is a live-reference object — the health endpoints read it
    # directly, so fields updated here are reflected immediately.
    logger.debug(
        "_wire_route_modules called", extra={"event": "channels._wire_route_modules"}
    )  # auto:entry
    health_state = HealthState(
        prompt_guard_loaded=prompt_guard_loaded,
        semgrep_loaded=semgrep_loaded,
        ollama_reachable=ollama_reachable,
        planner_available=planner_available,
        sidecar=sidecar,
        sandbox=sandbox,
        channel_registry=channel_registry,
        engine=engine,
        pin_verifier=pin_verifier,
    )
    health_routes.init(
        health_state=health_state,
        session_store=session_store,
        orchestrator=orchestrator,
        routine_engine=routine_engine,
        get_metrics_fn=get_metrics_fn,
        contact_store=contact_store,
        audit_emitter=getattr(app.state, "audit_emitter", None),
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
        loop_controller=getattr(app.state, "loop_controller", None),
        loop_store=loop_store,
    )
    memory_routes.init(
        memory_store=memory_store,
        embedding_client=embedding_client,
        hybrid_search_fn=hybrid_search_fn,
        audit=audit,
    )
    routine_routes.init(
        routine_store=routine_store,
        routine_engine=routine_engine,
        scan_pipeline=pipeline,
        audit_emitter=getattr(app.state, "audit_emitter", None),
    )
    # Q13.fix.e (F3): admin_pool is REQUIRED in production — the
    # receive path uses it to bypass RLS on the auth-exempt
    # current_user_id=0 context AND to persist replay fingerprints
    # (webhook_replay_fingerprints is NOT under RLS).
    _webhook_admin_pool = getattr(app.state, "admin_pool", None)
    if _webhook_admin_pool is None:
        raise RuntimeError(
            "Webhook routes require app.state.admin_pool; missing at init time. "
            "Check Tier 1 database initialization order."
        )
    webhook_routes.init(
        webhook_registry=webhook_registry,
        webhook_rate_limiter=webhook_rate_limiter,
        orchestrator=orchestrator,
        message_router=message_router,
        event_bus=event_bus,
        admin_pool=_webhook_admin_pool,
        audit=audit,
        loop_controller=getattr(app.state, "loop_controller", None),
        loop_store=loop_store,
    )
    streaming_routes.init(
        event_bus=event_bus,
        heartbeat_manager=heartbeat_manager,
        audit=audit,
        orchestrator=orchestrator,
        contact_store=contact_store,
        audit_emitter=getattr(app.state, "audit_emitter", None),
    )
    websocket_routes.init(
        orchestrator=orchestrator,
        event_bus=event_bus,
        message_router=message_router,
        pin_verifier=pin_verifier,
        audit=audit,
        loop_controller=getattr(app.state, "loop_controller", None),
        loop_store=loop_store,
    )
    a2a_routes.init(
        orchestrator=orchestrator,
        event_bus=event_bus,
    )

    # Loop + insight routes
    from sentinel.api.routes import loop as loop_routes

    loop_routes.init(
        orchestrator=orchestrator,
        loop_store=loop_store,
        loop_controller=getattr(app.state, "loop_controller", None),
        event_bus=event_bus,
        audit=audit,
        insight_store=insight_store,
        insight_extractor=getattr(app.state, "insight_extractor", None),
    )


def _validate_startup(settings, audit, prompt_guard_loaded, semgrep_loaded) -> None:
    """Warn if critical security scanners are both offline (BOOT-1)."""
    if not prompt_guard_loaded and not semgrep_loaded:
        if settings.trust_level >= 4:
            audit.critical(
                "DEGRADED: Both Prompt Guard and Semgrep failed to initialize at TL%d "
                "— security scanning severely limited",
                settings.trust_level,
                extra={
                    "event": "startup.degraded",
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
                    "event": "startup.degraded",
                    "trust_level": settings.trust_level,
                },
            )


def register_sites_route(app: FastAPI):
    """Register a dynamic route for serving user-created sites.

    Sites live at /workspace/{user_id}/sites/{site_id}/ but are served at
    /sites/{site_id}/{path} for clean shareable URLs. The handler searches
    across all user workspace directories so any user's site is reachable
    without knowing which user created it.
    """
    logger.debug(
        "register_sites_route called",
        extra={"event": "register.sites_route", "route_count": len(app.routes)},
    )
    workspace_base = Path(settings.workspace_path)

    @app.get("/sites/{site_id}/{file_path:path}")
    @app.get("/sites/{site_id}")
    async def serve_site(request: Request, site_id: str, file_path: str = ""):
        # Reject path traversal attempts
        logger.debug(
            "serve_site called",
            extra={"event": "serve.site", "site_id": site_id, "file_path": file_path},
        )
        if ".." in site_id or ".." in file_path:
            logger.debug(
                "serve_site: match", extra={"event": "channels.serve_site.match"}
            )
            logger.debug(
                "register_sites_route: match",
                extra={"event": "channels.register_sites_route.match"},
            )
            return Response(status_code=400, content="Invalid path")
        logger.debug(
            "serve_site: ___in_site_id_passed",
            extra={
                "event": "channels.serve_site.passed",
                "reason": "___in_site_id_passed",
            },
        )  # auto:neg

        # Redirect /sites/<name> → /sites/<name>/ so relative paths resolve
        # correctly (e.g. <script src="app.js"> becomes /sites/<name>/app.js
        # instead of /sites/app.js which 404s)
        if not file_path and not request.url.path.endswith("/"):
            logger.debug(
                "serve_site: not_file_path",
                extra={"event": "channels.serve_site.match", "reason": "not_file_path"},
            )  # auto:neg
            logger.debug(
                "register_sites_route: not_file_path",
                extra={
                    "event": "channels.register_sites_route.match",
                    "reason": "not_file_path",
                },
            )  # auto:neg
            return RedirectResponse(
                url=f"/sites/{site_id}/",
                status_code=301,
            )
        logger.debug(
            "serve_site: not_file_path_passed",
            extra={
                "event": "channels.serve_site.passed",
                "reason": "not_file_path_passed",
            },
        )  # auto:neg

        # Search all user workspace dirs for this site
        if not workspace_base.is_dir():
            logger.debug(
                "serve_site: match", extra={"event": "channels.serve_site.match"}
            )
            logger.debug(
                "register_sites_route: match",
                extra={"event": "channels.register_sites_route.match"},
            )
            return Response(status_code=404, content="Site not found")

        target_file = None
        for user_dir in workspace_base.iterdir():
            if not user_dir.is_dir() or not user_dir.name.isdigit():
                continue
            site_dir = user_dir / "sites" / site_id
            if not site_dir.is_dir():
                continue
            # Resolve the requested file (default to index.html)
            if file_path:
                logger.debug(
                    "serve_site: match", extra={"event": "channels.serve_site.match"}
                )
                logger.debug(
                    "register_sites_route: match",
                    extra={"event": "channels.register_sites_route.match"},
                )
                candidate = site_dir / file_path
            else:
                logger.debug(
                    "serve_site: clean", extra={"event": "channels.serve_site.clean"}
                )
                logger.debug(
                    "register_sites_route: clean",
                    extra={"event": "channels.register_sites_route.clean"},
                )
                candidate = site_dir / "index.html"
            if candidate.is_file():
                # Ensure resolved path is within the site dir (symlink guard)
                try:
                    candidate.resolve().relative_to(site_dir.resolve())
                except ValueError:
                    # Symlink escape attempt — resolved path outside site dir
                    logger.warning(
                        "Path traversal via symlink blocked: %s -> %s",
                        candidate,
                        candidate.resolve(),
                        extra={
                            "event": "serve.site_symlink_blocked",
                            "site_id": site_id,
                            "requested_path": file_path,
                        },
                        exc_info=True,  # auto:exc
                    )
                    return Response(status_code=400, content="Invalid path")
                target_file = candidate
                break

        if target_file is None:
            logger.debug(
                "serve_site: match", extra={"event": "channels.serve_site.match"}
            )
            logger.debug(
                "register_sites_route: match",
                extra={"event": "channels.register_sites_route.match"},
            )
            return Response(status_code=404, content="Site not found")

        content_type = (
            mimetypes.guess_type(str(target_file))[0] or "application/octet-stream"
        )
        return FileResponse(str(target_file), media_type=content_type)
