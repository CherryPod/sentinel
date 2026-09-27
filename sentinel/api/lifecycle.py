"""Application lifecycle: startup initialization and shutdown sequence.

Owns the module-level globals that tests patch via sentinel.api.lifecycle._*.
The actual initialization logic lives in sentinel.api.init.* sub-modules;
this file calls them in order and sets the globals from their return values.

Backward compatibility: lifecycle functions that mutate module globals also
sync the values back to sentinel.api.app via lazy import. This keeps
route-module fallbacks (which read _app._shutting_down etc.) and safety-net
test patches (which set app_module._pin_verifier etc.) working without
modifying those consumers.
"""

import asyncio
import contextvars
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinel.api.init.channels import init_channels
from sentinel.api.init.database import bootstrap_owner, init_database
from sentinel.api.init.orchestrator import init_orchestrator
from sentinel.api.init.security import init_security
from sentinel.api.init.shutdown import shutdown
from sentinel.api.routes import health as health_routes
from sentinel.api.routes import websocket as websocket_routes
from sentinel.api.routes.health import HealthState
from sentinel.audit import SecurityAuditEvent, setup_audit_logger
from sentinel.core.config import settings
from sentinel.core.context import spawn_task

logger = logging.getLogger(__name__)


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
# lifespan via init_* functions (dual-write to both globals and app.state).
# The _sync_to_app_module() helper propagates changes back to sentinel.api.app
# for backward compatibility with route-module fallbacks and test patches.

_pin_verifier = None
_engine = None
_pipeline = None
_prompt_guard_loaded: bool = False
_semgrep_loaded: bool = False
_planner_available: bool = False
_ollama_reachable: bool = False
_sidecar = None
_sandbox = None
_channel_registry = None  # ChannelRegistry — replaces per-channel globals

# Shutdown coordination (SYS-5a)
_shutting_down: bool = False
_background_tasks: set[asyncio.Task] = set()


# Per-global operator remediation hints surfaced when a critical global is
# still None at the end of startup. Hints append to the RuntimeError message
# so an operator who has never seen the codebase can act without grepping.
# Audit-event payload (lifecycle.startup.validation_failed) is unchanged.
# Other un-hinted globals (_engine / _pipeline / _pin_verifier / _sidecar)
# are out of scope here; widening hints to the rest is a future class-sweep.
_GLOBAL_REMEDIATION_HINTS: dict[str, str] = {
    "_sandbox": (
        "_sandbox is None. Reachable causes (see sandbox.init_failed / "
        "sandbox.disabled audit events earlier in startup logs):\n"
        "  1. SENTINEL_SANDBOX_ENABLED=false — set it true if you want the "
        "sandbox active.\n"
        "  2. PodmanSandbox.health_check() returned False — typically the "
        "sentinel-sandbox:latest image is missing, the podman socket is "
        "unreachable, or the proxy API is down. Rebuild the image with:\n"
        "       podman build -t sentinel-sandbox:latest "
        "-f container/Containerfile.sandbox .\n"
        "     (Definition: container/Containerfile.sandbox)"
    ),
}


async def _periodic_revocation_cleanup():
    """Run periodic cleanup of expired revocation entries."""
    from sentinel.api.revocation import get_revocation_set

    while True:
        await asyncio.sleep(900)  # 15 minutes
        try:
            get_revocation_set().cleanup()
        except Exception:  # catch-all: periodic cleanup must not crash
            logger.warning(
                "Revocation cleanup failed",
                exc_info=True,
                extra={"event": "revocation.cleanup_failed"},
            )


async def _periodic_db_maintenance(admin_pool, audit_emitter, event_bus) -> None:
    """Run run_db_maintenance every db_maintenance_interval_s (Q5.fix.a / F7).

    Startup one-shot stays in init_database; this loop picks up afterwards so
    retention windows (audit_log 90d, routine_executions 30d, provenance 7d,
    approvals 7d, security_audit_log per-category) keep firing on long-running
    processes instead of only at restart.

    admin_pool is the lifespan-owned sentinel_owner pool; the ref is captured
    once at scheduler start and stays valid until shutdown drains this task
    before admin_pool.close() (ordering verified in init/shutdown.py).

    event_bus is threaded through so periodic expiry-transition sweeps (e.g.
    `approvals_expired` UPDATE … RETURNING) publish their downstream topics
    on every tick, not just the startup one-shot. Without the bus, the
    startup scheduler-loop silently drops `approval.expired` + equivalent
    events — Q5.fix.b MC review round 1 caught this gap at merge gate
    (Codex thread `019db59f`).

    Cancellation policy: CancelledError from asyncio.sleep or from
    run_db_maintenance propagates out of the loop unchanged — the
    ``except Exception:`` catch-all at line 135 does not catch BaseException.
    See D33.design for emit-site observability at the _emit_maintenance_audit call.
    """
    from sentinel.core.db import run_db_maintenance

    interval = settings.db_maintenance_interval_s
    while True:
        await asyncio.sleep(interval)
        try:
            await run_db_maintenance(
                admin_pool,
                audit_emitter=audit_emitter,
                event_bus=event_bus,
            )
        except Exception:  # catch-all: scheduler must survive task failures
            logger.warning(
                "Periodic DB maintenance failed",
                exc_info=True,
                extra={"event": "db.periodic_maintenance_failed"},
            )


def _sync_to_app_module(**kwargs) -> None:
    """Push global values back to sentinel.api.app for backward compat.

    Route modules read globals from sentinel.api.app via lazy import fallbacks,
    and safety-net tests patch them via patch.object(app_module, ...). This
    function keeps the app module's attributes in sync after lifecycle functions
    mutate them.
    """
    logger.debug("_sync_to_app_module called", extra={"event": "sync.to_app_module"})
    import sentinel.api.app as _app_mod

    for name, value in kwargs.items():
        setattr(_app_mod, name, value)


def _log_task_exception(task: asyncio.Task) -> None:
    """Log unhandled exceptions from background tasks."""
    if not task.cancelled() and task.exception():
        exc = task.exception()
        logging.getLogger("sentinel.audit").error(
            "Background task %s failed: %s",
            task.get_name(),
            exc,
            exc_info=(type(exc), exc, exc.__traceback__),
            extra={"event": "background.task_failed", "task_name": task.get_name()},
        )


def _track_task(coro, *, name: str | None = None) -> asyncio.Task:
    """Create an asyncio task and register it for shutdown tracking.

    Uses spawn_task() so user-scoped context (current_user_id, etc.) is
    propagated to the child task. Call sites include per-user orchestration
    work so the correct user ID must be visible inside the task.
    """
    logger.debug("_track_task called", extra={"event": "track.task", "task_name": name})
    task = spawn_task(coro, name=name)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    task.add_done_callback(_log_task_exception)
    return task


def _gather_component_status() -> dict:
    """Build component status dict shared by heartbeat and legacy callers.

    Delegates to health_routes.gather_component_status() using a HealthState
    built from the current module-level globals.
    """
    logger.debug(
        "_gather_component_status called", extra={"event": "gather.component_status"}
    )
    hs = HealthState(
        prompt_guard_loaded=_prompt_guard_loaded,
        semgrep_loaded=_semgrep_loaded,
        ollama_reachable=_ollama_reachable,
        planner_available=_planner_available,
        sidecar=_sidecar,
        sandbox=_sandbox,
        channel_registry=_channel_registry,
        engine=_engine,
        pin_verifier=_pin_verifier,
    )
    return health_routes.gather_component_status(hs)


async def _emit_startup_audit(
    audit_emitter,
    *,
    tiers_completed: list[str],
) -> None:
    """Emit system.startup audit event after all startup tiers complete.

    Fire-and-forget: swallows non-cancellation exceptions so startup is never
    blocked by audit infrastructure failures.

    Cancellation policy (D33.design lifecycle-surface ownership): NOT shielded.
    Cancellation here means SIGTERM during startup — operator has withdrawn
    lifecycle ownership. CancelledError is logged and re-raised.
    """
    if audit_emitter is None:
        logger.warning(
            "No audit emitter available — system.startup event not emitted",
            extra={"event": "lifecycle.startup_audit_skipped"},
        )
        return
    try:
        event = SecurityAuditEvent(
            event_type="system.startup",
            source_component="lifecycle",
            outcome="SUCCESS",
            severity="INFO",
            details={
                "actor_type": "system",
                "tiers_completed": tiers_completed,
                "tier_count": len(tiers_completed),
            },
        )
        await audit_emitter.emit(event)
    except asyncio.CancelledError:
        logger.debug(
            "Startup audit emit cancelled — SIGTERM during startup",
            extra={"event": "lifecycle.startup_audit_cancelled"},
        )
        raise
    except Exception:
        logger.debug(
            "Startup audit event emission failed — continuing",
            exc_info=True,
            extra={"event": "lifecycle.startup_audit_failed"},
        )


@asynccontextmanager
async def _startup_tier(name: str, audit_logger):
    """Track startup tier timing and log begin/complete/failed with duration.

    Wraps each startup phase so operators can see which tier is running, how
    long each took, and — critically — which tier failed if startup aborts.
    """
    t0 = time.monotonic()
    audit_logger.info(
        "Startup tier begin: %s",
        name,
        extra={"event": "lifecycle.startup.tier_begin", "tier": name},
    )
    try:
        yield
    except Exception:
        # audit_logger.error below captures the full traceback — no need
        # for a separate logger.exception which would produce duplicate output
        logger.exception(
            "_startup_tier: Exception", extra={"event": "lifecycle._startup_tier_error"}
        )  # auto:except
        elapsed = time.monotonic() - t0
        audit_logger.error(
            "Startup tier FAILED: %s (after %.3fs)",
            name,
            elapsed,
            exc_info=True,
            extra={
                "event": "lifecycle.startup.tier_failed",
                "tier": name,
                "duration_s": round(elapsed, 3),
            },
        )
        raise
    else:
        elapsed = time.monotonic() - t0
        audit_logger.info(
            "Startup tier complete: %s (%.3fs)",
            name,
            elapsed,
            extra={
                "event": "lifecycle.startup.tier_complete",
                "tier": name,
                "duration_s": round(elapsed, 3),
            },
        )


def _set_security_globals(
    *,
    pipeline,
    engine,
    pin_verifier,
    prompt_guard_loaded: bool,
    semgrep_loaded: bool,
) -> None:
    """Set security-tier module globals and sync to app module."""
    logger.debug(
        "_set_security_globals called",
        extra={"event": "lifecycle._set_security_globals"},
    )  # auto:entry
    global _pin_verifier, _engine, _pipeline, _prompt_guard_loaded, _semgrep_loaded

    _pin_verifier = pin_verifier
    _engine = engine
    _pipeline = pipeline
    _prompt_guard_loaded = prompt_guard_loaded
    _semgrep_loaded = semgrep_loaded
    _sync_to_app_module(
        _pin_verifier=_pin_verifier,
        _engine=_engine,
        _pipeline=_pipeline,
        _prompt_guard_loaded=_prompt_guard_loaded,
        _semgrep_loaded=_semgrep_loaded,
    )


def _set_orchestrator_globals(
    *,
    sidecar,
    sandbox,
    planner_available: bool,
    ollama_reachable: bool,
) -> None:
    """Set orchestrator-tier module globals and sync to app module."""
    logger.debug(
        "_set_orchestrator_globals called",
        extra={"event": "lifecycle._set_orchestrator_globals"},
    )  # auto:entry
    global _sidecar, _sandbox, _planner_available, _ollama_reachable

    _sidecar = sidecar
    _sandbox = sandbox
    _planner_available = planner_available
    _ollama_reachable = ollama_reachable
    _sync_to_app_module(
        _ollama_reachable=_ollama_reachable,
        _sidecar=_sidecar,
        _sandbox=_sandbox,
        _planner_available=_planner_available,
    )


async def _run_channels_tier(
    *,
    app,
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
    prompt_guard_loaded: bool,
    semgrep_loaded: bool,
    ollama_reachable: bool,
    planner_available: bool,
    hybrid_search_fn,
    get_metrics_fn,
    classifier,
    fast_path_executor,
    loop_store,
    insight_store,
):
    """Run tier 4 (channels) with RLS context and set channel globals.

    Returns redirect_server for shutdown cleanup.
    """
    logger.debug(
        "_run_channels_tier called", extra={"event": "lifecycle._run_channels_tier"}
    )  # auto:entry
    global _channel_registry

    # RLS context for startup seeding (routines table INSERT requires valid user_id)
    from sentinel.core.context import current_user_id

    _startup_token = current_user_id.set(1)
    try:
        (
            channel_registry,
            redirect_server,
        ) = await init_channels(
            app,
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
            _track_task,
            background_tasks=_background_tasks,
            gather_component_status_fn=_gather_component_status,
            classifier=classifier,
            fast_path_executor=fast_path_executor,
            loop_store=loop_store,
            insight_store=insight_store,
        )
    finally:
        current_user_id.reset(_startup_token)

    _channel_registry = channel_registry
    _sync_to_app_module(
        _channel_registry=_channel_registry,
    )
    return redirect_server


def _wire_post_init(
    *,
    app,
    audit,
    orchestrator,
    pg_pool,
    admin_pool,
    audit_emitter,
    event_bus,
    episodic_store,
    domain_summary_store,
    strategy_store,
) -> None:
    """Tier 5: wire late-binding dependencies after all init tiers complete.

    Connects attachment ingester to channels and executor, wires memory stores
    into the orchestrator, initialises the reranker, and schedules background
    cleanup tasks. Must run in lifespan scope (lifecycle.py scoping gotcha).
    """
    # Media attachment store and ingester
    logger.debug(
        "_wire_post_init called", extra={"event": "lifecycle._wire_post_init"}
    )  # auto:entry
    from sentinel.media.ingestion import AttachmentIngester
    from sentinel.media.store import MediaStore

    media_store = MediaStore(pg_pool)
    app.state.media_store = media_store

    ingester = AttachmentIngester(
        workspace_root=settings.workspace_path,
        media_store=media_store,
        max_file_bytes=settings.attachment_max_file_bytes,
    )

    audit.debug(
        "media ingester initialised",
        extra={
            "event": "media.ingester_init",
            "max_file_bytes": settings.attachment_max_file_bytes,
            "attachment_enabled": settings.attachment_enabled,
        },
    )

    # Inject ingester into messaging channels (must be in lifespan,
    # not init_channels — lifecycle.py scoping gotcha)
    if settings.attachment_enabled and _channel_registry is not None:
        for channel in _channel_registry.enabled():
            channel._ingester = ingester
            audit.debug(
                "%s attachment ingester wired",
                channel.descriptor.name,
                extra={"event": f"{channel.descriptor.name}.ingester_wired"},
            )

    # Wire ingester into tool executor for email attachment ingestion
    if settings.attachment_enabled:
        _te = getattr(orchestrator, "_tool_executor", None)
        if _te is not None:
            _te.set_ingester(ingester)
            audit.debug(
                "executor attachment ingester wired",
                extra={"event": "executor.ingester_wired"},
            )

    # Wire late-binding dependencies into orchestrator atomically
    # (must be after init_channels where orchestrator is fully wired,
    # and in lifespan() where stores are in scope)
    from sentinel.memory.reranker import Reranker

    reranker = Reranker()
    orchestrator.wire_late_deps(
        episodic_store=episodic_store,
        domain_summary_store=domain_summary_store,
        strategy_store=strategy_store,
        reranker=reranker,
    )

    # Wire episodic store into executor so anchor maps persist to episodic memory
    _te = getattr(orchestrator, "_tool_executor", None)
    if _te is not None:
        _te.set_episodic_store(episodic_store)

    # Schedule periodic revocation cleanup (finding #11 — cleanup was never called)
    # Infrastructure task — bare create_task() is correct (no user context needed)
    _cleanup_task = asyncio.create_task(_periodic_revocation_cleanup())
    _background_tasks.add(_cleanup_task)
    _cleanup_task.add_done_callback(_background_tasks.discard)

    # Schedule periodic DB maintenance (Q5.fix.a / F7 — run_db_maintenance only
    # fired once at startup before this). The scheduler runs with admin scope:
    # we pass an explicit fresh contextvars.Context() to create_task so future
    # refactors that set current_user_id earlier in lifespan can't accidentally
    # bind the scheduler to a user. An empty Context leaves current_user_id at
    # its default (0), which AuditEmitter reads as admin.
    _maint_task = asyncio.create_task(
        _periodic_db_maintenance(admin_pool, audit_emitter, event_bus),
        context=contextvars.Context(),
        name="db_maintenance",
    )
    _background_tasks.add(_maint_task)
    _maint_task.add_done_callback(_background_tasks.discard)
    _maint_task.add_done_callback(_log_task_exception)


def _validate_critical_globals(audit) -> None:
    """Assert critical dependencies are non-None before yielding to FastAPI.

    A None here means a tier silently returned None instead of raising,
    which would cause cryptic AttributeError crashes at request time.
    """
    _CRITICAL_GLOBALS = {
        "_engine": _engine,
        "_pipeline": _pipeline,
        "_pin_verifier": _pin_verifier,
        "_sidecar": _sidecar,
        "_sandbox": _sandbox,
    }
    _missing = [name for name, val in _CRITICAL_GLOBALS.items() if val is None]
    if _missing:
        base_msg = f"Critical globals still None after startup: {', '.join(_missing)}"
        # Audit payload contract is unchanged (event + missing_globals only) —
        # the operator-visible message is enriched separately so structured
        # log consumers don't see a shape change.
        audit.error(
            base_msg,
            extra={
                "event": "lifecycle.startup.validation_failed",
                "missing_globals": _missing,
            },
        )
        hints = [
            _GLOBAL_REMEDIATION_HINTS[name]
            for name in _missing
            if name in _GLOBAL_REMEDIATION_HINTS
        ]
        msg = "\n\n".join([base_msg, *hints]) if hints else base_msg
        raise RuntimeError(msg)
    audit.info(
        "Startup validation passed — all critical globals set",
        extra={"event": "lifecycle.startup.validation_passed"},
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _shutting_down

    # Declare before try so they're visible in finally for cleanup
    audit = None
    redirect_server = None
    try:
        audit = setup_audit_logger(
            log_dir=settings.log_dir,
            log_level=settings.log_level,
        )
        app.state.audit = audit
        app.state.shutting_down = False
        app.state.ws_failure_tracker = websocket_routes._ws_failure_tracker
        audit.info("Starting sentinel-controller", extra={"event": "lifecycle.startup"})

        # ── Tier 1: Database ──
        async with _startup_tier("database", audit):
            # Q5-F6: ``event_bus`` now comes back from init_database (hoisted
            # up from Tier 3) — required for SessionStore construction.
            (
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
            ) = await init_database(app, settings, audit)

            # Bootstrap owner on first run — no-op if users already exist
            await bootstrap_owner(admin_pool)

        # ── Tier 2: Security ──
        async with _startup_tier("security", audit):
            (
                pipeline,
                engine,
                pin_verifier,
                prompt_guard_loaded,
                semgrep_loaded,
            ) = await init_security(app, settings, audit)
            _set_security_globals(
                pipeline=pipeline,
                engine=engine,
                pin_verifier=pin_verifier,
                prompt_guard_loaded=prompt_guard_loaded,
                semgrep_loaded=semgrep_loaded,
            )

        # ── Tier 3: Orchestrator ──
        async with _startup_tier("orchestrator", audit):
            # Q5-F6: event_bus is now owned by Tier 1 (see init_database).
            # init_orchestrator still echoes it back for backward-compat with
            # the tuple shape; we accept the echo and keep using the Tier 1
            # instance (they're the same object).
            (
                orchestrator,
                message_router,
                _event_bus_echo,
                sidecar,
                sandbox,
                embedding_client,
                planner_available,
                ollama_reachable,
                mcp_server,
                classifier,
                fast_path_executor,
            ) = await init_orchestrator(
                app,
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
                _track_task,
                event_bus=event_bus,
                insight_store=insight_store,
                loop_store=loop_store,
            )
            _set_orchestrator_globals(
                sidecar=sidecar,
                sandbox=sandbox,
                planner_available=planner_available,
                ollama_reachable=ollama_reachable,
            )

        # ── Tier 4: Channels ──
        async with _startup_tier("channels", audit):
            redirect_server = await _run_channels_tier(
                app=app,
                audit=audit,
                orchestrator=orchestrator,
                message_router=message_router,
                event_bus=event_bus,
                pipeline=pipeline,
                engine=engine,
                pin_verifier=pin_verifier,
                pg_pool=pg_pool,
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
                classifier=classifier,
                fast_path_executor=fast_path_executor,
                loop_store=loop_store,
                insight_store=insight_store,
            )

        # ── Tier 5: Post-init wiring (must be in lifespan scope — lifecycle.py scoping gotcha) ──
        async with _startup_tier("post_init_wiring", audit):
            _wire_post_init(
                app=app,
                audit=audit,
                orchestrator=orchestrator,
                pg_pool=pg_pool,
                admin_pool=admin_pool,
                audit_emitter=getattr(app.state, "audit_emitter", None),
                event_bus=event_bus,
                episodic_store=episodic_store,
                domain_summary_store=domain_summary_store,
                strategy_store=strategy_store,
            )

        # Lock orchestrator configuration — no set_*() calls after this point
        orchestrator.freeze()

        # Q13.fix.e — deprecation warning for legacy webhook signature
        # acceptance. Operators who leave webhook_legacy_signature_enabled
        # True past the sunset release get a LOUD, audit-routed warning on
        # every boot; the webhook.signature.legacy_accepted INFO event is
        # the per-request observability lever.
        if settings.webhook_legacy_signature_enabled:
            audit.warning(
                "Legacy webhook signature acceptance enabled (sha256= body-only HMAC)",
                extra={
                    "event": "webhook.legacy_signature_deprecated",
                    "flag": "webhook_legacy_signature_enabled",
                },
            )

        audit.info(
            "All startup tiers complete",
            extra={"event": "lifecycle.startup.all_complete"},
        )

        _validate_critical_globals(audit)

        # Emit structured audit event for startup completion
        await _emit_startup_audit(
            getattr(app.state, "audit_emitter", None),
            tiers_completed=[
                "database",
                "security",
                "orchestrator",
                "channels",
                "post_init_wiring",
            ],
        )

        yield  # App runs here

    except Exception:
        # Per-tier failure already logged by _startup_tier — this catches
        # the re-raise and ensures the exception propagates to FastAPI
        logger.exception(
            "Fatal startup error — see tier_failed log above for details",
            extra={"event": "lifecycle.startup.fatal"},
        )
        raise
    finally:
        logger.info(
            "Lifespan exiting — beginning shutdown",
            extra={"event": "lifecycle.shutdown.start"},
        )
        _shutting_down = True
        await shutdown(
            app,
            audit,
            _background_tasks,
            _sync_to_app_module,
            redirect_server=redirect_server,
        )
