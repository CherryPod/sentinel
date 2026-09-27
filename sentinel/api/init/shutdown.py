"""Shutdown sequence: ordered 11-step teardown of all application components.

Order is critical — see inline comments for rationale at each step.
Components are read from app.state (canonical source) with getattr fallback
for components that may not have been initialized.
"""

import asyncio
import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)

# Budget for draining tracked background tasks before cancellation
_DRAIN_TIMEOUT_S = 30
# Grace period for cancelled tasks to handle CancelledError
_CANCEL_GRACE_S = 5


async def _shutdown_services(app: FastAPI, audit) -> None:
    """Steps 2-4: notify subscribers, stop orchestrator and routine engine."""
    # 2. Notify subscribers (channels, routines) so they can flush state
    event_bus = getattr(app.state, "event_bus", None)
    if event_bus is not None:
        try:
            await event_bus.publish("system.shutdown", {"reason": "process_exit"})
        except Exception as exc:
            logger.exception(
                "shutdown: Exception",
                extra={"event": "shutdown.event_bus_error"},
            )
            audit.warning(
                "Failed to publish shutdown event: %s",
                exc,
                extra={"event": "shutdown.event_failed", "error": str(exc)},
                exc_info=True,
            )

    # 3. Signal the orchestrator to stop accepting new plan steps
    orchestrator = getattr(app.state, "orchestrator", None)
    if orchestrator is not None:
        logger.debug(
            "Stopping orchestrator", extra={"event": "shutdown.orchestrator_stop"}
        )
        await orchestrator.shutdown()

    # 4. SYS-5b: Stop routine engine before drain (routines create tasks)
    routine_engine = getattr(app.state, "routine_engine", None)
    if routine_engine is not None:
        logger.debug(
            "Stopping routine engine", extra={"event": "shutdown.routine_engine_stop"}
        )
        await routine_engine.stop()


async def _drain_background_tasks(background_tasks: set, audit) -> None:
    """Steps 5-6: drain tracked background tasks, cancel stragglers."""
    if not background_tasks:
        return

    audit.info(
        "Draining %d background tasks (timeout=%ds)",
        len(background_tasks),
        _DRAIN_TIMEOUT_S,
        extra={
            "event": "shutdown.drain_start",
            "task_count": len(background_tasks),
            "task_names": [t.get_name() for t in background_tasks],
        },
    )
    done, pending = await asyncio.wait(
        background_tasks,
        timeout=_DRAIN_TIMEOUT_S,
    )
    # Log each completed task's outcome individually
    for task in done:
        name = task.get_name()
        if task.cancelled():
            logger.debug(
                "_drain_background_tasks: match",
                extra={"event": "shutdown._drain_background_tasks.match"},
            )
            audit.debug(
                "Task %s: cancelled during drain",
                name,
                extra={"event": "shutdown.task.cancelled", "task_name": name},
            )
        elif task.exception():
            logger.debug(
                "_drain_background_tasks: clean",
                extra={"event": "shutdown._drain_background_tasks.clean"},
            )
            audit.warning(
                "Task %s: failed with %s",
                name,
                type(task.exception()).__name__,
                exc_info=task.exception(),
                extra={
                    "event": "shutdown.task.failed",
                    "task_name": name,
                    "error": str(task.exception()),
                },
            )
        else:
            logger.debug(
                "_drain_background_tasks: clean",
                extra={"event": "shutdown._drain_background_tasks.clean"},
            )
            audit.debug(
                "Task %s: completed cleanly",
                name,
                extra={"event": "shutdown.task.done", "task_name": name},
            )
    # 6. Cancel stragglers (grace period)
    if pending:
        logger.debug(
            "_drain_background_tasks: match",
            extra={"event": "shutdown._drain_background_tasks.match"},
        )
        audit.warning(
            "Cancelling %d tasks that did not finish in time",
            len(pending),
            extra={
                "event": "shutdown.cancel",
                "cancelled_names": [t.get_name() for t in pending],
            },
        )
        for task in pending:
            task.cancel()
            audit.debug(
                "Cancelling straggler: %s",
                task.get_name(),
                extra={
                    "event": "shutdown.task.cancel_sent",
                    "task_name": task.get_name(),
                },
            )
        # Give cancelled tasks a moment to handle CancelledError
        await asyncio.wait(pending, timeout=_CANCEL_GRACE_S)
    audit.info(
        "Background task drain complete: %d drained, %d cancelled",
        len(done),
        len(pending),
        extra={
            "event": "shutdown.drain_done",
            "drained": len(done),
            "cancelled": len(pending),
        },
    )


async def _shutdown_channels_and_sidecar(app: FastAPI, audit, redirect_server) -> None:
    """Steps 7-9: stop channels, sidecar, redirect server."""
    # 7. Shutdown messaging channels via registry
    channel_registry = getattr(app.state, "channel_registry", None)
    if channel_registry is not None:
        for channel in channel_registry.enabled():
            name = channel.descriptor.name
            logger.debug(
                "Stopping %s channel",
                name,
                extra={"event": f"shutdown.{name}_stop"},
            )
            try:
                await channel.stop()
                audit.debug(
                    "%s channel stopped",
                    name,
                    extra={"event": f"shutdown.{name}.stopped"},
                )
            except Exception:  # catch-all: graceful shutdown — must not abort
                logger.warning(
                    "Failed to stop %s channel",
                    name,
                    extra={"event": f"shutdown.{name}_stop_error"},
                    exc_info=True,
                )

    # 8. Shutdown WASM sidecar if running
    sidecar = getattr(app.state, "sidecar", None)
    if sidecar is not None:
        logger.debug("Stopping WASM sidecar", extra={"event": "shutdown.sidecar_stop"})
        await sidecar.stop_sidecar()
        audit.debug("WASM sidecar stopped", extra={"event": "shutdown.sidecar.stopped"})

    # 9. Shutdown redirect server if running
    if redirect_server is not None:
        redirect_server.should_exit = True
        audit.debug(
            "Redirect server signalled to exit",
            extra={"event": "shutdown.redirect.stopped"},
        )


async def _shutdown_sandbox_and_stores(app: FastAPI, audit) -> None:
    """Steps 10-11: clean sandbox containers, flush stores, close DB pools."""
    # 10. SYS-5b: Cleanup orphaned sandbox containers (after drain — tasks may use containers)
    sandbox = getattr(app.state, "sandbox", None)
    if sandbox is not None:
        try:
            cleaned = await sandbox.cleanup_stale()
            if cleaned:
                audit.info(
                    "Shutdown sandbox cleanup: removed %d containers",
                    cleaned,
                    extra={"event": "shutdown.sandbox_cleanup", "removed": cleaned},
                )
        except Exception as exc:
            logger.exception(
                "shutdown: Exception",
                extra={"event": "shutdown.sandbox_cleanup_error"},
            )
            audit.warning(
                "Shutdown sandbox cleanup failed: %s",
                exc,
                extra={"event": "shutdown.sandbox_cleanup_failed", "error": str(exc)},
                exc_info=True,
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
                logger.exception(
                    "shutdown: Exception",
                    extra={"event": "shutdown.store_close_error"},
                )
                audit.warning(
                    "Store %s close failed: %s",
                    store_name,
                    exc,
                    extra={
                        "event": "shutdown.store_close_failed",
                        "store": store_name,
                        "error": str(exc),
                    },
                    exc_info=True,
                )

    # Close PostgreSQL pools
    if getattr(app.state, "admin_pool", None) is not None:
        await app.state.admin_pool.close()
        audit.info("Admin pool closed", extra={"event": "admin.pool_close"})
    if getattr(app.state, "pg_pool", None) is not None:
        await app.state.pg_pool.close()
        audit.info("PostgreSQL pool closed", extra={"event": "pg.pool_close"})


async def shutdown(
    app: FastAPI,
    audit,
    background_tasks: set,
    sync_to_app_module_fn,
    redirect_server=None,
):
    """Execute the 11-step shutdown sequence.

    Args:
        app: FastAPI application instance
        audit: Audit logger (may be None on partial startup failure)
        background_tasks: Set of tracked background asyncio.Task objects
        sync_to_app_module_fn: Callback to sync globals to sentinel.api.app
        redirect_server: HTTP→HTTPS redirect server (or None)
    """
    # Guard against audit=None (partial startup failure) — fall back to logger
    if audit is None:
        logger.warning(
            "Audit logger unavailable — using fallback",
            extra={"event": "shutdown.audit_fallback"},
        )
        audit = logger

    logger.debug(
        "Starting shutdown sequence",
        extra={"event": "shutdown.sequence_start", "task_count": len(background_tasks)},
    )

    # 1. Set shutdown flag — reject new requests immediately
    app.state.shutting_down = True
    sync_to_app_module_fn(_shutting_down=True)
    audit.info(
        "Shutdown initiated — rejecting new requests", extra={"event": "shutdown.start"}
    )

    # 2-4. Stop services (event bus, orchestrator, routine engine)
    await _shutdown_services(app, audit)

    # 5-6. Drain and cancel background tasks
    await _drain_background_tasks(background_tasks, audit)

    # 7-9. Stop channels, sidecar, redirect server
    await _shutdown_channels_and_sidecar(app, audit, redirect_server)

    # 10-11. Clean sandbox, flush stores, close DB pools
    await _shutdown_sandbox_and_stores(app, audit)

    audit.info(
        "Shutting down sentinel-controller", extra={"event": "lifecycle.shutdown"}
    )

    logger.debug(
        "Shutdown sequence complete",
        extra={"event": "shutdown.sequence_done"},
    )
