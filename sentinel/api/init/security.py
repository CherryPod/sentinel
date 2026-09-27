"""Security initialization: PIN auth, policy engine, scanners, scan pipeline.

Sets up the authentication layer, policy engine, and the ``ScanPipeline``
(which wraps all six ``ScannerPlugin`` scanners wired through the
preprocessor + suppression engine via ``_pipeline_factory``).

Phase 9b-ii: production pipeline construction switched from direct
legacy scanner instantiation to ``build_pipeline(settings, audit_emitter)``.
The ML/external scanner initialisers (``prompt_guard.initialize()`` and
``semgrep_scanner.initialize()``) are still called here because they
populate module state that the ``PromptGuardScanner`` / ``SemgrepScanner``
plugins consult via ``is_loaded()`` at scan time.  Skipping them would
leave both scanners in their fail-closed degraded mode at all times.
"""

import asyncio
import logging
import time

from fastapi import FastAPI

from sentinel.api.auth import PinVerifier
from sentinel.security import prompt_guard, semgrep_scanner
from sentinel.security._pipeline_factory import build_pipeline
from sentinel.security.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)


async def init_security(app: FastAPI, settings, audit) -> tuple:
    """Initialize PIN auth, policy engine, scanners, and scan pipeline.

    Returns (pipeline, engine, pin_verifier, prompt_guard_loaded, semgrep_loaded).
    Does NOT set module-level globals — the caller (lifespan) does that.
    """
    logger.debug(
        "Initializing security layer",
        extra={"event": "init.security_start"},
    )

    # Load PIN for authentication — hash immediately, never store plaintext (H-002)
    pin_verifier = None
    if settings.pin_required:
        try:
            logger.debug(
                "Reading PIN file",
                extra={"event": "pin.file_read", "pin_path": settings.pin_file},
            )

            def _read_pin() -> str:
                with open(settings.pin_file) as f:
                    return f.read().strip()

            raw_pin = await asyncio.to_thread(_read_pin)
            pin_verifier = PinVerifier(raw_pin)
            app.state.pin_verifier = pin_verifier
            del raw_pin  # Clear plaintext from local scope
            audit.info("PIN auth enabled (hashed)", extra={"event": "pin.loaded"})
        except FileNotFoundError:
            logger.exception(
                "init_security: FileNotFoundError",
                extra={"event": "security.init_security_error"},
            )
            app.state.pin_verifier = None
            audit.warning(
                "PIN file not found, auth disabled",
                extra={"event": "pin.missing", "path": settings.pin_file},
                exc_info=True,
            )
    else:
        logger.debug("init_security: clean", extra={"event": "pin.file_read.clean"})
        app.state.pin_verifier = None
        audit.info("PIN auth disabled by config", extra={"event": "pin.disabled"})

    policy_path = settings.policy_file
    engine = PolicyEngine(
        policy_path,
        workspace_path=settings.workspace_path,
        trust_level=settings.trust_level,
    )
    audit.info(
        "Policy loaded",
        extra={"event": "policy.loaded", "path": policy_path},
    )
    app.state.engine = engine

    # Initialize Prompt Guard: loads the ML model into module state that
    # ``PromptGuardScanner.is_loaded()`` consults at scan time.  The
    # pipeline registers PromptGuard via the factory when
    # ``settings.prompt_guard_enabled`` is True; this call controls
    # whether it produces real verdicts vs fail-closed synthetic matches.
    prompt_guard_loaded = False
    if settings.prompt_guard_enabled:
        logger.debug(
            "init_security: match",
            extra={"event": "security.init_security.match"},
        )
        t0 = time.monotonic()
        prompt_guard_loaded = prompt_guard.initialize(settings.prompt_guard_model)
        app.state.prompt_guard_loaded = prompt_guard_loaded
        elapsed = time.monotonic() - t0
        audit.info(
            "Prompt Guard init",
            extra={
                "event": "prompt.guard_init",
                "loaded": prompt_guard_loaded,
                "elapsed_s": round(elapsed, 2),
            },
        )

    # Build the full scan pipeline from YAML rules + suppression config
    # + new ScannerPlugin instances.  The factory is pure — no app.state
    # side effects, no network I/O beyond reading rule files.
    pipeline = build_pipeline(
        settings,
        audit_emitter=getattr(app.state, "audit_emitter", None),
    )
    app.state.pipeline = pipeline

    # Initialize Semgrep scanner: populates module state consulted by
    # ``SemgrepScanner.is_loaded()`` at scan time.  Same rationale as
    # PromptGuard above — scanner is always registered, this controls
    # real-verdict vs fail-closed behaviour.
    t0 = time.monotonic()
    semgrep_loaded = semgrep_scanner.initialize()
    app.state.semgrep_loaded = semgrep_loaded
    elapsed = time.monotonic() - t0
    audit.info(
        "Semgrep init",
        extra={
            "event": "semgrep.init",
            "loaded": semgrep_loaded,
            "elapsed_s": round(elapsed, 2),
        },
    )

    logger.debug(
        "Security initialization complete",
        extra={
            "event": "init.security_done",
            "pin_enabled": pin_verifier is not None,
            "prompt_guard": prompt_guard_loaded,
            "semgrep": semgrep_loaded,
        },
    )

    return pipeline, engine, pin_verifier, prompt_guard_loaded, semgrep_loaded
