"""Security validation and scanning route handlers.

Extracted from app.py as part of the route-module refactor.
Follows the init() globals pattern documented in routes/__init__.py.

Endpoints:
  GET  /api/validate/path    — path validation via policy engine
  GET  /api/validate/command  — command validation via policy engine
  POST /api/scan              — text scanning via pipeline
  POST /api/process           — text processing via pipeline (Qwen round-trip)

Compatibility note: the safety-net tests (test_refactor_app_safety_net.py) patch
app_module._pipeline and app_module._shutting_down directly.  To keep those tests
green without modification, the route handlers read from the init()-injected
globals first, then fall back to the app module globals.  Once the
implementation-coupled tests are migrated (Phase 4+), the fallback can be removed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from sentinel.api.models import ProcessRequest, ScanRequest
from sentinel.api.rate_limit import limiter
from sentinel.core.config import settings
from sentinel.core.models import PolicyResult, ValidationResult
from sentinel.security.pipeline import SecurityViolation

logger = logging.getLogger("sentinel.api")

# ── Router ──────────────────────────────────────────────────────────

router = APIRouter()


# ── Module globals (init pattern) ──────────────────────────────────

_engine: Any = None
_pipeline: Any = None
_audit: Any = None


def init(
    *,
    engine: Any = None,
    pipeline: Any = None,
    audit: Any = None,
    **_kwargs: Any,
) -> None:
    """Inject dependencies — called once from app.py lifespan."""
    global _engine, _pipeline, _audit
    _engine = engine
    _pipeline = pipeline
    _audit = audit


# ── Accessors (with app-module fallback for safety-net compat) ────

def _resolve_engine():
    """Return the policy engine from init() globals or app module fallback."""
    if _engine is not None:
        return _engine
    # Fallback: safety-net tests patch app_module._engine directly
    import sentinel.api.app as _app
    return _app._engine


def _resolve_pipeline():
    """Return the scan pipeline from init() globals or app module fallback."""
    if _pipeline is not None:
        return _pipeline
    import sentinel.api.app as _app
    return _app._pipeline


def _resolve_audit():
    """Return the audit logger from init() globals or app module fallback."""
    if _audit is not None:
        return _audit
    import sentinel.api.app as _app
    return getattr(_app, "_audit", None)


def _resolve_shutting_down(request: Request) -> bool:
    """Check shutdown flag from app.state, then app module fallback."""
    # Prefer app.state (set by lifespan dual-write)
    state_val = getattr(request.app.state, "shutting_down", None)
    if state_val is not None:
        return state_val
    # Fallback: safety-net tests set app_module._shutting_down directly
    import sentinel.api.app as _app
    return _app._shutting_down


# ── Validate endpoints ─────────────────────────────────────────────

@router.get("/validate/path")
async def validate_path(
    path: str = Query(..., max_length=4096, description="File path to validate"),
    operation: str = Query("read", max_length=16, description="'read' or 'write'"),
) -> ValidationResult:
    engine = _resolve_engine()
    if engine is None:
        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=path,
            reason="Policy engine not loaded",
        )

    if operation == "write":
        result = engine.check_file_write(path)
    else:
        result = engine.check_file_read(path)

    audit = _resolve_audit()
    if audit:
        audit.info(
            "Path validation",
            extra={
                "event": "validate_path",
                "path": path,
                "operation": operation,
                "result": result.status.value,
                "reason": result.reason,
            },
        )
    return result


@router.get("/validate/command")
async def validate_command(
    command: str = Query(..., max_length=4096, description="Shell command to validate"),
) -> ValidationResult:
    engine = _resolve_engine()
    if engine is None:
        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=command,
            reason="Policy engine not loaded",
        )

    result = engine.check_command(command)

    audit = _resolve_audit()
    if audit:
        audit.info(
            "Command validation",
            extra={
                "event": "validate_command",
                "command": command,
                "result": result.status.value,
                "reason": result.reason,
            },
        )
    return result


# ── Scan / Process endpoints ───────────────────────────────────────

@router.post("/scan")
@limiter.limit("10/minute")
async def scan_text(request: Request, req: ScanRequest):
    """Run full scan pipeline on text (Prompt Guard + credential + path)."""
    pipeline = _resolve_pipeline()
    if pipeline is None:
        return {"error": "Pipeline not initialized"}

    result = await pipeline.scan_output(req.text)
    return {
        "clean": result.is_clean,
        "results": {
            name: {
                "found": sr.found,
                "matches": [m.model_dump() for m in sr.matches],
            }
            for name, sr in result.results.items()
        },
    }


@router.post("/process")
@limiter.limit("5/minute")
async def process_text(request: Request, req: ProcessRequest):
    """Send text through the full Qwen pipeline (scan → spotlight → Qwen → scan)."""
    if _resolve_shutting_down(request):
        return JSONResponse(
            status_code=503,
            content={"status": "error", "reason": "Server is shutting down"},
        )

    pipeline = _resolve_pipeline()
    if pipeline is None:
        return {"error": "Pipeline not initialized"}

    audit = _resolve_audit()

    try:
        tagged = await asyncio.wait_for(
            pipeline.process_with_qwen(
                prompt=req.text,
                untrusted_data=req.untrusted_data,
            ),
            timeout=settings.worker_timeout,
        )
        return {
            "status": "ok",
            "data_id": tagged.id,
            "content": tagged.content,
            "trust_level": tagged.trust_level.value,
            "scan_results": {
                name: {
                    "found": sr.found,
                    "matches": [m.model_dump() for m in sr.matches],
                }
                for name, sr in tagged.scan_results.items()
            },
        }
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=504,
            content={
                "status": "error",
                "reason": f"Processing timed out after {settings.worker_timeout}s",
            },
        )
    except SecurityViolation as exc:
        # Log full details server-side for forensic analysis
        if audit:
            audit.warning("Security violation on /process: %s", exc)
        else:
            logger.warning("Security violation on /process (audit unavailable): %s", exc)
        return {
            "status": "blocked",
            "reason": "Request blocked by security policy",
        }
