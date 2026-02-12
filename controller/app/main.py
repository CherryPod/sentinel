import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from pydantic import BaseModel

from .audit import setup_audit_logger
from .config import settings
from .models import PolicyResult, ValidationResult
from .pipeline import ScanPipeline, SecurityViolation
from .policy_engine import PolicyEngine
from . import prompt_guard
from .scanner import CredentialScanner, SensitivePathScanner

# Module-level references populated at startup
_engine: PolicyEngine | None = None
_cred_scanner: CredentialScanner | None = None
_path_scanner: SensitivePathScanner | None = None
_pipeline: ScanPipeline | None = None
_prompt_guard_loaded: bool = False
_audit = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _cred_scanner, _path_scanner, _pipeline
    global _prompt_guard_loaded, _audit

    _audit = setup_audit_logger(
        log_dir=settings.log_dir,
        log_level=settings.log_level,
    )
    _audit.info("Starting sentinel-controller", extra={"event": "startup"})

    policy_path = settings.policy_file
    _engine = PolicyEngine(policy_path)
    _audit.info(
        "Policy loaded",
        extra={"event": "policy_loaded", "path": policy_path},
    )

    _cred_scanner = CredentialScanner(_engine.policy.get("credential_patterns", []))
    _path_scanner = SensitivePathScanner(_engine.policy.get("sensitive_path_patterns", []))

    # Initialize Prompt Guard (Phase 2)
    if settings.prompt_guard_enabled:
        t0 = time.monotonic()
        _prompt_guard_loaded = prompt_guard.initialize(settings.prompt_guard_model)
        elapsed = time.monotonic() - t0
        _audit.info(
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
    )

    yield

    _audit.info("Shutting down sentinel-controller", extra={"event": "shutdown"})


app = FastAPI(title="Sentinel Controller", lifespan=lifespan)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
        "prompt_guard_loaded": _prompt_guard_loaded,
    }


@app.get("/validate/path")
async def validate_path(
    path: str = Query(..., description="File path to validate"),
    operation: str = Query("read", description="'read' or 'write'"),
) -> ValidationResult:
    if _engine is None:
        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=path,
            reason="Policy engine not loaded",
        )

    if operation == "write":
        result = _engine.check_file_write(path)
    else:
        result = _engine.check_file_read(path)

    if _audit:
        _audit.info(
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


@app.get("/validate/command")
async def validate_command(
    command: str = Query(..., description="Shell command to validate"),
) -> ValidationResult:
    if _engine is None:
        return ValidationResult(
            status=PolicyResult.BLOCKED,
            path=command,
            reason="Policy engine not loaded",
        )

    result = _engine.check_command(command)

    if _audit:
        _audit.info(
            "Command validation",
            extra={
                "event": "validate_command",
                "command": command,
                "result": result.status.value,
                "reason": result.reason,
            },
        )
    return result


# ── Phase 2 endpoints ────────────────────────────────────────────


class ScanRequest(BaseModel):
    text: str


class ProcessRequest(BaseModel):
    text: str
    untrusted_data: str | None = None


@app.post("/scan")
async def scan_text(req: ScanRequest):
    """Run full scan pipeline on text (Prompt Guard + credential + path)."""
    if _pipeline is None:
        return {"error": "Pipeline not initialized"}

    result = _pipeline.scan_output(req.text)
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


@app.post("/process")
async def process_text(req: ProcessRequest):
    """Send text through the full Qwen pipeline (scan → spotlight → Qwen → scan)."""
    if _pipeline is None:
        return {"error": "Pipeline not initialized"}

    try:
        tagged = await _pipeline.process_with_qwen(
            prompt=req.text,
            untrusted_data=req.untrusted_data,
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
    except SecurityViolation as exc:
        return {
            "status": "blocked",
            "reason": str(exc),
            "violations": {
                name: {
                    "found": sr.found,
                    "matches": [m.model_dump() for m in sr.matches],
                }
                for name, sr in exc.scan_results.items()
            },
        }
