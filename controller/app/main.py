from contextlib import asynccontextmanager

from fastapi import FastAPI, Query

from .audit import setup_audit_logger
from .config import settings
from .models import PolicyResult, ValidationResult
from .policy_engine import PolicyEngine
from .scanner import CredentialScanner, SensitivePathScanner

# Module-level references populated at startup
_engine: PolicyEngine | None = None
_cred_scanner: CredentialScanner | None = None
_path_scanner: SensitivePathScanner | None = None
_audit = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _cred_scanner, _path_scanner, _audit

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

    yield

    _audit.info("Shutting down sentinel-controller", extra={"event": "shutdown"})


app = FastAPI(title="Sentinel Controller", lifespan=lifespan)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
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
