import re
import time
import unicodedata
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .approval import ApprovalManager
from .auth import PinAuthMiddleware
from .audit import setup_audit_logger
from .config import settings
from .conversation import ConversationAnalyzer
from .models import PolicyResult, ValidationResult
from .orchestrator import Orchestrator
from .pipeline import ScanPipeline, SecurityViolation
from .planner import ClaudePlanner, PlannerError
from .policy_engine import PolicyEngine
from . import codeshield, prompt_guard
from .scanner import CommandPatternScanner, CredentialScanner, SensitivePathScanner
from .session import SessionStore
from .tools import ToolExecutor


class CSRFMiddleware(BaseHTTPMiddleware):
    """Validate Origin header on state-changing requests to prevent CSRF."""

    def __init__(self, app, allowed_origins: list[str]):
        super().__init__(app)
        self._allowed = set(o.rstrip("/").lower() for o in allowed_origins)

    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin", "")
            if origin:
                normalised = origin.rstrip("/").lower()
                if normalised not in self._allowed:
                    return JSONResponse(
                        status_code=403,
                        content={"status": "error", "reason": "CSRF: invalid origin"},
                    )
        return await call_next(request)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with Content-Length exceeding the configured limit."""

    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={"status": "error", "reason": "Request too large"},
            )
        return await call_next(request)

# Rate limiter — per-IP, in-memory storage
limiter = Limiter(key_func=get_remote_address)

# Module-level references populated at startup
_pin: str | None = None
_engine: PolicyEngine | None = None
_cred_scanner: CredentialScanner | None = None
_path_scanner: SensitivePathScanner | None = None
_cmd_scanner: CommandPatternScanner | None = None
_pipeline: ScanPipeline | None = None
_orchestrator: Orchestrator | None = None
_session_store: SessionStore | None = None
_prompt_guard_loaded: bool = False
_codeshield_loaded: bool = False
_planner_available: bool = False
_audit = None

# ── Input validation constants ────────────────────────────────────
MAX_TEXT_LENGTH = 50_000
MIN_TASK_REQUEST_LENGTH = 3
MAX_REASON_LENGTH = 1_000
_CONSECUTIVE_NEWLINES = re.compile(r"\n{3,}")


def _normalize_text(v: str, *, min_length: int = 1, max_length: int = MAX_TEXT_LENGTH, field_name: str = "Text") -> str:
    """Shared validation: strip, NFC normalize, collapse newlines, enforce length."""
    v = v.strip()
    v = unicodedata.normalize("NFC", v)
    v = _CONSECUTIVE_NEWLINES.sub("\n\n", v)
    if not v:
        raise ValueError(f"{field_name} must not be empty")
    if len(v) < min_length:
        raise ValueError(f"{field_name} too short (minimum {min_length} characters)")
    if len(v) > max_length:
        raise ValueError(f"{field_name} too long (maximum {max_length:,} characters)")
    return v


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pin, _engine, _cred_scanner, _path_scanner, _cmd_scanner, _pipeline
    global _prompt_guard_loaded, _codeshield_loaded, _session_store, _audit

    _audit = setup_audit_logger(
        log_dir=settings.log_dir,
        log_level=settings.log_level,
    )
    _audit.info("Starting sentinel-controller", extra={"event": "startup"})

    # Load PIN for authentication
    if settings.pin_required:
        try:
            with open(settings.pin_file) as f:
                _pin = f.read().strip()
            _audit.info("PIN auth enabled", extra={"event": "pin_loaded"})
        except FileNotFoundError:
            _pin = None
            _audit.warning(
                "PIN file not found, auth disabled",
                extra={"event": "pin_missing", "path": settings.pin_file},
            )
    else:
        _pin = None
        _audit.info("PIN auth disabled by config", extra={"event": "pin_disabled"})

    policy_path = settings.policy_file
    _engine = PolicyEngine(policy_path, workspace_path=settings.workspace_path)
    _audit.info(
        "Policy loaded",
        extra={"event": "policy_loaded", "path": policy_path},
    )

    _cred_scanner = CredentialScanner(_engine.policy.get("credential_patterns", []))
    _path_scanner = SensitivePathScanner(_engine.policy.get("sensitive_path_patterns", []))
    _cmd_scanner = CommandPatternScanner()

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
        cmd_scanner=_cmd_scanner,
    )

    # Initialize CodeShield (Phase 5)
    t0 = time.monotonic()
    _codeshield_loaded = codeshield.initialize()
    elapsed = time.monotonic() - t0
    _audit.info(
        "CodeShield init",
        extra={
            "event": "codeshield_init",
            "loaded": _codeshield_loaded,
            "elapsed_s": round(elapsed, 2),
        },
    )

    # Initialize session store + conversation analyzer (Phase 5)
    global _session_store
    _session_store = SessionStore()
    conversation_analyzer = ConversationAnalyzer()
    _audit.info(
        "Conversation tracking initialized",
        extra={
            "event": "conversation_init",
            "enabled": settings.conversation_enabled,
            "session_ttl": settings.session_ttl,
        },
    )

    # Initialize Claude planner + orchestrator (Phase 3)
    global _orchestrator, _planner_available
    try:
        planner = ClaudePlanner()
        approval_mgr = ApprovalManager()
        tool_executor = ToolExecutor(policy_engine=_engine)
        _orchestrator = Orchestrator(
            planner=planner,
            pipeline=_pipeline,
            tool_executor=tool_executor,
            approval_manager=approval_mgr,
            session_store=_session_store,
            conversation_analyzer=conversation_analyzer,
        )
        _planner_available = True
        _audit.info(
            "Claude planner initialized",
            extra={"event": "planner_init", "model": settings.claude_model},
        )
    except PlannerError as exc:
        _audit.warning(
            "Claude planner not available: %s",
            exc,
            extra={"event": "planner_init_failed", "error": str(exc)},
        )
        _planner_available = False

    yield

    _audit.info("Shutting down sentinel-controller", extra={"event": "shutdown"})


app = FastAPI(title="Sentinel Controller", lifespan=lifespan)
app.state.limiter = limiter

# Middleware stack (outermost first): size limit → CSRF → PIN auth
app.add_middleware(PinAuthMiddleware, pin_getter=lambda: _pin)
app.add_middleware(
    CSRFMiddleware,
    allowed_origins=[o.strip() for o in settings.allowed_origins.split(",") if o.strip()],
)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Return JSON 429 when rate limit is exceeded."""
    if _audit:
        _audit.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate_limit_exceeded",
                "path": str(request.url.path),
                "remote": request.client.host if request.client else "unknown",
            },
        )
    return JSONResponse(
        status_code=429,
        content={
            "status": "error",
            "reason": "Rate limit exceeded — try again later",
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensure all errors return JSON, never HTML error pages."""
    if _audit:
        _audit.error(
            "Unhandled exception",
            extra={
                "event": "unhandled_exception",
                "path": str(request.url.path),
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "reason": f"Internal server error: {type(exc).__name__}: {exc}",
        },
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
        "prompt_guard_loaded": _prompt_guard_loaded,
        "codeshield_loaded": _codeshield_loaded,
        "planner_available": _planner_available,
        "conversation_tracking": settings.conversation_enabled,
        "pin_auth_enabled": _pin is not None,
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

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")


class ProcessRequest(BaseModel):
    text: str
    untrusted_data: str | None = None

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        return _normalize_text(v, min_length=1, field_name="Text")

    @field_validator("untrusted_data")
    @classmethod
    def validate_untrusted_data(cls, v: str | None) -> str | None:
        if v is None:
            return v
        # No minimum — can be empty string if explicitly provided, but enforce max
        v = unicodedata.normalize("NFC", v)
        if len(v) > MAX_TEXT_LENGTH:
            raise ValueError(f"Untrusted data too long (maximum {MAX_TEXT_LENGTH:,} characters)")
        return v


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


# ── Phase 3 endpoints ────────────────────────────────────────────


class TaskRequest(BaseModel):
    request: str
    source: str = "api"
    session_id: str | None = None  # Accepted but ignored — server assigns sessions

    @field_validator("request")
    @classmethod
    def validate_request(cls, v: str) -> str:
        return _normalize_text(v, min_length=MIN_TASK_REQUEST_LENGTH, field_name="Request")


@app.post("/task")
@limiter.limit("10/minute")
async def handle_task(req: TaskRequest, request: Request):
    """Full CaMeL pipeline: user request → Claude plans → Qwen executes → scanned result."""
    if _orchestrator is None:
        return {"status": "error", "reason": "Orchestrator not initialized"}

    # Server-side session binding: derive session from client IP, not client-provided ID.
    # This prevents attackers from rotating session IDs to bypass conversation tracking.
    client_ip = request.client.host if request.client else "unknown"
    source_key = f"{req.source}:{client_ip}"

    result = await _orchestrator.handle_task(
        user_request=req.request,
        source=req.source,
        approval_mode=settings.approval_mode,
        source_key=source_key,
    )
    return result.model_dump()


@app.get("/approval/{approval_id}")
async def check_approval(approval_id: str):
    """Check the status of an approval request."""
    if _orchestrator is None or _orchestrator._approval_manager is None:
        return {"status": "error", "reason": "Approval manager not available"}

    return _orchestrator._approval_manager.check_approval(approval_id)


class ApprovalDecision(BaseModel):
    granted: bool
    reason: str = ""

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        if len(v) > MAX_REASON_LENGTH:
            raise ValueError(f"Reason too long (maximum {MAX_REASON_LENGTH:,} characters)")
        return v


@app.post("/approve/{approval_id}")
async def submit_approval(approval_id: str, decision: ApprovalDecision):
    """Submit an approval decision, then execute the plan if approved."""
    if _orchestrator is None or _orchestrator._approval_manager is None:
        return {"status": "error", "reason": "Approval manager not available"}

    accepted = _orchestrator._approval_manager.submit_approval(
        approval_id=approval_id,
        granted=decision.granted,
        reason=decision.reason,
    )
    if not accepted:
        return {"status": "error", "reason": "Invalid, expired, or duplicate approval"}

    if decision.granted:
        result = await _orchestrator.execute_approved_plan(approval_id)
        return result.model_dump()

    return {"status": "denied", "reason": decision.reason}


# ── Session debug endpoint ─────────────────────────────────────


@app.get("/session/{session_id}")
async def get_session(session_id: str):
    """Debug endpoint: view session state and conversation history."""
    if _session_store is None:
        return {"error": "Session store not initialized"}

    session = _session_store.get(session_id)
    if session is None:
        return {"error": "Session not found or expired"}

    return {
        "session_id": session.session_id,
        "source": session.source,
        "turn_count": len(session.turns),
        "cumulative_risk": session.cumulative_risk,
        "violation_count": session.violation_count,
        "is_locked": session.is_locked,
        "turns": [
            {
                "request_preview": t.request_text[:100],
                "result_status": t.result_status,
                "blocked_by": t.blocked_by,
                "risk_score": t.risk_score,
            }
            for t in session.turns
        ],
    }
