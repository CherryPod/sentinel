import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from pydantic import BaseModel

from .approval import ApprovalManager
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

# Module-level references populated at startup
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _cred_scanner, _path_scanner, _cmd_scanner, _pipeline
    global _prompt_guard_loaded, _codeshield_loaded, _session_store, _audit

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


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "policy_loaded": _engine is not None,
        "prompt_guard_loaded": _prompt_guard_loaded,
        "codeshield_loaded": _codeshield_loaded,
        "planner_available": _planner_available,
        "conversation_tracking": settings.conversation_enabled,
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


# ── Phase 3 endpoints ────────────────────────────────────────────


class TaskRequest(BaseModel):
    request: str
    source: str = "api"
    session_id: str | None = None


@app.post("/task")
async def handle_task(req: TaskRequest):
    """Full CaMeL pipeline: user request → Claude plans → Qwen executes → scanned result."""
    if _orchestrator is None:
        return {"status": "error", "reason": "Orchestrator not initialized"}

    result = await _orchestrator.handle_task(
        user_request=req.request,
        source=req.source,
        approval_mode=settings.approval_mode,
        session_id=req.session_id,
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
