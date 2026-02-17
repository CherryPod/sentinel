"""B2 red team test endpoint — compromised planner scenario.

Registers POST /api/test/execute-plan which accepts a pre-built Plan JSON
and runs it through the full execution pipeline (constraint validator,
PolicyEngine, scanners, executor) without calling the planner.

Gated by SENTINEL_RED_TEAM_MODE=true. Route is NOT registered when false.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter

from sentinel.core.models import Plan, TaskResult
from sentinel.planner.orchestrator import Orchestrator

logger = logging.getLogger("sentinel.audit")


def create_red_team_router(
    orchestrator: Orchestrator,
    limiter: Limiter,
    log_dir: str,
) -> APIRouter:
    """Create the red team router with dependencies wired in.

    Uses the factory pattern (same as MCP server) so the limiter decorator
    has a concrete object at definition time.
    """
    router = APIRouter(prefix="/api/test", tags=["red-team"])

    # Dedicated JSONL audit log for red team traffic
    audit_log_path = Path(log_dir) / "red_team_audit.jsonl"
    rt_audit = _setup_audit_logger(audit_log_path)

    logger.warning(
        "Red team router created — B2 testing mode ACTIVE",
        extra={
            "event": "red_team_router_init",
            "audit_log": str(audit_log_path),
        },
    )

    def _write_audit(entry: dict) -> None:
        """Append one JSON line to the red team audit log."""
        rt_audit.info(json.dumps(entry, default=str))

    class ExecutePlanRequest(BaseModel):
        """Request body for POST /api/test/execute-plan."""
        plan: Plan
        trust_level: int = Field(default=4, ge=0, le=4)

        @field_validator("trust_level")
        @classmethod
        def validate_trust_level(cls, v: int) -> int:
            if not 0 <= v <= 4:
                raise ValueError("trust_level must be 0-4")
            return v

    @router.post("/execute-plan")
    @limiter.limit("1/second")
    async def execute_plan(request: Request, body: ExecutePlanRequest):
        """Execute a pre-built plan through the security pipeline.

        Bypasses planner and approval. Runs constraint validator,
        PolicyEngine, scanners, executor. PIN auth is enforced by
        PinAuthMiddleware at the middleware level.
        """
        remote = request.client.host if request.client else "unknown"
        task_id = str(uuid.uuid4())
        t0 = time.monotonic()

        # Audit: log incoming plan before execution
        _write_audit({
            "event": "red_team_request",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "task_id": task_id,
            "remote": remote,
            "trust_level": body.trust_level,
            "plan_summary": body.plan.plan_summary,
            "step_count": len(body.plan.steps),
            "plan": body.plan.model_dump(),
        })

        logger.warning(
            "Red team plan execution requested",
            extra={
                "event": "red_team_execute",
                "task_id": task_id,
                "remote": remote,
                "trust_level": body.trust_level,
                "plan_summary": body.plan.plan_summary,
                "step_count": len(body.plan.steps),
            },
        )

        try:
            result = await orchestrator.execute_prebuilt_plan(
                plan=body.plan,
                trust_level=body.trust_level,
                task_id=task_id,
            )
        except Exception as exc:
            logger.error(
                "Red team plan execution failed",
                extra={
                    "event": "red_team_error",
                    "task_id": task_id,
                    "error": str(exc),
                },
            )
            _write_audit({
                "event": "red_team_error",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "task_id": task_id,
                "error": str(exc),
            })
            return JSONResponse(
                status_code=500,
                content={"status": "error", "reason": "Plan execution failed", "task_id": task_id},
            )

        elapsed = round(time.monotonic() - t0, 2)

        # Audit: log the outcome
        _write_audit({
            "event": "red_team_result",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "task_id": task_id,
            "remote": remote,
            "trust_level": body.trust_level,
            "status": result.status,
            "elapsed_s": elapsed,
            "step_outcomes": result.step_outcomes,
            "reason": result.reason,
        })

        return {
            "task_id": task_id,
            "status": result.status,
            "plan_summary": result.plan_summary,
            "step_results": [sr.model_dump() for sr in result.step_results],
            "step_outcomes": result.step_outcomes,
            "reason": result.reason,
            "elapsed_s": elapsed,
            "trust_level_used": body.trust_level,
        }

    return router


def _setup_audit_logger(path: Path) -> logging.Logger:
    """Create a dedicated JSONL logger for the red team audit trail."""
    path.parent.mkdir(parents=True, exist_ok=True)

    rt_logger = logging.getLogger("sentinel.red_team_audit")
    rt_logger.setLevel(logging.INFO)
    rt_logger.propagate = False

    for h in rt_logger.handlers[:]:
        h.close()
        rt_logger.removeHandler(h)

    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    rt_logger.addHandler(handler)
    return rt_logger
