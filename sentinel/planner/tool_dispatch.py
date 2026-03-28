"""Tool dispatch — provenance gate, constraint validation, and tool execution (Phase 5).

Security-critical:
- check_provenance() enforces S3 — provenance verification BEFORE argument resolution.
- validate_constraints() enforces S4 — constraint validation on RESOLVED args.
- dispatch_tool() enforces S5 — output scan BEFORE result is returned to caller.
These orderings are security invariants.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, TYPE_CHECKING

from sentinel.core.models import OutputDestination, PlanStep, StepResult
from sentinel.security.provenance import is_trust_safe_for_execution

if TYPE_CHECKING:
    from sentinel.security.pipeline import ScanPipeline
    from .safe_tools import SafeToolHandlers
    from .orchestrator import ExecutionContext

logger = logging.getLogger("sentinel.audit")

# Content-creation tools: Qwen's output IS the content (not system execution).
# Exempt from provenance gate because the output is displayed, not executed.
CONTENT_CREATION_TOOLS = frozenset({
    "website", "signal_send", "telegram_send", "email_send",
})

# Paths where file_patch is treated as content creation (display-only, not
# executed). file_patch on files outside these paths with untrusted provenance
# is still blocked by the trust gate — patching a script or config with
# untrusted web data is a different risk profile to updating a served webpage.
#
# Why file_patch isn't in CONTENT_CREATION_TOOLS:
#   file_patch can target ANY file type (Python, shell, YAML, HTML). A blanket
#   exemption would let untrusted web data flow into executable files. The
#   website tool is safe to exempt because it only writes to /workspace/sites/.
#   file_patch needs destination-aware exemption instead.
#
# Added 2026-03-22 during file_patch adoption testing. The trust gate was
# blocking web_search → llm_task → file_patch on site HTML — the same flow
# that website create handles without issue.
FILE_PATCH_CONTENT_PATHS = ("/workspace/sites/",)


async def check_provenance(
    step: PlanStep,
    context: ExecutionContext,
    trust_level: int,
) -> StepResult | None:
    """Verify provenance of data flowing into tool args.

    Returns None if safe to proceed, StepResult(blocked) if not.
    Enforces S3: this MUST be called BEFORE context.resolve_args().
    """
    referenced_ids = context.get_referenced_data_ids_from_args(step.args)
    untrusted_ids = [
        did for did in referenced_ids
        if not await is_trust_safe_for_execution(did)
    ]

    if not untrusted_ids:
        return None

    # TL4+: constrained steps bypass provenance gate — constraint validation
    # enforces the planner's approved scope instead.
    has_constraints = (
        step.allowed_commands is not None
        or step.allowed_paths is not None
    )
    is_content_creation = step.tool in CONTENT_CREATION_TOOLS

    # file_patch: destination-aware exemption. Patching served web content
    # (sites/) has the same risk profile as website create — the output is
    # displayed, not executed. Patching scripts or configs is higher risk
    # and stays gated.
    # NOTE: step.args.get("path") is UNRESOLVED at this point (pre-resolve_args).
    # If path is a $variable, it won't match and is_content_creation stays False —
    # this is FAIL-SAFE (provenance gate blocks, then S4 validates resolved path).
    if step.tool == "file_patch" and not is_content_creation:
        patch_path = step.args.get("path", "")
        if any(patch_path.startswith(p) for p in FILE_PATCH_CONTENT_PATHS):
            is_content_creation = True

    if trust_level >= 4 and (has_constraints or is_content_creation):
        logger.info(
            "Provenance gate bypassed — constraint-gated at TL4+",
            extra={
                "event": "provenance_bypassed",
                "reason": "constraint_gated",
                "step_id": step.id,
                "tool": step.tool,
                "untrusted_data_ids": untrusted_ids,
                "allowed_commands": step.allowed_commands,
                "allowed_paths": step.allowed_paths,
            },
        )
        return None

    # TL1-3, or TL4+ without constraints: block
    logger.warning(
        "Tool execution blocked — untrusted provenance",
        extra={
            "event": "trust_gate_blocked",
            "step_id": step.id,
            "tool": step.tool,
            "untrusted_data_ids": untrusted_ids,
        },
    )
    return StepResult(
        step_id=step.id,
        status="blocked",
        error=f"Provenance trust check failed: {len(untrusted_ids)} arg(s) have untrusted data in their provenance chain",
    )


async def validate_constraints(
    step: PlanStep,
    resolved_args: dict[str, Any],
    trust_level: int,
) -> StepResult | None:
    """Validate resolved args against plan-policy constraints (TL4+).

    Three-tier validation: static denylist, command constraints, path constraints.
    Returns None if allowed, StepResult(blocked) if not.
    Enforces S4: this MUST be called AFTER context.resolve_args() and BEFORE tool dispatch.
    """
    if trust_level < 4:
        return None

    from sentinel.security.constraint_validator import (
        check_denylist,
        validate_command_constraints,
        validate_path_constraints,
    )

    # shell_exec: validate resolved command
    if step.tool == "shell_exec" and "command" in resolved_args:
        resolved_cmd = resolved_args["command"]

        # Tier 1: Static denylist (constitutional)
        denylist_hit = check_denylist(resolved_cmd)
        if denylist_hit:
            logger.warning(
                "Command blocked by constitutional denylist",
                extra={
                    "event": "denylist_block",
                    "step_id": step.id,
                    "pattern_name": denylist_hit.pattern_name,
                    "resolved_command": resolved_cmd[:200],
                },
            )
            return StepResult(
                step_id=step.id,
                status="blocked",
                error=f"Blocked by constitutional denylist: {denylist_hit.pattern_name}",
            )

        # Tier 2: Plan-constraint validation
        cmd_result = validate_command_constraints(
            resolved_cmd, step.allowed_commands,
        )
        if not cmd_result.skipped:
            if cmd_result.allowed:
                logger.info(
                    "Command validated against plan constraint",
                    extra={
                        "event": "constraint_validated",
                        "step_id": step.id,
                        "tool": "shell_exec",
                        "resolved_command": resolved_cmd[:200],
                        "matched_constraint": cmd_result.matched_constraint,
                    },
                )
            else:
                logger.warning(
                    "Command violates plan constraints",
                    extra={
                        "event": "constraint_violation",
                        "step_id": step.id,
                        "tool": "shell_exec",
                        "resolved_command": resolved_cmd[:200],
                        "allowed_commands": step.allowed_commands,
                        "reason": cmd_result.reason,
                    },
                )
                return StepResult(
                    step_id=step.id,
                    status="blocked",
                    error=f"Command constraint violation: {cmd_result.reason}",
                )

    # file_write / file_read / file_patch: validate resolved path.
    # file_patch writes files — same path constraint validation as file_write/file_read.
    # PolicyEngine also validates at dispatch time (defence-in-depth, not sole gate).
    if step.tool in ("file_write", "file_read", "file_patch") and "path" in resolved_args:
        path_result = validate_path_constraints(
            resolved_args["path"], step.allowed_paths,
        )
        if not path_result.skipped:
            if path_result.allowed:
                logger.info(
                    "Path validated against plan constraint",
                    extra={
                        "event": "constraint_validated",
                        "step_id": step.id,
                        "tool": step.tool,
                        "resolved_path": resolved_args["path"],
                        "matched_constraint": path_result.matched_constraint,
                    },
                )
            else:
                logger.warning(
                    "Path violates plan constraints",
                    extra={
                        "event": "constraint_violation",
                        "step_id": step.id,
                        "tool": step.tool,
                        "resolved_path": resolved_args["path"],
                        "allowed_paths": step.allowed_paths,
                        "reason": path_result.reason,
                    },
                )
                return StepResult(
                    step_id=step.id,
                    status="blocked",
                    error=f"Path constraint violation: {path_result.reason}",
                )

    return None


async def dispatch_tool(
    step: PlanStep,
    resolved_args: dict[str, Any],
    destination: OutputDestination,
    session_id: str | None,
    safe_tool_handlers: SafeToolHandlers,
    tool_executor: Any | None,
    pipeline: ScanPipeline,
    tool_timeout: float,
    user_id: int = 1,
) -> tuple[StepResult, dict | None]:
    """Route to SAFE handler or ToolExecutor. Scan output before returning.

    Enforces S5: tool output is scanned BEFORE the result is returned to
    the caller. If the scan blocks, the blocked result is returned and
    the raw output never reaches context storage.
    """
    from .safe_tools import SAFE_HANDLERS

    # SAFE handler dispatch — internal tools handled by SafeToolHandlers
    safe_handler_name = SAFE_HANDLERS.get(step.tool)
    if safe_handler_name is not None:
        handler = getattr(safe_tool_handlers, safe_handler_name)
        # Inject session_id for handlers that accept it, when the planner
        # omits it (tool description says "optional — uses current session").
        if session_id and not resolved_args.get("session_id"):
            resolved_args = {**resolved_args, "session_id": session_id}
        # Inject user_id for user-scoped memory queries (privacy boundary).
        resolved_args = {**resolved_args, "user_id": user_id}
        try:
            tagged = await handler(resolved_args)
            logger.info(
                "SAFE tool executed",
                extra={
                    "event": "safe_tool_success",
                    "step_id": step.id,
                    "tool": step.tool,
                },
            )
            return StepResult(
                step_id=step.id,
                status="success",
                data_id=tagged.id,
                content=tagged.content,
            ), None
        except Exception as exc:
            logger.warning(
                "SAFE tool failed",
                extra={
                    "event": "safe_tool_failed",
                    "step_id": step.id,
                    "tool": step.tool,
                    "error": str(exc),
                },
            )
            return StepResult(
                step_id=step.id,
                status="error",
                error=f"SAFE tool '{step.tool}' failed: {exc}",
            ), None

    # System/external tools — dispatched to ToolExecutor
    if tool_executor is None:
        logger.info(
            "Tool execution not available — skipping",
            extra={
                "event": "tool_skipped",
                "step_id": step.id,
                "tool": step.tool,
            },
        )
        return StepResult(
            step_id=step.id,
            status="skipped",
            error="Tool execution not yet available",
        ), None

    try:
        tagged, exec_meta = await asyncio.wait_for(
            tool_executor.execute(
                tool_name=step.tool,
                args=resolved_args,
            ),
            timeout=tool_timeout,
        )

        # S5: Scan tool output for sensitive data BEFORE it enters the
        # execution context or gets returned in step_results.
        if tagged.content:
            try:
                output_scan = await pipeline.scan_output(
                    tagged.content, destination,
                )
            except Exception:
                logger.error(
                    "Tool output scan crashed — failing closed",
                    extra={
                        "event": "tool_output_scan_crash",
                        "step_id": step.id, "tool": step.tool,
                    },
                    exc_info=True,
                )
                return StepResult(
                    step_id=step.id,
                    status="blocked",
                    error="Tool output scan failed — blocked for safety",
                ), exec_meta

            tagged.scan_results = output_scan.results

            if not output_scan.is_clean:
                details = []
                for scanner_name, sr in output_scan.violations.items():
                    patterns = [m.pattern_name for m in sr.matches]
                    details.append(f"{scanner_name}: {', '.join(patterns)}")
                specific = "; ".join(details)
                logger.warning(
                    "Tool output blocked by scan pipeline",
                    extra={
                        "event": "tool_output_blocked",
                        "step_id": step.id,
                        "tool": step.tool,
                        "destination": destination.value,
                        "violations": list(output_scan.violations.keys()),
                    },
                )
                return StepResult(
                    step_id=step.id,
                    status="blocked",
                    error=f"Output blocked — {specific}",
                ), exec_meta

        # Check for non-zero exit codes (sandbox or direct shell)
        # TODO: Some tools use non-zero exit for non-error conditions (grep exit 1 = no
        # matches, diff exit 1 = files differ). A future allowlist could exempt these
        # informational exit codes from triggering replanning.
        exit_code = exec_meta.get("exit_code") if isinstance(exec_meta, dict) else None
        if isinstance(exit_code, int) and exit_code != 0:
            return StepResult(
                step_id=step.id,
                status="soft_failed",
                data_id=tagged.id,
                content=tagged.content,
                error=f"Command exited with code {exit_code}",
            ), exec_meta
        return StepResult(
            step_id=step.id,
            status="success",
            data_id=tagged.id,
            content=tagged.content,
        ), exec_meta
    except asyncio.TimeoutError:
        logger.error(
            "Tool execution timed out",
            extra={
                "event": "tool_timeout",
                "step_id": step.id,
                "tool": step.tool,
                "timeout_s": tool_timeout,
            },
        )
        return StepResult(
            step_id=step.id,
            status="error",
            error=f"Tool '{step.tool}' timed out after {tool_timeout}s",
        ), None
    except Exception as exc:
        from sentinel.tools.executor import ToolBlockedError
        status = "blocked" if isinstance(exc, ToolBlockedError) else "error"
        logger.error(
            "Tool execution exception: %s — %s",
            type(exc).__name__, str(exc)[:500],
            exc_info=True,
            extra={
                "event": "tool_execution_exception",
                "step_id": step.id,
                "tool": step.tool,
                "status": status,
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )
        return StepResult(
            step_id=step.id,
            status=status,
            error=f"Tool execution failed: {exc}",
        ), None
