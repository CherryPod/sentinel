"""Tool dispatch — provenance gate and tool execution (Phase 5).

Security-critical:
- check_provenance() enforces S3 — provenance verification BEFORE argument resolution.
- validate_constraints() enforces S4 — see _tool_constraints.py.
- dispatch_tool() enforces S5 — output scan BEFORE result is returned to caller.
These orderings are security invariants.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import TYPE_CHECKING, Any

from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.context import require_user_id
from sentinel.core.models import OutputDestination, PlanStep, StepResult
from sentinel.security._log_shape import canonical_set_hash
from sentinel.security.provenance import is_trust_safe_for_execution

from ._tool_constraints import (  # noqa: F401 — validate_constraints re-exported for _step_executors
    CONTENT_CREATION_TOOLS,
    FILE_PATCH_CONTENT_PATHS,
    validate_constraints,
)

if TYPE_CHECKING:
    from sentinel.security.pipeline import ScanPipeline

    from .orchestrator import ExecutionContext
    from .safe_tools import SafeToolHandlers

logger = logging.getLogger(__name__)


def _provenance_ids_hash(ids: list[str]) -> str:
    """Sorted-without-dedup hash of provenance ID references.

    Unlike canonical_set_hash (which deduplicates), this preserves
    multiplicity so repeated references to the same data ID produce a
    distinct fingerprint from a single reference. Two calls with
    ["id1", "id1"] vs ["id1"] produce different hashes, preventing
    distinct provenance graphs from collapsing to the same audit token.
    Input order is normalized (sorted) — this hash distinguishes multisets,
    not sequences. Empty input → "empty".
    """
    if not ids:
        return "empty"
    from sentinel.crypto.blind_index import log_hash  # lazy: avoids triggering sentinel.crypto.__init__ at module load time
    canonical = sorted(str(did) for did in ids)
    joined = "|".join(f"{len(item)}:{item}" for item in canonical)
    return log_hash(joined)


async def check_provenance(
    step: PlanStep,
    context: ExecutionContext,
    trust_level: int,
    audit_emitter: Any | None = None,
) -> StepResult | None:
    """Verify provenance of data flowing into tool args.

    Returns None if safe to proceed, StepResult(blocked) if not.
    Enforces S3: this MUST be called BEFORE context.resolve_args().
    """
    logger.debug(
        "check_provenance called",
        extra={
            "event": "check.provenance",
            "step_id": step.id,
            "tool": step.tool,
            "trust_level": trust_level,
        },
    )
    referenced_ids = context.get_referenced_data_ids_from_args(step.args)
    untrusted_ids = [
        did for did in referenced_ids if not await is_trust_safe_for_execution(did)
    ]

    if not untrusted_ids:
        logger.debug(
            "check_provenance passed — no untrusted data",
            extra={
                "event": "check.provenance_clean",
                "step_id": step.id,
                "tool": step.tool,
                "referenced_count": len(referenced_ids),
            },
        )
        if audit_emitter is not None:
            await audit_emitter.emit(
                SecurityAuditEvent(
                    event_type="trust.provenance_check",
                    source_component="tool_dispatch",
                    outcome="CLEAN",
                    details={
                        "step_id": step.id,
                        "tool": step.tool,
                        "trust_level": trust_level,
                        "referenced_count": len(referenced_ids),
                    },
                )
            )
        return None
    logger.debug(
        "check_provenance: not_untrusted_ids_passed",
        extra={
            "event": "check.provenance_clean.passed",
            "reason": "not_untrusted_ids_passed",
        },
    )  # auto:neg

    # TL4+: constrained steps bypass provenance gate — constraint validation
    # enforces the planner's approved scope instead.
    has_constraints = (
        step.allowed_commands is not None or step.allowed_paths is not None
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
                "event": "provenance.bypassed",
                "reason": "constraint_gated",
                "step_id": step.id,
                "tool": step.tool,
                "untrusted_ids_count": len(untrusted_ids),
                "untrusted_ids_hash": _provenance_ids_hash(untrusted_ids),
                "allowed_commands_count": (
                    len(step.allowed_commands) if step.allowed_commands else 0
                ),
                "allowed_commands_hash": canonical_set_hash(step.allowed_commands),
                "allowed_paths_count": (
                    len(step.allowed_paths) if step.allowed_paths else 0
                ),
                "allowed_paths_hash": canonical_set_hash(step.allowed_paths),
            },
        )
        if audit_emitter is not None:
            await audit_emitter.emit(
                SecurityAuditEvent(
                    event_type="trust.provenance_check",
                    source_component="tool_dispatch",
                    outcome="BYPASSED",
                    details={
                        "step_id": step.id,
                        "tool": step.tool,
                        "trust_level": trust_level,
                        "reason": "constraint_gated",
                        "untrusted_ids_count": len(untrusted_ids),
                        "untrusted_ids_hash": _provenance_ids_hash(untrusted_ids),
                    },
                )
            )
        return None

    # TL1-3, or TL4+ without constraints: block
    logger.warning(
        "Tool execution blocked — untrusted provenance",
        extra={
            "event": "trust.gate_blocked",
            "step_id": step.id,
            "tool": step.tool,
            "untrusted_ids_count": len(untrusted_ids),
            "untrusted_ids_hash": _provenance_ids_hash(untrusted_ids),
        },
    )
    if audit_emitter is not None:
        await audit_emitter.emit(
            SecurityAuditEvent(
                event_type="trust.gate_block",
                source_component="tool_dispatch",
                outcome="BLOCKED",
                severity="MEDIUM",
                details={
                    "step_id": step.id,
                    "tool": step.tool,
                    "trust_level": trust_level,
                    "untrusted_ids_count": len(untrusted_ids),
                    "untrusted_ids_hash": _provenance_ids_hash(untrusted_ids),
                },
            )
        )
    return StepResult(
        step_id=step.id,
        status="blocked",
        error=f"Provenance trust check failed: {len(untrusted_ids)} arg(s) have untrusted data in their provenance chain",
    )


async def dispatch_tool(
    step: PlanStep,
    resolved_args: dict[str, Any],
    destination: OutputDestination,
    session_id: str | None,
    safe_tool_handlers: SafeToolHandlers,
    tool_executor: Any | None,
    pipeline: ScanPipeline,
    tool_timeout: float,
    user_id: int | None = None,
    task_exec_context: Any | None = None,
) -> tuple[StepResult, dict | None]:
    """Route to SAFE handler or ToolExecutor. Scan output before returning.

    Enforces S5: tool output is scanned BEFORE the result is returned to
    the caller. If the scan blocks, the blocked result is returned and
    the raw output never reaches context storage.
    """
    user_id = require_user_id(user_id, "tool_dispatch.dispatch_tool")
    logger.debug(
        "dispatch_tool called",
        extra={
            "event": "dispatch.tool",
            "step_id": step.id,
            "tool": step.tool,
            "destination": destination.value,
        },
    )
    from .safe_tools import SAFE_HANDLERS

    # SAFE handler dispatch — internal tools handled by SafeToolHandlers
    safe_handler_name = SAFE_HANDLERS.get(step.tool)
    if safe_handler_name is not None:
        logger.debug(
            "dispatch_tool routing to SAFE handler",
            extra={
                "event": "dispatch.route_safe",
                "step_id": step.id,
                "tool": step.tool,
                "handler_name": safe_handler_name,
            },
        )
        return await _dispatch_safe_tool(
            step,
            resolved_args,
            session_id,
            user_id,
            safe_tool_handlers,
            safe_handler_name,
        )

    # System/external tools — dispatched to ToolExecutor
    if tool_executor is None:
        logger.info(
            "Tool execution not available — skipping",
            extra={
                "event": "tool.skipped",
                "step_id": step.id,
                "tool": step.tool,
            },
        )
        return StepResult(
            step_id=step.id,
            status="skipped",
            error="Tool execution not yet available",
        ), None

    logger.debug(
        "dispatch_tool routing to external ToolExecutor",
        extra={
            "event": "dispatch.route_external",
            "step_id": step.id,
            "tool": step.tool,
        },
    )
    return await _dispatch_external_tool(
        step,
        resolved_args,
        destination,
        tool_executor,
        pipeline,
        tool_timeout,
        task_exec_context=task_exec_context,
    )


async def _dispatch_safe_tool(
    step: PlanStep,
    resolved_args: dict[str, Any],
    session_id: str | None,
    user_id: int,
    safe_tool_handlers: SafeToolHandlers,
    handler_name: str,
) -> tuple[StepResult, dict | None]:
    """Execute an internal SAFE handler. No output scanning — SAFE tools are trusted.

    Injects session_id (when the planner omits it) and user_id (privacy boundary)
    before calling the handler.
    """
    logger.debug(
        "_dispatch_safe_tool called",
        extra={
            "event": "dispatch.safe_tool",
            "step_id": step.id,
            "tool": step.tool,
            "handler_name": handler_name,
        },
    )
    handler = getattr(safe_tool_handlers, handler_name)
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
                "event": "safe.tool_success",
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
    except Exception as exc:  # catch-all: tool execution isolation
        logger.warning(
            "SAFE tool failed",
            extra={
                "event": "safe.tool_failed",
                "step_id": step.id,
                "tool": step.tool,
                "error": str(exc),
            },
            exc_info=True,
        )
        return StepResult(
            step_id=step.id,
            status="error",
            error=f"SAFE tool '{step.tool}' failed: {exc}",
        ), None


async def _scan_tool_output(
    tagged: Any,
    step: PlanStep,
    destination: OutputDestination,
    pipeline: ScanPipeline,
    *,
    pipeline_run_id: str | None = None,
) -> StepResult | None:
    """S5: Scan tool output for sensitive data BEFORE it enters context storage.

    Returns None if the output is clean (caller proceeds to success/soft_failed
    classification). Returns a blocked StepResult if the scan crashes or finds
    violations — the raw output never reaches context storage in that case.

    Security invariant: this MUST be called before the result is returned to
    the caller. Fail-closed: scan crash → blocked.

    Q17-F4 (D3, 2026-04-24): ``pipeline_run_id`` is threaded down from
    ``_dispatch_external_tool`` so the scan's audit events share the
    same correlation id as the surrounding ``tool.*`` envelope.
    Optional for direct callers; when ``None``, ``run_output_scan``
    allocates a fresh id.
    """
    logger.debug(
        "_scan_tool_output called",
        extra={
            "event": "scan.tool_output",
            "step_id": step.id,
            "tool": step.tool,
            "destination": destination.value,
            "has_content": bool(tagged.content),
            "has_pipeline_run_id": pipeline_run_id is not None,
        },
    )
    if not tagged.content:
        logger.debug(
            "No content to scan — skipping output scan",
            extra={
                "event": "output.scan_skipped",
                "step_id": step.id,
                "tool": step.tool,
            },
        )
        return None

    try:
        output_scan = await pipeline.scan_output(
            tagged.content,
            destination,
            pipeline_run_id=pipeline_run_id,
        )
    except Exception:  # catch-all: output scan crash — fail closed
        logger.warning(
            "Tool output scan crashed — failing closed",
            extra={
                "event": "tool.output_scan_crash",
                "step_id": step.id,
                "tool": step.tool,
            },
            exc_info=True,
        )
        return StepResult(
            step_id=step.id,
            status="blocked",
            error="Tool output scan failed — blocked for safety",
        )

    tagged.scan_result = output_scan

    if not output_scan.is_clean:
        details = []
        for scanner_name, verdicts in output_scan.unsuppressed_by_scanner().items():
            patterns = [v.match.rule_id for v in verdicts]
            details.append(f"{scanner_name}: {', '.join(patterns)}")
        specific = "; ".join(details)
        logger.warning(
            "Tool output blocked by scan pipeline",
            extra={
                "event": "tool.output_blocked",
                "step_id": step.id,
                "tool": step.tool,
                "destination": destination.value,
                "violations": list(output_scan.violated_scanners()),
            },
        )
        return StepResult(
            step_id=step.id,
            status="blocked",
            error=f"Output blocked — {specific}",
        )

    logger.debug(
        "Output scan passed",
        extra={
            "event": "output.scan_clean",
            "step_id": step.id,
            "tool": step.tool,
        },
    )
    return None


async def _dispatch_external_tool(
    step: PlanStep,
    resolved_args: dict[str, Any],
    destination: OutputDestination,
    tool_executor: Any,
    pipeline: ScanPipeline,
    tool_timeout: float,
    task_exec_context: Any | None = None,
) -> tuple[StepResult, dict | None]:
    """Execute a system/external tool via ToolExecutor with timeout and output scan.

    Enforces S5 by calling _scan_tool_output before returning any successful result.
    Handles timeout, ToolBlockedError, and general exceptions.

    Q17-F4 (D3, 2026-04-24): this caller owns the correlation id that
    links the ``tool.*`` envelope (emitted by ``tool_executor.execute``)
    to the downstream ``scan.*`` events (emitted by the output scan).
    A fresh ``pipeline_run_id`` is allocated per dispatch and threaded
    into both ``execute()`` and ``_scan_tool_output``.  This is the
    only production entry point that threads the correlation id;
    other callers of ``ToolExecutor.execute`` / ``ScanPipeline.scan_output``
    leave the id unset and each side allocates its own (legacy shape,
    no join at details level).
    """
    logger.debug(
        "_dispatch_external_tool called",
        extra={
            "event": "dispatch.external_tool",
            "step_id": step.id,
            "tool": step.tool,
            "timeout_s": tool_timeout,
        },
    )
    # Allocate the correlation id BEFORE execute() so the tool.dispatch
    # audit event (emitted at entry inside execute) carries it too.
    pipeline_run_id = uuid.uuid4().hex
    try:
        tagged, exec_meta = await asyncio.wait_for(
            tool_executor.execute(
                tool_name=step.tool,
                args=resolved_args,
                task_context=task_exec_context,
                pipeline_run_id=pipeline_run_id,
            ),
            timeout=tool_timeout,
        )

        # S5: Scan output BEFORE it enters context or gets returned.
        blocked = await _scan_tool_output(
            tagged,
            step,
            destination,
            pipeline,
            pipeline_run_id=pipeline_run_id,
        )
        if blocked is not None:
            return blocked, exec_meta

        # Check for non-zero exit codes (sandbox or direct shell).
        # TODO: Some tools use non-zero exit for non-error conditions (grep exit 1 = no
        # matches, diff exit 1 = files differ). A future allowlist could exempt these
        # informational exit codes from triggering replanning.
        exit_code = exec_meta.get("exit_code") if isinstance(exec_meta, dict) else None
        if isinstance(exit_code, int) and exit_code != 0:
            logger.debug(
                "Tool soft_failed — non-zero exit code",
                extra={
                    "event": "tool.soft_failed",
                    "step_id": step.id,
                    "tool": step.tool,
                    "exit_code": exit_code,
                },
            )
            return StepResult(
                step_id=step.id,
                status="soft_failed",
                data_id=tagged.id,
                content=tagged.content,
                error=f"Command exited with code {exit_code}",
            ), exec_meta

        logger.debug(
            "Tool dispatch success",
            extra={
                "event": "tool_dispatch.success",
                "step_id": step.id,
                "tool": step.tool,
            },
        )
        return StepResult(
            step_id=step.id,
            status="success",
            data_id=tagged.id,
            content=tagged.content,
        ), exec_meta
    except TimeoutError:
        logger.error(
            "Tool execution timed out",
            extra={
                "event": "tool.timeout",
                "step_id": step.id,
                "tool": step.tool,
                "timeout_s": tool_timeout,
            },
            exc_info=True,
        )
        return StepResult(
            step_id=step.id,
            status="error",
            error=f"Tool '{step.tool}' timed out after {tool_timeout}s",
        ), None
    except Exception as exc:
        from sentinel.tools.executor import ToolBlockedError

        status = "blocked" if isinstance(exc, ToolBlockedError) else "error"
        logger.exception(
            "Tool execution exception: %s — %s",
            type(exc).__name__,
            str(exc)[:500],
            extra={
                "event": "tool.execution_exception",
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
