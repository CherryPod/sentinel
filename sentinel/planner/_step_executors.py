"""Step-type execution functions for the plan execution loop.

Contains the per-step-type execution logic extracted from ExecutionMixin:
  execute_llm_task  — Qwen invocation + error handling for llm_task steps
  execute_tool_call — S3→S5 security gate chain for tool_call steps
  resolve_llm_prompt — prompt variable resolution + worker history injection

These are module-level functions (not mixin methods). ExecutionMixin._execute_step
dispatches to them, passing the required service objects as parameters.

Adding a new step type = add a function here + add an elif in _execute_step.

Extracted from _execution.py during planner modularisation Phase 4 fixes.
"""

import asyncio
import hashlib
import logging
import re
import time
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any

from sentinel.core.config import settings
from sentinel.core.context import require_user_id
from sentinel.core.models import (
    OutputDestination,
    PlanStep,
    StepResult,
)
from sentinel.security.pipeline import SecurityViolation
from sentinel.security.spotlighting import generate_marker

from ._execution_context import _VAR_RE, ExecutionContext
from .builders import FORMAT_INSTRUCTIONS, genericise_error
from .tool_dispatch import check_provenance, dispatch_tool, validate_constraints

if TYPE_CHECKING:
    from sentinel.tools._handlers._task_exec_context import TaskExecutionContext

logger = logging.getLogger(__name__)

# Type alias for the process_worker_output callback passed from ExecutionMixin
ProcessWorkerOutput = Callable[..., Coroutine[Any, Any, StepResult]]


def resolve_llm_prompt(
    step: PlanStep,
    context: ExecutionContext,
    worker_contexts: dict,
    worker_context_accessed: dict,
    session_id: str | None = None,
) -> tuple[str, str, dict]:
    """Resolve prompt variables, apply format instructions, inject worker history.

    Returns (resolved_prompt, marker, verbose_extra).

    Chain-safe: if step references prior output, apply structural marking.
    Defence-in-depth: also check for actual $var references in the prompt
    even if input_vars is empty — catches planner omissions that would
    otherwise cause UNTRUSTED worker output to resolve without wrapping.
    """
    actual_refs = set(re.findall(_VAR_RE, step.prompt or ""))
    declared_refs = set(step.input_vars or [])
    has_undeclared = bool(actual_refs - declared_refs) and any(
        context.get(ref) is not None for ref in (actual_refs - declared_refs)
    )
    if has_undeclared:
        logger.warning(
            "Undeclared variable references in prompt — using safe resolver",
            extra={
                "event": "execution.input_vars_mismatch",
                "step_id": step.id,
                "declared": sorted(declared_refs),
                "actual": sorted(actual_refs),
                "undeclared": sorted(actual_refs - declared_refs),
            },
        )
    if step.input_vars or has_undeclared:
        logger.debug(
            "_resolve_llm_prompt: input_vars",
            extra={
                "event": "_execution._resolve_llm_prompt.match",
                "reason": "input_vars",
            },
        )  # auto:neg
        marker = generate_marker() if settings.spotlighting_enabled else ""
        resolved_prompt = context.resolve_text_safe(step.prompt, marker=marker)
    else:
        logger.debug(
            "_resolve_llm_prompt: input_vars",
            extra={
                "event": "_execution._resolve_llm_prompt.clean",
                "reason": "input_vars",
            },
        )  # auto:neg
        marker = ""
        resolved_prompt = context.resolve_text(step.prompt)

    # Append format instruction if output_format is set (P8)
    if step.output_format and step.output_format in FORMAT_INSTRUCTIONS:
        logger.debug(
            "_resolve_llm_prompt: output_format",
            extra={
                "event": "_execution._resolve_llm_prompt.match",
                "reason": "output_format",
            },
        )  # auto:neg
        resolved_prompt += FORMAT_INSTRUCTIONS[step.output_format]

    # F3: Inject worker turn buffer if planner requested it
    if step.include_worker_history and session_id:
        logger.debug(
            "_resolve_llm_prompt: include_worker_history",
            extra={
                "event": "_execution._resolve_llm_prompt.match",
                "reason": "include_worker_history",
            },
        )  # auto:neg
        worker_ctx = worker_contexts.get(session_id)
        if worker_ctx:
            logger.debug(
                "_resolve_llm_prompt: worker_ctx",
                extra={
                    "event": "_execution._resolve_llm_prompt.match",
                    "reason": "worker_ctx",
                },
            )  # auto:neg
            worker_context_accessed[session_id] = time.monotonic()
            context_block = worker_ctx.format_context()
            if context_block:
                logger.debug(
                    "_resolve_llm_prompt: context_block",
                    extra={
                        "event": "_execution._resolve_llm_prompt.match",
                        "reason": "context_block",
                    },
                )  # auto:neg
                resolved_prompt = (
                    context_block + "\n\n[Current task:]\n" + resolved_prompt
                )

    # Verbose logging — capture prompts/responses for stress test analysis.
    # Only populated when SENTINEL_VERBOSE_RESULTS=true (never in production).
    verbose = settings.verbose_results
    _v: dict = {}
    if verbose:
        logger.debug(
            "_resolve_llm_prompt: verbose",
            extra={
                "event": "_execution._resolve_llm_prompt.match",
                "reason": "verbose",
            },
        )  # auto:neg
        _v["planner_prompt"] = step.prompt
        _v["resolved_prompt"] = resolved_prompt

    return resolved_prompt, marker, _v


async def execute_llm_task(
    step: PlanStep,
    context: ExecutionContext,
    pipeline: Any,
    worker_contexts: dict,
    worker_context_accessed: dict,
    process_worker_output: ProcessWorkerOutput,
    user_input: str | None = None,
    destination: OutputDestination = OutputDestination.EXECUTION,
    session_id: str | None = None,
) -> StepResult:
    """Send a prompt to Qwen via the scan pipeline.

    Delegates prompt resolution to resolve_llm_prompt() and post-generation
    processing to the process_worker_output callback (bound to ExecutionMixin).
    """
    if not step.prompt:
        return StepResult(
            step_id=step.id,
            status="error",
            error="LLM task step has no prompt",
        )

    resolved_prompt, marker, _v = resolve_llm_prompt(
        step, context, worker_contexts, worker_context_accessed, session_id
    )
    verbose = settings.verbose_results

    try:
        tagged, worker_stats = await asyncio.wait_for(
            pipeline.process_with_qwen(
                prompt=resolved_prompt,
                marker=marker or None,
                skip_input_scan=bool(step.input_vars)
                or destination == OutputDestination.DISPLAY,
                user_input=user_input,
                destination=destination,
            ),
            timeout=settings.worker_timeout,
        )

        # Type-check to avoid MagicMock leaking into Pydantic models in tests.
        worker_usage = worker_stats if isinstance(worker_stats, dict) else None

        # Capture Qwen's raw response before any post-processing
        logger.debug(
            "Raw Qwen output received (before any processing)",
            extra={
                "event": "execution.qwen_raw_output",
                "step_id": step.id,
                "content_length": len(tagged.content) if tagged.content else 0,
                "content_hash": hashlib.sha256(
                    (tagged.content or "").encode()
                ).hexdigest()[:16],
                "has_entities": (
                    "&lt;" in (tagged.content or "") or "&gt;" in (tagged.content or "")
                ),
                "has_response_tags": ("<RESPONSE>" in (tagged.content or "")),
                "data_id": tagged.id,
            },
        )
        if verbose:
            # Log length/hash only — raw Qwen output must not reach
            # planner context or log aggregation systems
            _v["worker_response_length"] = len(tagged.content) if tagged.content else 0
            _v["worker_response_hash"] = hashlib.sha256(
                (tagged.content or "").encode()
            ).hexdigest()[:16]

        # Post-generation output processing pipeline
        return await process_worker_output(
            tagged=tagged,
            step=step,
            destination=destination,
            worker_usage=worker_usage,
            verbose_extra=_v,
        )
    except TimeoutError:
        logger.error(
            "Worker inference timed out",
            extra={
                "event": "execution.worker_timeout",
                "step_id": step.id,
                "timeout_s": settings.worker_timeout,
            },
            exc_info=True,
        )
        return StepResult(
            step_id=step.id,
            status="error",
            error=f"Worker inference timed out after {settings.worker_timeout}s",
            **_v,
        )
    except SecurityViolation as exc:
        # Capture Qwen's raw response from the exception (post-Qwen violations
        # like output scan or echo scan include it; pre-Qwen violations don't)
        logger.exception(
            "_execute_llm_task: SecurityViolation",
            extra={"event": "_execution._execute_llm_task_securityviolation"},
        )  # auto:except
        if verbose and exc.raw_response is not None:
            _v["worker_response_length"] = len(exc.raw_response)
            _v["worker_response_hash"] = hashlib.sha256(
                exc.raw_response.encode()
            ).hexdigest()[:16]
        # Build specific block reason from scan results
        details = []
        for scanner_name, verdicts in exc.violations.unsuppressed_by_scanner().items():
            patterns = [v.match.rule_id for v in verdicts]
            details.append(f"{scanner_name}: {', '.join(patterns)}")
        specific = "; ".join(details) if details else str(exc)
        return StepResult(
            step_id=step.id,
            status="blocked",
            error=f"Output blocked — {specific}",
            **_v,
        )
    except Exception as exc:
        logger.error(
            "LLM task failed",
            extra={
                "event": "execution.llm_task_error",
                "step_id": step.id,
                "error": str(exc),
            },
            exc_info=True,
        )
        return StepResult(
            step_id=step.id,
            status="error",
            error=genericise_error(f"LLM task failed: {exc}") or "LLM task failed",
            **_v,
        )


async def execute_tool_call(
    step: PlanStep,
    context: ExecutionContext,
    pipeline: Any,
    contact_store: Any,
    safe_tool_handlers: Any,
    tool_executor: Any,
    destination: OutputDestination = OutputDestination.EXECUTION,
    session_id: str | None = None,
    user_id: int | None = None,
    effective_tl: int | None = None,
    task_exec_context: "TaskExecutionContext | None" = None,
) -> tuple[StepResult, dict | None]:
    """Execute a tool call step with security chain enforcement.

    Security chain (visible in sequence):
      S3: check_provenance()   — BEFORE argument resolution
          context.resolve_args — argument resolution
      S4: validate_constraints — on RESOLVED args
      S5: dispatch_tool        — output scanned BEFORE return
    """
    user_id = require_user_id(user_id, "_step_executors.execute_tool_call")
    # Resolve trust level: parameter > system default
    if effective_tl is None:
        effective_tl = settings.trust_level

    if not step.tool:
        logger.debug(
            "Tool call rejected: no tool specified",
            extra={"event": "execution.toolcall.notool", "step_id": step.id},
        )
        return StepResult(
            step_id=step.id,
            status="error",
            error="Tool call step has no tool specified",
        ), None

    # S3: Provenance gate BEFORE argument resolution
    _audit = getattr(pipeline, "_audit_emitter", None)
    provenance_block = await check_provenance(
        step,
        context,
        effective_tl,
        audit_emitter=_audit,
    )
    if provenance_block:
        return provenance_block, None

    # resolve_args uses the UNSAFE resolver (resolve_text, not resolve_text_safe)
    # intentionally — tools need raw content, not UNTRUSTED_DATA-wrapped content.
    # Trust is enforced by the S3/S4/S5 gate chain, not by data marking.
    resolved_args = context.resolve_args(step.args)

    # Log resolved args for debugging — shows what content the tool receives
    _resolved_preview = {}
    for k, v in resolved_args.items():
        if isinstance(v, str):
            _resolved_preview[k] = {
                "length": len(v),
                "preview": v[:300],
                "has_entities": ("&lt;" in v or "&gt;" in v),
            }
        elif isinstance(v, dict):
            logger.debug(
                "_execute_tool_call: clean",
                extra={"event": "execution._execute_tool_call.branch.clean"},
            )
            _resolved_preview[k] = {}
            for dk, dv in v.items():
                if isinstance(dv, str):
                    _resolved_preview[k][dk] = {
                        "length": len(dv),
                        "preview": dv[:300],
                        "has_entities": ("&lt;" in dv or "&gt;" in dv),
                    }
                else:
                    _resolved_preview[k][dk] = str(dv)
        else:
            logger.debug(
                "_execute_tool_call: clean",
                extra={"event": "execution._execute_tool_call.branch.clean"},
            )
            _resolved_preview[k] = str(v)
    logger.debug(
        "Tool step — resolved args",
        extra={
            "event": "execution.tool_resolved_args",
            "step_id": step.id,
            "tool": step.tool,
            "resolved_args_detail": _resolved_preview,
        },
    )

    # S4: Constraint validation on resolved args (TL4+)
    constraint_block = await validate_constraints(
        step,
        resolved_args,
        effective_tl,
        audit_emitter=_audit,
    )
    if constraint_block:
        return constraint_block, None

    # Recipient resolution — convert "user {N}" to real channel identifiers.
    # Runs AFTER S3→resolve→S4 (security operates on opaque IDs) and
    # BEFORE tool dispatch (handler needs real identifiers).
    from sentinel.contacts.resolver import resolve_tool_recipient

    try:
        resolved_args = await resolve_tool_recipient(
            contact_store,
            step.tool,
            resolved_args,
        )
    except ValueError as exc:
        logger.debug("execution.tool_call_value_error", exc_info=True)
        return StepResult(
            step_id=step.id,
            status="error",
            error=str(exc),
        ), None

    # S5: Dispatch and scan output before returning
    return await dispatch_tool(
        step=step,
        resolved_args=resolved_args,
        destination=destination,
        session_id=session_id,
        safe_tool_handlers=safe_tool_handlers,
        tool_executor=tool_executor,
        pipeline=pipeline,
        tool_timeout=settings.tool_timeout,
        user_id=user_id,
        task_exec_context=task_exec_context,
    )
