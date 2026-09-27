"""Plan validation and constraint inference for the planner.

Validates plan structure (types, variable refs, assertions, tool names)
and auto-infers execution constraints from step arguments at TL4+.
"""

import logging
import os
import re
import shlex
from typing import Literal, NoReturn

from sentinel.core.config import settings
from sentinel.core.exceptions import PlanValidationError
from sentinel.core.models import Plan
from sentinel.crypto.blind_index import log_hash
from sentinel.planner._command_shape import _cmd_shape
from sentinel.security._log_shape import canonical_set_hash
from sentinel.security.constraint_validator import (
    CV_CONSTRAINT_ERROR_CODES,
    validate_constraint_definitions,
)

logger = logging.getLogger(__name__)

# FL-C72-a1 / D36: closed-world fixed-template codes for PlanValidationError.
# No raw planner/user-derived content may appear in any PlanValidationError
# message or its traceback chain. All raise sites MUST use _raise_plan_validation.
# Adding a new code requires updating this tuple AND the AST drift test at
# tests/test_plan_validation_error_drift.py.
_PV_CODES = (
    "Plan has no steps",
    "Plan exceeds maximum steps",
    "Duplicate step ID",
    "Step has unknown type",
    "Step (tool_call) missing tool name",
    "Step (llm_task) missing prompt",
    "Step references unknown tool",
    "Step references undefined variable",
    "Step has invalid output_format",
    "Plan has too many replan_after markers",
    "Step has invalid constraint definition",
    "Step assertion missing 'assert' key",
    "Plan does not match expected schema",
)

# Closed-world Literal type — enforces code membership at type-check time.
PVCode = Literal[
    "Plan has no steps",
    "Plan exceeds maximum steps",
    "Duplicate step ID",
    "Step has unknown type",
    "Step (tool_call) missing tool name",
    "Step (llm_task) missing prompt",
    "Step references unknown tool",
    "Step references undefined variable",
    "Step has invalid output_format",
    "Plan has too many replan_after markers",
    "Step has invalid constraint definition",
    "Step assertion missing 'assert' key",
    "Plan does not match expected schema",
]


def _raise_plan_validation(
    *,
    code: PVCode,
    step_id: str | None = None,
    step_type: str | None = None,
    step_tool: str | None = None,
    var_name: str | None = None,
    output_format: str | None = None,
    first_error_code: str | None = None,
    error_count: int | None = None,
    assertion_index: int | None = None,
    pydantic_error_class: str | None = None,
    pydantic_error_text: str | None = None,
) -> NoReturn:
    """Raise PlanValidationError with fixed-template message and server-side log.

    The code MUST be a member of _PV_CODES. Message is the code itself —
    no raw user/planner content. Server-side warning carries hash/length
    extras only for forensic correlation. Per FL-C72-a1 / D36 class policy:
    PlanValidationError text and traceback must not carry planner/user-derived
    content. The from None suppression prevents __cause__/__context__ traceback
    rendering at exc_info=True log sites.
    """
    if code not in _PV_CODES:
        raise ValueError(f"D36 violation: unregistered PVCode at raise site: {code!r}")
    log_extras: dict = {
        "event": "plan_validator.validation_blocked",
        "code": code,
    }
    if step_id is not None:
        log_extras["step_id_len"] = len(step_id)
        log_extras["step_id_hash"] = log_hash(step_id)
    if step_type is not None:
        log_extras["step_type_len"] = len(step_type)
        log_extras["step_type_hash"] = log_hash(step_type)
    if step_tool is not None:
        log_extras["step_tool_len"] = len(step_tool)
        log_extras["step_tool_hash"] = log_hash(step_tool)
    if var_name is not None:
        log_extras["var_name_len"] = len(var_name)
        log_extras["var_name_hash"] = log_hash(var_name)
    if output_format is not None:
        log_extras["output_format_len"] = len(output_format)
        log_extras["output_format_hash"] = log_hash(output_format)
    if first_error_code is not None:
        if first_error_code not in CV_CONSTRAINT_ERROR_CODES:
            raise ValueError(
                f"D36 violation: first_error_code {first_error_code!r} not in "
                "CV_CONSTRAINT_ERROR_CODES — raw content would leak into log extras"
            )
        # Member of CV_CONSTRAINT_ERROR_CODES fixed-template codes — safe to log raw.
        log_extras["first_error_code"] = first_error_code
    if error_count is not None:
        log_extras["error_count"] = error_count
    if assertion_index is not None:
        log_extras["assertion_index"] = assertion_index
    if pydantic_error_class is not None:
        # Class name only (e.g. "TypeError"), not the exception text — safe.
        log_extras["pydantic_error_class"] = pydantic_error_class
    if pydantic_error_text is not None:
        log_extras["pydantic_error_len"] = len(pydantic_error_text)
        log_extras["pydantic_error_hash"] = log_hash(pydantic_error_text)
    logger.warning("Plan validation blocked", extra=log_extras)
    raise PlanValidationError(code) from None

# #14 LOW / #24 LOW: shared constants — avoids magic numbers scattered in methods
MAX_PLAN_STEPS = 50

# Shell metacharacters that indicate chained commands (#2 HIGH — single-command extraction)
_SHELL_CHAIN_RE = re.compile(r"[;&|]")


def infer_constraints(step) -> dict:
    """Derive allowed_commands / allowed_paths from tool_call args.

    Returns a dict with inferred constraint fields, or empty dict
    if constraints cannot be inferred (step will use legacy scanning).
    """
    logger.debug(
        "infer_constraints called",
        extra={
            "event": "infer.constraints",
            "step_id": step.id,
            "step_tool": step.tool or "",
        },
    )
    result = {}
    tool = step.tool or ""
    args = step.args or {}

    # file_write / file_read / file_patch: infer allowed_paths from path arg
    if tool in ("file_write", "file_read", "file_patch") and "path" in args:
        logger.debug(
            "infer_constraints branch: file path tool",
            extra={
                "event": "infer.constraints_branch",
                "step_id": step.id,
                "branch": "file_path_tool",
                "step_tool": tool,
            },
        )
        path = args["path"]
        if "$" in path:
            # #9 MED: log when variable reference causes fallback
            logger.debug(
                "Constraint inference skipped — variable reference in path",
                extra={
                    "event": "constraint.infer_skip",
                    "reason": "variable_ref",
                    "tool": tool,
                },
            )
            return {}
        result["allowed_paths"] = [path]

    # mkdir: infer allowed_paths from path arg
    elif tool == "mkdir" and "path" in args:
        logger.debug(
            "infer_constraints branch: mkdir",
            extra={
                "event": "infer.constraints_branch",
                "step_id": step.id,
                "branch": "mkdir",
                "step_tool": tool,
            },
        )
        path = args["path"]
        if "$" in path:
            logger.debug(
                "Constraint inference skipped — variable reference in path",
                extra={
                    "event": "constraint.infer_skip",
                    "reason": "variable_ref",
                    "tool": tool,
                },
            )
            return {}
        result["allowed_paths"] = [path]

    # shell_exec / shell: infer allowed_commands from command arg
    elif tool in ("shell_exec", "shell") and "command" in args:
        logger.debug(
            "infer_constraints branch: shell command",
            extra={
                "event": "infer.constraints_branch",
                "step_id": step.id,
                "branch": "shell_command",
                "step_tool": tool,
            },
        )
        command = args["command"]
        if "$" in command:
            logger.debug(
                "Constraint inference skipped — variable reference in command",
                extra={
                    "event": "constraint.infer_skip",
                    "reason": "variable_ref",
                    "tool": tool,
                },
            )
            return {}
        # #2 HIGH: detect shell metacharacters (&&, ||, ;, |) that indicate
        # chained commands. Extracting only the first command gives a false
        # sense of constraint coverage. Fall back to legacy scanning.
        if _SHELL_CHAIN_RE.search(command):
            # FL-C76-a2 (D38): replace command_preview raw extra with shape +
            # hash + length triple. Same value class as eval_command_returns
            # cmd extras — composite shell command may embed workspace paths
            # or user-authored filenames. Helper grammar is generic over any
            # shell command (allowlist-or-denied-category fallback).
            logger.debug(
                "Constraint inference skipped — chained shell command detected",
                extra={
                    "event": "constraint.infer_skip",
                    "reason": "chained_command",
                    "tool": tool,
                    "command_shape": _cmd_shape(command),
                    "command_hash": log_hash(command),
                    "command_len": len(command) if command else 0,
                },
            )
            return {}
        try:
            tokens = shlex.split(command)
            if tokens:
                base_cmd = os.path.basename(tokens[0])
                result["allowed_commands"] = [base_cmd]
        except ValueError as exc:
            # #11 MED: log when unparseable command causes fallback.
            # D36: shlex error text may contain command content — hash/len only.
            logger.debug(
                "Constraint inference skipped — unparseable command",
                extra={
                    "event": "constraint.infer_skip",
                    "reason": "shlex_error",
                    "tool": tool,
                    "error_len": len(str(exc)),
                    "error_hash": log_hash(str(exc)),
                },
            )
            return {}

    if not result:
        logger.debug(
            "Constraint inference produced empty result",
            extra={
                "event": "planner.inferconstraints.empty",
                "step_id": step.id,
                "step_tool": step.tool or "",
            },
        )
    else:
        logger.debug(
            "Constraint inference complete",
            extra={
                "event": "planner.inferconstraints.done",
                "step_id": step.id,
                "result_count": len(result),
            },
        )
    return result


def validate_plan(
    plan: Plan,
    available_tool_names: set[str] | None = None,
    prior_vars: set[str] | None = None,
) -> None:
    """Validate plan structure: non-empty, valid types, variable refs resolve.

    For continuation plans, pass prior_vars with the output_var names from
    already-executed steps so the validator doesn't reject references to them.
    """
    logger.debug(
        "validate_plan called",
        extra={
            "event": "validate.plan",
            "step_count": len(plan.steps) if plan.steps else 0,
            "available_tool_names_len": len(available_tool_names)
            if available_tool_names
            else 0,
            "prior_vars_len": len(prior_vars) if prior_vars else 0,
        },
    )
    if not plan.steps:
        _raise_plan_validation(code="Plan has no steps")

    if len(plan.steps) > MAX_PLAN_STEPS:
        _raise_plan_validation(code="Plan exceeds maximum steps")

    valid_types = {"llm_task", "tool_call"}
    defined_vars: set[str] = set(prior_vars) if prior_vars else set()
    seen_ids: set[str] = set()

    for step in plan.steps:
        # Check unique IDs
        if step.id in seen_ids:
            _raise_plan_validation(code="Duplicate step ID", step_id=step.id)
        seen_ids.add(step.id)

        # Check valid type
        if step.type not in valid_types:
            _raise_plan_validation(
                code="Step has unknown type",
                step_id=step.id,
                step_type=step.type,
            )

        # Step-type-specific field validation
        if step.type == "tool_call" and not step.tool:
            _raise_plan_validation(code="Step (tool_call) missing tool name", step_id=step.id)
        if step.type == "llm_task" and not step.prompt:
            _raise_plan_validation(code="Step (llm_task) missing prompt", step_id=step.id)
        # Validate tool name against available tools if provided
        if (
            step.type == "tool_call"
            and step.tool
            and available_tool_names is not None
            and step.tool not in available_tool_names
        ):
            _raise_plan_validation(
                code="Step references unknown tool",
                step_id=step.id,
                step_tool=step.tool,
            )

        # Check input variable references
        for var in step.input_vars:
            if var not in defined_vars:
                _raise_plan_validation(
                    code="Step references undefined variable",
                    step_id=step.id,
                    var_name=var,
                )

        # Check output_format if set
        valid_formats = {None, "json", "tagged"}
        if step.output_format not in valid_formats:
            _raise_plan_validation(
                code="Step has invalid output_format",
                step_id=step.id,
                output_format=str(step.output_format) if step.output_format is not None else None,
            )

        # Track output variable
        if step.output_var:
            defined_vars.add(step.output_var)

    # Dynamic replanning: validate replan_after usage
    replan_markers = sum(1 for s in plan.steps if s.replan_after)
    if replan_markers > 3:
        _raise_plan_validation(code="Plan has too many replan_after markers")
    # D5: Validate constraint definitions on tool_call steps
    for step in plan.steps:
        if step.type != "tool_call":
            continue
        errors = validate_constraint_definitions(
            step.allowed_commands,
            step.allowed_paths,
        )
        if errors:
            _raise_plan_validation(
                code="Step has invalid constraint definition",
                step_id=step.id,
                first_error_code=errors[0],
                error_count=len(errors),
            )

    # Validate assertion structure
    for step in plan.steps:
        for i, assertion in enumerate(step.assertions):
            if "assert" not in assertion:
                _raise_plan_validation(
                    code="Step assertion missing 'assert' key",
                    step_id=step.id,
                    assertion_index=i,
                )

    logger.debug(
        "validate_plan succeeded",
        extra={
            "event": "validate.plan_done",
            "step_count": len(plan.steps),
            "defined_vars_count": len(defined_vars),
        },
    )


def auto_infer_constraints(plan: Plan) -> None:
    """At TL4+, auto-infer constraints on tool_call steps if missing.

    The planner prompt instructs Claude to include constraints, but
    this isn't always followed. Rather than rejecting the plan, we
    derive constraints from the step's args deterministically.
    """
    if settings.trust_level < 4:
        logger.debug(
            "auto_infer_constraints skipped — trust level below 4",
            extra={
                "event": "auto.infer_constraints_skip",
                "trust_level": settings.trust_level,
            },
        )
        return
    for step in plan.steps:
        if step.type != "tool_call":
            continue
        has_constraints = (
            step.allowed_commands is not None or step.allowed_paths is not None
        )
        if has_constraints:
            continue
        inferred = infer_constraints(step)
        if inferred:
            if "allowed_commands" in inferred:
                step.allowed_commands = inferred["allowed_commands"]
            if "allowed_paths" in inferred:
                step.allowed_paths = inferred["allowed_paths"]
            logger.info(
                "Auto-inferred TL4 constraints for tool_call step",
                extra={
                    "event": "auto.inferred_constraints",
                    "step_id": step.id,
                    "tool": step.tool,
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

    logger.debug(
        "auto_infer_constraints done",
        extra={
            "event": "auto.infer_constraints_done",
            "step_count": len(plan.steps),
        },
    )


def log_plan_details(plan: Plan) -> None:
    """Log plan summary and per-step details for diagnostics.

    Emits an INFO-level summary (step count, types, IDs) followed by
    DEBUG-level detail for each step (prompts, tool args, variables).
    """
    logger.info(
        "Plan created",
        extra={
            "event": "plan.created",
            "plan_summary_len": (len(plan.plan_summary) if plan.plan_summary else 0),
            "plan_step_count": len(plan.steps),
            "step_types": [s.type for s in plan.steps],
            "step_ids": [s.id for s in plan.steps],
        },
    )
    for step in plan.steps:
        step_detail: dict = {
            "event": "plan.step_detail",
            "step_id": step.id,
            "step_type": step.type,
            "description": step.description,
        }
        if step.type == "llm_task" and step.prompt:
            step_detail["prompt_preview"] = step.prompt[:500]
        if step.type == "tool_call":
            step_detail["tool"] = step.tool
            step_detail["args_keys"] = list((step.args or {}).keys())
            # Show file-related args but not full content
            step_detail["args_preview"] = {
                k: v[:200] if isinstance(v, str) and len(v) > 200 else v
                for k, v in (step.args or {}).items()
                if k != "content"  # skip large content blobs
            }
        if step.input_vars:
            step_detail["input_vars"] = step.input_vars
        if step.output_var:
            step_detail["output_var"] = step.output_var
        logger.debug("Plan step detail", extra=step_detail)
