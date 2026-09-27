"""Tool constraint validation — S4 enforcement for resolved arguments.

Security-critical: validate_constraints() enforces S4 — constraint validation
on RESOLVED args. This MUST be called AFTER context.resolve_args() and BEFORE
tool dispatch. The ordering is a security invariant.

Constants for content-creation tool classification are also defined here,
shared by check_provenance() in tool_dispatch.py.
"""

from __future__ import annotations

import logging
from functools import partial
from typing import Any

from sentinel.audit.events import SecurityAuditEvent
from sentinel.core.models import PlanStep, StepResult
from sentinel.crypto.blind_index import log_hash
from sentinel.planner._command_shape import _ALLOWED_COMMAND_PREFIXES
from sentinel.security._log_shape import (
    canonical_set_hash,
    command_shape,
    path_shape,
    shape_counts,
)

logger = logging.getLogger(__name__)

# Content-creation tools: Qwen's output IS the content authored to a display-bound,
# approval-gated sink (web page body, message body, calendar event description).
# Exempt from the S3 provenance gate because the output is displayed to a human
# reviewer, not consumed by system execution. Per-tool approval gate, output scan
# (S5), and per-channel allowlists remain in force for every member.
CONTENT_CREATION_TOOLS = frozenset(
    {
        "website",
        "signal_send",
        "telegram_send",
        "email_send",
        "email_draft",
        "matrix_send",
        "calendar_create_event",  # Q2-FL1 — free-text summary/location/description
        "calendar_update_event",  # Q2-FL1 — sibling, identical risk profile
    }
)

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


async def validate_constraints(
    step: PlanStep,
    resolved_args: dict[str, Any],
    trust_level: int,
    audit_emitter: Any | None = None,
) -> StepResult | None:
    """Validate resolved args against plan-policy constraints (TL4+).

    Three-tier validation: static denylist, command constraints, path constraints.
    Returns None if allowed, StepResult(blocked) if not.
    Enforces S4: this MUST be called AFTER context.resolve_args() and BEFORE tool dispatch.
    """
    logger.debug(
        "validate_constraints called",
        extra={
            "event": "validate.constraints",
            "step_id": step.id,
            "tool": step.tool,
            "trust_level": trust_level,
            "has_allowed_commands": step.allowed_commands is not None,
            "has_allowed_paths": step.allowed_paths is not None,
        },
    )
    if trust_level < 4:
        logger.debug(
            "validate_constraints skipped — trust_level below 4",
            extra={
                "event": "validate.constraints_skip",
                "step_id": step.id,
                "tool": step.tool,
                "trust_level": trust_level,
            },
        )
        return None

    from sentinel.security.constraint_validator import (
        _normalise_path,
        check_denylist,
        validate_command_constraints,
        validate_path_constraints,
    )

    # shell / shell_exec: validate resolved command.
    # Both names dispatch to the same underlying `_shell` handler via the executor
    # alias map (tools/executor.py:145). Planner prompt examples teach `"shell"`
    # (_prompts/_sections/examples.py:90,174); the older `"shell_exec"` spelling
    # is preserved as an alias. S4 must enforce on both, otherwise a `"shell"`
    # step with `allowed_commands` silently bypasses the command allowlist while
    # still riding the constraint-gated provenance bypass at tool_dispatch.py:113.
    if step.tool in ("shell", "shell_exec") and "command" in resolved_args:
        resolved_cmd = resolved_args["command"]

        # Tier 1: Static denylist (constitutional)
        denylist_hit = check_denylist(resolved_cmd)
        if denylist_hit:
            logger.warning(
                "Command blocked by constitutional denylist",
                extra={
                    "event": "denylist.block",
                    "step_id": step.id,
                    "pattern_name": denylist_hit.pattern_name,
                    "command_shape": command_shape(resolved_cmd, _ALLOWED_COMMAND_PREFIXES),
                    "command_hash": log_hash(resolved_cmd),
                    "command_len": len(resolved_cmd) if resolved_cmd else 0,
                },
            )
            if audit_emitter is not None:
                await audit_emitter.emit(
                    SecurityAuditEvent(
                        event_type="trust.constraint_check",
                        source_component="tool_dispatch",
                        outcome="BLOCKED",
                        severity="HIGH",
                        details={
                            "step_id": step.id,
                            "tool": step.tool,
                            "constraint_type": "denylist",
                            "constitutional": True,
                            "pattern_name": denylist_hit.pattern_name,
                        },
                    )
                )
            return StepResult(
                step_id=step.id,
                status="blocked",
                error=f"Blocked by constitutional denylist: {denylist_hit.pattern_name}",
            )
        logger.debug(
            "Denylist check clean — command allowed",
            extra={
                "event": "denylist.clean",
                "step_id": step.id,
                "command_length": len(resolved_cmd),
            },
        )

        # Tier 2: Plan-constraint validation
        cmd_result = validate_command_constraints(
            resolved_cmd,
            step.allowed_commands,
        )
        if not cmd_result.skipped:
            if cmd_result.allowed:
                logger.info(
                    "Command validated against plan constraint",
                    extra={
                        "event": "constraint.validated",
                        "step_id": step.id,
                        "tool": step.tool,
                        "command_shape": command_shape(resolved_cmd, _ALLOWED_COMMAND_PREFIXES),
                        "command_hash": log_hash(resolved_cmd),
                        "command_len": len(resolved_cmd) if resolved_cmd else 0,
                        "matched_constraint_shape": command_shape(
                            cmd_result.matched_constraint, _ALLOWED_COMMAND_PREFIXES
                        ),
                        "matched_constraint_hash": log_hash(cmd_result.matched_constraint),
                        "matched_constraint_len": (
                            len(cmd_result.matched_constraint)
                            if cmd_result.matched_constraint else 0
                        ),
                    },
                )
                if audit_emitter is not None:
                    await audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="trust.constraint_check",
                            source_component="tool_dispatch",
                            outcome="CLEAN",
                            details={
                                "step_id": step.id,
                                "tool": step.tool,
                                "constraint_type": "command",
                                "matched_constraint_shape": command_shape(
                                    cmd_result.matched_constraint, _ALLOWED_COMMAND_PREFIXES
                                ),
                                "matched_constraint_hash": log_hash(cmd_result.matched_constraint),
                                "matched_constraint_len": (
                                    len(cmd_result.matched_constraint)
                                    if cmd_result.matched_constraint else 0
                                ),
                            },
                        )
                    )
            else:
                logger.warning(
                    "Command violates plan constraints",
                    extra={
                        "event": "constraint.violation",
                        "step_id": step.id,
                        "tool": step.tool,
                        "command_shape": command_shape(resolved_cmd, _ALLOWED_COMMAND_PREFIXES),
                        "command_hash": log_hash(resolved_cmd),
                        "command_len": len(resolved_cmd) if resolved_cmd else 0,
                        "allowed_commands_count": (
                            len(step.allowed_commands) if step.allowed_commands else 0
                        ),
                        "allowed_commands_hash": canonical_set_hash(step.allowed_commands),
                        "allowed_command_shape_counts": shape_counts(
                            step.allowed_commands,
                            partial(command_shape, allowed_prefixes=_ALLOWED_COMMAND_PREFIXES),
                        ),
                        "reason": cmd_result.reason,
                    },
                )
                if audit_emitter is not None:
                    await audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="trust.constraint_check",
                            source_component="tool_dispatch",
                            outcome="BLOCKED",
                            severity="MEDIUM",
                            details={
                                "step_id": step.id,
                                "tool": step.tool,
                                "constraint_type": "command",
                                "reason": cmd_result.reason,
                            },
                        )
                    )
                return StepResult(
                    step_id=step.id,
                    status="blocked",
                    error=f"Command constraint violation: {cmd_result.reason}",
                )

    # file_write / file_read / file_patch / mkdir: validate resolved path.
    # file_patch writes files — same path constraint validation as file_write/file_read.
    # mkdir is included because _plan_validator.infer_constraints auto-infers
    # allowed_paths for mkdir at TL4+ (sentinel/planner/_plan_validator.py:70-91);
    # without mkdir here the inferred allowlist is inert.
    # PolicyEngine also validates at dispatch time (defence-in-depth, not sole gate).
    if (
        step.tool in ("file_write", "file_read", "file_patch", "mkdir")
        and "path" in resolved_args
    ):
        path_result = validate_path_constraints(
            resolved_args["path"],
            step.allowed_paths,
        )
        if not path_result.skipped:
            # path_hash/path_len use the normalised form to match constraint_validator.path_blocked;
            # path_shape intentionally keeps the raw form to describe what arrived.
            _path_for_log = _normalise_path(resolved_args["path"])
            if path_result.allowed:
                logger.info(
                    "Path validated against plan constraint",
                    extra={
                        "event": "constraint.validated",
                        "step_id": step.id,
                        "tool": step.tool,
                        "path_shape": path_shape(resolved_args["path"]),
                        "path_hash": log_hash(_path_for_log),
                        "path_len": len(_path_for_log) if _path_for_log else 0,
                        "matched_constraint_shape": path_shape(path_result.matched_constraint),
                        "matched_constraint_hash": log_hash(path_result.matched_constraint),
                        "matched_constraint_len": (
                            len(path_result.matched_constraint)
                            if path_result.matched_constraint else 0
                        ),
                    },
                )
                if audit_emitter is not None:
                    await audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="trust.constraint_check",
                            source_component="tool_dispatch",
                            outcome="CLEAN",
                            details={
                                "step_id": step.id,
                                "tool": step.tool,
                                "constraint_type": "path",
                                "matched_constraint_shape": path_shape(path_result.matched_constraint),
                                "matched_constraint_hash": log_hash(path_result.matched_constraint),
                                "matched_constraint_len": (
                                    len(path_result.matched_constraint)
                                    if path_result.matched_constraint else 0
                                ),
                            },
                        )
                    )
            else:
                logger.warning(
                    "Path violates plan constraints",
                    extra={
                        "event": "constraint.violation",
                        "step_id": step.id,
                        "tool": step.tool,
                        "path_shape": path_shape(resolved_args["path"]),
                        "path_hash": log_hash(_path_for_log),
                        "path_len": len(_path_for_log) if _path_for_log else 0,
                        "allowed_paths_count": (
                            len(step.allowed_paths) if step.allowed_paths else 0
                        ),
                        "allowed_paths_hash": canonical_set_hash(step.allowed_paths),
                        "allowed_path_shape_counts": shape_counts(
                            step.allowed_paths, path_shape
                        ),
                        "reason": path_result.reason,
                    },
                )
                if audit_emitter is not None:
                    await audit_emitter.emit(
                        SecurityAuditEvent(
                            event_type="trust.constraint_check",
                            source_component="tool_dispatch",
                            outcome="BLOCKED",
                            severity="MEDIUM",
                            details={
                                "step_id": step.id,
                                "tool": step.tool,
                                "constraint_type": "path",
                                "reason": path_result.reason,
                            },
                        )
                    )
                return StepResult(
                    step_id=step.id,
                    status="blocked",
                    error=f"Path constraint violation: {path_result.reason}",
                )

    logger.debug(
        "validate_constraints passed — all constraints satisfied",
        extra={
            "event": "validate.constraints_pass",
            "step_id": step.id,
            "tool": step.tool,
        },
    )
    # Emit CLEAN only when no specific constraint checks ran (no command/path
    # validation). If a specific check ran, it already emitted its own event.
    ran_specific_check = (
        step.tool in ("shell", "shell_exec") and "command" in resolved_args
    ) or (
        step.tool in ("file_write", "file_read", "file_patch", "mkdir")
        and "path" in resolved_args
    )
    if audit_emitter is not None and trust_level >= 4 and not ran_specific_check:
        await audit_emitter.emit(
            SecurityAuditEvent(
                event_type="trust.constraint_check",
                source_component="tool_dispatch",
                outcome="CLEAN",
                details={
                    "step_id": step.id,
                    "tool": step.tool,
                    "constraint_type": "none",
                },
            )
        )
    return None
