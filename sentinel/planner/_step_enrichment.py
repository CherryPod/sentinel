"""Step outcome builder — structured metadata for plan step results.

Constructs the F1 outcome dict that the planner uses to understand what
happened during each execution step. Enrichment functions attach structural
digests, execution flags, code analysis, and exec metadata.
"""

from __future__ import annotations

import logging

from sentinel.analysis.metadata_extractor import (
    compute_token_usage_ratio,
    extract_code_symbols,
    extract_complexity,
    extract_diff_stats,
    extract_stderr_preview,
)
from sentinel.core.models import (
    OutputDestination,
    PlanStep,
    StepResult,
)
from sentinel.crypto.blind_index import log_hash
from sentinel.security.code_extractor import extract_code_blocks

from ._error_context import genericise_error

logger = logging.getLogger(__name__)

_DIGEST_EXTENSIONS = frozenset({"html", "htm", "js", "mjs", "py", "css"})


def _enrich_structural_data(
    outcome: dict,
    step: PlanStep,
    result: StepResult,
    exec_meta: dict | None,
) -> None:
    """Attach structural digests and content manifests for the verification judge.

    Handles both single-file operations (file_write/file_patch — digest extracted
    from result.content) and website operations (digests/manifests pre-extracted
    at execution time and stored in exec_meta).
    """
    logger.debug(
        "_enrich_structural_data called",
        extra={
            "event": "enrich.structural_data_entry",
            "step_tool": step.tool or "",
            "has_exec_meta": exec_meta is not None,
            "has_content": bool(result.content),
        },
    )
    file_path = outcome.get("file_path")

    # Single-file structural digest — extract from content for supported extensions
    if file_path and result.content and step.tool in ("file_write", "file_patch"):
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        if ext in _DIGEST_EXTENSIONS:
            from sentinel.analysis.structural_digest import extract_structural_digest

            digest = extract_structural_digest(file_path, result.content, "")
            outcome["structural_digest"] = digest
            logger.debug(
                "step_outcome: structural digest attached for %s",
                log_hash(file_path),
                extra={
                    "event": "step.outcome_digest",
                    "file_path_hash": log_hash(file_path),
                    "file_path_len": len(file_path) if file_path else 0,
                },
            )

    # Website tool: digests extracted at execution time (result.content is a
    # status message, not file content). Read from exec_meta.
    if step.tool == "website" and exec_meta and exec_meta.get("structural_digests"):
        outcome["structural_digests"] = exec_meta["structural_digests"]
        logger.debug(
            "step_outcome: website structural digests attached — %d files",
            len(exec_meta["structural_digests"]),
            extra={
                "event": "step.outcome_digest_website",
                "file_count": len(exec_meta["structural_digests"]),
            },
        )

    # Content manifest — observable file properties for verification judge
    if exec_meta and exec_meta.get("content_manifest"):
        outcome["content_manifest"] = exec_meta["content_manifest"]
        logger.debug(
            "step_outcome: content manifest attached for %s",
            log_hash(file_path) or "(website)",
            extra={
                "event": "step.outcome_manifest",
                "file_path_hash": log_hash(file_path),
                "file_path_len": len(file_path) if file_path else 0,
                "language": exec_meta["content_manifest"].get("language"),
            },
        )

    # Website tool: manifests extracted at execution time
    if step.tool == "website" and exec_meta and exec_meta.get("content_manifests"):
        outcome["content_manifests"] = exec_meta["content_manifests"]
        logger.debug(
            "step_outcome: website content manifests attached — %d files",
            len(exec_meta["content_manifests"]),
            extra={
                "event": "step.outcome_manifest_website",
                "file_count": len(exec_meta["content_manifests"]),
            },
        )

    logger.debug(
        "_enrich_structural_data exit",
        extra={"event": "enrich.structural_data_exit", "step_tool": step.tool or ""},
    )


def _enrich_execution_flags(
    outcome: dict,
    step: PlanStep,
    result: StepResult,
    exec_meta: dict | None,
) -> None:
    """Attach execution flags: logging injection, structural removal, patch metadata, sandbox, constraints.

    These fields tell the planner about post-execution events (auto-fixes,
    resource limits, constraint outcomes) so it can adapt subsequent steps.
    """
    logger.debug(
        "_enrich_execution_flags called",
        extra={
            "event": "enrich.execution_flags_entry",
            "step_id": step.id,
            "step_type": step.type,
            "result_status": result.status,
            "has_exec_meta": exec_meta is not None,
        },
    )
    file_path = outcome.get("file_path")

    # Logging injection metadata (set by executor after inject_logging call)
    if exec_meta:
        if exec_meta.get("logging_injected"):
            outcome["logging_injected"] = True
            outcome["logging_injection_count"] = exec_meta.get(
                "logging_injection_count", 0
            )
            logger.debug(
                "step_outcome: logging injected — %d entry points in %s",
                exec_meta.get("logging_injection_count", 0),
                log_hash(file_path) or "?",
                extra={
                    "event": "step.outcome_logging_injected",
                    "file_path_hash": log_hash(file_path),
                    "file_path_len": len(file_path) if file_path else 0,
                    "count": exec_meta.get("logging_injection_count", 0),
                },
            )
        if exec_meta.get("structural_elements_removed"):
            outcome["structural_elements_removed"] = exec_meta[
                "structural_elements_removed"
            ]
            logger.warning(
                "step_outcome: structural elements removed — %s",
                exec_meta["structural_elements_removed"],
                extra={
                    "event": "step.outcome_elements_removed",
                    "file_path_hash": log_hash(file_path),
                    "file_path_len": len(file_path) if file_path else 0,
                    "removed": exec_meta["structural_elements_removed"],
                },
            )

    # file_patch metadata — patch operation details for planner history
    if exec_meta and step.tool == "file_patch":
        logger.debug(
            "_enrich_execution_flags: exec_meta",
            extra={
                "event": "builders._enrich_execution_flags.match",
                "reason": "exec_meta",
            },
        )  # auto:neg
        outcome["patch_operation"] = exec_meta.get("patch_operation")
        outcome["patch_anchor_length"] = exec_meta.get("patch_anchor_length")
        if "anchor_size_warning" in exec_meta:
            logger.debug(
                "_enrich_execution_flags: anchor_size_warning_in_exec_meta",
                extra={
                    "event": "builders._enrich_execution_flags.match",
                    "reason": "anchor_size_warning_in_exec_meta",
                },
            )  # auto:neg
            outcome["anchor_size_warning"] = exec_meta["anchor_size_warning"]

    # Sandbox termination flags — tells the planner whether the sandbox hit a
    # resource limit so it can replan (e.g. reduce scope or split the task).
    outcome["sandbox_timed_out"] = (
        exec_meta.get("timed_out", False) if exec_meta else False
    )
    outcome["sandbox_oom_killed"] = (
        exec_meta.get("oom_killed", False) if exec_meta else False
    )

    # D5: Constraint validation result for enriched planner history
    if step.type == "tool_call":
        if result.status == "blocked" and "denylist" in (result.error or "").lower():
            outcome["constraint_result"] = "denylist_block"
        elif (
            result.status == "blocked" and "constraint" in (result.error or "").lower()
        ):
            logger.debug(
                "_enrich_execution_flags: clean",
                extra={"event": "builders._enrich_execution_flags.branch.clean"},
            )
            outcome["constraint_result"] = "violation"
        elif step.allowed_commands is not None or step.allowed_paths is not None:
            logger.debug(
                "_enrich_execution_flags: clean",
                extra={"event": "builders._enrich_execution_flags.branch.clean"},
            )
            outcome["constraint_result"] = "validated"
        else:
            logger.debug(
                "_enrich_execution_flags: clean",
                extra={"event": "builders._enrich_execution_flags.branch.clean"},
            )
            outcome["constraint_result"] = "skipped"
        logger.debug(
            "_enrich_execution_flags constraint branch",
            extra={
                "event": "enrich.execution_flags_constraint",
                "step_id": step.id,
                "constraint_result": outcome["constraint_result"],
            },
        )

    logger.debug(
        "_enrich_execution_flags exit",
        extra={"event": "enrich.execution_flags_exit", "step_id": step.id},
    )


def _enrich_exec_metadata(
    outcome: dict,
    step: PlanStep,
    exec_meta: dict | None,
) -> None:
    """Add execution metadata fields: exit_code, stderr, file paths, sizes, diffs, code fixer, JS syntax.

    All data here is orchestrator-generated (TRUSTED). Populates outcome["file_path"]
    which downstream helpers depend on.
    """
    logger.debug(
        "_enrich_exec_metadata called",
        extra={
            "event": "enrich.exec_metadata_entry",
            "step_id": step.id,
            "step_tool": step.tool or "",
            "has_exec_meta": exec_meta is not None,
        },
    )
    # Shell exec metadata
    outcome["exit_code"] = (
        exec_meta.get("exit_code") if exec_meta and "exit_code" in exec_meta else None
    )
    # REVIEWED (B2 red team, 0 S0/S1): fed to planner (trusted), not Qwen.
    # Side-channel risk outside threat model.
    # F-02: raw preserved for audit (session store, red-team API);
    # consumer-side SP applied at each planner injection point.
    outcome["stderr_preview"] = (
        extract_stderr_preview(exec_meta.get("stderr"))
        if exec_meta and "stderr" in exec_meta
        else None
    )

    # File metadata — path derived from tool args for file operations
    outcome["file_path"] = (
        step.args.get("path")
        if step.tool in ("file_write", "file_read", "file_patch")
        else None
    )

    # Tool-specific metadata — surface identifiers from tool outputs so the
    # planner can reference prior outputs (e.g. reuse a website site_id).
    # All data here is orchestrator-generated (TRUSTED), not Qwen output.
    if exec_meta and step.tool == "website":
        logger.debug(
            "_enrich_exec_metadata: exec_meta",
            extra={
                "event": "builders._enrich_exec_metadata.match",
                "reason": "exec_meta",
            },
        )  # auto:neg
        outcome["site_id"] = exec_meta.get("site_id")
        outcome["site_url"] = exec_meta.get("url")
        outcome["site_files"] = exec_meta.get("filenames")  # list of deployed filenames

    # REVIEWED (B2 red team, 0 S0/S1): fed to planner (trusted), not Qwen.
    # Side-channel risk outside threat model.
    outcome["file_size_before"] = (
        exec_meta.get("file_size_before") if exec_meta else None
    )
    outcome["file_size_after"] = exec_meta.get("file_size_after") if exec_meta else None

    # Diff stats for file_write / file_patch
    if (
        exec_meta
        and "file_content_before" in exec_meta
        and step.tool in ("file_write", "file_patch")
    ):
        logger.debug(
            "_enrich_exec_metadata: exec_meta",
            extra={
                "event": "builders._enrich_exec_metadata.match",
                "reason": "exec_meta",
            },
        )  # auto:neg
        after_content = step.args.get("content", "")
        outcome["diff_stats"] = extract_diff_stats(
            exec_meta.get("file_content_before"), after_content
        )
    else:
        logger.debug(
            "_enrich_exec_metadata: exec_meta",
            extra={
                "event": "builders._enrich_exec_metadata.clean",
                "reason": "exec_meta",
            },
        )  # auto:neg
        outcome["diff_stats"] = None

    # Code fixer metadata — deterministic fixer output (TRUSTED), not Qwen text.
    # Tells the planner whether content was auto-corrected before writing.
    outcome["code_fixer_changed"] = (
        exec_meta.get("code_fixer_changed", False) if exec_meta else False
    )
    outcome["code_fixer_fixes"] = (
        exec_meta.get("code_fixer_fixes", []) if exec_meta else []
    )
    outcome["code_fixer_errors"] = (
        exec_meta.get("code_fixer_errors", []) if exec_meta else []
    )

    # JS syntax validation — use code fixer errors as proxy
    # (code fixer already processes every JS file Qwen writes)
    file_path = outcome.get("file_path")
    if exec_meta and file_path:
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        if ext in ("js", "mjs") and "code_fixer_errors" in exec_meta:
            code_fixer_errors = exec_meta.get("code_fixer_errors", [])
            outcome["syntax_valid"] = len(code_fixer_errors) == 0
            if code_fixer_errors:
                logger.info(
                    "step_outcome: JS syntax_valid=False for %s — %d unfixable errors",
                    log_hash(file_path),
                    len(code_fixer_errors),
                    extra={
                        "event": "step.outcome_js_syntax_invalid",
                        "file_path_hash": log_hash(file_path),
                        "file_path_len": len(file_path) if file_path else 0,
                        "error_count": len(code_fixer_errors),
                    },
                )

    logger.debug(
        "_enrich_exec_metadata exit",
        extra={"event": "enrich.exec_metadata_exit", "step_id": step.id},
    )


def _enrich_code_analysis(outcome: dict, step: PlanStep, result: StepResult) -> None:
    """Add code-analysis fields for llm_task steps that produced code.

    Extracts code blocks from worker output, checks Python syntax validity,
    and computes AST symbols + cyclomatic complexity from the first block.
    Only fires for llm_task steps with non-empty content.
    """
    logger.debug(
        "_enrich_code_analysis called",
        extra={
            "event": "enrich.code_analysis_entry",
            "step_type": step.type,
            "has_content": bool(result.content),
        },
    )
    if step.type != "llm_task" or not result.content:
        logger.debug(
            "_enrich_code_analysis skipped — not llm_task or no content",
            extra={
                "event": "enrich.code_analysis_skip",
                "step_type": step.type,
                "has_content": bool(result.content),
            },
        )
        return
    logger.debug(
        "_enrich_code_analysis: type_noteq_llm_task_passed",
        extra={
            "event": "enrich.code_analysis_skip.passed",
            "reason": "type_noteq_llm_task_passed",
        },
    )  # auto:neg

    code_blocks = extract_code_blocks(result.content)
    if not code_blocks:
        logger.debug(
            "_enrich_code_analysis skipped — no code blocks found",
            extra={"event": "enrich.code_analysis_no_blocks"},
        )
        return

    logger.debug(
        "step_outcome: code analysis — %d blocks, first lang=%s",
        len(code_blocks),
        code_blocks[0].language,
        extra={
            "event": "step.outcome_code_analysis",
            "block_count": len(code_blocks),
            "first_language": code_blocks[0].language,
        },
    )

    outcome["output_language"] = code_blocks[0].language

    # Syntax validity: Python only in F1
    if code_blocks[0].language == "python":
        import ast as _ast

        try:
            _ast.parse(code_blocks[0].code)
            outcome["syntax_valid"] = True
        except (SyntaxError, MemoryError, RecursionError, ValueError) as exc:
            logger.debug(
                "step_outcome: Python syntax invalid",
                extra={
                    "event": "step.outcome_python_syntax_invalid",
                    "error": str(exc),
                },
            )
            outcome["syntax_valid"] = False

    # AST symbols + complexity from first code block
    symbols = extract_code_symbols(code_blocks[0].code, code_blocks[0].language or "")
    outcome["defined_symbols"] = symbols["defined_symbols"]
    outcome["imports"] = symbols["imports"]
    complexity = extract_complexity(code_blocks[0].code, code_blocks[0].language or "")
    outcome["complexity_max"] = complexity["complexity_max"]
    outcome["complexity_function"] = complexity["complexity_function"]


def build_step_outcome(
    step: PlanStep,
    result: StepResult,
    elapsed_s: float,
    destination: OutputDestination | None = None,
    exec_meta: dict | None = None,
) -> dict:
    """Build a structured outcome dict for one plan step.

    All data here is orchestrator-generated (TRUSTED). No Qwen
    conversational text crosses the privacy boundary.
    """
    # Base fields (always present)
    logger.debug(
        "build_step_outcome called",
        extra={
            "event": "builders.build_step_outcome",
            "step_type": type(step).__name__,
            "result_content_len": len(result.content) if result.content else 0,
            "elapsed_s": elapsed_s,
        },
    )  # auto:entry
    outcome: dict = {
        "step_type": step.type,
        "description": step.description,
        "tool": step.tool or "",
        "status": result.status,
        # REVIEWED (B2 red team, 0 S0/S1): fed to planner (trusted), not Qwen.
        # Side-channel risk outside threat model.
        "output_size": len(result.content) if result.content else 0,
        "duration_s": round(elapsed_s, 2),
        "error_detail": genericise_error(result.error),
        "destination": destination.value if destination else None,
    }

    # Code analysis — language detection, syntax validity, symbols, complexity
    _enrich_code_analysis(outcome, step, result)

    # Scanner result — binary only (blocked/clean).
    # scanner_details intentionally removed: exposing scanner name +
    # triggering pattern helps an adversary learn defence rules.
    if result.status == "blocked" and result.error:
        outcome["scanner_result"] = "blocked"
    else:
        outcome["scanner_result"] = "clean"

    # Quality warnings (R7)
    if result.quality_warnings:
        logger.debug(
            "build_step_outcome: quality_warnings",
            extra={
                "event": "builders.build_step_outcome.match",
                "reason": "quality_warnings",
            },
        )  # auto:neg
        outcome["quality_warnings"] = result.quality_warnings

    # Token usage ratio
    outcome["token_usage_ratio"] = compute_token_usage_ratio(result.worker_usage)

    # Execution metadata — exit_code, stderr, file paths, sizes, diffs, code fixer, JS syntax
    _enrich_exec_metadata(outcome, step, exec_meta)

    # Structural digests and content manifests for verification judge
    _enrich_structural_data(outcome, step, result, exec_meta)

    # Execution flags — logging injection, patch metadata, sandbox, constraints
    _enrich_execution_flags(outcome, step, result, exec_meta)

    return outcome
