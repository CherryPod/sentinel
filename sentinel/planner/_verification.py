"""VerificationMixin — goal verification and judge logic for the orchestrator.

Extracted from orchestrator.py during Phase 5 structural refactor.
Contains the planner-as-judge (Tier 2) verification pipeline:
  - _should_invoke_judge (module-level decision function)
  - VerificationMixin._evaluate_task_assertions
  - VerificationMixin._invoke_judge
  - VerificationMixin._attempt_judge_replan
"""

from __future__ import annotations

import asyncio
import logging

from sentinel.analysis.structural_digest import cross_reference_check
from sentinel.core.config import settings
from sentinel.core.models import Plan, TaskResult
from sentinel.core.workspace import get_user_workspace
from sentinel.crypto.blind_index import log_hash
from sentinel.planner.verification import (
    AssertionResult,
    build_judge_payload,
    classify_task_category,
    evaluate_assertions_async,
    process_judge_verdict,
)

from ._task_context import TaskContext
from .planner import PlannerError, PlannerRefusalError

logger = logging.getLogger(__name__)


def _should_invoke_judge(
    result: TaskResult,
    task_category: str,
    assertions_defined: int = 0,
    cross_ref_warnings: list[dict] | None = None,
) -> bool:
    """Decide whether to invoke the planner-as-judge (Tier 2).

    Decision matrix:
    - Any Tier 1 RED signal (partial/abandoned) → skip (conclusive)
    - Deterministic + assertions defined & pass → skip
    - Structural + assertions defined & pass → skip
    - Semantic → always invoke
    - Structural + assertions fail → invoke (judge arbitrates)
    - No assertions defined + not deterministic → invoke (no evidence)
    - Tool output warnings present → invoke (something looked off)
    - Cross-reference warnings present → invoke (structural inconsistency)
    """
    # Tier 1 RED: conclusive, no judge needed
    if result.completion in ("partial", "abandoned"):
        if cross_ref_warnings:
            logger.debug(
                "Judge gate: SKIP (Tier 1 RED) — but %d cross-ref warning(s) "
                "present (logged for diagnostics)",
                len(cross_ref_warnings),
                extra={
                    "event": "verification.judge_gate_skip",
                    "reason": "tier1_red",
                    "completion": result.completion,
                    "cross_ref_warning_count": len(cross_ref_warnings),
                },
            )
        else:
            logger.debug(
                "Judge gate: SKIP — Tier 1 RED (completion=%s)",
                result.completion,
                extra={
                    "event": "verification.judge_gate_skip",
                    "reason": "tier1_red",
                    "completion": result.completion,
                },
            )
        return False
    logger.debug(
        "_should_invoke_judge: completion_in_passed",
        extra={
            "event": "verification.judge_gate_skip.passed",
            "reason": "completion_in_passed",
        },
    )  # auto:neg
    if result.status != "success":
        logger.debug(
            "Judge gate: SKIP — non-success status (%s)",
            result.status,
            extra={
                "event": "verification.judge_gate_skip",
                "reason": "non_success",
                "status": result.status,
            },
        )
        return False
    logger.debug(
        "_should_invoke_judge: status_noteq_success_passed",
        extra={
            "event": "verification.judge_gate_skip.passed",
            "reason": "status_noteq_success_passed",
        },
    )  # auto:neg

    # Semantic tasks always need the judge
    if task_category == "semantic":
        logger.debug(
            "Judge gate: INVOKE — semantic task always needs judge",
            extra={
                "event": "verification.judge_gate_invoke",
                "reason": "semantic_always",
            },
        )
        return True
    logger.debug(
        "_should_invoke_judge: task_category_eq_semantic_passed",
        extra={
            "event": "verification.judge_gate_invoke.passed",
            "reason": "task_category_eq_semantic_passed",
        },
    )  # auto:neg

    # Tool output warnings present — something looked off, invoke judge
    if result.tool_output_warnings:
        logger.debug(
            "Judge gate: INVOKE — %d tool output warning(s) detected",
            len(result.tool_output_warnings),
            extra={
                "event": "verification.judge_gate_invoke",
                "reason": "tool_output_warnings",
                "warning_count": len(result.tool_output_warnings),
            },
        )
        return True
    logger.debug(
        "_should_invoke_judge: tool_output_warnings_passed",
        extra={
            "event": "verification.judge_gate_invoke.passed",
            "reason": "tool_output_warnings_passed",
        },
    )  # auto:neg

    # Cross-reference warnings — structural inconsistencies across files
    if cross_ref_warnings:
        logger.debug(
            "Judge gate: INVOKE — %d cross-reference warning(s)",
            len(cross_ref_warnings),
            extra={
                "event": "verification.judge_gate_invoke",
                "reason": "cross_ref_warnings",
                "warning_count": len(cross_ref_warnings),
                "types": [w["type"] for w in cross_ref_warnings],
            },
        )
        return True
    logger.debug(
        "Judge gate: cross-references clean",
        extra={
            "event": "verification.judge_gate_cross_ref_clean",
        },
    )

    # Structural with failed assertions: judge arbitrates
    if task_category == "structural" and result.assertion_failures:
        logger.debug(
            "Judge gate: INVOKE — structural task with %d assertion failure(s)",
            len(result.assertion_failures),
            extra={
                "event": "verification.judge_gate_invoke",
                "reason": "structural_assertion_fail",
            },
        )
        return True
    logger.debug(
        "_should_invoke_judge: task_category_eq_structural_passed",
        extra={
            "event": "verification.judge_gate_invoke.passed",
            "reason": "task_category_eq_structural_passed",
        },
    )  # auto:neg

    # No assertions defined → no evidence of success beyond Tier 1 signals.
    # Deterministic tasks can skip (specific values are verifiable by assertions
    # if the planner generated them; if not, the task is simple enough).
    # Structural/other tasks without assertions need the judge.
    if assertions_defined == 0:
        if task_category == "deterministic":
            logger.debug(
                "Judge gate: SKIP — deterministic task, no assertions needed",
                extra={
                    "event": "verification.judge_gate_skip",
                    "reason": "deterministic_no_assertions",
                },
            )
            return False
        logger.debug(
            "Judge gate: INVOKE — %s task with no assertions defined (no evidence)",
            task_category,
            extra={
                "event": "verification.judge_gate_invoke",
                "reason": "no_assertions_defined",
                "category": task_category,
            },
        )
        return True
    logger.debug(
        "_should_invoke_judge: assertions_defined_eq_0_passed",
        extra={
            "event": "verification.judge_gate_skip.passed",
            "reason": "assertions_defined_eq_0_passed",
        },
    )  # auto:neg

    # Assertions were defined and none failed → confident
    if not result.assertion_failures:
        logger.debug(
            "Judge gate: SKIP — %d assertion(s) defined, all passed",
            assertions_defined,
            extra={
                "event": "verification.judge_gate_skip",
                "reason": "assertions_passed",
                "assertions_defined": assertions_defined,
            },
        )
        return False

    # Default: invoke
    logger.debug(
        "Judge gate: INVOKE — default fallthrough",
        extra={"event": "verification.judge_gate_invoke", "reason": "default"},
    )
    return True


# Expected keys in a well-formed judge verdict.
_JUDGE_VERDICT_REQUIRED_KEYS = {"GOAL_MET", "CONFIDENCE"}
_JUDGE_VERDICT_VALID_GOAL_MET = {"yes", "no", "partial", "UNKNOWN"}
_JUDGE_VERDICT_VALID_CONFIDENCE = {"high", "medium", "low"}


def _validate_judge_verdict(raw: object) -> dict:
    """Coerce raw planner output into a safe verdict dict.

    The planner may return malformed JSON (string, None, list, or a dict
    missing expected keys).  This function normalises the output so
    downstream code never KeyErrors or crashes on unexpected types.

    Returns a dict that always has GOAL_MET and CONFIDENCE keys.
    """
    if not isinstance(raw, dict):
        logger.warning(
            "Judge verdict is not a dict — coercing to UNKNOWN",
            extra={
                "event": "verification.judge.invalid_type",
                "raw_type": type(raw).__name__,
            },
        )
        return {
            "GOAL_MET": "UNKNOWN",
            "CONFIDENCE": "low",
            "error": "invalid_verdict_type",
        }

    # Ensure required keys exist with valid values
    missing = _JUDGE_VERDICT_REQUIRED_KEYS - raw.keys()
    if missing:
        logger.warning(
            "Judge verdict missing required keys: %s — defaulting to safe values",
            missing,
            extra={
                "event": "verification.judge.missing_keys",
                "missing_keys": sorted(missing),
            },
        )
        raw = {**raw}  # shallow copy to avoid mutating caller's dict
        raw.setdefault("GOAL_MET", "UNKNOWN")
        raw.setdefault("CONFIDENCE", "low")

    # Validate enum values — unknown values default to conservative choice
    if raw.get("GOAL_MET") not in _JUDGE_VERDICT_VALID_GOAL_MET:
        logger.warning(
            "Judge verdict has unexpected GOAL_MET=%r — coercing to UNKNOWN",
            raw["GOAL_MET"],
            extra={
                "event": "verification.judge.invalid_goal_met",
                "raw_value": str(raw["GOAL_MET"])[:50],
            },
        )
        raw = {**raw, "GOAL_MET": "UNKNOWN"}

    if raw.get("CONFIDENCE") not in _JUDGE_VERDICT_VALID_CONFIDENCE:
        logger.warning(
            "Judge verdict has unexpected CONFIDENCE=%r — coercing to low",
            raw["CONFIDENCE"],
            extra={
                "event": "verification.judge.invalid_confidence",
                "raw_value": str(raw["CONFIDENCE"])[:50],
            },
        )
        raw = {**raw, "CONFIDENCE": "low"}

    return raw


def _collect_all_assertions(
    result: TaskResult,
    plan: Plan,
) -> list[dict]:
    """Collect assertions from all plan phases (initial + continuations).

    The local plan only holds the initial plan; continuation steps
    (and their assertions) live in result.plan_phases.  Falls back to
    the initial plan for single-phase tasks with no plan_phases yet.

    Args:
        result: The TaskResult with plan_phases populated by execution.
        plan: The initial Plan (has .steps and .assertions).

    Returns:
        Flat list of assertion dicts from all phases.
    """
    all_assertions: list[dict] = []
    for phase in result.plan_phases:
        phase_plan = phase.get("plan", {})
        for pstep_dict in phase_plan.get("steps", []):
            all_assertions.extend(pstep_dict.get("assertions", []))
        all_assertions.extend(phase_plan.get("assertions", []))
    # Single-phase tasks: assertions not yet captured in plan_phases
    if not result.plan_phases:
        logger.debug(
            "_collect_all_assertions: not_plan_phases",
            extra={
                "event": "_verification._collect_all_assertions.match",
                "reason": "not_plan_phases",
            },
        )  # auto:neg
        for pstep in plan.steps:
            all_assertions.extend(pstep.assertions)
        all_assertions.extend(plan.assertions)

    if all_assertions:
        logger.debug(
            "Collected %d assertion(s) from %d plan phase(s)",
            len(all_assertions),
            max(len(result.plan_phases), 1),
            extra={
                "event": "verification.collect_assertions",
                "total": len(all_assertions),
                "phase_count": max(len(result.plan_phases), 1),
            },
        )
    else:
        logger.debug(
            "No assertions defined by planner — judge may be needed "
            "for non-deterministic tasks",
            extra={"event": "verification.no_assertions_defined"},
        )

    return all_assertions


_WORKSPACE_FALLBACK = "/workspace"


def _resolve_evaluation_context(
    ctx: TaskContext,
    all_assertions: list[dict],
) -> tuple[str, dict[str, str]]:
    """Resolve workspace root and before_hashes for assertion evaluation.

    Args:
        ctx: The task context with task_exec_context for file hashes.
        all_assertions: Collected assertions (used to warn about
            content_changed when before_hashes is empty).

    Returns:
        (workspace_root, before_hashes) tuple.
    """
    # Resolve user-scoped workspace path
    try:
        ws_root = str(get_user_workspace())
    except ValueError:
        logger.debug(
            "Workspace resolution failed — using fallback",
            extra={"event": "verification.workspace_fallback"},
        )
        ws_root = _WORKSPACE_FALLBACK

    # Read before_hashes from per-task context (populated during
    # file_read execution via TaskExecutionContext).  Falls back to
    # empty dict when context is unavailable (backwards-compatible).
    before_hashes = (
        dict(ctx.task_exec_context.file_hashes)
        if ctx.task_exec_context is not None
        else {}
    )
    if before_hashes:
        logger.debug(
            "before_hashes from executor: %d files",
            len(before_hashes),
            extra={
                "event": "verification.before_hashes_captured",
                "count": len(before_hashes),
                "paths": list(before_hashes.keys()),
            },
        )
    else:
        logger.warning(
            "before_hashes empty — no file_read hashes captured "
            "during execution; content_changed assertions will "
            "fall back to skip",
            extra={
                "event": "verification.before_hashes_empty",
                "has_content_changed": "content_changed"
                in [a.get("assert") for a in all_assertions],
            },
        )

    return ws_root, before_hashes


def _apply_assertion_results(
    result: TaskResult,
    assertion_results: list[AssertionResult],
    task_id: str,
    loop_label: str,
) -> None:
    """Process assertion results: log breakdown, build failure list, downgrade status.

    Mutates result in-place:
    - Sets result.assertion_failures from failed assertion results
    - Downgrades result.status and result.completion to 'partial' if any fail

    Args:
        result: The TaskResult to update.
        assertion_results: List of AssertionResult objects from evaluate_assertions_async.
        task_id: For logging context.
        loop_label: For logging context.
    """
    passed_results = [r for r in assertion_results if r.passed]
    failed_results = [r for r in assertion_results if not r.passed]
    logger.debug(
        "Assertion evaluation complete — %d/%d passed, %d failed",
        len(passed_results),
        len(assertion_results),
        len(failed_results),
        extra={
            "event": "verification.assertion_eval_complete",
            "task_id": task_id,
            "total": len(assertion_results),
            "passed": len(passed_results),
            "failed": len(failed_results),
            "failed_details": [
                {
                    "type": r.assertion_type,
                    "path_hash": log_hash(r.path),
                    "path_len": len(r.path) if r.path else 0,
                    "message_len": len(r.message) if r.message else 0,
                }
                for r in failed_results
            ],
            "passed_types": [r.assertion_type for r in passed_results],
            "attempt": loop_label,
        },
    )

    result.assertion_failures = [
        {
            "type": r.assertion_type,
            "path": r.path,
            "passed": r.passed,
            "message": r.message,
            "recovery": r.recovery,
        }
        for r in assertion_results
        if not r.passed
    ]

    # Assertion failure is conclusive → mark partial
    if result.assertion_failures and result.completion == "full":
        logger.debug(
            "Assertion failure causing status downgrade: "
            "status=%s→partial, completion=%s→partial — "
            "this will trigger loop retry",
            result.status,
            result.completion,
            extra={
                "event": "verification.assertion_status_downgrade",
                "task_id": task_id,
                "status_before": result.status,
                "status_after": "partial",
                "completion_before": result.completion,
                "completion_after": "partial",
                "failure_count": len(result.assertion_failures),
                "failure_types": [f["type"] for f in result.assertion_failures],
                "attempt": loop_label,
            },
        )
        result.completion = "partial"
        result.status = "partial"
        logger.info(
            "Assertion failure(s) detected — marking partial",
            extra={
                "event": "verification.assertion_failure",
                "failures": len(result.assertion_failures),
                "task_id": task_id,
                "attempt": loop_label,
            },
        )


class VerificationMixin:
    """Goal verification and planner-as-judge methods for the Orchestrator."""

    async def _evaluate_task_assertions(
        self, ctx: TaskContext, loop_label: str
    ) -> None:
        """Collect and evaluate assertions from all plan phases.

        Modifies ctx.result.assertion_failures and may downgrade
        ctx.result.status/completion to 'partial' on failure.
        """
        result = ctx.result
        all_assertions = _collect_all_assertions(result, ctx.plan)

        if all_assertions and result.completion == "full":
            ws_root, before_hashes = _resolve_evaluation_context(ctx, all_assertions)

            # Log which assertion types are about to be evaluated
            assertion_types = [a.get("assert", "unknown") for a in all_assertions]
            has_content_changed = "content_changed" in assertion_types
            logger.debug(
                "Assertion evaluation starting — types=%s, "
                "content_changed_present=%s, before_hashes_count=%d, "
                "workspace_root=%s, completion=%s, status=%s",
                assertion_types,
                has_content_changed,
                len(before_hashes),
                ws_root,
                result.completion,
                result.status,
                extra={
                    "event": "verification.assertion_eval_pre",
                    "task_id": ctx.task_id,
                    "assertion_types": assertion_types,
                    "content_changed_present": has_content_changed,
                    "before_hashes_passed": bool(before_hashes),
                    "before_hashes_count": len(before_hashes),
                    "before_hashes_paths": list(before_hashes.keys()),
                    "workspace_root": ws_root,
                    "result_completion": result.completion,
                    "result_status": result.status,
                    "attempt": loop_label,
                },
            )

            assertion_results = await evaluate_assertions_async(
                all_assertions,
                step_outcomes=result.step_outcomes,
                workspace_root=ws_root,
                before_hashes=before_hashes,
                sandbox=self._tool_executor._sandbox,
            )

            _apply_assertion_results(result, assertion_results, ctx.task_id, loop_label)

    async def _invoke_judge(self, ctx: TaskContext, loop_label: str) -> bool:
        """Classify task and invoke planner-as-judge (Tier 2) if needed.

        Returns True if the judge says retry (goal not met, replan requested),
        False otherwise.  Modifies ctx.result (judge_verdict, completion,
        status) based on the verdict.
        """
        result = ctx.result
        all_assertions = _collect_all_assertions(result, ctx.plan)

        # Classify task and decide if judge is needed
        task_category = classify_task_category(
            ctx.user_request,
            assertions=all_assertions,
        )

        # Cross-reference checks — compare structural metadata
        # across files in the same site. Computed before the gate
        # so cross-ref warnings can force judge invocation.
        site_digests: dict[str, dict] = {}
        written_files: set[str] = set()
        for _outcome in result.step_outcomes:
            _fpath = _outcome.get("file_path")
            _digest = _outcome.get("structural_digest")
            if _fpath:
                written_files.add(_fpath.rsplit("/", 1)[-1])
                if _digest:
                    site_digests[_fpath.rsplit("/", 1)[-1]] = _digest
        cross_ref_warnings = (
            cross_reference_check(site_digests, written_files) if site_digests else []
        )

        should_judge = _should_invoke_judge(
            result,
            task_category,
            assertions_defined=len(all_assertions),
            cross_ref_warnings=cross_ref_warnings,
        )
        logger.debug(
            "Post-execution: judge decision — category=%s, should_invoke=%s, "
            "assertions_defined=%d, assertion_failures=%d, warnings=%d",
            task_category,
            should_judge,
            len(all_assertions),
            len(result.assertion_failures) if result.assertion_failures else 0,
            len(result.tool_output_warnings) if result.tool_output_warnings else 0,
            extra={
                "event": "verification.post_exec_judge_decision",
                "task_id": ctx.task_id,
                "category": task_category,
                "invoke_judge": should_judge,
                "assertions_defined": len(all_assertions),
                "assertion_failures": len(result.assertion_failures)
                if result.assertion_failures
                else 0,
                "tool_output_warnings": len(result.tool_output_warnings)
                if result.tool_output_warnings
                else 0,
                "attempt": loop_label,
            },
        )

        if not should_judge:
            return False

        try:
            if cross_ref_warnings:
                logger.info(
                    "Cross-reference check: %d warnings before judge",
                    len(cross_ref_warnings),
                    extra={
                        "event": "verification.cross_ref_warnings_for_judge",
                        "warning_count": len(cross_ref_warnings),
                        "types": [w["type"] for w in cross_ref_warnings],
                    },
                )

            judge_prompt = build_judge_payload(
                original_request=ctx.user_request,
                plan_summary=ctx.plan.plan_summary,
                step_outcomes=result.step_outcomes,
                file_mutations=result.file_mutations,
                completion=result.completion,
                goal_actions_executed=result.goal_actions_executed or False,
                assertion_results=result.assertion_failures,
                tool_output_warnings=result.tool_output_warnings,
                cross_ref_warnings=cross_ref_warnings,
            )
            try:
                verdict = await asyncio.wait_for(
                    self._planner.verify_goal(judge_prompt),
                    timeout=settings.planner_timeout,
                )
            except TimeoutError:
                logger.error(
                    "Judge verify_goal timed out",
                    extra={
                        "event": "verification.judge.timeout",
                        "timeout_s": settings.planner_timeout,
                    },
                    exc_info=True,
                )
                verdict = {
                    "GOAL_MET": "UNKNOWN",
                    "CONFIDENCE": "low",
                    "error": "judge_timeout",
                }

            # Validate verdict structure — planner may return malformed
            # JSON, a string, or None.  Coerce to a safe default so
            # downstream code never KeyErrors on garbage.
            verdict = _validate_judge_verdict(verdict)

            result.judge_verdict = verdict
            processed = process_judge_verdict(verdict, result.completion)

            logger.debug(
                "Judge verdict: GOAL_MET=%s, CONFIDENCE=%s, acted_on=%s, "
                "completion=%s, GAP=%s",
                verdict.get("GOAL_MET"),
                verdict.get("CONFIDENCE"),
                processed["acted_on"],
                processed.get("completion"),
                verdict.get("GAP", "none"),
                extra={
                    "event": "verification.judge_verdict_detail",
                    "task_id": ctx.task_id,
                    "goal_met": verdict.get("GOAL_MET"),
                    "confidence": verdict.get("CONFIDENCE"),
                    "acted_on": processed["acted_on"],
                    "new_completion": processed.get("completion"),
                    "gap": verdict.get("GAP"),
                    "attempt": loop_label,
                },
            )

            if processed["acted_on"]:
                result.completion = processed["completion"]
                if processed["completion"] in ("partial", "failed"):
                    result.status = processed["completion"]
                    # Judge says goal not met — should we retry?
                    gap = verdict.get("GAP") or ""
                    if (
                        gap  # Only retry if judge gave actionable feedback
                        and result.status != "error"  # Don't retry hard errors
                    ):
                        logger.info(
                            "Judge-driven replan: goal not met "
                            "(GOAL_MET=%s, CONFIDENCE=%s) — requesting "
                            "new plan with GAP context",
                            verdict.get("GOAL_MET"),
                            verdict.get("CONFIDENCE"),
                            extra={
                                "event": "verification.judge_replan_triggered",
                                "task_id": ctx.task_id,
                                "goal_met": verdict.get("GOAL_MET"),
                                "confidence": verdict.get("CONFIDENCE"),
                                "gap": gap,
                            },
                        )
                        return True
                    logger.debug(
                        "Judge says incomplete but no GAP context "
                        "for replan — accepting verdict",
                        extra={
                            "event": "verification.judge_no_gap_for_replan",
                            "task_id": ctx.task_id,
                            "gap": gap,
                        },
                    )

        except Exception as exc:  # catch-all: judge API fallback to tier-1 verdict
            logger.warning(
                "Judge invocation failed — using Tier 1 verdict",
                exc_info=True,
                extra={
                    "event": "verification.judge_failed",
                    "error": str(exc),
                    "task_id": ctx.task_id,
                },
            )

        return False

    async def _attempt_judge_replan(
        self,
        ctx: TaskContext,
        judge_replan_count: int,
        loop_label: str,
    ) -> bool:
        """Request a new plan after the judge says the goal was not met.

        Returns True if replan succeeded (caller should continue the loop),
        False if replan failed or budget exhausted (caller should break).
        Modifies ctx.plan and ctx.planner_usage on success.
        """
        if judge_replan_count > self.MAX_JUDGE_REPLANS:
            logger.warning(
                "Judge-driven replan budget exhausted — accepting verdict",
                extra={
                    "event": "verification.judge_replan_budget_exhausted",
                    "task_id": ctx.task_id,
                    "judge_replan_count": judge_replan_count,
                    "self.MAX_JUDGE_REPLANS": self.MAX_JUDGE_REPLANS,
                },
            )
            return False

        gap_context = (
            ctx.result.judge_verdict.get("GAP", "") if ctx.result.judge_verdict else ""
        )

        # Emit event so UI can show what's happening
        await self._emit(
            ctx.task_id,
            "judge_replan",
            {
                "judge_replan_number": judge_replan_count,
                "gap": gap_context,
                "previous_completion": ctx.result.completion,
                "goal_met": ctx.result.judge_verdict.get("GOAL_MET")
                if ctx.result.judge_verdict
                else None,
            },
        )

        logger.debug(
            "Judge replan: storing episodic record for failed attempt before retry",
            extra={
                "event": "verification.judge_replan_episodic_pre_store",
                "task_id": ctx.task_id,
            },
        )

        try:
            # Request a new plan with GAP context injected
            replan_request = (
                f"{ctx.user_request}\n\n"
                f"[PREVIOUS ATTEMPT FAILED — Judge feedback: {gap_context}]\n"
                f"[Previous plan summary: {ctx.plan.plan_summary}]\n"
                f"[Address the gap identified above. Do not repeat the same approach.]"
            )
            logger.debug(
                "Judge replan: requesting new plan with GAP context — %s",
                gap_context[:200],
                extra={
                    "event": "verification.judge_replan_plan_request",
                    "task_id": ctx.task_id,
                    "gap_context": gap_context[:500],
                },
            )
            ctx.plan = await asyncio.wait_for(
                self._planner.create_plan(
                    user_request=replan_request,
                    available_tools=ctx.available_tools,
                ),
                timeout=settings.planner_timeout,
            )
            # Capture updated planner usage (overwrites — latest call only)
            ctx.planner_usage = getattr(self._planner, "_last_usage", None)
            logger.info(
                "Judge replan: new plan received — %d steps, summary_len: %d",
                len(ctx.plan.steps),
                len(ctx.plan.plan_summary) if ctx.plan.plan_summary else 0,
                extra={
                    "event": "verification.judge_replan_plan_received",
                    "task_id": ctx.task_id,
                    "new_step_count": len(ctx.plan.steps),
                    "plan_summary_len": (
                        len(ctx.plan.plan_summary) if ctx.plan.plan_summary else 0
                    ),
                },
            )
            return True

        except (TimeoutError, PlannerError, PlannerRefusalError) as exc:
            logger.error(
                "Judge-driven replan failed — accepting original verdict",
                exc_info=True,
                extra={
                    "event": "verification.judge_replan_failed",
                    "task_id": ctx.task_id,
                    "error": str(exc),
                },
            )
            return False
