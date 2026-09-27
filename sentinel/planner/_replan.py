"""ReplanMixin — dynamic replanning helpers extracted from Orchestrator.

Provides continuation and failure replanning logic:
- _build_replan_context: assembles context string for planner replan calls
- _request_continuation: calls the planner to get continuation steps
- _handle_continuation_replan: success-triggered replan checkpoint
- _handle_failure_replan: failure-triggered replan for soft_failed steps
"""

from __future__ import annotations

import asyncio
import logging

from sentinel.core.config import settings
from sentinel.core.models import (
    Plan,
    PlanStep,
    StepResult,
    TaskResult,
)
from sentinel.crypto.blind_index import log_hash
from sentinel.memory.episodic import _redact_paths, _sanitise_for_planner
from sentinel.planner.verification import (
    check_goal_actions_executed,
    check_stagnation,
    extract_file_mutations,
)

# Lazy-style imports for anchor map accumulation — kept at module level
# so tests can patch them.
from sentinel.tools.anchor_allocator._core import content_hash
from sentinel.tools.anchor_allocator._memory import read_anchor_map

from ._execution import (
    _TRUSTED_OUTPUT_TOOLS,
    _build_replan_summary,
    _extract_prior_error,
    _truncate_plan_prompts,
)
from ._task_context import PlanExecState
from .builders import (
    compute_execution_vars,
    enforce_tagged_format,
    genericise_error,
)
from .planner import PlannerError, PlannerRefusalError

logger = logging.getLogger(__name__)


# ── Module-level helpers (no self — pure state operations) ────────────


def _update_stagnation_tracking(
    state: PlanExecState,
    step_id: str,
) -> str | None:
    """Track file mutations since last replan and check for stagnation.

    Updates ``state.consecutive_no_mutation_replans`` and
    ``state.pre_replan_mutation_count`` in place.

    Returns the result of :func:`check_stagnation` — ``None`` (ok),
    ``"warn"``, or ``"abort"``.
    """
    current_mutations = len(extract_file_mutations(state.step_outcomes))
    mutations_this_cycle = current_mutations - state.pre_replan_mutation_count

    if mutations_this_cycle == 0:
        state.consecutive_no_mutation_replans += 1
        logger.debug(
            "Stagnation tracking: no new file mutations this replan cycle — counter=%d",
            state.consecutive_no_mutation_replans,
            extra={
                "event": "replan.stagnation_no_mutations",
                "consecutive_no_mutation_replans": state.consecutive_no_mutation_replans,
                "total_mutations": current_mutations,
                "step_id": step_id,
            },
        )
    else:
        if state.consecutive_no_mutation_replans > 0:
            logger.debug(
                "Stagnation tracking: %d new mutation(s) — resetting counter (was %d)",
                mutations_this_cycle,
                state.consecutive_no_mutation_replans,
                extra={
                    "event": "replan.stagnation_reset",
                    "mutations_this_cycle": mutations_this_cycle,
                    "previous_counter": state.consecutive_no_mutation_replans,
                },
            )
        state.consecutive_no_mutation_replans = 0

    state.pre_replan_mutation_count = current_mutations
    return check_stagnation(state.consecutive_no_mutation_replans)


def _build_terminated_result(
    state: PlanExecState,
    *,
    status: str,
    reason: str,
    completion: str,
) -> TaskResult:
    """Build a TaskResult for early plan termination.

    Used by stagnation abort, failure budget exhaustion, and replan
    request failure — all share the same field pattern.
    """
    logger.debug(
        "Building terminated result",
        extra={
            "event": "replan.build_terminated_result",
            "result_status": status,
            "result_completion": completion,
        },
    )
    return TaskResult(
        status=status,
        plan_summary=state.plan.plan_summary,
        step_results=state.step_results,
        step_outcomes=state.step_outcomes,
        reason=reason,
        replan_count=state.replan_count,
        plan_phases=state.plan_phases + [state.current_phase],
        completion=completion,
        goal_actions_executed=check_goal_actions_executed(state.step_outcomes),
        file_mutations=extract_file_mutations(state.step_outcomes),
    )


def _check_fixer_degradation(
    state: PlanExecState,
    step_id: str,
) -> None:
    """Apply one-time budget penalty for persistent code fixer errors.

    When the worker produces structurally broken output that the fixer
    cannot repair (>= 3 consecutive iterations), accelerate budget
    exhaustion by consuming an extra failure replan attempt.  The penalty
    is applied at most once per degradation episode (guarded by
    ``fixer_degradation_applied``).
    """
    if state.consecutive_fixer_error_iterations < 3:
        return
    if state.fixer_degradation_applied:
        return

    state.fixer_degradation_applied = True
    logger.warning(
        "Persistent code fixer errors (%d consecutive) — "
        "treating as degradation signal during failure replan",
        state.consecutive_fixer_error_iterations,
        extra={
            "event": "replan.fixer_degradation_during_replan",
            "consecutive_fixer_error_iterations": state.consecutive_fixer_error_iterations,
            "failure_replan_count": state.failure_replan_count,
            "step_id": step_id,
        },
    )
    # Accelerate budget exhaustion: count persistent fixer errors
    # as an extra replan attempt consumed (one-time penalty)
    state.failure_replan_count += 1


def _apply_continuation_to_state(
    state: PlanExecState,
    *,
    step: PlanStep,
    continuation: Plan,
    trigger: str,
    failure_trigger: bool = False,
) -> None:
    """Apply a planner continuation to execution state.

    Closes the current plan phase, opens a new one, replaces remaining
    steps with continuation steps, and recomputes execution variables.
    """
    # Close current phase, open new one
    state.plan_phases.append(state.current_phase)
    state.current_phase = {
        "phase": f"continuation_{len(state.plan_phases)}",
        "trigger": trigger,
        "trigger_step": step.id,
        "plan": _truncate_plan_prompts(continuation.model_dump(exclude_none=True)),
        "step_outcomes_summary": {},
        "replan_context_summary": _build_replan_summary(
            executed_steps=state.executed_steps,
            step_outcomes=state.step_outcomes,
            failure_trigger=failure_trigger,
        ),
    }
    logger.info(
        "plan_history: %s closed, continuation triggered by %s (%s)",
        state.plan_phases[-1]["phase"],
        step.id,
        trigger,
        extra={
            "event": "replan.plan_history_phase_close",
            "closed_phase": state.plan_phases[-1]["phase"],
            "trigger_step": step.id,
            "trigger": trigger,
        },
    )

    # Replace remaining steps with continuation steps
    state.remaining_steps = list(continuation.steps)

    # Recompute execution_vars for the extended plan
    extended_plan = Plan(
        plan_summary=state.plan.plan_summary,
        steps=list(state.executed_steps) + state.remaining_steps,
    )
    state.execution_vars = compute_execution_vars(extended_plan)
    enforce_tagged_format(extended_plan, state.execution_vars)

    logger.debug(
        "Continuation applied to state",
        extra={
            "event": "replan.continuation_applied",
            "trigger": trigger,
            "trigger_step": step.id,
            "new_step_count": len(continuation.steps),
        },
    )


class ReplanMixin:
    """Mixin providing dynamic replanning helpers for the Orchestrator."""

    @staticmethod
    def _build_replan_context(
        user_request: str,
        plan_summary: str,
        step_results: list[StepResult],
        step_outcomes: list[dict],
        executed_steps: list[PlanStep],
        failure_trigger: bool = False,
    ) -> str:
        """Build context for a continuation planner call.

        Includes F1 metadata for all completed steps, plus actual output for
        trusted tool steps (shell, file_read). Worker (llm_task) output is
        never included — only F1 metadata (status, size, symbols).

        When failure_trigger=True, prepends a FAILURE DIAGNOSTIC header so the
        planner knows to diagnose the error and plan corrective steps.
        """
        lines = []
        if failure_trigger:
            # _extract_prior_error already handles soft_failed (Task 2) and
            # already applies _redact_paths internally at _error_tracking.py:49.
            # Q7-F4 (`_replan.py:252-256`): apply _sanitise_for_planner to
            # complete the scrub stack — markers in stored stderr replay into
            # this header on every failure cycle.
            error_summary = _sanitise_for_planner(
                _extract_prior_error(step_outcomes) or "unknown error"
            )
            lines.extend(
                [
                    "FAILURE DIAGNOSTIC:",
                    f"  {error_summary}",
                    "",
                    "  The command ran but produced an error. The full output is included below.",
                    "  Diagnose the issue, plan corrective steps (fix the code, adjust the",
                    "  command, etc.), then retry.",
                    "",
                ]
            )
        # Q7-F4 (`_replan.py:267`): scrub replayed user_request — same class
        # as F2 at `_history_rendering.py:245`. plan_summary is planner-generated
        # (Claude output) so it does not need scrub.
        lines.extend(
            [
                f"REPLAN CONTEXT — continuing plan: {plan_summary}",
                f"Original request: {_sanitise_for_planner(user_request)}",
                "",
                "Completed steps:",
            ]
        )

        for step, result, outcome in zip(
            executed_steps, step_results, step_outcomes, strict=True
        ):
            # Include output_var so the continuation plan references the correct
            # variable names. Without this, the planner guesses variable names
            # (e.g. $step_1_result) instead of using the actual names from the
            # initial plan (e.g. $weather_search, $current_html).
            var_suffix = f" → {step.output_var}" if step.output_var else ""
            lines.append(
                f"  {step.id} [{step.type}]{var_suffix}: {outcome.get('status', 'unknown')}"
            )

            # F1 metadata (always included — privacy-safe)
            meta_parts = []
            if outcome.get("output_size"):
                meta_parts.append(f"output={outcome['output_size']}B")
            if outcome.get("exit_code") is not None:
                meta_parts.append(f"exit={outcome['exit_code']}")
            # Q7-F4 (`_replan.py:291-292`): scrub + redact tool stderr in
            # replan metadata — tool-controlled text reaches planner replay.
            if outcome.get("stderr_preview"):
                meta_parts.append(
                    f"stderr: {_redact_paths(_sanitise_for_planner(outcome['stderr_preview']))}"
                )
            # Q7-F4 (`_replan.py:294`): scrub + redact tool result file_path
            # — adversarial filenames reach planner via replan metadata.
            if outcome.get("file_path"):
                meta_parts.append(
                    f"file={_redact_paths(_sanitise_for_planner(outcome['file_path']))}"
                )
            if outcome.get("diff_stats"):
                meta_parts.append(f"diff={outcome['diff_stats']}")
            if meta_parts:
                lines.append(f"    metadata: {' | '.join(meta_parts)}")

            # Content manifest — structural file awareness for planner.
            # Mostly structural (element IDs, tag names, CSS properties,
            # function signatures), but `_format_manifest` also emits
            # worker-derived content for HTML elements (text_content),
            # JS fetch URLs, and DOM IDs (see `_judge_payload.py:80,95,105,109`).
            _manifest = outcome.get("content_manifest")
            _manifests = outcome.get("content_manifests", {})
            if _manifest or _manifests:
                from sentinel.planner.verification import _format_manifest

                manifest_lines: list[str] = []
                if _manifest:
                    fp = outcome.get("file_path", "?")
                    manifest_lines.extend(_format_manifest(fp, _manifest))
                for fname, m in _manifests.items():
                    manifest_lines.extend(_format_manifest(fname, m))
                # Q7-F4 (`_replan.py:319`, Codex-round site expansion 2026-04-21,
                # thread `019db15d-d50a-7610-b513-73da8d8bd508`): scrub + redact
                # the aggregated manifest_text. Per-line emit lines in
                # `_format_manifest` carry worker-controlled HTML text_content,
                # JS fetch URLs, DOM IDs, and the file_path header. Scrub-then-
                # truncate so a marker straddling the 2000-char boundary still
                # matches.
                manifest_text = _redact_paths(
                    _sanitise_for_planner("\n".join(manifest_lines))
                )
                if len(manifest_text) > 2000:
                    manifest_text = manifest_text[:1997] + "..."
                indent = "      "
                indented = "\n".join(indent + ln for ln in manifest_text.splitlines())
                lines.append(f"    file structure:\n{indented}")
                file_path = outcome.get("file_path")
                logger.debug(
                    "replan context: manifest injected for %s (%d chars, %s)",
                    log_hash(file_path) or "website",
                    len(manifest_text),
                    "truncated" if len(manifest_text) >= 1997 else "full",
                    extra={
                        "event": "replan.replan_manifest_injected",
                        "file_path_hash": log_hash(file_path),
                        "file_path_len": len(file_path) if file_path else 0,
                        "manifest_chars": len(manifest_text),
                        "truncated": len(manifest_text) >= 1997,
                        "file_count": 1 if _manifest else len(_manifests),
                    },
                )

            # Actual output for trusted tools — lets the planner see
            # directory listings, file contents, shell errors, etc.
            # Q7-F4 (`_replan.py:334-346`): SP only — paths in tool output
            # body are task-relevance signal (e.g. `ls` listings) so RP
            # is intentionally NOT stacked here per design §4.3.
            # Scrub-then-truncate so a marker spanning the 4000-char
            # boundary still matches.
            if (
                step.type == "tool_call"
                and step.tool in _TRUSTED_OUTPUT_TOOLS
                and result.status in ("success", "soft_failed")
                and result.content
            ):
                scrubbed = _sanitise_for_planner(result.content)
                content = scrubbed[:4000]
                if len(scrubbed) > 4000:
                    content += f"\n... (truncated, {len(scrubbed)} chars total)"
                indent = "      "
                indented = "\n".join(indent + ln for ln in content.splitlines())
                lines.append(f"    output:\n{indented}")

            # Worker steps: F1 metadata only (no raw content — privacy boundary)
            elif step.type == "llm_task" and result.status == "success":
                if outcome.get("output_language"):
                    lines.append(f"    language: {outcome['output_language']}")
                if outcome.get("syntax_valid") is not None:
                    lines.append(
                        f"    syntax: {'valid' if outcome['syntax_valid'] else 'ERROR'}"
                    )
                if outcome.get("defined_symbols"):
                    lines.append(f"    symbols: {outcome['defined_symbols']}")

        lines.append("")
        if failure_trigger:
            lines.append(
                "The previous step failed. Diagnose the error using the output above, "
                "then plan corrective steps to fix the issue and retry. "
                'Set "continuation": true in your response.'
            )
        else:
            lines.append(
                "Continue the plan from the next step. Use the results above to determine "
                "correct file paths, commands, and approach for remaining steps. "
                'Set "continuation": true in your response.'
            )
        return "\n".join(lines)

    async def _request_continuation(
        self,
        user_request: str,
        plan_summary: str,
        step_results: list[StepResult],
        step_outcomes: list[dict],
        executed_steps: list[PlanStep],
        available_tools: list[dict] | None = None,
        failure_trigger: bool = False,
        active_anchor_maps: dict[str, str] | None = None,
    ) -> Plan:
        """Request continuation steps from the planner after a replan checkpoint."""
        logger.debug(
            "_request_continuation called",
            extra={
                "event": "replan.request_continuation",
                "request_len": len(user_request) if user_request else 0,
                "summary_len": len(plan_summary) if plan_summary else 0,
                "step_result_count": len(step_results) if step_results else 0,
            },
        )
        # Diagnostic: how many outcomes carry manifests at replan time
        _manifest_count = sum(
            1
            for o in step_outcomes
            if o.get("content_manifest") or o.get("content_manifests")
        )
        logger.debug(
            "replan: %d/%d step_outcomes carry content manifests",
            _manifest_count,
            len(step_outcomes),
            extra={
                "event": "replan.replan_manifest_availability",
                "outcomes_total": len(step_outcomes),
                "outcomes_with_manifest": _manifest_count,
                "failure_trigger": failure_trigger,
            },
        )
        replan_context = self._build_replan_context(
            user_request=user_request,
            plan_summary=plan_summary,
            step_results=step_results,
            step_outcomes=step_outcomes,
            executed_steps=executed_steps,
            failure_trigger=failure_trigger,
        )

        # --- Inject anchor maps for files read in this task ---
        _anchor_maps = active_anchor_maps or {}
        if _anchor_maps:
            replan_context += "\n\n" + "\n\n".join(_anchor_maps.values())

        # Collect output_var names from executed steps so the continuation
        # plan validator accepts references to them. Without this, the validator
        # rejects $weather_search etc. as "undefined variable" because it only
        # sees the continuation plan's steps, not the initial plan's.
        prior_vars = {s.output_var for s in executed_steps if s.output_var}

        continuation = await asyncio.wait_for(
            self._planner.create_plan(
                user_request=replan_context,
                available_tools=available_tools,
                prior_vars=prior_vars,
            ),
            timeout=settings.planner_timeout,
        )

        # Validate continuation step IDs don't conflict with executed steps
        executed_ids = {s.id for s in executed_steps}
        for step in continuation.steps:
            if step.id in executed_ids:
                raise PlannerError(
                    f"Continuation step ID '{step.id}' conflicts with "
                    f"already-executed step. IDs must be unique across phases.",
                    category="validation",
                )

        return continuation

    async def _accumulate_anchor_maps(
        self,
        *,
        state: "PlanExecState",
        step: PlanStep,
        result: StepResult | None,
        user_id: int,
    ) -> None:
        """Accumulate anchor maps for file_read steps into replan context.

        If ``step`` is a ``file_read`` with a valid path and an episodic
        store is available, looks up the anchor map for the read file and
        stores the formatted text in ``state.active_anchor_maps``.

        Errors are logged but never raised — anchor maps are a non-fatal
        enrichment for replan context.
        """
        if step.tool != "file_read" or not step.args:
            return
        file_path = step.args.get("path", "")
        if not file_path:
            return
        if not hasattr(self, "_episodic_store") or not self._episodic_store:
            return

        try:
            file_content = result.content if result and result.content else ""
            anchor_list = await read_anchor_map(
                path=file_path,
                current_hash=content_hash(file_content),
                episodic_store=self._episodic_store,
                user_id=user_id,
            )
            if anchor_list:
                lines = [f"[ANCHOR MAP: {file_path}]"]
                for anchor in anchor_list:
                    # Q7-F4 (`_replan.py:529`, 14th-site fold-in 2026-04-21):
                    # anchor names/descriptions can carry worker-derived HTML IDs,
                    # config keys, and CSS comment/media text. Scrub at the
                    # planner render boundary before f-string interpolation.
                    scrubbed_name = _sanitise_for_planner(_redact_paths(anchor["name"]))
                    scrubbed_desc = _sanitise_for_planner(
                        _redact_paths(anchor["description"])
                    )
                    end_tag = (
                        f" (pair: {scrubbed_name}-end)" if anchor.get("has_end") else ""
                    )
                    lines.append(f"  {scrubbed_name} — {scrubbed_desc}{end_tag}")
                lines.append("[END ANCHOR MAP]")
                state.active_anchor_maps[file_path] = "\n".join(lines)
                logger.info(
                    "Anchor map injected for replan",
                    extra={
                        "event": "replan.anchor_map_injected",
                        "path_hash": log_hash(file_path),
                        "path_len": len(file_path) if file_path else 0,
                        "anchor_count": len(anchor_list),
                    },
                )
        except Exception:  # catch-all: anchor map accumulation best-effort
            # Drop exc_info=True: catch-all may include OSError / FileNotFoundError
            # whose stringification embeds the raw path.
            logger.debug(
                "Anchor map accumulation failed (non-fatal)",
                extra={
                    "event": "replan.anchor_map_error",
                    "path_hash": log_hash(file_path),
                    "path_len": len(file_path) if file_path else 0,
                },
            )

    # ── Replan request execution ────────────────────────────────────

    async def _do_continuation_replan_request(
        self,
        state: PlanExecState,
        step: PlanStep,
    ) -> None:
        """Execute a continuation replan request and update state.

        Calls the planner for continuation steps, applies them to state,
        logs new tool types, and emits the plan_continued event.

        On planner error, logs the failure and falls through (returns None)
        so the loop can execute any remaining original steps.
        """
        try:
            continuation = await self._request_continuation(
                user_request=state.user_input or "",
                plan_summary=state.plan.plan_summary,
                step_results=state.step_results,
                step_outcomes=state.step_outcomes,
                executed_steps=state.executed_steps,
                available_tools=state.available_tools,
                active_anchor_maps=state.active_anchor_maps,
            )

            _apply_continuation_to_state(
                state,
                step=step,
                continuation=continuation,
                trigger="replan_after",
            )

            # Log if continuation introduces new tool types
            original_tools = {s.tool for s in state.plan.steps if s.tool}
            continuation_tools = {s.tool for s in continuation.steps if s.tool}
            new_tools = continuation_tools - original_tools
            if new_tools:
                logger.info(
                    "Continuation introduces new tool types",
                    extra={
                        "event": "replan.replan_new_tools",
                        "new_tools": sorted(new_tools),
                        "original_tools": sorted(original_tools),
                    },
                )

            await self._emit(
                state.task_id,
                "plan_continued",
                {
                    "replan_number": state.replan_count,
                    "new_steps": len(continuation.steps),
                    "continuation_summary": continuation.plan_summary,
                },
            )

            logger.debug(
                "Continuation replan completed successfully",
                extra={
                    "event": "replan.continuation_replan_exit",
                    "step_id": step.id,
                    "new_step_count": len(continuation.steps),
                    "replan_count": state.replan_count,
                },
            )

        except (TimeoutError, PlannerError, PlannerRefusalError) as exc:
            logger.error(
                "Replan failed — executing remaining steps as-is",
                extra={
                    "event": "replan.replan_failed",
                    "error": str(exc),
                    "remaining_steps": len(state.remaining_steps),
                },
                exc_info=True,
            )
            # Fall through to execute any remaining original steps.

    async def _do_failure_replan_request(
        self,
        state: PlanExecState,
        step: PlanStep,
        exec_meta: dict | None = None,
    ) -> TaskResult | None:
        """Execute a failure replan request and update state.

        Calls the planner for recovery steps, applies them to state,
        and emits the failure_replan event.

        Returns a TaskResult if the planner request fails (abort),
        or None on success (continue loop).
        """
        try:
            continuation = await self._request_continuation(
                user_request=state.user_input or "",
                plan_summary=state.plan.plan_summary,
                step_results=state.step_results,
                step_outcomes=state.step_outcomes,
                executed_steps=state.executed_steps,
                available_tools=state.available_tools,
                failure_trigger=True,
                active_anchor_maps=state.active_anchor_maps,
            )

            _apply_continuation_to_state(
                state,
                step=step,
                continuation=continuation,
                trigger="soft_failed",
                failure_trigger=True,
            )

            await self._emit(
                state.task_id,
                "failure_replan",
                {
                    "failure_replan_number": state.failure_replan_count,
                    "new_steps": len(continuation.steps),
                    "trigger_step": step.id,
                    "exit_code": (exec_meta or {}).get("exit_code"),
                },
            )

            logger.debug(
                "Failure replan completed successfully",
                extra={
                    "event": "replan.failure_replan_exit",
                    "step_id": step.id,
                    "new_step_count": len(continuation.steps),
                    "failure_replan_count": state.failure_replan_count,
                },
            )

        except (TimeoutError, PlannerError, PlannerRefusalError) as exc:
            logger.error(
                "Failure replan request failed — aborting",
                extra={
                    "event": "replan.failure_replan_request_failed",
                    "error": str(exc),
                },
                exc_info=True,
            )
            return _build_terminated_result(
                state,
                status="failed",
                reason=genericise_error(f"Failure replan failed: {exc}")
                or "Failure replan failed",
                completion="abandoned",
            )

        return None

    # ── Plan execution (extracted sub-methods) ────────────────────────

    async def _handle_continuation_replan(
        self,
        state: PlanExecState,
        step: PlanStep,
        result: StepResult,
    ) -> TaskResult | None:
        """Handle success-triggered dynamic replanning checkpoint.

        Called when a step has replan_after=True and succeeded.  Checks
        stagnation, replan budget, accumulates anchor maps for file_read
        steps, calls _request_continuation, and updates plan phases.

        Returns a TaskResult if the plan should terminate early (stagnation
        abort), or None if execution should continue with updated state.
        """
        logger.debug(
            "Continuation replan checkpoint entered",
            extra={
                "event": "replan.continuation_replan_enter",
                "step_id": step.id,
                "replan_count": state.replan_count,
                "max_replans": state.max_replans,
                "consecutive_no_mutation_replans": state.consecutive_no_mutation_replans,
            },
        )

        # Stagnation detection: count file mutations since last replan
        stagnation_result = _update_stagnation_tracking(state, step_id=step.id)
        if stagnation_result == "abort":
            state.stagnation_aborted = True
            logger.warning(
                "Stagnation abort: %d consecutive no-mutation replans — forcing partial",
                state.consecutive_no_mutation_replans,
                extra={
                    "event": "replan.stagnation_abort",
                    "consecutive_no_mutation_replans": state.consecutive_no_mutation_replans,
                    "steps_completed": len(state.step_results),
                },
            )
            return _build_terminated_result(
                state,
                status="partial",
                reason=f"Stagnation detected: {state.consecutive_no_mutation_replans} consecutive replan cycles with no file mutations",
                completion="partial",
            )
        if stagnation_result == "warn":
            logger.warning(
                "Stagnation warning: %d consecutive no-mutation replans — continuing but at risk",
                state.consecutive_no_mutation_replans,
                extra={
                    "event": "replan.stagnation_warn",
                    "consecutive_no_mutation_replans": state.consecutive_no_mutation_replans,
                },
            )

        # Budget check
        if state.replan_count >= state.max_replans:
            state.budget_exhausted = True
            logger.warning(
                "Replan budget exhausted — executing remaining steps as-is",
                extra={
                    "event": "replan.replan_budget_exhausted",
                    "replan_count": state.replan_count,
                    "remaining_steps": len(state.remaining_steps),
                },
            )
            return None  # Continue loop without replanning

        state.replan_count += 1
        logger.info(
            "Replan checkpoint reached — requesting continuation",
            extra={
                "event": "replan.replan_checkpoint",
                "step_id": step.id,
                "replan_number": state.replan_count,
                "steps_completed": len(state.executed_steps),
            },
        )

        # Accumulate anchor maps for file_read steps
        await self._accumulate_anchor_maps(
            state=state,
            step=step,
            result=result,
            user_id=state.user_id,
        )

        # Extension point: pre-replan enrichers would run here

        await self._do_continuation_replan_request(state, step)
        return None  # Continue loop

    async def _handle_failure_replan(
        self,
        state: PlanExecState,
        step: PlanStep,
        result: StepResult,
        exec_meta: dict | None,
    ) -> TaskResult | None:
        """Handle failure-triggered replanning for soft_failed steps.

        Called when a step has status 'soft_failed'.  Tracks stagnation
        as a secondary signal, checks fixer degradation, enforces the
        failure replan budget, then calls _request_continuation with
        failure_trigger=True.

        Returns a TaskResult if the plan should terminate (budget exhausted
        or replan request failed), or None if execution should continue.
        """
        logger.debug(
            "Failure replan checkpoint entered",
            extra={
                "event": "replan.failure_replan_enter",
                "step_id": step.id,
                "failure_replan_count": state.failure_replan_count,
                "max_failure_replans": state.max_failure_replans,
                "consecutive_fixer_error_iterations": state.consecutive_fixer_error_iterations,
            },
        )

        # Stagnation: track mutations (logging/signal only — failure budget takes priority)
        stagnation_result = _update_stagnation_tracking(state, step_id=step.id)
        if stagnation_result == "abort":
            logger.warning(
                "Stagnation detected during failure replan (%d cycles) — "
                "deferring to failure budget (%d/%d)",
                state.consecutive_no_mutation_replans,
                state.failure_replan_count,
                state.max_failure_replans,
                extra={
                    "event": "replan.stagnation_during_failure_replan",
                    "consecutive_no_mutation_replans": state.consecutive_no_mutation_replans,
                    "failure_replan_count": state.failure_replan_count,
                    "step_id": step.id,
                },
            )
        elif stagnation_result == "warn":
            logger.warning(
                "Stagnation warning during failure replan: %d consecutive no-mutation cycles",
                state.consecutive_no_mutation_replans,
                extra={
                    "event": "replan.stagnation_warn_failure_replan",
                    "consecutive_no_mutation_replans": state.consecutive_no_mutation_replans,
                },
            )

        # Fixer degradation: one-time budget penalty for persistent errors
        _check_fixer_degradation(state, step_id=step.id)

        if state.failure_replan_count >= state.max_failure_replans:
            logger.warning(
                "Failure replan budget exhausted — aborting",
                extra={
                    "event": "replan.failure_replan_budget_exhausted",
                    "failure_replan_count": state.failure_replan_count,
                    "step_id": step.id,
                },
            )
            return _build_terminated_result(
                state,
                status="failed",
                reason=f"Failure replan budget exhausted ({state.max_failure_replans} attempts)",
                completion="abandoned",
            )

        state.failure_replan_count += 1
        state.replan_count += 1
        logger.info(
            "Failure replan triggered — requesting fix from planner",
            extra={
                "event": "replan.failure_replan_triggered",
                "step_id": step.id,
                "failure_replan_number": state.failure_replan_count,
                "exit_code": (exec_meta or {}).get("exit_code"),
            },
        )

        # Extension point: pre-failure-replan enrichers would run here

        return await self._do_failure_replan_request(state, step, exec_meta)
