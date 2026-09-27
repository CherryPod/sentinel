"""EpisodicMixin -- episodic memory storage extracted from Orchestrator.

Pure code-move from orchestrator.py (lines 2284-2549).  No logic changes.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import NamedTuple

from sentinel.core.context import current_user_id, require_user_id, spawn_task
from sentinel.memory.episodic import (
    classify_task_domain,
    extract_episodic_facts,
)

logger = logging.getLogger(__name__)

# Embedding calls go to Ollama over HTTP — bound them so a stalled
# inference server doesn't block episodic storage indefinitely.
_EMBEDDING_TIMEOUT = 30.0


class _OutcomeMeta(NamedTuple):
    """Parsed metadata from step outcomes."""

    file_paths: list[str]
    error_patterns: list[str]
    all_symbols: list[str]
    success_count: int
    task_domain: str


class EpisodicMixin:
    """Episodic-memory helpers formerly on Orchestrator."""

    async def _store_episodic_record(
        self,
        session_id: str,
        task_id: str,
        user_request: str,
        task_status: str,
        plan_summary: str,
        step_outcomes: list[dict],
        original_request: str | None = None,
        prior_error_summary: str | None = None,
        plan_phases: list[dict] | None = None,
        # Verification signals (from TaskResult)
        completion: str = "full",
        goal_actions_executed: bool | None = None,
        file_mutations: list[dict] | None = None,
        assertion_failures: list[dict] | None = None,
        tool_output_warnings: list[dict] | None = None,
        judge_verdict: dict | None = None,
    ) -> None:
        """Store a structured episodic record after task completion.

        Best-effort — failures are logged, never block the task. Creates:
        1. Episodic record with structured fields
        2. Memory_chunks shadow entry (for full-text/vec search)
        3. Extracted facts with tsvector index

        All data is TRUSTED by construction — F1 metadata only.
        """
        logger.debug(
            "Storing episodic record",
            extra={
                "event": "episodic.store_record_entry",
                "task_id": task_id,
                "task_status": task_status,
                "step_count": len(step_outcomes) if step_outcomes else 0,
            },
        )
        if self._episodic_store is None or self._memory_store is None:
            return

        try:
            meta = self._extract_outcomes_metadata(step_outcomes)

            plan_json_data = self._build_plan_json(
                task_id=task_id,
                user_request=user_request,
                plan_phases=plan_phases,
                completion=completion,
                goal_actions_executed=goal_actions_executed,
                file_mutations=file_mutations,
                assertion_failures=assertion_failures,
                tool_output_warnings=tool_output_warnings,
                judge_verdict=judge_verdict,
            )

            embedding = await self._get_episodic_embedding(
                user_request=user_request,
                task_status=task_status,
                step_outcomes=step_outcomes,
                success_count=meta.success_count,
                file_paths=meta.file_paths,
                plan_summary=plan_summary,
                error_patterns=meta.error_patterns,
                task_domain=meta.task_domain,
                original_request=original_request,
                prior_error_summary=prior_error_summary,
                plan_json_data=plan_json_data,
            )

            record_id = await self._episodic_store.create_with_shadow(
                memory_store=self._memory_store,
                session_id=session_id,
                task_id=task_id,
                user_request=user_request[:2000],
                task_status=task_status,
                plan_summary=plan_summary,
                step_count=len(step_outcomes),
                success_count=meta.success_count,
                file_paths=meta.file_paths,
                error_patterns=meta.error_patterns,
                defined_symbols=meta.all_symbols,
                step_outcomes=step_outcomes,
                embedding=embedding,
                task_domain=meta.task_domain,
                original_request=original_request,
                prior_error_summary=prior_error_summary,
                plan_json=plan_json_data,
            )

            # Extract and store facts
            facts = extract_episodic_facts(step_outcomes, user_request, task_status)
            if facts:
                await self._episodic_store.store_facts(record_id, facts)

            logger.info(
                "Episodic record stored",
                extra={
                    "event": "episodic.episodic_stored",
                    "record_id": record_id,
                    "fact_count": len(facts),
                    "file_count": len(meta.file_paths),
                    "plan_phases": len(plan_phases) if plan_phases else 0,
                },
            )

            await self._record_strategy_pattern(
                task_domain=meta.task_domain,
                step_outcomes=step_outcomes,
                task_status=task_status,
            )

            await self._refresh_domain_summary_if_needed(
                task_domain=meta.task_domain,
            )

        except Exception as exc:  # catch-all: episodic storage best-effort
            logger.warning(
                "Episodic record storage failed (best-effort)",
                extra={"event": "episodic.episodic_store_failed", "error": str(exc)},
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Extracted helpers (from _store_episodic_record decomposition)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_outcomes_metadata(step_outcomes: list[dict]) -> _OutcomeMeta:
        """Parse file paths, error patterns, symbols, and domain from outcomes."""
        logger.debug(
            "_extract_outcomes_metadata called",
            extra={
                "event": "_episodic._extract_outcomes_metadata",
                "step_outcomes_len": len(step_outcomes)
                if hasattr(step_outcomes, "__len__")
                else 0,
            },
        )  # auto:entry
        file_paths: list[str] = []
        error_patterns: list[str] = []
        all_symbols: list[str] = []
        for outcome in step_outcomes:
            fp = outcome.get("file_path")
            if fp and fp not in file_paths:
                file_paths.append(fp)
            if outcome.get("scanner_result") == "blocked":
                generic_err = outcome.get("error_detail", "blocked")
                error_patterns.append(generic_err)
            if outcome.get("exit_code") and outcome["exit_code"] != 0:
                stderr = outcome.get("stderr_preview", "")
                error_patterns.append(
                    f"exit {outcome['exit_code']}: {stderr[:80]}"
                    if stderr
                    else f"exit {outcome['exit_code']}"
                )
            symbols = outcome.get("defined_symbols", [])
            if symbols:
                all_symbols.extend(symbols)

        success_count = sum(1 for o in step_outcomes if o.get("status") == "success")
        task_domain = classify_task_domain(step_outcomes)

        return _OutcomeMeta(
            file_paths=file_paths,
            error_patterns=error_patterns,
            all_symbols=all_symbols,
            success_count=success_count,
            task_domain=task_domain,
        )

    @staticmethod
    def _build_plan_json(
        *,
        task_id: str,
        user_request: str,
        plan_phases: list[dict] | None,
        completion: str,
        goal_actions_executed: bool | None,
        file_mutations: list[dict] | None,
        assertion_failures: list[dict] | None,
        tool_output_warnings: list[dict] | None,
        judge_verdict: dict | None,
    ) -> dict | None:
        """Assemble plan_json for plan-outcome memory."""
        if not plan_phases:
            return None

        plan_json_data: dict = {
            "phases": plan_phases,
            "user_request_full": user_request[:2000],
            "completion": completion,
        }
        if goal_actions_executed is not None:
            plan_json_data["goal_actions_executed"] = goal_actions_executed
        if file_mutations:
            plan_json_data["file_mutations"] = file_mutations
        if assertion_failures:
            plan_json_data["assertion_failures"] = assertion_failures
        if tool_output_warnings:
            plan_json_data["tool_output_warnings"] = tool_output_warnings
        if judge_verdict:
            plan_json_data["judge_verdict"] = judge_verdict

        plan_json_size = len(json.dumps(plan_json_data))
        if plan_json_size > 50_000:
            logger.warning(
                "plan_history: plan_json %d bytes for task %s, consider review",
                plan_json_size,
                task_id,
                extra={
                    "event": "episodic.plan_history_large",
                    "size_bytes": plan_json_size,
                    "task_id": task_id,
                },
            )

        return plan_json_data

    async def _get_episodic_embedding(
        self,
        *,
        user_request: str,
        task_status: str,
        step_outcomes: list[dict],
        success_count: int,
        file_paths: list[str],
        plan_summary: str,
        error_patterns: list[str],
        task_domain: str,
        original_request: str | None,
        prior_error_summary: str | None,
        plan_json_data: dict | None,
    ) -> list[float] | None:
        """Generate embedding for the episodic shadow entry. Best-effort."""
        if self._embedding_client is None:
            return None

        try:
            from sentinel.memory.episodic import render_episodic_text

            text = render_episodic_text(
                user_request=user_request,
                task_status=task_status,
                step_count=len(step_outcomes),
                success_count=success_count,
                file_paths=file_paths,
                plan_summary=plan_summary,
                error_patterns=error_patterns,
                step_outcomes=step_outcomes,
                task_domain=task_domain,
                original_request=original_request,
                prior_error_summary=prior_error_summary,
                plan_json=plan_json_data,
            )
            return await asyncio.wait_for(
                self._embedding_client.embed(text, prefix="search_document: "),
                timeout=_EMBEDDING_TIMEOUT,
            )
        except Exception as exc:  # catch-all: embedding fallback to none
            logger.debug(
                "Episodic embedding failed",
                exc_info=True,
                extra={
                    "event": "episodic.episodic_embedding_failed",
                    "error": str(exc),
                },
            )
            return None

    async def _record_strategy_pattern(
        self,
        *,
        task_domain: str,
        step_outcomes: list[dict],
        task_status: str,
    ) -> None:
        """Record strategy pattern for this task's domain. Best-effort."""
        if not task_domain or self._strategy_store is None:
            return

        try:
            from sentinel.memory.episodic import _categorise_strategy

            strategy = _categorise_strategy(step_outcomes)
            total_duration = sum(o.get("duration_s", 0) or 0 for o in step_outcomes)
            await self._strategy_store.upsert(
                domain=task_domain,
                strategy_name=strategy,
                step_sequence=[
                    o.get("tool") or o.get("step_type", "")
                    for o in step_outcomes
                    if o.get("step_type")
                ],
                success=task_status in ("success", "completed"),
                duration_s=total_duration if total_duration > 0 else None,
            )
        except Exception as exc:  # catch-all: strategy pattern best-effort
            logger.debug(
                "Strategy pattern recording failed (non-fatal)",
                extra={
                    "event": "episodic.strategy_record_failed",
                    "error": str(exc),
                },
                exc_info=True,
            )

    async def _refresh_domain_summary_if_needed(
        self,
        *,
        task_domain: str,
    ) -> None:
        """Check domain summary staleness and spawn refresh if needed. Best-effort."""
        if not task_domain or self._domain_summary_store is None:
            return

        try:
            new_count = await self._domain_summary_store.increment_task_count(
                task_domain
            )
            if new_count >= 10:
                await self._domain_summary_store.reset_task_count(task_domain)
                _uid = current_user_id.get()
                task = spawn_task(
                    self._refresh_domain_summary(task_domain, user_id=_uid)
                )
                # ASYNCIO SAFETY: .add() and .discard() are synchronous
                # set ops — safe without locks on the single-threaded
                # event loop.  See orchestrator.__init__ for full argument.
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
        except Exception as exc:  # catch-all: domain summary check best-effort
            logger.debug(
                "Domain summary check failed (non-fatal)",
                extra={
                    "event": "episodic.domain_summary_check_failed",
                    "error": str(exc),
                },
                exc_info=True,
            )

    async def _refresh_domain_summary(
        self, domain: str, user_id: int | None = None
    ) -> None:
        """Background refresh of a domain summary. Best-effort.

        user_id is threaded explicitly because asyncio.create_task does not
        propagate ContextVars reliably to background tasks.
        """
        # Q4-F11: resolve via helper — None resolves from current_user_id; raises on 0.
        # This was the demonstrable misattribution bug: the `=1` default
        # silently routed user B's background refresh to user 1's partition
        # when the caller forgot to thread user_id.
        user_id = require_user_id(user_id, "_PlannerEpisodic._refresh_domain_summary")
        logger.debug(
            "Refreshing domain summary",
            extra={"event": "episodic.refresh_domain_summary_entry", "domain": domain},
        )
        try:
            from sentinel.memory.domain_summary import generate_domain_summary

            # Q4-F11: thread user_id through the call site explicitly so
            # generate_domain_summary doesn't fall back to its own resolve
            # (which would re-derive from the surrounding ContextVar).
            summary = await generate_domain_summary(
                domain=domain,
                episodic_store=self._episodic_store,
                user_id=user_id,
            )
            await self._domain_summary_store.upsert(summary)
            logger.info(
                "Domain summary refreshed",
                extra={
                    "event": "episodic.domain_summary_refreshed",
                    "domain": domain,
                    "total_tasks": summary.total_tasks,
                },
            )
        except Exception as exc:  # catch-all: domain summary refresh best-effort
            logger.warning(
                "Domain summary refresh failed (non-fatal)",
                extra={
                    "event": "episodic.domain_summary_refresh_failed",
                    "error": str(exc),
                },
                exc_info=True,
            )

        # Piggyback canonical trajectory refresh on domain summary refresh
        if self._strategy_store is not None and self._memory_store is not None:
            try:
                from sentinel.memory.canonical import refresh_canonical_trajectories

                await refresh_canonical_trajectories(
                    user_id=user_id,
                    strategy_store=self._strategy_store,
                    episodic_store=self._episodic_store,
                    memory_store=self._memory_store,
                    embedding_client=self._embedding_client,
                    domain_summary_store=self._domain_summary_store,
                )
            except Exception as exc:  # catch-all: canonical refresh best-effort
                logger.debug(
                    "Canonical refresh failed (non-fatal)",
                    extra={
                        "event": "episodic.canonical_refresh_failed",
                        "error": str(exc),
                    },
                    exc_info=True,
                )
