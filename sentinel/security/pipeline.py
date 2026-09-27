"""Security scanning pipeline for Qwen worker output.

Orchestrates multi-layer scanning (credential, path, command, encoding,
prompt-guard, semgrep, vulnerability-echo) on both input prompts and
worker output, enforcing fail-closed semantics and trust boundaries.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

from sentinel.core.config import settings
from sentinel.core.context import get_task_id, spawn_task
from sentinel.core.models import (
    OutputDestination,
    TaggedData,
)
from sentinel.worker.base import WorkerBase
from sentinel.worker.ollama import OllamaWorker

from . import _worker_interaction, prompt_guard
from ._phase_input import run_input_scan, validate_input
from ._phase_output import run_output_scan, scan_output_and_finalize
from ._phase_preprocessing import Preprocessor
from ._rule_schema import RuleDefinition
from ._scan_context import ScanResult, SuppressionVerdict
from ._scanner_names import (
    scanner_is_security,
    scanner_legacy_name,
    scanner_order,
)
from ._scanner_registry import ScannerPlugin
from ._suppression import SuppressionEngine

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sentinel.audit.emitter import AuditEmitter

logger = logging.getLogger(__name__)


# Re-exports consumed by external code (tests, planner, router).
# Keep these even though pipeline.py no longer uses them directly.
from sentinel.core.exceptions import (  # noqa: F401 — re-export for test_pipeline_audit
    SecurityViolation,
    ViolationPhase,
)

from ._input_gates import (
    _MAX_PROMPT_CHARS,  # noqa: F401 — re-export for test_pipeline_audit
)


def _pg_stub_context():
    """Build a stub ``ScanContext`` for synthetic PG availability outcomes.

    The ``raw_text`` is empty because scanner audit builders read the
    actual scan text from ``audit_ctx["text"]``; the synthetic context's
    ``raw_text`` is not exposed in any audit field.  Phase is set to
    ``INPUT`` for consistency with the pre-H1 synthesizer — the phase is
    not consumed by downstream code for this synthetic result.
    """
    from ._enums import Phase
    from ._scan_context import ScanContext, ScanMetadata

    return ScanContext(
        raw_text="",
        regions=(),
        decoded_variants=(),
        metadata=ScanMetadata(
            phase=Phase.INPUT,
            output_destination=None,
            trust_level=0,
            tool_target=None,
            input_text=None,
        ),
    )


def _synthesize_pg_blocked_result() -> ScanResult:
    """Return a synthetic blocked ``ScanResult`` for require-PG + not-loaded.

    Single CRITICAL unsuppressed verdict with rule_id
    ``scanner_unavailable``.  Callers propagate this as the PG outcome
    for the scan and remove ``PromptGuardScanner`` from their dispatch
    list to avoid double-counting.

    Emits a deliberate dual signal on the audit wire: the derived
    scan.result carries ``outcome="BLOCKED"`` (because the verdict is
    CRITICAL + unsuppressed, which ``build_scan_result_event`` reads as
    found → BLOCKED) *and* ``degraded=True`` (because
    ``degraded_scanners={"prompt_guard"}``).  BLOCKED tells the policy
    layer to fail the scan; degraded tells ops the block came from a
    missing model, not from a detection.  The pre-H1 inline-PG path
    emitted the same pair.
    """
    logger.debug(
        "_synthesize_pg_blocked_result called",
        extra={"event": "security.pipeline._synthesize_pg_blocked_result"},
    )  # auto:entry
    from ._enums import Severity
    from ._scan_context import (
        MLMatchMeta,
        ScanMatch,
    )

    stub_match = ScanMatch(
        rule_id="scanner_unavailable",
        scanner="prompt_guard",
        severity=Severity.CRITICAL,
        confidence=1.0,
        matched_text="Prompt Guard required but not loaded",
        offset=0,
        length=0,
        region=None,
        metadata=MLMatchMeta(model_name="prompt_guard", model_confidence=0.0),
    )
    stub_verdict = SuppressionVerdict(
        match=stub_match,
        suppressed=False,
        canonical_reason=None,
        all_reasons=(),
    )
    return ScanResult(
        found=True,
        verdicts=(stub_verdict,),
        context=_pg_stub_context(),
        degraded_scanners=frozenset({"prompt_guard"}),
    )


def _synthesize_pg_clean_degraded_result() -> ScanResult:
    """Return a synthetic clean-degraded ``ScanResult`` for enabled + not-loaded.

    Preserves the pre-H1 semantic that PG enabled but model unloaded
    with ``require_prompt_guard=False`` produces a clean result with
    ``degraded_scanners={"prompt_guard"}``.  Empty verdicts mean the
    scan.result outcome is ``CLEAN`` with ``degraded=True``.
    """
    return ScanResult(
        found=False,
        verdicts=(),
        context=_pg_stub_context(),
        degraded_scanners=frozenset({"prompt_guard"}),
    )


class ScanPipeline:
    """Orchestrates all security scanners in order."""

    def __init__(
        self,
        scanners: Sequence[ScannerPlugin],
        *,
        suppression: SuppressionEngine,
        preprocessor: Preprocessor,
        rules: Mapping[str, RuleDefinition],
        worker: WorkerBase | None = None,
        audit_emitter: AuditEmitter | None = None,
    ):
        # Phase 9b-i: `suppression`, `preprocessor`, and `rules` are
        # stored here but not yet consumed by `scan_input`/`scan_output`.
        # The async cutover in Phase 9b-ii wires them into the dispatch
        # path. Keeping the parameters required now decouples the
        # signature change from the behavioural change, so each phase
        # has its own rollback.
        self._suppression = suppression
        self._preprocessor = preprocessor
        self._rules = rules

        # Sort scanners by declared order, preserve registration order for ties.
        self._scanners: list[ScannerPlugin] = sorted(scanners, key=scanner_order)

        # Reject duplicate declared orders at construction time. Silent
        # ordering ambiguity would be a lurking-bug vector in a security
        # pipeline — scanners that disagree on execution order could
        # reorder themselves at any registration-order perturbation.
        self._assert_unique_orders(self._scanners)

        self._scanner_by_name = self._build_scanner_index(self._scanners)
        self._audit_emitter = audit_emitter

        # Stable hash of scanner names + order for audit trail reproducibility.
        # Names are routed through ``scanner_legacy_name`` so the hash is
        # invariant across the old→new scanner transition (input hash
        # reads ``"credential_scanner:100|..."`` in both shapes).
        scanner_sig = "|".join(
            f"{scanner_legacy_name(s)}:{scanner_order(s)}" for s in self._scanners
        )
        self._scanner_config_hash = hashlib.sha256(scanner_sig.encode()).hexdigest()[
            :16
        ]

        logger.debug(
            "Pipeline initialised with %d scanners",
            len(self._scanners),
            extra={
                "event": "pipeline.init",
                "scanner_names": [scanner_legacy_name(s) for s in self._scanners],
            },
        )

        # OllamaWorker created at init — required for most operations (process_with_qwen).
        # Lazy init would add complexity for marginal benefit since the pipeline
        # is typically long-lived and the worker is used on every task.
        self._worker = worker or OllamaWorker(
            base_url=settings.ollama_url,
            timeout=settings.ollama_timeout,
            model=settings.ollama_model,
        )

        if settings.baseline_mode and settings.trust_level >= 3:
            raise RuntimeError(
                f"Baseline mode cannot be active at trust level "
                f"{settings.trust_level} (>= 3). Disable "
                f"SENTINEL_BASELINE_MODE or lower the trust level."
            )

        if settings.baseline_mode:
            logger.error(
                "BASELINE MODE ACTIVE — ALL security scanning is DISABLED",
                extra={"event": "baseline.mode_active"},
            )

    @staticmethod
    def _build_scanner_index(
        scanners: Sequence[ScannerPlugin],
    ) -> dict[str, ScannerPlugin]:
        """Build the name → scanner lookup, rejecting duplicate names.

        Phase 9b-i moved the vulnerability-echo scanner into the
        ``scanners`` list and made ``_phase_output`` look it up by
        name. Before this change, a duplicate scanner name logged a
        warning and let the later registration silently shadow the
        first. That behaviour was already a latent bug vector; with
        name-based echo lookup it becomes a trust-boundary concern —
        a stray second registration of ``vulnerability_echo_scanner``
        would silently replace the real one.

        Treat duplicate names the same as duplicate orders: fail
        closed at construction time.
        """
        index: dict[str, ScannerPlugin] = {}
        for s in scanners:
            name = scanner_legacy_name(s)
            existing = index.get(name)
            if existing is not None:
                logger.error(
                    "Duplicate scanner name",
                    extra={
                        "event": "security.scanner.duplicate_name",
                        "scanner": name,
                    },
                )
                raise ValueError(
                    f"Duplicate scanner name: '{name}' is registered more than once",
                )
            index[name] = s
        return index

    @staticmethod
    def _assert_unique_orders(scanners: Sequence[ScannerPlugin]) -> None:
        """Raise ``ValueError`` if any two scanners declare the same order.

        Scanners opt into an execution order via their metadata (legacy
        ``scanner_info.order`` or new ``scanner_meta.order``).
        Two scanners that share an order rely on registration order to
        tie-break, which is invisible and easy to perturb. In a security
        pipeline, a reorder is a silent correctness change — e.g. a
        credential detector running after an encoding normaliser versus
        before would report different matches. Catch the conflict at
        construction time rather than letting it drift through audit
        logs.
        """
        seen: dict[int, str] = {}
        for s in scanners:
            order = scanner_order(s)
            name = scanner_legacy_name(s)
            existing = seen.get(order)
            if existing is not None:
                logger.error(
                    "Scanner order conflict",
                    extra={
                        "event": "security.scanner.order_conflict",
                        "name_a": existing,
                        "name_b": name,
                        "order": order,
                    },
                )
                raise ValueError(
                    f"Scanner order conflict: '{existing}' and "
                    f"'{name}' both declare order={order}",
                )
            seen[order] = name

    @property
    def security_scanner_names(self) -> frozenset[str]:
        """Names of all registered scanners classified as security scanners.

        Used by conversation analysis to classify block categories. The
        echo scanner is part of ``_scanners`` from Phase 9b-i onwards,
        so no separate branch is needed.
        """
        return frozenset(
            scanner_legacy_name(s) for s in self._scanners if scanner_is_security(s)
        )

    @staticmethod
    def _check_prompt_guard_available() -> ScanResult | None:
        """Resolve PromptGuard availability for the current scan.

        Returns ``None`` when PG can be dispatched normally — callers
        proceed with the standard scanner flow.  Returns a synthetic
        ``ScanResult`` representing the pre-dispatch outcome when PG is
        enabled but the model is not loaded; callers MUST then:

          1. Remove any ``PromptGuardScanner`` from their dispatch list
             (otherwise PG would execute twice — once via this synthetic
             result, once via ``PromptGuardScanner``'s own fail-closed
             path).
          2. Merge the synthetic result's verdicts and
             ``degraded_scanners`` set into their per-scanner aggregate.

        Outcome matrix:

        ===============  =====================  ==========  =========================================
        ``enabled``      ``require_pg``          Loaded?     Return
        ===============  =====================  ==========  =========================================
        ``False``        — (any)                —           ``None`` (no PG in list anyway)
        ``True``         — (any)                ``True``    ``None`` (dispatch PG normally)
        ``True``         ``True``               ``False``   Synthetic BLOCKED (CRITICAL, unsuppressed)
        ``True``         ``False``              ``False``   Synthetic CLEAN-DEGRADED (no verdicts,
                                                            ``degraded_scanners={"prompt_guard"}``)
        ===============  =====================  ==========  =========================================

        The CLEAN-DEGRADED outcome preserves the pre-H1 semantic that
        PG enabled + require=False + not loaded yields a clean-degraded
        ScanResult (previously produced by the inline-PG shim calling
        ``prompt_guard.scan()`` against an unloaded model).
        """
        logger.debug(
            "prompt_guard availability resolver",
            extra={
                "event": "security.pipeline.pg_availability.resolve_start",
                "enabled": settings.prompt_guard_enabled,
                "require": settings.require_prompt_guard,
                "loaded": prompt_guard.is_loaded(),
            },
        )
        if not settings.prompt_guard_enabled:
            logger.debug(
                "prompt_guard disabled — dispatch skips PG",
                extra={
                    "event": "security.pipeline.pg_availability.disabled",
                },
            )  # auto:neg
            return None
        logger.debug(
            "_check_prompt_guard_available: not_prompt_guard_enabled_passed",
            extra={
                "event": "security.pipeline.pg_availability.disabled.passed",
                "reason": "not_prompt_guard_enabled_passed",
            },
        )  # auto:neg
        if prompt_guard.is_loaded():
            logger.debug(
                "prompt_guard available — normal dispatch",
                extra={
                    "event": "security.pipeline.pg_availability.available",
                },
            )  # auto:neg
            return None
        logger.debug(
            "_check_prompt_guard_available: is_loaded_passed",
            extra={
                "event": "security.pipeline.pg_availability.available.passed",
                "reason": "is_loaded_passed",
            },
        )  # auto:neg
        if settings.require_prompt_guard:
            logger.warning(
                "PromptGuard required but unavailable — failing closed",
                extra={
                    "event": "security.pipeline.pg_availability.skip_blocked",
                },
            )
            return _synthesize_pg_blocked_result()
        logger.warning(
            "PromptGuard enabled but unavailable — clean-degraded",
            extra={
                "event": "security.pipeline.pg_availability.skip_clean_degraded",
            },
        )
        return _synthesize_pg_clean_degraded_result()

    def _schedule_audit_events(self, event_dicts: list[dict]) -> None:
        """Schedule audit event emission as a fire-and-forget background task.

        Project policy for async work: user-scoped
        background work uses ``spawn_task`` from ``sentinel.core.context``.
        The emitter reads ``current_user_id`` / ``current_task_id`` /
        ``current_request_id`` in ``audit/emitter.py:_build_db_payload``
        and routes the write pool on ``user_id`` — so this call site is
        user-scoped background work, and the blessed idiom applies.
        """
        if not self._audit_emitter or not event_dicts:
            return
        try:
            spawn_task(self._emit_audit_events(event_dicts))
        except RuntimeError:
            pass  # No event loop — skip audit (test environments)

    async def _emit_audit_events(
        self,
        event_dicts: list[dict],
    ) -> None:
        """Emit collected audit events, swallowing all failures."""
        from sentinel.audit.events import SecurityAuditEvent

        for event_dict in event_dicts:
            try:
                event = SecurityAuditEvent(**event_dict)
                await self._audit_emitter.emit(event)
            except Exception:
                logger.debug(
                    "Audit event emission failed — continuing",
                    extra={
                        "event": "pipeline.audit_emit_failed",
                        "event_type": event_dict.get("event_type", "unknown"),
                    },
                    exc_info=True,
                )

    def _build_audit_ctx(
        self,
        text: str,
        scan_path: str,
        pipeline_run_id: str,
    ) -> dict | None:
        """Build audit context dict if emitter is configured, else None."""
        if self._audit_emitter is None:
            return None
        return {
            "text": text,
            "scan_path": scan_path,
            "pipeline_run_id": pipeline_run_id,
            "scanner_config_hash": self._scanner_config_hash,
        }

    async def scan_input(
        self,
        text: str,
        *,
        context_aware_paths: bool = False,
    ) -> ScanResult:
        """Scan inbound text (Prompt Guard + deterministic scanners).

        Returns the new frozen ``ScanResult`` from ``_scan_context``.
        Callers iterate ``result.verdicts`` or use the per-scanner
        helpers (``unsuppressed_by_scanner``, ``violated_scanners``).
        """
        return await run_input_scan(self, text, context_aware_paths)

    async def scan_output(
        self,
        text: str,
        destination: OutputDestination = OutputDestination.EXECUTION,
        *,
        user_input: str | None = None,
        pipeline_run_id: str | None = None,
    ) -> ScanResult:
        """Scan Qwen output (Prompt Guard + deterministic scanners).

        Returns the new frozen ``ScanResult`` from ``_scan_context``.

        ``user_input`` flows through to ``ScanMetadata.input_text`` so
        the echo scanner (unified into dispatch in 9b-ii) can compare
        the user's request against the Qwen output.  Legacy callers
        omit it; ``scan_output_and_finalize`` threads it when
        available.

        Q17-F4 (D3, 2026-04-24): ``pipeline_run_id`` is optional
        caller-owned correlation.  The tool-dispatch seam allocates
        the id at ``_dispatch_external_tool`` so ``tool.*`` and
        ``scan.*`` events share the same key; other callers
        (fast-path routes, tests, direct API usage) continue to omit
        it and ``run_output_scan`` allocates a fresh id.
        """
        return await run_output_scan(
            self,
            text,
            destination,
            user_input=user_input,
            pipeline_run_id=pipeline_run_id,
        )

    async def _validate_input(
        self,
        prompt: str,
        untrusted_data: str | None,
        skip_input_scan: bool,
    ) -> None:
        """Pre-flight validation: input scan, script gate, prompt length gates.

        Delegates to _phase_input.validate_input — see that module for
        the full implementation.
        """
        await validate_input(self, prompt, untrusted_data, skip_input_scan)

    async def _scan_output_and_finalize(
        self,
        tagged: TaggedData,
        response_text: str,
        user_input: str | None,
        destination: OutputDestination,
        spotlighting_active: bool,
    ) -> None:
        """Scan tagged output, run echo scan, log pipeline completion.

        Delegates to _phase_output.scan_output_and_finalize — see that
        module for the full implementation.
        """
        await scan_output_and_finalize(
            self, tagged, response_text, user_input, destination, spotlighting_active
        )

    async def process_with_qwen(
        self,
        prompt: str,
        untrusted_data: str | None = None,
        marker: str | None = None,
        skip_input_scan: bool = False,
        user_input: str | None = None,
        destination: OutputDestination = OutputDestination.EXECUTION,
    ) -> tuple[TaggedData, dict | None]:
        """Full pipeline: scan → spotlight → Qwen → scan → tag.

        Returns (tagged_data, worker_stats) where worker_stats contains Ollama
        token stats (eval_count, prompt_eval_count, etc.) or None.

        Raises SecurityViolation if any scan fails.
        """
        # 1. Pre-flight validation: input scan, script gate, prompt length gates
        await self._validate_input(prompt, untrusted_data, skip_input_scan)

        # 2. Assemble prompt with spotlighting + sandwich defence
        full_prompt, marker, spotlighting_active = _worker_interaction._assemble_prompt(
            prompt,
            untrusted_data,
            marker,
            settings=settings,
        )

        prompt_hash = hashlib.sha256(full_prompt.encode()).hexdigest()[:16]
        logger.info(
            "Sending to Qwen",
            extra={
                "event": "qwen.request",
                "task_id": get_task_id(),
                "prompt_length": len(full_prompt),
                "prompt_hash": prompt_hash,
                "spotlighted": bool(untrusted_data) and spotlighting_active,
                "model": settings.ollama_model,
            },
        )

        # 3. Send to Qwen (with single retry on empty response)
        response_text, worker_stats = await _worker_interaction._call_qwen_with_retry(
            self._worker,
            full_prompt,
            marker,
            prompt_hash,
            settings=settings,
        )

        # 4. Post-process: marker strip, think-block strip, tag as UNTRUSTED
        tagged, response_text = await _worker_interaction._postprocess_response(
            response_text,
            marker,
        )

        # 5. Scan output, run echo scan, finalize
        await self._scan_output_and_finalize(
            tagged, response_text, user_input, destination, spotlighting_active
        )

        return tagged, worker_stats
