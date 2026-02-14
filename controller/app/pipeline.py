import hashlib
import logging
import time

from .config import settings
from .models import DataSource, ScanMatch, ScanResult, TaggedData, TrustLevel
from .provenance import create_tagged_data
from .scanner import CommandPatternScanner, CredentialScanner, SensitivePathScanner
from . import prompt_guard
from .spotlighting import apply_datamarking
from .worker import OllamaWorker

logger = logging.getLogger("sentinel.audit")


class SecurityViolation(Exception):
    """Raised when the scan pipeline detects a security violation."""

    def __init__(self, message: str, scan_results: dict[str, ScanResult]):
        super().__init__(message)
        self.scan_results = scan_results


class PipelineScanResult:
    """Aggregated result from all scanners in the pipeline."""

    def __init__(self):
        self.results: dict[str, ScanResult] = {}

    @property
    def is_clean(self) -> bool:
        return not any(r.found for r in self.results.values())

    @property
    def violations(self) -> dict[str, ScanResult]:
        return {k: v for k, v in self.results.items() if v.found}


class ScanPipeline:
    """Orchestrates all security scanners in order."""

    def __init__(
        self,
        cred_scanner: CredentialScanner,
        path_scanner: SensitivePathScanner,
        cmd_scanner: CommandPatternScanner | None = None,
        worker: OllamaWorker | None = None,
    ):
        self._cred_scanner = cred_scanner
        self._path_scanner = path_scanner
        self._cmd_scanner = cmd_scanner or CommandPatternScanner()
        self._worker = worker or OllamaWorker(
            base_url=settings.ollama_url,
            timeout=settings.ollama_timeout,
        )

    def scan_input(self, text: str) -> PipelineScanResult:
        """Scan inbound text (Prompt Guard + deterministic scanners)."""
        t0 = time.monotonic()
        result = PipelineScanResult()

        # Fail-closed: if PromptGuard is required but unavailable, block
        if settings.prompt_guard_enabled and settings.require_prompt_guard and not prompt_guard.is_loaded():
            result.results["prompt_guard"] = ScanResult(
                found=True,
                matches=[ScanMatch(
                    pattern_name="scanner_unavailable",
                    matched_text="Prompt Guard required but not loaded",
                )],
                scanner_name="prompt_guard",
            )
            return result

        if settings.prompt_guard_enabled:
            result.results["prompt_guard"] = prompt_guard.scan(
                text, threshold=settings.prompt_guard_threshold
            )

        # Run deterministic scanners on input too — catches obvious
        # credential leaks, sensitive path references, and dangerous
        # command patterns before they even reach the planner.
        result.results["credential_scanner"] = self._cred_scanner.scan(text)
        result.results["sensitive_path_scanner"] = self._path_scanner.scan(text)
        result.results["command_pattern_scanner"] = self._cmd_scanner.scan(text)

        elapsed = time.monotonic() - t0

        for scanner_name, sr in result.results.items():
            if sr.found:
                logger.warning(
                    "Input scanner found matches",
                    extra={
                        "event": "input_scanner_match",
                        "scanner": scanner_name,
                        "match_count": len(sr.matches),
                        "patterns": [m.pattern_name for m in sr.matches],
                    },
                )

        logger.info(
            "Input scan complete",
            extra={
                "event": "scan_input",
                "clean": result.is_clean,
                "scanners": list(result.results.keys()),
                "violations": list(result.violations.keys()),
                "text_length": len(text),
                "elapsed_s": round(elapsed, 3),
            },
        )
        return result

    def scan_output(self, text: str) -> PipelineScanResult:
        """Scan Qwen output (Prompt Guard + credential + sensitive path)."""
        t0 = time.monotonic()
        result = PipelineScanResult()

        # Fail-closed: if PromptGuard is required but unavailable, block
        if settings.prompt_guard_enabled and settings.require_prompt_guard and not prompt_guard.is_loaded():
            result.results["prompt_guard"] = ScanResult(
                found=True,
                matches=[ScanMatch(
                    pattern_name="scanner_unavailable",
                    matched_text="Prompt Guard required but not loaded",
                )],
                scanner_name="prompt_guard",
            )
            return result

        if settings.prompt_guard_enabled:
            result.results["prompt_guard"] = prompt_guard.scan(
                text, threshold=settings.prompt_guard_threshold
            )

        result.results["credential_scanner"] = self._cred_scanner.scan(text)
        result.results["sensitive_path_scanner"] = self._path_scanner.scan(text)
        result.results["command_pattern_scanner"] = self._cmd_scanner.scan(text)

        elapsed = time.monotonic() - t0

        # Log detailed match info for each scanner
        for scanner_name, sr in result.results.items():
            if sr.found:
                logger.warning(
                    "Scanner found matches",
                    extra={
                        "event": "scanner_match",
                        "scanner": scanner_name,
                        "match_count": len(sr.matches),
                        "patterns": [m.pattern_name for m in sr.matches],
                    },
                )

        logger.info(
            "Output scan complete",
            extra={
                "event": "scan_output",
                "clean": result.is_clean,
                "scanners": list(result.results.keys()),
                "violations": list(result.violations.keys()),
                "text_length": len(text),
                "elapsed_s": round(elapsed, 3),
            },
        )
        return result

    async def process_with_qwen(
        self,
        prompt: str,
        untrusted_data: str | None = None,
    ) -> TaggedData:
        """Full pipeline: scan → spotlight → Qwen → scan → tag.

        Raises SecurityViolation if any scan fails.
        """
        # 1. Scan input via Prompt Guard
        input_scan = self.scan_input(prompt)
        if not input_scan.is_clean:
            logger.warning(
                "Input blocked by scan pipeline",
                extra={
                    "event": "input_blocked",
                    "violations": list(input_scan.violations.keys()),
                },
            )
            raise SecurityViolation(
                "Input blocked by security scan",
                input_scan.violations,
            )

        # 2. Apply spotlighting to untrusted data
        if untrusted_data and settings.spotlighting_enabled:
            marked_data = apply_datamarking(
                untrusted_data,
                marker=settings.spotlighting_marker,
            )
            full_prompt = f"{prompt}\n\nData:\n{marked_data}"
        elif untrusted_data:
            full_prompt = f"{prompt}\n\nData:\n{untrusted_data}"
        else:
            full_prompt = prompt

        prompt_hash = hashlib.sha256(full_prompt.encode()).hexdigest()[:16]
        logger.info(
            "Sending to Qwen",
            extra={
                "event": "qwen_request",
                "prompt_length": len(full_prompt),
                "prompt_hash": prompt_hash,
                "spotlighted": bool(untrusted_data) and settings.spotlighting_enabled,
                "model": settings.ollama_model,
            },
        )

        # 3. Send to Qwen
        t0 = time.monotonic()
        response_text = await self._worker.generate(
            prompt=full_prompt,
            model=settings.ollama_model,
        )
        qwen_elapsed = time.monotonic() - t0

        logger.info(
            "Qwen response received",
            extra={
                "event": "qwen_response",
                "response_length": len(response_text),
                "elapsed_s": round(qwen_elapsed, 2),
                "prompt_hash": prompt_hash,
            },
        )
        logger.debug(
            "Qwen response preview",
            extra={
                "event": "qwen_response_preview",
                "content_preview": response_text[:500],
                "prompt_hash": prompt_hash,
            },
        )

        # 4. Tag output as UNTRUSTED
        tagged = create_tagged_data(
            content=response_text,
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="qwen_pipeline",
        )
        logger.debug(
            "Tagged data created",
            extra={
                "event": "tagged_data_created",
                "data_id": tagged.id,
                "source": "qwen",
                "trust_level": "untrusted",
            },
        )

        # 5. Scan output
        output_scan = self.scan_output(response_text)
        tagged.scan_results = output_scan.results

        if not output_scan.is_clean:
            logger.warning(
                "Qwen output blocked by scan pipeline",
                extra={
                    "event": "output_blocked",
                    "violations": list(output_scan.violations.keys()),
                    "data_id": tagged.id,
                },
            )
            raise SecurityViolation(
                "Qwen output blocked by security scan",
                output_scan.violations,
            )

        logger.info(
            "Pipeline complete — output clean",
            extra={
                "event": "pipeline_complete",
                "data_id": tagged.id,
                "trust_level": tagged.trust_level.value,
            },
        )
        return tagged
