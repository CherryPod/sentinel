"""PromptGuard ML-based injection detection.

Runs text through Meta's Llama Prompt Guard model to detect injection
attempts. Falls back to clean results if the model is unavailable —
deterministic scanners still protect the pipeline.
"""

import asyncio
import logging

from sentinel.core.models import ScanMatch, ScanResult

logger = logging.getLogger(__name__)

# Lazy-loaded pipeline reference
_pipeline = None
_model_name: str = ""

# Moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import PromptGuardError  # noqa: F401


def initialize(model_name: str = "meta-llama/Llama-Prompt-Guard-2-86M") -> bool:
    """Load the Prompt Guard model once. Returns True on success."""
    global _pipeline, _model_name
    _model_name = model_name

    try:
        from transformers import pipeline as hf_pipeline

        _pipeline = hf_pipeline("text-classification", model=model_name)
        logger.info(
            "Prompt Guard loaded",
            extra={"event": "prompt_guard.loaded", "model": model_name},
        )
        return True
    except Exception as exc:  # catch-all: HF model load (network, CUDA, format errors)
        logger.warning(
            "Prompt Guard model not available: %s",
            exc,
            extra={"event": "prompt_guard.load_failed", "model": model_name},
            exc_info=True,
        )
        _pipeline = None
        return False


def is_loaded() -> bool:
    """Check if the Prompt Guard model is loaded."""
    return _pipeline is not None


async def scan(text: str, threshold: float = 0.9) -> ScanResult:
    """Run text through Prompt Guard and return a ScanResult.

    If the model isn't loaded, returns a clean (not found) result — graceful
    degradation. The deterministic scanners still protect the pipeline.

    For text longer than ~512 tokens, we chunk and flag if ANY chunk is
    malicious. Inference is offloaded to a thread pool worker via
    asyncio.to_thread() so the event loop stays responsive.
    """
    if _pipeline is None:
        logger.warning(
            "Prompt Guard not loaded — scan skipped (degraded mode)",
            extra={"event": "prompt_guard.skipped", "text_length": len(text)},
        )
        return ScanResult(
            found=False,
            matches=[],
            scanner_name="prompt_guard",
            degraded=True,
        )

    logger.debug(
        "PromptGuard scan started",
        extra={
            "event": "prompt_guard.scan",
            "text_len": len(text),
            "threshold": threshold,
        },
    )
    chunk_size = _CHUNK_SIZE
    overlap = _CHUNK_OVERLAP
    stride = chunk_size - overlap
    chunks = _segment_text(text, max_chars=chunk_size)
    all_matches: list[ScanMatch] = []

    for i, chunk in enumerate(chunks):
        # F-006: Per-chunk exception handling — fail-closed. A chunk that
        # causes inference failure is treated as flagged (conservative).
        try:
            results = await asyncio.to_thread(_pipeline, chunk)
        except Exception:  # catch-all: ML inference on untrusted input (fail-closed)
            logger.warning(
                "Prompt Guard inference failed on chunk %d — treating as flagged (fail-closed)",
                i,
                extra={"event": "prompt_guard.chunk_error", "chunk_index": i},
                exc_info=True,
            )
            all_matches.append(
                ScanMatch(
                    pattern_name="prompt_guard_inference_error",
                    matched_text=f"inference_error_chunk_{i} (len={len(chunk)})",
                    position=i * stride,
                )
            )
            continue
        if not results:
            continue

        # The pipeline returns a list of dicts: [{"label": ..., "score": ...}]
        top = results[0]
        label = top.get("label", "")
        score = top.get("score", 0.0)

        # Prompt Guard v1 labels: BENIGN, INJECTION, JAILBREAK
        # Prompt Guard v2 labels: LABEL_0 (benign), LABEL_1 (malicious)
        benign_labels = {"BENIGN", "LABEL_0"}
        logger.debug(
            "Prompt Guard chunk result",
            extra={
                "event": "prompt_guard.chunk",
                "chunk_index": i,
                "label": label,
                "score": round(score, 4),
                "malicious": label not in benign_labels and score >= threshold,
            },
        )
        if label not in benign_labels and score >= threshold:
            all_matches.append(
                ScanMatch(
                    pattern_name=f"prompt_guard_{label.lower()}",
                    matched_text=chunk[:200],  # truncate for logging
                    position=i * stride,
                )
            )

    result = ScanResult(
        found=len(all_matches) > 0,
        matches=all_matches,
        scanner_name="prompt_guard",
    )
    logger.debug(
        "PromptGuard scan complete",
        extra={
            "event": "prompt_guard.scan_complete",
            "found": result.found,
            "match_count": len(all_matches),
        },
    )
    return result


# Module-level constants for chunk sizing
_CHUNK_SIZE = 2000
_CHUNK_OVERLAP = 200


def _segment_text(text: str, max_chars: int = _CHUNK_SIZE) -> list[str]:
    """Split text into chunks for the model's context window."""
    logger.debug(
        "_segment_text called",
        extra={
            "event": "prompt_guard._segment_text",
            "text_len": len(text) if hasattr(text, "__len__") else 0,
            "max_chars": max_chars,
        },
    )  # auto:entry
    if len(text) <= max_chars:
        return [text]

    # F-005: Overlap chunks by 200 chars so injections straddling a boundary
    # are captured in at least one complete chunk.
    overlap = _CHUNK_OVERLAP
    stride = max_chars - overlap
    chunks = []
    for i in range(0, len(text), stride):
        chunks.append(text[i : i + max_chars])
    return chunks
