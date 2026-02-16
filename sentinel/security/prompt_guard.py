import logging
from typing import Optional

from sentinel.core.models import ScanMatch, ScanResult

logger = logging.getLogger("sentinel.audit")

# Lazy-loaded pipeline reference
_pipeline = None
_model_name: str = ""


class PromptGuardError(Exception):
    """Error loading or running Prompt Guard model."""


def initialize(model_name: str = "meta-llama/Llama-Prompt-Guard-2-86M") -> bool:
    """Load the Prompt Guard model once. Returns True on success."""
    global _pipeline, _model_name
    _model_name = model_name

    try:
        from transformers import pipeline as hf_pipeline

        _pipeline = hf_pipeline("text-classification", model=model_name)
        logger.info(
            "Prompt Guard loaded",
            extra={"event": "prompt_guard_loaded", "model": model_name},
        )
        return True
    except Exception as exc:
        logger.warning(
            "Prompt Guard model not available: %s",
            exc,
            extra={"event": "prompt_guard_load_failed", "model": model_name},
        )
        _pipeline = None
        return False


def is_loaded() -> bool:
    """Check if the Prompt Guard model is loaded."""
    return _pipeline is not None


def scan(text: str, threshold: float = 0.9) -> ScanResult:
    """Run text through Prompt Guard and return a ScanResult.

    If the model isn't loaded, returns a clean (not found) result — graceful
    degradation. The deterministic scanners still protect the pipeline.

    For text longer than ~512 tokens, we chunk and flag if ANY chunk is
    malicious.
    """
    if _pipeline is None:
        logger.debug(
            "Prompt Guard not loaded, skipping scan",
            extra={"event": "prompt_guard_skipped", "text_length": len(text)},
        )
        return ScanResult(
            found=False,
            matches=[],
            scanner_name="prompt_guard",
        )

    chunks = _segment_text(text, max_chars=2000)
    all_matches: list[ScanMatch] = []

    for i, chunk in enumerate(chunks):
        results = _pipeline(chunk)
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
                "event": "prompt_guard_chunk",
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
                    position=i * 2000,
                )
            )

    return ScanResult(
        found=len(all_matches) > 0,
        matches=all_matches,
        scanner_name="prompt_guard",
    )


def _segment_text(text: str, max_chars: int = 2000) -> list[str]:
    """Split text into chunks for the model's context window."""
    if len(text) <= max_chars:
        return [text]

    chunks = []
    for i in range(0, len(text), max_chars):
        chunks.append(text[i : i + max_chars])
    return chunks
