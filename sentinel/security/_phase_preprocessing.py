"""Preprocessing phase for the security scanner pipeline.

Orchestrates encoding normalisation and context classification to produce
the frozen ``ScanContext`` consumed by all scanners.  Runs once per scan
pass — scanners never call the normalizer or classifier directly.
"""

from __future__ import annotations

import logging

from sentinel.security._encoding_normalizer import EncodingNormalizer
from sentinel.security._scan_context import ScanContext, ScanMetadata
from sentinel.security.context_classifier import classify_regions
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)


class Preprocessor:
    """Produces ``ScanContext`` from raw text and scan metadata.

    Orchestrates:
      1. ``EncodingNormalizer.decode(raw_text)`` → decoded variants
      2. ``normalise_homoglyphs(raw_text)`` → normalised_text (shared coordinate space)
      3. ``classify_regions(normalised_text)`` → context regions
      4. Assembles frozen ``ScanContext``
    """

    def __init__(
        self,
        normalizer: EncodingNormalizer,
    ) -> None:
        self._normalizer = normalizer

    def process(self, raw_text: str, metadata: ScanMetadata) -> ScanContext:
        """Run preprocessing and return an immutable ``ScanContext``.

        Args:
            raw_text: The text to scan (already stripped of outer fences
                      by the pipeline caller).
            metadata: Per-scan metadata (phase, destination, trust level).

        Returns:
            Frozen ``ScanContext`` ready for scanner consumption.
        """
        logger.debug(
            "preprocessing.process called",
            extra={
                "event": "security.preprocessing.start",
                "text_len": len(raw_text),
                "phase": metadata.phase.value,
            },
        )

        # Step 1: Decode encoded content
        decoded_variants = self._normalizer.decode(raw_text)

        # Step 2: Normalise homoglyphs once — this is the shared coordinate
        # space for all scanners and suppression handlers.  classify_regions
        # and every scanner must operate on the same string so that
        # ScanMatch.offset and ContextRegion.start/end are comparable.
        normalised_text = normalise_homoglyphs(raw_text)

        # Step 3: Classify text regions on the normalised string so region
        # offsets are in the same space as scanner match offsets.
        regions = classify_regions(normalised_text)

        # Step 4: Assemble immutable context
        context = ScanContext(
            raw_text=raw_text,
            regions=regions,
            decoded_variants=decoded_variants,
            metadata=metadata,
            normalised_text=normalised_text,
        )

        # Summarise decode chains for logging (no raw content)
        decode_chains = [
            ":".join(e.value for e in v.decode_chain) for v in decoded_variants
        ]

        logger.debug(
            "preprocessing.process complete",
            extra={
                "event": "security.preprocessing.complete",
                "variant_count": len(decoded_variants),
                "region_count": len(regions),
                "decode_chains": decode_chains,
            },
        )

        return context
