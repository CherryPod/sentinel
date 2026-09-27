"""TextPatchBackend — text match and range anchor resolution.

Default backend for non-HTML files. Handles exact text matching,
range anchor syntax (name...name-end), and the css: literal fallback
for non-HTML files.
"""

from __future__ import annotations

import logging
import os

from sentinel.core.exceptions import ToolError
from sentinel.tools.anchor_allocator._core import build_marker
from sentinel.tools.patch_backends._constants import (
    FUZZY_DEDUP_REGION_SIZE,
    REPLACE_ANCHOR_HARD_LIMIT,
    REPLACE_ANCHOR_WARN_LIMIT,
)
from sentinel.tools.patch_backends._protocol import AnchorResult

logger = logging.getLogger(__name__)


class TextPatchBackend:
    """Patch backend for plain text files — exact match and range anchors."""

    def resolve_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
        fuzzy_match: bool = False,
    ) -> AnchorResult:
        """Resolve a text anchor to a character range.

        Three resolution paths:
        1. Range anchor syntax (name...name-end) — marker resolution
        2. Literal text match — exact string, uniqueness enforced
        3. Fuzzy match fallback — opt-in, when exact match fails

        Args:
            fuzzy_match: If True and exact match fails, attempt fuzzy matching
                with similarity >= 85% and proximity constraint. Fail-closed
                when no named anchors exist in the file.
        """
        metadata: dict = {}

        # ── Range anchor syntax (name...name-end) ────────────────────
        if "..." in anchor:
            return self._resolve_range_anchor(anchor, content, path)

        # ── Exact text match ─────────────────────────────────────────
        count = content.count(anchor)
        if count == 0:
            # Try fuzzy matching if opted in
            if fuzzy_match:
                fuzzy_result = self._fuzzy_resolve(anchor, content, path)
                if fuzzy_result is not None:
                    return fuzzy_result

            logger.warning(
                "file_patch: anchor not found in %s",
                path,
                extra={
                    "event": "file.patch_anchor_miss",
                    "path": path,
                    "anchor_length": len(anchor),
                    "anchor_preview": anchor[:80],
                },
            )
            raise ToolError(
                f"Anchor not found in {path}. Re-read the file and copy an exact string."
            )
        logger.debug(
            "resolve_anchor: count_eq_0_passed",
            extra={
                "event": "file.patch_anchor_miss.passed",
                "reason": "count_eq_0_passed",
            },
        )  # auto:neg
        if count > 1:
            logger.warning(
                "file_patch: anchor matched %d locations in %s",
                count,
                path,
                extra={
                    "event": "file.patch_anchor_ambiguous",
                    "path": path,
                    "match_count": count,
                    "anchor_preview": anchor[:80],
                },
            )
            raise ToolError(
                f"Anchor matches {count} locations in {path}. "
                "Use a longer or more specific anchor string."
            )

        idx = content.index(anchor)
        logger.debug(
            "file_patch: text anchor matched at position %d (%d bytes)",
            idx,
            len(anchor),
            extra={
                "event": "file.patch_text_match",
                "path": path,
                "anchor_preview": anchor[:80],
                "match_position": idx,
                "anchor_length": len(anchor),
            },
        )

        return AnchorResult(
            anchor_text=anchor,
            anchor_start=idx,
            anchor_end=idx + len(anchor),
            prefer_replace_inner=False,
            metadata=metadata,
        )

    def check_replace_size(self, anchor: str, path: str) -> dict | None:
        """Check anchor size for replace operations.

        Returns warning metadata dict if anchor is large, raises
        ToolError if anchor exceeds hard limit. Returns None if OK.
        """
        anchor_len = len(anchor)
        if anchor_len > REPLACE_ANCHOR_HARD_LIMIT:
            logger.warning(
                "file_patch: replace anchor is %d chars — rejected",
                anchor_len,
                extra={
                    "event": "file.patch_anchor_too_large",
                    "path": path,
                    "anchor_length": anchor_len,
                },
            )
            raise ToolError(
                f"Replace anchor is {anchor_len} chars — too large for safe "
                "replacement. Use a smaller anchor targeting a specific section, "
                "or use file_write for large-scale rewrites."
            )
        logger.debug(
            "check_replace_size: anchor_len_gt_REPLACE_ANCHOR_HARD_LIMIT_passed",
            extra={
                "event": "file.patch_anchor_too_large.passed",
                "reason": "anchor_len_gt_REPLACE_ANCHOR_HARD_LIMIT_passed",
            },
        )  # auto:neg
        if anchor_len > REPLACE_ANCHOR_WARN_LIMIT:
            logger.debug(
                "file_patch: replace anchor large (%d chars)",
                anchor_len,
                extra={
                    "event": "file.patch_anchor_large_warning",
                    "path": path,
                    "anchor_length": anchor_len,
                },
            )
            return {
                "anchor_size_warning": (
                    f"Replace anchor is {anchor_len} chars — "
                    "verify this targets the intended section"
                )
            }
        return None

    def apply_replace_inner(
        self,
        content: str,
        anchor_result: AnchorResult,
        new_content: str,
    ) -> str:
        """Text files don't support replace_inner."""
        raise ToolError(
            "replace_inner requires an HTML file with a CSS selector anchor"
        )

    def structural_check(
        self,
        before: str,
        after: str,
        anchor_result: AnchorResult,
        operation: str = "",
    ) -> dict:
        """Advisory structural check — delegates to existing utility.

        Text backends never set blocking=True.
        """
        result: dict = {
            "survival_ok": True,
            "elements_removed": [],
            "target_id_survived": True,
            "blocking": False,
        }

        # Determine language for the structural checker
        ext = (
            os.path.splitext(anchor_result.metadata.get("path", ""))[1].lower()
            if "path" in anchor_result.metadata
            else ""
        )
        lang_map = {
            ".js": "javascript",
            ".mjs": "javascript",
            ".py": "python",
            ".css": "css",
        }
        lang = lang_map.get(ext, "")
        if not lang:
            return result

        try:
            from sentinel.analysis.structural_digest import structural_survival_check

            survival = structural_survival_check(before, after, lang)
            if not survival["survival_ok"]:
                result["survival_ok"] = False
                result["elements_removed"] = survival["elements_removed"]
        except Exception as exc:  # catch-all: survival check must not block patch
            logger.warning(
                "file_patch: structural survival check failed: %s",
                exc,
                extra={
                    "event": "structural.survival_error",
                    "error": str(exc),
                },
                exc_info=True,
            )

        return result

    def _resolve_range_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve name...name-end range anchor syntax."""
        start_name, end_name = anchor.split("...", 1)
        start_marker = build_marker(path, start_name.strip())
        end_marker = build_marker(path, end_name.strip())

        if start_marker is None or end_marker is None:
            raise ToolError(
                f"Range anchors not supported for {os.path.splitext(path)[1]} files"
            )

        start_count = content.count(start_marker)
        end_count = content.count(end_marker)

        if start_count != 1:
            raise ToolError(
                f"Range anchor start '{start_name.strip()}' found {start_count} times "
                f"(expected 1) in {path}"
            )
        if end_count != 1:
            raise ToolError(
                f"Range anchor end '{end_name.strip()}' found {end_count} times "
                f"(expected 1) in {path}"
            )

        start_idx = content.index(start_marker)
        end_idx = content.index(end_marker) + len(end_marker)

        if start_idx >= end_idx:
            raise ToolError(f"Range anchor start must come before end in {path}")

        resolved = content[start_idx:end_idx]

        logger.debug(
            "file_patch: range anchor '%s...%s' resolved (%d bytes)",
            start_name.strip(),
            end_name.strip(),
            end_idx - start_idx,
            extra={
                "event": "file.patch_range_resolved",
                "path": path,
                "start_name": start_name.strip(),
                "end_name": end_name.strip(),
                "span_length": end_idx - start_idx,
                "start_position": start_idx,
                "end_position": end_idx,
            },
        )

        return AnchorResult(
            anchor_text=resolved,
            anchor_start=start_idx,
            anchor_end=end_idx,
            prefer_replace_inner=False,
            metadata={
                "range_anchor": True,
                "range_start": start_name.strip(),
                "range_end": end_name.strip(),
            },
        )

    def _fuzzy_resolve(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult | None:
        """Attempt fuzzy matching when exact match fails.

        Returns AnchorResult on single confident match, None on failure.
        Adversarial-aware: requires both similarity AND proximity to
        named anchors. Fail-closed when no anchors exist.
        """
        from difflib import SequenceMatcher

        _SIMILARITY_THRESHOLD = 0.85
        _MAX_DISTANCE_LINES = 200

        logger.debug(
            "file_patch: fuzzy match attempt on %s",
            path,
            extra={
                "event": "file.patch_fuzzy_attempt",
                "path": path,
                "anchor_preview": anchor[:80],
                "exact_match_failed": True,
            },
        )

        # Check for named anchors in the file (from anchor allocator).
        # No anchors = no fuzzy matching (fail-closed).
        anchor_markers = []
        for i, line in enumerate(content.split("\n")):
            if "<!-- @anchor:" in line or "/* @anchor:" in line or "# @anchor:" in line:
                anchor_markers.append(i)

        if not anchor_markers:
            logger.warning(
                "file_patch: fuzzy matching disabled — no named anchors in %s",
                path,
                extra={
                    "event": "file.patch_fuzzy_no_anchors",
                    "path": path,
                },
            )
            return None

        # Sliding window: scan content for regions similar to anchor
        anchor_len = len(anchor)
        candidates = []

        # Step through content with overlapping windows
        for start in range(0, len(content) - anchor_len + 1, max(1, anchor_len // 4)):
            window = content[start : start + anchor_len]
            ratio = SequenceMatcher(None, anchor, window).ratio()
            if ratio >= _SIMILARITY_THRESHOLD:
                candidates.append((start, ratio, window))

        if not candidates:
            return None

        logger.debug(
            "file_patch: fuzzy candidates: %d found, best ratio=%.3f",
            len(candidates),
            max(c[1] for c in candidates),
            extra={
                "event": "file.patch_fuzzy_candidates",
                "path": path,
                "candidate_count": len(candidates),
                "best_ratio": max(c[1] for c in candidates),
                "best_position": max(candidates, key=lambda c: c[1])[0],
            },
        )

        # Proximity filter: candidate must be within _MAX_DISTANCE_LINES
        # of a named anchor
        proximate = []
        for start, ratio, window in candidates:
            cand_line = content[:start].count("\n")
            min_dist = min(abs(cand_line - al) for al in anchor_markers)
            if min_dist <= _MAX_DISTANCE_LINES:
                logger.debug(
                    "_fuzzy_resolve: clean",
                    extra={"event": "file.patch_fuzzy_rejected_distance.clean"},
                )
                proximate.append((start, ratio, window, cand_line, min_dist))
            else:
                logger.debug(
                    "file_patch: fuzzy candidate at pos %d rejected — %d lines from nearest anchor",
                    start,
                    min_dist,
                    extra={
                        "event": "file.patch_fuzzy_rejected_distance",
                        "path": path,
                        "best_position": start,
                        "nearest_anchor": min(
                            anchor_markers, key=lambda a: abs(cand_line - a)
                        ),
                        "distance_lines": min_dist,
                        "max_distance": _MAX_DISTANCE_LINES,
                    },
                )

        if not proximate:
            return None

        # Reject ambiguous — multiple candidates above threshold is dangerous
        # in an untrusted-worker context
        if len(proximate) > 1:
            # Deduplicate overlapping windows (keep best per region)
            logger.debug(
                "_fuzzy_resolve: condition_match",
                extra={
                    "event": "_text._fuzzy_resolve.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            best_by_region: dict[int, tuple] = {}
            for entry in proximate:
                region = entry[0] // FUZZY_DEDUP_REGION_SIZE
                if region not in best_by_region or entry[1] > best_by_region[region][1]:
                    best_by_region[region] = entry
            proximate = list(best_by_region.values())

        if len(proximate) > 1:
            logger.warning(
                "file_patch: fuzzy matching rejected — %d ambiguous candidates in %s",
                len(proximate),
                path,
                extra={
                    "event": "file.patch_fuzzy_rejected_ambiguous",
                    "path": path,
                    "candidate_count": len(proximate),
                },
            )
            return None

        # Single match — accept with warning
        start, ratio, window, cand_line, min_dist = proximate[0]
        nearest_anchor_line = min(anchor_markers, key=lambda a: abs(cand_line - a))

        logger.warning(
            "file_patch: fuzzy match accepted at pos %d (%.1f%% similar, %d lines from anchor)",
            start,
            ratio * 100,
            min_dist,
            extra={
                "event": "file.patch_fuzzy_match",
                "path": path,
                "match_position": start,
                "similarity_ratio": ratio,
                "nearest_anchor": nearest_anchor_line,
                "distance_lines": min_dist,
            },
        )

        return AnchorResult(
            anchor_text=window,
            anchor_start=start,
            anchor_end=start + len(window),
            prefer_replace_inner=False,
            metadata={
                "fuzzy_match_used": True,
                "fuzzy_similarity": ratio,
                "fuzzy_nearest_anchor_line": nearest_anchor_line,
                "fuzzy_distance_lines": min_dist,
            },
        )
