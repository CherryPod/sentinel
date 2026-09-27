"""PatchBackend protocol and AnchorResult dataclass.

Defines the interface that language-specific patch backends implement.
The shared core in executor.py dispatches to these backends for anchor
resolution, replace_inner application, and structural checking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger(__name__)


@dataclass
class AnchorResult:
    """Result of anchor resolution by a PatchBackend.

    The core uses anchor_start/anchor_end for all splice operations.
    Backend-specific metadata flows through to exec_meta for logging.
    """

    anchor_text: str  # Resolved anchor text in raw source
    anchor_start: int  # Character offset of anchor start in file
    anchor_end: int  # Character offset of anchor end in file
    tag_name: str | None = None  # For HTML: the element's tag name
    is_void: bool = False  # For HTML: whether element is self-closing
    prefer_replace_inner: bool = False  # Backend hint: should replace → replace_inner?
    metadata: dict = field(
        default_factory=dict
    )  # Backend-specific metadata for exec_meta


@dataclass
class SurvivalResult:
    """Result of verify_survival — whether the patched target can still be resolved."""

    survived: bool
    reason: str
    new_span_start: int | None = None
    new_span_end: int | None = None
    rerun_metadata: dict | None = None


def verify_survival(
    backend: PatchBackend,
    anchor_result: AnchorResult,
    after: str,
) -> SurvivalResult:
    """Re-run resolve_anchor on patched content to verify the target still exists.

    Reads anchor_key, path, original_span_size, and resolved_structurally from
    anchor_result.metadata. Never raises — all failure modes return SurvivalResult.
    """
    try:
        metadata = anchor_result.metadata
        anchor_key = metadata.get("anchor_key")
        if not anchor_key:
            return SurvivalResult(survived=True, reason="no_anchor_key_fallback")

        path = metadata.get("path", "")
        original_span_size = metadata.get("original_span_size")
        # None when not explicitly set — only Python sets this key
        resolved_structurally = metadata.get("resolved_structurally")

        from sentinel.core.exceptions import ToolError

        try:
            r = backend.resolve_anchor(anchor_key, after, path)
        except ToolError as e:
            logger.warning(
                "patch.survival_rerun_fail: ToolError for anchor '%s': %s",
                anchor_key,
                str(e),
                extra={
                    "event": "patch.survival_rerun_fail",
                    "anchor_key": anchor_key,
                    "reason": str(e),
                },
            )
            return SurvivalResult(survived=False, reason=str(e))

        # Empty span check
        if r.anchor_end <= r.anchor_start:
            return SurvivalResult(survived=False, reason="empty_span")

        # CSS EOF-spanning guard (D7): only applies to CSS sel: anchors.
        # CSS _find_closing_brace returns len(content) on unclosed braces, so the
        # resolved span swallows the rest of the file. Other backends raise ToolError
        # on broken content, so the growth guard would only produce false negatives
        # for those backends (e.g., a tiny Python stub legitimately expanded to a
        # large implementation would falsely trigger span_growth_exceeded).
        rerun_size = r.anchor_end - r.anchor_start
        if original_span_size is not None and anchor_key.startswith("sel:"):
            # _find_closing_brace returns `i+1` for a valid close at position i
            # (so after[r.anchor_end-1] == '}') and returns len(content) as a
            # fallback when no close brace is found. When the fallback fires AND
            # the file doesn't end with '}', after[anchor_end-1] != '}' — that
            # is the unambiguous indicator. When the file ends with '}' the two
            # cases are indistinguishable from anchor_end alone; we rely on the
            # growth_exceeded branch to catch unclosed-brace corruption there.
            at_eof = (
                r.anchor_end >= len(after)
                and after[r.anchor_end - 1 : r.anchor_end] != "}"
            )
            growth_exceeded = rerun_size > original_span_size * 3
            if at_eof or growth_exceeded:
                return SurvivalResult(survived=False, reason="span_growth_exceeded")

        # Python parse-fallthrough detection (D3).
        # Only fires when resolved_structurally is explicitly True (Python AST paths).
        # Other backends do not set this key, so None is the default — no check.
        if (
            resolved_structurally is True
            and anchor_key.startswith(("fn:", "class:"))
            and "function_name" not in r.metadata
            and "class_name" not in r.metadata
        ):
            return SurvivalResult(survived=False, reason="parse_fallthrough_on_rerun")

        logger.debug(
            "patch.survival_rerun_ok: anchor '%s' survived at span %d-%d",
            anchor_key,
            r.anchor_start,
            r.anchor_end,
            extra={
                "event": "patch.survival_rerun_ok",
                "anchor_key": anchor_key,
                "span_start": r.anchor_start,
                "span_end": r.anchor_end,
            },
        )
        return SurvivalResult(
            survived=True,
            reason="resolved",
            new_span_start=r.anchor_start,
            new_span_end=r.anchor_end,
            rerun_metadata=r.metadata,
        )

    except Exception as exc:
        logger.warning(
            "patch.survival_rerun_fail: unexpected error for anchor_result: %s",
            exc,
            extra={
                "event": "patch.survival_rerun_fail",
                "reason": f"verify_error: {exc}",
            },
            exc_info=True,
        )
        return SurvivalResult(survived=False, reason=f"verify_error: {exc}")


class PatchBackend(Protocol):
    """Protocol for language-specific patch backends.

    Each backend handles anchor resolution, replace_inner logic, and
    structural validation for its language. The shared core handles
    everything else (arg validation, policy, backup, code fixer, etc.).
    """

    def resolve_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve an anchor string to a character range in the file content.

        Raises ToolError if anchor cannot be resolved (not found,
        ambiguous, invalid syntax).
        """
        ...

    def apply_replace_inner(
        self,
        content: str,
        anchor_result: AnchorResult,
        new_content: str,
    ) -> str:
        """Apply replace_inner operation. Returns the patched file content.

        Only HTMLPatchBackend implements this meaningfully. TextPatchBackend
        raises ToolError (replace_inner requires DOM awareness).
        """
        ...

    def structural_check(
        self,
        before: str,
        after: str,
        anchor_result: AnchorResult,
        operation: str = "",
    ) -> dict:
        """Post-patch structural validation.

        Returns dict with:
          - survival_ok: bool
          - elements_removed: list[str] (if any)
          - target_id_survived: bool (for HTML CSS selector patches)
          - blocking: bool (True only if target element ID disappeared)
        """
        ...
