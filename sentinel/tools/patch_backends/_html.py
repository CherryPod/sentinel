"""HTMLPatchBackend — CSS selector anchor resolution for HTML files.

Handles css: prefix anchors via BeautifulSoup, replace_inner with DOM
awareness, and structural checking with targeted element ID survival.
"""

from __future__ import annotations

import logging

from sentinel.core.exceptions import ToolError
from sentinel.tools.patch_backends._protocol import AnchorResult, verify_survival

logger = logging.getLogger(__name__)


class HTMLPatchBackend:
    """Patch backend for HTML files using CSS selector anchors."""

    def resolve_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve a css: anchor to a character range via BeautifulSoup.

        The selector must match exactly one element. The resolved span
        covers the full element from opening tag to closing tag in the
        raw source (not BeautifulSoup's serialised form).
        """

        if not anchor.startswith("css:"):
            logger.debug(
                "resolve_anchor: not_startswith_css:",
                extra={
                    "event": "html.resolve_anchor.match",
                    "reason": "not_startswith_css:",
                },
            )  # auto:neg
            raise ToolError(
                "HTMLPatchBackend.resolve_anchor called without css: prefix. "
                "This is a bug in backend dispatch."
            )
        logger.debug(
            "resolve_anchor: not_startswith_css:_passed",
            extra={
                "event": "html.resolve_anchor.passed",
                "reason": "not_startswith_css:_passed",
            },
        )  # auto:neg

        selector = anchor[4:].strip()
        if not selector:
            logger.debug(
                "resolve_anchor: not_selector",
                extra={"event": "html.resolve_anchor.match", "reason": "not_selector"},
            )  # auto:neg
            raise ToolError(
                "css: prefix requires a CSS selector (e.g. css:#panel-weather)"
            )

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(content, "html.parser")
        matches = soup.select(selector)

        logger.debug(
            "file_patch: CSS selector '%s' -> %d matches",
            selector,
            len(matches),
            extra={
                "event": "file.patch_css_parse",
                "path": path,
                "selector": selector,
                "match_count": len(matches),
            },
        )

        if len(matches) == 0:
            logger.debug(
                "resolve_anchor: condition_match",
                extra={
                    "event": "html.resolve_anchor.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            raise ToolError(f"CSS selector '{selector}' matched no elements in {path}.")
        logger.debug(
            "resolve_anchor: condition_passed",
            extra={
                "event": "html.resolve_anchor.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg
        if len(matches) > 1:
            logger.debug(
                "resolve_anchor: condition_match",
                extra={
                    "event": "html.resolve_anchor.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            raise ToolError(
                f"CSS selector '{selector}' matched {len(matches)} elements in "
                f"{path}. Use a more specific selector (e.g. add an ID)."
            )
        logger.debug(
            "resolve_anchor: condition_passed",
            extra={
                "event": "html.resolve_anchor.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        element = matches[0]

        if element.sourceline is None or element.sourcepos is None:
            logger.debug(
                "resolve_anchor: sourceline_is_None",
                extra={
                    "event": "html.resolve_anchor.match",
                    "reason": "sourceline_is_None",
                },
            )  # auto:neg
            raise ToolError(
                f"CSS selector '{selector}' matched but element has no "
                "source position. Try a text anchor instead."
            )

        # Calculate character offset from sourceline + sourcepos.
        # BeautifulSoup's sourceline is 1-based, sourcepos is 0-based
        # offset within that line.
        lines = content.split("\n")
        css_start = (
            sum(len(line) + 1 for line in lines[: element.sourceline - 1])
            + element.sourcepos
        )

        tag_name = element.name
        serialised = str(element)

        # For self-closing or void elements, the span is just the tag
        if element.is_empty_element:
            logger.debug(
                "resolve_anchor: is_empty_element",
                extra={
                    "event": "html.resolve_anchor.match",
                    "reason": "is_empty_element",
                },
            )  # auto:neg
            css_end = content.index(">", css_start) + 1
        else:
            logger.debug(
                "resolve_anchor: is_empty_element",
                extra={
                    "event": "html.resolve_anchor.clean",
                    "reason": "is_empty_element",
                },
            )  # auto:neg
            css_end = _find_closing_tag(content, css_start, tag_name, serialised, path)

        # Cross-check: compare raw span against serialised length.
        # Large divergence is the canary that would have caught the P0 bug.
        raw_span_len = css_end - css_start
        serialised_len = len(serialised)
        if abs(raw_span_len - serialised_len) > serialised_len * 0.5:
            logger.warning(
                "file_patch: CSS span divergence — raw=%d serialised=%d (%.0f%% diff)",
                raw_span_len,
                serialised_len,
                abs(raw_span_len - serialised_len) / serialised_len * 100,
                extra={
                    "event": "file.patch_css_span_divergence",
                    "path": path,
                    "raw_span": raw_span_len,
                    "serialised_span": serialised_len,
                    "selector": selector,
                },
            )

        anchor_text = content[css_start:css_end]

        # Extract target element ID for the blocking structural check
        target_id = element.get("id")

        # Non-void CSS-selected elements get the replace_inner hint —
        # the planner usually means "update this panel's content" not
        # "nuke the panel wrapper and replace everything"
        prefer_replace_inner = not element.is_empty_element

        raw_span_size = css_end - css_start
        metadata = {
            "css_selector": selector,
            "css_resolved_length": len(anchor_text),
            "css_tag_name": tag_name,
            "css_is_void": element.is_empty_element,
            "css_position": css_start,
            "anchor_key": f"css:{selector}",
            "path": path,
            "original_span_size": raw_span_size,
        }
        if target_id:
            logger.debug(
                "resolve_anchor: target_id",
                extra={"event": "html.resolve_anchor.match", "reason": "target_id"},
            )  # auto:neg
            metadata["target_element_id"] = target_id

        logger.debug(
            "file_patch: CSS '%s' matched <%s> at byte %d (%d bytes)",
            selector,
            tag_name,
            css_start,
            len(anchor_text),
            extra={
                "event": "file.patch_css_resolved",
                "path": path,
                "selector": selector,
                "tag_name": tag_name,
                "is_void": element.is_empty_element,
                "resolved_length": len(anchor_text),
                "position": css_start,
            },
        )

        return AnchorResult(
            anchor_text=anchor_text,
            anchor_start=css_start,
            anchor_end=css_end,
            tag_name=tag_name,
            is_void=element.is_empty_element,
            prefer_replace_inner=prefer_replace_inner,
            metadata=metadata,
        )

    def apply_replace_inner(
        self,
        content: str,
        anchor_result: AnchorResult,
        new_content: str,
    ) -> str:
        """Replace only the children of the matched element.

        Preserves the element wrapper (tag, ID, classes, attributes).
        """

        if anchor_result.is_void:
            raise ToolError(
                "replace_inner cannot be used on void/self-closing elements"
            )

        tag_name = anchor_result.tag_name or "div"
        idx = anchor_result.anchor_start
        css_end = anchor_result.anchor_end

        # Find the end of the opening tag
        open_tag_end = content.index(">", idx) + 1

        # Find the start of the closing tag within the resolved span
        close_tag = f"</{tag_name}>"
        close_tag_start = content.rfind(close_tag, idx, css_end)
        if close_tag_start == -1:
            raise ToolError(f"replace_inner: closing tag </{tag_name}> not found")

        inner_before_length = close_tag_start - open_tag_end

        patched = (
            content[:open_tag_end]
            + "\n"
            + new_content
            + "\n"
            + content[close_tag_start:]
        )

        logger.debug(
            "file_patch: replace_inner on <%s> — inner %d->%d bytes",
            tag_name,
            inner_before_length,
            len(new_content),
            extra={
                "event": "file.patch_replace_inner",
                "path": anchor_result.metadata.get("css_selector", ""),
                "tag_name": tag_name,
                "inner_before_length": inner_before_length,
                "content_length": len(new_content),
            },
        )

        return patched

    def structural_check(
        self,
        before: str,
        after: str,
        anchor_result: AnchorResult,
        operation: str = "",
    ) -> dict:
        """Check structural integrity after patch.

        Blocking check: target element ID disappeared (cheap string search).
        Advisory check: delegates to existing structural_survival_check.
        For replace_inner: advisory removals are promoted to blocking —
        destroying child elements via replace_inner is almost always accidental.
        """
        result: dict = {
            "survival_ok": True,
            "elements_removed": [],
            "target_id_survived": True,
            "blocking": False,
        }

        # Blocking check: resolver-rerun via verify_survival, plus target_element_id
        # identity check when the original element had an ID attribute.
        # The resolver-rerun alone can miss cases where the selector now matches a
        # *different* element; the ID check catches that for elements with IDs.
        anchor_key = anchor_result.metadata.get("anchor_key")
        target_id = anchor_result.metadata.get("target_element_id")

        if anchor_key:
            survival = verify_survival(self, anchor_result, after)
            if not survival.survived:
                result["survival_ok"] = False
                result["elements_removed"] = [anchor_key]
                result["target_id_survived"] = False
                result["blocking"] = True
                logger.warning(
                    "file_patch: HTML structural check BLOCKING — "
                    "verify_survival failed for '%s': %s",
                    anchor_key,
                    survival.reason,
                    extra={
                        "event": "file.patch_html_structural_block",
                        "anchor_key": anchor_key,
                        "reason": survival.reason,
                    },
                )
                return result
            # Additional identity check: if the original element had an ID,
            # verify the ID is still on the element the selector NOW resolves to,
            # not just somewhere in the file. Checking the whole file misses the case
            # where the selector jumps to a sibling element that lacks the ID while
            # the original element (with the ID) still exists elsewhere.
            if target_id:
                if survival.rerun_metadata is not None:
                    # Use the ID that BeautifulSoup read off the re-resolved element
                    # rather than string-scanning the raw span. String scan is unsafe
                    # for HTML with '>' inside attribute values and would pass when
                    # the selector jumps to a wrapper containing the original ID on
                    # a descendant. The re-run metadata carries the element's own ID.
                    rerun_id = survival.rerun_metadata.get("target_element_id")
                    id_present = rerun_id == target_id
                else:
                    # rerun_metadata is None only when verify_survival could not
                    # complete the re-resolve. Fail closed.
                    logger.warning(
                        "file_patch: rerun_metadata is None despite anchor_key set"
                        " — failing closed on target_id check",
                        extra={
                            "event": "file.patch_target_id_check_no_rerun_metadata",
                            "target_id": target_id,
                        },
                    )
                    id_present = False
                logger.debug(
                    "file_patch: target element #%s survived post-patch: %s",
                    target_id,
                    id_present,
                    extra={
                        "event": "file.patch_target_id_check",
                        "path": "",
                        "target_id": target_id,
                        "survived": id_present,
                    },
                )
                if not id_present:
                    result["survival_ok"] = False
                    result["elements_removed"] = [f"#{target_id}"]
                    result["target_id_survived"] = False
                    result["blocking"] = True
                    return result
        else:
            # Fallback: cheap string search for target element ID (no anchor_key)
            if target_id:
                id_present = f'id="{target_id}"' in after or f"id='{target_id}'" in after
                logger.debug(
                    "file_patch: target element #%s survived post-patch: %s",
                    target_id,
                    id_present,
                    extra={
                        "event": "file.patch_target_id_check",
                        "path": "",
                        "target_id": target_id,
                        "survived": id_present,
                    },
                )
                if not id_present:
                    result["survival_ok"] = False
                    result["elements_removed"] = [f"#{target_id}"]
                    result["target_id_survived"] = False
                    result["blocking"] = True
                    return result

        # Advisory check: delegate to existing structural_survival_check
        try:
            from sentinel.analysis.structural_digest import structural_survival_check

            survival = structural_survival_check(before, after, "html")
            if not survival["survival_ok"]:
                result["survival_ok"] = False
                result["elements_removed"] = survival["elements_removed"]
                # replace_inner that destroys named children is almost always
                # accidental (e.g. CSS text dumped inside a container).
                # Promote advisory → blocking so the planner retries.
                if operation == "replace_inner" and survival["elements_removed"]:
                    result["blocking"] = True
                    logger.warning(
                        "file_patch: replace_inner destroyed child elements %s — blocking",
                        survival["elements_removed"],
                        extra={
                            "event": "file.patch_replace_inner_structural_blocked",
                            "elements_removed": survival["elements_removed"],
                        },
                    )
        except Exception as exc:  # catch-all: survival check must not block patch
            # Survival check function itself failed — don't block on internal errors
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


def _find_closing_tag(
    content: str,
    css_start: int,
    tag_name: str,
    serialised: str,
    path: str,
) -> int:
    """Find the matching closing tag for an element starting at css_start.

    Tracks nesting depth to handle same-tag siblings and nested elements.
    Falls back to serialised length if no closing tag is found.

    **P0 bug fix:** The original code checked depth == 0 BEFORE decrementing,
    which caused the scanner to stop one nesting level too early when
    same-tag siblings were present. Fixed: decrement first, then check.
    """
    depth = 0
    i = css_start

    while i < len(content):
        open_tag = content.find(f"<{tag_name}", i)
        close_tag = content.find(f"</{tag_name}>", i)

        logger.debug(
            "CSS close-tag scan: depth=%d open=%s close=%s i=%d",
            depth,
            open_tag,
            close_tag,
            i,
            extra={
                "event": "file.patch_css_close_scan",
                "depth": depth,
                "open_tag_pos": open_tag,
                "close_tag_pos": close_tag,
                "scan_position": i,
            },
        )

        if close_tag == -1:
            # No closing tag found — use serialised length as fallback
            return css_start + len(serialised)

        if open_tag != -1 and open_tag < close_tag:
            depth += 1
            i = open_tag + 1
        else:
            # P0 FIX: decrement BEFORE checking depth.
            # Old code: checked depth == 0 first, then decremented.
            # This caused the scanner to match the wrong closing tag
            # when same-tag siblings existed.
            depth -= 1
            if depth <= 0:
                return close_tag + len(f"</{tag_name}>")
            i = close_tag + 1
    else:
        return css_start + len(serialised)
