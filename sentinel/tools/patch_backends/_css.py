"""CSSPatchBackend — CSS selector anchor resolution for .css files.

Handles sel: prefix anchors by scanning for CSS rule selectors in raw
source, replace_inner with brace-aware splicing, and structural checking
with targeted selector survival.
"""

from __future__ import annotations

import logging
import re

from sentinel.core.exceptions import ToolError
from sentinel.tools.patch_backends._protocol import AnchorResult, verify_survival

logger = logging.getLogger(__name__)


class CSSPatchBackend:
    """Patch backend for CSS files using selector anchors."""

    def resolve_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve a sel: anchor to the character range of a CSS rule.

        Two resolution paths:
        1. sel:.selector — find the CSS rule by its selector string,
           then brace-track to locate the full rule span.
        2. No prefix — fall through to TextPatchBackend for plain text.
        """
        if not anchor.startswith("sel:"):
            from sentinel.tools.patch_backends._text import TextPatchBackend

            result = TextPatchBackend().resolve_anchor(anchor, content, path)
            result.metadata["anchor_key"] = anchor
            result.metadata["path"] = path
            result.metadata["original_span_size"] = result.anchor_end - result.anchor_start
            return result

        selector = anchor[4:].strip()
        if not selector:
            raise ToolError(
                "sel: prefix requires a CSS selector (e.g. sel:.panel-weather)"
            )

        # Find all occurrences of the selector followed by whitespace + {.
        # re.escape handles special regex chars in compound selectors like
        # .dashboard .panel:first-child
        escaped = re.escape(selector)
        pattern = re.compile(escaped + r"\s*\{")
        raw_matches = list(pattern.finditer(content))

        # Filter out matches inside compound selectors (e.g. "html, body {"
        # should not match when searching for "body"). A compound selector
        # has a comma followed by optional whitespace before our selector.
        matches = []
        for m in raw_matches:
            pre = content[: m.start()].rstrip()
            if pre and pre[-1] == ",":
                logger.debug(
                    "file_patch: CSS sel '%s' skipped compound match at byte %d "
                    "(preceded by comma in '%s')",
                    selector,
                    m.start(),
                    content[max(0, m.start() - 20) : m.start()].strip(),
                    extra={
                        "event": "file.patch_css_sel_compound_skip",
                        "path": path,
                        "selector": selector,
                        "position": m.start(),
                    },
                )
                continue
            matches.append(m)

        if len(matches) == 0:
            logger.warning(
                "file_patch: CSS selector '%s' not found in %s",
                selector,
                path,
                extra={
                    "event": "file.patch_css_sel_miss",
                    "path": path,
                    "selector": selector,
                },
            )
            raise ToolError(
                f"CSS selector '{selector}' not found in {path}. "
                "Re-read the file and use the exact selector text."
            )
        logger.debug(
            "resolve_anchor: condition_passed",
            extra={
                "event": "file.patch_css_sel_miss.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if len(matches) > 1:
            logger.warning(
                "file_patch: CSS selector '%s' matched %d rules in %s",
                selector,
                len(matches),
                path,
                extra={
                    "event": "file.patch_css_sel_ambiguous",
                    "path": path,
                    "selector": selector,
                    "match_count": len(matches),
                },
            )
            raise ToolError(
                f"CSS selector '{selector}' matched {len(matches)} rules in "
                f"{path}. Use a more specific selector or include the at-rule context."
            )

        match = matches[0]
        rule_start = match.start()

        # Find the opening brace position from the match
        open_brace = content.index("{", match.start())

        # Track brace depth to find the matching closing brace.
        # CSS has minimal nesting (only @media/@supports nest rules),
        # so depth rarely exceeds 2.
        rule_end = _find_closing_brace(content, open_brace)

        span_length = rule_end - rule_start
        anchor_text = content[rule_start:rule_end]

        logger.debug(
            "file_patch: CSS sel '%s' resolved at byte %d (%d bytes)",
            selector,
            rule_start,
            span_length,
            extra={
                "event": "file.patch_css_sel_resolved",
                "path": path,
                "selector": selector,
                "position": rule_start,
                "span_length": span_length,
            },
        )

        return AnchorResult(
            anchor_text=anchor_text,
            anchor_start=rule_start,
            anchor_end=rule_end,
            prefer_replace_inner=True,
            metadata={
                "css_selector": selector,
                "css_position": rule_start,
                "css_span_length": span_length,
                "anchor_key": f"sel:{selector}",
                "path": path,
                "original_span_size": span_length,
            },
        )

    def apply_replace_inner(
        self,
        content: str,
        anchor_result: AnchorResult,
        new_content: str,
    ) -> str:
        """Replace declarations between { and } of the matched rule.

        Preserves the selector and braces, replacing only the inner
        declarations. This lets the planner say "replace the styles for
        .panel-weather" without restating the selector.
        """
        span = content[anchor_result.anchor_start : anchor_result.anchor_end]

        # Find the opening brace within the resolved span
        brace_offset = span.index("{")
        abs_open = anchor_result.anchor_start + brace_offset

        # The closing brace is the last character of the span
        abs_close = anchor_result.anchor_end - 1

        patched = (
            content[: abs_open + 1] + "\n" + new_content + "\n" + content[abs_close:]
        )

        logger.debug(
            "file_patch: replace_inner on CSS rule '%s'",
            anchor_result.metadata.get("css_selector", ""),
            extra={
                "event": "file.patch_css_replace_inner",
                "selector": anchor_result.metadata.get("css_selector", ""),
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

        Blocking check: target selector disappeared from post-patch content.
        Advisory check: delegates to structural_survival_check.
        """
        result: dict = {
            "survival_ok": True,
            "elements_removed": [],
            "target_id_survived": True,
            "blocking": False,
        }

        # Blocking check: re-run resolver on patched content
        selector = anchor_result.metadata.get("css_selector")
        anchor_key = anchor_result.metadata.get("anchor_key")
        if anchor_key:
            survival = verify_survival(self, anchor_result, after)
            if not survival.survived:
                result["survival_ok"] = False
                result["elements_removed"] = [anchor_key]
                result["target_id_survived"] = False
                result["blocking"] = True
                logger.warning(
                    "file_patch: CSS structural check BLOCKING — "
                    "verify_survival failed for '%s': %s",
                    anchor_key,
                    survival.reason,
                    extra={
                        "event": "file.patch_css_structural_block",
                        "anchor_key": anchor_key,
                        "reason": survival.reason,
                    },
                )
                return result
        elif selector and selector not in after:
            logger.warning(
                "file_patch: CSS structural check — anchor_key missing, "
                "falling back to substring check for '%s'",
                selector,
                extra={
                    "event": "file.patch_css_structural_fallback",
                    "selector": selector,
                },
            )
            result["survival_ok"] = False
            result["elements_removed"] = [selector]
            result["target_id_survived"] = False
            result["blocking"] = True
            return result

        # Advisory check: delegate to existing structural_survival_check
        try:
            from sentinel.analysis.structural_digest import structural_survival_check

            survival = structural_survival_check(before, after, "css")
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


def _find_closing_brace(content: str, open_brace: int) -> int:
    """Find the matching closing brace starting from an opening brace.

    Tracks brace depth, skipping braces inside string literals
    (single-quoted and double-quoted) to avoid false depth changes
    from url("...") or content: "..." values.
    Returns the character position just AFTER the closing brace.
    """
    logger.debug(
        "_find_closing_brace called",
        extra={
            "event": "_css._find_closing_brace",
            "content_len": len(content) if hasattr(content, "__len__") else 0,
            "open_brace": open_brace,
        },
    )  # auto:entry
    depth = 0
    i = open_brace
    length = len(content)

    while i < length:
        ch = content[i]

        # Skip string literals — braces inside url("...") or
        # content: "..." must not affect depth tracking
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < length and content[i] != quote:
                if content[i] == "\\":
                    i += 1  # skip escaped character
                i += 1
            i += 1  # move past closing quote
            continue

        # Skip CSS comments /* ... */
        if ch == "/" and i + 1 < length and content[i + 1] == "*":
            i += 2
            while i + 1 < length and not (content[i] == "*" and content[i + 1] == "/"):
                i += 1
            i += 2  # move past */
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1  # position AFTER closing brace

        i += 1

    # Fallback: no matching brace found, return end of content
    return length
