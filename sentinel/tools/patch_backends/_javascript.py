"""JavaScriptPatchBackend — structural anchor resolution for JS/TS files.

Handles fn: and class: prefix anchors by scanning for function/class
declarations in raw source, with brace-depth tracking that handles
string literals, template literals, comments, and regex patterns.
"""

from __future__ import annotations

import logging
import re

from sentinel.core.exceptions import ToolError
from sentinel.tools.patch_backends._constants import (
    SPAN_MAX_BYTES,
    SPAN_MIN_BYTES_DEFAULT,
)
from sentinel.tools.patch_backends._protocol import AnchorResult, verify_survival

logger = logging.getLogger(__name__)

# ── Function patterns ────────────────────────────────────────────────
# Each pattern is a template with {name} to be filled. They match the
# opening declaration through to the opening brace.

_FN_PATTERNS = [
    # function name(...) {
    r"(?:^|\n)([ \t]*(?:export\s+)?(?:export\s+default\s+)?(?:async\s+)?function\s+{name}\s*\([^)]*\)\s*\{{)",
    # const/let/var name = (...) => {
    r"(?:^|\n)([ \t]*(?:export\s+)?(?:const|let|var)\s+{name}\s*=\s*(?:async\s+)?\([^)]*\)\s*=>\s*\{{)",
    # const/let/var name = function(...) {
    r"(?:^|\n)([ \t]*(?:export\s+)?(?:const|let|var)\s+{name}\s*=\s*(?:async\s+)?function\s*\([^)]*\)\s*\{{)",
]

# class Name { / class Name extends Base {
_CLASS_PATTERN = (
    r"(?:^|\n)([ \t]*(?:export\s+)?(?:export\s+default\s+)?class\s+{name}"
    r"(?:\s+extends\s+[\w.]+)?\s*\{{)"
)


class JavaScriptPatchBackend:
    """Patch backend for JS/TS files using structural anchors."""

    def resolve_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve a fn: or class: anchor to a character range.

        Three resolution paths:
        1. fn:functionName — match function declaration, arrow function,
           or function expression assigned to const/let/var.
        2. class:ClassName — match class declaration with optional extends.
        3. No prefix — fall through to TextPatchBackend for plain text.
        """
        if anchor.startswith("fn:"):
            return self._resolve_function(anchor[3:].strip(), content, path)
        if anchor.startswith("class:"):
            return self._resolve_class(anchor[6:].strip(), content, path)
        from sentinel.tools.patch_backends._text import TextPatchBackend

        result = TextPatchBackend().resolve_anchor(anchor, content, path)
        result.metadata["anchor_key"] = anchor
        result.metadata["path"] = path
        result.metadata["original_span_size"] = result.anchor_end - result.anchor_start
        return result

    def apply_replace_inner(
        self,
        content: str,
        anchor_result: AnchorResult,
        new_content: str,
    ) -> str:
        """Replace content between the opening { and closing } of a function/class.

        Preserves the signature/declaration line and closing brace.
        """
        span = content[anchor_result.anchor_start : anchor_result.anchor_end]

        target_name = (
            anchor_result.metadata.get("function_name")
            or anchor_result.metadata.get("class_name")
            or "unknown"
        )

        # Find the opening brace within the resolved span
        try:
            brace_offset = span.index("{")
        except ValueError as exc:
            logger.warning(
                "file_patch: JS replace_inner — no opening brace in span for '%s'",
                target_name,
                extra={
                    "event": "file.patch_js_replace_inner_no_brace",
                    "target_name": target_name,
                },
            )
            raise ToolError(
                f"No opening brace found in resolved span for '{target_name}'. "
                "The anchor may have resolved incorrectly — use a text anchor instead."
            ) from exc
        abs_open = anchor_result.anchor_start + brace_offset

        # The closing brace is the last character of the span
        abs_close = anchor_result.anchor_end - 1

        patched = (
            content[: abs_open + 1] + "\n" + new_content + "\n" + content[abs_close:]
        )
        logger.debug(
            "file_patch: replace_inner on JS '%s'",
            target_name,
            extra={
                "event": "file.patch_js_replace_inner",
                "target_name": target_name,
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

        Blocking check: target function/class name disappeared.
        Advisory check: delegates to structural_survival_check.
        """
        result: dict = {
            "survival_ok": True,
            "elements_removed": [],
            "target_id_survived": True,
            "blocking": False,
        }

        # Blocking check: re-run resolver on patched content
        target_name = anchor_result.metadata.get(
            "function_name"
        ) or anchor_result.metadata.get("class_name")
        anchor_key = anchor_result.metadata.get("anchor_key")
        if anchor_key:
            survival = verify_survival(self, anchor_result, after)
            if not survival.survived:
                result["survival_ok"] = False
                result["elements_removed"] = [anchor_key]
                result["target_id_survived"] = False
                result["blocking"] = True
                logger.warning(
                    "file_patch: JS structural check BLOCKING — "
                    "verify_survival failed for '%s': %s",
                    anchor_key,
                    survival.reason,
                    extra={
                        "event": "file.patch_js_structural_block",
                        "anchor_key": anchor_key,
                        "reason": survival.reason,
                    },
                )
                return result
        elif target_name and target_name not in after:
            logger.warning(
                "file_patch: JS structural check — anchor_key missing, "
                "falling back to substring check for '%s'",
                target_name,
                extra={
                    "event": "file.patch_js_structural_fallback",
                    "target_name": target_name,
                },
            )
            result["survival_ok"] = False
            result["elements_removed"] = [target_name]
            result["target_id_survived"] = False
            result["blocking"] = True
            return result

        # Advisory check: delegate to existing structural_survival_check
        try:
            from sentinel.analysis.structural_digest import structural_survival_check

            survival = structural_survival_check(before, after, "javascript")
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

    # ── Private resolution methods ───────────────────────────────────

    def _resolve_function(
        self,
        name: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve fn:name to the full function span."""

        if not name:
            logger.debug(
                "_resolve_function: not_name",
                extra={
                    "event": "_javascript._resolve_function.match",
                    "reason": "not_name",
                },
            )  # auto:neg
            raise ToolError("fn: prefix requires a function name (e.g. fn:handleClick)")
        logger.debug(
            "_resolve_function: not_name_passed",
            extra={
                "event": "_javascript._resolve_function.passed",
                "reason": "not_name_passed",
            },
        )  # auto:neg

        # Try each pattern — collect all matches across all forms
        all_matches = []
        for pattern_template in _FN_PATTERNS:
            pattern = re.compile(
                pattern_template.format(name=re.escape(name)),
                re.MULTILINE,
            )
            all_matches.extend(pattern.finditer(content))

        if len(all_matches) == 0:
            logger.debug(
                "file_patch: JS fn '%s' not found in %s",
                name,
                path,
                extra={
                    "event": "file.patch_js_parse_fallthrough",
                    "path": path,
                    "reason": f"function '{name}' not found",
                },
            )
            raise ToolError(
                f"Function '{name}' not found in {path}. "
                "Re-read the file and verify the function name, or use a text anchor."
            )
        logger.debug(
            "_resolve_function: condition_passed",
            extra={
                "event": "file.patch_js_parse_fallthrough.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if len(all_matches) > 1:
            logger.debug(
                "_resolve_function: condition_match",
                extra={
                    "event": "_javascript._resolve_function.match",
                    "reason": "condition_match",
                },
            )  # auto:neg
            raise ToolError(
                f"Function '{name}' matched {len(all_matches)} declarations in "
                f"{path}. Use a text anchor for disambiguation."
            )

        match = all_matches[0]
        # The match group 1 is the full declaration including the opening brace.
        # We need the start of the declaration (may include leading whitespace).
        decl_text = match.group(1)
        # Find where this declaration starts in the content
        fn_start = match.start(1)

        # Find the opening brace at the end of the declaration
        open_brace = fn_start + decl_text.rindex("{")

        # Track brace depth to find the matching closing brace
        fn_end = _find_closing_brace(content, open_brace, path)

        span_length = fn_end - fn_start

        # Span sanity checks
        if span_length > SPAN_MAX_BYTES:
            logger.warning(
                "file_patch: JS fn '%s' span is %d bytes — unusually large",
                name,
                span_length,
                extra={
                    "event": "file.patch_js_span_warning",
                    "path": path,
                    "span_length": span_length,
                    "expected_range": "< 10KB",
                },
            )
        elif span_length < SPAN_MIN_BYTES_DEFAULT:
            logger.warning(
                "file_patch: JS fn '%s' span is only %d bytes — suspiciously small",
                name,
                span_length,
                extra={
                    "event": "file.patch_js_span_warning",
                    "path": path,
                    "span_length": span_length,
                    "expected_range": "> 10 bytes",
                },
            )

        anchor_text = content[fn_start:fn_end]

        logger.debug(
            "file_patch: JS fn '%s' resolved at byte %d (%d bytes)",
            name,
            fn_start,
            span_length,
            extra={
                "event": "file.patch_js_fn_resolved",
                "path": path,
                "function_name": name,
                "position": fn_start,
                "span_length": span_length,
            },
        )

        return AnchorResult(
            anchor_text=anchor_text,
            anchor_start=fn_start,
            anchor_end=fn_end,
            prefer_replace_inner=True,
            metadata={
                "function_name": name,
                "js_position": fn_start,
                "js_span_length": span_length,
                "anchor_key": f"fn:{name}",
                "path": path,
                "original_span_size": span_length,
            },
        )

    def _resolve_class(
        self,
        name: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve class:name to the full class span."""

        if not name:
            raise ToolError("class: prefix requires a class name (e.g. class:Widget)")

        pattern = re.compile(
            _CLASS_PATTERN.format(name=re.escape(name)),
            re.MULTILINE,
        )
        matches = list(pattern.finditer(content))

        if len(matches) == 0:
            logger.debug(
                "file_patch: JS class '%s' not found in %s",
                name,
                path,
                extra={
                    "event": "file.patch_js_parse_fallthrough",
                    "path": path,
                    "reason": f"class '{name}' not found",
                },
            )
            raise ToolError(
                f"Class '{name}' not found in {path}. "
                "Re-read the file and verify the class name, or use a text anchor."
            )

        if len(matches) > 1:
            raise ToolError(
                f"Class '{name}' matched {len(matches)} declarations in "
                f"{path}. Use a text anchor for disambiguation."
            )

        match = matches[0]
        decl_text = match.group(1)
        cls_start = match.start(1)
        open_brace = cls_start + decl_text.rindex("{")
        cls_end = _find_closing_brace(content, open_brace, path)

        span_length = cls_end - cls_start
        anchor_text = content[cls_start:cls_end]

        logger.debug(
            "file_patch: JS class '%s' resolved at byte %d (%d bytes)",
            name,
            cls_start,
            span_length,
            extra={
                "event": "file.patch_js_class_resolved",
                "path": path,
                "class_name": name,
                "position": cls_start,
                "span_length": span_length,
            },
        )

        return AnchorResult(
            anchor_text=anchor_text,
            anchor_start=cls_start,
            anchor_end=cls_end,
            prefer_replace_inner=True,
            metadata={
                "class_name": name,
                "js_position": cls_start,
                "js_span_length": span_length,
                "anchor_key": f"class:{name}",
                "path": path,
                "original_span_size": span_length,
            },
        )


def _find_closing_brace(content: str, open_brace: int, path: str) -> int:
    """Find the matching closing brace starting from an opening brace.

    Tracks brace depth while skipping:
    - String literals ("...", '...', `...`)
    - Template literal expressions ${...} (up to 2 levels of nesting)
    - Line comments (// ...)
    - Block comments (/* ... */)
    - Regex literals (/pattern/) — basic detection only

    Returns the character position just AFTER the closing brace.
    Raises ToolError if the matching brace cannot be found confidently.
    """
    depth = 0
    i = open_brace
    length = len(content)
    template_depth = 0  # track ${...} nesting inside template literals

    while i < length:
        ch = content[i]

        # ── String literals (single/double quote) ────────────────
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < length and content[i] != quote:
                if content[i] == "\\":
                    i += 1  # skip escaped character
                i += 1
            i += 1  # move past closing quote
            continue

        # ── Template literals (backtick) ─────────────────────────
        if ch == "`":
            i += 1
            while i < length and content[i] != "`":
                if content[i] == "\\":
                    i += 1  # skip escaped character
                elif content[i] == "$" and i + 1 < length and content[i + 1] == "{":
                    # ${...} expression — track its braces
                    template_depth += 1
                    if template_depth > 2:
                        raise ToolError(
                            "Template literal nesting too deep in "
                            f"{path} — use a text anchor instead."
                        )
                    i += 2  # skip ${
                    # Scan inside the expression until matching }
                    expr_depth = 1
                    while i < length and expr_depth > 0:
                        ec = content[i]
                        if ec == "{":
                            expr_depth += 1
                        elif ec == "}":
                            logger.debug(
                                "_find_closing_brace: clean",
                                extra={
                                    "event": "javascript._find_closing_brace.branch.clean"
                                },
                            )
                            expr_depth -= 1
                        elif ec in ('"', "'"):
                            # Skip strings inside template expressions
                            logger.debug(
                                "_find_closing_brace: clean",
                                extra={
                                    "event": "javascript._find_closing_brace.branch.clean"
                                },
                            )
                            eq = ec
                            i += 1
                            while i < length and content[i] != eq:
                                if content[i] == "\\":
                                    i += 1
                                i += 1
                        i += 1
                    template_depth -= 1
                    continue
                i += 1
            i += 1  # move past closing backtick
            continue

        # ── Line comments ────────────────────────────────────────
        if ch == "/" and i + 1 < length and content[i + 1] == "/":
            i += 2
            while i < length and content[i] != "\n":
                i += 1
            i += 1  # move past newline
            continue

        # ── Block comments ───────────────────────────────────────
        if ch == "/" and i + 1 < length and content[i + 1] == "*":
            i += 2
            while i + 1 < length and not (content[i] == "*" and content[i + 1] == "/"):
                i += 1
            i += 2  # move past */
            continue

        # ── Regex literals (basic detection) ─────────────────────
        # A / after certain tokens is likely a regex, not division.
        # This is intentionally conservative — we only skip if the
        # preceding non-whitespace char is one of: = ( , [ ! & | ? : ;
        if ch == "/" and i > 0:
            # Look back for the preceding non-whitespace character
            j = i - 1
            while j >= 0 and content[j] in " \t":
                j -= 1
            if j >= 0 and content[j] in "=([,!&|?:;{":
                i += 1  # move past opening /
                while i < length and content[i] != "/":
                    if content[i] == "\\":
                        i += 1  # skip escaped character
                    i += 1
                i += 1  # move past closing /
                # Skip regex flags
                while i < length and content[i].isalpha():
                    i += 1
                continue

        # ── Brace tracking ───────────────────────────────────────
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1  # position AFTER closing brace

        i += 1

    # Could not find matching brace — fail safely
    raise ToolError(
        f"Could not find matching closing brace in {path}. "
        "The file may have a syntax error, or use a text anchor instead."
    )
