"""RustPatchBackend — structural anchor resolution for Rust files.

Handles fn:, class: (struct), and block: (impl) prefix anchors using
regex-based matching with brace-depth tracking. Handles raw strings
(r#"..."#), nested block comments, and char vs lifetime disambiguation.
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

# ── Regex patterns ──────────────────────────────────────────────────
# Each pattern is a template with {name} to be filled via re.escape.
# They match the opening declaration through to the opening brace.

# fn patterns: handle pub, pub(crate), const, async, unsafe, extern "C",
# generics, return types, and where clauses.
# Note: \([^)]*\) does not handle function pointer params like fn(i32).
# Those cases fail safely with ToolError, suggesting text anchors.
_FN_PATTERN = (
    r"(?:^|\n)(\s*(?:pub(?:\([\w:]+\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"C\"\s+)?fn\s+{name}\s*(?:<[^>]*>)?\s*\([^)]*\)"
    r"(?:\s*->\s*[^{{]+?)?\s*(?:where\s+[^{{]+?)?\s*\{{)"
)

# struct patterns: handle pub, generics, where clauses
_STRUCT_PATTERN = (
    r"(?:^|\n)(\s*(?:pub(?:\([\w:]+\))?\s+)?struct\s+{name}"
    r"(?:<[^>]*>)?\s*(?:where\s+[^{{]+?)?\s*\{{)"
)

# impl patterns: impl Target or impl Trait for Target
_IMPL_PATTERN = (
    r"(?:^|\n)(\s*impl(?:<[^>]*>)?\s+(?:[\w<>:]+\s+for\s+)?{name}"
    r"(?:<[^>]*>)?\s*(?:where\s+[^{{]+?)?\s*\{{)"
)


class RustPatchBackend:
    """Patch backend for Rust files using structural anchors."""

    def resolve_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve a fn:, class:, or block: anchor to a character range.

        Four resolution paths:
        1. fn:function_name — match Rust function declaration.
        2. class:StructName — match struct (class: for cross-language
           consistency with the JS backend).
        3. block:ImplTarget — match impl block (impl Target or
           impl Trait for Target).
        4. No prefix — fall through to TextPatchBackend for plain text.
        """
        if anchor.startswith("fn:"):
            name = anchor[3:].strip()
            logger.debug(
                "file_patch: Rust resolve_anchor dispatching fn: prefix for '%s' in %s",
                name,
                path,
                extra={
                    "event": "file.patch_rs_dispatch",
                    "path": path,
                    "prefix": "fn",
                    "target": name,
                },
            )
            return self._resolve_fn(name, content, path)
        logger.debug(
            "resolve_anchor: startswith_fn:_passed",
            extra={
                "event": "file.patch_rs_dispatch.passed",
                "reason": "startswith_fn:_passed",
            },
        )  # auto:neg
        if anchor.startswith("class:"):
            name = anchor[6:].strip()
            logger.debug(
                "file_patch: Rust resolve_anchor dispatching class: prefix for '%s' in %s",
                name,
                path,
                extra={
                    "event": "file.patch_rs_dispatch",
                    "path": path,
                    "prefix": "class",
                    "target": name,
                },
            )
            return self._resolve_struct(name, content, path)
        logger.debug(
            "resolve_anchor: startswith_class:_passed",
            extra={
                "event": "file.patch_rs_dispatch.passed",
                "reason": "startswith_class:_passed",
            },
        )  # auto:neg
        if anchor.startswith("block:"):
            name = anchor[6:].strip()
            logger.debug(
                "file_patch: Rust resolve_anchor dispatching block: prefix for '%s' in %s",
                name,
                path,
                extra={
                    "event": "file.patch_rs_dispatch",
                    "path": path,
                    "prefix": "block",
                    "target": name,
                },
            )
            return self._resolve_impl(name, content, path)
        logger.debug(
            "file_patch: Rust resolve_anchor falling through to TextPatchBackend for %s",
            path,
            extra={
                "event": "file.patch_rs_dispatch",
                "path": path,
                "prefix": "text",
                "target": anchor[:50],
            },
        )
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
        """Replace content between the opening { and closing } of the match.

        Preserves the declaration/signature and closing brace.
        """

        span = content[anchor_result.anchor_start : anchor_result.anchor_end]
        target_name = (
            anchor_result.metadata.get("function_name")
            or anchor_result.metadata.get("struct_name")
            or anchor_result.metadata.get("impl_target")
            or "unknown"
        )

        logger.debug(
            "file_patch: Rust replace_inner starting for '%s' — "
            "span %d-%d (%d bytes), new_content %d bytes",
            target_name,
            anchor_result.anchor_start,
            anchor_result.anchor_end,
            len(span),
            len(new_content),
            extra={
                "event": "file.patch_rs_replace_inner_start",
                "target_name": target_name,
                "anchor_start": anchor_result.anchor_start,
                "anchor_end": anchor_result.anchor_end,
                "span_length": len(span),
                "new_content_length": len(new_content),
            },
        )

        # Find the opening brace within the resolved span
        try:
            brace_offset = span.index("{")
        except ValueError as exc:
            logger.warning(
                "file_patch: Rust replace_inner — no opening brace in span for '%s'",
                target_name,
                extra={
                    "event": "file.patch_rs_replace_inner_no_brace",
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

        body_size_before = abs_close - (abs_open + 1)
        body_size_after = len(new_content)

        patched = (
            content[: abs_open + 1] + "\n" + new_content + "\n" + content[abs_close:]
        )

        logger.debug(
            "file_patch: replace_inner on Rust '%s' — brace at offset %d, "
            "body %d -> %d bytes",
            target_name,
            brace_offset,
            body_size_before,
            body_size_after,
            extra={
                "event": "file.patch_rs_replace_inner",
                "target_name": target_name,
                "brace_offset": brace_offset,
                "body_size_before": body_size_before,
                "body_size_after": body_size_after,
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

        Blocking check: target fn/struct/impl name disappeared.
        Advisory check: delegates to structural_survival_check.
        """
        result: dict = {
            "survival_ok": True,
            "elements_removed": [],
            "target_id_survived": True,
            "blocking": False,
        }

        # Blocking check: re-run resolver on patched content
        target_name = (
            anchor_result.metadata.get("function_name")
            or anchor_result.metadata.get("struct_name")
            or anchor_result.metadata.get("impl_target")
        )
        anchor_key = anchor_result.metadata.get("anchor_key")
        if anchor_key:
            survival = verify_survival(self, anchor_result, after)
            if not survival.survived:
                result["survival_ok"] = False
                result["elements_removed"] = [anchor_key]
                result["target_id_survived"] = False
                result["blocking"] = True
                logger.warning(
                    "file_patch: Rust structural check BLOCKING — "
                    "verify_survival failed for '%s': %s",
                    anchor_key,
                    survival.reason,
                    extra={
                        "event": "file.patch_rs_structural_block",
                        "anchor_key": anchor_key,
                        "reason": survival.reason,
                    },
                )
                return result
        elif target_name and target_name not in after:
            logger.warning(
                "file_patch: Rust structural check — anchor_key missing, "
                "falling back to substring check for '%s'",
                target_name,
                extra={
                    "event": "file.patch_rs_structural_fallback",
                    "target_name": target_name,
                },
            )
            result["survival_ok"] = False
            result["elements_removed"] = [target_name]
            result["target_id_survived"] = False
            result["blocking"] = True
            logger.warning(
                "file_patch: Rust structural check BLOCKING (substring fallback) — "
                "target '%s' disappeared from patched content",
                target_name,
                extra={
                    "event": "file.patch_rs_structural_block",
                    "target_name": target_name,
                },
            )
            return result

        # Advisory check: delegate to existing structural_survival_check
        try:
            from sentinel.analysis.structural_digest import structural_survival_check

            survival = structural_survival_check(before, after, "rust")
            if not survival["survival_ok"]:
                result["survival_ok"] = False
                result["elements_removed"] = survival["elements_removed"]
                logger.debug(
                    "file_patch: Rust structural advisory — elements removed: %s",
                    survival["elements_removed"],
                    extra={
                        "event": "file.patch_rs_structural_advisory",
                        "elements_removed": survival["elements_removed"],
                    },
                )
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

        logger.debug(
            "file_patch: Rust structural check passed for '%s' — survival_ok=%s",
            target_name,
            result["survival_ok"],
            extra={
                "event": "file.patch_rs_structural_ok",
                "target_name": target_name,
                "survival_ok": result["survival_ok"],
            },
        )

        return result

    # ── Private resolution methods ──────────────────────────────────

    def _resolve_fn(
        self,
        name: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve fn:name to the full function span."""

        if not name:
            logger.debug(
                "_resolve_fn: not_name",
                extra={"event": "_rust._resolve_fn.match", "reason": "not_name"},
            )  # auto:neg
            raise ToolError(
                "fn: prefix requires a function name (e.g. fn:handle_request)"
            )
        logger.debug(
            "_resolve_fn: not_name_passed",
            extra={"event": "_rust._resolve_fn.passed", "reason": "not_name_passed"},
        )  # auto:neg

        pattern = re.compile(
            _FN_PATTERN.format(name=re.escape(name)),
            re.MULTILINE,
        )
        matches = list(pattern.finditer(content))

        if len(matches) == 0:
            logger.debug(
                "file_patch: Rust fn '%s' not found in %s",
                name,
                path,
                extra={
                    "event": "file.patch_rs_parse_fallthrough",
                    "path": path,
                    "reason": f"function '{name}' not found",
                },
            )
            raise ToolError(
                f"Function '{name}' not found in {path}. "
                "Re-read the file and verify the function name, or use a text anchor."
            )
        logger.debug(
            "_resolve_fn: condition_passed",
            extra={
                "event": "file.patch_rs_parse_fallthrough.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if len(matches) > 1:
            logger.debug(
                "file_patch: Rust fn '%s' ambiguous — %d matches in %s",
                name,
                len(matches),
                path,
                extra={
                    "event": "file.patch_rs_fn_ambiguous",
                    "path": path,
                    "function_name": name,
                    "match_count": len(matches),
                },
            )
            raise ToolError(
                f"Function '{name}' matched {len(matches)} declarations in "
                f"{path}. Use a text anchor for disambiguation."
            )

        match = matches[0]
        decl_text = match.group(1)
        fn_start = match.start(1)

        # Find the opening brace at the end of the declaration
        open_brace = fn_start + decl_text.rindex("{")

        # Track brace depth to find the matching closing brace
        fn_end = _find_closing_brace(content, open_brace, path)

        span_length = fn_end - fn_start

        # Span sanity checks
        if span_length > SPAN_MAX_BYTES:
            logger.warning(
                "file_patch: Rust fn '%s' span is %d bytes — unusually large",
                name,
                span_length,
                extra={
                    "event": "file.patch_rs_span_warning",
                    "path": path,
                    "span_length": span_length,
                    "expected_range": "< 10KB",
                },
            )
        elif span_length < SPAN_MIN_BYTES_DEFAULT:
            logger.warning(
                "file_patch: Rust fn '%s' span is only %d bytes — suspiciously small",
                name,
                span_length,
                extra={
                    "event": "file.patch_rs_span_warning",
                    "path": path,
                    "span_length": span_length,
                    "expected_range": "> 10 bytes",
                },
            )

        anchor_text = content[fn_start:fn_end]

        logger.debug(
            "file_patch: Rust fn '%s' resolved at byte %d (%d bytes)",
            name,
            fn_start,
            span_length,
            extra={
                "event": "file.patch_rs_fn_resolved",
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
                "rs_position": fn_start,
                "rs_span_length": span_length,
                "anchor_key": f"fn:{name}",
                "path": path,
                "original_span_size": span_length,
            },
        )

    def _resolve_struct(
        self,
        name: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve class:name to the full struct span."""

        if not name:
            raise ToolError(
                "class: prefix requires a struct name (e.g. class:AppState)"
            )

        pattern = re.compile(
            _STRUCT_PATTERN.format(name=re.escape(name)),
            re.MULTILINE,
        )
        matches = list(pattern.finditer(content))

        if len(matches) == 0:
            logger.debug(
                "file_patch: Rust struct '%s' not found in %s",
                name,
                path,
                extra={
                    "event": "file.patch_rs_parse_fallthrough",
                    "path": path,
                    "reason": f"struct '{name}' not found",
                },
            )
            raise ToolError(
                f"Struct '{name}' not found in {path}. "
                "Re-read the file and verify the struct name, or use a text anchor."
            )
        logger.debug(
            "_resolve_struct: condition_passed",
            extra={
                "event": "file.patch_rs_parse_fallthrough.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if len(matches) > 1:
            logger.debug(
                "file_patch: Rust struct '%s' ambiguous — %d matches in %s",
                name,
                len(matches),
                path,
                extra={
                    "event": "file.patch_rs_struct_ambiguous",
                    "path": path,
                    "struct_name": name,
                    "match_count": len(matches),
                },
            )
            raise ToolError(
                f"Struct '{name}' matched {len(matches)} declarations in "
                f"{path}. Use a text anchor for disambiguation."
            )

        match = matches[0]
        decl_text = match.group(1)
        struct_start = match.start(1)
        open_brace = struct_start + decl_text.rindex("{")
        struct_end = _find_closing_brace(content, open_brace, path)

        span_length = struct_end - struct_start
        anchor_text = content[struct_start:struct_end]

        logger.debug(
            "file_patch: Rust struct '%s' resolved at byte %d (%d bytes)",
            name,
            struct_start,
            span_length,
            extra={
                "event": "file.patch_rs_struct_resolved",
                "path": path,
                "struct_name": name,
                "position": struct_start,
                "span_length": span_length,
            },
        )

        return AnchorResult(
            anchor_text=anchor_text,
            anchor_start=struct_start,
            anchor_end=struct_end,
            prefer_replace_inner=True,
            metadata={
                "struct_name": name,
                "rs_position": struct_start,
                "rs_span_length": span_length,
                "anchor_key": f"class:{name}",
                "path": path,
                "original_span_size": span_length,
            },
        )

    def _resolve_impl(
        self,
        name: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve block:name to the full impl block span."""

        if not name:
            raise ToolError(
                "block: prefix requires an impl target (e.g. block:AppState)"
            )

        pattern = re.compile(
            _IMPL_PATTERN.format(name=re.escape(name)),
            re.MULTILINE,
        )
        matches = list(pattern.finditer(content))

        if len(matches) == 0:
            logger.debug(
                "file_patch: Rust impl '%s' not found in %s",
                name,
                path,
                extra={
                    "event": "file.patch_rs_parse_fallthrough",
                    "path": path,
                    "reason": f"impl '{name}' not found",
                },
            )
            raise ToolError(
                f"Impl block for '{name}' not found in {path}. "
                "Re-read the file and verify the impl target, or use a text anchor."
            )
        logger.debug(
            "_resolve_impl: condition_passed",
            extra={
                "event": "file.patch_rs_parse_fallthrough.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if len(matches) > 1:
            logger.debug(
                "file_patch: Rust impl '%s' ambiguous — %d matches in %s",
                name,
                len(matches),
                path,
                extra={
                    "event": "file.patch_rs_impl_ambiguous",
                    "path": path,
                    "impl_target": name,
                    "match_count": len(matches),
                },
            )
            raise ToolError(
                f"Impl block for '{name}' matched {len(matches)} declarations in "
                f"{path}. Use a text anchor for disambiguation."
            )

        match = matches[0]
        decl_text = match.group(1)
        impl_start = match.start(1)
        open_brace = impl_start + decl_text.rindex("{")
        impl_end = _find_closing_brace(content, open_brace, path)

        span_length = impl_end - impl_start
        anchor_text = content[impl_start:impl_end]

        logger.debug(
            "file_patch: Rust impl '%s' resolved at byte %d (%d bytes)",
            name,
            impl_start,
            span_length,
            extra={
                "event": "file.patch_rs_impl_resolved",
                "path": path,
                "impl_target": name,
                "position": impl_start,
                "span_length": span_length,
            },
        )

        return AnchorResult(
            anchor_text=anchor_text,
            anchor_start=impl_start,
            anchor_end=impl_end,
            prefer_replace_inner=True,
            metadata={
                "impl_target": name,
                "rs_position": impl_start,
                "rs_span_length": span_length,
                "anchor_key": f"block:{name}",
                "path": path,
                "original_span_size": span_length,
            },
        )


# ── Brace-depth tracker ────────────────────────────────────────────


def _find_closing_brace(content: str, open_brace: int, path: str) -> int:
    """Find the matching closing brace starting from an opening brace.

    Tracks brace depth while skipping:
    - String literals ("..." with backslash escaping)
    - Raw strings (r#"..."# with variable hash count)
    - Line comments (// ...)
    - Block comments (/* ... */ — supports Rust nested block comments)
    - Character literals ('x', '\\n') vs lifetime annotations ('a)

    Returns the character position just AFTER the closing brace.
    Raises ToolError if the matching brace cannot be found confidently.
    """

    depth = 0
    i = open_brace
    length = len(content)

    logger.debug(
        "file_patch: Rust brace scan starting at offset %d in %s (%d bytes total)",
        open_brace,
        path,
        length,
        extra={
            "event": "file.patch_rs_brace_scan_start",
            "path": path,
            "open_brace": open_brace,
            "file_length": length,
        },
    )

    # Track skip counts for summary logging instead of per-skip logging.
    # Per-skip logging produces 100+ lines on a moderately complex file,
    # which floods the SSE-fed UI. Summary at the end gives the same
    # diagnostic value without the noise.
    skips = {
        "string": 0,
        "raw_string": 0,
        "line_comment": 0,
        "block_comment": 0,
        "char_literal": 0,
    }

    while i < length:
        ch = content[i]

        # ── String literals (double-quoted) ─────────────────────
        # Also handles b"..." byte strings — the 'b' is consumed as a
        # regular character on the prior iteration, then '"' triggers here.
        if ch == '"':
            skips["string"] += 1
            i += 1
            while i < length and content[i] != '"':
                if content[i] == "\\":
                    i += 1  # skip escaped character
                i += 1
            i += 1  # move past closing quote
            continue

        # ── Raw strings (r"...", r#"..."#, r##"..."##, etc.) ───
        # Rust raw strings start with r followed by optional #s
        # then a double quote. They end with " followed by the
        # same number of #s.
        # Also handles br#"..."# — the 'b' is consumed as a regular
        # character, then 'r' triggers this handler on the next iteration.
        if ch == "r" and i + 1 < length and content[i + 1] in ('"', "#"):
            j = i + 1
            hashes = 0
            while j < length and content[j] == "#":
                hashes += 1
                j += 1
            if j < length and content[j] == '"':
                skips["raw_string"] += 1
                start_pos = i
                j += 1  # past opening "
                closing = '"' + "#" * hashes
                while j + len(closing) <= length:
                    if content[j : j + len(closing)] == closing:
                        j += len(closing)
                        break
                    j += 1
                else:
                    j = length  # unterminated raw string
                    logger.warning(
                        "file_patch: Rust brace scan — unterminated raw string "
                        "(r#%d) at offset %d in %s",
                        hashes,
                        start_pos,
                        path,
                        extra={
                            "event": "file.patch_rs_brace_unterminated_raw",
                            "path": path,
                            "start": start_pos,
                            "hashes": hashes,
                        },
                    )
                i = j
                continue

        # ── Line comments ───────────────────────────────────────
        if ch == "/" and i + 1 < length and content[i + 1] == "/":
            skips["line_comment"] += 1
            i += 2
            while i < length and content[i] != "\n":
                i += 1
            i += 1  # move past newline
            continue

        # ── Block comments (Rust supports nesting) ──────────────
        if ch == "/" and i + 1 < length and content[i + 1] == "*":
            skips["block_comment"] += 1
            i += 2
            comment_depth = 1
            while i + 1 < length and comment_depth > 0:
                if content[i] == "/" and content[i + 1] == "*":
                    comment_depth += 1
                    i += 2
                elif content[i] == "*" and content[i + 1] == "/":
                    logger.debug(
                        "_find_closing_brace: clean",
                        extra={"event": "rust._find_closing_brace.branch.clean"},
                    )
                    comment_depth -= 1
                    i += 2
                else:
                    logger.debug(
                        "_find_closing_brace: clean",
                        extra={"event": "rust._find_closing_brace.branch.clean"},
                    )
                    i += 1
            continue

        # ── Character literals vs lifetime annotations ──────────
        # 'a' is a char literal, 'a (followed by ident chars) is
        # a lifetime. We only skip char literals to avoid false
        # brace matches inside them.
        if ch == "'" and i + 1 < length:
            # Escaped char literal: '\n', '\\'
            if (
                i + 2 < length
                and content[i + 1] == "\\"
                and i + 3 < length
                and content[i + 3] == "'"
            ):
                skips["char_literal"] += 1
                i += 4  # skip '\x'
                continue
            # Simple char literal: 'x'
            if i + 2 < length and content[i + 2] == "'":
                skips["char_literal"] += 1
                i += 3  # skip 'x'
                continue
            # Otherwise it's a lifetime annotation — don't skip

        # ── Brace tracking ──────────────────────────────────────
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end_pos = i + 1
                logger.debug(
                    "file_patch: Rust brace scan completed — closing brace at "
                    "offset %d (span: %d bytes, skips: %s)",
                    i,
                    end_pos - open_brace,
                    skips,
                    extra={
                        "event": "file.patch_rs_brace_scan_done",
                        "path": path,
                        "close_brace": i,
                        "scan_length": end_pos - open_brace,
                        "skips": skips,
                    },
                )
                return end_pos  # position AFTER closing brace

        i += 1

    # Could not find matching brace — fail safely
    logger.warning(
        "file_patch: Rust brace scan FAILED — no matching brace found in %s "
        "(scanned %d bytes from offset %d, final depth=%d)",
        path,
        length - open_brace,
        open_brace,
        depth,
        extra={
            "event": "file.patch_rs_brace_scan_failed",
            "path": path,
            "open_brace": open_brace,
            "scanned_bytes": length - open_brace,
            "final_depth": depth,
        },
    )
    raise ToolError(
        f"Could not find matching closing brace in {path}. "
        "The file may have a syntax error, or use a text anchor instead."
    )
