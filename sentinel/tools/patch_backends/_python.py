"""PythonPatchBackend — structural anchor resolution for Python files.

Handles fn: and class: prefix anchors using Python's ast module for
exact function/class resolution. Supports fn:ClassName.method for
method resolution within a class. Decorators are included in spans.
"""

from __future__ import annotations

import ast
import logging

from sentinel.core.exceptions import ToolError
from sentinel.tools.patch_backends._constants import (
    SPAN_MAX_BYTES,
    SPAN_MIN_BYTES_PYTHON,
)
from sentinel.tools.patch_backends._protocol import AnchorResult, verify_survival

logger = logging.getLogger(__name__)


class PythonPatchBackend:
    """Patch backend for Python files using ast-based structural anchors."""

    def resolve_anchor(
        self,
        anchor: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve a fn: or class: anchor to a character range.

        Four resolution paths:
        1. fn:function_name — match function/async function by name.
        2. fn:ClassName.method — match method within a class.
        3. class:ClassName — match class by name.
        4. No prefix — fall through to TextPatchBackend for plain text.
        """
        if anchor.startswith("fn:"):
            name = anchor[3:].strip()
            logger.debug(
                "file_patch: Python resolve_anchor dispatching fn: prefix for '%s' in %s",
                name,
                path,
                extra={
                    "event": "file.patch_py_dispatch",
                    "path": path,
                    "prefix": "fn",
                    "target": name,
                },
            )
            return self._resolve_function(name, content, path)
        logger.debug(
            "resolve_anchor: startswith_fn:_passed",
            extra={
                "event": "file.patch_py_dispatch.passed",
                "reason": "startswith_fn:_passed",
            },
        )  # auto:neg
        if anchor.startswith("class:"):
            name = anchor[6:].strip()
            logger.debug(
                "file_patch: Python resolve_anchor dispatching class: prefix for '%s' in %s",
                name,
                path,
                extra={
                    "event": "file.patch_py_dispatch",
                    "path": path,
                    "prefix": "class",
                    "target": name,
                },
            )
            return self._resolve_class(name, content, path)
        logger.debug(
            "file_patch: Python resolve_anchor falling through to TextPatchBackend for %s",
            path,
            extra={
                "event": "file.patch_py_dispatch",
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
        result.metadata["resolved_structurally"] = False
        return result

    def apply_replace_inner(
        self,
        content: str,
        anchor_result: AnchorResult,
        new_content: str,
    ) -> str:
        """Replace the function/class body, preserving def line + decorators.

        Finds the colon that ends the def/class signature and replaces
        everything after it up to the end of the span.
        """
        span = content[anchor_result.anchor_start : anchor_result.anchor_end]
        target_name = (
            anchor_result.metadata.get("function_name")
            or anchor_result.metadata.get("class_name")
            or "unknown"
        )

        logger.debug(
            "file_patch: Python replace_inner starting for '%s' — "
            "span %d-%d (%d bytes), new_content %d bytes",
            target_name,
            anchor_result.anchor_start,
            anchor_result.anchor_end,
            len(span),
            len(new_content),
            extra={
                "event": "file.patch_py_replace_inner_start",
                "target_name": target_name,
                "anchor_start": anchor_result.anchor_start,
                "anchor_end": anchor_result.anchor_end,
                "span_length": len(span),
                "new_content_length": len(new_content),
            },
        )

        # Find the colon that ends the def/class line.
        # Walk through the span line by line to find the signature's ':'
        colon_offset = _find_signature_colon(span)
        abs_colon = anchor_result.anchor_start + colon_offset

        body_size_before = anchor_result.anchor_end - (abs_colon + 1)
        body_size_after = len(new_content)

        patched = (
            content[: abs_colon + 1]
            + "\n"
            + new_content
            + "\n"
            + content[anchor_result.anchor_end :]
        )

        logger.debug(
            "file_patch: replace_inner on Python '%s' — colon at offset %d, "
            "body %d -> %d bytes",
            target_name,
            colon_offset,
            body_size_before,
            body_size_after,
            extra={
                "event": "file.patch_py_replace_inner",
                "target_name": target_name,
                "colon_offset": colon_offset,
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
                    "file_patch: Python structural check BLOCKING — "
                    "verify_survival failed for '%s': %s",
                    anchor_key,
                    survival.reason,
                    extra={
                        "event": "file.patch_py_structural_block",
                        "anchor_key": anchor_key,
                        "reason": survival.reason,
                    },
                )
                return result
        elif target_name:
            # Fallback: old substring check when anchor_key absent (backward compat)
            check_name = (
                target_name.split(".")[-1] if "." in target_name else target_name
            )
            logger.warning(
                "file_patch: Python structural check — anchor_key missing, "
                "falling back to substring check for '%s'",
                target_name,
                extra={
                    "event": "file.patch_py_structural_fallback",
                    "target_name": target_name,
                },
            )
            if check_name not in after:
                result["survival_ok"] = False
                result["elements_removed"] = [target_name]
                result["target_id_survived"] = False
                result["blocking"] = True
                logger.warning(
                    "file_patch: Python structural check BLOCKING (substring fallback) — "
                    "target '%s' disappeared from patched content",
                    target_name,
                    extra={
                        "event": "file.patch_py_structural_block",
                        "target_name": target_name,
                        "check_name": check_name,
                    },
                )
                return result

        # Advisory check: delegate to existing structural_survival_check
        try:
            from sentinel.analysis.structural_digest import structural_survival_check

            survival = structural_survival_check(before, after, "python")
            if not survival["survival_ok"]:
                result["survival_ok"] = False
                result["elements_removed"] = survival["elements_removed"]
                logger.debug(
                    "file_patch: Python structural advisory — elements removed: %s",
                    survival["elements_removed"],
                    extra={
                        "event": "file.patch_py_structural_advisory",
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
            "file_patch: Python structural check passed for '%s' — survival_ok=%s",
            target_name,
            result["survival_ok"],
            extra={
                "event": "file.patch_py_structural_ok",
                "target_name": target_name,
                "survival_ok": result["survival_ok"],
            },
        )

        return result

    # ── Private resolution methods ──────────────────────────────────

    def _resolve_function(
        self,
        name: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve fn:name to the full function span.

        Supports fn:ClassName.method syntax for method resolution.
        Falls through to TextPatchBackend on SyntaxError.
        """

        if not name:
            raise ToolError(
                "fn: prefix requires a function name "
                "(e.g. fn:process_data or fn:MyClass.handle)"
            )

        # Parse the source — fall through to text on syntax error
        try:
            tree = ast.parse(content)
        except SyntaxError:
            logger.debug(
                "file_patch: Python ast.parse failed for %s, falling through to text",
                path,
                extra={
                    "event": "file.patch_py_parse_fallthrough",
                    "path": path,
                    "reason": "SyntaxError in ast.parse",
                },
            )
            from sentinel.tools.patch_backends._text import TextPatchBackend

            result = TextPatchBackend().resolve_anchor(f"fn:{name}", content, path)
            result.metadata["anchor_key"] = f"fn:{name}"
            result.metadata["path"] = path
            result.metadata["original_span_size"] = result.anchor_end - result.anchor_start
            result.metadata["resolved_structurally"] = False
            return result

        # Handle fn:ClassName.method syntax
        if "." in name:
            class_name, method_name = name.split(".", 1)
            return self._resolve_method(class_name, method_name, tree, content, path)

        # Find all matching function definitions (top-level and nested)
        matches = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]

        if len(matches) == 0:
            logger.debug(
                "file_patch: Python fn '%s' not found in %s",
                name,
                path,
                extra={
                    "event": "file.patch_py_parse_fallthrough",
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
                "event": "file.patch_py_parse_fallthrough.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if len(matches) > 1:
            logger.debug(
                "file_patch: Python fn '%s' ambiguous — %d matches in %s",
                name,
                len(matches),
                path,
                extra={
                    "event": "file.patch_py_fn_ambiguous",
                    "path": path,
                    "function_name": name,
                    "match_count": len(matches),
                },
            )
            raise ToolError(
                f"Function '{name}' matched {len(matches)} definitions in "
                f"{path}. Use fn:ClassName.method for disambiguation, "
                "or use a text anchor."
            )

        logger.debug(
            "file_patch: Python fn '%s' — single match found, resolving span",
            name,
            extra={
                "event": "file.patch_py_fn_matched",
                "path": path,
                "function_name": name,
            },
        )
        node = matches[0]
        return self._node_to_anchor(node, name, content, path, "function_name")

    def _resolve_method(
        self,
        class_name: str,
        method_name: str,
        tree: ast.Module,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve fn:ClassName.method to the method span within a class."""

        # Find the class
        classes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]

        logger.debug(
            "file_patch: Python method resolution — found %d class(es) named '%s' in %s",
            len(classes),
            class_name,
            path,
            extra={
                "event": "file.patch_py_method_class_search",
                "path": path,
                "class_name": class_name,
                "match_count": len(classes),
            },
        )

        if len(classes) == 0:
            raise ToolError(
                f"Class '{class_name}' not found in {path}. "
                "Re-read the file and verify the class name."
            )

        # Find the method within the class body
        matches = []
        for cls in classes:
            for item in cls.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name == method_name
                ):
                    matches.append(item)

        logger.debug(
            "file_patch: Python method resolution — found %d method(s) named '%s' in class '%s'",
            len(matches),
            method_name,
            class_name,
            extra={
                "event": "file.patch_py_method_search",
                "path": path,
                "class_name": class_name,
                "method_name": method_name,
                "match_count": len(matches),
            },
        )

        if len(matches) == 0:
            raise ToolError(
                f"Method '{method_name}' not found in class '{class_name}' "
                f"in {path}. Re-read the file and verify the method name."
            )

        if len(matches) > 1:
            raise ToolError(
                f"Method '{method_name}' matched {len(matches)} definitions "
                f"in class '{class_name}' in {path}. Use a text anchor."
            )

        full_name = f"{class_name}.{method_name}"
        return self._node_to_anchor(
            matches[0], full_name, content, path, "function_name"
        )

    def _resolve_class(
        self,
        name: str,
        content: str,
        path: str,
    ) -> AnchorResult:
        """Resolve class:name to the full class span."""

        if not name:
            raise ToolError(
                "class: prefix requires a class name (e.g. class:UserManager)"
            )

        try:
            tree = ast.parse(content)
        except SyntaxError:
            logger.debug(
                "file_patch: Python ast.parse failed for %s, falling through to text",
                path,
                extra={
                    "event": "file.patch_py_parse_fallthrough",
                    "path": path,
                    "reason": "SyntaxError in ast.parse",
                },
            )
            from sentinel.tools.patch_backends._text import TextPatchBackend

            result = TextPatchBackend().resolve_anchor(f"class:{name}", content, path)
            result.metadata["anchor_key"] = f"class:{name}"
            result.metadata["path"] = path
            result.metadata["original_span_size"] = result.anchor_end - result.anchor_start
            result.metadata["resolved_structurally"] = False
            return result

        matches = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == name
        ]

        if len(matches) == 0:
            logger.debug(
                "file_patch: Python class '%s' not found in %s",
                name,
                path,
                extra={
                    "event": "file.patch_py_parse_fallthrough",
                    "path": path,
                    "reason": f"class '{name}' not found",
                },
            )
            raise ToolError(
                f"Class '{name}' not found in {path}. "
                "Re-read the file and verify the class name, or use a text anchor."
            )
        logger.debug(
            "_resolve_class: condition_passed",
            extra={
                "event": "file.patch_py_parse_fallthrough.passed",
                "reason": "condition_passed",
            },
        )  # auto:neg

        if len(matches) > 1:
            logger.debug(
                "file_patch: Python class '%s' ambiguous — %d matches in %s",
                name,
                len(matches),
                path,
                extra={
                    "event": "file.patch_py_class_ambiguous",
                    "path": path,
                    "class_name": name,
                    "match_count": len(matches),
                },
            )
            raise ToolError(
                f"Class '{name}' matched {len(matches)} definitions in "
                f"{path}. Use a text anchor for disambiguation."
            )

        logger.debug(
            "file_patch: Python class '%s' — single match found, resolving span",
            name,
            extra={
                "event": "file.patch_py_class_matched",
                "path": path,
                "class_name": name,
            },
        )
        return self._node_to_anchor(matches[0], name, content, path, "class_name")

    def _node_to_anchor(
        self,
        node: ast.AST,
        name: str,
        content: str,
        path: str,
        name_key: str,
    ) -> AnchorResult:
        """Convert an AST node to an AnchorResult with byte offsets.

        Includes decorators in the span if present.
        """
        # Start position: include decorators if present.
        # ast gives col_offset AFTER the @, so subtract 1 to include it.
        if hasattr(node, "decorator_list") and node.decorator_list:
            start_line = node.decorator_list[0].lineno
            start_col = max(0, node.decorator_list[0].col_offset - 1)
        else:
            start_line = node.lineno
            start_col = node.col_offset

        # End position (Python 3.8+)
        end_line = node.end_lineno
        end_col = node.end_col_offset

        start_offset = _linecol_to_offset(content, start_line, start_col)
        end_offset = _linecol_to_offset(content, end_line, end_col)

        span_length = end_offset - start_offset
        anchor_text = content[start_offset:end_offset]

        # Span sanity checks
        if span_length > SPAN_MAX_BYTES:
            logger.warning(
                "file_patch: Python %s '%s' span is %d bytes — unusually large",
                name_key,
                name,
                span_length,
                extra={
                    "event": "file.patch_py_span_warning",
                    "path": path,
                    "span_length": span_length,
                    "expected_range": "< 10KB",
                },
            )
        elif span_length < SPAN_MIN_BYTES_PYTHON:
            logger.warning(
                "file_patch: Python %s '%s' span is only %d bytes — suspiciously small",
                name_key,
                name,
                span_length,
                extra={
                    "event": "file.patch_py_span_warning",
                    "path": path,
                    "span_length": span_length,
                    "expected_range": "> 5 bytes",
                },
            )

        event = (
            "file.patch_py_fn_resolved"
            if name_key == "function_name"
            else "file.patch_py_class_resolved"
        )
        logger.debug(
            "file_patch: Python %s '%s' resolved at byte %d (%d bytes)",
            name_key,
            name,
            start_offset,
            span_length,
            extra={
                "event": event,
                "path": path,
                name_key: name,
                "position": start_offset,
                "span_length": span_length,
            },
        )

        # Derive the anchor_key from context: name_key tells us the prefix
        _prefix = "fn" if name_key == "function_name" else "class"
        _anchor_key = f"{_prefix}:{name}"

        return AnchorResult(
            anchor_text=anchor_text,
            anchor_start=start_offset,
            anchor_end=end_offset,
            prefer_replace_inner=True,
            metadata={
                name_key: name,
                "py_position": start_offset,
                "py_span_length": span_length,
                "anchor_key": _anchor_key,
                "path": path,
                "original_span_size": span_length,
                "resolved_structurally": True,
            },
        )


# ── Helpers ────────────────────────────────────────────────────────


def _linecol_to_offset(content: str, lineno: int, col_offset: int) -> int:
    """Convert 1-based line number + 0-based column offset to character offset.

    If lineno exceeds the total number of lines (shouldn't happen with
    valid AST output), clamps to end of content to avoid out-of-bounds.
    """
    offset = 0
    for i, line in enumerate(content.splitlines(keepends=True), 1):
        if i == lineno:
            return offset + col_offset
        offset += len(line)
    # lineno beyond file — clamp to end of content
    return min(offset + col_offset, len(content))


def _find_signature_colon(span: str) -> int:
    """Find the colon that ends a def/class signature in a span.

    Walks through the span looking for a ':' that ends a def or class
    line, skipping colons inside type annotations (which appear inside
    brackets/parens), strings, and comments.

    Tracks both parentheses and square brackets to correctly handle
    type annotations like `-> Dict[str, int]:` where the `:` inside
    the brackets is NOT the signature colon.

    Returns the character offset of the colon within the span.
    """
    i = 0
    length = len(span)
    paren_depth = 0  # tracks ( )
    bracket_depth = 0  # tracks [ ] — needed for type annotations
    found_keyword = False

    while i < length:
        ch = span[i]

        # Skip string literals
        if ch in ('"', "'"):
            quote = ch
            # Check for triple-quote
            if i + 2 < length and span[i + 1] == quote and span[i + 2] == quote:
                i += 3
                while i + 2 < length:
                    if (
                        span[i] == quote
                        and span[i + 1] == quote
                        and span[i + 2] == quote
                    ):
                        i += 3
                        break
                    if span[i] == "\\":
                        i += 1
                    i += 1
                continue
            i += 1
            while i < length and span[i] != quote:
                if span[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue

        # Skip comments
        if ch == "#":
            while i < length and span[i] != "\n":
                i += 1
            continue

        # Track parentheses and brackets for multi-line signatures
        # and type annotations like Dict[str, int]
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            logger.debug(
                "_find_signature_colon: clean",
                extra={"event": "python._find_signature_colon.branch.clean"},
            )
            paren_depth -= 1
        elif ch == "[":
            logger.debug(
                "_find_signature_colon: clean",
                extra={"event": "python._find_signature_colon.branch.clean"},
            )
            bracket_depth += 1
        elif ch == "]":
            logger.debug(
                "_find_signature_colon: clean",
                extra={"event": "python._find_signature_colon.branch.clean"},
            )
            bracket_depth -= 1

        # Look for def/class keyword
        if not found_keyword:
            for kw in ("def ", "class "):
                if span[i : i + len(kw)] == kw:
                    found_keyword = True
                    break

        # The signature colon is the first ':' at depth 0 for both
        # parens and brackets, after the def/class keyword
        if found_keyword and ch == ":" and paren_depth == 0 and bracket_depth == 0:
            logger.debug(
                "file_patch: Python signature colon found at offset %d in span",
                i,
                extra={
                    "event": "file.patch_py_signature_colon",
                    "colon_offset": i,
                },
            )
            return i

        i += 1

    # Fallback: return end of first line — log as this is unusual
    newline = span.find("\n")
    fallback = newline if newline >= 0 else length - 1
    logger.warning(
        "file_patch: Python signature colon not found, using fallback at offset %d",
        fallback,
        extra={
            "event": "file.patch_py_signature_colon_fallback",
            "fallback_offset": fallback,
            "span_length": length,
        },
    )
    return fallback
