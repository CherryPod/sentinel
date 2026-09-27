"""JavaScript/TypeScript anchor parser using regex."""

from __future__ import annotations

import logging
import re

from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier

logger = logging.getLogger(__name__)

# Named function declarations: function foo(), async function foo()
_FUNC_DECL_RE = re.compile(
    r"^[ \t]*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(",
    re.MULTILINE,
)

# Arrow / function-expression assigned to const/let/var:
#   const foo = (...) =>    or    const foo = function(
_ARROW_RE = re.compile(
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>",
    re.MULTILINE,
)
_FUNC_EXPR_RE = re.compile(
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(",
    re.MULTILINE,
)

# Class declarations: class Foo, export class Foo
_CLASS_RE = re.compile(
    r"^[ \t]*(?:export\s+(?:default\s+)?)?class\s+(\w+)",
    re.MULTILINE,
)


def parse_javascript_anchors(content: str) -> list[AnchorEntry]:
    """Parse JavaScript/TypeScript source and return anchor candidates.

    Uses regex — no AST. Returns an empty list for empty content.
    """
    logger.debug(
        "parse_javascript_anchors called",
        extra={
            "event": "javascript.parse_javascript_anchors",
            "content_len": len(content) if hasattr(content, "__len__") else 0,
        },
    )  # auto:entry
    if not content.strip():
        return []

    anchors: list[AnchorEntry] = []
    seen_names: set[str] = set()

    # Helper to find the 1-based line number for a match position
    def _line_of(pos: int) -> int:
        return content[:pos].count("\n") + 1

    # Named function declarations
    for m in _FUNC_DECL_RE.finditer(content):
        name = m.group(1)
        if name not in seen_names:
            seen_names.add(name)
            anchors.append(
                AnchorEntry(
                    name=f"fn-{name}",
                    line=_line_of(m.start()),
                    tier=AnchorTier.BLOCK,
                    description=f"Function {name}()",
                    has_end=False,
                )
            )

    # Arrow functions assigned to variables
    for m in _ARROW_RE.finditer(content):
        name = m.group(1)
        if name not in seen_names:
            seen_names.add(name)
            anchors.append(
                AnchorEntry(
                    name=f"fn-{name}",
                    line=_line_of(m.start()),
                    tier=AnchorTier.BLOCK,
                    description=f"Function {name}()",
                    has_end=False,
                )
            )

    # Function expressions assigned to variables
    for m in _FUNC_EXPR_RE.finditer(content):
        name = m.group(1)
        if name not in seen_names:
            seen_names.add(name)
            anchors.append(
                AnchorEntry(
                    name=f"fn-{name}",
                    line=_line_of(m.start()),
                    tier=AnchorTier.BLOCK,
                    description=f"Function {name}()",
                    has_end=False,
                )
            )

    # Class declarations
    for m in _CLASS_RE.finditer(content):
        name = m.group(1)
        if name not in seen_names:
            seen_names.add(name)
            anchors.append(
                AnchorEntry(
                    name=f"class-{name}",
                    line=_line_of(m.start()),
                    tier=AnchorTier.BLOCK,
                    description=f"Class {name}",
                    has_end=False,
                )
            )

    # Sort by line number for consistent ordering
    anchors.sort(key=lambda a: a.line)
    return anchors
