"""Rust anchor parser using regex."""

from __future__ import annotations

import logging
import re

from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier

logger = logging.getLogger(__name__)

# fn declarations: fn foo(), pub fn foo(), pub(crate) fn foo(), async fn foo()
_FN_RE = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*[<(]",
    re.MULTILINE,
)

# Struct declarations: struct Foo, pub struct Foo
_STRUCT_RE = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)",
    re.MULTILINE,
)

# Impl blocks: impl Foo, impl Trait for Foo
_IMPL_RE = re.compile(
    r"^[ \t]*impl(?:<[^>]*>)?\s+(?:\w+\s+for\s+)?(\w+)",
    re.MULTILINE,
)

# Enum declarations: enum Foo, pub enum Foo
_ENUM_RE = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?enum\s+(\w+)",
    re.MULTILINE,
)


def parse_rust_anchors(content: str) -> list[AnchorEntry]:
    """Parse Rust source and return anchor candidates.

    Uses regex — no AST. Returns an empty list for empty content.
    """
    logger.debug(
        "parse_rust_anchors called",
        extra={
            "event": "rust.parse_rust_anchors",
            "content_len": len(content) if hasattr(content, "__len__") else 0,
        },
    )  # auto:entry
    if not content.strip():
        return []

    anchors: list[AnchorEntry] = []

    # Helper to find the 1-based line number for a match position
    def _line_of(pos: int) -> int:
        return content[:pos].count("\n") + 1

    # Functions
    for m in _FN_RE.finditer(content):
        anchors.append(
            AnchorEntry(
                name=f"fn-{m.group(1)}",
                line=_line_of(m.start()),
                tier=AnchorTier.BLOCK,
                description=f"Function {m.group(1)}()",
                has_end=False,
            )
        )

    # Structs
    for m in _STRUCT_RE.finditer(content):
        anchors.append(
            AnchorEntry(
                name=f"struct-{m.group(1)}",
                line=_line_of(m.start()),
                tier=AnchorTier.BLOCK,
                description=f"Struct {m.group(1)}",
                has_end=False,
            )
        )

    # Impl blocks — deduplicate names with a counter for multiple impls
    impl_counts: dict[str, int] = {}
    for m in _IMPL_RE.finditer(content):
        type_name = m.group(1)
        impl_counts.setdefault(type_name, 0)
        impl_counts[type_name] += 1
        count = impl_counts[type_name]
        # First impl gets plain name, subsequent get numbered suffix
        anchor_name = f"impl-{type_name}" if count == 1 else f"impl-{type_name}-{count}"
        anchors.append(
            AnchorEntry(
                name=anchor_name,
                line=_line_of(m.start()),
                tier=AnchorTier.BLOCK,
                description=f"Impl block for {type_name}",
                has_end=False,
            )
        )

    # Enums
    for m in _ENUM_RE.finditer(content):
        anchors.append(
            AnchorEntry(
                name=f"enum-{m.group(1)}",
                line=_line_of(m.start()),
                tier=AnchorTier.BLOCK,
                description=f"Enum {m.group(1)}",
                has_end=False,
            )
        )

    # Sort by line number for consistent ordering
    anchors.sort(key=lambda a: a.line)
    return anchors
