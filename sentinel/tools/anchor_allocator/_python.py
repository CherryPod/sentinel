"""Python anchor parser using the ast module."""

from __future__ import annotations

import ast
import logging

from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier

logger = logging.getLogger(__name__)


def parse_python_anchors(content: str) -> list[AnchorEntry]:
    """Parse Python source and return anchor candidates at all tiers.

    Returns an empty list on parse failure (fail-safe).
    """
    if not content.strip():
        return []

    try:
        tree = ast.parse(content)
    except SyntaxError as exc:
        logger.warning("python_anchor_parse_failed", exc_info=exc)
        return []

    anchors: list[AnchorEntry] = []
    has_imports = False
    has_constants = False
    first_def_line = None

    for node in ast.iter_child_nodes(tree):
        # Track imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            has_imports = True
            continue

        # Track module-level assignments (constants) before first def/class
        if isinstance(node, ast.Assign) and first_def_line is None:
            has_constants = True
            continue

        # Module-level functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if first_def_line is None:
                first_def_line = node.lineno
            anchors.append(AnchorEntry(
                name=f"func-{node.name}",
                line=node.lineno,
                tier=AnchorTier.BLOCK,
                description=f"Function {node.name}()",
                has_end=True,
                end_line=getattr(node, "end_lineno", None),
            ))

        # Classes
        if isinstance(node, ast.ClassDef):
            if first_def_line is None:
                first_def_line = node.lineno
            anchors.append(AnchorEntry(
                name=f"class-{node.name}",
                line=node.lineno,
                tier=AnchorTier.BLOCK,
                description=f"Class {node.name}",
                has_end=True,
                end_line=getattr(node, "end_lineno", None),
            ))
            # Methods within the class
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    anchors.append(AnchorEntry(
                        name=f"{node.name}.{child.name}",
                        line=child.lineno,
                        tier=AnchorTier.BLOCK,
                        description=f"Method {node.name}.{child.name}()",
                        has_end=True,
                        end_line=getattr(child, "end_lineno", None),
                    ))

    # Section-tier anchors
    if has_imports:
        anchors.insert(0, AnchorEntry(
            name="imports",
            line=1,
            tier=AnchorTier.SECTION,
            description="Import block",
            has_end=False,
        ))

    if has_constants:
        anchors.insert(
            1 if has_imports else 0,
            AnchorEntry(
                name="constants",
                line=1,
                tier=AnchorTier.SECTION,
                description="Module-level constants",
                has_end=False,
            ),
        )

    return anchors
