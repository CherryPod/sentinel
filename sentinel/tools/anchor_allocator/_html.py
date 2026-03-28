"""HTML anchor parser using BeautifulSoup."""

from __future__ import annotations

import logging
import re

from bs4 import BeautifulSoup, Tag

from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier

logger = logging.getLogger(__name__)

# Structural HTML tags that get anchored even without IDs
_STRUCTURAL_TAGS = frozenset({
    "nav", "header", "footer", "main", "section", "article", "aside",
})

# Regex for function declarations inside <script> blocks
_JS_FUNC_RE = re.compile(
    r'(?:async\s+)?function\s+(\w+)\s*\(', re.MULTILINE,
)


def _add_with_end(
    anchors: list[AnchorEntry],
    name: str,
    tier: AnchorTier,
    description: str,
) -> None:
    """Add an anchor entry and its end-pair entry to the list.

    The start entry gets has_end=True so _resolve_html_lines knows to
    find a closing tag, but we do NOT emit a separate "-end" AnchorEntry
    here.  _insert_anchors() generates the end marker from end_line once
    _resolve_html_lines has resolved it.
    """
    anchors.append(AnchorEntry(
        name=name, line=0,
        tier=tier,
        description=description,
        has_end=True,
    ))


def parse_html_anchors(content: str) -> list[AnchorEntry]:
    """Parse HTML and return anchor candidates at all tiers.

    Returns an empty list on parse failure (fail-safe).
    """
    if not content.strip():
        return []

    try:
        soup = BeautifulSoup(content, "html.parser")
    except Exception as exc:
        logger.warning("html_anchor_parse_failed", exc_info=exc)
        return []

    anchors: list[AnchorEntry] = []
    structural_counts: dict[str, int] = {}

    # --- SECTION tier: <head> structure ---
    head = soup.find("head")
    if head:
        # Style blocks
        for style in head.find_all("style"):
            _add_with_end(
                anchors, "head-styles", AnchorTier.SECTION,
                "Before <style> block in <head>. Insert CSS here",
            )

        # Script blocks in head
        for script in head.find_all("script"):
            _add_with_end(
                anchors, "head-scripts", AnchorTier.SECTION,
                "Before <script> block in <head>",
            )

    # --- SECTION tier: <body> boundaries ---
    body = soup.find("body")
    if body:
        anchors.append(AnchorEntry(
            name="body-start", line=0,
            tier=AnchorTier.SECTION,
            description="Start of <body>",
            has_end=False,
        ))
        anchors.append(AnchorEntry(
            name="body-end", line=0,
            tier=AnchorTier.SECTION,
            description="End of <body>. Insert new sections before this",
            has_end=False,
        ))

    # --- SECTION tier: <script> blocks in body ---
    if body:
        body_scripts = body.find_all("script", recursive=False)
        if body_scripts:
            _add_with_end(
                anchors, "scripts", AnchorTier.SECTION,
                "Main <script> block in body",
            )

    # --- BLOCK tier: elements with IDs ---
    for tag in soup.find_all(True, id=True):
        tag_id = tag.get("id", "")
        if not tag_id or tag.name in ("html", "head", "body"):
            continue
        _add_with_end(
            anchors, f"el-{tag_id}", AnchorTier.BLOCK,
            f"Element #{tag_id} (<{tag.name}>)",
        )

    # --- BLOCK tier: structural elements without IDs ---
    for tag_name in _STRUCTURAL_TAGS:
        for tag in soup.find_all(tag_name):
            if tag.get("id"):
                continue  # Already handled above
            structural_counts.setdefault(tag_name, 0)
            structural_counts[tag_name] += 1
            n = structural_counts[tag_name]
            _add_with_end(
                anchors, f"el-{tag_name}-{n}", AnchorTier.BLOCK,
                f"<{tag_name}> element (#{n}, no ID)",
            )

    # --- BLOCK tier: JS functions inside <script> blocks ---
    if body:
        for script in body.find_all("script"):
            script_text = script.string or ""
            for match in _JS_FUNC_RE.finditer(script_text):
                func_name = match.group(1)
                _add_with_end(
                    anchors, f"func-{func_name}", AnchorTier.BLOCK,
                    f"JS function {func_name}()",
                )

    return anchors
