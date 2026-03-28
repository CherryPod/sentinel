"""Anchor allocator — places deterministic named markers in files.

Called by the executor after the code fixer. Parsers identify structural
boundaries, place comment markers, and write anchor maps to episodic memory.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.tools.anchor_allocator._core import (
    AnchorEntry,
    AnchorResult,
    AnchorTier,
    build_marker,
    content_hash,
)
from sentinel.tools.anchor_allocator._strip import strip_anchors

__all__ = [
    "AnchorEntry",
    "AnchorResult",
    "AnchorTier",
    "allocate_anchors",
    "build_marker",
    "content_hash",
]

logger = logging.getLogger("sentinel.audit")

# Extension -> parser function mapping (lazy-loaded)
_PARSER_MAP: dict[str, callable] = {}


def _load_parsers() -> None:
    """Lazy-load parsers to avoid circular imports."""
    if _PARSER_MAP:
        return
    from sentinel.tools.anchor_allocator._html import parse_html_anchors
    from sentinel.tools.anchor_allocator._python import parse_python_anchors
    from sentinel.tools.anchor_allocator._css import parse_css_anchors
    from sentinel.tools.anchor_allocator._shell import parse_shell_anchors
    from sentinel.tools.anchor_allocator._config import (
        parse_yaml_anchors,
        parse_json_anchors,
        parse_toml_anchors,
    )
    _PARSER_MAP.update({
        ".html": parse_html_anchors,
        ".htm":  parse_html_anchors,
        ".py":   parse_python_anchors,
        ".css":  parse_css_anchors,
        ".sh":   parse_shell_anchors,
        ".bash": parse_shell_anchors,
        ".yaml": parse_yaml_anchors,
        ".yml":  parse_yaml_anchors,
        ".json": parse_json_anchors,
        ".toml": parse_toml_anchors,
    })


def _resolve_html_lines(
    content: str,
    anchors: list[AnchorEntry],
) -> list[AnchorEntry]:
    """Resolve line=0 anchors for HTML by searching content for elements.

    HTML parsers (BeautifulSoup) don't provide reliable line numbers,
    so we search the source text for tag patterns and assign line numbers.
    Returns a new list with resolved line numbers.
    """
    lines = content.split("\n")
    resolved: list[AnchorEntry] = []

    for anchor in anchors:
        if anchor.line > 0:
            resolved.append(anchor)
            continue

        name = anchor.name
        found_line = 0
        found_end_line = None

        # body-start: line after <body>
        if name == "body-start":
            for i, line in enumerate(lines, 1):
                if re.search(r'<body[\s>]', line, re.IGNORECASE):
                    found_line = i + 1  # Line after <body>
                    break

        # body-end: line with </body>
        elif name == "body-end":
            for i in range(len(lines) - 1, -1, -1):
                if re.search(r'</body>', lines[i], re.IGNORECASE):
                    found_line = i + 1  # 1-based
                    break

        # head-styles / head-styles-end: <style> and </style> in <head>
        elif name == "head-styles":
            for i, line in enumerate(lines, 1):
                if re.search(r'<style[\s>]', line, re.IGNORECASE):
                    found_line = i
                    break
            # Find end line for </style>
            for i, line in enumerate(lines, 1):
                if re.search(r'</style>', line, re.IGNORECASE):
                    found_end_line = i
                    break
        elif name == "head-styles-end":
            for i, line in enumerate(lines, 1):
                if re.search(r'</style>', line, re.IGNORECASE):
                    found_line = i + 1  # After </style>
                    break

        # head-scripts / head-scripts-end: <script> in <head>
        elif name == "head-scripts":
            for i, line in enumerate(lines, 1):
                if re.search(r'<script[\s>]', line, re.IGNORECASE):
                    found_line = i
                    break
            # Find end: last </script> before </head>
            head_end = None
            for i, line in enumerate(lines, 1):
                if re.search(r'</head>', line, re.IGNORECASE):
                    head_end = i
                    break
            if head_end:
                for i in range(head_end - 1, -1, -1):
                    if re.search(r'</script>', lines[i], re.IGNORECASE):
                        found_end_line = i + 1  # 1-based
                        break
        elif name == "head-scripts-end":
            # Find last </script> in head area
            head_end = None
            for i, line in enumerate(lines, 1):
                if re.search(r'</head>', line, re.IGNORECASE):
                    head_end = i
                    break
            if head_end:
                for i in range(head_end - 1, -1, -1):
                    if re.search(r'</script>', lines[i], re.IGNORECASE):
                        found_line = i + 2  # After </script> (1-based + 1)
                        break

        # scripts / scripts-end: <script> in body
        elif name == "scripts":
            # Find first <script> in body area
            in_body = False
            for i, line in enumerate(lines, 1):
                if re.search(r'<body[\s>]', line, re.IGNORECASE):
                    in_body = True
                if in_body and re.search(r'<script[\s>]', line, re.IGNORECASE):
                    found_line = i
                    break
            # Find end: last </script> before </body>
            body_end = len(lines)
            for i in range(len(lines) - 1, -1, -1):
                if re.search(r'</body>', lines[i], re.IGNORECASE):
                    body_end = i
                    break
            for i in range(body_end - 1, -1, -1):
                if re.search(r'</script>', lines[i], re.IGNORECASE):
                    found_end_line = i + 1  # 1-based
                    break
        elif name == "scripts-end":
            # Find last </script> before </body>
            body_end = len(lines)
            for i in range(len(lines) - 1, -1, -1):
                if re.search(r'</body>', lines[i], re.IGNORECASE):
                    body_end = i
                    break
            for i in range(body_end - 1, -1, -1):
                if re.search(r'</script>', lines[i], re.IGNORECASE):
                    found_line = i + 2  # After </script>
                    break

        # el-{id} / el-{id}-end: elements with IDs
        elif name.startswith("el-") and not name.endswith("-end"):
            # Extract the ID or structural element reference
            el_ref = name[3:]  # Remove "el-" prefix
            # Try matching an element with this ID
            id_pattern = re.compile(
                rf'<\w+[^>]*\bid\s*=\s*["\']?{re.escape(el_ref)}["\']?',
                re.IGNORECASE,
            )
            for i, line in enumerate(lines, 1):
                if id_pattern.search(line):
                    found_line = i
                    break

            # If not found by ID, try as a structural tag (e.g., el-nav-1)
            if found_line == 0:
                struct_match = re.match(r'^(\w+)-(\d+)$', el_ref)
                if struct_match:
                    tag_name = struct_match.group(1)
                    occurrence = int(struct_match.group(2))
                    count = 0
                    tag_re = re.compile(
                        rf'<{re.escape(tag_name)}[\s>]', re.IGNORECASE,
                    )
                    for i, line in enumerate(lines, 1):
                        if tag_re.search(line):
                            count += 1
                            if count == occurrence:
                                found_line = i
                                break

            # Find the closing tag for end_line
            if found_line > 0:
                # Determine the tag name from the found line
                tag_match = re.match(r'.*<(\w+)', lines[found_line - 1])
                if tag_match:
                    tag = tag_match.group(1)
                    depth = 0
                    open_re = re.compile(
                        rf'<{re.escape(tag)}[\s>]', re.IGNORECASE,
                    )
                    close_re = re.compile(
                        rf'</{re.escape(tag)}>', re.IGNORECASE,
                    )
                    for i in range(found_line - 1, len(lines)):
                        # Count opens and closes on this line
                        depth += len(open_re.findall(lines[i]))
                        depth -= len(close_re.findall(lines[i]))
                        if depth <= 0:
                            found_end_line = i + 1  # 1-based
                            break

        elif name.startswith("el-") and name.endswith("-end"):
            # End marker for an element — find the start anchor's end_line
            # This is handled by the start anchor's end_line, skip here
            # We'll set found_line from the sibling's end_line below
            base_name = name[:-4]  # Remove "-end"
            # Look through already-resolved anchors for the base
            for prev in resolved:
                if prev.name == base_name and prev.end_line is not None:
                    found_line = prev.end_line + 1  # After closing tag
                    break

        # JS function anchors (func-{name} / func-{name}-end) inside scripts
        elif name.startswith("func-") and not name.endswith("-end"):
            func_name = name[5:]
            func_re = re.compile(
                rf'(?:async\s+)?function\s+{re.escape(func_name)}\s*\(',
            )
            in_body = False
            for i, line in enumerate(lines, 1):
                if re.search(r'<body[\s>]', line, re.IGNORECASE):
                    in_body = True
                if in_body and func_re.search(line):
                    found_line = i
                    break
        elif name.startswith("func-") and name.endswith("-end"):
            base_name = name[:-4]
            for prev in resolved:
                if prev.name == base_name and prev.end_line is not None:
                    found_line = prev.end_line + 1
                    break

        if found_line > 0:
            resolved.append(AnchorEntry(
                name=anchor.name,
                line=found_line,
                tier=anchor.tier,
                description=anchor.description,
                has_end=anchor.has_end,
                end_line=found_end_line if found_end_line else anchor.end_line,
            ))
        else:
            # Couldn't resolve — keep the anchor for the map but skip insertion
            resolved.append(anchor)

    return resolved


def _insert_anchors(
    content: str,
    anchors: list[AnchorEntry],
    path: str,
) -> str:
    """Insert anchor marker comments into content at appropriate positions.

    Handles three cases:
    1. Start markers: inserted BEFORE the anchor's line
    2. Explicit end-marker entries (HTML): already separate AnchorEntry objects
       with their own line numbers (resolved by _resolve_html_lines)
    3. Implicit end markers (Python/Shell): anchor has has_end=True with
       end_line set — inserts "{name}-end" marker AFTER end_line

    JSON files are skipped (no comment syntax).
    """
    ext = Path(path).suffix.lower()
    if ext == ".json":
        return content  # JSON has no comments

    lines = content.split("\n")

    # Build a list of (line_idx_0based, marker_string) insertions
    insertions: list[tuple[int, str]] = []

    for anchor in anchors:
        marker = build_marker(path, anchor.name)
        if marker is None:
            continue

        # Skip anchors where we couldn't resolve a line number
        if anchor.line <= 0:
            continue

        # Insert start marker BEFORE the anchor's line
        line_idx = anchor.line - 1  # Convert 1-based to 0-based
        insertions.append((line_idx, marker))

        # For anchors with has_end=True and end_line set, insert end marker
        # AFTER the block's last line. This handles Python/Shell/CSS where
        # the parser sets has_end=True but does NOT emit a separate end entry.
        if anchor.has_end and anchor.end_line is not None:
            end_marker = build_marker(path, f"{anchor.name}-end")
            if end_marker is not None:
                # Insert after end_line (0-based: end_line itself, because
                # inserting at index N pushes existing N down)
                insertions.append((anchor.end_line, end_marker))

    # Sort by line index descending so insertions from bottom don't shift
    # indices of insertions above. For same line, sort start markers before
    # end markers (stable sort keeps original order, start markers come first
    # in the anchors list).
    insertions.sort(key=lambda x: x[0], reverse=True)

    for line_idx, marker in insertions:
        # Determine indentation from the target line
        if line_idx < len(lines):
            existing = lines[line_idx]
            indent = len(existing) - len(existing.lstrip()) if existing.strip() else 0
            indented_marker = " " * indent + marker
        else:
            indented_marker = marker
        lines.insert(line_idx, indented_marker)

    return "\n".join(lines)


async def allocate_anchors(
    path: str,
    content: str,
    episodic_store=None,
    user_id: int = 1,
    tier: str = "block",
) -> AnchorResult:
    """Place anchor markers in content and write map to episodic memory.

    Pipeline:
        1. Strip existing anchors (idempotency)
        2. Parse structure (language-specific)
        3. Filter by configured tier
        4. Resolve line numbers (HTML needs content-search)
        5. Insert anchor markers as comments
        6. Compute content hash
        7. Write anchor map to episodic memory (if store provided)

    Fail-safe: any parser error -> return original content unchanged.
    """
    _load_parsers()

    ext = Path(path).suffix.lower()
    parser = _PARSER_MAP.get(ext)

    if parser is None:
        logger.debug("anchor_allocator_no_parser path=%s ext=%s", path, ext)
        return AnchorResult(
            content=content, changed=False,
            file_hash=content_hash(content),
        )

    logger.debug("anchor_allocator_called path=%s ext=%s", path, ext)

    # Step 1: Strip existing anchors for idempotency
    stripped, count_removed = strip_anchors(content)
    if count_removed > 0:
        logger.debug("anchors_stripped path=%s count=%d", path, count_removed)

    # Step 2: Parse structure
    try:
        all_anchors = parser(stripped)
    except Exception as exc:
        logger.warning(
            "anchor_parse_failed path=%s parser=%s error=%s", path, ext, exc,
        )
        return AnchorResult(
            content=content, changed=False,
            file_hash=content_hash(content),
            parse_failed=True, error=str(exc),
        )

    if not all_anchors:
        # Parser returned empty — check if this is a failure or just empty file
        is_failure = bool(stripped.strip())
        return AnchorResult(
            content=content, changed=False,
            file_hash=content_hash(content),
            parse_failed=is_failure,
            error="Parser returned no anchors" if is_failure else None,
        )

    # Step 3: Filter by tier
    tier_threshold = AnchorTier.from_string(tier)
    filtered = [a for a in all_anchors if a.tier.value <= tier_threshold.value]

    # Step 4: Resolve HTML line numbers (anchors at line=0 need content search)
    if ext in (".html", ".htm"):
        filtered = _resolve_html_lines(stripped, filtered)

    # Step 5: Insert markers
    new_content = _insert_anchors(stripped, filtered, path)

    # Step 6: Compute hash
    final_hash = content_hash(new_content)

    # Step 7: Write to episodic memory (if store provided)
    if episodic_store is not None:
        from sentinel.tools.anchor_allocator._memory import write_anchor_map
        await write_anchor_map(
            path=path,
            anchors=filtered,
            file_hash=final_hash,
            tier=tier,
            episodic_store=episodic_store,
            user_id=user_id,
        )

    changed = new_content != content
    anchor_names = [a.name for a in filtered]
    if changed:
        logger.info(
            "anchors_placed path=%s count=%d tier=%s names=%s",
            path, len(filtered), tier, anchor_names,
        )

    return AnchorResult(
        content=new_content,
        changed=changed,
        anchors=filtered,
        file_hash=final_hash,
    )
