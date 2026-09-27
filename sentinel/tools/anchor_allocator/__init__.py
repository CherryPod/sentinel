"""Anchor allocator — places deterministic named markers in files.

Called by the executor after the code fixer. Parsers identify structural
boundaries, place comment markers, and write anchor maps to episodic memory.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path

from sentinel.core.context import require_user_id
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

logger = logging.getLogger(__name__)

# Extension -> parser function mapping (lazy-loaded)
_PARSER_MAP: dict[str, Callable] = {}


def _load_parsers() -> None:
    """Lazy-load parsers to avoid circular imports."""
    logger.debug(
        "_load_parsers called", extra={"event": "anchor_allocator._load_parsers"}
    )  # auto:entry
    if _PARSER_MAP:
        return
    from sentinel.tools.anchor_allocator._config import (
        parse_json_anchors,
        parse_toml_anchors,
        parse_yaml_anchors,
    )
    from sentinel.tools.anchor_allocator._css import parse_css_anchors
    from sentinel.tools.anchor_allocator._html import parse_html_anchors
    from sentinel.tools.anchor_allocator._javascript import parse_javascript_anchors
    from sentinel.tools.anchor_allocator._python import parse_python_anchors
    from sentinel.tools.anchor_allocator._rust import parse_rust_anchors
    from sentinel.tools.anchor_allocator._shell import parse_shell_anchors

    _PARSER_MAP.update(
        {
            ".html": parse_html_anchors,
            ".htm": parse_html_anchors,
            ".py": parse_python_anchors,
            ".css": parse_css_anchors,
            ".js": parse_javascript_anchors,
            ".mjs": parse_javascript_anchors,
            ".jsx": parse_javascript_anchors,
            ".tsx": parse_javascript_anchors,
            ".ts": parse_javascript_anchors,
            ".rs": parse_rust_anchors,
            ".sh": parse_shell_anchors,
            ".bash": parse_shell_anchors,
            ".yaml": parse_yaml_anchors,
            ".yml": parse_yaml_anchors,
            ".json": parse_json_anchors,
            ".toml": parse_toml_anchors,
        }
    )


def _resolve_body_marker(
    name: str,
    lines: list[str],
) -> tuple[int, int | None]:
    """Resolve body-start or body-end anchor to a line number."""
    if name == "body-start":
        for i, line in enumerate(lines, 1):
            if re.search(r"<body[\s>]", line, re.IGNORECASE):
                return i + 1, None  # Line after <body>
    else:  # body-end
        for i in range(len(lines) - 1, -1, -1):
            if re.search(r"</body>", lines[i], re.IGNORECASE):
                return i + 1, None  # 1-based
    return 0, None


def _resolve_head_style_marker(
    name: str,
    lines: list[str],
) -> tuple[int, int | None]:
    """Resolve head-styles or head-styles-end anchor."""
    if name == "head-styles":
        found_line = 0
        found_end_line = None
        for i, line in enumerate(lines, 1):
            if re.search(r"<style[\s>]", line, re.IGNORECASE):
                found_line = i
                break
        for i, line in enumerate(lines, 1):
            if re.search(r"</style>", line, re.IGNORECASE):
                found_end_line = i
                break
        return found_line, found_end_line

    # head-styles-end
    for i, line in enumerate(lines, 1):
        if re.search(r"</style>", line, re.IGNORECASE):
            return i + 1, None  # After </style>
    return 0, None


def _find_head_end_line(lines: list[str]) -> int | None:
    """Find the 1-based line number of </head>, or None if not found."""
    for i, line in enumerate(lines, 1):
        if re.search(r"</head>", line, re.IGNORECASE):
            return i
    return None


def _resolve_head_script_marker(
    name: str,
    lines: list[str],
) -> tuple[int, int | None]:
    """Resolve head-scripts or head-scripts-end anchor."""
    head_end = _find_head_end_line(lines)

    if name == "head-scripts":
        found_line = 0
        found_end_line = None
        for i, line in enumerate(lines, 1):
            if re.search(r"<script[\s>]", line, re.IGNORECASE):
                found_line = i
                break
        # Last </script> before </head>
        if head_end:
            for i in range(head_end - 1, -1, -1):
                if re.search(r"</script>", lines[i], re.IGNORECASE):
                    found_end_line = i + 1  # 1-based
                    break
        return found_line, found_end_line

    # head-scripts-end
    if head_end:
        for i in range(head_end - 1, -1, -1):
            if re.search(r"</script>", lines[i], re.IGNORECASE):
                return i + 2, None  # After </script> (1-based + 1)
    return 0, None


def _find_body_end_index(lines: list[str]) -> int:
    """Find the 0-based index of </body>, or len(lines) if not found."""
    for i in range(len(lines) - 1, -1, -1):
        if re.search(r"</body>", lines[i], re.IGNORECASE):
            return i
    return len(lines)


def _resolve_body_script_marker(
    name: str,
    lines: list[str],
) -> tuple[int, int | None]:
    """Resolve scripts or scripts-end anchor (body-area scripts)."""
    body_end = _find_body_end_index(lines)

    if name == "scripts":
        found_line = 0
        found_end_line = None
        # First <script> in body area
        in_body = False
        for i, line in enumerate(lines, 1):
            if re.search(r"<body[\s>]", line, re.IGNORECASE):
                in_body = True
            if in_body and re.search(r"<script[\s>]", line, re.IGNORECASE):
                found_line = i
                break
        # Last </script> before </body>
        for i in range(body_end - 1, -1, -1):
            if re.search(r"</script>", lines[i], re.IGNORECASE):
                found_end_line = i + 1  # 1-based
                break
        return found_line, found_end_line

    # scripts-end
    for i in range(body_end - 1, -1, -1):
        if re.search(r"</script>", lines[i], re.IGNORECASE):
            return i + 2, None  # After </script>
    return 0, None


def _find_closing_tag_line(
    lines: list[str],
    start_idx: int,
    tag: str,
) -> int | None:
    """Find the closing tag line for a balanced open/close pair.

    Uses depth-tracking to handle nested tags of the same type.
    Returns a 1-based line number, or None if no closing tag found.
    """
    logger.debug(
        "_find_closing_tag_line called",
        extra={
            "event": "anchor_allocator._find_closing_tag_line",
            "lines_len": len(lines) if hasattr(lines, "__len__") else 0,
            "start_idx": start_idx,
            "tag": tag,
        },
    )  # auto:entry
    depth = 0
    open_re = re.compile(rf"<{re.escape(tag)}[\s>]", re.IGNORECASE)
    close_re = re.compile(rf"</{re.escape(tag)}>", re.IGNORECASE)
    for i in range(start_idx, len(lines)):
        depth += len(open_re.findall(lines[i]))
        depth -= len(close_re.findall(lines[i]))
        if depth <= 0:
            return i + 1  # 1-based
    return None


def _resolve_element_marker(
    name: str,
    lines: list[str],
    resolved: list[AnchorEntry],
) -> tuple[int, int | None]:
    """Resolve el-{id} or el-{id}-end anchors.

    Start anchors: search by HTML id attribute, then fall back to
    structural tag occurrence (e.g. el-nav-1 = first <nav>).
    End anchors: look up the sibling start anchor's end_line.
    """
    logger.debug(
        "resolve_element_marker called",
        extra={
            "event": "anchor_allocator.resolve_element_marker",
            "anchor_name": name,
            "line_count": len(lines),
            "resolved_count": len(resolved),
        },
    )
    if name.endswith("-end"):
        # End marker — resolve from sibling's end_line
        base_name = name[:-4]
        for prev in resolved:
            if prev.name == base_name and prev.end_line is not None:
                return prev.end_line + 1, None
        return 0, None

    el_ref = name[3:]  # Remove "el-" prefix
    found_line = 0

    # Try matching by HTML id attribute
    id_pattern = re.compile(
        rf'<\w+[^>]*\bid\s*=\s*["\']?{re.escape(el_ref)}["\']?',
        re.IGNORECASE,
    )
    for i, line in enumerate(lines, 1):
        if id_pattern.search(line):
            found_line = i
            break

    # Fallback: structural tag occurrence (e.g. el-nav-1 = 1st <nav>)
    if found_line == 0:
        struct_match = re.match(r"^(\w+)-(\d+)$", el_ref)
        if struct_match:
            tag_name = struct_match.group(1)
            occurrence = int(struct_match.group(2))
            count = 0
            tag_re = re.compile(
                rf"<{re.escape(tag_name)}[\s>]",
                re.IGNORECASE,
            )
            for i, line in enumerate(lines, 1):
                if tag_re.search(line):
                    count += 1
                    if count == occurrence:
                        found_line = i
                        break

    # Find the closing tag for end_line via depth tracking
    found_end_line = None
    if found_line > 0:
        tag_match = re.match(r".*<(\w+)", lines[found_line - 1])
        if tag_match:
            found_end_line = _find_closing_tag_line(
                lines,
                found_line - 1,
                tag_match.group(1),
            )

    return found_line, found_end_line


def _resolve_func_marker(
    name: str,
    lines: list[str],
    resolved: list[AnchorEntry],
) -> tuple[int, int | None]:
    """Resolve func-{name} or func-{name}-end anchors (JS in HTML body)."""
    logger.debug(
        "_resolve_func_marker called",
        extra={
            "event": "anchor_allocator._resolve_func_marker",
            "record_name": name,  # auto:key
            "lines_len": len(lines) if hasattr(lines, "__len__") else 0,
            "resolved_len": len(resolved) if hasattr(resolved, "__len__") else 0,
        },
    )  # auto:entry
    if name.endswith("-end"):
        base_name = name[:-4]
        for prev in resolved:
            if prev.name == base_name and prev.end_line is not None:
                return prev.end_line + 1, None
        return 0, None

    func_name = name[5:]  # Remove "func-" prefix
    func_re = re.compile(
        rf"(?:async\s+)?function\s+{re.escape(func_name)}\s*\(",
    )
    in_body = False
    for i, line in enumerate(lines, 1):
        if re.search(r"<body[\s>]", line, re.IGNORECASE):
            in_body = True
        if in_body and func_re.search(line):
            return i, None
    return 0, None


# Dispatch table: exact anchor names to resolver functions.
# Prefix-based anchors (el-*, func-*) are handled in the dispatcher.
_EXACT_RESOLVERS: dict[str, Callable] = {
    "body-start": _resolve_body_marker,
    "body-end": _resolve_body_marker,
    "head-styles": _resolve_head_style_marker,
    "head-styles-end": _resolve_head_style_marker,
    "head-scripts": _resolve_head_script_marker,
    "head-scripts-end": _resolve_head_script_marker,
    "scripts": _resolve_body_script_marker,
    "scripts-end": _resolve_body_script_marker,
}


def _dispatch_resolver(
    name: str,
    lines: list[str],
    resolved: list[AnchorEntry],
) -> tuple[int, int | None]:
    """Dispatch an anchor name to the appropriate resolver function."""
    # Exact name match
    resolver = _EXACT_RESOLVERS.get(name)
    if resolver is not None:
        logger.debug(
            "dispatch exact resolver",
            extra={"event": "anchor_allocator.dispatch.exact", "anchor_name": name},
        )
        return resolver(name, lines)

    # Prefix-based matches (need resolved list for end-marker lookups)
    if name.startswith("el-"):
        logger.debug(
            "dispatch element resolver",
            extra={"event": "anchor_allocator.dispatch.element", "anchor_name": name},
        )
        return _resolve_element_marker(name, lines, resolved)
    logger.debug(
        "_dispatch_resolver: startswith_el__passed",
        extra={
            "event": "anchor_allocator.dispatch.element.passed",
            "reason": "startswith_el__passed",
        },
    )  # auto:neg
    if name.startswith("func-"):
        logger.debug(
            "dispatch func resolver",
            extra={"event": "anchor_allocator.dispatch.func", "anchor_name": name},
        )
        return _resolve_func_marker(name, lines, resolved)

    logger.debug(
        "unrecognised anchor name",
        extra={"event": "anchor_allocator.dispatch.unrecognised", "anchor_name": name},
    )
    return 0, None


def _resolve_html_lines(
    content: str,
    anchors: list[AnchorEntry],
) -> list[AnchorEntry]:
    """Resolve line=0 anchors for HTML by searching content for elements.

    HTML parsers (BeautifulSoup) don't provide reliable line numbers,
    so we search the source text for tag patterns and assign line numbers.
    Returns a new list with resolved line numbers.
    """
    logger.debug(
        "resolve_html_lines called",
        extra={
            "event": "anchor_allocator.resolve_html_lines",
            "anchor_count": len(anchors),
        },
    )
    lines = content.split("\n")
    resolved: list[AnchorEntry] = []

    for anchor in anchors:
        if anchor.line > 0:
            resolved.append(anchor)
            continue

        found_line, found_end_line = _dispatch_resolver(
            anchor.name,
            lines,
            resolved,
        )

        if found_line > 0:
            resolved.append(
                AnchorEntry(
                    name=anchor.name,
                    line=found_line,
                    tier=anchor.tier,
                    description=anchor.description,
                    has_end=anchor.has_end,
                    end_line=found_end_line or anchor.end_line,
                )
            )
        else:
            # Couldn't resolve — keep the anchor for the map but skip insertion
            resolved.append(anchor)

    unresolved = sum(1 for a in resolved if a.line == 0)
    if unresolved:
        logger.debug(
            "resolve_html_lines.unresolved_anchors",
            extra={
                "event": "anchor_allocator.resolve_html_lines.unresolved",
                "unresolved_count": unresolved,
                "total_count": len(resolved),
            },
        )

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
    logger.debug(
        "_insert_anchors called",
        extra={
            "event": "anchor_allocator._insert_anchors",
            "content_len": len(content) if hasattr(content, "__len__") else 0,
            "anchors_len": len(anchors) if hasattr(anchors, "__len__") else 0,
            "path": path,
        },
    )  # auto:entry
    ext = Path(path).suffix.lower()
    if ext == ".json":
        logger.debug(
            "_insert_anchors: ext_eq__json",
            extra={
                "event": "anchor_allocator._insert_anchors.match",
                "reason": "ext_eq__json",
            },
        )  # auto:neg
        return content  # JSON has no comments
    logger.debug(
        "_insert_anchors: ext_eq__json_passed",
        extra={
            "event": "anchor_allocator._insert_anchors.passed",
            "reason": "ext_eq__json_passed",
        },
    )  # auto:neg

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
    user_id: int | None = None,
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
    user_id = require_user_id(user_id, "anchor_allocator.allocate_anchors")
    _load_parsers()

    ext = Path(path).suffix.lower()
    parser = _PARSER_MAP.get(ext)

    if parser is None:
        logger.debug("anchor_allocator_no_parser path=%s ext=%s", path, ext)
        return AnchorResult(
            content=content,
            changed=False,
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
    except Exception as exc:  # catch-all: untrusted content parsing
        logger.warning(
            "anchor_parse_failed path=%s parser=%s error=%s",
            path,
            ext,
            exc,
            exc_info=True,
        )
        return AnchorResult(
            content=content,
            changed=False,
            file_hash=content_hash(content),
            parse_failed=True,
            error=str(exc),
        )

    if not all_anchors:
        # Parser returned empty — check if this is a failure or just empty file
        is_failure = bool(stripped.strip())
        return AnchorResult(
            content=content,
            changed=False,
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
            path,
            len(filtered),
            tier,
            anchor_names,
        )

    return AnchorResult(
        content=new_content,
        changed=changed,
        anchors=filtered,
        file_hash=final_hash,
    )
