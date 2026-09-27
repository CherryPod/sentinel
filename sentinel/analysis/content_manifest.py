# sentinel/analysis/content_manifest.py
"""Content manifest extraction for deployed files.

Extracts deterministic, observable properties from files — CSS colours,
text content, layout direction, JS behaviour patterns, Python structure.
This fills the semantic gap between structural_digest (element names and
counts) and what the user actually asked for (colours, content, behaviour).

Privacy boundary: the manifest confirms elements the planner already
planned. It does NOT expose raw file content the planner didn't originate.

Follows the same registry/dispatch pattern as structural_digest.py and
code_fixer/ — language-specific extractors keyed by file extension.
"""

from __future__ import annotations

import ast
import logging
import re
from typing import TYPE_CHECKING

from sentinel.core.decorators import no_audit_log

if TYPE_CHECKING:
    from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# -- CSS property parsing -----------------------------------------------------
# Matches "property: value;" inside a style attribute or block
_CSS_PROP_RE = re.compile(r"([\w\-]+)\s*:\s*([^;\"'}{]+);?")

# Layout-related CSS properties worth extracting
_LAYOUT_PROPS = frozenset(
    {
        "display",
        "flex-direction",
        "grid-template-columns",
        "grid-template-rows",
        "justify-content",
        "align-items",
        "position",
        "float",
    }
)

# Visual CSS properties worth extracting
_VISUAL_PROPS = frozenset(
    {
        "background",
        "background-color",
        "color",
        "font-size",
        "font-weight",
        "border",
        "border-radius",
        "opacity",
        "text-align",
        "width",
        "height",
        "max-width",
        "min-height",
    }
)

# CSS selector matching for style blocks: #id or .class { ... }
_CSS_RULE_RE = re.compile(
    r"([^{}@/]+?)\s*\{([^}]*)\}",
    re.DOTALL,
)

# Text content length cap — prevents manifest bloat from long prose
_TEXT_CONTENT_MAX = 200


# -- Public API ---------------------------------------------------------------


def extract_content_manifest(
    filename: str,
    content: str,
    language: str,
) -> dict:
    """Extract observable content properties from a file.

    Returns a dict of deterministic, verifiable properties.
    Never raises — returns empty manifest on parse errors.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    lang = language or _guess_language(filename)

    if not content:
        logger.debug(
            "content_manifest: empty content for %s",
            filename,
            extra={"event": "content_manifest.empty", "file_name": filename},
        )
        return _empty_manifest(lang)

    logger.debug(
        "content_manifest: dispatching %s (ext=%s, lang=%s, %d bytes)",
        filename,
        ext,
        lang,
        len(content),
        extra={
            "event": "content_manifest.dispatch",
            "file_name": filename,
            "ext": ext,
            "lang": lang,
            "content_bytes": len(content),
        },
    )

    try:
        if lang in ("html", "htm") or ext in ("html", "htm"):
            return _extract_html_manifest(content)
        if lang in ("javascript", "js", "mjs") or ext in ("js", "mjs"):
            return _extract_js_manifest(content)
        if lang in ("python", "py") or ext == "py":
            return _extract_python_manifest(content)
        if lang == "css" or ext == "css":
            return _extract_css_manifest(content)
    except Exception as exc:  # catch-all: untrusted content analysis
        logger.warning(
            "content_manifest: extraction failed for %s: %s",
            filename,
            exc,
            extra={
                "event": "content_manifest.error",
                "file_name": filename,
                "error": str(exc),
            },
            exc_info=True,
        )
        return _empty_manifest(lang)

    logger.debug(
        "content_manifest: unsupported file type %s — skipped",
        filename,
        extra={"event": "content_manifest.skipped", "file_name": filename},
    )
    return _empty_manifest(lang)


# -- HTML extractor -----------------------------------------------------------


def _extract_html_manifest(content: str) -> dict:
    """Extract observable properties from HTML content."""
    # Lazy import: bs4 is in [project.optional-dependencies] worker, so
    # consumers that import content_manifest must not eagerly load it.
    # See deferred-again D20 / FL-C17-a1.
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        logger.warning(
            "content_manifest: bs4 not installed, skipping HTML manifest extraction",
            extra={"event": "content_manifest.bs4_unavailable"},
            exc_info=True,
        )
        return _empty_manifest("html")

    logger.debug(
        "content_manifest: HTML extraction starting — %d bytes",
        len(content),
        extra={"event": "content_manifest.html_start", "content_bytes": len(content)},
    )

    soup = BeautifulSoup(content, "html.parser")

    # Body styles — background colour is the most common user request
    body_styles: dict[str, str] = {}
    body = soup.find("body")
    if body:
        body_styles = _parse_inline_style(body.get("style", ""))
        logger.debug(
            "content_manifest: body inline styles found: %d",
            len(body_styles),
            extra={
                "event": "content_manifest.html_body",
                "inline_count": len(body_styles),
            },
        )
    else:
        logger.debug(
            "content_manifest: no <body> tag found",
            extra={"event": "content_manifest.html_nobody"},
        )

    # Style block rules keyed by selector for computed style lookup
    style_rules = _parse_style_blocks(soup)

    # Apply body rules from style blocks if not overridden by inline
    body_block_styles = style_rules.get("body", {})
    for prop, val in body_block_styles.items():
        if prop not in body_styles:
            body_styles[prop] = val
    if body_block_styles:
        logger.debug(
            "content_manifest: body style-block rules merged — %d props (%d from block, %d from inline)",
            len(body_styles),
            len(body_block_styles),
            len(body_styles) - len(body_block_styles),
            extra={
                "event": "content_manifest.html_body_merge",
                "block_count": len(body_block_styles),
                "total_count": len(body_styles),
            },
        )

    # Elements with IDs — extract styles, text content, layout
    elements: list[dict] = []
    for el in soup.find_all(id=True):
        el_id = el.get("id", "")
        if not el_id or el_id in ("html", "head", "body"):
            continue

        inline_styles = _parse_inline_style(el.get("style", ""))

        # Computed styles from style blocks (ID selector)
        computed = {}
        id_selector = f"#{el_id}"
        if id_selector in style_rules:
            computed = dict(style_rules[id_selector])

        # Class-based styles
        for cls in el.get("class", []):
            cls_selector = f".{cls}"
            if cls_selector in style_rules:
                for prop, val in style_rules[cls_selector].items():
                    if prop not in computed:
                        computed[prop] = val

        # Direct text content (not children's text)
        text = el.get_text(strip=True)
        if len(text) > _TEXT_CONTENT_MAX:
            text = text[:_TEXT_CONTENT_MAX]

        # Layout properties from inline styles
        layout = {k: v for k, v in inline_styles.items() if k in _LAYOUT_PROPS}
        # Also from computed
        for prop in _LAYOUT_PROPS:
            if prop in computed and prop not in layout:
                layout[prop] = computed[prop]

        entry: dict = {
            "id": el_id,
            "tag": el.name,
            "text_content": text,
            "inline_styles": {
                k: v for k, v in inline_styles.items() if k in _VISUAL_PROPS
            },
            "computed_styles": {
                k: v for k, v in computed.items() if k in _VISUAL_PROPS
            },
        }
        if layout:
            entry["layout"] = layout

        elements.append(entry)

        logger.debug(
            "content_manifest: element id=%s tag=%s styles=%d",
            el_id,
            el.name,
            len(inline_styles),
            extra={
                "event": "content_manifest.element",
                "element_id": el_id[:32],
                "tag": el.name,
                "has_text": bool(text),
                "inline_style_count": len(inline_styles),
                "computed_style_count": len(computed),
            },
        )

    # Panel count
    panel_count = len(soup.find_all(class_="panel"))

    # Script refs
    script_refs = [script["src"] for script in soup.find_all("script", src=True)]

    manifest = {
        "language": "html",
        "body_styles": {k: v for k, v in body_styles.items() if k in _VISUAL_PROPS},
        "elements": elements,
        "panel_count": panel_count,
        "script_refs": script_refs,
        "element_count": len(elements),
    }

    logger.debug(
        "content_manifest: HTML complete — %d elements, %d panels, body_styles=%s",
        len(elements),
        panel_count,
        bool(body_styles),
        extra={
            "event": "content_manifest.html",
            "element_count": len(elements),
            "panel_count": panel_count,
            "has_body_styles": bool(body_styles),
            "script_ref_count": len(script_refs),
        },
    )

    return manifest


# -- JS extractor -------------------------------------------------------------

# JS regex patterns for behaviour detection
_JS_GETBYID_RE = re.compile(
    r"getElementById\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
)
_JS_QUERYSELECTOR_RE = re.compile(
    r"querySelector(?:All)?\s*\(\s*['\"]#([^'\"]+)['\"]\s*\)",
)
_JS_TIMER_RE = re.compile(
    r"(setInterval|setTimeout)\s*\([^,]+,\s*(\d+)\s*\)",
)
_JS_FETCH_RE = re.compile(
    r"fetch\s*\(\s*['\"]([^'\"]*)['\"]",
)
_JS_DATE_RE = re.compile(r"new\s+Date\s*\(")


def _extract_js_manifest(content: str) -> dict:
    """Extract observable behaviour patterns from JavaScript."""
    logger.debug(
        "content_manifest: JS extraction starting — %d bytes",
        len(content),
        extra={"event": "content_manifest.js_start", "content_bytes": len(content)},
    )

    behaviours: list[dict] = []
    dom_updates: list[str] = []
    _seen_dom_ids: set[str] = set()

    # DOM element references
    for pattern in (_JS_GETBYID_RE, _JS_QUERYSELECTOR_RE):
        for m in pattern.finditer(content):
            el_id = m.group(1)
            if el_id not in _seen_dom_ids:
                _seen_dom_ids.add(el_id)
                dom_updates.append(el_id)

    # Timer behaviours
    for m in _JS_TIMER_RE.finditer(content):
        behaviours.append(
            {
                "type": "timer",
                "function": m.group(1),
                "interval_ms": int(m.group(2)),
            }
        )
        logger.debug(
            "content_manifest: JS timer detected — %s every %dms",
            m.group(1),
            int(m.group(2)),
            extra={
                "event": "content_manifest.behaviour",
                "type": "timer",
                "interval_ms": int(m.group(2)),
            },
        )

    # Fetch behaviours
    for m in _JS_FETCH_RE.finditer(content):
        behaviours.append(
            {
                "type": "fetch",
                "url": m.group(1),
            }
        )
        logger.debug(
            "content_manifest: JS fetch detected — len=%d",
            len(m.group(1)),
            extra={
                "event": "content_manifest.behaviour",
                "type": "fetch",
                "url_len": len(m.group(1)),
            },
        )

    # Date usage
    if _JS_DATE_RE.search(content):
        behaviours.append({"type": "date_usage"})
        logger.debug(
            "content_manifest: JS Date() usage detected",
            extra={"event": "content_manifest.behaviour", "type": "date_usage"},
        )

    # Timer interval list for quick access
    timer_intervals = [b["interval_ms"] for b in behaviours if b["type"] == "timer"]

    manifest = {
        "language": "javascript",
        "behaviours": behaviours,
        "dom_updates": dom_updates,
        "timer_intervals": timer_intervals,
    }

    logger.debug(
        "content_manifest: JS complete — %d behaviours, %d DOM targets, timers=%s",
        len(behaviours),
        len(dom_updates),
        timer_intervals,
        extra={
            "event": "content_manifest.js",
            "behaviour_count": len(behaviours),
            "dom_update_count": len(dom_updates),
            "timer_intervals": timer_intervals,
        },
    )

    return manifest


# -- Style parsing helpers ----------------------------------------------------


def _parse_inline_style(style_attr: str) -> dict[str, str]:
    """Parse a CSS style attribute string into a property dict.

    No failure logging needed — regex matching is infallible. Returns
    empty dict for empty/unparseable input.
    """
    if not style_attr:
        return {}
    props = {}
    for match in _CSS_PROP_RE.finditer(style_attr):
        props[match.group(1).strip().lower()] = match.group(2).strip()
    return props


def _parse_style_blocks(soup: BeautifulSoup) -> dict[str, dict[str, str]]:
    """Parse <style> blocks into a selector -> properties dict."""
    rules: dict[str, dict[str, str]] = {}
    rule_count = 0
    for style_tag in soup.find_all("style"):
        css_text = style_tag.get_text()
        for match in _CSS_RULE_RE.finditer(css_text):
            selector = match.group(1).strip()
            props_text = match.group(2)
            props = {}
            for prop_match in _CSS_PROP_RE.finditer(props_text):
                prop = prop_match.group(1).strip().lower()
                val = prop_match.group(2).strip()
                props[prop] = val
            if props:
                rules[selector] = props
                rule_count += 1

    logger.debug(
        "content_manifest: parsed %d style block rules",
        rule_count,
        extra={"event": "content_manifest.style_blocks", "rule_count": rule_count},
    )
    return rules


# -- CSS extractor ------------------------------------------------------------

# Colour detection regex — named colours + hex + rgb/hsl
_COLOUR_RE = re.compile(
    r"(?:#[0-9a-fA-F]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\)"
    r"|transparent|inherit|currentColor"
    r"|black|white|red|green|blue|yellow|orange|purple|pink|gray|grey"
    r"|cyan|magenta|brown|navy|teal|maroon|olive|silver|aqua|fuchsia"
    r"|lime|indigo|violet|gold|coral|salmon|tomato|crimson|turquoise)",
)

_COLOUR_PROPS = frozenset(
    {
        "color",
        "background-color",
        "background",
        "border-color",
        "outline-color",
        "text-decoration-color",
    }
)


def _extract_css_manifest(content: str) -> dict:
    """Extract observable style properties from a CSS file."""
    logger.debug(
        "content_manifest: CSS extraction starting — %d bytes",
        len(content),
        extra={"event": "content_manifest.css_start", "content_bytes": len(content)},
    )

    element_styles: dict[str, dict[str, str]] = {}
    colour_palette: list[str] = []
    layout_rules: list[dict] = []
    seen_colours: set[str] = set()

    for match in _CSS_RULE_RE.finditer(content):
        selector = match.group(1).strip()
        props_text = match.group(2)

        if selector.startswith("@"):
            continue  # @media, @keyframes etc. — skip silently (high-volume)

        props: dict[str, str] = {}
        for prop_match in _CSS_PROP_RE.finditer(props_text):
            prop = prop_match.group(1).strip().lower()
            val = prop_match.group(2).strip()
            props[prop] = val

        # Collect colours from colour-related properties
        for prop in _COLOUR_PROPS:
            if prop in props:
                for colour_match in _COLOUR_RE.finditer(props[prop]):
                    colour = colour_match.group(0).lower()
                    if colour not in seen_colours:
                        seen_colours.add(colour)
                        colour_palette.append(colour)

        # Store visual properties for ID selectors (strip #)
        if selector.startswith("#"):
            el_id = selector[1:].split(":")[0].split(" ")[0]
            visual = {k: v for k, v in props.items() if k in _VISUAL_PROPS}
            if visual:
                element_styles[el_id] = visual

        # Layout rules
        layout = {k: v for k, v in props.items() if k in _LAYOUT_PROPS}
        if layout:
            layout["selector"] = selector
            layout_rules.append(layout)

    manifest = {
        "language": "css",
        "element_styles": element_styles,
        "colour_palette": colour_palette,
        "layout_rules": layout_rules,
    }

    logger.debug(
        "content_manifest: CSS complete — %d styled elements, %d colours, %d layout rules",
        len(element_styles),
        len(colour_palette),
        len(layout_rules),
        extra={
            "event": "content_manifest.css",
            "styled_element_count": len(element_styles),
            "colour_count": len(colour_palette),
            "layout_count": len(layout_rules),
        },
    )

    return manifest


# -- Python extractor ---------------------------------------------------------


def _extract_python_manifest(content: str) -> dict:
    """Extract observable structure from a Python file."""
    logger.debug(
        "content_manifest: Python extraction starting — %d bytes",
        len(content),
        extra={"event": "content_manifest.python_start", "content_bytes": len(content)},
    )

    entry_points: list[dict] = []
    class_signatures: list[dict] = []
    cli_args = False

    try:
        tree = ast.parse(content)
    except (SyntaxError, MemoryError, RecursionError, ValueError) as exc:
        logger.warning(
            "content_manifest: Python parse failed: %s",
            exc,
            extra={"event": "content_manifest.error", "error": str(exc)},
            exc_info=True,
        )
        return _empty_manifest("python")

    # Only top-level nodes — ast.walk would descend into class bodies
    # and double-count methods as both entry_points and class members
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in node.args.args if a.arg != "self"]
            entry_points.append(
                {
                    "name": node.name,
                    "args": args,
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                }
            )
            logger.debug(
                "content_manifest: Python function %s(%s)",
                node.name,
                ", ".join(args),
                extra={
                    "event": "content_manifest.element",
                    "type": "function",
                    "element_name": node.name,
                },
            )

        elif isinstance(node, ast.ClassDef):
            methods = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.append(item.name)
            class_signatures.append(
                {
                    "name": node.name,
                    "methods": methods,
                }
            )
            logger.debug(
                "content_manifest: Python class %s with %d methods",
                node.name,
                len(methods),
                extra={
                    "event": "content_manifest.element",
                    "type": "class",
                    "element_name": node.name,
                },
            )

    # CLI argument detection
    if "argparse" in content or "sys.argv" in content:
        cli_args = True
        logger.debug(
            "content_manifest: Python CLI args detected",
            extra={"event": "content_manifest.behaviour", "type": "cli_args"},
        )

    manifest = {
        "language": "python",
        "entry_points": entry_points,
        "class_signatures": class_signatures,
        "cli_args": cli_args,
    }

    logger.debug(
        "content_manifest: Python complete — %d functions, %d classes, cli_args=%s",
        len(entry_points),
        len(class_signatures),
        cli_args,
        extra={
            "event": "content_manifest.python",
            "function_count": len(entry_points),
            "class_count": len(class_signatures),
            "cli_args": cli_args,
        },
    )

    return manifest


# -- Helpers ------------------------------------------------------------------


def _guess_language(filename: str) -> str:
    """Guess language from filename extension."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return {
        "html": "html",
        "htm": "html",
        "js": "javascript",
        "mjs": "javascript",
        "py": "python",
        "css": "css",
        "sh": "shell",
        "bash": "shell",
        "rs": "rust",
        "txt": "text",
    }.get(ext, "")


@no_audit_log
def _empty_manifest(lang: str) -> dict:
    """Return an empty manifest for a given language."""
    if lang in ("html", "htm"):
        logger.debug(
            "content_manifest: empty manifest for html",
            extra={"event": "content_manifest.empty_manifest", "resolved_lang": "html"},
        )
        return {
            "language": "html",
            "body_styles": {},
            "elements": [],
            "panel_count": 0,
            "script_refs": [],
            "element_count": 0,
        }
    if lang in ("javascript", "js", "mjs"):
        logger.debug(
            "content_manifest: empty manifest for javascript",
            extra={
                "event": "content_manifest.empty_manifest",
                "resolved_lang": "javascript",
            },
        )
        return {
            "language": "javascript",
            "behaviours": [],
            "dom_updates": [],
            "timer_intervals": [],
        }
    if lang in ("python", "py"):
        logger.debug(
            "content_manifest: empty manifest for python",
            extra={
                "event": "content_manifest.empty_manifest",
                "resolved_lang": "python",
            },
        )
        return {
            "language": "python",
            "entry_points": [],
            "class_signatures": [],
            "cli_args": False,
        }
    if lang == "css":
        logger.debug(
            "content_manifest: empty manifest for css",
            extra={"event": "content_manifest.empty_manifest", "resolved_lang": "css"},
        )
        return {
            "language": "css",
            "element_styles": {},
            "colour_palette": [],
            "layout_rules": [],
        }
    logger.debug(
        "content_manifest: empty manifest for unknown lang=%s",
        lang or "unknown",
        extra={
            "event": "content_manifest.empty_manifest",
            "resolved_lang": lang or "unknown",
        },
    )
    return {"language": lang or "unknown"}
