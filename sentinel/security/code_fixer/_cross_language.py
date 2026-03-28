"""Cross-language content detection and repair for the code_fixer package.

Detects and fixes content placed outside its proper container:
- CSS outside <style> tags in HTML/SVG files
- JS outside <script> tags in HTML/SVG files
- <style> wrapper tags in .css files (LLM wraps CSS in HTML tags)
- <script> wrapper tags in .js/.ts files (LLM wraps JS in HTML tags)

Runs as a post-chain step in fix_code() — after language-specific fixers
but before truncation/duplicate detection.
"""
import logging
import re
from pathlib import Path

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)


# ── File type groupings ─────────────────────────────────────────────────

_HTML_LIKE_EXTS = frozenset({".html", ".htm", ".svg"})
_CSS_EXTS = frozenset({".css"})
_JS_EXTS = frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"})


# ── CSS wrapper stripping (.css files) ──────────────────────────────────

def _fix_css_wrapper_tags(content: str) -> FixResult:
    """Strip <style>...</style> wrapper from .css file content.

    LLMs sometimes wrap CSS content in <style> tags when writing to a .css
    file, confusing "CSS for an HTML file" with "CSS file content".
    """
    result = FixResult(content=content)
    fname = _current_filename.get()

    stripped = content.strip()

    # Check for <style> at start (with optional attributes)
    open_match = re.match(r"^<style[^>]*>\s*\n?", stripped, re.IGNORECASE)
    if not open_match:
        logger.debug(
            "cross_language: no <style> wrapper in CSS file",
            extra={"event": "cross_lang_css_no_wrapper", "file": fname},
        )
        return result

    # Check for </style> at end
    close_match = re.search(r"\n?\s*</style>\s*$", stripped, re.IGNORECASE)
    if not close_match:
        logger.debug(
            "cross_language: <style> open but no close in CSS file",
            extra={"event": "cross_lang_css_partial_wrapper", "file": fname},
        )
        result.warnings.append(
            "CSS file starts with <style> but has no </style>"
        )
        return result

    # Strip the wrapper tags, preserve the inner content
    inner = stripped[open_match.end():close_match.start()]
    result.content = inner.strip() + "\n"

    result.changed = result.content != content
    if result.changed:
        result.fixes_applied.append("Stripped <style> wrapper from CSS file")
        logger.debug(
            "cross_language: stripped <style> wrapper from CSS file",
            extra={"event": "cross_lang_css_wrapper_stripped", "file": fname},
        )

    return result


# ── JS/TS wrapper stripping (.js/.ts files) ─────────────────────────────

def _fix_js_wrapper_tags(content: str) -> FixResult:
    """Strip <script>...</script> wrapper from .js/.ts file content.

    LLMs sometimes wrap JS content in <script> tags when writing to a .js
    file, confusing "JS for an HTML file" with "JS file content".
    """
    result = FixResult(content=content)
    fname = _current_filename.get()

    stripped = content.strip()

    open_match = re.match(r"^<script[^>]*>\s*\n?", stripped, re.IGNORECASE)
    if not open_match:
        logger.debug(
            "cross_language: no <script> wrapper in JS file",
            extra={"event": "cross_lang_js_no_wrapper", "file": fname},
        )
        return result

    close_match = re.search(r"\n?\s*</script>\s*$", stripped, re.IGNORECASE)
    if not close_match:
        logger.debug(
            "cross_language: <script> open but no close in JS file",
            extra={"event": "cross_lang_js_partial_wrapper", "file": fname},
        )
        result.warnings.append(
            "JS file starts with <script> but has no </script>"
        )
        return result

    inner = stripped[open_match.end():close_match.start()]
    result.content = inner.strip() + "\n"

    result.changed = result.content != content
    if result.changed:
        result.fixes_applied.append("Stripped <script> wrapper from JS file")
        logger.debug(
            "cross_language: stripped <script> wrapper from JS file",
            extra={"event": "cross_lang_js_wrapper_stripped", "file": fname},
        )

    return result


# ── CSS detection patterns (for HTML/SVG text nodes) ────────────────────

# Selector followed by opening brace: .class {, #id {, tag {
_CSS_SELECTOR_RE = re.compile(
    r"^\s*"
    r"(?:"
    r"[.#][\w-]+"                          # .class or #id
    r"|[\w*][\w-]*"                        # tag name or *
    r")"
    r"(?:\s*[>+~,]\s*[\w.#*][\w-]*)*"     # optional combinators
    r"(?:[\s.#:\[\]='\"-][\w-]*)*"         # pseudo-classes, attribute selectors
    r"\s*\{"
)

# CSS property: value; pattern
_CSS_PROPERTY_RE = re.compile(r"^\s*[\w-]+\s*:\s*[^;]+;\s*$")

# CSS at-rules
_CSS_AT_RULE_RE = re.compile(
    r"^\s*@(?:media|keyframes|import|font-face|charset|supports|layer|namespace)\b"
)


# ── JS detection patterns (for HTML/SVG text nodes) ─────────────────────

# Function/variable/class declarations
_JS_DECL_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?:function|class)\s+\w+"
    r"|^\s*(?:const|let|var)\s+\w+\s*="
)

# DOM API access
_JS_DOM_RE = re.compile(
    r"(?:document|window)\s*\.\s*"
    r"(?:getElementById|querySelector|querySelectorAll|createElement"
    r"|addEventListener|removeEventListener|location|onload|onready"
    r"|appendChild|removeChild|textContent|innerHTML|getElement)"
)

# addEventListener standalone
_JS_LISTENER_RE = re.compile(r"\.addEventListener\s*\(")


# ── Protected tag tracking ──────────────────────────────────────────────

_PROTECTED_TAGS = ("style", "script", "pre", "code", "textarea")

_OPEN_TAG_RES = {
    tag: re.compile(rf"<{tag}[\s>]", re.IGNORECASE)
    for tag in _PROTECTED_TAGS
}
_CLOSE_TAG_RES = {
    tag: re.compile(rf"</{tag}\s*>", re.IGNORECASE)
    for tag in _PROTECTED_TAGS
}


def _is_css_line(line: str) -> bool:
    """Check if a line looks like CSS content."""
    stripped = line.strip()
    if not stripped or stripped.startswith("<") or stripped.startswith("//"):
        return False
    return bool(
        _CSS_SELECTOR_RE.match(stripped)
        or _CSS_PROPERTY_RE.match(stripped)
        or _CSS_AT_RULE_RE.match(stripped)
    )


def _is_js_line(line: str) -> bool:
    """Check if a line looks like JS content."""
    stripped = line.strip()
    if not stripped or stripped.startswith("<"):
        return False
    return bool(
        _JS_DECL_RE.match(stripped)
        or _JS_DOM_RE.search(stripped)
        or _JS_LISTENER_RE.search(stripped)
    )


def _fix_html_misplaced_content(content: str) -> FixResult:
    """Detect and wrap CSS/JS content outside container tags in HTML/SVG.

    Uses a state machine to track protected zones (<style>, <script>, <pre>,
    <code>, <textarea>), then classifies lines outside those zones as CSS
    or JS using regex patterns. Contiguous blocks of >= 2 classified lines
    are wrapped in the appropriate container tag.

    Skips template files (Jinja2, Django, ERB) to avoid corrupting template
    syntax that looks like code.
    """
    result = FixResult(content=content)
    fname = _current_filename.get()

    # Skip template files
    if "{{" in content or "{%" in content or "<%" in content:
        logger.debug(
            "cross_language: skipping template file",
            extra={"event": "cross_lang_skip_template", "file": fname},
        )
        return result

    lines = content.split("\n")
    in_protected: str | None = None

    # Phase 1: Identify misplaced content blocks
    # Each block: {start: line_idx, end: line_idx, type: 'css'|'js'}
    blocks: list[dict] = []
    current_block: dict | None = None

    for i, line in enumerate(lines):
        # Track protected zone transitions
        if in_protected:
            if _CLOSE_TAG_RES[in_protected].search(line):
                in_protected = None
            if current_block:
                blocks.append(current_block)
                current_block = None
            continue

        # Check if entering a protected zone
        entered = False
        for tag in _PROTECTED_TAGS:
            if _OPEN_TAG_RES[tag].search(line):
                if not _CLOSE_TAG_RES[tag].search(line):
                    # Multi-line protected zone
                    in_protected = tag
                entered = True
                break

        if entered:
            if current_block:
                blocks.append(current_block)
                current_block = None
            continue

        # Skip lines that are HTML tags
        if line.strip().startswith("<"):
            if current_block:
                blocks.append(current_block)
                current_block = None
            continue

        # Classify this line
        is_css = _is_css_line(line)
        is_js = _is_js_line(line)
        lang = "css" if is_css else ("js" if is_js else None)

        if lang:
            if current_block and current_block["type"] == lang:
                current_block["end"] = i
            else:
                if current_block:
                    blocks.append(current_block)
                current_block = {"start": i, "end": i, "type": lang}
        elif not line.strip() and current_block:
            # Blank line inside a block — extend (CSS/JS blocks have blanks)
            current_block["end"] = i
        else:
            if current_block:
                blocks.append(current_block)
                current_block = None

    if current_block:
        blocks.append(current_block)

    # Filter: require >= 2 classified lines to avoid false positives
    def _count_classified(block: dict) -> int:
        count = 0
        for j in range(block["start"], block["end"] + 1):
            bline = lines[j]
            if block["type"] == "css" and _is_css_line(bline):
                count += 1
            elif block["type"] == "js" and _is_js_line(bline):
                count += 1
        return count

    significant = [b for b in blocks if _count_classified(b) >= 2]

    if not significant:
        logger.debug(
            "cross_language: no misplaced content in HTML",
            extra={"event": "cross_lang_html_clean", "file": fname},
        )
        return result

    # Phase 2: Wrap misplaced blocks (work backwards to preserve positions)
    for block in reversed(significant):
        tag = "style" if block["type"] == "css" else "script"
        start = block["start"]
        end = block["end"]

        # Trim trailing blank lines from the block
        while end > start and not lines[end].strip():
            end -= 1

        # Get indentation from the first content line
        indent = re.match(r"^\s*", lines[start]).group()

        lines.insert(end + 1, f"{indent}</{tag}>")
        lines.insert(start, f"{indent}<{tag}>")

        result.fixes_applied.append(
            f"Wrapped misplaced {block['type'].upper()} content "
            f"in <{tag}> (lines {start + 1}-{end + 1})"
        )
        logger.debug(
            "cross_language: wrapped misplaced %s in <%s>",
            block["type"],
            tag,
            extra={
                "event": "cross_lang_html_wrapped",
                "file": fname,
                "type": block["type"],
                "tag": tag,
                "start_line": start + 1,
                "end_line": end + 1,
            },
        )

    result.content = "\n".join(lines)
    result.changed = result.content != content
    return result


# ── Entry point ─────────────────────────────────────────────────────────

def fix_cross_language(content: str) -> FixResult:
    """Detect and fix cross-language content issues.

    Reads _current_filename to determine file type and applies the
    appropriate checks. Safe to call on any file type — returns
    unchanged content for unsupported types.
    """
    fname = _current_filename.get()
    ext = Path(fname).suffix.lower()

    logger.debug(
        "cross_language: checking file",
        extra={"event": "cross_lang_check", "file": fname, "ext": ext},
    )

    if ext in _HTML_LIKE_EXTS:
        return _fix_html_misplaced_content(content)
    elif ext in _CSS_EXTS:
        return _fix_css_wrapper_tags(content)
    elif ext in _JS_EXTS:
        return _fix_js_wrapper_tags(content)

    logger.debug(
        "cross_language: no checks for extension",
        extra={"event": "cross_lang_skip", "file": fname, "ext": ext},
    )
    return FixResult(content=content)
