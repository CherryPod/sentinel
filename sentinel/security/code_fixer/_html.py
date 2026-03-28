"""HTML structural repair for the code_fixer package.

Contains: fix_html, decomposed into named helpers per Finding #40.

Finding fixes applied:
  #11: _encode_entities uses re.search(r'<script[\\s>]') instead of f"<script" in
  #22: attribute quote alternating segments documented as known constraint
  #40: decomposed into _fix_doctype, _balance_tags, _normalise_attributes,
       _encode_entities, _check_accessibility
  #50: _SKIP_ENTITY_TAGS moved to module-level constant
  #53: recursion depth cap documented
  #56: recursive calls merge errors_found and warnings (not just fixes_applied)
"""
import logging
import re

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_HTML_VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})

# Finding #53: recursion depth cap — prevents infinite loops on pathological
# input where misnested tag repair keeps producing new mismatches.
# 10 is generous; real-world LLM output rarely needs more than 2-3 passes.
_HTML_MAX_RECURSION = 10

# Finding #50: moved to module-level constant (was inline in fix_html)
_SKIP_ENTITY_TAGS = frozenset({"script", "style", "pre", "code", "textarea"})


# ---------------------------------------------------------------------------
# Helper: DOCTYPE insertion
# ---------------------------------------------------------------------------
def _fix_doctype(content: str, result: FixResult) -> str:
    """Add <!DOCTYPE html> if <html> tag is present but no doctype."""
    stripped = content.lstrip()
    if ("<html" in stripped.lower()
            and not stripped.lower().startswith("<!doctype")):
        content = "<!DOCTYPE html>\n" + content
        result.fixes_applied.append("Added <!DOCTYPE html>")
        logger.debug(
            "Added missing DOCTYPE",
            extra={
                "event": "html_doctype_added",
                "file": _current_filename.get(),
            },
        )
    return content


# ---------------------------------------------------------------------------
# Helper: Tag balancing (stack-based)
# ---------------------------------------------------------------------------
def _balance_tags(
    content: str, result: FixResult, _depth: int = 0
) -> tuple[str, bool]:
    """Track and fix unclosed/misnested tags.

    Returns (content, needs_rerun) — if misnested tags were fixed by
    inserting closing tags, positions shift and the caller should re-run
    with incremented depth.

    Uses stack-based tag tracking:
    - Void elements (br, img, input, etc.) are never pushed to the stack
    - Self-closing tags (/>) are ignored
    - Misnested tags trigger insertion of closing tags at the correct position
    - Unclosed tags at EOF get closing tags appended
    """
    # WONTFIX (audit #21): This regex terminates at the first > character,
    # so attributes containing > (e.g. data-value="a>b") will truncate the
    # tag match. This is a fundamental limitation of regex-based HTML parsing.
    # A proper fix requires html.parser, which is overkill for this module's
    # use case — LLM-generated HTML rarely contains > in attribute values.
    tag_pattern = re.compile(r"<(/?)(\w+)([^>]*?)(/?)>")
    stack: list[tuple[str, int]] = []  # (tag_name, match_end_position)

    for m in tag_pattern.finditer(content):
        is_closing = m.group(1) == "/"
        tag_name = m.group(2).lower()
        is_self_closing = m.group(4) == "/"

        if tag_name in _HTML_VOID_ELEMENTS or is_self_closing:
            continue

        if is_closing:
            if stack and stack[-1][0] == tag_name:
                stack.pop()
            elif any(t[0] == tag_name for t in stack):
                # Misnested: close intermediate tags before this closer
                unclosed = []
                while stack and stack[-1][0] != tag_name:
                    unclosed.append(stack.pop()[0])
                if stack:
                    stack.pop()
                if unclosed:
                    insert_pos = m.start()
                    closing_str = "".join(f"</{t}>" for t in unclosed)
                    content = (
                        content[:insert_pos] + closing_str + content[insert_pos:]
                    )
                    result.fixes_applied.append(
                        f"Auto-closed {len(unclosed)} misnested tag(s): "
                        f"{', '.join(unclosed)}"
                    )
                    logger.debug(
                        "Auto-closed %d misnested tags",
                        len(unclosed),
                        extra={
                            "event": "html_misnested_fixed",
                            "file": _current_filename.get(),
                            "tags": unclosed,
                        },
                    )
                    # Positions shifted — signal caller to re-run
                    return content, True
        else:
            stack.append((tag_name, m.end()))

    # Close remaining unclosed tags at end of document
    if stack:
        tag_names = [t[0] for t in stack]
        closing_tags = "".join(f"</{tag}>" for tag in reversed(tag_names))
        content = content.rstrip("\n") + "\n" + closing_tags + "\n"
        result.fixes_applied.append(
            f"Closed {len(stack)} unclosed tag(s): "
            f"{', '.join(reversed(tag_names))}"
        )
        logger.debug(
            "Closed %d unclosed tags at EOF",
            len(stack),
            extra={
                "event": "html_unclosed_tags_fixed",
                "file": _current_filename.get(),
                "tags": tag_names,
            },
        )

    return content, False


# ---------------------------------------------------------------------------
# Helper: Attribute normalisation
# ---------------------------------------------------------------------------
def _normalise_attributes(content: str, result: FixResult) -> str:
    """Quote bare attributes, fix mixed quote pairs. Skip template files.

    Finding #22: The alternating-segment approach (splitting into quoted vs
    unquoted segments) is a known constraint — it handles most cases but
    cannot perfectly distinguish attribute boundaries when quotes alternate
    between single and double in complex patterns.  This is acceptable for
    LLM output which rarely produces such edge cases.
    """
    # Skip template files (Jinja2, Django, ERB) — template syntax looks like
    # unquoted attributes and would be corrupted by quoting
    has_templates = "{{" in content or "{%" in content or "<%" in content
    if has_templates:
        return content

    pre_attr = content

    def _quote_attr(m: re.Match) -> str:
        """Wrap bare attribute values in double quotes."""
        attr_name = m.group(1)
        value = m.group(2)
        return f'{attr_name}="{value}"'

    def _fix_tag_attrs(tag_match: re.Match) -> str:
        """Find unquoted attribute values within a single tag.

        Splits the tag into quoted and unquoted segments first,
        then only applies the quoting fix to unquoted segments.
        This prevents corrupting values inside already-quoted
        attributes (e.g. content="width=device-width, ...").

        Finding #22: the alternating-segment split is a known constraint
        documented above.
        """
        tag_content = tag_match.group(0)
        # Split into segments: quoted strings vs everything else
        # This preserves content="width=device-width" as-is
        segments = re.split(r'''("[^"]*"|'[^']*')''', tag_content)
        result_parts = []
        for i, seg in enumerate(segments):
            if i % 2 == 1:
                # Quoted segment — leave untouched
                result_parts.append(seg)
            else:
                # Unquoted segment — fix bare attribute values
                result_parts.append(
                    re.sub(
                        r'(\w+)=([^\s"\'<>=]+)(?=[\s>/>])',
                        _quote_attr,
                        seg,
                    )
                )
        return "".join(result_parts)

    content = re.sub(r'<[a-zA-Z][^>]*>', _fix_tag_attrs, content)

    def _fix_tag_mixed_quotes(tag_match: re.Match) -> str:
        """Fix mismatched quote pairs (opening single, closing double
        or vice versa)."""
        tag_content = tag_match.group(0)
        return re.sub(
            r"""(\w+)='([^']*?)"|(\w+)="([^"]*?)'""",
            lambda m: (
                f'{m.group(1) or m.group(3)}="{m.group(2) or m.group(4)}"'
            ),
            tag_content,
        )

    content = re.sub(r'<[a-zA-Z][^>]*>', _fix_tag_mixed_quotes, content)

    if content != pre_attr:
        result.fixes_applied.append(
            "Normalised attribute quotes to double-quoted"
        )
        logger.debug(
            "Normalised HTML attribute quotes",
            extra={
                "event": "html_attributes_normalised",
                "file": _current_filename.get(),
            },
        )

    return content


# ---------------------------------------------------------------------------
# Helper: Entity encoding
# ---------------------------------------------------------------------------
def _encode_entities(content: str, result: FixResult) -> str:
    """Encode bare & and < in text content.

    Only encodes bare & and < in text nodes — skips tags, attributes,
    and content inside script/style/pre/code/textarea blocks.

    Finding #11: uses re.search(r'<script[\\s>]') instead of
    f"<script" in line_lower, which could false-positive on attribute
    values like data-script="...".
    """
    in_skip_tag = None
    entity_lines = content.split("\n")
    entity_fixed = False

    for i, line in enumerate(entity_lines):
        line_lower = line.lower()
        for tag in _SKIP_ENTITY_TAGS:
            # Check close before open — handles same-line open+close correctly
            if f"</{tag}" in line_lower:
                in_skip_tag = None
            # Finding #11: use regex with tag boundary check instead of
            # bare substring match, to avoid matching things like
            # data-script-name="..." or <scriptalert>
            if (re.search(rf'<{tag}[\s>]', line_lower)
                    and f"</{tag}" not in line_lower):
                # Only enter skip mode if the tag opens but doesn't close
                # on this line
                in_skip_tag = tag

        if in_skip_tag:
            continue

        # Split line into tag and non-tag segments, only fix non-tag segments
        # Use [a-zA-Z/] after < to only match real HTML tags, not bare < in text
        parts = re.split(r'(<[a-zA-Z/][^>]*>)', line)
        line_changed = False
        # Track skip-tag state within a single line (handles inline
        # <script>...</script>)
        inline_skip = False
        for j, part in enumerate(parts):
            if part.startswith("<"):
                part_lower = part.lower()
                for tag in _SKIP_ENTITY_TAGS:
                    # Finding #11: tag boundary check for inline skip tracking
                    if re.match(rf'<{tag}[\s>]', part_lower):
                        inline_skip = True
                    elif part_lower == f"</{tag}>":
                        inline_skip = False
                continue
            if inline_skip:
                continue
            original_part = part
            # Encode bare ampersands (not already part of an entity reference)
            part = re.sub(
                r'&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[\da-fA-F]+);)',
                '&amp;',
                part,
            )
            # Encode < that isn't a tag start (followed by space, digit, or =)
            part = re.sub(r'<(?=[\s\d=])', '&lt;', part)
            if part != original_part:
                parts[j] = part
                line_changed = True
        if line_changed:
            entity_lines[i] = "".join(parts)
            entity_fixed = True

    if entity_fixed:
        content = "\n".join(entity_lines)
        result.fixes_applied.append(
            "Encoded bare HTML entities in text content"
        )
        logger.debug(
            "Encoded bare HTML entities",
            extra={
                "event": "html_entities_encoded",
                "file": _current_filename.get(),
            },
        )

    return content


# ---------------------------------------------------------------------------
# Helper: Accessibility warnings (non-blocking)
# ---------------------------------------------------------------------------
def _check_accessibility(content: str, result: FixResult) -> None:
    """Non-blocking warnings: missing lang attribute, missing charset."""
    if re.search(r"<html\s*>", content, re.IGNORECASE):
        result.warnings.append(
            '<html> missing lang attribute (e.g. <html lang="en">)'
        )
    if "<head" in content.lower() and "charset" not in content.lower():
        result.warnings.append("Missing charset meta tag in <head>")


# ---------------------------------------------------------------------------
# Public entry point (Finding #40: decomposed orchestrator)
# ---------------------------------------------------------------------------
def fix_html(content: str, _depth: int = 0) -> FixResult:
    """HTML fixes: unclosed tags, missing doctype, common LLM HTML errors.

    Orchestrates all sub-fixers in order:
    1. DOCTYPE insertion
    2. Tag balancing (stack-based, recursive on misnest)
    3. Attribute quote normalisation
    4. Entity encoding in text nodes
    5. Accessibility warnings (non-blocking)

    The _depth parameter is for internal recursive calls when misnested
    tag repair shifts positions and requires a re-parse.
    """
    result = FixResult(content=content)
    original = content

    # Finding #53: recursion guard for pathological input — documented at
    # _HTML_MAX_RECURSION.  Real-world LLM output rarely needs > 2-3 passes.
    if _depth > _HTML_MAX_RECURSION:
        result.warnings.append("HTML tag repair hit recursion limit")
        return result

    logger.debug(
        "HTML fixer starting (depth=%d)",
        _depth,
        extra={
            "event": "html_fixer_start",
            "file": _current_filename.get(),
            "content_length": len(content),
            "depth": _depth,
        },
    )

    # Step 1: DOCTYPE
    content = _fix_doctype(content, result)

    # Step 2: Tag balancing (may trigger re-run via recursion)
    content, needs_rerun = _balance_tags(content, result, _depth)
    if needs_rerun:
        inner = fix_html(content, _depth + 1)
        inner.changed = True
        inner.fixes_applied = result.fixes_applied + inner.fixes_applied
        # Finding #56: merge errors_found and warnings from recursive calls
        # (the original only merged fixes_applied)
        inner.errors_found = result.errors_found + inner.errors_found
        inner.warnings = result.warnings + inner.warnings
        return inner

    # Step 3: Attribute normalisation
    content = _normalise_attributes(content, result)

    # Step 4: Entity encoding
    content = _encode_entities(content, result)

    # Step 5: Accessibility warnings
    _check_accessibility(content, result)

    result.content = content
    result.changed = content != original
    return result
