"""JSON repair module.

Fix common LLM JSON errors: Python booleans, single quotes, trailing commas,
NaN/Infinity. Uses json-repair library when available, with regex fallback.
"""
import json
import logging
import re

from ._core import CharContext, FixResult, _current_filename, _iter_code_chars

logger = logging.getLogger(__name__)

# Optional dependency — robust JSON fixer
try:
    from json_repair import repair_json as _json_repair  # type: ignore[import-untyped]
except ImportError:
    _json_repair = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Context-aware replacement helper
# ---------------------------------------------------------------------------

def _replace_outside_strings(
    content: str, replacements: list[tuple[str, str]]
) -> str:
    """Replace patterns only in CODE context (outside JSON strings).

    Finding #2 (HIGH), #7, #30: boolean/NaN/Infinity replacement and
    quote normalisation must not modify values inside JSON strings.

    Rebuilds string_positions after each replacement pattern to avoid
    stale positions when replacements change content length.
    """
    result = content
    for pattern, replacement in replacements:
        # Rebuild string positions for current content state
        string_positions: set[int] = set()
        for idx, _, ctx in _iter_code_chars(result, "json"):
            if ctx == CharContext.STRING:
                string_positions.add(idx)

        # Apply in reverse order to preserve positions within this pattern
        for m in reversed(list(re.finditer(r"\b" + re.escape(pattern) + r"\b", result))):
            if any(pos in string_positions for pos in range(m.start(), m.end())):
                continue
            result = result[: m.start()] + replacement + result[m.end() :]
    return result


# ---------------------------------------------------------------------------
# Layer 3: JSON repair
# ---------------------------------------------------------------------------

def fix_json(content: str) -> FixResult:
    """Fix common LLM JSON errors using json-repair (v2) with regex fallback.

    Conservative approach:
    - Try parsing first — if valid, return immediately
    - Try json-repair library if available (handles nested brackets, NaN, etc.)
    - Fall back to regex-based fixes (Python bools, single quotes, trailing commas)
    """
    result = FixResult(content=content)
    original = content

    # Check for non-standard tokens Python json accepts but JSON spec forbids.
    # NaN/Infinity pass json.loads() but aren't valid JSON — fix them.
    # Finding #30: only detect outside strings (handled by _replace_outside_strings below)
    _has_nonstandard = bool(re.search(r"\bNaN\b|\bInfinity\b", content))

    # Already valid strict JSON? Skip entirely.
    if not _has_nonstandard:
        try:
            json.loads(content)
            return result
        except json.JSONDecodeError:
            pass

    # Finding #2 (HIGH): Python booleans -> JSON booleans, NaN/Infinity -> null.
    # Uses context-aware replacement to skip values inside JSON strings.
    # json-repair doesn't know Python's True/False/None — it treats None
    # as a string "None". Do this substitution before json-repair.
    content = _replace_outside_strings(content, [
        ("True", "true"),
        ("False", "false"),
        ("None", "null"),
        ("NaN", "null"),
        ("Infinity", "null"),
        ("-Infinity", "null"),
    ])
    if content != original:
        result.fixes_applied.append("Python bools/None/NaN -> JSON")

    # Valid after bool fix? Return early.
    try:
        json.loads(content)
        result.content = content
        result.changed = content != original
        if result.changed:
            logger.debug(
                "JSON fixes applied (bool/None/NaN conversion)",
                extra={
                    "event": "fixer_applied",
                    "fixer": "fix_json",
                    "file": _current_filename.get(),
                    "fix_description": ", ".join(result.fixes_applied),
                },
            )
        return result
    except json.JSONDecodeError:
        pass

    # v2: Try json-repair library (handles nested brackets, NaN, etc.)
    if _json_repair is not None:
        try:
            repaired = _json_repair(content)
            if isinstance(repaired, str) and repaired != content:
                # json-repair may strip trailing newline — preserve it
                if original.endswith("\n") and not repaired.endswith("\n"):
                    repaired += "\n"
                try:
                    json.loads(repaired.rstrip())
                    content = repaired
                    result.fixes_applied.append("json-repair: fixed malformed JSON")
                    result.content = content
                    result.changed = True
                    logger.debug(
                        "JSON fixed by json-repair library",
                        extra={
                            "event": "fixer_applied",
                            "fixer": "fix_json",
                            "file": _current_filename.get(),
                            "fix_description": "json-repair: fixed malformed JSON",
                        },
                    )
                    return result
                except json.JSONDecodeError:
                    pass  # json-repair output still invalid — fall through to regex
        except Exception as exc:
            # Finding #36: log instead of silently swallowing
            logger.warning(
                "json-repair library crashed, falling through to regex",
                extra={
                    "event": "validation_rejected",
                    "fixer": "fix_json",
                    "file": _current_filename.get(),
                    "validator": "json_repair",
                    "error_summary": str(exc),
                },
            )

    # Regex fallback (v1 approach) — Python bools already handled above.
    # Finding #7: Single quotes -> double quotes — only outside existing strings.
    # ONLY if there are zero double quotes (avoids mangling mixed strings).
    # Validate with json.loads after replacement — revert if it produced
    # invalid JSON (e.g. escaped apostrophes like "it's" get corrupted).
    if "'" in content and '"' not in content:
        candidate = content.replace("'", '"')
        try:
            json.loads(candidate)
            content = candidate
            result.fixes_applied.append("Single quotes -> double quotes")
        except json.JSONDecodeError:
            pass  # replacement produced invalid JSON — skip

    # Trailing commas before } or ]
    before_comma = content
    content = re.sub(r",\s*([}\]])", r"\1", content)
    if content != before_comma:
        result.fixes_applied.append("Removed trailing commas")

    # Validate after fixes
    try:
        json.loads(content)
    except json.JSONDecodeError as e:
        result.errors_found.append(f"JSONDecodeError after repair: {e}")

    result.content = content
    result.changed = content != original

    if result.changed:
        logger.debug(
            "JSON fixes applied (regex fallback)",
            extra={
                "event": "fixer_applied",
                "fixer": "fix_json",
                "file": _current_filename.get(),
                "fix_description": ", ".join(result.fixes_applied),
            },
        )

    return result
