"""YAML repair module.

Fix YAML indentation issues (tabs, inconsistent indent) and validate.
"""
import logging

import yaml

from ._core import FixResult, _current_filename

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Layer 3: YAML repair
# ---------------------------------------------------------------------------

def fix_yaml(content: str) -> FixResult:
    """Fix YAML indentation issues and validate.

    v1: Tab -> 2 spaces (YAML spec forbids tabs for indentation)
    v2: Normalize inconsistent indentation (4-space) to 2 spaces

    Known constraint (Finding #18): tab-to-space replacement operates on
    the entire file, including inside string values. The YAML spec forbids
    tabs for indentation, so this is correct for structure. However, if a
    multi-line string value contains literal tabs, they will also be
    converted. This is an accepted edge case — LLM-generated YAML rarely
    contains intentional tabs inside string values.
    """
    result = FixResult(content=content)
    original = content

    # Tab -> 2 spaces (safe — YAML spec forbids tabs)
    if "\t" in content:
        content = content.replace("\t", "  ")
        result.fixes_applied.append("Tabs -> spaces in YAML")

    # v2: Normalize 4-space indentation to 2-space (YAML convention).
    # Detect the indent unit: if the smallest non-zero indent is exactly
    # 4 spaces, the file uses 4-space indentation. If it's 2, leave it alone.
    lines = content.split("\n")
    indent_sizes: set[int] = set()
    for line in lines:
        if line.strip() and line != line.lstrip():
            leading = len(line) - len(line.lstrip())
            indent_sizes.add(leading)

    min_indent = min(indent_sizes) if indent_sizes else 0

    # Finding #8: only normalise when smallest indent is exactly 4.
    # The old code used `min_indent >= 4 and min_indent % 4 == 0` which
    # also matched 8, 12, etc. and could halve indentation incorrectly.
    if min_indent == 4:
        normalized_lines = []
        for line in lines:
            if line and not line.lstrip().startswith("#"):
                leading = len(line) - len(line.lstrip())
                if leading > 0 and leading % 2 == 0:
                    normalized_lines.append(
                        " " * (leading // 2) + line.lstrip()
                    )
                else:
                    normalized_lines.append(line)
            else:
                normalized_lines.append(line)
        candidate = "\n".join(normalized_lines)
        try:
            yaml.safe_load(candidate)
            content = candidate
            result.fixes_applied.append(
                "Normalized 4-space indent -> 2-space (YAML convention)"
            )
        except yaml.YAMLError:
            pass  # normalization broke it — revert

    # Final validation
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        result.errors_found.append(f"YAMLError: {e}")

    result.content = content
    result.changed = content != original

    if result.changed:
        logger.debug(
            "YAML fixes applied",
            extra={
                "event": "fixer_applied",
                "fixer": "fix_yaml",
                "file": _current_filename.get(),
                "fix_description": ", ".join(result.fixes_applied),
                "len_before": len(original),
                "len_after": len(content),
            },
        )

    return result
