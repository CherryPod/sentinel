"""Composable prompt assembly for the planner.

Public API
----------
assemble_system_prompt(sections, *, tool_descriptions="") -> str
    Join prompt sections and fill runtime placeholders.
"""

from __future__ import annotations


def assemble_system_prompt(
    sections: list[str],
    *,
    tool_descriptions: str = "",
) -> str:
    """Join prompt sections and fill runtime placeholders.

    Parameters
    ----------
    sections:
        Ordered list of prompt section strings (each an XML-tagged block).
    tool_descriptions:
        Runtime tool description text to substitute into the ``{tool_descriptions}``
        placeholder in the ``<tools>`` section.

    Returns
    -------
    str
        The assembled system prompt, ready to send to the planner LLM.
    """
    joined = "\n\n".join(sections)
    # Always substitute — empty string is a valid replacement (no tools available)
    joined = joined.replace("{tool_descriptions}", tool_descriptions)
    return joined
