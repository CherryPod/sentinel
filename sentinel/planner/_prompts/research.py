"""Research planner prompt — core sections plus research-specific guidance.

This is a stub that validates the infrastructure can produce prompt variants.
The research-specific cognitive guidance sections will be added when research
mode is implemented.
"""

from sentinel.planner._prompts._sections import (
    constraints,
    debugging,
    episodic_learning,
    examples,
    media_attachments,
    output_schema,
    plan_rules,
    role,
    security_rules,
    tool_selection,
    tools,
    worker_llm,
)

# Same as general for now. When research mode is built, insert
# research-specific thinking/reasoning sections here (e.g. between
# plan_rules and media_attachments, or after debugging).
SECTIONS: list[str] = [
    role.SECTION,
    security_rules.SECTION,
    output_schema.SECTION,
    worker_llm.SECTION,
    tool_selection.SECTION,
    plan_rules.SECTION,
    media_attachments.SECTION,
    examples.SECTION,
    tools.SECTION,
    constraints.SECTION,
    episodic_learning.SECTION,
    debugging.SECTION,
]
