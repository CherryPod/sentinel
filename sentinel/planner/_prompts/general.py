"""General planner prompt — assembles all sections in standard order."""

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

# Section order matches the original inline _PLANNER_SYSTEM_PROMPT_TEMPLATE.
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
