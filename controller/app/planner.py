import json
import logging

import anthropic

from .config import settings
from .models import Plan, PlanStep

logger = logging.getLogger("sentinel.audit")

_PLANNER_SYSTEM_PROMPT_TEMPLATE = """\
You are a task planner for a secure execution system. Given a user request, \
produce a JSON execution plan.

Respond ONLY with a JSON object (no markdown, no commentary) matching this schema:
{{
  "plan_summary": "Brief description of what the plan does",
  "steps": [
    {{
      "id": "step_1",
      "type": "llm_task",
      "description": "What this step does",
      "prompt": "The prompt to send to the LLM worker",
      "output_var": "$result_name",
      "expects_code": false,
      "input_vars": []
    }}
  ]
}}

Step types:
- "llm_task": Send a prompt to the text-processing LLM. Use "prompt" field.
- "tool_call": Execute a tool action. Use "tool" and "args" fields.

Variable references:
- Use "$var_name" in output_var to store a step's result.
- Reference previous results in prompts/args via "$var_name".
- input_vars lists which $variables a step depends on.

Available tools:
{tool_descriptions}

Rules:
- Every step must have a unique "id" (e.g. "step_1", "step_2").
- Only reference variables defined by previous steps' output_var.
- Set expects_code=true if the LLM step should produce code.
- Keep plans minimal — use the fewest steps necessary.
"""


class PlannerError(Exception):
    """General error from the Claude planner."""


class PlanValidationError(PlannerError):
    """The plan produced by Claude failed validation."""


class ClaudePlanner:
    """Claude API client that generates structured execution plans."""

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or self._load_api_key()
        self._client = anthropic.AsyncAnthropic(
            api_key=self._api_key,
            timeout=settings.claude_timeout,
        )

    @staticmethod
    def _load_api_key() -> str:
        try:
            with open(settings.claude_api_key_file) as f:
                return f.read().strip()
        except FileNotFoundError:
            raise PlannerError(
                f"Claude API key file not found: {settings.claude_api_key_file}"
            )
        except OSError as exc:
            raise PlannerError(f"Cannot read API key file: {exc}")

    async def create_plan(
        self,
        user_request: str,
        available_tools: list[dict] | None = None,
        policy_summary: str = "",
    ) -> Plan:
        """Ask Claude to produce a structured Plan for the given request."""
        tool_desc = json.dumps(available_tools or [], indent=2)
        system = _PLANNER_SYSTEM_PROMPT_TEMPLATE.format(tool_descriptions=tool_desc)
        if policy_summary:
            system += f"\n\nSecurity policy summary:\n{policy_summary}"

        user_content = f"User request: {user_request}"

        logger.info(
            "Sending plan request to Claude",
            extra={
                "event": "planner_request",
                "model": settings.claude_model,
                "request_preview": user_request[:200],
            },
        )

        last_error: Exception | None = None
        for attempt in range(2):  # initial + 1 retry
            try:
                response = await self._client.messages.create(
                    model=settings.claude_model,
                    max_tokens=settings.claude_max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user_content}],
                )
                break
            except anthropic.APIConnectionError as exc:
                last_error = PlannerError(f"Cannot connect to Claude API: {exc}")
                if attempt == 0:
                    continue
                raise last_error from exc
            except anthropic.APITimeoutError as exc:
                last_error = PlannerError(f"Claude API timed out: {exc}")
                if attempt == 0:
                    continue
                raise last_error from exc
            except anthropic.APIStatusError as exc:
                raise PlannerError(
                    f"Claude API error {exc.status_code}: {exc.message}"
                ) from exc
        else:
            raise last_error  # type: ignore[misc]

        # Extract text content from response
        raw_text = ""
        for block in response.content:
            if block.type == "text":
                raw_text += block.text

        if not raw_text.strip():
            raise PlannerError("Claude returned empty response")

        # Parse JSON
        try:
            plan_data = json.loads(raw_text.strip())
        except json.JSONDecodeError as exc:
            raise PlannerError(f"Claude returned invalid JSON: {exc}") from exc

        # Build Plan model
        try:
            plan = Plan(**plan_data)
        except Exception as exc:
            raise PlanValidationError(
                f"Plan does not match expected schema: {exc}"
            ) from exc

        # Validate plan
        self._validate_plan(plan)

        logger.info(
            "Plan created",
            extra={
                "event": "plan_created",
                "summary": plan.plan_summary,
                "step_count": len(plan.steps),
            },
        )
        return plan

    @staticmethod
    def _validate_plan(plan: Plan) -> None:
        """Validate plan structure: non-empty, valid types, variable refs resolve."""
        if not plan.steps:
            raise PlanValidationError("Plan has no steps")

        valid_types = {"llm_task", "tool_call"}
        defined_vars: set[str] = set()
        seen_ids: set[str] = set()

        for step in plan.steps:
            # Check unique IDs
            if step.id in seen_ids:
                raise PlanValidationError(f"Duplicate step ID: {step.id}")
            seen_ids.add(step.id)

            # Check valid type
            if step.type not in valid_types:
                raise PlanValidationError(
                    f"Step {step.id} has unknown type: {step.type}"
                )

            # Check input variable references
            for var in step.input_vars:
                if var not in defined_vars:
                    raise PlanValidationError(
                        f"Step {step.id} references undefined variable: {var}"
                    )

            # Track output variable
            if step.output_var:
                defined_vars.add(step.output_var)
