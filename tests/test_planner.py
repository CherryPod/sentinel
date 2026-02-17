import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.planner.planner import ClaudePlanner, PlannerError, PlanValidationError


def _make_claude_response(plan_dict: dict) -> MagicMock:
    """Build a mock Anthropic messages.create() response."""
    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = json.dumps(plan_dict)

    response = MagicMock()
    response.content = [text_block]
    return response


def _valid_plan_dict(**overrides) -> dict:
    """Minimal valid plan dict."""
    base = {
        "plan_summary": "Test plan",
        "steps": [
            {
                "id": "step_1",
                "type": "llm_task",
                "description": "Do something",
                "prompt": "Hello world",
                "output_var": "$result",
            }
        ],
    }
    base.update(overrides)
    return base


@pytest.fixture
def planner():
    """ClaudePlanner with a mock API key (no file read)."""
    return ClaudePlanner(api_key="test-key-123")


class TestCreatePlan:
    @pytest.mark.asyncio
    async def test_successful_plan(self, planner):
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        plan = await planner.create_plan("Build a hello world page")
        assert plan.plan_summary == "Test plan"
        assert len(plan.steps) == 1
        assert plan.steps[0].id == "step_1"
        assert plan.steps[0].type == "llm_task"

    @pytest.mark.asyncio
    async def test_invalid_json_response(self, planner):
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "This is not JSON at all"
        response = MagicMock()
        response.content = [text_block]
        planner._client.messages.create = AsyncMock(return_value=response)

        with pytest.raises(PlannerError, match="invalid JSON"):
            await planner.create_plan("Do something")

    @pytest.mark.asyncio
    async def test_empty_response(self, planner):
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = ""
        response = MagicMock()
        response.content = [text_block]
        planner._client.messages.create = AsyncMock(return_value=response)

        with pytest.raises(PlannerError, match="empty response"):
            await planner.create_plan("Do something")

    @pytest.mark.asyncio
    async def test_variable_references_validated(self, planner):
        plan_dict = {
            "plan_summary": "Multi-step",
            "steps": [
                {
                    "id": "step_1",
                    "type": "llm_task",
                    "description": "Generate",
                    "prompt": "Write code",
                    "output_var": "$code",
                },
                {
                    "id": "step_2",
                    "type": "llm_task",
                    "description": "Review",
                    "prompt": "Review $code",
                    "input_vars": ["$code"],
                    "output_var": "$review",
                },
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        plan = await planner.create_plan("Write and review code")
        assert len(plan.steps) == 2

    @pytest.mark.asyncio
    async def test_undefined_variable_detected(self, planner):
        plan_dict = {
            "plan_summary": "Bad refs",
            "steps": [
                {
                    "id": "step_1",
                    "type": "llm_task",
                    "description": "Use undefined var",
                    "prompt": "Use $nonexistent",
                    "input_vars": ["$nonexistent"],
                },
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        with pytest.raises(PlanValidationError, match="undefined variable"):
            await planner.create_plan("Bad plan")

    @pytest.mark.asyncio
    async def test_no_steps_rejected(self, planner):
        plan_dict = {"plan_summary": "Empty", "steps": []}
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        with pytest.raises(PlanValidationError, match="no steps"):
            await planner.create_plan("Empty plan")

    @pytest.mark.asyncio
    async def test_unknown_step_type_rejected(self, planner):
        plan_dict = {
            "plan_summary": "Bad type",
            "steps": [
                {
                    "id": "step_1",
                    "type": "unknown_type",
                    "description": "Mystery step",
                }
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        with pytest.raises(PlanValidationError, match="unknown type"):
            await planner.create_plan("Bad type plan")

    @pytest.mark.asyncio
    async def test_duplicate_step_id_rejected(self, planner):
        plan_dict = {
            "plan_summary": "Dupes",
            "steps": [
                {"id": "step_1", "type": "llm_task", "description": "A", "prompt": "a"},
                {"id": "step_1", "type": "llm_task", "description": "B", "prompt": "b"},
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        with pytest.raises(PlanValidationError, match="Duplicate step ID"):
            await planner.create_plan("Dupe IDs")

    @pytest.mark.asyncio
    async def test_system_prompt_includes_tool_descriptions(self, planner):
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        tools = [{"name": "file_write", "description": "Write a file"}]
        await planner.create_plan("Do something", available_tools=tools)

        call_kwargs = planner._client.messages.create.call_args.kwargs
        # System prompt is a list of dicts (prompt caching format)
        system_text = " ".join(
            block["text"] for block in call_kwargs["system"] if "text" in block
        )
        assert "file_write" in system_text


class TestPlannerSystemPrompt:
    """Verify the hardened system prompt contains critical security rules."""

    def test_prompt_contains_expects_code_rules(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "expects_code" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "scripts" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "Containerfile" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_contains_workspace_constraint(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "/workspace/" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_prohibits_system_prompt_access(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "system prompt" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_prohibits_credential_access(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        # New prompt uses "Credentials" and "API keys" in security_rules
        assert "redentials" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "API keys" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_prohibits_exfiltration(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "exfiltration" in _PLANNER_SYSTEM_PROMPT_TEMPLATE.lower()

    def test_prompt_marks_worker_untrusted(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "UNTRUSTED" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_has_refusal_instructions(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "Request refused" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_system_prompt_contains_language_safety_rule(self, planner):
        """W7 fix: planner must prohibit non-English text in worker prompts."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "LANGUAGE SAFETY" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "non-English" in _PLANNER_SYSTEM_PROMPT_TEMPLATE


class TestTokenUsageTracking:
    """Per-prompt token counting: _last_usage includes cache fields."""

    @pytest.mark.asyncio
    async def test_last_usage_populated_after_create_plan(self, planner):
        """_last_usage should contain input, output, and cache token counts."""
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        # Add usage attrs to the mock response
        usage = MagicMock()
        usage.input_tokens = 500
        usage.output_tokens = 120
        usage.cache_creation_input_tokens = 450
        usage.cache_read_input_tokens = 50
        mock_response.usage = usage
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        assert planner._last_usage is None
        await planner.create_plan("Hello world")
        assert planner._last_usage is not None
        assert planner._last_usage["input_tokens"] == 500
        assert planner._last_usage["output_tokens"] == 120
        assert planner._last_usage["cache_creation_input_tokens"] == 450
        assert planner._last_usage["cache_read_input_tokens"] == 50

    @pytest.mark.asyncio
    async def test_last_usage_handles_missing_cache_fields(self, planner):
        """Cache fields should be None when not present on usage object."""
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        # Simulate an older API response without cache fields
        usage = MagicMock(spec=[])
        usage.input_tokens = 200
        usage.output_tokens = 50
        mock_response.usage = usage
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        await planner.create_plan("Test")
        assert planner._last_usage["input_tokens"] == 200
        assert planner._last_usage["output_tokens"] == 50
        # getattr with default None when attr doesn't exist
        assert planner._last_usage["cache_creation_input_tokens"] is None
        assert planner._last_usage["cache_read_input_tokens"] is None


class TestAPIKeyLoading:
    def test_api_key_not_found(self):
        with patch("sentinel.planner.planner.settings") as mock_settings:
            mock_settings.claude_api_key_file = "/nonexistent/path"
            with pytest.raises(PlannerError, match="key file not found"):
                ClaudePlanner()

    def test_api_key_passed_directly(self):
        planner = ClaudePlanner(api_key="direct-key")
        assert planner._api_key == "direct-key"


class TestAPIErrors:
    @pytest.mark.asyncio
    async def test_connection_error_retries(self, planner):
        import anthropic

        planner._client.messages.create = AsyncMock(
            side_effect=anthropic.APIConnectionError(request=MagicMock())
        )
        with pytest.raises(PlannerError, match="Cannot connect"):
            await planner.create_plan("test")
        # Should have been called 3 times (initial + 2 retries)
        assert planner._client.messages.create.call_count == 3

    @pytest.mark.asyncio
    async def test_timeout_retries(self, planner):
        import anthropic

        planner._client.messages.create = AsyncMock(
            side_effect=anthropic.APITimeoutError(request=MagicMock())
        )
        with pytest.raises(PlannerError, match="timed out"):
            await planner.create_plan("test")
        assert planner._client.messages.create.call_count == 3

    @pytest.mark.asyncio
    async def test_status_error_no_retry(self, planner):
        import anthropic

        error_response = MagicMock()
        error_response.status_code = 401
        error_response.headers = {}
        planner._client.messages.create = AsyncMock(
            side_effect=anthropic.AuthenticationError(
                message="Invalid API key",
                response=error_response,
                body=None,
            )
        )
        with pytest.raises(PlannerError, match="API error 401"):
            await planner.create_plan("test")
        # Status errors should NOT retry
        assert planner._client.messages.create.call_count == 1


class TestConversationHistoryInjection:
    """Part 2 Layer 2: Conversation history passed to Claude planner prompt."""

    @pytest.mark.asyncio
    async def test_history_included_in_user_message(self, planner):
        """Conversation history should appear in the user content sent to Claude."""
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        history = [
            {"turn": 1, "request": "list files in /workspace/", "outcome": "success", "summary": "Listed files"},
            {"turn": 2, "request": "show config directory", "outcome": "success", "summary": "Showed config"},
        ]
        await planner.create_plan("read secrets.yaml", conversation_history=history)

        call_kwargs = planner._client.messages.create.call_args.kwargs
        user_msg = call_kwargs["messages"][0]["content"]
        assert "OPERATIONAL LOG" in user_msg
        assert "Turn 1" in user_msg
        assert "list files in /workspace/" in user_msg
        assert "adversarial escalation" in user_msg

    @pytest.mark.asyncio
    async def test_no_history_no_injection(self, planner):
        """Without conversation history, the prompt should be simple."""
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        await planner.create_plan("hello world")

        call_kwargs = planner._client.messages.create.call_args.kwargs
        user_msg = call_kwargs["messages"][0]["content"]
        assert "OPERATIONAL LOG" not in user_msg
        assert user_msg == "User request: hello world"

    @pytest.mark.asyncio
    async def test_history_truncates_long_requests(self, planner):
        """Request text in history should be truncated to 1000 chars."""
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        long_request = "x" * 1500
        history = [
            {"turn": 1, "request": long_request, "outcome": "success", "summary": ""},
        ]
        await planner.create_plan("next request", conversation_history=history)

        call_kwargs = planner._client.messages.create.call_args.kwargs
        user_msg = call_kwargs["messages"][0]["content"]
        # The long request should be truncated — not all 1500 chars
        assert long_request not in user_msg
        assert "x" * 1000 in user_msg


class TestOutputFormatValidation:
    """P8: Validate output_format field in plan validation."""

    @pytest.mark.asyncio
    async def test_output_format_invalid_rejected(self, planner):
        plan_dict = {
            "plan_summary": "Bad format",
            "steps": [
                {
                    "id": "step_1",
                    "type": "llm_task",
                    "description": "Generate",
                    "prompt": "Hello",
                    "output_format": "invalid",
                }
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        with pytest.raises(PlanValidationError, match="invalid output_format"):
            await planner.create_plan("Bad format plan")

    @pytest.mark.asyncio
    async def test_valid_output_formats_accepted(self, planner):
        """None, 'json', and 'tagged' should all pass validation."""
        for fmt in [None, "json", "tagged"]:
            step = {
                "id": "step_1",
                "type": "llm_task",
                "description": "Test",
                "prompt": "Hello",
            }
            if fmt is not None:
                step["output_format"] = fmt
            plan_dict = {"plan_summary": f"Format {fmt}", "steps": [step]}
            mock_response = _make_claude_response(plan_dict)
            planner._client.messages.create = AsyncMock(return_value=mock_response)

            plan = await planner.create_plan(f"Test {fmt}")
            assert len(plan.steps) == 1


class TestR13DecompositionGuidance:
    """R13: Verify planner system prompt contains refined decomposition guidance."""

    def test_prompt_contains_decomposition_triggers(self):
        """System prompt includes explicit triggers for when to decompose."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        prompt_lower = _PLANNER_SYSTEM_PROMPT_TEMPLATE.lower()
        assert "decompose" in prompt_lower
        assert "multiple files" in prompt_lower
        assert "multiple classes" in prompt_lower
        assert "do not decompose" in prompt_lower

    def test_prompt_contains_size_targeting(self):
        """System prompt includes size targeting guidance (100-200 lines per step)."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "100-200 lines" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "8192-token" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_contains_descriptive_variable_names(self):
        """System prompt shows GOOD/BAD examples of descriptive variable naming."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "$data_models" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "$api_routes" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "$step1_output" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_contains_decomposition_patterns(self):
        """System prompt includes common decomposition patterns for reference."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        prompt_lower = _PLANNER_SYSTEM_PROMPT_TEMPLATE.lower()
        assert "common pattern" in prompt_lower
        assert "web app" in prompt_lower
        assert "feature" in prompt_lower and "test" in prompt_lower

    def test_prompt_contains_context_threading_guidance(self):
        """System prompt includes guidance on how to thread context between steps."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "input_vars" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "$var_name" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    @pytest.mark.asyncio
    async def test_complex_multifile_task_produces_multistep_plan(self, planner):
        """A complex multi-file task should produce a multi-step plan.

        This tests that the system prompt guidance is compatible with multi-step
        plans by validating a plan that Claude *would* produce for a complex task.
        """
        # Simulate Claude returning a decomposed plan for a complex task
        plan_dict = {
            "plan_summary": "Build REST API with data models, routes, and tests",
            "steps": [
                {
                    "id": "step_1",
                    "type": "llm_task",
                    "description": "Generate SQLAlchemy data models",
                    "prompt": "Write SQLAlchemy models for User and Post...",
                    "output_var": "$data_models",
                    "expects_code": True,
                    "output_format": "tagged",
                },
                {
                    "id": "step_2",
                    "type": "llm_task",
                    "description": "Generate FastAPI route handlers",
                    "prompt": "Using these data models: $data_models\nWrite FastAPI routes...",
                    "output_var": "$api_routes",
                    "expects_code": True,
                    "input_vars": ["$data_models"],
                    "output_format": "tagged",
                },
                {
                    "id": "step_3",
                    "type": "llm_task",
                    "description": "Generate pytest test suite",
                    "prompt": "Given models $data_models and routes $api_routes, write tests...",
                    "output_var": "$test_suite",
                    "expects_code": True,
                    "input_vars": ["$data_models", "$api_routes"],
                },
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        plan = await planner.create_plan(
            "Build a REST API with User and Post models, CRUD routes, and a test suite"
        )
        assert len(plan.steps) == 3
        # Verify descriptive variable names
        var_names = [s.output_var for s in plan.steps if s.output_var]
        assert "$data_models" in var_names
        assert "$api_routes" in var_names
        assert "$test_suite" in var_names
        # Intermediate steps use tagged format
        assert plan.steps[0].output_format == "tagged"
        assert plan.steps[1].output_format == "tagged"
        # Final step has no output_format constraint (displays to user)
        assert plan.steps[2].output_format is None

    @pytest.mark.asyncio
    async def test_simple_task_produces_single_step_plan(self, planner):
        """A simple short-output task should remain a single-step plan."""
        plan_dict = {
            "plan_summary": "Write a Python function to validate email addresses",
            "steps": [
                {
                    "id": "step_1",
                    "type": "llm_task",
                    "description": "Generate email validation function",
                    "prompt": "Write a Python function that validates email addresses...",
                    "output_var": "$result",
                    "expects_code": True,
                }
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        plan = await planner.create_plan(
            "Write a Python function to validate email addresses using regex"
        )
        assert len(plan.steps) == 1
        assert plan.steps[0].type == "llm_task"

    @pytest.mark.asyncio
    async def test_decomposed_plan_uses_descriptive_var_names(self, planner):
        """Variable names in decomposed plans should be descriptive, not ordinal.

        This validates that a multi-step plan passes validation when using
        descriptive $var_name references (the style the guidance promotes).
        """
        plan_dict = {
            "plan_summary": "Generate a Flask app with config and tests",
            "steps": [
                {
                    "id": "step_1",
                    "type": "llm_task",
                    "description": "Generate Flask app configuration",
                    "prompt": "Write a Flask config module with dev/prod/test classes...",
                    "output_var": "$config_module",
                    "expects_code": True,
                    "output_format": "tagged",
                },
                {
                    "id": "step_2",
                    "type": "llm_task",
                    "description": "Generate Flask application factory",
                    "prompt": "The config module is: $config_module\nWrite a Flask app factory...",
                    "output_var": "$flask_app",
                    "expects_code": True,
                    "input_vars": ["$config_module"],
                    "output_format": "tagged",
                },
                {
                    "id": "step_3",
                    "type": "llm_task",
                    "description": "Generate test suite",
                    "prompt": "Given config $config_module and app $flask_app, write tests...",
                    "output_var": "$test_suite",
                    "expects_code": True,
                    "input_vars": ["$config_module", "$flask_app"],
                },
            ],
        }
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        plan = await planner.create_plan(
            "Build a Flask app with config, application factory, and tests"
        )
        assert len(plan.steps) == 3
        # All variable names should be descriptive (not generic ordinals)
        for step in plan.steps:
            if step.output_var:
                # Should not match ordinal patterns like $step1_output, $result1
                assert not step.output_var.startswith("$step"), \
                    f"Variable {step.output_var} uses ordinal naming"
                assert not any(c.isdigit() for c in step.output_var.lstrip("$")), \
                    f"Variable {step.output_var} contains numbers (avoid ordinal naming)"
        # Variable references should resolve correctly (validation passed)
        assert plan.steps[1].input_vars == ["$config_module"]
        assert plan.steps[2].input_vars == ["$config_module", "$flask_app"]


class TestD5ConstraintPrompt:
    """D5: Planner prompt includes constraint generation instructions."""

    def test_prompt_contains_constraint_section(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "PLAN-POLICY CONSTRAINTS" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_mentions_allowed_commands(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "allowed_commands" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_mentions_allowed_paths(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "allowed_paths" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_mentions_workspace_requirement(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "/workspace/" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_mentions_static_denylist(self):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "denylist" in _PLANNER_SYSTEM_PROMPT_TEMPLATE.lower()

    def test_allowed_commands_shows_base_names_only(self):
        """GOOD example should show base command names, not full command strings."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        constraints_section = _PLANNER_SYSTEM_PROMPT_TEMPLATE[
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("<constraints>"):
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("</constraints>")
        ]
        # GOOD example should be base command names like ["find", "wc"]
        assert '["find", "wc"]' in constraints_section
        # The old incorrect GOOD example with full command string must be gone
        assert 'GOOD: ["rm -rf /workspace/build-cache/*"]' not in constraints_section

    def test_bad_example_shows_full_command_line_rejected(self):
        """BAD example should show that full command lines with metacharacters are rejected."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        constraints_section = _PLANNER_SYSTEM_PROMPT_TEMPLATE[
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("<constraints>"):
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("</constraints>")
        ]
        assert "metacharacters blocked" in constraints_section.lower()

    def test_constraint_examples_include_file_write_step(self):
        """Constraints section includes a concrete file_write step example."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        constraints_section = _PLANNER_SYSTEM_PROMPT_TEMPLATE[
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("<constraints>"):
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("</constraints>")
        ]
        assert '"tool": "file_write"' in constraints_section
        assert '"allowed_paths": ["/workspace/app.py"]' in constraints_section

    def test_constraint_examples_include_shell_exec_step(self):
        """Constraints section includes a concrete shell_exec step example."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        constraints_section = _PLANNER_SYSTEM_PROMPT_TEMPLATE[
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("<constraints>"):
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("</constraints>")
        ]
        assert '"tool": "shell_exec"' in constraints_section
        assert '"allowed_commands": ["find"]' in constraints_section

    def test_constraint_clarification_note(self):
        """Constraints section explains that allowed_commands lists BASE command names."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        constraints_section = _PLANNER_SYSTEM_PROMPT_TEMPLATE[
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("<constraints>"):
            _PLANNER_SYSTEM_PROMPT_TEMPLATE.index("</constraints>")
        ]
        # Should explain the distinction between base names and full command strings
        assert "BASE command name" in constraints_section or "base command name" in constraints_section

    def test_constraint_examples_pass_validator(self):
        """The example constraint values in the prompt should pass validate_constraint_definitions."""
        from sentinel.security.constraint_validator import validate_constraint_definitions
        # file_write example
        errors = validate_constraint_definitions(None, ["/workspace/app.py"])
        assert errors == []
        # shell_exec example
        errors = validate_constraint_definitions(["find"], ["/workspace/src/"])
        assert errors == []
        # multi-step example
        errors = validate_constraint_definitions(["python3"], ["/workspace/tests/"])
        assert errors == []

    def test_old_bad_example_would_fail_validator(self):
        """The old GOOD example with full command strings should fail validation (metacharacters)."""
        from sentinel.security.constraint_validator import validate_constraint_definitions
        # The old example: ["rm -rf /workspace/build-cache/*"]
        # While * isn't in the metachar set, piped commands like the BAD example are
        errors = validate_constraint_definitions(
            ["find /workspace/ -type f -name '*.py' | wc -l"], None,
        )
        assert len(errors) > 0
        assert "metacharacter" in errors[0].lower()


class TestD5EnrichedHistory:
    """D5: constraint_result appears in enriched history format."""

    def test_constraint_validated_in_history(self):
        """The most recent turn always expands step detail (Step 0.2 change).
        Non-last successful turns collapse to one-liners. A single-entry
        history means that entry IS the last turn, so it expands."""
        from sentinel.planner.planner import ClaudePlanner
        planner = ClaudePlanner.__new__(ClaudePlanner)
        # Single turn = last turn → always expanded (Step 0.2)
        history = [{
            "turn": 1,
            "request": "clean cache",
            "outcome": "success",
            "step_outcomes": [{
                "step_type": "tool_call",
                "status": "success",
                "constraint_result": "validated",
            }],
        }]
        result = planner._format_enriched_history(history)
        assert "clean cache" in result
        assert "success" in result
        # Last turn is always expanded — constraint detail IS shown
        assert "constraint=validated" in result

        # Two turns: first (success, not last) collapses, second (last) expands
        history_multi = [
            {
                "turn": 1, "request": "clean cache", "outcome": "success",
                "step_outcomes": [{"step_type": "tool_call", "status": "success",
                                   "constraint_result": "validated"}],
            },
            {
                "turn": 2, "request": "check status", "outcome": "success",
                "step_outcomes": [{"step_type": "tool_call", "status": "success",
                                   "constraint_result": "validated"}],
            },
        ]
        result_multi = planner._format_enriched_history(history_multi)
        # Turn 1 (not last, success) should NOT have step detail
        # Split around turn 2 to isolate turn 1's output
        turn2_idx = result_multi.index("Turn 2:")
        turn1_section = result_multi[:turn2_idx]
        assert "constraint=validated" not in turn1_section
        # Turn 2 (last) should have step detail expanded
        turn2_section = result_multi[turn2_idx:]
        assert "constraint=validated" in turn2_section

    def test_constraint_violation_in_history(self):
        from sentinel.planner.planner import ClaudePlanner
        planner = ClaudePlanner.__new__(ClaudePlanner)
        history = [{
            "turn": 1,
            "request": "bad command",
            "outcome": "blocked",
            "step_outcomes": [{
                "step_type": "tool_call",
                "status": "blocked",
                "constraint_result": "violation",
                "scanner_result": "blocked",
                "error_detail": "constraint violation",
            }],
        }]
        result = planner._format_enriched_history(history)
        assert "constraint=violation" in result


class TestPlannerPromptStructure:
    """Verify prompt_upgrade_v1 structural requirements."""

    def test_prompt_has_xml_sections(self, planner):
        """Prompt uses XML section tags for structural parsing."""
        prompt = planner._build_system_prompt()
        for tag in ["<role>", "<security_rules>", "<output_schema>",
                     "<worker_llm>", "<plan_rules>", "<tools>", "<constraints>"]:
            assert tag in prompt, f"Missing XML section: {tag}"

    def test_security_rules_before_output_schema(self, planner):
        """Security rules in high-attention position (before schema)."""
        prompt = planner._build_system_prompt()
        assert prompt.index("<security_rules>") < prompt.index("<output_schema>")

    def test_constraints_at_end(self, planner):
        """Constraints at end of prompt for U-shaped attention."""
        prompt = planner._build_system_prompt()
        assert prompt.index("<constraints>") > prompt.index("<tools>")

    def test_prompt_requires_constraints_at_tl4(self, planner):
        """TL4 MUST language present in constraints section."""
        prompt = planner._build_system_prompt()
        assert "MUST" in prompt[prompt.index("<constraints>"):]

    def test_prompt_reinforces_valid_step_types(self, planner):
        """Step types explicitly listed (fixes file_write step type bug)."""
        prompt = planner._build_system_prompt()
        assert '"llm_task"' in prompt
        assert '"tool_call"' in prompt

    def test_prompt_variable_ordering_rule(self, planner):
        """Explicit rule about only referencing prior step variables."""
        prompt = planner._build_system_prompt()
        assert "prior step" in prompt.lower() or "previous step" in prompt.lower()

    def test_no_removed_content(self, planner):
        """Key functional content preserved from current prompt."""
        prompt = planner._build_system_prompt()
        # Language safety rule (verbatim requirement from design)
        assert "Chinese-trained" in prompt or "Qwen" in prompt
        # Post-data reminder pattern
        assert "REMINDER:" in prompt
        # Workspace constraint
        assert "/workspace/" in prompt
        # Tool descriptions placeholder was filled
        assert "{tool_descriptions}" not in prompt

    def test_prompt_contains_replan_after_field(self, planner):
        """System prompt documents replan_after field."""
        prompt = planner._build_system_prompt()
        assert "replan_after" in prompt

    def test_prompt_contains_dynamic_replanning_rule(self, planner):
        """System prompt contains the DYNAMIC REPLANNING plan rule."""
        prompt = planner._build_system_prompt()
        assert "DYNAMIC REPLANNING" in prompt


class TestReplanValidation:
    """Validation of replan_after constraints on plans."""

    @pytest.fixture
    def planner(self):
        return ClaudePlanner(api_key="test-key")

    def test_replan_after_on_last_step_preserved(self, planner):
        """replan_after on the last step is valid for discovery-first plans."""
        from sentinel.core.models import Plan, PlanStep
        plan = Plan(
            plan_summary="Test",
            steps=[PlanStep(
                id="step_1", type="tool_call", tool="shell",
                args={"command": "ls /workspace/"},
                replan_after=True,
            )],
        )
        planner._validate_plan(plan)
        assert plan.steps[0].replan_after is True

    def test_too_many_replan_markers_rejected(self, planner):
        """More than 3 replan_after markers are rejected."""
        from sentinel.core.models import Plan, PlanStep
        from sentinel.planner.planner import PlanValidationError
        steps = [
            PlanStep(
                id=f"step_{i}", type="tool_call", tool="shell",
                args={"command": f"echo {i}"}, replan_after=True,
            )
            for i in range(1, 5)  # 4 replan markers — exceeds budget of 3
        ]
        plan = Plan(plan_summary="Test", steps=steps)

        with pytest.raises(PlanValidationError, match="replan_after"):
            planner._validate_plan(plan)

    def test_three_replan_markers_accepted(self, planner):
        """Exactly 3 replan_after markers are within budget."""
        from sentinel.core.models import Plan, PlanStep
        steps = [
            PlanStep(
                id=f"step_{i}", type="tool_call", tool="shell",
                args={"command": f"echo {i}"}, replan_after=True,
            )
            for i in range(1, 4)  # 3 replan markers
        ]
        steps.append(PlanStep(id="step_4", type="llm_task", prompt="Done"))
        plan = Plan(plan_summary="Test", steps=steps)
        # Should not raise
        planner._validate_plan(plan)

    def test_plan_without_replan_after_unchanged(self, planner):
        """Plans without replan_after pass validation unchanged (backward compat)."""
        from sentinel.core.models import Plan, PlanStep
        plan = Plan(
            plan_summary="Normal plan",
            steps=[
                PlanStep(id="step_1", type="llm_task", prompt="Hello"),
                PlanStep(id="step_2", type="tool_call", tool="shell", args={"command": "ls"}),
            ],
        )
        planner._validate_plan(plan)
        assert not any(s.replan_after for s in plan.steps)
