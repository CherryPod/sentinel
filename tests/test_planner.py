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
        assert "shell scripts" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "Dockerfiles" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_contains_workspace_constraint(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "/workspace/" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_prohibits_system_prompt_access(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "system prompt" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_prohibits_credential_access(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "credentials" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "API keys" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_prohibits_exfiltration(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "exfiltrate" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_marks_worker_untrusted(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "UNTRUSTED" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_prompt_has_refusal_instructions(self, planner):
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "Request refused" in _PLANNER_SYSTEM_PROMPT_TEMPLATE

    def test_system_prompt_contains_language_safety_rule(self, planner):
        """W7 fix: planner must prohibit non-English text in worker prompts."""
        from sentinel.planner.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "LANGUAGE SAFETY RULE" in _PLANNER_SYSTEM_PROMPT_TEMPLATE
        assert "non-English" in _PLANNER_SYSTEM_PROMPT_TEMPLATE


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
        # Should have been called twice (initial + 1 retry)
        assert planner._client.messages.create.call_count == 2

    @pytest.mark.asyncio
    async def test_timeout_retries(self, planner):
        import anthropic

        planner._client.messages.create = AsyncMock(
            side_effect=anthropic.APITimeoutError(request=MagicMock())
        )
        with pytest.raises(PlannerError, match="timed out"):
            await planner.create_plan("test")
        assert planner._client.messages.create.call_count == 2

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
        assert "CONVERSATION HISTORY" in user_msg
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
        assert "CONVERSATION HISTORY" not in user_msg
        assert user_msg == "User request: hello world"

    @pytest.mark.asyncio
    async def test_history_truncates_long_requests(self, planner):
        """Request text in history should be truncated to 200 chars."""
        plan_dict = _valid_plan_dict()
        mock_response = _make_claude_response(plan_dict)
        planner._client.messages.create = AsyncMock(return_value=mock_response)

        long_request = "x" * 500
        history = [
            {"turn": 1, "request": long_request, "outcome": "success", "summary": ""},
        ]
        await planner.create_plan("next request", conversation_history=history)

        call_kwargs = planner._client.messages.create.call_args.kwargs
        user_msg = call_kwargs["messages"][0]["content"]
        # The long request should be truncated — not all 500 chars
        assert long_request not in user_msg
        assert "x" * 200 in user_msg


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
