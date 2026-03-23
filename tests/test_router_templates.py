"""Tests for the router template registry.

Covers: Template dataclass creation, validation, alias resolution,
chain detection, and TemplateRegistry operations including the
default day-one template set.
"""

import pytest

from sentinel.router.templates import Template, TemplateRegistry


# --- Template dataclass ---


class TestTemplateDefaults:
    """Template creation with default values."""

    def test_minimal_template(self):
        t = Template(name="test", description="A test", tool="some_tool")
        assert t.name == "test"
        assert t.description == "A test"
        assert t.tool == "some_tool"
        assert t.required_params == []
        assert t.optional_params == []
        assert t.param_aliases == {}
        assert t.side_effect is False
        assert t.requires_confirmation is False
        assert t.source_is_user is True

    def test_frozen(self):
        t = Template(name="test", description="A test", tool="some_tool")
        with pytest.raises(AttributeError):
            t.name = "changed"


class TestTemplateSideEffects:
    """Templates with side_effect and source_is_user flags."""

    def test_side_effect_template(self):
        t = Template(
            name="send",
            description="Send a message",
            tool="signal_send",
            required_params=["message"],
            side_effect=True,
            source_is_user=True,
        )
        assert t.side_effect is True
        assert t.source_is_user is True

    def test_read_only_template(self):
        t = Template(
            name="search",
            description="Search the web",
            tool="web_search",
            required_params=["query"],
            side_effect=False,
        )
        assert t.side_effect is False


class TestValidateParams:
    """validate_params checks that all required_params are present."""

    def test_all_required_present(self):
        t = Template(
            name="cal",
            description="Add event",
            tool="calendar_create_event",
            required_params=["summary", "start"],
        )
        assert t.validate_params({"summary": "Meeting", "start": "2026-03-05T10:00"}) is True

    def test_extra_params_ok(self):
        t = Template(
            name="cal",
            description="Add event",
            tool="calendar_create_event",
            required_params=["summary", "start"],
        )
        assert t.validate_params({"summary": "Meeting", "start": "2026-03-05", "end": "2026-03-05T11:00"}) is True

    def test_missing_required(self):
        t = Template(
            name="cal",
            description="Add event",
            tool="calendar_create_event",
            required_params=["summary", "start"],
        )
        assert t.validate_params({"summary": "Meeting"}) is False

    def test_empty_params_with_no_required(self):
        t = Template(name="list", description="List events", tool="calendar_list_events")
        assert t.validate_params({}) is True

    def test_empty_params_with_required(self):
        t = Template(
            name="search",
            description="Search",
            tool="web_search",
            required_params=["query"],
        )
        assert t.validate_params({}) is False


class TestResolveAliases:
    """resolve_aliases maps aliased param names to canonical names."""

    def test_alias_resolved(self):
        t = Template(
            name="cal",
            description="Add event",
            tool="calendar_create_event",
            required_params=["summary", "start"],
            param_aliases={"title": "summary"},
        )
        result = t.resolve_aliases({"title": "Meeting", "start": "2026-03-05"})
        assert result == {"summary": "Meeting", "start": "2026-03-05"}

    def test_no_aliases_passthrough(self):
        t = Template(
            name="search",
            description="Search",
            tool="web_search",
            required_params=["query"],
        )
        params = {"query": "weather"}
        result = t.resolve_aliases(params)
        assert result == {"query": "weather"}

    def test_canonical_name_not_overwritten(self):
        """If both alias and canonical are present, canonical wins."""
        t = Template(
            name="cal",
            description="Add event",
            tool="calendar_create_event",
            required_params=["summary"],
            param_aliases={"title": "summary"},
        )
        result = t.resolve_aliases({"title": "Alias Value", "summary": "Canonical Value"})
        assert result["summary"] == "Canonical Value"

    def test_non_alias_params_preserved(self):
        t = Template(
            name="cal",
            description="Add event",
            tool="calendar_create_event",
            required_params=["summary"],
            param_aliases={"title": "summary"},
        )
        result = t.resolve_aliases({"title": "Meeting", "extra": "data"})
        assert result == {"summary": "Meeting", "extra": "data"}


class TestChainDetection:
    """is_chain and tool_chain properties for single and chained tools."""

    def test_single_tool_not_chain(self):
        t = Template(name="search", description="Search", tool="web_search")
        assert t.is_chain is False
        assert t.tool_chain == ["web_search"]

    def test_chain_tool(self):
        t = Template(
            name="email_read",
            description="Search and read email",
            tool="email_search+email_read",
        )
        assert t.is_chain is True
        assert t.tool_chain == ["email_search", "email_read"]

    def test_three_tool_chain(self):
        t = Template(
            name="complex",
            description="Multi-step",
            tool="step_a+step_b+step_c",
        )
        assert t.is_chain is True
        assert t.tool_chain == ["step_a", "step_b", "step_c"]


# --- TemplateRegistry ---


class TestRegistryDefault:
    """TemplateRegistry.default() returns all 9 day-one templates."""

    @pytest.fixture
    def registry(self):
        return TemplateRegistry.default()

    def test_default_has_nine_templates(self, registry):
        assert len(registry.names()) == 9

    def test_all_expected_names_present(self, registry):
        expected = {
            "calendar_read",
            "calendar_add",
            "email_search",
            "email_read",
            "email_send",
            "web_search",
            "x_search",
            "signal_send",
            "telegram_send",
            # memory_search commented out — not wired into ToolExecutor
        }
        assert set(registry.names()) == expected

    def test_calendar_read(self, registry):
        t = registry.get("calendar_read")
        assert t is not None
        assert t.tool == "calendar_list_events"
        assert t.required_params == []
        assert t.side_effect is False

    def test_calendar_add(self, registry):
        t = registry.get("calendar_add")
        assert t is not None
        assert t.tool == "calendar_create_event"
        assert t.required_params == ["summary", "start"]
        assert t.side_effect is True
        assert t.param_aliases == {"title": "summary"}

    def test_email_search(self, registry):
        t = registry.get("email_search")
        assert t is not None
        assert t.tool == "email_search"
        assert t.required_params == ["query"]
        assert t.side_effect is False

    def test_email_read_is_chain(self, registry):
        t = registry.get("email_read")
        assert t is not None
        assert t.tool == "email_search+email_read"
        assert t.is_chain is True
        assert t.required_params == ["query"]
        assert t.side_effect is False

    def test_web_search(self, registry):
        t = registry.get("web_search")
        assert t is not None
        assert t.tool == "web_search"
        assert t.required_params == ["query"]
        assert t.side_effect is False

    def test_x_search(self, registry):
        t = registry.get("x_search")
        assert t is not None
        assert t.tool == "x_search"
        assert t.required_params == ["query"]
        assert t.side_effect is False

    def test_signal_send(self, registry):
        t = registry.get("signal_send")
        assert t is not None
        assert t.tool == "signal_send"
        assert t.required_params == ["message"]
        assert t.side_effect is True
        assert t.source_is_user is True

    def test_telegram_send(self, registry):
        t = registry.get("telegram_send")
        assert t is not None
        assert t.tool == "telegram_send"
        assert t.required_params == ["message"]
        assert t.side_effect is True
        assert t.source_is_user is True

    def test_email_send(self, registry):
        t = registry.get("email_send")
        assert t is not None
        assert t.tool == "email_send"
        assert t.required_params == ["recipient", "subject", "body"]
        assert t.side_effect is True
        assert t.requires_confirmation is True
        assert t.source_is_user is True
        assert t.param_aliases == {"to": "recipient"}

    def test_memory_search_not_registered(self, registry):
        # memory_search commented out — not wired into ToolExecutor
        assert registry.get("memory_search") is None


class TestRegistryOperations:
    """Registry get, register, and get-nonexistent."""

    def test_get_nonexistent(self):
        registry = TemplateRegistry.default()
        assert registry.get("nonexistent") is None

    def test_register_custom_template(self):
        registry = TemplateRegistry()
        custom = Template(
            name="custom_tool",
            description="A custom tool",
            tool="my_tool",
            required_params=["input"],
        )
        registry.register(custom)
        assert registry.get("custom_tool") is custom
        assert "custom_tool" in registry.names()

    def test_register_overwrites(self):
        registry = TemplateRegistry()
        t1 = Template(name="test", description="First", tool="tool_a")
        t2 = Template(name="test", description="Second", tool="tool_b")
        registry.register(t1)
        registry.register(t2)
        assert registry.get("test").tool == "tool_b"

    def test_empty_registry(self):
        registry = TemplateRegistry()
        assert registry.names() == []
        assert registry.get("anything") is None


class TestBuildClassifierPrompt:
    """build_classifier_prompt includes all template names and params."""

    def test_contains_all_template_names(self):
        registry = TemplateRegistry.default()
        prompt = registry.build_classifier_prompt()
        for name in registry.names():
            assert name in prompt, f"Template '{name}' not found in classifier prompt"

    def test_contains_required_params(self):
        registry = TemplateRegistry.default()
        prompt = registry.build_classifier_prompt()
        # Check that specific required params appear
        assert "summary" in prompt
        assert "start" in prompt
        assert "query" in prompt
        assert "message" in prompt

    def test_contains_descriptions(self):
        registry = TemplateRegistry.default()
        prompt = registry.build_classifier_prompt()
        # Each template should have its description in the prompt
        for name in registry.names():
            t = registry.get(name)
            assert t.description in prompt

    def test_empty_registry_prompt(self):
        registry = TemplateRegistry()
        prompt = registry.build_classifier_prompt()
        assert isinstance(prompt, str)


# --- format_preview() ---


class TestTemplateFormatPreview:
    def test_calendar_add_preview(self):
        registry = TemplateRegistry.default()
        t = registry.get("calendar_add")
        preview = t.format_preview({"summary": "Dentist", "start": "2026-03-10T14:00"})
        assert "Dentist" in preview
        assert "2026-03-10" in preview

    def test_signal_send_preview(self):
        registry = TemplateRegistry.default()
        t = registry.get("signal_send")
        preview = t.format_preview({"message": "Hello Keith", "recipient": "Keith"})
        assert "Signal" in preview
        assert "Keith" in preview
        assert "Hello Keith" in preview

    def test_telegram_send_preview(self):
        registry = TemplateRegistry.default()
        t = registry.get("telegram_send")
        preview = t.format_preview({"message": "Hi there", "recipient": "Keith"})
        assert "Telegram" in preview
        assert "Hi there" in preview

    def test_email_send_preview(self):
        registry = TemplateRegistry.default()
        t = registry.get("email_send")
        preview = t.format_preview({
            "recipient": "john@example.com",
            "subject": "Meeting notes",
            "body": "Here are the notes from today.",
        })
        assert "john@example.com" in preview
        assert "Meeting notes" in preview

    def test_preview_truncates_long_message(self):
        registry = TemplateRegistry.default()
        t = registry.get("signal_send")
        long_msg = "x" * 500
        preview = t.format_preview({"message": long_msg, "recipient": "Keith"})
        # Preview should not contain the full 500 chars
        assert len(preview) < 300

    def test_read_only_template_preview_returns_empty(self):
        registry = TemplateRegistry.default()
        t = registry.get("web_search")
        preview = t.format_preview({"query": "test"})
        assert preview == ""

    def test_default_preview_for_unknown_template(self):
        t = Template(
            name="custom_tool",
            description="Custom",
            tool="custom_tool",
            side_effect=True,
            requires_confirmation=True,
        )
        preview = t.format_preview({"foo": "bar"})
        assert "custom_tool" in preview


class TestKeywordClassifierSync:
    """Every template name in the keyword classifier must exist in the registry.

    This prevents drift where a pattern routes to a template that doesn't
    exist, causing silent fallback to planner.
    """

    def test_all_classifier_templates_exist_in_registry(self):
        from sentinel.router.keyword_classifier import KeywordClassifier

        registry = TemplateRegistry.default()
        kc = KeywordClassifier(registry=registry)

        # Extract all unique template names from the classifier's patterns
        classifier_templates = {entry.template_name for entry in kc._patterns}

        missing = []
        for name in classifier_templates:
            if registry.get(name) is None:
                missing.append(name)

        assert not missing, (
            f"Keyword classifier references templates not in registry: {missing}. "
            f"Add them to TemplateRegistry.default() or remove the patterns."
        )

    def test_all_registry_templates_have_classifier_patterns(self):
        """Every registry template should have at least one keyword pattern.

        This is advisory — not every template needs fast-path patterns
        (some may only be accessible via planner). But it catches templates
        that were intended to be fast-pathed but have no route in.
        """
        from sentinel.router.keyword_classifier import KeywordClassifier

        registry = TemplateRegistry.default()
        kc = KeywordClassifier(registry=registry)

        classifier_templates = {entry.template_name for entry in kc._patterns}
        registry_templates = set(registry.names())

        uncovered = registry_templates - classifier_templates
        # This is a soft check — some templates might intentionally only
        # be reachable via planner or confirmation flows
        assert not uncovered, (
            f"Registry templates with no keyword classifier patterns: {uncovered}. "
            f"These are only reachable via the planner. If intentional, add to "
            f"the allow-list in this test."
        )


class TestTemplateRequiresConfirmation:
    def test_side_effect_templates_require_confirmation(self):
        registry = TemplateRegistry.default()
        for name in ["calendar_add", "email_send", "signal_send", "telegram_send"]:
            t = registry.get(name)
            assert t.requires_confirmation is True, f"{name} should require confirmation"

    def test_read_only_templates_do_not_require_confirmation(self):
        registry = TemplateRegistry.default()
        for name in ["calendar_read", "email_search", "email_read",
                      "web_search", "x_search"]:
            t = registry.get(name)
            assert t.requires_confirmation is False, f"{name} should not require confirmation"
