"""Template dataclass and registry for the fast-path router.

Templates define single-tool (or chained-tool) operations that can bypass
the Claude planner when the classifier determines the user request is simple
enough. The TemplateRegistry holds all available templates and generates
the classifier prompt used by Qwen to match user input to a template.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Template:
    """A fast-path template mapping a user intent to one or more tool calls.

    Attributes:
        name: Unique identifier for this template (e.g. "calendar_add").
        description: Human-readable description used in classifier prompts.
        tool: Tool name, or "+" delimited chain (e.g. "email_search+email_read").
        required_params: Params that must be present for the template to match.
        optional_params: Params that may be extracted but are not required.
        param_aliases: Maps alternative param names to canonical names
            (e.g. {"title": "summary"}).
        side_effect: True if the tool mutates state (send, create, delete).
        requires_confirmation: Stub for future confirmation gate.
        source_is_user: True if the content originates from the user (not
            external data). Affects trust classification.
    """

    name: str
    description: str
    tool: str
    required_params: list[str] = field(default_factory=list)
    optional_params: list[str] = field(default_factory=list)
    param_aliases: dict[str, str] = field(default_factory=dict)
    side_effect: bool = False
    requires_confirmation: bool = False
    source_is_user: bool = True

    @property
    def is_chain(self) -> bool:
        """True if this template invokes multiple tools in sequence."""
        return "+" in self.tool

    @property
    def tool_chain(self) -> list[str]:
        """Ordered list of tool names to invoke."""
        return self.tool.split("+")

    def validate_params(self, params: dict) -> bool:
        """Check that all required_params are present in params."""
        return all(p in params for p in self.required_params)

    def format_preview(self, params: dict) -> str:
        """Generate a compact preview string for confirmation display.

        Returns empty string for templates that don't require confirmation.
        """
        if not self.requires_confirmation:
            return ""

        # Template-specific formats
        if self.name == "calendar_add":
            summary = params.get("summary", "")
            start = params.get("start", "")
            location = params.get("location", "")
            preview = f"Add to calendar: {summary} -- {start}"
            if location:
                preview += f" @ {location}"
            return preview

        if self.name == "signal_send":
            return self._send_preview("Signal", params)

        if self.name == "telegram_send":
            return self._send_preview("Telegram", params)

        if self.name == "email_send":
            recipient = params.get("recipient", "")
            subject = params.get("subject", "")
            body = params.get("body", "")
            if len(body) > 200:
                body = body[:200] + "..."
            return f"Send email to {recipient} -- Subject: {subject}\n{body}"

        # Fallback for unknown side-effect templates
        return f"Execute {self.tool} with params: {params}"

    @staticmethod
    def _send_preview(channel_name: str, params: dict) -> str:
        """Format a send-message preview, truncating long messages."""
        recipient = params.get("recipient", "")
        message = params.get("message", "")
        if len(message) > 200:
            message = message[:200] + "..."
        return f"Send via {channel_name} to {recipient}: {message}"

    def resolve_aliases(self, params: dict) -> dict:
        """Return a new dict with aliased param names mapped to canonical names.

        If both an alias and its canonical name are present, the canonical
        value takes precedence and the alias is dropped.
        """
        resolved = {}
        for key, value in params.items():
            canonical = self.param_aliases.get(key)
            if canonical is not None:
                # Only use alias if canonical isn't already provided
                if canonical not in params:
                    resolved[canonical] = value
                # If canonical IS in params, drop the alias silently
            else:
                resolved[key] = value
        return resolved


class TemplateRegistry:
    """Registry of available fast-path templates.

    Provides lookup by name and generates classifier prompts from
    the registered template set.
    """

    def __init__(self) -> None:
        self._templates: dict[str, Template] = {}

    def register(self, template: Template) -> None:
        """Add or replace a template in the registry."""
        self._templates[template.name] = template

    def get(self, name: str) -> Template | None:
        """Look up a template by name. Returns None if not found."""
        return self._templates.get(name)

    def names(self) -> list[str]:
        """Return a list of all registered template names."""
        return list(self._templates.keys())

    def build_classifier_prompt(self) -> str:
        """Generate a prompt listing all templates for the classifier.

        The classifier (Qwen) uses this prompt to decide whether a user
        message matches a known template and to extract its parameters.
        """
        if not self._templates:
            return ""

        lines = ["Available templates:\n"]
        for t in self._templates.values():
            parts = [f"- {t.name}: {t.description}"]
            if t.required_params:
                parts.append(f"  required: {', '.join(t.required_params)}")
            if t.optional_params:
                parts.append(f"  optional: {', '.join(t.optional_params)}")
            if t.side_effect:
                parts.append("  side_effect: yes")
            lines.append("\n".join(parts))

        return "\n".join(lines)

    @classmethod
    def default(cls) -> TemplateRegistry:
        """Return a registry pre-loaded with the 9 day-one templates."""
        registry = cls()

        templates = [
            Template(
                name="calendar_read",
                description="List upcoming calendar events",
                tool="calendar_list_events",
                optional_params=["time_min", "time_max"],
            ),
            Template(
                name="calendar_add",
                description="Create a new calendar event",
                tool="calendar_create_event",
                required_params=["summary", "start"],
                optional_params=["end", "location", "description"],
                param_aliases={"title": "summary"},
                side_effect=True,
                requires_confirmation=True,
            ),
            Template(
                name="email_search",
                description="Search emails by query",
                tool="email_search",
                required_params=["query"],
                optional_params=["max_results"],
            ),
            Template(
                name="email_read",
                description="Search and read an email",
                tool="email_search+email_read",
                required_params=["query"],
                optional_params=["max_results"],
            ),
            Template(
                name="web_search",
                description="Search the web",
                tool="web_search",
                required_params=["query"],
                optional_params=["count"],
            ),
            Template(
                name="x_search",
                description="Search X/Twitter posts",
                tool="x_search",
                required_params=["query"],
                optional_params=["count"],
            ),
            Template(
                name="signal_send",
                description="Send a message via Signal",
                tool="signal_send",
                required_params=["message"],
                optional_params=["recipient"],
                param_aliases={"to": "recipient"},
                side_effect=True,
                requires_confirmation=True,
                source_is_user=True,
            ),
            Template(
                name="telegram_send",
                description="Send a message via Telegram",
                tool="telegram_send",
                required_params=["message"],
                optional_params=["recipient"],
                param_aliases={"to": "recipient", "chat_id": "recipient"},
                side_effect=True,
                requires_confirmation=True,
                source_is_user=True,
            ),
            Template(
                name="memory_search",
                description="Search stored memories",
                tool="memory_search",
                required_params=["query"],
            ),
        ]

        for t in templates:
            registry.register(t)

        return registry
