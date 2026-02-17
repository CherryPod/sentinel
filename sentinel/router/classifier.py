"""Qwen-based request classifier for the fast-path router.

Classifies user messages as either FAST (matching a known template) or
PLANNER (requiring the full Claude planning pipeline). Every failure mode
falls back to PLANNER — Qwen is untrusted and the planner is always safe.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from sentinel.core.config import settings
from sentinel.router.templates import TemplateRegistry

logger = logging.getLogger(__name__)

# Phrases that short-circuit to planner without calling Qwen
_PLANNER_OVERRIDE_PHRASES = [
    "use the planner",
    "plan this",
    "think about this",
]

# Regex to strip Qwen thinking blocks
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

# Regex to extract JSON from prose (e.g. markdown code fences or inline).
# Supports up to 2 levels of brace nesting (route > params > nested value).
_JSON_EXTRACT_RE = re.compile(
    r"\{[^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*\}"
)

_SYSTEM_PROMPT_TEMPLATE = """\
You are a request classifier. Analyse the user's message and return JSON.
If the request maps to a single template, return the route as "fast" with extracted parameters.
If the request is complex, ambiguous, or multi-step, return "planner".
When uncertain, ALWAYS return "planner" — it is the safe default.
If the user explicitly asks to "use the planner", "plan this", or "think about this", ALWAYS return "planner" regardless of complexity.

Current date/time: {now}

{templates}

Respond with ONLY valid JSON, no other text.

Format for fast route:
{{"route": "fast", "template": "<name>", "params": {{...}}}}

Format for planner route:
{{"route": "planner", "reason": "<why>"}}\
"""


class Route(Enum):
    """Classification outcome — fast path or full planner."""
    FAST = "fast"
    PLANNER = "planner"


@dataclass
class ClassificationResult:
    """Result of classifying a user message."""
    route: Route
    template_name: str | None = None
    params: dict = field(default_factory=dict)
    reason: str = ""

    @property
    def is_fast(self) -> bool:
        return self.route == Route.FAST

    @property
    def is_planner(self) -> bool:
        return self.route == Route.PLANNER


def _planner_fallback(reason: str) -> ClassificationResult:
    """Convenience: build a planner-fallback result."""
    return ClassificationResult(route=Route.PLANNER, reason=reason)


class Classifier:
    """Classifies user messages using Qwen via the OllamaWorker.

    Every error path falls back to the planner — classify() never raises.
    """

    def __init__(
        self,
        worker,
        registry: TemplateRegistry,
        timeout: float | None = None,
    ) -> None:
        self._worker = worker
        self._registry = registry
        self._timeout = timeout if timeout is not None else settings.router_classifier_timeout

    async def classify(self, user_message: str) -> ClassificationResult:
        """Classify a user message as FAST or PLANNER.

        Never raises — all errors produce a planner fallback.
        """
        # Short-circuit: planner override phrases. Uses word-boundary match
        # with negation guard to avoid false positives like "don't use the
        # planner" triggering the override.
        msg_lower = user_message.lower()
        for phrase in _PLANNER_OVERRIDE_PHRASES:
            # Find all occurrences and check none are preceded by negation
            for m in re.finditer(r"\b" + re.escape(phrase) + r"\b", msg_lower):
                # Check for negation words immediately before the match
                prefix = msg_lower[:m.start()].rstrip()
                if prefix.endswith(("not", "don't", "dont", "no", "never")):
                    continue
                logger.debug("Planner override phrase detected: %r", phrase)
                return _planner_fallback(f"User requested planner: '{phrase}'")

        # Build the system prompt with current time and template listing
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
            now=now,
            templates=self._registry.build_classifier_prompt(),
        )

        # Call Qwen via the worker
        try:
            raw_response, _ = await asyncio.wait_for(
                self._worker.generate(
                    user_message,
                    system_prompt=system_prompt,
                ),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Classifier timed out after %.1fs", self._timeout)
            return _planner_fallback("Worker timeout — falling back to planner")
        except Exception:
            logger.exception("Classifier worker error")
            return _planner_fallback("Worker error — falling back to planner")

        # Parse the response
        return self._parse_response(raw_response)

    def _parse_response(self, raw: str) -> ClassificationResult:
        """Parse Qwen's JSON response into a ClassificationResult.

        Strips thinking tags, tries direct JSON parse, then regex extraction.
        """
        # Strip <think>...</think> blocks
        cleaned = _THINK_RE.sub("", raw).strip()

        # Try direct JSON parse
        data = self._try_parse_json(cleaned)

        # If that failed, try regex extraction
        if data is None:
            match = _JSON_EXTRACT_RE.search(cleaned)
            if match:
                data = self._try_parse_json(match.group())

        if data is None:
            return _planner_fallback("Failed to parse classifier response as JSON")

        return self._interpret(data)

    @staticmethod
    def _try_parse_json(text: str) -> dict | None:
        """Attempt JSON parse, return None on failure."""
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    def _interpret(self, data: dict) -> ClassificationResult:
        """Interpret a parsed JSON dict into a ClassificationResult."""
        route_str = data.get("route", "").lower()

        # Planner route
        if route_str == "planner":
            return _planner_fallback(data.get("reason", "Qwen chose planner"))

        # Fast route — validate template and params
        if route_str != "fast":
            return _planner_fallback(f"Unknown route value: {route_str!r}")

        template_name = data.get("template", "")
        template = self._registry.get(template_name)

        if template is None:
            return _planner_fallback(
                f"Unknown template '{template_name}' — falling back to planner"
            )

        raw_params = data.get("params", {})
        if not isinstance(raw_params, dict):
            raw_params = {}

        # Resolve aliases before validation
        resolved_params = template.resolve_aliases(raw_params)

        # Validate required params
        if not template.validate_params(resolved_params):
            missing = [p for p in template.required_params if p not in resolved_params]
            return _planner_fallback(
                f"Missing required param(s) {missing} for template '{template_name}'"
            )

        return ClassificationResult(
            route=Route.FAST,
            template_name=template_name,
            params=resolved_params,
        )
