import asyncio
import logging
import random
import time

import anthropic

from sentinel.core.config import settings
from sentinel.core.models import Plan
from sentinel.planner._plan_validator import (
    _raise_plan_validation,
    auto_infer_constraints,
    infer_constraints,
    log_plan_details,
    validate_plan,
)
from sentinel.planner._prompt_builder import (
    build_system_block,
    build_system_prompt,
    build_user_content,
    call_judge,
    format_enriched_history,
    prune_history,
)
from sentinel.planner._response_parser import (
    looks_like_refusal,
    parse_plan_json,
    repair_truncated_json,
    strip_response_markup,
)
from sentinel.worker.base import PlannerBase

logger = logging.getLogger(__name__)

# Backward-compatible re-export — used by tests/test_planner_json_repair.py
_repair_truncated_json = repair_truncated_json

# Backward-compatible re-export — assembled from _prompts/ package.
# Tests check content presence; the {tool_descriptions} placeholder is intact.
from sentinel.planner._prompts.general import SECTIONS as _SECTIONS

_PLANNER_SYSTEM_PROMPT_TEMPLATE = "\n\n".join(_SECTIONS)

del _SECTIONS  # clean up module namespace

# Standard error categories for monitoring/alerting classification.
# "security"     — policy blocks, refusals, scan violations
# "upstream_api" — Claude API errors, timeouts, overload
# "validation"   — malformed plans, schema violations, bad input
# "internal"     — bugs, unexpected state
# "resource"     — missing files, config, infra unavailable
ERROR_CATEGORIES = frozenset(
    {"security", "upstream_api", "validation", "internal", "resource"}
)

# Exception classes moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import (  # noqa: E402
    PlannerError,
    PlannerRefusalError,
    PlanValidationError,
)


class ClaudePlanner(PlannerBase):
    """Claude API client that generates structured execution plans."""

    def __init__(self, api_key: str | None = None):
        logger.debug(
            "ClaudePlanner initialising",
            extra={"event": "planner.init", "has_api_key": api_key is not None},
        )
        self._api_key = api_key or self._load_api_key()
        self._client = anthropic.AsyncAnthropic(
            api_key=self._api_key,
            timeout=settings.claude_timeout,
        )
        # Token usage from the most recent create_plan() call (None until first call)
        self._last_usage: dict | None = None

    # Delegate to module-level functions in _plan_validator
    _infer_constraints = staticmethod(infer_constraints)

    @staticmethod
    def _load_api_key() -> str:
        logger.debug(
            "_load_api_key called",
            extra={"event": "load.api_key"},
        )
        try:
            with open(settings.claude_api_key_file) as f:
                key = f.read().strip()
            logger.debug(
                "_load_api_key succeeded",
                extra={"event": "load.api_key_done"},
            )
            return key
        except FileNotFoundError:
            raise PlannerError(
                f"Claude API key file not found: {settings.claude_api_key_file}",
                category="resource",
            )
        except OSError as exc:
            raise PlannerError(
                f"Cannot read API key file: {exc}", category="resource"
            ) from exc

    # Delegate to module-level functions in _prompt_builder
    _build_system_prompt = staticmethod(build_system_prompt)
    _build_system_block = staticmethod(build_system_block)
    _build_user_content = staticmethod(build_user_content)
    _format_enriched_history = staticmethod(format_enriched_history)
    prune_history = staticmethod(prune_history)

    # Delegate to module-level functions in _response_parser
    _strip_response_markup = staticmethod(strip_response_markup)
    _parse_plan_json = staticmethod(parse_plan_json)
    _looks_like_refusal = staticmethod(looks_like_refusal)

    async def _call_claude_api(
        self, system: list[dict], user_content: str, attempt: int
    ) -> object:
        """Make a single Claude API call, classifying errors for retry.

        Returns the API response on success.
        Raises PlannerError with retryable=True for transient errors (timeout,
        connection, overload).
        Raises PlannerError with retryable=False for fatal errors.
        """
        logger.debug(
            "_call_claude_api called",
            extra={
                "event": "call.claude_api",
                "model_name": settings.claude_model,
                "attempt": attempt + 1,
                "max_tokens": settings.claude_max_tokens,
            },
        )
        try:
            response = await self._client.messages.create(
                model=settings.claude_model,
                max_tokens=settings.claude_max_tokens,
                system=system,
                messages=[{"role": "user", "content": user_content}],
            )
        except anthropic.APIConnectionError as exc:
            logger.warning(
                "Claude API connection error",
                extra={
                    "event": "planner.connect_error",
                    "attempt": attempt + 1,
                    "error": str(exc),
                },
            )
            raise PlannerError(
                f"Cannot connect to Claude API: {exc}",
                retryable=True,
                category="upstream_api",
            ) from exc
        except anthropic.APITimeoutError as exc:
            logger.warning(
                "Claude API timeout",
                extra={
                    "event": "planner.timeout",
                    "attempt": attempt + 1,
                    "timeout_s": settings.claude_timeout,
                },
            )
            raise PlannerError(
                f"Claude API timed out: {exc}",
                retryable=True,
                category="upstream_api",
            ) from exc
        except anthropic.APIStatusError as exc:
            if exc.status_code == 529:
                logger.warning(
                    "Claude API overloaded (529), retrying",
                    extra={"event": "planner.overloaded", "attempt": attempt + 1},
                )
                raise PlannerError(
                    f"Claude API overloaded: {exc.message}",
                    retryable=True,
                    category="upstream_api",
                ) from exc
            logger.exception(
                "Claude API status error",
                extra={
                    "event": "planner.api_error",
                    "status_code": exc.status_code,
                    "error_message": exc.message,
                },
            )
            raise PlannerError(
                f"Claude API error {exc.status_code}: {exc.message}",
                category="upstream_api",
            ) from exc
        logger.debug(
            "_call_claude_api succeeded",
            extra={
                "event": "call.claude_api_done",
                "attempt": attempt + 1,
                "model_name": settings.claude_model,
            },
        )
        return response

    def _extract_response_text(
        self, response: object, elapsed_s: float, attempt_num: int
    ) -> str:
        """Extract text content from API response and log usage metrics.

        Concatenates all text blocks from the response, records token usage
        (including prompt caching stats), and logs timing information.
        """
        logger.debug(
            "_extract_response_text called",
            extra={
                "event": "extract.response_text",
                "elapsed_s": round(elapsed_s, 2),
                "attempt": attempt_num,
            },
        )
        raw_text = ""
        try:
            for block in getattr(response, "content", None) or []:
                if getattr(block, "type", None) == "text":
                    raw_text += getattr(block, "text", "") or ""
        except TypeError:
            logger.warning(
                "Unexpected content type in Claude response, treating as empty",
                extra={
                    "event": "planner.content_type_error",
                    "attempt": attempt_num,
                },
            )
            raw_text = ""

        usage = getattr(response, "usage", None)
        self._last_usage = {
            "input_tokens": getattr(usage, "input_tokens", None) if usage else None,
            "output_tokens": getattr(usage, "output_tokens", None) if usage else None,
            "cache_creation_input_tokens": getattr(
                usage, "cache_creation_input_tokens", None
            )
            if usage
            else None,
            "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", None)
            if usage
            else None,
        }
        logger.info(
            "Claude API response received",
            extra={
                "event": "planner.response",
                "elapsed_s": round(elapsed_s, 2),
                "attempt": attempt_num,
                **{k: v for k, v in self._last_usage.items() if v is not None},
                "response_length": len(raw_text),
            },
        )
        return raw_text

    async def create_plan(
        self,
        user_request: str,
        available_tools: list[dict] | None = None,
        policy_summary: str = "",
        conversation_history: list[dict] | None = None,
        cross_session_context: str = "",
        interrupted_context: str = "",
        max_history_turns: int = 0,
        session_files_context: str = "",
        prior_vars: set[str] | None = None,
    ) -> Plan:
        """Ask Claude to produce a structured Plan for the given request."""
        system = self._build_system_block(available_tools, policy_summary)
        user_content = self._build_user_content(
            user_request=user_request,
            conversation_history=conversation_history,
            max_history_turns=max_history_turns,
            cross_session_context=cross_session_context,
            interrupted_context=interrupted_context,
            session_files_context=session_files_context,
        )

        logger.info(
            "Sending plan request to Claude",
            extra={
                "event": "planner.request",
                "model": settings.claude_model,
                "request_preview": user_request[:200],
            },
        )

        max_attempts = (
            3  # initial + 2 retries (covers API errors AND empty/invalid responses)
        )
        last_error: Exception | None = None
        plan_data: dict | None = None
        retry_categories: list[str] = []  # #19 MED: track what consumed each attempt
        t0 = time.monotonic()

        for attempt in range(max_attempts):
            # #20 MED: exponential backoff with jitter and cap
            if attempt > 0:
                delay = min(2**attempt, 10) + random.uniform(0, 1)
                await asyncio.sleep(delay)

            # ── Step 1: API call ──
            try:
                response = await self._call_claude_api(system, user_content, attempt)
            except PlannerError as exc:
                logger.debug(
                    "create_plan: API call error",
                    extra={
                        "event": "create.plan_api_error",
                        "error": str(exc),
                        "error_category": exc.category,
                        "error_class": "transient" if exc.retryable else "permanent",
                    },
                )
                if exc.retryable and attempt < max_attempts - 1:
                    retry_categories.append(exc.category)
                    last_error = exc
                    continue
                if exc.retryable:
                    retry_categories.append(exc.category)
                raise

            api_elapsed = time.monotonic() - t0
            raw_text = self._extract_response_text(response, api_elapsed, attempt + 1)

            # ── Step 2: Empty response — retry before giving up ──
            if not raw_text.strip():
                stop = getattr(response, "stop_reason", None)
                if attempt < max_attempts - 1:
                    logger.warning(
                        "Claude returned empty response, retrying",
                        extra={
                            "event": "planner.empty_retry",
                            "attempt": attempt + 1,
                            "stop_reason": stop,
                        },
                    )
                    last_error = PlannerError("Claude returned empty response")
                    retry_categories.append("empty_response")
                    continue
                logger.info(
                    "Claude returned empty response — classifying as planner refusal",
                    extra={
                        "event": "planner.refusal",
                        "stop_reason": stop,
                    },
                )
                raise PlannerRefusalError(
                    "Claude returned empty response (planner refusal)"
                )

            # ── Step 3: Strip markup and parse JSON ──
            cleaned = self._strip_response_markup(raw_text)

            try:
                plan_data = self._parse_plan_json(
                    cleaned, last_attempt=(attempt >= max_attempts - 1)
                )
                break  # success — exit retry loop
            except PlannerRefusalError:
                raise  # never retry refusals (already logged in _parse_plan_json)
            except PlannerError as exc:
                # Invalid JSON — retry if attempts remain
                if attempt < max_attempts - 1:
                    logger.warning(
                        "Claude returned invalid JSON, retrying",
                        extra={
                            "event": "planner.json_retry",
                            "attempt": attempt + 1,
                            "json_error": str(exc),
                            "response_preview": cleaned[:200],
                        },
                    )
                    last_error = exc
                    retry_categories.append("invalid_json")
                    continue
                # #19 MED: log which categories consumed the retry budget
                logger.warning(
                    "All planner retries exhausted",
                    extra={
                        "event": "planner.retries_exhausted",
                        "retry_categories": retry_categories,
                        "max_attempts": max_attempts,
                    },
                )
                raise
        else:
            # #19 MED: log which categories consumed the retry budget
            logger.warning(
                "All planner retries exhausted",
                extra={
                    "event": "planner.retries_exhausted",
                    "retry_categories": retry_categories,
                    "max_attempts": max_attempts,
                },
            )
            raise last_error  # type: ignore[misc]

        return self._finalize_plan(plan_data, available_tools, prior_vars)

    def _finalize_plan(
        self,
        plan_data: dict,
        available_tools: list[dict] | None,
        prior_vars: set[str] | None,
    ) -> Plan:
        """Construct, validate, and enrich a Plan from parsed JSON data.

        Builds the Plan model, runs structural validation against available
        tools and prior variables, auto-infers constraints at TL4+, and
        logs detailed step information.
        """
        logger.debug(
            "_finalize_plan called",
            extra={
                "event": "finalize.plan",
                "has_available_tools": available_tools is not None
                and len(available_tools) > 0,
                "has_prior_vars": prior_vars is not None and len(prior_vars) > 0,
            },
        )
        try:
            plan = Plan(**plan_data)
        except (TypeError, KeyError, ValueError) as exc:
            _raise_plan_validation(
                code="Plan does not match expected schema",
                pydantic_error_class=type(exc).__name__,
                pydantic_error_text=str(exc),
            )

        tool_names: set[str] | None = None
        if available_tools:
            tool_names = {t["name"] for t in available_tools if "name" in t}
        logger.debug(
            "_finalize_plan decision: tool validation",
            extra={
                "event": "finalize.plan_decision",
                "tool_names_provided": tool_names is not None,
                "tool_names_count": len(tool_names) if tool_names else 0,
            },
        )
        self._validate_plan(
            plan, available_tool_names=tool_names, prior_vars=prior_vars
        )

        # D5: At TL4+, auto-infer constraints on tool_call steps if missing.
        logger.debug(
            "_finalize_plan decision: auto-infer constraints",
            extra={
                "event": "finalize.plan_decision",
                "will_auto_infer": settings.trust_level >= 4,
                "trust_level": settings.trust_level,
            },
        )
        self._auto_infer_constraints(plan)

        self._log_plan_details(plan)
        logger.debug(
            "_finalize_plan done",
            extra={
                "event": "finalize.plan_done",
                "plan_step_count": len(plan.steps),
                "plan_summary_len": (
                    len(plan.plan_summary) if plan.plan_summary else 0
                ),
            },
        )
        return plan

    # Delegate to module-level functions in _plan_validator
    _log_plan_details = staticmethod(log_plan_details)
    _validate_plan = staticmethod(validate_plan)
    _auto_infer_constraints = staticmethod(auto_infer_constraints)

    async def verify_goal(self, judge_prompt: str) -> dict:
        """Invoke the planner as a verification judge.

        Thin wrapper — delegates to call_judge() in _prompt_builder.
        """
        return await call_judge(self._client, judge_prompt)
