"""Response parsing utilities for the planner.

Extracts and validates JSON plan data from Claude API responses.
Handles code fence stripping, preamble removal, refusal detection,
and truncated JSON repair.
"""

import json
import logging
import re

from sentinel.core.exceptions import PlannerError, PlannerRefusalError

logger = logging.getLogger(__name__)


# #22 LOW: single compiled alternation instead of 16 separate patterns
_REFUSAL_PATTERN: re.Pattern[str] = re.compile(
    r"\b("
    r"i cannot|i can't|i'm sorry|i apologize|i'm unable|i am unable|"
    r"i must decline|i won't|i will not|cannot assist|not able to|"
    r"refuse|inappropriate|against my|violates|harmful"
    r")\b",
    re.IGNORECASE,
)


def looks_like_refusal(text: str) -> bool:
    """Heuristic: does this non-JSON text look like Claude refusing?"""
    return bool(_REFUSAL_PATTERN.search(text))


def repair_truncated_json(text: str) -> str | None:
    """Attempt to repair truncated JSON by closing open structures.

    Returns repaired JSON string if successful, None if hopeless.
    Only called after json.loads() has already failed.

    Security (#1 HIGH): rejects repairs where truncation occurred inside a
    string value — closing an open string mechanically can produce valid JSON
    with semantically corrupted content (e.g. a mangled prompt or path that
    passes structural validation but carries unintended instructions).
    """
    logger.debug(
        "repair_truncated_json called",
        extra={"event": "repair.truncated_json", "text_len": len(text)},
    )
    # Must look like JSON
    stripped = text.strip()
    if not stripped or stripped[0] not in ("{", "["):
        return None

    # Single-pass: track string state and bracket depth simultaneously (#6 MED)
    in_string = False
    stack: list[str] = []
    i = 0
    while i < len(stripped):
        c = stripped[i]
        if c == "\\" and in_string:
            i += 2
            continue
        if c == '"':
            in_string = not in_string
        elif not in_string:
            if c in ("{", "["):
                stack.append(c)
            elif c in ("}", "]") and stack:
                stack.pop()
        i += 1

    # #1 HIGH: truncation inside a string value is semantically dangerous —
    # the closed string could contain a mangled prompt, path, or command.
    # Reject rather than silently produce corrupted content.
    if in_string:
        logger.warning(
            "JSON repair rejected — truncation inside string value",
            extra={
                "event": "planner.json_repair_rejected",
                "reason": "truncated_inside_string",
                "text_length": len(stripped),
            },
        )
        return None

    repaired = stripped

    # Remove trailing comma (invalid before closing bracket)
    repaired = repaired.rstrip()
    repaired = repaired.removesuffix(",")

    # Close remaining open structures in reverse order
    for opener in reversed(stack):
        repaired += "}" if opener == "{" else "]"

    try:
        json.loads(repaired)
        logger.debug(
            "Truncated JSON repaired successfully",
            extra={
                "event": "planner.repairjson.success",
                "repaired_len": len(repaired),
            },
        )
        return repaired
    except json.JSONDecodeError:
        logger.exception(
            "repair_truncated_json: json.JSONDecodeError",
            extra={"event": "planner.repair_truncated_json_jsondecodeerror"},
        )
        return None


def strip_response_markup(raw_text: str) -> str:
    """Strip code fences and preamble text from the API response.

    Handles three cases:
    1. Response wrapped in ```json ... ``` fences
    2. Reasoning preamble before the JSON plan object
    3. Trailing ``` left after preamble stripping
    """
    logger.debug(
        "Stripping response markup",
        extra={
            "event": "strip.response_markup",
            "raw_length": len(raw_text),
        },
    )

    cleaned = raw_text.strip()

    # Strip leading code fence (```json or ```)
    has_code_fence = cleaned.startswith("```")
    logger.debug(
        "strip_response_markup decision: code fence",
        extra={
            "event": "strip.response_markup_decision",
            "has_code_fence": has_code_fence,
        },
    )
    if has_code_fence:
        logger.debug(
            "strip_response_markup: has_code_fence",
            extra={
                "event": "planner.strip_response_markup.match",
                "reason": "has_code_fence",
            },
        )
        first_newline = cleaned.find("\n")
        if first_newline == -1:
            logger.debug(
                "strip_response_markup: first_newline_eq",
                extra={
                    "event": "planner.strip_response_markup.match",
                    "reason": "first_newline_eq",
                },
            )
            cleaned = cleaned[3:].lstrip()
        else:
            logger.debug(
                "strip_response_markup: first_newline_eq",
                extra={
                    "event": "planner.strip_response_markup.clean",
                    "reason": "first_newline_eq",
                },
            )
            cleaned = cleaned[first_newline + 1 :]
        # Strip closing fence paired with the opening
        if cleaned.rstrip().endswith("```"):
            logger.debug(
                "strip_response_markup: endswith_```",
                extra={
                    "event": "planner.strip_response_markup.match",
                    "reason": "endswith_```",
                },
            )
            cleaned = cleaned.rstrip()[:-3].rstrip()

    # Extract JSON plan from preamble text — Sonnet 4.6 and Opus 4.6
    # emit reasoning text before the JSON plan. Find the plan object
    # by looking for the first '{' that starts a plan structure.
    if cleaned and not cleaned.startswith("{"):
        plan_start = -1
        search_from = 0
        while True:
            idx = cleaned.find("{", search_from)
            if idx == -1:
                break
            lookahead = cleaned[idx : idx + 200]
            if (
                '"summary"' in lookahead
                or '"plan_summary"' in lookahead
                or '"steps"' in lookahead
            ):
                plan_start = idx
                break
            search_from = idx + 1

        if plan_start != -1:
            preamble = cleaned[:plan_start].strip()
            cleaned = cleaned[plan_start:]
            logger.info(
                "Stripped preamble text before JSON plan",
                extra={
                    "event": "planner.preamble_strip",
                    "preamble_length": len(preamble),
                    "preamble_preview": preamble[:200],
                },
            )

    # Strip trailing fence left after preamble extraction
    if cleaned.rstrip().endswith("```"):
        logger.debug(
            "strip_response_markup: endswith_```",
            extra={
                "event": "planner.strip_response_markup.match",
                "reason": "endswith_```",
            },
        )
        cleaned = cleaned.rstrip()[:-3].rstrip()

    logger.debug(
        "Response markup stripped",
        extra={
            "event": "strip.response_markup_done",
            "cleaned_length": len(cleaned),
        },
    )
    return cleaned


def parse_plan_json(cleaned_text: str, *, last_attempt: bool = False) -> dict:
    """Parse cleaned response text into a plan dict.

    Returns the parsed dict on success (including after JSON repair).
    Raises PlannerRefusalError for refusals (never retry).
    Raises PlannerError for invalid JSON (caller decides retry).

    JSON repair is a last resort — only attempted when last_attempt=True
    so the system prefers a fresh complete response over a mechanically
    repaired one.
    """
    logger.debug(
        "parse_plan_json called",
        extra={
            "event": "parse.plan_json",
            "text_len": len(cleaned_text),
            "last_attempt": last_attempt,
        },
    )
    try:
        result = json.loads(cleaned_text)
        logger.debug(
            "parse_plan_json succeeded on first try",
            extra={"event": "parse.plan_json_first_try"},
        )
        return result
    except json.JSONDecodeError as exc:
        # Refusals are intentional — never retry
        if looks_like_refusal(cleaned_text):
            logger.info(
                "Claude returned non-JSON refusal",
                extra={
                    "event": "planner.refusal",
                    "response_preview": cleaned_text[:200],
                },
            )
            raise PlannerRefusalError(f"Planner refusal: {cleaned_text[:200]}") from exc

        # JSON repair is a last resort — only on the final attempt so we
        # prefer a fresh retry over accepting a mechanically repaired plan
        if last_attempt:
            repaired = repair_truncated_json(cleaned_text)
            if repaired is not None:
                try:
                    result = json.loads(repaired)
                    logger.warning(
                        "Repaired truncated JSON from Claude",
                        extra={
                            "event": "planner.json_repaired",
                            "original_len": len(cleaned_text),
                            "repaired_len": len(repaired),
                        },
                    )
                    return result
                except json.JSONDecodeError:
                    logger.debug(
                        "JSON repair attempt also failed",
                        extra={"event": "planner.json_repair_failed"},
                    )

        # Signal parse failure — caller decides whether to retry
        raise PlannerError(
            f"Claude returned invalid JSON: {exc}",
            retryable=True,
            category="validation",
        ) from exc
