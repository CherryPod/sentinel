"""Deterministic keyword/regex classifier for the fast-path router.

Replaces the Qwen-based classifier with ordered regex patterns that match
user messages against fast-path templates. Zero GPU, microseconds, deterministic.

Routing logic:
- Multi-step signals ("and then", "after that") -> planner
- Planner override phrases ("use the planner") -> planner
- 0 pattern matches -> planner
- 1 pattern match -> attempt param extraction -> fast path (or planner if fails)
- 2+ unique template matches -> planner (multi-step request)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sentinel.router.classifier import ClassificationResult, Route
from sentinel.router.templates import TemplateRegistry

logger = logging.getLogger(__name__)

# Phrases that short-circuit to planner without pattern matching
_PLANNER_OVERRIDE_PHRASES = [
    "use the planner",
    "plan this",
    "think about this",
]

# Multi-step signals — if any of these appear, go straight to planner
_MULTI_STEP_SIGNALS = [
    r"\band then\b",
    r"\bafter that\b",
    r"\band also\b",
    r"\bonce that'?s done\b",
    r"\bfollowed by\b",
    r"\bthen send\b",
    r"\bthen email\b",
    r"\bthen message\b",
    r"\bfirst\b.+\bthen\b",
    r"\bas well as\b",
    r",\s*also\b",
    r"\bboth\b.+\band\b.+\b(?:email|signal|telegram|calendar)\b",
]

# Generative/creative intent — these verbs route to planner UNLESS
# the rest of the message matches a known template keyword (email, event, etc.)
# This prevents "create an event handler in JavaScript" from hitting calendar_add
# and "write a poem about the weather" from hitting web_search.
_GENERATIVE_VERBS_RE = re.compile(
    r"\b(?:write|compose|create|build|make|generate|design|develop|code|implement|add|update|modify|change|remove|delete)\b",
    re.IGNORECASE,
)
# Messages starting with "how to" or "how do i" are informational (web search),
# not generative, even if they contain verbs like "make" or "build"
_HOW_TO_PREFIX_RE = re.compile(
    r"^\s*how\s+(?:to|do\s+i|can\s+i)\b",
    re.IGNORECASE,
)
_GENERATIVE_TEMPLATE_EXCEPTIONS = re.compile(
    r"\b(?:(?:send\s+(?:a\s+|an\s+)?)?email\s+(?:to|about|saying)|draft\s+(?:a\s+|an\s+)?email|write\s+(?:a\s+|an\s+)?email|event\s+(?:for|on|at|today|tonight|tomorrow|next|friday|monday|tuesday|wednesday|thursday|saturday|sunday)|reminder)\b",
    re.IGNORECASE,
)
_MULTI_STEP_RE = re.compile("|".join(_MULTI_STEP_SIGNALS), re.IGNORECASE)


def _planner_fallback(reason: str) -> ClassificationResult:
    """Convenience: build a planner-fallback result."""
    return ClassificationResult(route=Route.PLANNER, reason=reason)


@dataclass
class _PatternEntry:
    """A single pattern-to-template mapping with optional param extraction."""
    pattern: re.Pattern
    template_name: str
    param_extractor: str | None = None  # regex group name or callable hint


# ---------------------------------------------------------------------------
# Pattern definitions — ORDER MATTERS (specific before general)
# ---------------------------------------------------------------------------

def _build_patterns() -> list[_PatternEntry]:
    """Build the ordered pattern list.

    Rules:
    - More specific patterns come first to avoid false matches
    - Each pattern uses re.IGNORECASE
    - Patterns should match natural English phrasing
    - param_extractor names a capture group whose content becomes the query
    """
    entries = []

    def add(pattern: str, template: str, extractor: str | None = None):
        entries.append(_PatternEntry(
            pattern=re.compile(pattern, re.IGNORECASE),
            template_name=template,
            param_extractor=extractor,
        ))

    # ---- calendar_add (before calendar_read — "add/create" is more specific) ----
    add(r"\badd\b.+\bto\b.+\bcalendar\b", "calendar_add")
    add(r"\bput\b.+\bin\b.+\bcalendar\b", "calendar_add")
    add(r"\bschedule\s+(?:a|an|the)\s+(?:meeting|call|appointment|session|event)\b", "calendar_add")
    add(r"\bbook\s+(?:a|an|the)\b.+\bmeeting\b", "calendar_add")
    add(r"\bcreate\s+(?:a|an)\s+(?:calendar\s+)?event\s+(?:for|on|at|tomorrow)\b", "calendar_add")
    add(r"\bnew\s+event\b", "calendar_add")
    add(r"\bset\s+(?:a\s+)?reminder\b", "calendar_add")
    add(r"\bremind\s+me\b", "calendar_add")
    # Requires time-ish context to avoid "block the user from accessing the API"
    add(r"\bblock\s+(?:out|time)\b.+\b(?:for|from|at)\s+\w", "calendar_add")

    # ---- calendar_read ----
    add(r"(?<!to )(?<!in )\bmy\s+calendar\b", "calendar_read")
    add(r"\bmy\s+schedule\b", "calendar_read")
    add(r"\bam\s+i\s+free\b", "calendar_read")
    add(r"\bwhat(?:'s|\s+is)\s+on\s+(?:my\s+)?calendar\b", "calendar_read")
    add(r"\bupcoming\s+events?\b", "calendar_read")
    add(r"\bany\s+meetings?\b", "calendar_read")
    add(r"\bmeetings?\s+(?:today|tomorrow|this\s+week|next\s+week)\b", "calendar_read")
    add(r"\bcalendar\s+(?:for\s+)?(?:today|tomorrow|this\s+week|next\s+week)\b", "calendar_read")
    add(r"\bdo\s+i\s+have\s+anything\s+(?:on|for|this|tomorrow|today)\b", "calendar_read")
    add(r"\bwhat(?:'s|\s+is)\s+happening\s+(?:this|today|tomorrow|on)\b", "calendar_read")
    add(r"\b(?:my\s+)?next\s+meeting\b", "calendar_read")
    add(r"\bwhen\s+is\s+my\s+next\s+meeting\b", "calendar_read")
    add(r"\bwhen(?:'s|\s+is)\s+my\s+next\s+(?:meeting|event|appointment|call)\b", "calendar_read")

    # ---- email_send (before email_search — "send/draft/write/forward" is more specific) ----
    add(r"\bsend\s+(?:a\s+|an\s+)?email\b", "email_send")
    add(r"\bemail\s+\w+\s+(?:about|saying|to\s+say)\b", "email_send")
    add(r"\breply\s+to\b.+\bemail\b", "email_send")
    add(r"\bforward\b.+\bemail\b", "email_send")
    add(r"\bdraft\s+(?:a\s+|an\s+)?email\b", "email_send")
    add(r"\bwrite\s+(?:a\s+|an\s+)?email\b", "email_send")

    # ---- email_search (after email_send — "search/find" is the key differentiator) ----
    add(r"\bsearch\s+(?:my\s+)?emails?\s+(?:for\s+)?(?P<query>.+)", "email_search", "query")
    add(r"\bfind\s+(?:my\s+)?emails?\s+(?:from|about|to)\s+(?P<query>.+)", "email_search", "query")
    # Standalone "emails from/about/to" — but only when not preceded by send-intent.
    # The send patterns above already captured "send an email to", "email X about",
    # so if we reach here, it's a genuine search intent like "emails from John".
    add(r"^emails?\s+(?:from|about|to)\s+(?P<query>.+)", "email_search", "query")

    # ---- email_read ----
    add(r"\b(?:my\s+)?(?:last|latest|recent|newest)\s+emails?\b", "email_read")
    add(r"\bcheck\s+(?:my\s+)?emails?\b", "email_read")
    add(r"\bread\s+(?:my\s+)?emails?\b", "email_read")
    add(r"\bany\s+(?:new|unread)\s+emails?\b", "email_read")
    add(r"\bunread\s+emails?\b", "email_read")
    add(r"\bwhat\s+did\b.+\bemail\b", "email_read")
    add(r"\b(?:my\s+)?inbox\b", "email_read")
    add(r"\bopen\s+(?:my\s+)?emails?\b", "email_read")

    # ---- signal_send ----
    add(r"\b(?:send|text|message)\b.+\b(?:on|via|over)\s+signal\b", "signal_send")
    add(r"\bsignal\s+\w+\s+saying\b", "signal_send")

    # ---- telegram_send ----
    add(r"\b(?:send|text|message)\b.+\b(?:on|via|over)\s+telegram\b", "telegram_send")
    add(r"\btelegram\s+\w+\s+saying\b", "telegram_send")

    # NOTE: signal_send and telegram_send param extraction is handled by
    # _extract_messaging_params() in the classify() method, not by regex
    # capture groups. The patterns above are for intent matching only.

    # ---- x_search (before web_search — "twitter/X" is more specific) ----
    add(r"\bsearch\s+(?:on\s+)?(?:x|twitter)\s+(?:for\s+)?(?P<query>.+)", "x_search", "query")
    add(r"\b(?:what(?:'s|\s+is)\s+)?trending\s+on\s+(?:x|twitter)\b", "x_search")
    add(r"\btweets?\s+(?:about|on|from)\s+(?P<query>.+)", "x_search", "query")
    add(r"\bwhat\s+are\s+people\s+saying\b.+\bon\s+(?:x|twitter)\b", "x_search")
    add(r"\bposts?\s+(?:about|on)\b.+\bon\s+(?:x|twitter)\b", "x_search")

    # ---- web_search (LAST — most general, catches broad "search" intent) ----
    add(r"\b(?P<query>weather\s+(?:in|for|at)\s+.+)", "web_search", "query")
    add(r"\bwhat(?:'s|\s+is)\s+the\s+(?P<query>weather\b(?:\s+(?:in|for|at)\s+.+)?)", "web_search", "query")
    add(r"\bsearch\s+(?:the\s+web\s+)?for\s+(?!.*\b(?:twitter|x|email)\b)(?P<query>.+)", "web_search", "query")
    add(r"\blook\s+up\s+(?P<query>.+)", "web_search", "query")
    add(r"\bgoogle\s+(?P<query>.+)", "web_search", "query")
    add(r"\bhow\s+(?:do\s+i|to|can\s+i)\s+(?P<query>.+)", "web_search", "query")
    add(r"\bwhen\s+(?:is|did|does|was)\s+(?!my\s+next\s+(?:meeting|event|appointment|call)\b)(?P<query>.+)", "web_search", "query")
    add(r"\bwhy\s+(?:is|do|does|did|are)\s+(?P<query>.+)", "web_search", "query")
    add(r"\bdefine\s+(?P<query>.+)", "web_search", "query")
    add(r"\bmeaning\s+of\s+(?P<query>.+)", "web_search", "query")
    add(r"\bhow\s+much\s+(?:does|do|is)\b.+\b(?:cost|price)\b", "web_search")
    add(r"\bprice\s+of\s+(?P<query>.+)", "web_search", "query")
    add(r"\bwhat\s+is\s+(?!on\s+(?:my\s+)?(?:calendar|schedule)\b)(?!happening\s+(?:this|today|tomorrow|on)\b)(?P<query>.+)", "web_search", "query")
    add(r"\bwho\s+is\s+(?P<query>.+)", "web_search", "query")
    add(r"\bwhere\s+is\s+(?P<query>.+)", "web_search", "query")
    add(r"\b(?:latest\s+)?news\s+(?:on|about)\s+(?P<query>.+)", "web_search", "query")
    add(r"\bsearch\s+(?:for\s+)?(?!(?:on\s+)?(?:twitter|x)\b)(?!(?:my\s+)?emails?\b)(?P<query>.+)", "web_search", "query")

    return entries


# Regexes to extract recipient from messaging commands.
# Two patterns tried in order:
# 1. "to user N" / "to <Name>" — explicit recipient with "to"
# 2. "<verb> user N" / "<verb> <Name>" — recipient right after the action verb
#    (e.g., "message Sarah via signal", "text John on signal")
# Intake rewrites display names to "user N", but we handle both for robustness.
_MESSAGING_RECIPIENT_TO_RE = re.compile(
    r"\bto\s+(?P<recipient>(?:user\s+)?\w+)"
    r"(?:\s+(?:on|via|over)\s+(?:signal|telegram)\b)?",
    re.IGNORECASE,
)
_MESSAGING_RECIPIENT_VERB_RE = re.compile(
    r"\b(?:send|text|message)\s+"
    # Skip over optional short message content before the recipient
    # (e.g., "send hi to John" — "hi" is the message, not the recipient).
    # Only match here if the word right after the verb looks like a recipient:
    # "user N" pattern (from intake rewriting) or a capitalised name followed
    # by a channel designator.
    r"(?P<recipient>user\s+\d+)\b",
    re.IGNORECASE,
)

# Regex to extract message body from messaging commands.
# Looks for content after the action verb and before/after channel designator.
# Handles patterns like:
#   "send hello on signal"         → message="hello"
#   "send hello to Keith on signal" → message="hello"
#   "message Keith via signal saying I'm late" → message="I'm late"
#   "text Keith on signal hello"   → message="hello" (content after channel)
_MESSAGING_BODY_SAYING_RE = re.compile(
    r"\bsaying\s+(?P<body>.+)", re.IGNORECASE,
)


def _extract_messaging_params(msg: str, template_name: str) -> dict:
    """Extract recipient and message from a signal_send or telegram_send message.

    The keyword classifier patterns match intent but don't capture params.
    This function does the structured extraction, handling the various
    natural-language phrasings users might use.

    Returns a dict that may contain 'recipient' and/or 'message' keys.
    """
    params: dict[str, str] = {}

    # Determine the channel name for stripping from the message
    channel = "signal" if template_name == "signal_send" else "telegram"

    # Extract recipient — try "to user N"/"to Name" first, then "verb user N"
    recip_match = _MESSAGING_RECIPIENT_TO_RE.search(msg)
    if recip_match:
        recipient = recip_match.group("recipient").strip()
        # Don't treat the channel name itself as a recipient
        if recipient.lower() not in (channel, "signal", "telegram"):
            params["recipient"] = recipient
    if "recipient" not in params:
        # Fallback: "message user 1 via signal", "text user 2 on signal"
        verb_match = _MESSAGING_RECIPIENT_VERB_RE.search(msg)
        if verb_match:
            params["recipient"] = verb_match.group("recipient").strip()

    # Extract message body — try "saying ..." first (most explicit)
    saying_match = _MESSAGING_BODY_SAYING_RE.search(msg)
    if saying_match:
        params["message"] = saying_match.group("body").strip()
        return params

    # Otherwise, extract the content between the action verb and the
    # recipient/channel designator. Strategy: strip out known structural
    # parts and what remains is the message body.
    # Start by removing the channel designator ("on signal", "via telegram")
    body = re.sub(
        r"\b(?:on|via|over)\s+(?:signal|telegram)\b", "", msg, flags=re.IGNORECASE,
    ).strip()

    # Remove the action verb prefix ("send", "text", "message")
    body = re.sub(
        r"^\s*(?:send|text|message)\s+", "", body, flags=re.IGNORECASE,
    ).strip()

    # Remove the recipient phrase ("to user 1", "to Keith", or "user N" after verb)
    if "recipient" in params:
        # Strip "to <recipient>" pattern
        body = re.sub(
            r"\bto\s+" + re.escape(params["recipient"]),
            "", body, count=1, flags=re.IGNORECASE,
        ).strip()
        # Also strip bare "user N" if it appears right after the verb was removed
        body = re.sub(
            r"^" + re.escape(params["recipient"]) + r"\b",
            "", body, flags=re.IGNORECASE,
        ).strip()

    # Clean up any leftover whitespace or punctuation artifacts
    body = body.strip(" ,.-")

    if body:
        params["message"] = body

    return params


class KeywordClassifier:
    """Deterministic keyword classifier — drop-in replacement for the Qwen Classifier.

    Routes user messages to fast-path templates using regex pattern matching.
    Falls back to planner for anything ambiguous, multi-step, or unrecognised.
    """

    def __init__(self, registry: TemplateRegistry) -> None:
        self._registry = registry
        self._patterns = _build_patterns()

    async def classify(self, user_message: str) -> ClassificationResult:
        """Classify a user message as FAST or PLANNER.

        Same interface as the Qwen Classifier — never raises.
        """
        if not user_message or not user_message.strip():
            return _planner_fallback("Empty message")

        msg = user_message.strip()

        # 1. Planner override phrases
        msg_lower = msg.lower()
        for phrase in _PLANNER_OVERRIDE_PHRASES:
            # Negation-aware check (same logic as Qwen classifier)
            for m in re.finditer(r"\b" + re.escape(phrase) + r"\b", msg_lower):
                prefix = msg_lower[:m.start()].rstrip()
                if prefix.endswith(("not", "don't", "dont", "no", "never")):
                    continue
                logger.debug("Planner override phrase: %r", phrase)
                return _planner_fallback(f"User requested planner: '{phrase}'")

        # 2. Multi-step signals -> planner
        if _MULTI_STEP_RE.search(msg):
            logger.debug("Multi-step signal detected")
            return _planner_fallback("Multi-step request detected")

        # 2b. Generative/creative intent -> planner (unless template keyword present)
        # Catches "create an event handler in JS", "write a poem about weather",
        # "build me a website" etc. but allows "create an event for Friday",
        # "draft an email to John", "write an email saying..."
        if _GENERATIVE_VERBS_RE.search(msg):
            if not _HOW_TO_PREFIX_RE.search(msg) and not _GENERATIVE_TEMPLATE_EXCEPTIONS.search(msg):
                logger.debug("Generative intent without template keyword — planner")
                return _planner_fallback("Generative/creative request — needs planner")

        # 3. Pattern matching — collect all unique template matches
        matches: list[tuple[str, dict]] = []  # (template_name, params)
        seen_templates: set[str] = set()

        for entry in self._patterns:
            m = entry.pattern.search(msg)
            if m and entry.template_name not in seen_templates:
                seen_templates.add(entry.template_name)
                # Extract params if extractor is defined
                params = {}
                if entry.param_extractor:
                    try:
                        extracted = m.group(entry.param_extractor)
                        if extracted:
                            params["query"] = extracted.strip()
                    except (IndexError, re.error):
                        pass
                matches.append((entry.template_name, params))

        # 4. Route based on match count
        if not matches:
            logger.debug("No pattern match — planner fallback")
            return _planner_fallback("No template match")

        if len(matches) > 1:
            templates = [t for t, _ in matches]
            logger.debug("Multi-template match %s — planner fallback", templates)
            return _planner_fallback(
                f"Multiple templates matched ({', '.join(templates)}) — likely multi-step"
            )

        # Single match — validate template exists and params are sufficient
        template_name, params = matches[0]
        template = self._registry.get(template_name)

        if template is None:
            return _planner_fallback(f"Template '{template_name}' not in registry")

        # Messaging templates (signal_send, telegram_send) need structured
        # param extraction — recipient and message body from natural language.
        # This runs BEFORE the generic required-param fallback below.
        if template_name in ("signal_send", "telegram_send"):
            messaging_params = _extract_messaging_params(msg, template_name)
            params.update(messaging_params)

            # If the extracted message body contains contextual references
            # ("the link", "the website", "that URL", "the results") rather
            # than actual content, the fast-path can't resolve them — the
            # planner needs to look up the referenced resource first.
            extracted_body = messaging_params.get("message", "")
            if re.search(
                r"\bthe\s+(?:website|site|link|url|page|results?|report|file|output)\b"
                r"|\bthat\s+(?:link|url|page|site)\b",
                extracted_body,
                re.IGNORECASE,
            ):
                return _planner_fallback(
                    "Message contains contextual reference — planner needed to resolve"
                )

        # Check required params — fall back to planner if extraction failed.
        # For query-based templates, use the full message as fallback query.
        # For non-query templates (e.g. calendar_add with summary/start),
        # the keyword classifier can't extract structured params — pass the
        # raw message for downstream processing (Qwen param extraction step).
        if template.required_params and not template.validate_params(params):
            if "query" in template.required_params and "query" not in params:
                # For email_read (search+read chain), generic requests like
                # "check my email" should fetch recent mail, not search for
                # the literal user message. Use "*" (IMAP wildcard = all).
                if template_name == "email_read":
                    params["query"] = "*"
                else:
                    params["query"] = msg
                if not template.validate_params(params):
                    return _planner_fallback(
                        f"Cannot extract required params for '{template_name}'"
                    )
            elif "query" not in template.required_params:
                # Non-query template (e.g. signal_send, calendar_add) —
                # if it has exactly one required param and nothing was
                # extracted, map the raw message to that param name.
                # For multi-param templates (e.g. calendar_add needs
                # summary+start, email_send needs recipient+subject+body),
                # the keyword classifier can't extract structured params
                # from natural language — fall through to planner.
                if len(template.required_params) == 1:
                    params[template.required_params[0]] = msg
                else:
                    return _planner_fallback(
                        f"Template '{template_name}' requires NLP param "
                        f"extraction ({', '.join(template.required_params)}) "
                        f"— routing to planner"
                    )
            else:
                return _planner_fallback(
                    f"Cannot extract required params for '{template_name}'"
                )

        logger.info(
            "Keyword classifier: fast-path -> %s",
            template_name,
            extra={
                "event": "keyword_classify",
                "route": "fast",
                "template": template_name,
                "param_keys": list(params.keys()),
            },
        )

        return ClassificationResult(
            route=Route.FAST,
            template_name=template_name,
            params=params,
        )
