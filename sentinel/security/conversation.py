"""Multi-turn conversation analysis — deterministic heuristic-based attack detection.

Eight scoring rules detect patterns that span multiple conversation turns:
retry_after_block, escalation, sensitive_topic_acceleration,
instruction_override, violation_accumulation, context_building,
reconnaissance, topic_shift.

Risk accumulates within a session but decays over time based on inactivity
(see Session.apply_decay). Locked sessions auto-unlock after a configurable timeout.
"""

import logging
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from sentinel.core.config import settings
from sentinel.core.context import get_task_id
from sentinel.security.homoglyph import normalise_homoglyphs
from sentinel.session.store import Session

logger = logging.getLogger("sentinel.audit")

# ── Capability tiers (ordered by severity) ──────────────────────

CAPABILITY_TIERS = {
    "observe": 0,
    "read": 1,
    "write": 2,
    "execute": 3,
    "persist": 4,
    "exfiltrate": 5,
}

# Keywords that map to capability tiers.
# Finding #2: Some keywords ("run", "curl", "shell") are common in dev contexts.
# The 2-tier jump threshold in _check_escalation mitigates most FPs — e.g.
# observe(0)→execute(3)=+3 tiers fires, but read(1)→execute(3)=+2 tiers is
# borderline. Adding dev-context awareness would overcomplicate the heuristic
# for marginal gain. Accepted trade-off.
# Keywords that map to capability tiers (pre-compiled word-boundary patterns)
TIER_KEYWORDS: dict[str, list[re.Pattern[str]]] = {
    "observe": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
                ["list", "show", "display", "status", "check", "info", "describe", "what is"]],
    "read": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
             ["read", "cat", "view", "open", "get contents", "print file", "head", "tail", "less"]],
    "write": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
              ["write", "create", "edit", "modify", "append", "save", "update file", "overwrite"]],
    "execute": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
                ["run", "execute", "bash", "shell", "script", "command", "invoke", "launch"]],
    "persist": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
                ["cron", "crontab", "systemd", "service", "startup", "autostart", "schedule",
                 "daemon", "boot", "init.d", "rc.local", "persist", "backdoor"]],
    "exfiltrate": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
                   ["curl", "wget", "upload", "send to", "post to", "exfil", "transfer out",
                    "base64 encode", "dns tunnel", "reverse shell", "nc -e", "netcat"]],
}

# ── Instruction override patterns ──────────────────────────────

INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"\bfrom now on\b", re.IGNORECASE),
    re.compile(r"\byou are now\b", re.IGNORECASE),
    re.compile(r"\bas we discussed\b", re.IGNORECASE),
    re.compile(r"\bforget (?:(?:your |all |previous |the )*)?(?:instructions|rules|constraints)\b", re.IGNORECASE),
    re.compile(r"\bignore (?:(?:your |all |previous |the )*)?(?:instructions|rules|constraints|policies)\b", re.IGNORECASE),
    re.compile(r"\byour new (?:role|persona|identity|instructions)\b", re.IGNORECASE),
    re.compile(r"\byou (?:must|should|will) now\b", re.IGNORECASE),
    re.compile(r"\bact as (?:if you are|a|an|my)\b", re.IGNORECASE),
    re.compile(r"\bpretend (?:you are|to be|that)\b", re.IGNORECASE),
    re.compile(r"\bswitch to (?:\w+ )?mode\b", re.IGNORECASE),
    re.compile(r"\benable (?:developer|debug|admin|god|unrestricted) mode\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bDAN\b"),  # "Do Anything Now" — case-sensitive, it's an acronym
    # Authority/command-style override patterns (v3 assessment gap)
    re.compile(r"\bsystem\s+override\b", re.IGNORECASE),
    re.compile(r"\bsafety\s+mode\s+(?:is\s+)?off\b", re.IGNORECASE),
    re.compile(r"\ball\s+restrictions?\s+(?:are\s+)?(?:now\s+)?(?:lifted|removed|disabled)\b", re.IGNORECASE),
    re.compile(r"\byour\s+(?:programming|rules|constraints)\s+(?:ha(?:ve|s)\s+been)\s+(?:revised|updated|changed|removed)\b", re.IGNORECASE),
    re.compile(r"\bbypass\s+(?:all\s+)?(?:filters?|security|restrictions?|constraints?)\b", re.IGNORECASE),
    re.compile(r"\b(?:new|updated)\s+directive\b", re.IGNORECASE),
    re.compile(r"\bdisable\s+(?:content\s+)?filter(?:ing|s)?\b", re.IGNORECASE),
]

# ── Sensitive topic patterns ──────────────────────────────────


def _sensitive_re(term: str, *, prefix: bool = False, literal: bool = False) -> re.Pattern[str]:
    """Build a regex for a sensitive topic term.

    Word boundaries prevent false positives (e.g. "token" != "tokenizer").
    prefix=True omits the trailing boundary (e.g. "escalat" -> escalation).
    literal=True uses plain substring matching (for path-like terms
    starting with / or . where word boundaries don't apply).
    """
    escaped = re.escape(term)
    if literal:
        return re.compile(escaped, re.IGNORECASE)
    if prefix:
        return re.compile(rf"\b{escaped}", re.IGNORECASE)
    return re.compile(rf"\b{escaped}\b", re.IGNORECASE)


# Finding #5: "token" and "secret" are intentionally broad — word boundary
# prevents "tokenizer" but not "token count". These only score via
# _check_sensitive_topic_acceleration (new category after benign turns) and
# _check_context_building (combined with escalation), limiting FP blast radius.
SENSITIVE_TOPIC_CATEGORIES: dict[str, list[re.Pattern[str]]] = {
    "credential": [
        _sensitive_re("password"),
        _sensitive_re("secret"),
        _sensitive_re("credential"),
        _sensitive_re("api key"),
        _sensitive_re("token"),
        _sensitive_re("private key"),
    ],
    "system_file": [
        _sensitive_re("shadow"),
        _sensitive_re("passwd"),
        _sensitive_re("/etc/shadow", literal=True),
        _sensitive_re(".ssh", literal=True),
        _sensitive_re("authorized_keys"),
        _sensitive_re("/root/", literal=True),
        _sensitive_re("/home/", literal=True),
        _sensitive_re("/var/log/", literal=True),
        _sensitive_re("bash_history"),
        _sensitive_re(".bashrc", literal=True),
        _sensitive_re("sudoers"),
        _sensitive_re("auth.log"),
    ],
    "privilege": [
        _sensitive_re("root access"),
        _sensitive_re("sudo"),
        _sensitive_re("privilege"),
        _sensitive_re("escalat", prefix=True),
        _sensitive_re("system access"),
    ],
    "attack_tool": [
        _sensitive_re("reverse shell"),
        _sensitive_re("backdoor"),
        _sensitive_re("exploit"),
        _sensitive_re("payload"),
        _sensitive_re("malware"),
    ],
    "control_tampering": [
        _sensitive_re("disable security"),
        _sensitive_re("disable firewall"),
        _sensitive_re("disable logging"),
        _sensitive_re("delete logs"),
        _sensitive_re("clear history"),
        _sensitive_re("cover tracks"),
    ],
}

# Flat list for backward compatibility with _has_sensitive_topic()
SENSITIVE_TOPIC_PATTERNS: list[re.Pattern[str]] = [
    p for patterns in SENSITIVE_TOPIC_CATEGORIES.values() for p in patterns
]


def _has_sensitive_topic(text: str) -> bool:
    """Check if text contains any sensitive topic keyword."""
    return any(p.search(text) for p in SENSITIVE_TOPIC_PATTERNS)


def _get_sensitive_categories(text: str) -> set[str]:
    """Return which sensitive topic categories are present in text."""
    categories = set()
    for cat, patterns in SENSITIVE_TOPIC_CATEGORIES.items():
        if any(p.search(text) for p in patterns):
            categories.add(cat)
    return categories

# ── Context building indicators ────────────────────────────────

CONTEXT_REFERENCE_PHRASES = [
    re.compile(r"\bas (?:I|we) (?:mentioned|discussed|said|noted)\b", re.IGNORECASE),
    re.compile(r"\byou (?:already|previously) (?:said|confirmed|agreed|told me)\b", re.IGNORECASE),
    re.compile(r"\bremember (?:when|that|earlier)\b", re.IGNORECASE),
    re.compile(r"\bbased on (?:our|the) (?:earlier|previous|prior) (?:conversation|discussion)\b", re.IGNORECASE),
    re.compile(r"\bcontinuing (?:from|where|what)\b", re.IGNORECASE),
    re.compile(r"\bso (?:now|next|then) (?:can you|let's|we can)\b", re.IGNORECASE),
]

ESCALATION_LANGUAGE = [
    "now that we have", "next step", "final step", "the real task",
    "what i actually need", "the important part",
]

# ── Reconnaissance indicators ────────────────────────────────

# Finding #15: Recon patterns match common dev workflows ("list files in
# the project", "find config files"). The 2-turn threshold prevents
# single-query FPs, but a normal exploratory session could hit 3+ recon
# turns and score 3.5. Accepted trade-off — recon detection is a signal
# that combines with other rules, not a standalone blocker at these scores.
RECON_PATTERNS = [
    re.compile(r"\b(?:ls|list|dir)\s+", re.IGNORECASE),
    re.compile(r"\blist\s+(?:files|directories|folders)\b", re.IGNORECASE),
    re.compile(r"\bwhat(?:'s| is)\s+in\b", re.IGNORECASE),
    re.compile(r"\bshow\s+(?:me\s+)?(?:the\s+)?(?:files|contents|directory|folder)\b", re.IGNORECASE),
    re.compile(r"\bcontents?\s+of\b", re.IGNORECASE),
    re.compile(r"\btree\s+", re.IGNORECASE),
    re.compile(r"\bfind\s+.*(?:/\w+)", re.IGNORECASE),
]

# ── Topic shift categories ────────────────────────────────────

TOPIC_CATEGORIES: dict[str, list[re.Pattern[str]]] = {
    "code": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
             ["write code", "function", "class", "implement", "refactor", "debug", "algorithm", "variable"]],
    "text": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
             ["write", "essay", "summarize", "translate", "explain", "describe", "poem", "story"]],
    "file": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
             ["file", "directory", "path", "read file", "list files", "contents of"]],
    "system": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
               ["execute", "run", "bash", "shell", "command", "sudo", "process", "kill", "service"]],
    "question": [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in
                 ["what is", "how does", "why", "can you explain", "tell me about", "help me understand"]],
}

# ── Block category classification ────────────────────────────

# Scanner names that indicate a genuine security violation.
# Everything in the scan pipeline that detects malicious content.
_SECURITY_SCANNERS = frozenset({
    "command_pattern_scanner",
    "sensitive_path_scanner",
    "encoding_normalization_scanner",
    "credential_scanner",
    "prompt_guard",
    "semgrep",
    "provenance",
    "constraint",
    "constraint_validator",
    "conversation_analyzer",
    "vulnerability_echo_scanner",
    "ascii_prompt_gate",
    "scanner_crash",        # fail-closed crash → treat as security
})


def _classify_block_category(blocked_by: list[str]) -> str:
    """Classify a block as security, policy, or planner.

    Uses the blocked_by list (scanner names) to determine whether a block
    represents a genuine security threat vs an environment/policy issue.

    Fail-closed: unknown or empty blocked_by → security (conservative default).
    """
    if not blocked_by:
        # No attribution — treat as security (fail-closed)
        return "security"
    # Planner refusals are their own category
    if blocked_by == ["planner"]:
        return "planner"
    # If ANY scanner in blocked_by is a security scanner, treat as security.
    # Mixed blocks (security + policy) are conservatively scored as security.
    if any(name in _SECURITY_SCANNERS for name in blocked_by):
        return "security"
    # Everything else is a policy/environment block (e.g. policy_engine,
    # sandbox filesystem errors, blocked commands)
    return "policy"


@dataclass
class AnalysisResult:
    action: str                          # "allow", "warn", "block"
    total_score: float
    rule_scores: dict[str, float] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    new_success_forgives: int | None = None  # Finding #11: caller persists this


class ConversationAnalyzer:
    """Deterministic multi-turn attack detection via heuristic scoring."""

    def __init__(
        self,
        warn_threshold: float | None = None,
        block_threshold: float | None = None,
    ):
        self._warn = warn_threshold if warn_threshold is not None else settings.conversation_warn_threshold
        self._block = block_threshold if block_threshold is not None else settings.conversation_block_threshold

    @staticmethod
    def _normalise_turn_text(text: str) -> str:
        """Normalise homoglyphs in historical turn text for keyword comparison."""
        return normalise_homoglyphs(text)

    def analyze(self, session: Session, current_request: str) -> AnalysisResult:
        """Analyze a request in the context of its session history.

        Returns AnalysisResult with action, score, and warnings.
        First message in a session always returns ALLOW (no history to analyze).
        """
        # Normalise homoglyphs so Cyrillic lookalikes can't bypass keyword rules
        current_request = normalise_homoglyphs(current_request)

        # First turn — only check stateless rules (instruction_override).
        # History-dependent rules (retry, escalation, etc.) are skipped because
        # there's nothing to compare against.
        if len(session.turns) == 0:
            s, w = self._check_instruction_override(current_request)
            if s > 0:
                action = "block" if s >= self._block else ("warn" if s >= self._warn else "allow")
                logger.info(
                    "Conversation first turn — instruction override detected",
                    extra={
                        "event": "conversation_first_turn_override",
                        "session_id": session.session_id,
                        "score": s,
                        "action": action,
                    },
                )
                return AnalysisResult(
                    action=action,
                    total_score=s,
                    rule_scores={"instruction_override": s},
                    warnings=w,
                )
            logger.debug(
                "Conversation first turn — no analysis needed",
                extra={"event": "conversation_first_turn", "session_id": session.session_id},
            )
            return AnalysisResult(action="allow", total_score=0.0)

        scores: dict[str, float] = {}
        warnings: list[str] = []

        # Run all 8 rules
        s, w = self._check_retry_after_block(session, current_request)
        if s > 0:
            scores["retry_after_block"] = s
            warnings.extend(w)

        s, w = self._check_escalation(session, current_request)
        if s > 0:
            scores["escalation"] = s
            warnings.extend(w)

        s, w = self._check_sensitive_topic_acceleration(session, current_request)
        if s > 0:
            scores["sensitive_topic_acceleration"] = s
            warnings.extend(w)

        s, w = self._check_instruction_override(current_request)
        if s > 0:
            scores["instruction_override"] = s
            warnings.extend(w)

        s, w, new_forgives = self._check_violation_accumulation(session)
        if s > 0:
            scores["violation_accumulation"] = s
            warnings.extend(w)

        s, w = self._check_context_building(session, current_request)
        if s > 0:
            scores["context_building"] = s
            warnings.extend(w)

        s, w = self._check_reconnaissance(session, current_request)
        if s > 0:
            scores["reconnaissance"] = s
            warnings.extend(w)

        s, w = self._check_topic_shift(session, current_request)
        if s > 0:
            scores["topic_shift"] = s
            warnings.extend(w)

        total = sum(scores.values())

        # Add cumulative risk from prior turns.
        # Finding #7: No ceiling on cumulative_risk — this is by design.
        # Risk ratchets via accumulate_risk() (max of old and new) and only
        # decays via time-based Session.apply_decay(). A user triggering
        # several warnings from FP-prone patterns could have their session
        # locked through accumulation alone. This is the intended trade-off:
        # FPs trigger warns (recoverable), true positives accumulate to blocks
        # (protective). The auto-unlock timeout is the escape valve.
        total += session.cumulative_risk

        # Determine action
        if total >= self._block:
            action = "block"
        elif total >= self._warn:
            action = "warn"
        else:
            action = "allow"

        result = AnalysisResult(
            action=action,
            total_score=total,
            rule_scores=scores,
            warnings=warnings,
            new_success_forgives=new_forgives,
        )

        logger.info(
            "Conversation analysis",
            extra={
                "event": "conversation_analysis",
                "task_id": get_task_id(),
                "session_id": session.session_id,
                "turn": len(session.turns),
                "action": action,
                "total_score": total,
                "rule_scores": scores,
                "request_excerpt": current_request[:200] + ("..." if len(current_request) > 200 else ""),
            },
        )

        return result

    # ── Rule 1: Retry after block ──────────────────────────────

    def _check_retry_after_block(
        self, session: Session, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect rephrased retries of previously blocked requests.

        Score: 3.0 per similar blocked request, max 5.0
        Trigger: SequenceMatcher ratio > 0.45 against any blocked turn in session
        """
        score = 0.0
        warnings: list[str] = []
        # Truncate to 1000 chars — SequenceMatcher is O(n²) and retry detection only needs prefix similarity
        current_lower = current_request.lower()[:1000]

        for turn in session.turns:
            if turn.result_status != "blocked":
                continue
            turn_text = self._normalise_turn_text(turn.request_text).lower()[:1000]
            ratio = SequenceMatcher(
                None, current_lower, turn_text,
            ).ratio()
            if ratio > 0.45:
                score += 3.0
                warnings.append(
                    f"Request similar to previously blocked request (similarity: {ratio:.0%})"
                )

        return min(score, 5.0), warnings

    # ── Rule 2: Capability escalation ──────────────────────────

    def _check_escalation(
        self, session: Session, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect rapid capability tier escalation.

        Score: 1.0 per tier jump, max 5.0
        Only flags: 2+ tier jumps in one step, or reaching persist/exfiltrate
        """
        # Find max tier from previous turns
        prev_max_tier = self._get_max_tier_from_turns(session.turns)
        current_tier = self._classify_tier(current_request)

        if current_tier is None:
            return 0.0, []

        current_tier_value = CAPABILITY_TIERS[current_tier]

        score = 0.0
        warnings: list[str] = []

        if prev_max_tier is not None:
            prev_value = CAPABILITY_TIERS[prev_max_tier]
            jump = current_tier_value - prev_value
            if jump >= 2:
                score = min(float(jump), 5.0)
                warnings.append(
                    f"Capability escalation: {prev_max_tier} → {current_tier} (+{jump} tiers)"
                )
        # Reaching persist or exfiltrate is always flagged
        if current_tier in ("persist", "exfiltrate") and score == 0.0:
            score = 3.0
            warnings.append(f"High-risk capability tier: {current_tier}")

        return score, warnings

    def _classify_tier(self, text: str) -> str | None:
        """Classify text into the highest matching capability tier."""
        text_lower = text.lower()
        best_tier = None
        best_value = -1

        for tier, patterns in TIER_KEYWORDS.items():
            for pattern in patterns:
                if pattern.search(text_lower):
                    tier_value = CAPABILITY_TIERS[tier]
                    if tier_value > best_value:
                        best_tier = tier
                        best_value = tier_value

        return best_tier

    def _get_max_tier_from_turns(self, turns: list) -> str | None:
        """Get the highest capability tier seen in prior turns."""
        max_tier = None
        max_value = -1

        for turn in turns:
            tier = self._classify_tier(self._normalise_turn_text(turn.request_text))
            if tier is not None:
                value = CAPABILITY_TIERS[tier]
                if value > max_value:
                    max_tier = tier
                    max_value = value

        return max_tier

    # ── Rule 3: Sensitive topic acceleration ───────────────────

    def _check_sensitive_topic_acceleration(
        self, session: Session, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect first mention of sensitive topic categories after N benign turns.

        Score: 2.0 if after 1+ benign turns, 3.0 if after 4+ benign turns.
        Tracks by category (credential, system_file, privilege, attack_tool,
        control_tampering) so that introducing a NEW category of sensitive
        topic triggers acceleration even if a different category appeared earlier.
        """
        current_categories = _get_sensitive_categories(current_request)
        if not current_categories:
            return 0.0, []

        # Collect categories seen in prior turns
        prior_categories: set[str] = set()
        for turn in session.turns:
            prior_categories |= _get_sensitive_categories(
                self._normalise_turn_text(turn.request_text)
            )

        # Check for NEW categories not seen before
        new_categories = current_categories - prior_categories
        if not new_categories:
            return 0.0, []

        # Count benign turns (not blocked)
        benign_count = sum(1 for t in session.turns if t.result_status != "blocked")

        if benign_count >= 4:
            return 3.0, [f"New sensitive topic category ({', '.join(sorted(new_categories))}) after {benign_count} benign turns"]
        elif benign_count >= 1:
            return 2.0, [f"New sensitive topic category ({', '.join(sorted(new_categories))}) after {benign_count} benign turns"]

        return 0.0, []

    # ── Rule 4: Instruction override ───────────────────────────

    def _check_instruction_override(
        self, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect attempts to override system instructions.

        Score: 3.0 per pattern match, max 5.0
        """
        score = 0.0
        warnings: list[str] = []

        for pattern in INSTRUCTION_OVERRIDE_PATTERNS:
            if pattern.search(current_request):
                score += 3.0
                warnings.append("Instruction override phrase detected")

        return min(score, 5.0), warnings

    # ── Rule 5: Violation accumulation ─────────────────────────

    def _check_violation_accumulation(
        self, session: Session,
    ) -> tuple[float, list[str], int | None]:
        """Score based on prior violations, weighted by category.

        Security blocks (scanner detections): 1.5 per violation
        Policy blocks (environment/sandbox rules): 0.5 per block
        Planner refusals: 0.0 (planner doing its job, not a threat signal)

        This prevents legitimate debugging sessions from cascading into
        session locks when environment/policy blocks (e.g. read-only FS,
        python3 -c blocked by policy) accumulate.

        Returns (score, warnings, new_forgives_total) where new_forgives_total
        is the updated success_forgives_used value for the caller to persist,
        or None if no forgiveness was applied.
        """
        if session.violation_count == 0:
            return 0.0, [], None

        security_count = 0
        policy_count = 0
        for turn in session.turns:
            if turn.result_status != "blocked":
                continue
            cat = _classify_block_category(turn.blocked_by)
            if cat == "security":
                security_count += 1
            elif cat == "policy":
                policy_count += 1
            # "planner" and "" contribute nothing

        # Fix-cycle awareness: a successful step after scanner blocks indicates
        # a legitimate retry workflow (e.g. code fixer correcting Qwen output).
        # Forgive one security block per success-after-block pattern in the
        # turn history, up to max_success_forgives total across the session.
        max_forgives = settings.max_success_forgives
        success_forgives_used = session.success_forgives_used
        new_forgives_total: int | None = None

        if security_count > 0 and success_forgives_used < max_forgives:
            # Count successes that follow at least one prior block
            seen_block = False
            forgive_eligible = 0
            for turn in session.turns:
                if turn.result_status == "blocked" and _classify_block_category(turn.blocked_by) == "security":
                    seen_block = True
                elif turn.result_status == "success" and seen_block:
                    forgive_eligible += 1
                    seen_block = False  # Reset: each success consumes one block signal

            # Apply new forgives (subtract already-used from eligible count)
            new_forgives = min(
                forgive_eligible - success_forgives_used,
                max_forgives - success_forgives_used,
                security_count,  # Never reduce below 0
            )
            if new_forgives > 0:
                security_count -= new_forgives
                new_forgives_total = success_forgives_used + new_forgives

        score = min(security_count * 1.5 + policy_count * 0.5, 5.0)
        warnings: list[str] = []
        if security_count:
            warnings.append(f"{security_count} security violation(s)")
        if policy_count:
            warnings.append(f"{policy_count} policy block(s)")
        if not warnings:
            return 0.0, [], new_forgives_total
        return score, [f"Session has {'; '.join(warnings)}"], new_forgives_total

    # ── Rule 6: Context building ───────────────────────────────

    def _check_context_building(
        self, session: Session, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect context-reference phrases combined with sensitive content or escalation.

        Score: 2.0 for context reference + sensitive topic, up to 4.0 with escalation language
        """
        # Check for context-reference phrases
        has_context_ref = any(p.search(current_request) for p in CONTEXT_REFERENCE_PHRASES)
        if not has_context_ref:
            return 0.0, []

        current_lower = current_request.lower()

        # Check for sensitive content
        has_sensitive = _has_sensitive_topic(current_request)

        # Check for escalation language
        has_escalation = any(phrase in current_lower for phrase in ESCALATION_LANGUAGE)

        score = 0.0
        warnings: list[str] = []

        if has_sensitive:
            score = 2.0
            warnings.append("Context reference combined with sensitive topic")
        if has_escalation:
            score += 2.0
            warnings.append("Context reference combined with escalation language")

        return min(score, 4.0), warnings

    # ── Rule 7: Reconnaissance detection ───────────────────────

    def _check_reconnaissance(
        self, session: Session, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect systematic directory/file exploration across turns.

        Score: 2.0 for 2 recon turns, 3.5 for 3+, max 5.0
        """
        # Count prior turns that match recon patterns
        recon_count = 0
        for turn in session.turns:
            if any(p.search(self._normalise_turn_text(turn.request_text)) for p in RECON_PATTERNS):
                recon_count += 1

        # Check if current request is also recon
        current_is_recon = any(p.search(current_request) for p in RECON_PATTERNS)
        if current_is_recon:
            recon_count += 1

        if recon_count >= 3:
            return min(3.5, 5.0), [f"Systematic reconnaissance: {recon_count} exploration turns"]
        elif recon_count >= 2:
            return 2.0, [f"Reconnaissance pattern: {recon_count} exploration turns"]

        return 0.0, []

    # ── Rule 8: Topic shift detection ──────────────────────────

    def _check_topic_shift(
        self, session: Session, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect shifts from benign topics to system/file operations.

        Score: 1.5 if session started with code/text/question and shifts
        to system/file requests.
        """
        if len(session.turns) < 2:
            return 0.0, []

        current_cat = self._classify_topic(current_request)
        if current_cat not in ("system", "file"):
            return 0.0, []

        # Check if earlier turns were in benign categories
        early_categories = set()
        for turn in session.turns[:3]:  # Look at first 3 turns
            cat = self._classify_topic(self._normalise_turn_text(turn.request_text))
            if cat:
                early_categories.add(cat)

        benign_start = early_categories and early_categories.issubset({"code", "text", "question"})
        if benign_start:
            return 1.5, [f"Topic shift from {early_categories} to {current_cat}"]

        return 0.0, []

    def _classify_topic(self, text: str) -> str | None:
        """Classify text into a topic category. Returns highest-risk match.

        Priority order: system > file > code > text > question.
        """
        text_lower = text.lower()
        priority = ["system", "file", "code", "text", "question"]
        for cat in priority:
            patterns = TOPIC_CATEGORIES[cat]
            for pattern in patterns:
                if pattern.search(text_lower):
                    return cat
        return None
