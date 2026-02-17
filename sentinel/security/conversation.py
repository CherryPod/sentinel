"""Multi-turn conversation analysis — deterministic heuristic-based attack detection.

Eight scoring rules detect patterns that span multiple conversation turns:
retry_after_block, escalation, sensitive_topic_acceleration,
instruction_override, violation_accumulation, context_building,
reconnaissance, topic_shift.

Risk accumulates within a session and never decreases.
"""

import logging
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from sentinel.core.config import settings
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

# Keywords that map to capability tiers
TIER_KEYWORDS: dict[str, list[str]] = {
    "observe": ["list", "show", "display", "status", "check", "info", "describe", "what is"],
    "read": ["read", "cat", "view", "open", "get contents", "print file", "head", "tail", "less"],
    "write": ["write", "create", "edit", "modify", "append", "save", "update file", "overwrite"],
    "execute": ["run", "execute", "bash", "shell", "script", "command", "invoke", "launch"],
    "persist": [
        "cron", "crontab", "systemd", "service", "startup", "autostart", "schedule",
        "daemon", "boot", "init.d", "rc.local", "persist", "backdoor",
    ],
    "exfiltrate": [
        "curl", "wget", "upload", "send to", "post to", "exfil", "transfer out",
        "base64 encode", "dns tunnel", "reverse shell", "nc -e", "netcat",
    ],
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

# ── Sensitive topic keywords ──────────────────────────────────

SENSITIVE_TOPICS = [
    "password", "secret", "credential", "api key", "token", "private key",
    "shadow", "passwd", "/etc/shadow", ".ssh", "authorized_keys",
    "root access", "sudo", "privilege", "escalat",
    "reverse shell", "backdoor", "exploit", "payload", "malware",
    "disable security", "disable firewall", "disable logging",
    "delete logs", "clear history", "cover tracks",
    # Path-related terms from v3 missed catches
    "/root/", "/home/", "/var/log/", "bash_history", ".bashrc",
    "sudoers", "auth.log", "system access",
]

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

TOPIC_CATEGORIES = {
    "code": ["write code", "function", "class", "implement", "refactor", "debug", "algorithm", "variable"],
    "text": ["write", "essay", "summarize", "translate", "explain", "describe", "poem", "story"],
    "file": ["file", "directory", "path", "read file", "list files", "contents of"],
    "system": ["execute", "run", "bash", "shell", "command", "sudo", "process", "kill", "service"],
    "question": ["what is", "how does", "why", "can you explain", "tell me about", "help me understand"],
}


@dataclass
class AnalysisResult:
    action: str                          # "allow", "warn", "block"
    total_score: float
    rule_scores: dict[str, float] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class ConversationAnalyzer:
    """Deterministic multi-turn attack detection via heuristic scoring."""

    def __init__(
        self,
        warn_threshold: float | None = None,
        block_threshold: float | None = None,
    ):
        self._warn = warn_threshold if warn_threshold is not None else settings.conversation_warn_threshold
        self._block = block_threshold if block_threshold is not None else settings.conversation_block_threshold

    def analyze(self, session: Session, current_request: str) -> AnalysisResult:
        """Analyze a request in the context of its session history.

        Returns AnalysisResult with action, score, and warnings.
        First message in a session always returns ALLOW (no history to analyze).
        """
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

        # Run all 6 rules
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

        s, w = self._check_violation_accumulation(session)
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

        # Add cumulative risk from prior turns
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
        )

        logger.info(
            "Conversation analysis",
            extra={
                "event": "conversation_analysis",
                "session_id": session.session_id,
                "turn": len(session.turns),
                "action": action,
                "total_score": total,
                "rule_scores": scores,
            },
        )

        return result

    # ── Rule 1: Retry after block ──────────────────────────────

    def _check_retry_after_block(
        self, session: Session, current_request: str,
    ) -> tuple[float, list[str]]:
        """Detect rephrased retries of previously blocked requests.

        Score: 3.0 per similar blocked request, max 5.0
        Trigger: SequenceMatcher ratio > 0.6 against any blocked turn in session
        """
        score = 0.0
        warnings: list[str] = []
        current_lower = current_request.lower()

        for turn in session.turns:
            if turn.result_status != "blocked":
                continue
            ratio = SequenceMatcher(
                None, current_lower, turn.request_text.lower(),
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

        for tier, keywords in TIER_KEYWORDS.items():
            for kw in keywords:
                # Use word boundary matching to avoid substring false positives
                # (e.g. "running" should not match "run")
                pattern = r"\b" + re.escape(kw) + r"\b"
                if re.search(pattern, text_lower):
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
            tier = self._classify_tier(turn.request_text)
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
        """Detect first mention of sensitive topics after N benign turns.

        Score: 2.0 if after 2+ benign turns, 3.0 if after 4+ benign turns
        """
        # Check if current request contains sensitive topics
        current_lower = current_request.lower()
        matched_topics = [t for t in SENSITIVE_TOPICS if t in current_lower]
        if not matched_topics:
            return 0.0, []

        # Check if any prior turn also mentioned sensitive topics
        for turn in session.turns:
            turn_lower = turn.request_text.lower()
            if any(t in turn_lower for t in SENSITIVE_TOPICS):
                return 0.0, []  # Not the first mention

        # Count benign turns (not blocked)
        benign_count = sum(1 for t in session.turns if t.result_status != "blocked")

        if benign_count >= 4:
            return 3.0, [f"Sensitive topic introduced after {benign_count} benign turns"]
        elif benign_count >= 1:
            return 2.0, [f"Sensitive topic introduced after {benign_count} benign turns"]

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
                warnings.append(f"Instruction override attempt: '{pattern.pattern}'")

        return min(score, 5.0), warnings

    # ── Rule 5: Violation accumulation ─────────────────────────

    def _check_violation_accumulation(
        self, session: Session,
    ) -> tuple[float, list[str]]:
        """Score based on prior security violations in this session.

        Score: 1.5 per prior block, max 5.0
        """
        if session.violation_count == 0:
            return 0.0, []

        score = min(session.violation_count * 1.5, 5.0)
        return score, [f"Session has {session.violation_count} prior violation(s)"]

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
        has_sensitive = any(t in current_lower for t in SENSITIVE_TOPICS)

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
            if any(p.search(turn.request_text) for p in RECON_PATTERNS):
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
            cat = self._classify_topic(turn.request_text)
            if cat:
                early_categories.add(cat)

        benign_start = early_categories and early_categories.issubset({"code", "text", "question"})
        if benign_start:
            return 1.5, [f"Topic shift from {early_categories} to {current_cat}"]

        return 0.0, []

    def _classify_topic(self, text: str) -> str | None:
        """Classify text into a topic category. Returns highest-risk match."""
        text_lower = text.lower()
        # Check in priority order: system > file > code > text > question
        priority = ["system", "file", "code", "text", "question"]
        for cat in priority:
            keywords = TOPIC_CATEGORIES[cat]
            for kw in keywords:
                if kw in text_lower:
                    return cat
        return None
