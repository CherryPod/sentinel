"""S9: Code danger escalation signal extractor.

Detects cross-turn composition of dangerous code capabilities.
Tracks four capability categories across the session's sliding window:
  network, data_intake, execution, exfiltration.

Single capability = legitimate code (0.0). Combinations escalate.
See design doc Section 4.2 for scoring rationale.
"""

from __future__ import annotations

import logging
import re

from sentinel.security.conversation.config import MTMConfig
from sentinel.security.conversation.types import SignalResult
from sentinel.session.store import Session

logger = logging.getLogger(__name__)

# ── Code capability categories and trigger patterns ───────────

CODE_CAPABILITIES: dict[str, list[re.Pattern[str]]] = {
    "network": [
        re.compile(r"\bsocket\b", re.IGNORECASE),
        re.compile(r"\bconnect\b", re.IGNORECASE),
        re.compile(r"\bbind\b", re.IGNORECASE),
        re.compile(r"\blisten\b", re.IGNORECASE),
        re.compile(r"requests\.", re.IGNORECASE),
        re.compile(r"\burllib\b", re.IGNORECASE),
        re.compile(r"http\.client", re.IGNORECASE),
    ],
    "data_intake": [
        re.compile(r"\breceive\b", re.IGNORECASE),
        re.compile(r"\brecv\b", re.IGNORECASE),
        re.compile(r"\bread\b", re.IGNORECASE),
        re.compile(r"\bstdin\b", re.IGNORECASE),
        re.compile(r"\binput\s*\(", re.IGNORECASE),
    ],
    "execution": [
        re.compile(r"\bsubprocess\b", re.IGNORECASE),
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
        re.compile(r"os\.system", re.IGNORECASE),
        re.compile(r"os\.popen", re.IGNORECASE),
        re.compile(r"shell\s*=\s*True", re.IGNORECASE),
        re.compile(r"\bPopen\b"),
    ],
    "exfiltration": [
        re.compile(r"requests\.post", re.IGNORECASE),
        re.compile(r"urllib\.request", re.IGNORECASE),
        re.compile(r"\bcurl\b", re.IGNORECASE),
        re.compile(r"\bwget\b", re.IGNORECASE),
        re.compile(r"\bsendall\b", re.IGNORECASE),
        re.compile(r"\bsend\s*\(", re.IGNORECASE),
    ],
}

# ── Scoring constants ─────────────────────────────────────────

_SCORE_TWO_CAPS = 2.0
_SCORE_THREE_WITH_EXEC = 4.0
_SCORE_THREE_WITH_EXEC_AND_EXFIL = 5.0


def _detect_capabilities(text: str) -> set[str]:
    """Return which code capability categories are present in text.

    Note: ``\\bread\\b`` in data_intake is intentionally broad per design doc.
    False positives are mitigated by the 2+ capability requirement for scoring.
    """
    caps: set[str] = set()
    for cap_name, patterns in CODE_CAPABILITIES.items():
        if any(p.search(text) for p in patterns):
            caps.add(cap_name)
    return caps


def check_code_danger(
    request: str, session: Session, config: MTMConfig
) -> SignalResult:
    """S9: Code danger escalation — cross-turn capability composition.

    Scans the current request and recent turns (within sliding window)
    for code capabilities. Scores based on capability combinations:
      - 1 capability: 0.0
      - 2 capabilities: 2.0
      - 3+ with execution: 4.0
      - 3+ with execution + exfiltration: 5.0

    Returns SignalResult with category 'code_escalation'.
    """
    logger.debug(
        "check_code_danger called",
        extra={
            "event": "signals.code_danger.check",
            "session_id": session.session_id,
            "request_len": len(request),
        },
    )

    # Collect capabilities from current request.
    # Note: session.turns does NOT include the current request at call time —
    # the monitor adds the turn after scoring.
    all_caps = _detect_capabilities(request)

    # Collect capabilities from turns within the sliding window
    window_turns = session.turns[-(config.window_size) :]
    for turn in window_turns:
        all_caps |= _detect_capabilities(turn.request_text)

    cap_count = len(all_caps)

    if cap_count <= 1:
        logger.debug(
            "check_code_danger: insufficient capabilities",
            extra={
                "event": "signals.code_danger.below_threshold",
                "cap_count": cap_count,
            },
        )
        return SignalResult(score=0.0, categories=frozenset(), details=())

    # Score based on combination
    has_execution = "execution" in all_caps
    has_exfiltration = "exfiltration" in all_caps

    if cap_count >= 3 and has_execution and has_exfiltration:
        score = _SCORE_THREE_WITH_EXEC_AND_EXFIL
        detail = f"Code danger: {cap_count} capabilities including execution + exfiltration ({', '.join(sorted(all_caps))})"
        decision = "three_with_exec_and_exfil"
    elif cap_count >= 3 and has_execution:
        score = _SCORE_THREE_WITH_EXEC
        detail = f"Code danger: {cap_count} capabilities including execution ({', '.join(sorted(all_caps))})"
        decision = "three_with_exec"
    else:
        score = _SCORE_TWO_CAPS
        detail = (
            f"Code danger: {cap_count} capabilities ({', '.join(sorted(all_caps))})"
        )
        decision = "two_caps"

    logger.info(
        "Code danger escalation detected",
        extra={
            "event": "signals.code_danger.detected",
            "session_id": session.session_id,
            "score": score,
            "cap_count": cap_count,
            "capabilities": sorted(all_caps),
            "decision": decision,
        },
    )

    return SignalResult(
        score=score,
        categories=frozenset({"code_escalation"}),
        details=(detail,),
    )
