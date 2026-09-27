"""MTM signal extractors — modular, registered signal functions.

Each signal extractor is a callable with signature:
    (request: str, session: Session, config: MTMConfig) -> SignalResult

Signals are registered in SIGNAL_REGISTRY as (name, callable) tuples.
The monitor iterates the registry to collect per-turn scores.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from sentinel.security.conversation.signals.code_danger import check_code_danger
from sentinel.security.conversation.signals.context_reference import (
    check_context_reference,
)
from sentinel.security.conversation.signals.escalation import (
    check_keyword_escalation,
)
from sentinel.security.conversation.signals.evaluation_framing import (
    check_evaluation_framing,
)
from sentinel.security.conversation.signals.flattery_override import (
    check_flattery_override,
)
from sentinel.security.conversation.signals.instruction_override import (
    check_instruction_override,
)
from sentinel.security.conversation.signals.reconnaissance import (
    check_reconnaissance,
)
from sentinel.security.conversation.signals.retry_detection import (
    check_retry_detection,
)
from sentinel.security.conversation.signals.sensitive_topic import (
    check_sensitive_topic,
)
from sentinel.security.conversation.signals.topic_shift import check_topic_shift
from sentinel.security.conversation.signals.violation_accumulation import (
    check_violation_accumulation,
)

if TYPE_CHECKING:
    from sentinel.security.conversation.config import MTMConfig
    from sentinel.security.conversation.types import SignalResult
    from sentinel.session.store import Session

# Type alias for signal extractor functions
SignalExtractor = Callable[["str", "Session", "MTMConfig"], "SignalResult"]

# Registry of active signal extractors (S1-S11).
# Each entry is (signal_name, extractor_function).
# Order does not affect scoring — all signals run independently.
SIGNAL_REGISTRY: list[tuple[str, SignalExtractor]] = [
    ("keyword_escalation", check_keyword_escalation),
    ("sensitive_topic", check_sensitive_topic),
    ("instruction_override", check_instruction_override),
    ("context_reference", check_context_reference),
    ("retry_detection", check_retry_detection),
    ("reconnaissance", check_reconnaissance),
    ("topic_shift", check_topic_shift),
    ("violation_accumulation", check_violation_accumulation),
    ("code_danger", check_code_danger),
    ("evaluation_framing", check_evaluation_framing),
    ("flattery_override", check_flattery_override),
]
