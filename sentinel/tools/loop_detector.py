"""Per-task tool call loop detection — SH-1 Part B.

Tracks repeated identical tool calls within a single task execution.
Hash signature = (tool_name, sorted arg key-value pairs).

Warn at LOOP_WARN_THRESHOLD (default 3), block at LOOP_BLOCK_THRESHOLD
(default 6) to prevent runaway agent loops that waste compute.

Usage:
    detector = LoopDetector()
    detector.check_and_record("file_read", {"path": "/workspace/index.html"})

Created fresh per task via TaskExecutionContext — no cross-task state.
"""

from __future__ import annotations

import hashlib
import json
import logging

from sentinel.core.exceptions import ToolBlockedError

logger = logging.getLogger(__name__)

# Thresholds — named constants, not magic numbers
LOOP_WARN_THRESHOLD: int = 3
LOOP_BLOCK_THRESHOLD: int = 6


def _call_signature(tool_name: str, args: dict) -> str:
    """Hash (tool_name, sorted args) into a stable string key.

    Args are sorted by key for order-independence — {'a': 1, 'b': 2}
    and {'b': 2, 'a': 1} produce the same hash.
    """
    # json.dumps with sort_keys handles nested dicts consistently
    canonical = json.dumps({"tool": tool_name, "args": args}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


class LoopDetector:
    """Detects repeated identical tool calls within a single task.

    Each instance is independent — create one per task to prevent
    cross-task counter leakage.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def check_and_record(self, tool_name: str, args: dict) -> None:
        """Record a tool call and check against loop thresholds.

        Raises ToolBlockedError at LOOP_BLOCK_THRESHOLD. Logs WARNING
        at LOOP_WARN_THRESHOLD.

        Args:
            tool_name: The tool being called (e.g. "file_read").
            args: The tool arguments dict.

        Raises:
            ToolBlockedError: When call count reaches LOOP_BLOCK_THRESHOLD.
        """
        sig = _call_signature(tool_name, args)
        count = self._counts.get(sig, 0) + 1
        self._counts[sig] = count

        if count >= LOOP_BLOCK_THRESHOLD:
            logger.warning(
                "Tool call loop BLOCKED — %s called %d times with identical args "
                "(threshold=%d)",
                tool_name,
                count,
                LOOP_BLOCK_THRESHOLD,
                extra={
                    "event": "loop_detector.blocked",
                    "tool": tool_name,
                    "call_count": count,
                    "threshold": LOOP_BLOCK_THRESHOLD,
                    "signature": sig,
                },
            )
            raise ToolBlockedError(
                "Tool call loop detected with identical args",
                retryable=False,
                category="security",
            )
        logger.debug(
            "check_and_record: count_gte_LOOP_BLOCK_THRESHOLD_passed",
            extra={
                "event": "loop_detector.blocked.passed",
                "reason": "count_gte_LOOP_BLOCK_THRESHOLD_passed",
            },
        )  # auto:neg

        if count >= LOOP_WARN_THRESHOLD:
            logger.warning(
                "Tool call loop WARNING — %s called %d times with identical args "
                "(warn threshold=%d, block at %d)",
                tool_name,
                count,
                LOOP_WARN_THRESHOLD,
                LOOP_BLOCK_THRESHOLD,
                extra={
                    "event": "loop_detector.warn",
                    "tool": tool_name,
                    "call_count": count,
                    "warn_threshold": LOOP_WARN_THRESHOLD,
                    "block_threshold": LOOP_BLOCK_THRESHOLD,
                    "signature": sig,
                },
            )
            return

        logger.debug(
            "Tool call recorded — %s count=%d (no loop)",
            tool_name,
            count,
            extra={
                "event": "loop_detector.recorded",
                "tool": tool_name,
                "call_count": count,
                "signature": sig,
            },
        )
