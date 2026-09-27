"""MTM configuration — all tuneable constants for the Multi-Turn Monitor.

All values are operator-tuneable via SENTINEL_MTM_* env vars through the
core Settings class. See design doc Section 5.2 for defaults rationale.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Design doc Section 6.1 — benign development keywords
_DEFAULT_BENIGN_ANCHORS = [
    "write",
    "create",
    "deploy",
    "build",
    "run",
    "install",
    "configure",
    "update",
    "commit",
    "explain",
    "walk me through",
]

# Design doc Section 6.1 — dangerous keywords never suppressed
_DEFAULT_DANGEROUS_KEYWORDS = [
    "shell",
    "sudo",
    "chmod",
    "eval",
    "exec",
    "/etc/",
    "/root/",
    "/proc/",
    "/var/log",
    ".ssh/",
    "rm -rf",
    "passwd",
    "shadow",
]


@dataclass
class MTMConfig:
    """All tuneable constants for the Multi-Turn Monitor.

    Construct directly with keyword args for testing, or use
    MTMConfig.from_settings() to load from SENTINEL_MTM_* env vars.
    """

    # Aggregation formula weights (design doc Section 5.2)
    alpha: float = 2.0  # Persistence weight
    delta: float = 0.4  # Per-category diversity bonus
    beta_e: float = 0.5  # Escalation velocity bonus

    # Thresholds
    low_threshold: float = 0.5  # Turns above this count toward persistence
    warn_threshold: float = (
        5.0  # Session total above this = warn (tuned Phase 8 from 4.0)
    )
    block_threshold: float = (
        8.5  # Session total above this = block (tuned Phase 8 from 7.0)
    )

    # Sliding window
    window_size: int = 8  # Per-turn signal evaluation window

    # Benign session floor (design doc Section 5.4)
    benign_floor_turns: int = 3  # First N turns must score 0.0 for floor
    benign_floor_discount: float = 0.7  # Multiplier when floor active

    # Per-signal weight overrides (design doc Section 4.3)
    signal_weights: dict[str, float] = field(default_factory=dict)

    # FP management lists (design doc Section 6.1)
    benign_anchors: list[str] = field(
        default_factory=lambda: list(_DEFAULT_BENIGN_ANCHORS),
    )
    dangerous_keywords: list[str] = field(
        default_factory=lambda: list(_DEFAULT_DANGEROUS_KEYWORDS),
    )

    def __post_init__(self) -> None:
        """Validate constraints after construction."""
        if self.alpha < 0:
            msg = "alpha must be >= 0.0"
            raise ValueError(msg)
        if self.delta < 0:
            msg = "delta must be >= 0.0"
            raise ValueError(msg)
        if self.beta_e < 0:
            msg = "beta_e must be >= 0.0"
            raise ValueError(msg)
        if self.low_threshold < 0:
            msg = "low_threshold must be >= 0.0"
            raise ValueError(msg)
        if self.warn_threshold < 0:
            msg = "warn_threshold must be >= 0.0"
            raise ValueError(msg)
        if self.block_threshold <= self.warn_threshold:
            msg = "block_threshold must be > warn_threshold"
            raise ValueError(msg)
        if self.window_size < 1:
            msg = "window_size must be >= 1"
            raise ValueError(msg)
        if self.benign_floor_turns < 1:
            msg = "benign_floor_turns must be >= 1"
            raise ValueError(msg)
        if not (0.0 < self.benign_floor_discount <= 1.0):
            msg = "benign_floor_discount must be in (0.0, 1.0]"
            raise ValueError(msg)
        for name, weight in self.signal_weights.items():
            if weight < 0:
                msg = f"signal_weights[{name!r}] must be >= 0.0"
                raise ValueError(msg)

    @classmethod
    def from_settings(cls) -> MTMConfig:
        """Construct from the core Settings (SENTINEL_MTM_* env vars).

        Reads the current settings singleton and maps MTM-prefixed fields
        to MTMConfig constructor kwargs.
        """
        from sentinel.core.config import settings

        logger.debug(
            "MTMConfig.from_settings: loading config",
            extra={"event": "conversation.config.from_settings"},
        )

        signal_weights = _parse_json_dict(settings.mtm_signal_weights)
        benign_anchors = _parse_json_list(
            settings.mtm_benign_anchors,
            _DEFAULT_BENIGN_ANCHORS,
        )
        dangerous_keywords = _parse_json_list(
            settings.mtm_dangerous_keywords,
            _DEFAULT_DANGEROUS_KEYWORDS,
        )

        return cls(
            alpha=settings.mtm_alpha,
            delta=settings.mtm_delta,
            beta_e=settings.mtm_beta_e,
            low_threshold=settings.mtm_low_threshold,
            warn_threshold=settings.mtm_warn_threshold,
            block_threshold=settings.mtm_block_threshold,
            window_size=settings.mtm_window_size,
            benign_floor_turns=settings.mtm_benign_floor_turns,
            benign_floor_discount=settings.mtm_benign_floor_discount,
            signal_weights=signal_weights,
            benign_anchors=benign_anchors,
            dangerous_keywords=dangerous_keywords,
        )


def _parse_json_dict(raw: str) -> dict[str, float]:
    """Parse a JSON string into a dict[str, float], returning {} on failure."""
    if not raw or raw == "{}":
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {k: float(v) for k, v in parsed.items()}
    except (json.JSONDecodeError, ValueError, TypeError):
        logger.warning(
            "Failed to parse JSON dict for MTM config",
            extra={"event": "conversation.config.parse_error", "raw_len": len(raw)},
            exc_info=True,
        )
    return {}


def _parse_json_list(raw: str, default: list[str]) -> list[str]:
    """Parse a JSON string into a list[str], returning default on failure."""
    if not raw:
        return list(default)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except (json.JSONDecodeError, ValueError, TypeError):
        logger.warning(
            "Failed to parse JSON list for MTM config",
            extra={"event": "conversation.config.parse_error", "raw_len": len(raw)},
            exc_info=True,
        )
    return list(default)
