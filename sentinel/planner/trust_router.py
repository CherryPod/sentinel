"""Trust router — classifies operations by required trust tier.

Static allowlist approach: operations in SAFE_OPS bypass the full CaMeL pipeline
(still go through auth + sandbox). Everything else is DANGEROUS by default.
The LLM never classifies its own operations — this is deterministic.

Not yet wired into the request flow — skeleton for Phase 2+ integration.
"""

from enum import Enum


class TrustTier(str, Enum):
    SAFE = "safe"           # Bypass CaMeL, still auth + sandbox
    DANGEROUS = "dangerous"  # Full CaMeL pipeline


# Static allowlist of operations that are safe to bypass CaMeL for.
# Immutable frozenset — cannot be modified at runtime.
SAFE_OPS = frozenset({
    "health_check",
    "session_info",
    "memory_search",
    "memory_list",
    "memory_store",
    "routine_list",
    "routine_get",
    "routine_history",
})


def classify_operation(op: str) -> TrustTier:
    """Classify an operation name into a trust tier.

    Everything not in the static SAFE_OPS allowlist is DANGEROUS by default.
    """
    if op in SAFE_OPS:
        return TrustTier.SAFE
    return TrustTier.DANGEROUS
