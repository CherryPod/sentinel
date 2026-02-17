"""Trust router — classifies operations by required trust tier.

Static allowlist approach: operations in SAFE_OPS bypass the full CaMeL pipeline
(still go through auth + sandbox). Everything else is DANGEROUS by default.
The LLM never classifies its own operations — this is deterministic.

Trust-level-aware classification (D3/D4/D5):
- TL1: SAFE_OPS only (internal state queries)
- TL2+: TL2_SAFE_OPS = SAFE_OPS + file_read (read-only file access)
  file_read still goes through ToolExecutor with full policy checks,
  provenance tracking, and trust inheritance — it just skips plan-level
  approval at TL2+.
- TL3+: file_write classified as PERMITTED (not SAFE). Still requires
  human plan approval. Enhanced pre-write Semgrep scanning activates.
- TL4+: Plan-policy enforcement. Planner generates per-step argument
  constraints (allowed_commands, allowed_paths). Constraint validator
  checks resolved commands/paths against constraints. Constitutional
  static denylist always blocks regardless of constraints.
"""

from enum import Enum


class TrustTier(str, Enum):
    SAFE = "safe"           # Bypass CaMeL, still auth + sandbox
    PERMITTED = "permitted"  # Allowed with approval + enhanced scanning (D4)
    DANGEROUS = "dangerous"  # Full CaMeL pipeline


# TL1 allowlist — internal state queries only.
# Immutable frozenset — cannot be modified at runtime.
# Note: email_send, email_draft, calendar_create_event, calendar_update_event,
# and calendar_delete_event are intentionally NOT in SAFE_OPS. These are write
# operations that modify external state (Gmail, Google Calendar) and must go
# through the full CaMeL pipeline with human approval at all trust levels.
# Read operations (email_search, email_read, calendar_list_events) are also
# excluded because they return UNTRUSTED external data that must be scanned.
SAFE_OPS = frozenset({
    "health_check",
    "session_info",
    "memory_search",
    "memory_list",
    "memory_store",
    "memory_recall_file",
    "memory_recall_session",
    "routine_list",
    "routine_get",
    "routine_history",
})

# TL2 allowlist — extends TL1 with read-only file access.
# file_read still runs through ToolExecutor (policy checks, provenance
# tracking, trust inheritance) — this only skips plan-level approval.
# file_write is intentionally NOT here — writes require approval at all levels.
TL2_SAFE_OPS = SAFE_OPS | frozenset({"file_read"})

# TL3 permitted ops — NOT auto-approvable, but classified distinctly from
# DANGEROUS at TL3+. Enables enhanced scanning (pre-write Semgrep) and
# signals that the operation has been red-teamed at this trust level.
# file_write NEVER enters SAFE_OPS — it always requires human plan approval.
TL3_PERMITTED_OPS = frozenset({"file_write"})


def classify_operation(op: str, trust_level: int = 1) -> TrustTier:
    """Classify an operation name into a trust tier.

    The classification depends on the trust level:
    - trust_level >= 2: TL2_SAFE_OPS (includes file_read) → SAFE
    - trust_level < 2:  SAFE_OPS (internal state queries only) → SAFE
    - trust_level >= 3: TL3_PERMITTED_OPS (file_write) → PERMITTED
    - Everything else → DANGEROUS

    PERMITTED is distinct from SAFE: it still requires human plan approval
    but activates enhanced scanning (pre-write Semgrep at TL3+).
    """
    safe_set = TL2_SAFE_OPS if trust_level >= 2 else SAFE_OPS
    if op in safe_set:
        return TrustTier.SAFE
    if trust_level >= 3 and op in TL3_PERMITTED_OPS:
        return TrustTier.PERMITTED
    return TrustTier.DANGEROUS
