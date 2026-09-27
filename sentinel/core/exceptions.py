"""Unified exception hierarchy for Sentinel.

Every custom exception inherits from ``SentinelError`` and carries
``retryable`` (bool) and ``category`` (str) fields for consistent error
handling, logging, and retry decisions across the codebase.

Subsystem groups:

    SentinelError
    ├── SecurityError  — security pipeline violations
    ├── PlannerError   — Claude planner failures
    ├── ToolError      — tool execution failures
    ├── ChannelError   — messaging / integration failures
    ├── ProviderError  — LLM / worker backend failures
    └── ResourceError  — infrastructure (crypto, DB, sidecar)

Backward compatibility: exceptions are re-exported from their original
locations so existing imports continue to work.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.security._scan_context import ScanResult

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class SentinelError(Exception):
    """Base exception for all Sentinel errors.

    All subclasses inherit ``retryable`` and ``category`` so callers can make
    uniform retry / classification decisions.
    """

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = "internal",
    ):
        super().__init__(message)
        self.retryable = retryable
        self.category = category


# ---------------------------------------------------------------------------
# Security subsystem
# ---------------------------------------------------------------------------


class SecurityError(SentinelError):
    """Base for security-related errors."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = "security",
    ):
        super().__init__(message, retryable=retryable, category=category)


class ViolationPhase(Enum):
    """When in the pipeline a violation occurred."""

    INPUT = "input"
    OUTPUT = "output"


class SecurityViolation(SecurityError):
    """Raised when the scan pipeline detects a security violation.

    ``violations`` is the new-shape frozen ``ScanResult`` from
    ``sentinel.security._scan_context`` — consumers iterate
    ``violations.verdicts`` or call
    ``violations.unsuppressed_by_scanner()`` / ``violated_scanners()``
    to reconstruct per-scanner groupings.  Pre-9d-ii callers passed
    ``dict[str, ScanResult]`` keyed by scanner name; gates now build a
    synthetic single-scanner ``ScanResult`` via
    ``sentinel.security._gate_violations.build_gate_scan_result``.
    """

    def __init__(
        self,
        message: str,
        violations: ScanResult,
        raw_response: str | None = None,
        phase: ViolationPhase = ViolationPhase.INPUT,
        *,
        retryable: bool = False,
        category: str = "security",
    ):
        super().__init__(message, retryable=retryable, category=category)
        self.violations = violations
        # Qwen's raw output when violation is post-Qwen (output scan, echo scan).
        # None for pre-Qwen violations (input scan, ASCII gate, prompt length gate).
        self.raw_response = raw_response
        self.phase = phase


class PromptGuardError(SecurityError):
    """Error loading or running Prompt Guard model."""


# ---------------------------------------------------------------------------
# Planner subsystem
# ---------------------------------------------------------------------------


class PlannerError(SentinelError):
    """General error from the Claude planner.

    Error return patterns in the planner module (M-NEW4):
    - **raise PlannerError/subclass** — unrecoverable failures during planning
      or API calls.  Caller (orchestrator) catches and converts to TaskResult.
    - **return TaskResult(status="error")** — used by orchestrator when the
      error is already handled and a user-facing result is needed.
    - **return IntakeResult** — used by the API route layer to wrap HTTP
      responses; never raised, always returned.
    """


class PlannerRefusalError(PlannerError):
    """Claude refused to plan this request (security feature, not an error)."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = "security",
    ):
        super().__init__(message, retryable=retryable, category=category)


class PlanValidationError(PlannerError):
    """The plan produced by Claude failed validation."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = "validation",
    ):
        super().__init__(message, retryable=retryable, category=category)


# ---------------------------------------------------------------------------
# Tool subsystem
# ---------------------------------------------------------------------------


class ToolError(SentinelError):
    """Error during tool execution.

    Error return patterns in the tool module (M-NEW4):
    - **raise ToolError** — tool logic failed (bad input, missing file,
      sandbox error).  Executor catches and returns error TaggedData.
    - **raise ToolBlockedError** — policy/security blocked execution.
      Never falls back to alternative handler.
    - **return (TaggedData, meta)** — normal success path from handlers.

    User-facing message hygiene policy (FL-C25-a4 / D34, 2026-05-01):
    ``ToolError.__str__()`` flows raw to the planner gap-synth pipeline
    AND to REST/SSE/A2A/channel/admin-log surfaces (``tool_dispatch.py``
    re-wraps to ``f"Tool execution failed: {exc}"`` and places that on
    ``StepResult.error`` — see ``_execution.py``, ``orchestrator.py``,
    ``a2a.py``, ``api/routes/task.py``, ``api/routes/websocket.py``,
    ``channels/mcp_server.py``). The planner-side
    ``_sanitise_error`` / ``genericise_error`` scrubbers protect ONLY
    the Worker-LLM input path, not the user/operator/A2A surfaces.
    Source-side hygiene at the raise site is therefore load-bearing.

    User-facing messages MUST NOT interpolate:

    - Exception text (``{exc}``, ``str(exc)``) — fully attacker-or-OS-
      controlled.
    - Validator-rejected user identifier values (filenames, paths,
      action names, site IDs) — these are unbounded attacker-controlled
      strings; the validator just rejected them.
    - Regex pattern internals (e.g. ``{self._FILENAME_RE.pattern}``) —
      mild defence-internal disclosure.
    - Filesystem details derived from ``{exc}``, raw paths, errno text.

    Messages MAY include the field name (``"site_id"``, ``"filename"``),
    the constraint description in plain English, and a safe location
    for list/map items where multi-item debugging matters
    (``"in 'files' map"``, ``"a media item"``).

    Operator correlation MUST happen server-side via
    ``logger.warning(..., extra={"<field>_len": <int>,
    "<field>_hash": log_hash(<value>)}, ...)`` using field-specific
    extras keys (e.g. ``site_id_len`` / ``site_id_hash``,
    ``filename_len`` / ``filename_hash``) per the existing
    ``policy_engine.py`` / ``constraint_validator.py`` /
    ``confirmation.py`` / ``resolver.py`` / ``matrix_channel.py``
    precedent. ``log_hash`` lives at ``sentinel/crypto/blind_index.py``.

    ``tool_dispatch.py``'s re-wrap (``f"Tool execution failed: {exc}"``)
    is harmless on the user-facing-content axis after this cure, since
    the inner ``ToolError`` message is already fixed-template. Future
    authors must not interpret that wrap as licence to re-add
    interpolated detail at the dispatch boundary.

    Scope: this policy applies to ``ToolError`` user-facing surfaces
    only. Nearby ``logger.debug`` / ``logger.info`` extras that log raw
    identifiers are server-side observability sinks and out of scope
    here (separate threat-model).
    """


class ToolBlockedError(ToolError):
    """Tool execution blocked by policy."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = "security",
    ):
        super().__init__(message, retryable=retryable, category=category)


class SearchError(ToolError):
    """Error during web search."""


class CryptoPriceError(ToolError):
    """Error during crypto price fetch."""


class WeatherError(ToolError):
    """Error during weather fetch."""


class XSearchError(ToolError):
    """Error during X search via Grok."""


# ---------------------------------------------------------------------------
# Channel subsystem (messaging / integrations)
# ---------------------------------------------------------------------------


class ChannelError(SentinelError):
    """Base for messaging and integration errors."""


class GmailError(ChannelError):
    """Error from Gmail API operations."""


class CalendarError(ChannelError):
    """Error from Google Calendar API operations."""


class CalDavError(ChannelError):
    """Error from CalDAV operations."""


class ImapEmailError(ChannelError):
    """Error from IMAP/SMTP operations."""


class OAuthError(ChannelError):
    """Error during OAuth2 token management."""


# ---------------------------------------------------------------------------
# Provider subsystem (LLM / worker backends)
# ---------------------------------------------------------------------------


class ProviderError(SentinelError):
    """Base exception for all provider errors."""


class ProviderConnectionError(ProviderError):
    """Cannot reach the provider backend."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = True,
        category: str = "resource",
    ):
        super().__init__(message, retryable=retryable, category=category)


class ProviderTimeoutError(ProviderError):
    """Request to the provider timed out."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = True,
        category: str = "resource",
    ):
        super().__init__(message, retryable=retryable, category=category)


class ProviderModelNotFound(ProviderError):
    """Requested model is not available on the provider."""


# ---------------------------------------------------------------------------
# Resource subsystem (infrastructure)
# ---------------------------------------------------------------------------


class ResourceError(SentinelError):
    """Base for infrastructure / resource errors."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = "resource",
    ):
        super().__init__(message, retryable=retryable, category=category)


class DecryptionError(ResourceError):
    """Raised when credential decryption fails (wrong key, corrupted data).

    .. deprecated::
        Re-parented under :class:`CryptoError`.  This alias preserves the
        old ``ResourceError`` import path until callers migrate.
    """


# ---------------------------------------------------------------------------
# Crypto subsystem
# ---------------------------------------------------------------------------


class CryptoError(SentinelError):
    """Base for all cryptographic errors."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        category: str = "crypto",
    ):
        super().__init__(message, retryable=retryable, category=category)


class CryptoConfigError(CryptoError):
    """Key not found in production mode, invalid crypto config."""


class KeyDerivationError(CryptoError):
    """HKDF derivation failure."""


class BlindIndexError(CryptoError):
    """HMAC computation failure."""


# Re-parent DecryptionError under CryptoError.  This shadows the
# ResourceError subclass above — ``except ResourceError`` will NO
# LONGER catch DecryptionError.  No existing callers use that pattern
# (verified via codebase search).  New code should catch CryptoError.
class DecryptionError(CryptoError):  # type: ignore[no-redef]  # noqa: F811
    """Decryption failure — wrong key, corrupted data, AAD mismatch."""
