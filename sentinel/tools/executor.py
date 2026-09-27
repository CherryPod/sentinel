import hashlib
import json
import logging
import os
import re
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.tools.sandbox import PodmanSandbox

from sentinel.audit import AuditEmitter, SecurityAuditEvent
from sentinel.core.config import settings
from sentinel.core.context import current_user_id, get_task_id
from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.security.policy_engine import PolicyEngine
from sentinel.security.provenance import create_tagged_data
from sentinel.tools._handlers._registry import _DYNAMIC_DESCRIPTION
from sentinel.tools._handlers._task_exec_context import (
    TaskExecutionContext,
    get_current_task_context,
    reset_current_task_context,
    set_current_task_context,
)
from sentinel.tools.sidecar import SidecarClient

logger = logging.getLogger(__name__)

# Tools that can be dispatched to the WASM sidecar when enabled
WASM_TOOLS = frozenset({"file_read", "file_write", "shell_exec", "http_fetch"})

# Capability mapping: tool name → required sidecar capabilities
_WASM_TOOL_CAPABILITIES = {
    "file_read": ["read_file"],
    "file_write": ["write_file"],
    "shell_exec": ["shell_exec"],
    "http_fetch": ["http_request"],
}

# Tools that fetch external data — override trust to UNTRUSTED
_EXTERNAL_DATA_TOOLS: dict[str, tuple[DataSource, TrustLevel]] = {
    "http_fetch": (DataSource.WEB, TrustLevel.UNTRUSTED),
}

# Sentinel for "no authenticated user" — infrastructure tasks run at user_id 0
_NO_USER_CONTEXT = 0

# Shared types — canonical definitions in _handlers/_types.py.
# Re-exported here for backwards compatibility with existing imports.
from sentinel.tools._handlers._calendar import CalendarHandlerMixin
from sentinel.tools._handlers._constants import _MANIFEST_EXTENSIONS
from sentinel.tools._handlers._container import ContainerHandlerMixin
from sentinel.tools._handlers._email import EmailHandlerMixin
from sentinel.tools._handlers._external_data import ExternalDataHandlerMixin
from sentinel.tools._handlers._file_ops import (
    FILE_READ_MAX_BYTES,  # noqa: F401 — re-export for backwards compat
    FileOpsHandlerMixin,
)
from sentinel.tools._handlers._file_patch import PatchHandlerMixin
from sentinel.tools._handlers._file_write import WriteHandlerMixin
from sentinel.tools._handlers._messaging import MessagingHandlerMixin
from sentinel.tools._handlers._types import (  # noqa: F401
    ToolBlockedError,
    ToolError,
    _CredentialOverlay,
)
from sentinel.tools._handlers._website import WebsiteHandlerMixin


class ToolExecutor(
    EmailHandlerMixin,
    CalendarHandlerMixin,
    MessagingHandlerMixin,
    WriteHandlerMixin,
    PatchHandlerMixin,
    FileOpsHandlerMixin,
    WebsiteHandlerMixin,
    ExternalDataHandlerMixin,
    ContainerHandlerMixin,
):
    """Executes tool actions with policy validation before every operation.

    When a SidecarClient is provided and a tool is in WASM_TOOLS, the tool
    is dispatched to the Rust WASM sidecar for sandboxed execution. Non-WASM
    tools (podman_*, mkdir) always use the Python handlers.

    Handler groups are defined in mixin classes under _handlers/:
    - EmailHandlerMixin: email_search, email_read, email_send, email_draft (Gmail + IMAP)
    - CalendarHandlerMixin: calendar_list/create/update/delete (Google + CalDAV)
    - MessagingHandlerMixin: signal_send, telegram_send, matrix_send
    - WriteHandlerMixin / PatchHandlerMixin / FileOpsHandlerMixin: file_write, file_read, file_patch, mkdir, shell, sandbox
    - WebsiteHandlerMixin: website create/list/remove
    - ExternalDataHandlerMixin: web_search, x_search, crypto_price, weather
    - ContainerHandlerMixin: podman_build, podman_run, podman_stop
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        sidecar: SidecarClient | None = None,
        google_oauth: object | None = None,
        sandbox: "PodmanSandbox | None" = None,
        trust_level: int = 0,
        audit_emitter: "AuditEmitter | None" = None,
    ):
        self._engine = policy_engine
        self._sidecar = sidecar
        self._google_oauth = google_oauth
        self._sandbox = sandbox
        self._trust_level = trust_level
        self._audit_emitter: AuditEmitter | None = audit_emitter
        self._channel_registry = None
        self._credential_store = None
        self._episodic_store = None
        self._ingester = None

        # Handler dispatch — auto-discovered from @tool_handler decorators on
        # mixin methods. Dynamic handlers (messaging channels) are added later
        # via set_channel_registry(). See tools/_handlers/_registry.py.
        self._handlers = self._discover_handlers()

    def _discover_handlers(self) -> dict:
        """Build handler dispatch dict from @tool_handler-decorated mixin methods.

        Scans all methods on the instance for a __tool_meta__ attribute
        (set by the @tool_handler decorator). Maps tool name and aliases
        to the bound method.
        """
        handlers = {}
        # Track seen methods to avoid processing the same method twice
        # (Python MRO can expose the same method via multiple inheritance paths).
        seen = set()
        for attr_name in dir(self):
            # Skip dunder and known non-handler attributes for speed.
            if attr_name.startswith("__"):
                continue
            try:
                method = getattr(self, attr_name)
            except AttributeError:
                continue
            if not callable(method):
                continue
            meta = getattr(method, "__tool_meta__", None)
            if meta is None:
                continue
            if id(method) in seen:
                continue
            seen.add(id(method))
            handlers[meta.name] = method
            for alias in meta.aliases:
                handlers[alias] = method
        logger.debug(
            "Tool handlers discovered: %d tools",
            len(handlers),
            extra={
                "event": "executor.handlers_discovered",
                "tool_count": len(handlers),
                "tools": sorted(handlers.keys()),
            },
        )
        return handlers

    def _iter_tool_meta(self) -> list[tuple]:
        """Return (method, ToolMeta) for all @tool_handler-decorated methods.

        Deduplicates by method identity — aliases don't produce extra entries.
        Walks the MRO class hierarchy via vars() to preserve definition order
        within each class (dir() sorts alphabetically, which would change the
        tool description ordering seen by the planner). Final order:
        sorted by meta.order, then by MRO + definition order within ties.
        """
        logger.debug(
            "_iter_tool_meta called", extra={"event": "executor._iter_tool_meta"}
        )  # auto:entry
        seen_names: set[str] = set()
        items: list[tuple] = []
        # Walk MRO in reverse so that the most-derived class's definitions
        # appear first when there are overrides. For our mixin chain this
        # gives us: ToolExecutor → EmailHandler → Calendar → Messaging →
        # FileHandler → WebsiteHandler → ExternalDataHandler → ContainerHandler
        # But since we sort by order field, the MRO order only matters within
        # same-order ties.
        for cls in type(self).__mro__:
            for attr_name, attr_value in vars(cls).items():
                meta = getattr(attr_value, "__tool_meta__", None)
                if meta is None:
                    continue
                if meta.name in seen_names:
                    continue
                seen_names.add(meta.name)
                # Get the bound method from the instance
                method = getattr(self, attr_name)
                items.append((method, meta))
        items.sort(key=lambda x: x[1].order)
        return items

    # Tools whose "path" arg should be rewritten to per-user workspace dirs.
    _PATH_REWRITE_TOOLS = frozenset(
        {
            "file_write",
            "file_read",
            "file_patch",
            "mkdir",
            "shell",
            "shell_exec",
        }
    )

    def _rewrite_workspace_paths(self, tool_name: str, args: dict) -> dict:
        """Rewrite /workspace/ paths to /workspace/{user_id}/ for multi-user isolation.

        The planner uses /workspace/ as a virtual root. This method transparently
        inserts the current user's ID so the planner never decides which user
        directory to target.

        For file tools: rewrites the "path" arg.
        For shell tools: rewrites /workspace/ references in the "command" string.
        Returns a shallow copy if any rewrite occurred, original args otherwise.
        """
        if tool_name not in self._PATH_REWRITE_TOOLS:
            return args

        # Type validation at the trust boundary: applied regardless of user context
        # so non-string args always raise ToolError (not AttributeError/TypeError).
        if tool_name in ("shell", "shell_exec"):
            command = args.get("command", "")
            if not isinstance(command, str):
                raise ToolError(
                    "Invalid argument: command must be a string",
                    category="validation",
                )
        else:
            path = args.get("path", "")
            if not isinstance(path, str):
                raise ToolError(
                    "Invalid argument: path must be a string",
                    category="validation",
                )

        user_id = current_user_id.get()
        if user_id == _NO_USER_CONTEXT:
            # No user context (infrastructure task) — pass through unchanged
            return args

        workspace_prefix = settings.workspace_path.rstrip("/") + "/"  # "/workspace/"
        user_prefix = f"{workspace_prefix}{user_id}/"  # "/workspace/1/"

        if tool_name in ("shell", "shell_exec"):
            # Rewrite /workspace/ refs that aren't already user-scoped.
            # Negative lookahead: don't rewrite if already /workspace/{digit}/
            rewritten = re.sub(
                rf"{re.escape(workspace_prefix)}(?!\d+/)",
                user_prefix,
                command,
            )
            if rewritten != command:
                args = {**args, "command": rewritten}
                logger.debug(
                    "Rewrote workspace path in shell command",
                    extra={"event": "workspace.path_rewrite", "tool": tool_name},
                )
            return args

        # File tools: rewrite "path" arg
        if not path.startswith(workspace_prefix):
            return args
        # Already user-scoped? (e.g. /workspace/1/sites/...) — skip
        remainder = path[len(workspace_prefix) :]
        if remainder and remainder.split("/", 1)[0].isdigit():
            return args

        rewritten_path = user_prefix + remainder
        args = {**args, "path": rewritten_path}
        logger.debug(
            "Rewrote workspace path for multi-user isolation",
            extra={
                "event": "workspace.path_rewrite",
                "tool": tool_name,
                "original": path,
                "rewritten": rewritten_path,
            },
        )
        return args

    def set_channel_registry(self, registry: object) -> None:
        """Wire channel registry — dynamically registers messaging tool handlers.

        For each channel with a tool_name, creates a handler via
        _make_channel_handler() and registers it in the dispatch dict.
        """
        if self._channel_registry is not None:
            logger.warning(
                "Overwriting existing channel registry — possible lifecycle bug",
                extra={"event": "channel_registry.overwrite"},
            )
        self._channel_registry = registry
        for channel in registry.with_tools():
            tool_name = channel.descriptor.tool_name
            handler = self._make_channel_handler(channel)
            self._handlers[tool_name] = lambda args, h=handler: h(self, args)
            logger.debug(
                "Registered messaging handler: %s",
                tool_name,
                extra={"event": "executor.handler_registered", "tool": tool_name},
            )

    def set_episodic_store(self, episodic_store: object | None) -> None:
        """Wire episodic store for anchor map persistence."""
        self._episodic_store = episodic_store

    def set_ingester(self, ingester: object | None) -> None:
        """Wire attachment ingester for email attachment ingestion."""
        self._ingester = ingester

    def set_credential_store(self, credential_store: object | None) -> None:
        """Wire per-user credential store for email/calendar tools."""
        if self._credential_store is not None and credential_store is not None:
            logger.warning(
                "Overwriting existing credential store — possible lifecycle bug",
                extra={"event": "credential.store_overwrite"},
            )
        self._credential_store = credential_store

    async def _resolve_credentials(self, service: str) -> dict | None:
        """Look up per-user credentials for a service. Returns None if not configured."""
        if self._credential_store is None:
            return None
        return await self._credential_store.get(service)

    def get_tool_descriptions(self) -> list[dict]:
        """Build tool description list from @tool_handler metadata.

        Descriptions are auto-discovered from decorated mixin methods.
        Special cases:
        - http_fetch: sidecar-only tool, no Python handler, injected when sidecar is present
        - Messaging tools: dynamic, from channel registry via _messaging_tool_descriptions()
        - Tools with _DYNAMIC_DESCRIPTION: skipped (descriptions come from elsewhere)
        - Tools with an enabled() gate that returns False: skipped
        """
        descriptions = []
        for _method, meta in self._iter_tool_meta():
            # Skip tools whose descriptions are provided by another mechanism.
            if meta.description is _DYNAMIC_DESCRIPTION:
                continue
            # Skip tools gated by a settings check.
            if meta.enabled is not None and not meta.enabled():
                continue
            descriptions.append(meta.to_description_dict())

        # Sidecar-only tool — no Python handler, no decorator. Injected when
        # the sidecar is available (provides the WASM http_fetch module).
        if self._sidecar is not None:
            descriptions.append(
                {
                    "name": "http_fetch",
                    "description": "Fetch content from a URL via HTTPS. Results are UNTRUSTED external data. Only allowed domains in the policy allowlist are accessible. Supports GET, POST, PUT, DELETE methods.",
                    "args": {
                        "url": "string (HTTPS URL, must be in allowed domains)",
                        "method": "string (GET|POST|PUT|DELETE, default GET)",
                        "headers": "object (optional request headers)",
                        "body": "string (optional request body)",
                    },
                }
            )

        # Messaging tools — dynamic, from channel registry.
        descriptions.extend(self._messaging_tool_descriptions())

        return descriptions

    def _get_http_allowlist(self) -> list[str]:
        """Read http_tool_allowed_domains from policy YAML."""
        return self._engine.get_http_allowlist()

    async def execute(
        self,
        tool_name: str,
        args: dict,
        task_context: TaskExecutionContext | None = None,
        *,
        pipeline_run_id: str | None = None,
    ) -> tuple[TaggedData, dict | None]:
        """Execute a tool by name with policy checks.

        Returns (tagged_data, exec_meta) where exec_meta contains tool-specific
        metadata (exit_code, stderr, file sizes) or None if not applicable.

        WASM-capable tools are dispatched to the sidecar when available.

        Q17-F4 (D3, 2026-04-24): ``pipeline_run_id`` is a new optional
        caller-owned correlation id.  ``_dispatch_external_tool``
        allocates the id and threads it here so the ``tool.*`` envelope
        emitted by this method shares the same key as the downstream
        ``scan.*`` events.  ``scan_triggered`` is ``True`` only on
        ``tool.completed`` when **both** (a) the caller threaded a
        correlation id AND (b) the tagged output has non-empty content
        (the condition under which ``_scan_tool_output`` will actually
        fire ``pipeline.scan_output`` and produce ``scan.*`` events
        under that id).  ``False`` on dispatch entry (scan has not
        run yet), ``tool.blocked`` (block terminates before scan),
        ``tool.timeout`` (timeout terminates before scan), and on
        ``tool.completed`` with empty content (scan is short-circuited
        by ``_scan_tool_output``).  MG-1 Q17.fix.d merge-review fix:
        the content inspection closes a false-positive audit gap where
        operators querying ``tool.completed AND scan_triggered=True
        AND NOT EXISTS (scan.* WHERE details.pipeline_run_id = ...)``
        previously flagged empty-content tool calls.  Direct callers
        outside the tool-dispatch seam (tests, internal callers,
        fast-path routes) omit the kwarg — the details payload
        records ``pipeline_run_id=None`` + ``scan_triggered=False``
        in that case, keeping the schema shape stable.
        """
        # Extract args keys safely before the mapping check so tool.dispatch
        # is always emitted even for non-dict payloads — provides an audit trail
        # when an adversarial worker sends a malformed args value.
        args_keys = list(args.keys()) if isinstance(args, dict) else None
        logger.info(
            "Tool execution requested",
            extra={
                "event": "tool.execute",
                "tool": tool_name,
                "args_keys": args_keys,
                "task_id": get_task_id(),
                "has_pipeline_run_id": pipeline_run_id is not None,
            },
        )

        # Emit tool.dispatch audit event at entry.  scan_triggered=False
        # regardless of pipeline_run_id presence — the scan has not
        # run yet at dispatch time.
        await self._emit_tool_audit(
            "tool.dispatch",
            tool_name,
            "SUCCESS",
            "INFO",
            details={"tool_name": tool_name, "args_keys": args_keys},
            pipeline_run_id=pipeline_run_id,
            scan_triggered=False,
        )

        if not isinstance(args, dict):
            raise ToolError(
                "Invalid argument: args must be a mapping",
                category="validation",
            )

        # Multi-user workspace path translation: the planner uses /workspace/
        # as a virtual root but files actually live at /workspace/{user_id}/.
        # Rewrite args here so all downstream handlers (Python + sidecar) see
        # the real per-user path. The planner never decides the user directory.
        args = self._rewrite_workspace_paths(tool_name, args)

        # Loop detection: check for repeated identical tool calls before dispatch.
        # Per-task detector created fresh in TaskExecutionContext — no cross-task state.
        # Skip when task_context is None (backward compatibility with direct callers).
        if task_context is not None:
            task_context.loop_detector.check_and_record(tool_name, args)

        # Expose task context for handler mixins during this execute() call
        # via a per-asyncio-Task ContextVar (C45 2026-04-26 — replaces the
        # previous singleton instance attribute that raced under concurrent
        # execute() calls across cross-channel + multi-WebSocket reachability).
        # set/reset live in try/finally so each Task sees its own binding.
        try:
            token = set_current_task_context(task_context)
            t0 = time.monotonic()
            result = await self._execute_dispatch(tool_name, args)
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            # Q17-F4 MG-1 (2026-04-24): scan_triggered is True only when
            # (a) the caller threaded a pipeline_run_id AND (b) the
            # tagged output has non-empty content.  _scan_tool_output
            # (the only production caller of scan.* with the threaded
            # id) short-circuits on empty content (tool_dispatch.py
            # _scan_tool_output — `if not tagged.content: return None`),
            # so flagging scan_triggered=True here when content="" would
            # be a wire-contract lie — operators querying for "tool.completed
            # with scan_triggered=True AND no matching scan.manifest by
            # pipeline_run_id" would see false-positive audit gaps.  The
            # tagged content is the result[0] of the execute_dispatch
            # tuple per the return annotation.
            tagged_has_content = bool(
                result[0].content
                if (
                    isinstance(result, tuple)
                    and result
                    and hasattr(result[0], "content")
                )
                else False
            )
            await self._emit_tool_audit(
                "tool.completed",
                tool_name,
                "SUCCESS",
                "INFO",
                duration_ms=elapsed_ms,
                details={"tool_name": tool_name},
                pipeline_run_id=pipeline_run_id,
                scan_triggered=pipeline_run_id is not None and tagged_has_content,
            )
            return result
        except ToolBlockedError as exc:
            logger.exception(
                "execute: ToolBlockedError",
                extra={"event": "executor.execute_toolblockederror"},
            )  # auto:except
            # Block during execute terminates before _scan_tool_output
            # fires — scan_triggered=False.
            await self._emit_tool_audit(
                "tool.blocked",
                tool_name,
                "BLOCKED",
                "HIGH",
                details={"tool_name": tool_name, "reason": str(exc)[:200]},
                pipeline_run_id=pipeline_run_id,
                scan_triggered=False,
            )
            # Emit specific access event based on tool type
            await self._emit_access_blocked(tool_name, str(exc))
            raise
        except ToolError as exc:
            if "timed out" in str(exc):
                # Timeout terminates before scan — scan_triggered=False.
                await self._emit_tool_audit(
                    "tool.timeout",
                    tool_name,
                    "TIMEOUT",
                    "HIGH",
                    details={"tool_name": tool_name},
                    pipeline_run_id=pipeline_run_id,
                    scan_triggered=False,
                )
            raise
        finally:
            reset_current_task_context(token)

    # Tools where ToolBlockedError means file access was denied by policy
    _FILE_TOOLS = frozenset({"file_read", "file_write", "file_patch"})
    # Tools where ToolBlockedError means a command was denied by policy
    _COMMAND_TOOLS = frozenset({"shell", "shell_exec"})

    async def _emit_tool_audit(
        self,
        event_type: str,
        tool_name: str,
        outcome: str,
        severity: str,
        duration_ms: int | None = None,
        details: dict | None = None,
        *,
        pipeline_run_id: str | None = None,
        scan_triggered: bool = False,
    ) -> None:
        """Fire-and-forget tool audit event. Never raises to caller.

        Q17-F4 (D3, 2026-04-24): ``pipeline_run_id`` + ``scan_triggered``
        are included in the details payload so operators can join
        ``tool.*`` events to the downstream ``scan.*`` events from the
        same ingress via the correlation id directly.  ``scan_triggered``
        disambiguates the absence case: ``True`` means the caller
        (``_dispatch_external_tool``) will fire an output scan with
        the same ``pipeline_run_id`` after this audit event; ``False``
        means no scan runs in this outcome path (dispatch entry,
        blocked-during-execute, timeout, or tools whose output never
        flows through the scan seam).
        """
        if self._audit_emitter is None:
            return
        merged_details: dict = dict(details or {})
        merged_details["pipeline_run_id"] = pipeline_run_id
        merged_details["scan_triggered"] = scan_triggered
        try:
            await self._audit_emitter.emit(
                SecurityAuditEvent(
                    event_type=event_type,
                    source_component="executor",
                    outcome=outcome,
                    severity=severity,
                    duration_ms=duration_ms,
                    details=merged_details,
                )
            )
        except Exception:
            logger.debug(
                "Tool audit emit failed (non-fatal)",
                extra={"event": "tool.audit_emit_failed", "event_type": event_type},
            )

    async def _emit_access_blocked(self, tool_name: str, reason: str) -> None:
        """Emit access.file_blocked or access.command_blocked based on tool type."""
        if self._audit_emitter is None:
            return
        if tool_name in self._FILE_TOOLS:
            event_type = "access.file_blocked"
        elif tool_name in self._COMMAND_TOOLS:
            event_type = "access.command_blocked"
        else:
            return
        try:
            await self._audit_emitter.emit(
                SecurityAuditEvent(
                    event_type=event_type,
                    source_component="policy_engine",
                    outcome="BLOCKED",
                    severity="HIGH",
                    details={"tool_name": tool_name, "reason": reason[:200]},
                )
            )
        except Exception:
            logger.debug(
                "Access audit emit failed (non-fatal)",
                extra={"event": "access.audit_emit_failed", "event_type": event_type},
            )

    async def _execute_dispatch(
        self,
        tool_name: str,
        args: dict,
    ) -> tuple[TaggedData, dict | None]:
        """Inner dispatch — separated so execute() can wrap with context cleanup."""
        # NOTE: See U4/SIMP-1 — 18 tool handlers follow 3 repetitive patterns
        # (~600 lines of structural duplication in backend dispatch). Deduplication
        # deferred: the handler-per-tool pattern is more readable than a generic
        # dispatch framework for the current tool count.
        handler = self._handlers.get(tool_name)

        # Dispatch to sidecar for WASM-capable tools.
        # Falls back to Python handler if sidecar execution fails AND a
        # Python handler exists. Security blocks always propagate.
        if self._sidecar is not None and tool_name in WASM_TOOLS:
            try:
                tagged = await self._execute_via_sidecar(tool_name, args)
                # Build minimal exec_meta for file_write so the goal verifier
                # can see file sizes. Without this, the judge sees "no file
                # changes" and retries endlessly on completed tasks.
                sidecar_meta = None
                if tool_name == "file_write":
                    logger.debug(
                        "_execute_dispatch: tool_name_eq_file_write",
                        extra={
                            "event": "file.read_hash_skip_redacted.clean",
                            "reason": "tool_name_eq_file_write",
                        },
                    )  # auto:neg
                    sidecar_meta = self._build_sidecar_file_meta(args)
                elif tool_name == "file_read":
                    if tagged.content.startswith("[REDACTED"):
                        # Skip manifest/hash when sidecar redacted a credential
                        # leak — hashing the placeholder would poison before_hashes.
                        logger.info(
                            "file_read: skipping manifest/hash capture — "
                            "content redacted due to credential leak",
                            extra={
                                "event": "file.read_hash_skip_redacted",
                                "path": args.get("path", ""),
                            },
                        )
                    else:
                        logger.debug(
                            "_execute_dispatch: startswith_[REDACTED",
                            extra={
                                "event": "file.read_hash_skip_redacted.clean",
                                "reason": "startswith_[REDACTED",
                            },
                        )  # auto:neg
                        sidecar_meta = self._build_sidecar_file_read_meta(
                            args.get("path", ""),
                            tagged.content,
                        )
                return tagged, sidecar_meta
            except ToolBlockedError:
                raise  # Security blocks must never fall back
            except ToolError as exc:
                if handler is None:
                    raise  # No Python fallback for this tool (e.g. http_fetch)
                logger.warning(
                    "Sidecar dispatch failed, falling back to Python handler",
                    extra={
                        "event": "sidecar.fallback",
                        "tool": tool_name,
                        "error": str(exc),
                        "error_category": exc.category,
                        "error_class": "transient",
                        "task_id": get_task_id(),
                    },
                    exc_info=True,
                )
                # Fall through to Python handler below

        if handler is None:
            logger.warning(
                "Unknown tool requested",
                extra={"event": "tool.unknown", "tool": tool_name},
            )
            raise ToolError(f"Unknown tool: {tool_name}", category="validation")

        t0 = time.monotonic()
        result, exec_meta = await handler(args)
        elapsed = time.monotonic() - t0
        logger.info(
            "Tool execution complete",
            extra={
                "event": "tool.complete",
                "tool": tool_name,
                "data_id": result.id,
                "elapsed_s": round(elapsed, 3),
                "task_id": get_task_id(),
            },
        )
        return result, exec_meta

    async def _execute_via_sidecar(self, tool_name: str, args: dict) -> TaggedData:
        """Dispatch a tool to the WASM sidecar for sandboxed execution."""
        capabilities = _WASM_TOOL_CAPABILITIES.get(tool_name, [])

        # Build extra kwargs for specific tools
        extra_kwargs: dict = {}
        if tool_name == "http_fetch":
            extra_kwargs["http_allowlist"] = self._get_http_allowlist()

        t0 = time.monotonic()
        response = await self._sidecar.execute(
            tool_name=tool_name,
            args=args,
            capabilities=capabilities,
            **extra_kwargs,
        )
        elapsed = time.monotonic() - t0

        if not response.success:
            logger.warning(
                "Sidecar tool execution failed",
                extra={
                    "event": "sidecar.tool_failed",
                    "tool": tool_name,
                    "error_len": len(str(response.result)),
                    "elapsed_s": round(elapsed, 3),
                },
            )
            raise ToolError(f"sidecar: {response.result}", category="internal")

        if response.leaked:
            logger.warning(
                "Sidecar detected credential leak in output",
                extra={
                    "event": "sidecar.leak_detected",
                    "tool": tool_name,
                },
            )
            # E-003: Redact output when sidecar detects credential leak to prevent
            # credential propagation through the provenance chain.
            content = f"[REDACTED — credential leak detected in {tool_name} output]"
        else:
            # Convert SidecarResponse to TaggedData.
            # For file_read: the sidecar returns {"bytes": N, "content": "..."}
            # as structured data. Extract just the file content so downstream
            # consumers (Qwen via $var substitution) receive raw file content,
            # not a JSON wrapper they'd have to parse.
            logger.debug(
                "_execute_via_sidecar: leaked",
                extra={"event": "sidecar.leak_detected.clean", "reason": "leaked"},
            )  # auto:neg
            content = response.result
            if response.data is not None:
                if (
                    tool_name == "file_read"
                    and isinstance(response.data, dict)
                    and "content" in response.data
                ):
                    content = response.data["content"]
                else:
                    content = json.dumps(response.data)

        # Trust override for external data tools
        source, trust_level = _EXTERNAL_DATA_TOOLS.get(
            tool_name, (DataSource.TOOL, TrustLevel.TRUSTED)
        )

        tagged = await create_tagged_data(
            content=content,
            source=source,
            trust_level=trust_level,
            originated_from=f"sidecar:{tool_name}",
        )

        logger.info(
            "Sidecar tool execution complete",
            extra={
                "event": "sidecar.tool_complete",
                "tool": tool_name,
                "data_id": tagged.id,
                "elapsed_s": round(elapsed, 3),
                "fuel_consumed": response.fuel_consumed,
                "leaked": response.leaked,
            },
        )
        return tagged

    def _build_sidecar_file_meta(self, args: dict) -> dict | None:
        """Build exec_meta for sidecar file_write by statting the file.

        The sidecar doesn't return file sizes in its response, so the
        goal verifier sees "no file changes" and retries on success.
        This stats the file after write to provide the data the verifier
        needs.
        """
        path = args.get("path", "")
        if not path:
            return None
        try:
            file_size = os.path.getsize(path)
            return {
                "file_size_before": None,  # sidecar doesn't track pre-write size
                "file_size_after": file_size,
                "patch_operation": "write",
                "sidecar": True,
            }
        except OSError:
            logger.warning(
                "_build_sidecar_file_meta: OSError",
                extra={"event": "executor.build_sidecar_file_meta_oserror"},
                exc_info=True,
            )
            return None

    def _build_sidecar_file_read_meta(self, path: str, content: str) -> dict | None:
        """Build exec_meta for sidecar file_read: manifest + before_hash.

        The sidecar bypasses _file_read(), so manifest extraction and hash
        capture must happen here. Zero extra I/O — content already in memory.
        """
        exec_meta: dict = {"file_size": len(content)}

        # Content manifest — structural metadata for replan context
        try:
            from sentinel.analysis.content_manifest import extract_content_manifest

            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext in _MANIFEST_EXTENSIONS:
                exec_meta["content_manifest"] = extract_content_manifest(
                    os.path.basename(path),
                    content,
                    "",
                )
                logger.debug(
                    "sidecar file_read: content manifest extracted",
                    extra={"event": "content.manifest_file_read", "path": path},
                )
            else:
                logger.debug(
                    "sidecar file_read: manifest skipped (unsupported ext)",
                    extra={"event": "content.manifest_skip", "path": path, "ext": ext},
                )
        except Exception as exc:  # catch-all: manifest extraction best-effort
            logger.warning(
                "sidecar file_read: manifest extraction failed: %s",
                exc,
                extra={
                    "event": "content.manifest_error",
                    "path": path,
                    "error": str(exc),
                },
                exc_info=True,
            )

        # Before-hash for content_changed assertions — captured at read time
        # so the assertion evaluator can verify mutations actually occurred.
        # Use binary disk read to match the verifier's binary read in
        # _eval_content_changed() (verification.py). Fall back to encoding
        # the string content if disk read fails (file deleted between sidecar
        # read and this call).
        try:
            with open(path, "rb") as f:
                content_hash = hashlib.sha256(f.read()).hexdigest()
        except OSError as exc:
            logger.debug(
                "sidecar file_read: hash fallback to content encoding (disk read failed)",
                extra={
                    "event": "before.hash_fallback",
                    "path": path,
                    "reason": str(exc),
                },
            )
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        _ctx = get_current_task_context()
        if _ctx is not None:
            _ctx.file_hashes[path] = content_hash
        logger.debug(
            "sidecar file_read: before_hash captured",
            extra={
                "event": "before.hash_captured",
                "path": path,
                "hash_prefix": content_hash[:16],
            },
        )

        return exec_meta

    # Handler implementations are in mixin classes under _handlers/:
    # _file_write → WriteHandlerMixin, _file_patch → PatchHandlerMixin
    # _file_read, _mkdir, _shell, _execute_in_sandbox → FileOpsHandlerMixin
    # _website, _website_list, _website_create, _website_remove → WebsiteHandlerMixin
    # _web_search, _x_search, _crypto_price, _weather → ExternalDataHandlerMixin
    # _podman_build, _podman_run, _podman_stop, _check_podman_flags → ContainerHandlerMixin
    # _email_*, _calendar_* → Session 1A mixins
    # Messaging handlers (signal_send, etc.) → registered dynamically via _make_channel_handler
