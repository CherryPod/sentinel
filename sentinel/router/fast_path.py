"""Fast-path executor for template-matched requests.

Executes single-tool (or chained-tool) templates, scans the output
through the security pipeline, records conversation turns, and emits
events. This bypasses the full Claude planner for simple operations.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING

from sentinel.core.config import settings
from sentinel.core.context import require_user_id
from sentinel.core.exceptions import ToolBlockedError
from sentinel.crypto.blind_index import log_hash
from sentinel.session.store import ConversationTurn

if TYPE_CHECKING:
    from sentinel.core.bus import EventBus
    from sentinel.router.templates import TemplateRegistry
    from sentinel.security.pipeline import ScanPipeline
    from sentinel.session.store import Session
    from sentinel.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)

# Maximum messages to read in an email chain
_MAX_EMAIL_READ = 5

# Q11-F12: fast-path tool execution deadline aligned to settings.tool_timeout
# (shared with planner at _step_executors.py). Removes prior 120s literal
# drift; SENTINEL_TOOL_TIMEOUT env override widens BOTH planes.


class FastPathExecutor:
    """Executes fast-path templates with security scanning and audit trail.

    All tool output is scanned via the security pipeline before being
    returned. Failures (tool errors, scan blocks) are recorded as
    conversation turns and emitted as events.
    """

    def __init__(
        self,
        tool_executor: ToolExecutor,
        pipeline: ScanPipeline,
        event_bus: EventBus | None,
        registry: TemplateRegistry,
        session_store=None,
        contact_store=None,
        confirmation_gate=None,
    ) -> None:
        self._tools = tool_executor
        self._pipeline = pipeline
        self._bus = event_bus
        self._registry = registry
        self._session_store = session_store
        self._contact_store = contact_store
        self._confirmation_gate = confirmation_gate
        # BH3-082: Shutdown flag — reject new requests during graceful shutdown
        self._shutdown = False

    def shutdown(self) -> None:
        """Signal that no new fast-path requests should be accepted."""
        self._shutdown = True

    async def execute(
        self,
        template_name: str,
        params: dict,
        session: Session,
        task_id: str,
        user_id: int | None = None,
        skip_confirmation: bool = False,
    ) -> dict:
        """Execute a template and return a result dict.

        Returns:
            dict with keys: status, response, reason, template.
            status is one of "success", "blocked", "error".
        """
        user_id = require_user_id(user_id, "FastPathExecutor.execute")
        # BH3-082: Reject new requests during graceful shutdown
        if self._shutdown:
            logger.debug(
                "execute: rejected during shutdown",
                extra={
                    "event": "fast_path.execute.shutdown_reject",
                    "template": template_name,
                },
            )
            return {
                "status": "error",
                "response": None,
                "reason": "Fast-path is shutting down",
                "template": template_name,
            }
        logger.debug(
            "execute: shutdown_passed",
            extra={
                "event": "fast_path.execute.shutdown_reject.passed",
                "reason": "shutdown_passed",
            },
        )  # auto:neg

        # BH3-DEF1: Scan Qwen-extracted param values before execution.
        # RoutineEngine._try_fast_path calls execute with skip_confirmation=True
        # and classification.params — Qwen could inject different values than
        # what the user's raw message contained. Mirror router._dispatch_fast.
        param_text = " ".join(str(v) for v in params.values() if v is not None)
        if param_text:
            try:
                param_scan = await self._pipeline.scan_input(param_text)
            except Exception:  # catch-all: param scan crash — fail closed
                logger.warning(
                    "Param input scan failed for %s",
                    template_name,
                    extra={
                        "event": "fast_path.param_scan_failed",
                        "template": template_name,
                    },
                    exc_info=True,
                )
                await self._record_turn(session, template_name, "error")
                await self._emit(
                    task_id,
                    "completed",
                    {"template": template_name, "status": "error", "reason": "Request processing failed"},
                )
                return {
                    "status": "error",
                    "response": None,
                    "reason": "Request processing failed",
                    "template": template_name,
                }
            if not param_scan.is_clean:
                blockers = list(param_scan.violated_scanners())
                logger.warning(
                    "Fast-path params blocked by %s for %s",
                    blockers,
                    template_name,
                    extra={
                        "event": "fast_path.param_blocked",
                        "template": template_name,
                        "blockers": blockers,
                    },
                )
                await self._record_turn(session, template_name, "blocked", blocked_by=blockers)
                await self._emit(
                    task_id,
                    "blocked",
                    {"template": template_name, "blocked_by": blockers},
                )
                return {
                    "status": "blocked",
                    "response": None,
                    "reason": f"Params blocked by: {', '.join(blockers)}",
                    "template": template_name,
                }

        # Resolve template and validate/resolve recipient params
        result = await self._resolve_and_validate_template(
            template_name,
            params,
            session,
            task_id,
            user_id,
        )
        if isinstance(result, dict):
            # Early exit — unknown template or recipient resolution error
            return result
        template, params = result

        await self._emit(
            task_id,
            "started",
            {
                "response": f"Running {template_name}...",
                "template": template_name,
            },
        )

        # Check if this template requires confirmation before execution
        confirmation = await self._check_confirmation_required(
            template,
            template_name,
            params,
            session,
            task_id,
            user_id,
            skip_confirmation,
        )
        if confirmation is not None:
            return confirmation

        # Execute tool(s) and scan through security pipeline
        return await self._execute_and_scan(
            template,
            template_name,
            params,
            session,
            task_id,
        )

    async def _resolve_and_validate_template(
        self,
        template_name: str,
        params: dict,
        session: Session,
        task_id: str,
        user_id: int,
    ) -> tuple | dict:
        """Look up template, resolve default and opaque recipient IDs.

        Returns:
            (template, params) on success, or an error result dict on failure.
        """
        template = self._registry.get(template_name)
        if template is None:
            logger.debug(
                "execute: unknown template",
                extra={
                    "event": "fast_path.execute.unknown_template",
                    "template": template_name,
                },
            )
            return {
                "status": "error",
                "response": None,
                "reason": f"Unknown template: {template_name}",
                "template": template_name,
            }

        # Default recipient for messaging tools — when no recipient was
        # extracted from the user message, fall back to the requesting user's
        # own channel identifier (e.g., send back to the Signal sender).
        from sentinel.contacts.resolver import (
            resolve_default_recipient,
            resolve_tool_recipient,
        )

        if (
            template_name.endswith("_send")
            and template_name != "email_send"
            and not params.get("recipient")
            and self._contact_store is not None
        ):
            default = await resolve_default_recipient(
                self._contact_store,
                template.tool,
                user_id,
            )
            if default:
                params["recipient"] = default
                logger.info(
                    "Fast-path defaulted recipient to self for %s",
                    template_name,
                    extra={
                        "event": "fast_path.default_recipient",
                        "template": template_name,
                    },
                )

        # Resolve opaque recipient IDs before execution
        try:
            params = await resolve_tool_recipient(
                self._contact_store,
                template.tool,
                params,
            )
        except ValueError as exc:
            logger.warning(
                "Fast-path recipient resolution failed for %s: %s",
                template_name,
                exc,
                exc_info=True,
            )
            await self._record_turn(session, template_name, "error")
            await self._emit(
                task_id,
                "completed",
                {
                    "template": template_name,
                    "status": "error",
                    "reason": str(exc),
                },
            )
            return {
                "status": "error",
                "response": None,
                "reason": str(exc),
                "template": template_name,
            }

        return template, params

    async def _check_confirmation_required(
        self,
        template,
        template_name: str,
        params: dict,
        session: Session,
        task_id: str,
        user_id: int,
        skip_confirmation: bool,
    ) -> dict | None:
        """Check if this template requires confirmation before execution.

        Returns:
            An awaiting_confirmation result dict if confirmation is needed,
            or None if execution should proceed.
        """
        if not (
            template.requires_confirmation
            and self._confirmation_gate is not None
            and not skip_confirmation
        ):
            return None

        logger.debug(
            "execute: requires confirmation",
            extra={
                "event": "fast_path.execute.awaiting_confirmation",
                "template": template_name,
            },
        )
        preview = template.format_preview(params)
        # Q3-F6: fail closed instead of falling back to a shared "unknown" key.
        # A silent fallback keys two same-user confirmations under one string;
        # the second cancels the first (confirmation.py cancel-on-create
        # semantics), silently dropping a pending confirmation.
        if session is None:
            raise RuntimeError(
                "fast_path confirmation requires a bound session "
                "(session_id is the source_key)"
            )
        source_key = session.session_id
        confirmation_id = await self._confirmation_gate.create(
            user_id=user_id,
            channel=session.source if session else "",
            source_key=source_key,
            tool_name=template.tool,
            tool_params=params,
            preview_text=preview,
            original_request=template_name,
            task_id=task_id or "",
        )
        await self._emit(
            task_id,
            "awaiting_confirmation",
            {
                "template": template_name,
                "preview": preview,
                "confirmation_id": confirmation_id,
                "original_request": template_name,
            },
        )
        return {
            "status": "awaiting_confirmation",
            "response": None,
            "reason": "",
            "template": template_name,
            "preview": preview,
            "confirmation_id": confirmation_id,
        }

    async def _execute_and_scan(
        self,
        template,
        template_name: str,
        params: dict,
        session: Session,
        task_id: str,
    ) -> dict:
        """Execute tool(s), scan output through security pipeline, return result.

        Handles tool dispatch (chain vs single), tool errors, security scan
        violations, and success recording.
        """
        # Execute tool(s)
        try:
            if template.is_chain:
                logger.debug(
                    "execute: dispatching chain",
                    extra={
                        "event": "fast_path.execute.chain",
                        "template": template_name,
                    },
                )
                output = await self._execute_chain(template, params)
            else:
                logger.debug(
                    "execute: dispatching single tool",
                    extra={
                        "event": "fast_path.execute.single",
                        "template": template_name,
                    },
                )
                output = await self._execute_single(template.tool, params)
        except ToolBlockedError:
            # D5 enforcement error (PolicyEngine / loop-detector / handler-level
            # security raise). Mirror Q4.fix.f Option B narrow-raise precedent
            # (commit 57d4084d) — let it propagate to the caller so the
            # `status="blocked"` / BLOCKED severity audit semantics stay
            # distinguishable from generic tool errors. ToolExecutor already
            # emitted the `tool.blocked` + `_emit_access_blocked` HIGH audit
            # before re-raising (executor.py:416-430), so propagation does not
            # lose the audit trail. Without this narrow, the broad
            # `except Exception` below would remap the D5 block to a generic
            # `status="error"`, and routines' `_try_fast_path` fall-back
            # (engine.py:873-886) would treat it like a routine tool failure.
            raise
        except Exception as exc:  # catch-all: fast-path tool execution isolation
            # Q14-F6 (class-enumeration sibling of execute_confirmed below):
            # generic except Exception → raw str(exc) in user-facing `reason`.
            # Upstream tool handlers can raise with internal paths / arg text /
            # asyncpg schema hints. Fixed safe reason on both the user-return
            # dict AND the _emit event body (event-bus drives SSE + WebSocket
            # task events — also user-visible surface). Detail stays server-side
            # via exc_info=True on the warning above.
            logger.warning(
                "Fast-path tool error for %s: %s",
                template_name,
                exc,
                extra={
                    "event": "fast_path.tool_error",
                    "template": template_name,
                },
                exc_info=True,
            )
            await self._record_turn(session, template_name, "error")
            await self._emit(
                task_id,
                "completed",
                {
                    "template": template_name,
                    "status": "error",
                    "reason": "Tool execution failed",
                },
            )
            return {
                "status": "error",
                "response": None,
                "reason": "Tool execution failed",
                "template": template_name,
            }

        # Scan output through security pipeline
        from sentinel.security.pipeline import OutputDestination

        scan_result = await self._pipeline.scan_output(
            output,
            destination=OutputDestination.DISPLAY,
        )

        if not scan_result.is_clean:
            blockers = list(scan_result.violated_scanners())
            logger.warning(
                "Fast-path output blocked by %s for %s",
                blockers,
                template_name,
                extra={
                    "event": "fast_path.output_blocked",
                    "template": template_name,
                    "blockers": blockers,
                },
            )
            await self._record_turn(
                session,
                template_name,
                "blocked",
                blocked_by=blockers,
            )
            await self._emit(
                task_id,
                "blocked",
                {
                    "template": template_name,
                    "blocked_by": blockers,
                },
            )
            return {
                "status": "blocked",
                "response": None,
                "reason": f"Output blocked by: {', '.join(blockers)}",
                "template": template_name,
            }
        logger.debug(
            "_execute_and_scan: not_is_clean_passed",
            extra={
                "event": "fast_path.output_blocked.passed",
                "reason": "not_is_clean_passed",
            },
        )  # auto:neg

        # Success — record turn and emit completion
        await self._record_turn(session, template_name, "success")
        await self._emit(
            task_id,
            "completed",
            {
                "template": template_name,
                "status": "success",
                "response": output,
            },
        )

        return {
            "status": "success",
            "response": output,
            "reason": "",
            "template": template_name,
        }

    async def execute_confirmed(
        self,
        tool_name: str,
        tool_params: dict,
        task_id: str,
    ) -> dict:
        """Execute a previously-confirmed tool call with its stored payload.

        Called by the router after the user replies "go". The params are the
        exact resolved payload stored at confirmation time — no re-derivation.
        BH3-DEF1 param scan already ran inside execute() before the
        confirmation entry was created; no re-scan here by design.
        """
        try:
            tagged, _ = await asyncio.wait_for(
                self._tools.execute(tool_name, tool_params),
                timeout=settings.tool_timeout,
            )
            output = tagged.content
        except ToolBlockedError:
            # Same narrow-raise as execute() (see above) — D5 enforcement
            # exceptions must remain distinguishable from generic tool errors.
            raise
        except Exception as exc:  # catch-all: tool execution isolation
            # Q14-F6: raw str(exc) was surfaced to the user via the return dict's
            # `reason`. Channel confirmation path (router/router.py:360-364) and
            # REST /api/confirm (task.py:411) both copy this reason into their
            # user-facing TaskResult / JSON response. Fixed safe reason for the
            # user surface; detail stays server-side via exc_info=True.
            logger.warning(
                "Confirmed execution failed for %s: %s",
                tool_name,
                exc,
                extra={
                    "event": "fast_path.confirmed_error",
                    "tool_name": tool_name,
                },
                exc_info=True,
            )
            return {
                "status": "error",
                "response": None,
                "reason": "Confirmation processing failed",
            }

        # Scan output through security pipeline
        from sentinel.security.pipeline import OutputDestination

        scan_result = await self._pipeline.scan_output(
            output,
            destination=OutputDestination.DISPLAY,
        )
        if not scan_result.is_clean:
            blockers = list(scan_result.violated_scanners())
            logger.warning(
                "Confirmed output blocked by %s for %s",
                blockers,
                tool_name,
                extra={
                    "event": "fast_path.confirmed_output_blocked",
                    "tool_name": tool_name,
                    "blockers": blockers,
                },
            )
            return {
                "status": "blocked",
                "response": None,
                "reason": f"Output blocked by: {', '.join(blockers)}",
            }
        logger.debug(
            "execute_confirmed: not_is_clean_passed",
            extra={
                "event": "fast_path.confirmed_output_blocked.passed",
                "reason": "not_is_clean_passed",
            },
        )  # auto:neg

        await self._emit(
            task_id,
            "completed",
            {
                "status": "success",
                "response": output,
                "tool_name": tool_name,
            },
        )

        return {"status": "success", "response": output, "reason": ""}

    async def _execute_single(self, tool_name: str, params: dict) -> str:
        """Execute a single tool and return its output as a string.

        BH3-028: Wrapped in asyncio.wait_for to prevent indefinite hangs.
        """
        tagged, _ = await asyncio.wait_for(
            self._tools.execute(tool_name, params),
            timeout=settings.tool_timeout,
        )
        return tagged.content

    async def _execute_chain(self, template, params: dict) -> str:
        """Execute a chained template (tool_a+tool_b).

        Currently supports the email_search+email_read pattern:
        run the first tool, parse message IDs from JSON results,
        then call the second tool for each message.
        """
        logger.debug(
            "_execute_chain called",
            extra={
                "event": "fast_path._execute_chain",
                "template_name": template.name,
                "params_count": len(params),
            },
        )
        tools = template.tool_chain
        if len(tools) < 2:
            return await self._execute_single(tools[0], params)

        # Execute first tool in the chain
        first_result = await self._execute_single(tools[0], params)

        # For email_search+email_read, parse and fetch each message
        if tools[0] == "email_search" and tools[1] == "email_read":
            return await self._chain_email_read(first_result, params)

        # Generic fallback: just return first tool's result
        return first_result

    async def _chain_email_read(
        self,
        search_result: str,
        params: dict,
    ) -> str:
        """Read individual emails from search results.

        Parses the search result as JSON, extracts message IDs,
        and calls email_read for each one (up to _MAX_EMAIL_READ).

        BH3-030: Logs per-message failures instead of silently dropping them.
        BH3-031: Individual reads use the same settings.tool_timeout.
        """
        try:
            messages = json.loads(search_result)
        except (json.JSONDecodeError, TypeError):
            # If search result isn't JSON, return it as-is
            logger.debug(
                "chain_email_read: search result not JSON, returning as-is",
                extra={
                    "event": "fast_path.chain_email_read.not_json",
                    "result_len": len(search_result),
                },
            )
            return search_result

        if not isinstance(messages, list):
            return search_result

        results = []
        for msg in messages[:_MAX_EMAIL_READ]:
            msg_id = msg.get("message_id") or msg.get("id")
            if msg_id:
                try:
                    body = await self._execute_single(
                        "email_read",
                        {"message_id": str(msg_id)},
                    )
                except Exception as exc:  # catch-all: email chain read isolation
                    # BH3-030: Log failure instead of silently dropping
                    # D27-B: hash msg_id; fixed-template + exc_info=False (C76 discipline)
                    # D27-B-fix: guard all str() calls; pathological __str__ must not escape isolation
                    msg_id_str = ""
                    exc_str = ""
                    try:
                        msg_id_str = str(msg_id)
                        exc_str = str(exc)
                    except Exception:
                        pass
                    logger.warning(
                        "Email chain read failed",
                        extra={
                            "event": "fast_path.chain_email_read.message_failed",
                            "msg_id_hash": log_hash(msg_id_str),
                            "msg_id_len": len(msg_id_str),
                            "error_class": type(exc).__name__,
                            "error_str_len": len(exc_str),
                        },
                        exc_info=False,
                    )
                    continue
                results.append(body)

        return "\n---\n".join(results) if results else search_result

    async def _record_turn(
        self,
        session: Session | None,
        template_name: str,
        status: str,
        blocked_by: list[str] | None = None,
    ) -> None:
        """Record a ConversationTurn on the session."""
        if session is None:
            return
        turn = ConversationTurn(
            request_text=template_name,
            result_status=status,
            blocked_by=blocked_by or [],
            plan_summary=f"fast-path: {template_name}",
        )
        session.add_turn(turn)
        if self._session_store is not None:
            await self._session_store.add_turn(
                session.session_id, turn, session=session
            )

    async def _emit(
        self,
        task_id: str,
        event: str,
        data: dict,
    ) -> None:
        """Publish an event to the bus, if available.

        BH3-083: Wrapped in try/except — event emission failure should not
        crash the fast-path execution.
        """
        try:
            if self._bus and task_id:
                logger.debug(
                    "fast_path emit",
                    extra={
                        "event": "fast_path.emit",
                        "task_id": task_id,
                        "event_name": event,
                    },
                )
                await self._bus.publish(f"task.{task_id}.{event}", data)
        except Exception as exc:  # catch-all: event publish best-effort
            logger.warning(
                "Fast-path event emission failed: %s",
                exc,
                extra={
                    "event": "fast_path.emit_error",
                    "task_id": task_id,
                    "event_name": event,
                    "error": str(exc),
                },
                exc_info=True,
            )
