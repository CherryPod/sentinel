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

from sentinel.router.templates import TemplateRegistry
from sentinel.session.store import ConversationTurn

if TYPE_CHECKING:
    from sentinel.core.bus import EventBus
    from sentinel.security.pipeline import ScanPipeline
    from sentinel.session.store import Session
    from sentinel.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)

# Maximum messages to read in an email chain
_MAX_EMAIL_READ = 5

# BH3-028: Default timeout for individual tool executions (seconds)
_TOOL_EXECUTION_TIMEOUT = 120


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
        user_id: int = 1,
        skip_confirmation: bool = False,
    ) -> dict:
        """Execute a template and return a result dict.

        Returns:
            dict with keys: status, response, reason, template.
            status is one of "success", "blocked", "error".
        """
        # BH3-082: Reject new requests during graceful shutdown
        if self._shutdown:
            return {
                "status": "error",
                "response": None,
                "reason": "Fast-path is shutting down",
                "template": template_name,
            }

        # Look up template
        template = self._registry.get(template_name)
        if template is None:
            return {
                "status": "error",
                "response": None,
                "reason": f"Unknown template: {template_name}",
                "template": template_name,
            }

        await self._emit(task_id, "started", {
            "response": f"Running {template_name}...",
            "template": template_name,
        })

        # Default recipient for messaging tools — when no recipient was
        # extracted from the user message, fall back to the requesting user's
        # own channel identifier (e.g., send back to the Signal sender).
        from sentinel.contacts.resolver import (
            resolve_default_recipient,
            resolve_tool_recipient,
        )
        if (
            template_name in ("signal_send", "telegram_send")
            and not params.get("recipient")
            and self._contact_store is not None
        ):
            default = await resolve_default_recipient(
                self._contact_store, template.tool, user_id,
            )
            if default:
                params["recipient"] = default
                logger.info(
                    "Fast-path defaulted recipient to self for %s",
                    template_name,
                )

        # Resolve opaque recipient IDs before execution
        try:
            params = await resolve_tool_recipient(
                self._contact_store, template.tool, params,
            )
        except ValueError as exc:
            logger.warning(
                "Fast-path recipient resolution failed for %s: %s",
                template_name, exc,
            )
            await self._record_turn(session, template_name, "error")
            await self._emit(task_id, "completed", {
                "template": template_name,
                "status": "error",
                "reason": str(exc),
            })
            return {
                "status": "error",
                "response": None,
                "reason": str(exc),
                "template": template_name,
            }

        # Check if this template requires confirmation
        if (
            template.requires_confirmation
            and self._confirmation_gate is not None
            and not skip_confirmation
        ):
            preview = template.format_preview(params)
            source_key = session.session_id if session else "unknown"
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
            await self._emit(task_id, "awaiting_confirmation", {
                "template": template_name,
                "preview": preview,
                "confirmation_id": confirmation_id,
                "original_request": template_name,
            })
            return {
                "status": "awaiting_confirmation",
                "response": None,
                "reason": "",
                "template": template_name,
                "preview": preview,
                "confirmation_id": confirmation_id,
            }

        # Execute tool(s)
        try:
            if template.is_chain:
                output = await self._execute_chain(template, params)
            else:
                output = await self._execute_single(template.tool, params)
        except Exception as exc:
            logger.warning(
                "Fast-path tool error for %s: %s", template_name, exc,
            )
            await self._record_turn(session, template_name, "error")
            await self._emit(task_id, "completed", {
                "template": template_name,
                "status": "error",
                "reason": str(exc),
            })
            return {
                "status": "error",
                "response": None,
                "reason": str(exc),
                "template": template_name,
            }

        # Scan output through security pipeline
        from sentinel.security.pipeline import OutputDestination

        scan_result = await self._pipeline.scan_output(
            output, destination=OutputDestination.DISPLAY,
        )

        if not scan_result.is_clean:
            blockers = list(scan_result.violations.keys())
            logger.warning(
                "Fast-path output blocked by %s for %s",
                blockers, template_name,
            )
            await self._record_turn(
                session, template_name, "blocked", blocked_by=blockers,
            )
            await self._emit(task_id, "blocked", {
                "template": template_name,
                "blocked_by": blockers,
            })
            return {
                "status": "blocked",
                "response": None,
                "reason": f"Output blocked by: {', '.join(blockers)}",
                "template": template_name,
            }

        # Success — record turn and emit completion
        await self._record_turn(session, template_name, "success")
        await self._emit(task_id, "completed", {
            "template": template_name,
            "status": "success",
            "response": output,
        })

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
        """
        try:
            tagged, _ = await self._tools.execute(tool_name, tool_params)
            output = tagged.content
        except Exception as exc:
            logger.warning("Confirmed execution failed for %s: %s", tool_name, exc)
            return {"status": "error", "response": None, "reason": str(exc)}

        # Scan output through security pipeline
        from sentinel.security.pipeline import OutputDestination

        scan_result = await self._pipeline.scan_output(
            output, destination=OutputDestination.DISPLAY,
        )
        if not scan_result.is_clean:
            blockers = list(scan_result.violations.keys())
            logger.warning("Confirmed output blocked by %s for %s", blockers, tool_name)
            return {
                "status": "blocked",
                "response": None,
                "reason": f"Output blocked by: {', '.join(blockers)}",
            }

        await self._emit(task_id, "completed", {
            "status": "success",
            "response": output,
            "tool_name": tool_name,
        })

        return {"status": "success", "response": output, "reason": ""}

    async def _execute_single(self, tool_name: str, params: dict) -> str:
        """Execute a single tool and return its output as a string.

        BH3-028: Wrapped in asyncio.wait_for to prevent indefinite hangs.
        """
        tagged, _ = await asyncio.wait_for(
            self._tools.execute(tool_name, params),
            timeout=_TOOL_EXECUTION_TIMEOUT,
        )
        return tagged.content

    async def _execute_chain(self, template, params: dict) -> str:
        """Execute a chained template (tool_a+tool_b).

        Currently supports the email_search+email_read pattern:
        run the first tool, parse message IDs from JSON results,
        then call the second tool for each message.
        """
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
        self, search_result: str, params: dict,
    ) -> str:
        """Read individual emails from search results.

        Parses the search result as JSON, extracts message IDs,
        and calls email_read for each one (up to _MAX_EMAIL_READ).

        BH3-030: Logs per-message failures instead of silently dropping them.
        BH3-031: Individual reads use the same _TOOL_EXECUTION_TIMEOUT.
        """
        try:
            messages = json.loads(search_result)
        except (json.JSONDecodeError, TypeError):
            # If search result isn't JSON, return it as-is
            return search_result

        if not isinstance(messages, list):
            return search_result

        results = []
        for msg in messages[:_MAX_EMAIL_READ]:
            msg_id = msg.get("message_id") or msg.get("id")
            if msg_id:
                try:
                    body = await self._execute_single(
                        "email_read", {"message_id": str(msg_id)},
                    )
                except Exception as exc:
                    # BH3-030: Log failure instead of silently dropping
                    logger.warning(
                        "Email chain read failed for message %s: %s",
                        msg_id, exc,
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
            await self._session_store.add_turn(session.session_id, turn, session=session)

    async def _emit(
        self, task_id: str, event: str, data: dict,
    ) -> None:
        """Publish an event to the bus, if available.

        BH3-083: Wrapped in try/except — event emission failure should not
        crash the fast-path execution.
        """
        try:
            logger.info(
                "fast_path_emit_check",
                extra={"event": "fast_path_emit_check", "task_id": task_id, "has_bus": bool(self._bus), "event_name": event},
            )
            if self._bus and task_id:
                await self._bus.publish(f"task.{task_id}.{event}", data)
        except Exception as exc:
            logger.warning(
                "Fast-path event emission failed: %s",
                exc,
                extra={
                    "event": "fast_path_emit_error",
                    "task_id": task_id,
                    "event_name": event,
                    "error": str(exc),
                },
            )
