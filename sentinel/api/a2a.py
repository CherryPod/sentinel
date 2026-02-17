"""A2A (Agent-to-Agent) protocol adapter for Sentinel.

Translates between Google's A2A JSON-RPC 2.0 protocol and Sentinel's
existing orchestrator/approval/event-bus internals. This is a thin
translation layer only -- no new business logic.

A2A spec: https://a2a-protocol.org/latest/specification/

Key mappings:
  A2A tasks/send        -> orchestrator.handle_task()
  A2A tasks/get         -> approval_manager.check_approval() + session lookup
  A2A tasks/cancel      -> not implemented (returns method-not-found)
  A2A tasks/sendSubscribe -> handle_task() + SSE stream from event bus

Sentinel task states -> A2A task states:
  awaiting_approval     -> input-required  (plan needs human approval)
  success               -> completed
  blocked / error       -> failed
  refused               -> failed
  denied                -> failed
  (in progress)         -> working
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from sentinel.core.bus import EventBus
from sentinel.core.config import settings
from sentinel.core.models import TaskResult
from sentinel.planner.orchestrator import Orchestrator

logger = logging.getLogger("sentinel.audit")


# ---- Agent Card (static metadata) ----------------------------------------

AGENT_CARD: dict[str, Any] = {
    "name": "Sentinel",
    "description": "Defence-in-depth AI assistant with CaMeL security pipeline",
    "url": "https://localhost:3001",
    "version": "0.3.0-alpha",
    "capabilities": {
        "streaming": True,
        "pushNotifications": False,
        "stateTransitionHistory": False,
    },
    "authentication": {
        "schemes": ["bearer"],
    },
    "defaultInputModes": ["text"],
    "defaultOutputModes": ["text"],
    "skills": [
        {
            "id": "general-task",
            "name": "General Task Execution",
            "description": (
                "Execute tasks through CaMeL security pipeline "
                "with planner + worker architecture"
            ),
        },
    ],
}


# ---- JSON-RPC 2.0 error codes -------------------------------------------

INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603


# ---- Sentinel -> A2A state mapping --------------------------------------

_STATE_MAP: dict[str, str] = {
    "awaiting_approval": "input-required",
    "success": "completed",
    "blocked": "failed",
    "error": "failed",
    "refused": "failed",
    "denied": "failed",
}


def map_sentinel_state(sentinel_status: str) -> str:
    """Convert a Sentinel TaskResult.status to an A2A task state."""
    return _STATE_MAP.get(sentinel_status, "failed")


# ---- A2A task response builder ------------------------------------------


def build_a2a_task(task_result: TaskResult) -> dict[str, Any]:
    """Build an A2A Task object from a Sentinel TaskResult.

    The A2A Task object contains: id, status (with state + optional message),
    and artifacts (for completed tasks with step output).
    """
    a2a_state = map_sentinel_state(task_result.status)

    # Build the status object -- includes message for human context
    status: dict[str, Any] = {"state": a2a_state}
    if task_result.reason:
        status["message"] = {"role": "agent", "parts": [{"text": task_result.reason}]}
    elif task_result.plan_summary:
        status["message"] = {"role": "agent", "parts": [{"text": task_result.plan_summary}]}

    task: dict[str, Any] = {
        "id": task_result.task_id or "unknown",
        "status": status,
    }

    # Attach artifacts for completed tasks -- collect step output as text parts
    if a2a_state == "completed" and task_result.step_results:
        parts = []
        for sr in task_result.step_results:
            if sr.content:
                parts.append({"text": sr.content})
        if parts:
            task["artifacts"] = [{"parts": parts}]

    # For input-required state, include approval_id so the client knows
    # which approval to submit
    if a2a_state == "input-required" and task_result.approval_id:
        status["message"] = {
            "role": "agent",
            "parts": [
                {
                    "text": (
                        f"Plan requires approval. "
                        f"approval_id={task_result.approval_id}. "
                        f"Summary: {task_result.plan_summary}"
                    ),
                },
            ],
        }

    return task


# ---- JSON-RPC response helpers ------------------------------------------


def jsonrpc_success(id: Any, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": "2.0", "id": id, "result": result}


def jsonrpc_error(id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": error}


# ---- JSON-RPC request parsing -------------------------------------------


def parse_jsonrpc_request(body: dict[str, Any]) -> tuple[Any, str, dict[str, Any]] | dict:
    """Parse a JSON-RPC 2.0 request body.

    Returns (id, method, params) on success, or a JSON-RPC error dict on failure.
    """
    if body.get("jsonrpc") != "2.0":
        return jsonrpc_error(
            body.get("id"),
            INVALID_REQUEST,
            "Missing or invalid jsonrpc version (must be '2.0')",
        )

    req_id = body.get("id")
    method = body.get("method")
    if not isinstance(method, str) or not method:
        return jsonrpc_error(req_id, INVALID_REQUEST, "Missing or invalid method")

    params = body.get("params", {})
    if not isinstance(params, dict):
        return jsonrpc_error(req_id, INVALID_REQUEST, "params must be an object")

    return (req_id, method, params)


# ---- Method handlers -----------------------------------------------------


async def handle_tasks_send(
    params: dict[str, Any],
    orchestrator: Orchestrator,
    client_ip: str,
) -> TaskResult:
    """Handle A2A tasks/send -- delegates to the existing orchestrator.

    Extracts the user message from the A2A Message object in params and
    calls handle_task() with the same logic as POST /api/task.
    """
    # A2A message: params.message.parts[0].text (simplified -- we accept
    # top-level "message" with "parts" containing "text")
    message = params.get("message", {})
    parts = message.get("parts", [])
    text_parts = [p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p]
    user_request = "\n".join(text_parts).strip()

    if not user_request:
        raise ValueError("No text content found in message parts")

    source_key = f"a2a:{client_ip}"
    try:
        result = await asyncio.wait_for(
            orchestrator.handle_task(
                user_request=user_request,
                source="a2a",
                approval_mode=settings.approval_mode,
                source_key=source_key,
            ),
            timeout=settings.api_task_timeout,
        )
    except asyncio.TimeoutError:
        return TaskResult(
            status="error",
            reason=f"Task timed out after {settings.api_task_timeout}s",
        )
    return result


async def handle_tasks_get(
    params: dict[str, Any],
    orchestrator: Orchestrator,
) -> dict[str, Any] | None:
    """Handle A2A tasks/get -- look up task status.

    Checks the approval manager for pending/completed approval states.
    Returns an A2A Task object or None if not found.
    """
    task_id = params.get("id", "")
    if not task_id:
        return None

    # Check the approval manager -- in Sentinel, the approval_id IS the
    # task identifier for the A2A flow (returned in tasks/send response)
    if orchestrator.approval_manager is not None:
        approval_status = await orchestrator.check_approval(task_id)
        status_val = approval_status.get("status", "not_found")

        if status_val != "not_found":
            # Map approval states to A2A states
            state_map = {
                "pending": "input-required",
                "approved": "working",
                "denied": "failed",
                "expired": "failed",
            }
            a2a_state = state_map.get(status_val, "failed")
            status: dict[str, Any] = {"state": a2a_state}

            # Add context message
            msg_text = approval_status.get("plan_summary") or approval_status.get("reason", "")
            if msg_text:
                status["message"] = {"role": "agent", "parts": [{"text": msg_text}]}

            return {"id": task_id, "status": status}

    return None


# ---- SSE streaming for tasks/sendSubscribe ------------------------------


async def a2a_sse_generator(
    task_result: TaskResult,
    event_bus: EventBus,
):
    """Yield A2A-formatted SSE events for a task.

    Subscribes to the Sentinel event bus for the given task_id and
    translates each internal event into an A2A StatusUpdate or
    TaskArtifactUpdate SSE message.
    """
    task_id = task_result.task_id
    queue: asyncio.Queue[dict] = asyncio.Queue()
    done = False

    async def _handler(topic: str, data):
        nonlocal done
        event_type = topic.split(".")[-1]  # e.g. "started", "completed"
        await queue.put({"event_type": event_type, "data": data})
        if event_type == "completed":
            done = True

    # Subscribe to task events
    pattern = f"task.{task_id}.*"
    event_bus.subscribe(pattern, _handler)

    try:
        # First: emit the initial task status from the synchronous result
        initial_task = build_a2a_task(task_result)
        yield {
            "event": "status",
            "data": json.dumps({"task": initial_task}),
        }

        # If the task is already terminal (completed/failed/input-required),
        # emit final event and stop
        initial_state = initial_task["status"]["state"]
        if initial_state in ("completed", "failed", "input-required"):
            yield {
                "event": "status",
                "data": json.dumps({"task": initial_task, "final": True}),
            }
            return

        # Stream events from the bus until task completes
        while not done:
            try:
                evt = await asyncio.wait_for(queue.get(), timeout=30.0)
                event_type = evt["event_type"]
                event_data = evt.get("data", {})

                # Map Sentinel bus events to A2A status updates
                if event_type == "completed":
                    state = "completed"
                    status_data = event_data.get("status", "success")
                    if status_data != "success":
                        state = "failed"
                elif event_type == "step_completed":
                    state = "working"
                elif event_type == "approval_requested":
                    state = "input-required"
                elif event_type == "started":
                    state = "working"
                else:
                    state = "working"

                status_obj: dict[str, Any] = {"state": state}
                msg_text = event_data.get("plan_summary") or event_data.get("status", "")
                if msg_text and isinstance(msg_text, str):
                    status_obj["message"] = {"role": "agent", "parts": [{"text": msg_text}]}

                task_update = {"id": task_id, "status": status_obj}
                is_final = state in ("completed", "failed", "input-required")

                yield {
                    "event": "status",
                    "data": json.dumps({"task": task_update, "final": is_final}),
                }

                if is_final:
                    break

            except asyncio.TimeoutError:
                # Send keepalive to prevent connection timeout
                yield {"comment": "keepalive"}

    finally:
        event_bus.unsubscribe(pattern, _handler)
