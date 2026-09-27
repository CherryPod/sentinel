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
import time
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from sentinel.channels.webhook import _IDEMPOTENCY_MAX_SIZE
from sentinel.core.bus import EventBus
from sentinel.core.config import settings
from sentinel.core.context import current_user_id
from sentinel.core.models import DataSource, TaskResult, TrustLevel
from sentinel.planner.orchestrator import Orchestrator
from sentinel.security.provenance import create_tagged_data

logger = logging.getLogger(__name__)


# ---- Agent Card (static metadata) ----------------------------------------

AGENT_CARD: dict[str, Any] = {
    "name": "Sentinel",
    "description": "Defence-in-depth AI assistant with CaMeL security pipeline",
    "version": "0.3.0-alpha",
    # `supportedInterfaces` replaces the top-level `url` (proto v1.0.0 drops
    # AgentCard.url, moves endpoint URL inside AgentInterface). The URL is
    # rewritten at request time by `_resolve_agent_card` in routes/a2a.py
    # (BH3-023 behaviour preserved); the default value below is a marker.
    "supportedInterfaces": [
        {
            "url": "REPLACED_AT_REQUEST_TIME",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        },
    ],
    "capabilities": {
        "streaming": True,
        "pushNotifications": False,
        # `stateTransitionHistory` intentionally dropped — not in proto v1.0.0
        # AgentCapabilities. Strict-proto ParseDict rejects it.
    },
    # Proto field 8: security_schemes: map<string, SecurityScheme>. The oneof
    # branch name (`apiKeySecurityScheme`) is the nested key under proto3-to-JSON
    # mapping.
    "securitySchemes": {
        "sessionCookie": {
            "apiKeySecurityScheme": {
                "description": (
                    "Session JWT delivered via HttpOnly cookie named 'session'. "
                    "Obtain out-of-band via the Sentinel /api/auth/login endpoint."
                ),
                "location": "cookie",
                "name": "session",
            },
        },
    },
    # Proto field 9: security_requirements. Proto-native nested shape
    # {"schemes": {name: {"list": [...]}}} — NOT legacy OpenAPI-flat
    # {name: [scopes]}; strict-proto ParseDict rejects legacy shape.
    "securityRequirements": [
        {"schemes": {"sessionCookie": {"list": []}}},
    ],
    # Media types per proto comments ("Defined as media types.").
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [
        {
            "id": "general-task",
            "name": "General Task Execution",
            "description": (
                "Execute tasks through CaMeL security pipeline "
                "with planner + worker architecture"
            ),
            # REQUIRED per proto AgentSkill.tags.
            "tags": ["general", "task-execution", "agent"],
        },
    ],
}


# ---- JSON-RPC 2.0 error codes -------------------------------------------

INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603
# Q13.fix.a (F9): server-defined code (-32000..-32099 reserved per JSON-RPC 2.0
# §5.1) signalling a caller-supplied params.id tuple the server has already
# processed within the TTL window. Mirrors webhook dedup (HTTP 409).
DUPLICATE_REQUEST = -32002

# Maximum allowed length for user request text via A2A
MAX_TEXT_LENGTH = 50_000

# Q13.fix.a (F9): TTL (seconds) for the (user_id, params.id) idempotency cache.
# Matches webhook timestamp_tolerance default (300s). Retries within the window
# are rejected with DUPLICATE_REQUEST; retries after expiry are accepted and
# treated as new tasks (fail-open — attacker cannot extend the window).
A2A_IDEMPOTENCY_TTL_S = 300


# Q13.fix.a (F9): process-local dedup cache for A2A tasks/send — keyed by the
# composite `f"{user_id}:{task_id}"` so a malicious caller cannot replay
# another user's captured request ID. In-memory only; restart clears the cache
# (acceptable for single-instance deployments — the A2A invariant is "don't
# duplicate-process within a freshness window," not persistent nonce storage).
#
# Two-phase access pattern (check-then-record-on-success, Codex review F9-C-1
# 2026-04-24): the lookup `_is_a2a_duplicate` runs pre-work and does NOT
# mutate the cache; the recorder `_record_a2a_nonce` runs AFTER the
# orchestrator returns successfully. This guarantees a transient downstream
# failure (TimeoutError, create_tagged_data exception, orchestrator raise)
# leaves the caller's id unrecorded, so a legitimate retry within the TTL
# window is admitted instead of poisoned-rejected. The single-asyncio-loop
# atomicity contract (no `await` between dict membership check and dict
# write) still holds inside each helper.
_a2a_idempotency_cache: dict = {}


class DuplicateTaskError(Exception):
    """Raised by handle_tasks_send when params.id matches a recent call.

    Q13.fix.a (F9): A2A JSON-RPC spec §TaskSendParams.id carries caller-
    supplied idempotency. Sentinel detects duplicates by `(user_id, task_id)`
    and surfaces them as JSON-RPC DUPLICATE_REQUEST (-32002). The route layer
    catches this exception and returns the JSON-RPC error envelope.
    """


def _is_a2a_duplicate(nonce: str, seen: dict, ttl: int) -> bool:
    """Lookup-only duplicate check for A2A tasks/send (Codex F9-C-1).

    Returns True iff `nonce` is present and its timestamp is within `ttl`
    seconds of now. Does NOT mutate `seen`; the caller records the nonce
    post-work via `_record_a2a_nonce` so transient downstream failures
    do not poison the caller's id for the full TTL window.

    Expired entries are removed lazily (cache hygiene); this is a mutation
    but never of the caller's own fresh-admit id. No `await` between
    check and any write — asyncio event-loop atomic per webhook convention.
    """
    logger.debug(
        "_is_a2a_duplicate called",
        extra={
            "event": "api.a2a._is_a2a_duplicate",
            "nonce_type": type(nonce).__name__,
            "seen_len": len(seen) if hasattr(seen, "__len__") else 0,
            "ttl": ttl,
        },
    )  # auto:entry
    now = time.monotonic()
    stored = seen.get(nonce)
    if stored is None:
        return False
    if now - stored <= ttl:
        return True
    # Expired — evict so memory doesn't leak. The caller's post-work record
    # will overwrite this slot anyway, but cleaning here keeps the cache
    # tight under steady state and is safe: an expired entry is, by
    # definition, not a duplicate.
    del seen[nonce]
    return False


def _record_a2a_nonce(nonce: str, seen: dict) -> None:
    """Record a successful A2A tasks/send id AFTER the orchestrator returns
    (Codex F9-C-1 — post-work record phase).

    Caps `seen` at `_IDEMPOTENCY_MAX_SIZE` (BH3-014, 10k entries); when at
    capacity, evicts the oldest entry by stored `now`-timestamp before
    inserting the new one. No `await` between the capacity check and the
    `seen[nonce] = now` write — asyncio event-loop atomic.
    """
    now = time.monotonic()
    while len(seen) >= _IDEMPOTENCY_MAX_SIZE:
        oldest_key = min(seen, key=seen.get)  # type: ignore[arg-type]
        del seen[oldest_key]
    seen[nonce] = now


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
    logger.debug(
        "build_a2a_task called",
        extra={
            "event": "a2a.build_a2a_task",
            "task_result_type": type(task_result).__name__,
        },
    )
    a2a_state = map_sentinel_state(task_result.status)

    # Build the status object -- includes message for human context
    status: dict[str, Any] = {"state": a2a_state}
    if task_result.reason:
        logger.debug(
            "build_a2a_task: match", extra={"event": "a2a.build_a2a_task.match"}
        )
        status["message"] = {"role": "agent", "parts": [{"text": task_result.reason}]}
    elif task_result.plan_summary:
        logger.debug(
            "build_a2a_task: clean", extra={"event": "a2a.build_a2a_task.clean"}
        )
        status["message"] = {
            "role": "agent",
            "parts": [{"text": task_result.plan_summary}],
        }

    task: dict[str, Any] = {
        "id": task_result.task_id or "unknown",
        "status": status,
    }

    # Attach artifacts for completed tasks -- collect step output as text parts
    if a2a_state == "completed" and task_result.step_results:
        logger.debug(
            "build_a2a_task: match", extra={"event": "a2a.build_a2a_task.match"}
        )
        parts = []
        for sr in task_result.step_results:
            if sr.content:
                logger.debug(
                    "build_a2a_task: match", extra={"event": "a2a.build_a2a_task.match"}
                )
                parts.append({"text": sr.content})
        if parts:
            logger.debug(
                "build_a2a_task: match", extra={"event": "a2a.build_a2a_task.match"}
            )
            task["artifacts"] = [{"parts": parts}]

    # For input-required state, include approval_id so the client knows
    # which approval to submit
    if a2a_state == "input-required" and task_result.approval_id:
        logger.debug(
            "build_a2a_task: match", extra={"event": "a2a.build_a2a_task.match"}
        )
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


def parse_jsonrpc_request(
    body: dict[str, Any],
) -> tuple[Any, str, dict[str, Any]] | dict:
    """Parse a JSON-RPC 2.0 request body.

    Returns (id, method, params) on success, or a JSON-RPC error dict on failure.
    """
    logger.debug(
        "parse_jsonrpc_request called",
        extra={
            "event": "a2a.parse_jsonrpc_request",
            "body_len": len(body) if hasattr(body, "__len__") else 0,
        },
    )
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
    logger.debug(
        "handle_tasks_send called",
        extra={
            "event": "a2a.handle_tasks_send",
            "params_len": len(params) if hasattr(params, "__len__") else 0,
            "client_ip": client_ip,
        },
    )
    message = params.get("message", {})
    parts = message.get("parts", [])
    text_parts = [
        p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p
    ]
    user_request = "\n".join(text_parts).strip()

    if not user_request:
        raise ValueError("No text content found in message parts")

    # Input length limit — prevent oversized payloads from consuming resources
    if len(user_request) > MAX_TEXT_LENGTH:
        raise ValueError(
            f"Request text too long ({len(user_request)} chars, max {MAX_TEXT_LENGTH})"
        )

    user_id = current_user_id.get()
    if user_id == 0:
        raise HTTPException(
            status_code=401,
            detail="authenticated endpoint requires user context",
        )

    # Q13.fix.a (F9): replay/dedup per A2A spec §TaskSendParams.id. When the
    # caller supplies a string `id`, reject any byte-identical POST from the
    # same user_id within A2A_IDEMPOTENCY_TTL_S. Missing/non-string `id`
    # preserves the pre-fix behaviour (each call mints a fresh source_key
    # and is treated as a new task). The composite cache key user_id:task_id
    # prevents a malicious caller from replaying another user's captured id.
    #
    # Codex F9-C-1 (2026-04-24): the duplicate CHECK runs pre-work and does
    # NOT write to the cache. The nonce is recorded post-work only on
    # successful orchestrator return — a TimeoutError (504) or downstream
    # raise leaves the id unrecorded, so a legitimate retry within the TTL
    # window is admitted instead of poisoned-rejected.
    caller_task_id = params.get("id")
    cache_nonce: str | None = None
    if isinstance(caller_task_id, str) and caller_task_id:
        cache_nonce = f"{user_id}:{caller_task_id}"
        if _is_a2a_duplicate(
            cache_nonce, _a2a_idempotency_cache, ttl=A2A_IDEMPOTENCY_TTL_S
        ):
            logger.warning(
                "A2A tasks/send duplicate rejected",
                extra={
                    "event": "a2a.duplicate_task",
                    "user_id": user_id,
                    "task_id_len": len(caller_task_id),
                },
            )
            raise DuplicateTaskError(
                f"duplicate tasks/send within {A2A_IDEMPOTENCY_TTL_S}s window"
            )

    source_key = f"a2a:{user_id}:{uuid4()}"

    # Q8.fix.b — wrap the A2A message as UNTRUSTED at the adapter boundary
    # after multi-part concatenation. A2A parts are caller-supplied text; the
    # adapter extracts only `text` keys and ignores caller-supplied trust
    # fields (D4 fail-closed: no caller trust assertions accepted).
    tagged_request = await create_tagged_data(
        content=user_request,
        source=DataSource.USER,
        trust_level=TrustLevel.UNTRUSTED,
        originated_from=f"ingress:a2a:{source_key}",
    )
    user_request_data_id = tagged_request.id
    logger.info(
        "A2A ingress tagged UNTRUSTED",
        extra={
            "event": "a2a.ingress_tagged",
            "user_id": user_id,
            "data_id": user_request_data_id,
            "request_len": len(user_request),
        },
    )

    try:
        result = await asyncio.wait_for(
            orchestrator.handle_task(
                user_request=user_request,
                source="a2a",
                approval_mode=settings.approval_mode,
                source_key=source_key,
                user_request_data_id=user_request_data_id,
            ),
            timeout=settings.api_task_timeout,
        )
    except TimeoutError:
        logger.warning(
            "A2A task timed out", exc_info=True, extra={"event": "a2a.task_timeout"}
        )
        # Codex F9-C-1: do NOT record the nonce — timeout is transient and
        # the caller should be allowed to retry with the same params.id.
        return TaskResult(
            status="error",
            reason=f"Task timed out after {settings.api_task_timeout}s",
        )

    # Codex F9-C-1: post-work dedup RECORD. We only reach here if the
    # orchestrator returned a result (any `status` — success, denied, refused,
    # blocked are all legitimate business outcomes). If `create_tagged_data`
    # or `orchestrator.handle_task` raised, control does not reach this
    # line and the nonce is never stored, so a retry is admitted.
    if cache_nonce is not None:
        _record_a2a_nonce(cache_nonce, _a2a_idempotency_cache)

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
            # Ownership check: verify the approval belongs to the requesting user.
            # Approval user_id is set when the task was created — if present, it
            # must match the current authenticated user.
            approval_user_id = approval_status.get("user_id")
            uid = current_user_id.get()
            if approval_user_id is not None and approval_user_id != uid:
                return None  # treat as not found to avoid leaking existence
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
            msg_text = approval_status.get("plan_summary") or approval_status.get(
                "reason", ""
            )
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
    logger.debug(
        "a2a_sse_generator called",
        extra={
            "event": "a2a.a2a_sse_generator",
            "task_result_type": type(task_result).__name__,
            "event_bus_type": type(event_bus).__name__,
        },
    )
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
            logger.debug(
                "a2a_sse_generator: match",
                extra={"event": "a2a.a2a_sse_generator.match"},
            )
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
                    logger.debug(
                        "a2a_sse_generator: match",
                        extra={"event": "a2a.a2a_sse_generator.match"},
                    )
                    state = "completed"
                    status_data = event_data.get("status", "success")
                    if status_data != "success":
                        state = "failed"
                elif event_type == "step_completed":
                    logger.debug(
                        "a2a_sse_generator: clean",
                        extra={"event": "a2a.a2a_sse_generator.clean"},
                    )
                    state = "working"
                elif event_type == "approval_requested":
                    logger.debug(
                        "a2a_sse_generator: clean",
                        extra={"event": "a2a.a2a_sse_generator.clean"},
                    )
                    state = "input-required"
                elif event_type == "started":
                    logger.debug(
                        "a2a_sse_generator: clean",
                        extra={"event": "a2a.a2a_sse_generator.clean"},
                    )
                    state = "working"
                else:
                    logger.debug(
                        "a2a_sse_generator: clean",
                        extra={"event": "a2a.a2a_sse_generator.clean"},
                    )
                    state = "working"

                status_obj: dict[str, Any] = {"state": state}
                msg_text = event_data.get("plan_summary") or event_data.get(
                    "status", ""
                )
                if msg_text and isinstance(msg_text, str):
                    logger.debug(
                        "a2a_sse_generator: match",
                        extra={"event": "a2a.a2a_sse_generator.match"},
                    )
                    status_obj["message"] = {
                        "role": "agent",
                        "parts": [{"text": msg_text}],
                    }

                task_update = {"id": task_id, "status": status_obj}
                is_final = state in ("completed", "failed", "input-required")

                yield {
                    "event": "status",
                    "data": json.dumps({"task": task_update, "final": is_final}),
                }

                if is_final:
                    break

            except TimeoutError:
                # Send keepalive to prevent connection timeout
                # Keepalive timeout is expected — send comment to keep connection alive
                logger.debug(
                    "SSE keepalive sent",
                    extra={"event": "a2a.sse_keepalive", "task_id": task_id},
                )
                yield {"comment": "keepalive"}

    finally:
        event_bus.unsubscribe(pattern, _handler)
