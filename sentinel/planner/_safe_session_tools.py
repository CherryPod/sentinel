"""Safe session/routine/health tool handlers.

Mixin providing handler methods for session-related safe tools: health_check,
session_info, routine_list, routine_get, routine_history. These share
``_session_store``, ``_routine_store``, and ``_routine_engine`` dependencies.
Mixed into SafeToolHandlers by the facade (safe_tools.py).
"""

import json
import logging

from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.security.provenance import create_tagged_data

logger = logging.getLogger(__name__)


class SessionToolsMixin:
    """Handlers for session/routine/health SAFE tools."""

    _planner: object
    _pipeline: object
    _memory_store: object
    _session_store: object
    _event_bus: object
    _routine_store: object
    _routine_engine: object

    async def health_check(self, args: dict) -> TaggedData:
        """Check component availability and return status dict."""
        logger.debug(
            "health_check called",
            extra={
                "event": "safe_tools.health_check",
                "args_len": len(args) if hasattr(args, "__len__") else 0,
            },
        )  # auto:entry
        from sentinel.security import prompt_guard as pg
        from sentinel.security import semgrep_scanner as sg

        status = {
            "planner_available": self._planner is not None,
            "pipeline_available": self._pipeline is not None,
            "semgrep_loaded": sg.is_loaded(),
            "prompt_guard_loaded": pg.is_loaded()
            if hasattr(pg, "is_loaded")
            else False,
            "memory_store": self._memory_store is not None,
            "session_store": self._session_store is not None,
            "routine_store": self._routine_store is not None,
            "routine_engine": self._routine_engine is not None,
            "event_bus": self._event_bus is not None,
        }
        content = json.dumps(status, indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )

    async def session_info(self, args: dict) -> TaggedData:
        """Get session state: risk score, turns, lock status."""
        logger.debug(
            "session_info called",
            extra={
                "event": "safe_tools.session_info",
                "args_len": len(args) if hasattr(args, "__len__") else 0,
            },
        )  # auto:entry
        if self._session_store is None:
            raise RuntimeError("Session store not available")
        session_id = args.get("session_id", "")
        if not session_id:
            logger.debug(
                "session_info: not_session_id",
                extra={
                    "event": "safe_tools.session_info.match",
                    "reason": "not_session_id",
                },
            )  # auto:neg
            raise RuntimeError("No session_id provided")
        logger.debug(
            "session_info: not_session_id_passed",
            extra={
                "event": "safe_tools.session_info.passed",
                "reason": "not_session_id_passed",
            },
        )  # auto:neg
        session = await self._session_store.get(session_id)
        if session is None:
            content = json.dumps({"error": "Session not found"})
        else:
            content = json.dumps(
                {
                    "session_id": session.session_id,
                    "turn_count": len(session.turns),
                    "cumulative_risk": session.cumulative_risk,
                    "violation_count": session.violation_count,
                    "is_locked": session.is_locked,
                }
            )
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
        )

    async def routine_list(self, args: dict) -> TaggedData:
        """List all routines."""
        if self._routine_store is None:
            raise RuntimeError("Routine store not available")
        enabled_only = str(args.get("enabled_only", "false")).lower() == "true"
        try:
            limit = min(int(args.get("limit", 100)), 100)
        except (TypeError, ValueError):
            logger.warning(
                "routine_list: invalid limit parameter, using default",
                exc_info=True,
                extra={"event": "safe_tools.routine_list_fallback"},
            )
            limit = 100
        routines = await self._routine_store.list(
            enabled_only=enabled_only, limit=limit
        )
        content = json.dumps(
            [
                {
                    "routine_id": r.routine_id,
                    "name": r.name,
                    "trigger_type": r.trigger_type,
                    "enabled": r.enabled,
                    "last_run_at": r.last_run_at,
                    "next_run_at": r.next_run_at,
                }
                for r in routines
            ],
            indent=2,
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
        )

    async def routine_get(self, args: dict) -> TaggedData:
        """Get a single routine by ID."""
        logger.debug(
            "routine_get called",
            extra={
                "event": "safe_tools.routine_get",
                "args_len": len(args) if hasattr(args, "__len__") else 0,
            },
        )  # auto:entry
        if self._routine_store is None:
            raise RuntimeError("Routine store not available")
        routine_id = args.get("routine_id", "")
        if not routine_id:
            logger.debug(
                "routine_get: not_routine_id",
                extra={
                    "event": "safe_tools.routine_get.match",
                    "reason": "not_routine_id",
                },
            )  # auto:neg
            raise RuntimeError("No routine_id provided")
        logger.debug(
            "routine_get: not_routine_id_passed",
            extra={
                "event": "safe_tools.routine_get.passed",
                "reason": "not_routine_id_passed",
            },
        )  # auto:neg
        routine = await self._routine_store.get(routine_id)
        if routine is None:
            content = json.dumps({"error": "Routine not found"})
        else:
            content = json.dumps(
                {
                    "routine_id": routine.routine_id,
                    "name": routine.name,
                    "description": routine.description,
                    "trigger_type": routine.trigger_type,
                    "trigger_config": routine.trigger_config,
                    "action_config": routine.action_config,
                    "enabled": routine.enabled,
                    "cooldown_s": routine.cooldown_s,
                    "last_run_at": routine.last_run_at,
                    "next_run_at": routine.next_run_at,
                }
            )
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
        )

    async def routine_history(self, args: dict) -> TaggedData:
        """Get execution history for a routine."""
        if self._routine_engine is None:
            raise RuntimeError("Routine engine not available")
        routine_id = args.get("routine_id", "")
        if not routine_id:
            raise RuntimeError("No routine_id provided")
        try:
            limit = min(int(args.get("limit", 20)), 100)
        except (TypeError, ValueError):
            logger.warning(
                "routine_history: invalid limit parameter, using default",
                exc_info=True,
                extra={"event": "safe_tools.routine_history_fallback"},
            )
            limit = 20
        executions = await self._routine_engine.get_execution_history(
            routine_id,
            limit=limit,
        )
        content = json.dumps(executions, indent=2)
        return await create_tagged_data(
            content=content,
            source=DataSource.TOOL,
            trust_level=TrustLevel.UNTRUSTED,
        )
