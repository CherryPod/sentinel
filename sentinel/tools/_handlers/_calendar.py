"""Calendar handler mixin — Google Calendar and CalDAV backends.

Extracted from executor.py during Phase 1 structural refactor.
The mixin expects these attributes on self (provided by ToolExecutor):
  - _credential_store: per-user credential store (or None)
  - _google_oauth: Google OAuth client (or None)
  - _resolve_credentials(service): look up per-user creds
"""

import logging

from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.security.provenance import create_tagged_data
from sentinel.tools._handlers._registry import tool_handler
from sentinel.tools._handlers._types import ToolError, _CredentialOverlay

logger = logging.getLogger(__name__)


def _cal_provider() -> str:
    """Return 'calendar' for CalDAV or 'Google Calendar' for Google backend."""
    from sentinel.core.config import settings

    return "calendar" if settings.calendar_backend == "caldav" else "Google Calendar"


def _cal_list_desc() -> str:
    return f"List events from {_cal_provider()}. Results are UNTRUSTED external data. Returns summary, time, location for each event."


def _cal_create_desc() -> str:
    return f"Create a {_cal_provider()} event. REQUIRES APPROVAL — write operation."


def _cal_update_desc() -> str:
    return f"Update an existing {_cal_provider()} event (partial). REQUIRES APPROVAL — write operation."


def _cal_delete_desc() -> str:
    return (
        f"Delete a {_cal_provider()} event. REQUIRES APPROVAL — destructive operation."
    )


def _cal_event_id_args() -> dict[str, str]:
    return {"event_id": f"string ({_cal_provider()} event ID)"}


def _cal_list_args() -> dict[str, str]:
    from sentinel.core.config import settings

    base = {
        "time_min": "string (optional RFC3339 timestamp, e.g. '2026-02-19T00:00:00Z')",
        "time_max": "string (optional RFC3339 timestamp)",
        "max_results": "integer (default 50)",
    }
    if settings.calendar_backend != "caldav":
        base["calendar_id"] = "string (default 'primary')"
    return base


def _cal_create_args() -> dict[str, str]:
    from sentinel.core.config import settings

    base = {
        "summary": "string (event title)",
        "start": "string (RFC3339 datetime, e.g. '2026-02-20T10:00:00Z')",
        "end": "string (RFC3339 datetime)",
        "location": "string (optional)",
        "description": "string (optional)",
    }
    if settings.calendar_backend != "caldav":
        base["calendar_id"] = "string (default 'primary')"
    return base


def _cal_update_args() -> dict[str, str]:
    from sentinel.core.config import settings

    base = {
        "event_id": f"string ({_cal_provider()} event ID)",
        "summary": "string (optional new title)",
        "start": "string (optional new start datetime)",
        "end": "string (optional new end datetime)",
        "location": "string (optional)",
        "description": "string (optional)",
    }
    if settings.calendar_backend != "caldav":
        base["calendar_id"] = "string (default 'primary')"
    return base


def _cal_delete_args() -> dict[str, str]:
    from sentinel.core.config import settings

    base = {"event_id": f"string ({_cal_provider()} event ID)"}
    if settings.calendar_backend != "caldav":
        base["calendar_id"] = "string (default 'primary')"
    return base


class CalendarHandlerMixin:
    """Calendar tool handlers (dispatchers + Google + CalDAV backends)."""

    # -- Credential helper ---------------------------------------------------

    async def _get_caldav_config(self):
        """Return config with per-user CalDAV credentials overlaid.

        Falls back to system settings if no per-user credentials are configured.
        Raises ToolError if neither per-user nor system credentials exist.
        """
        from sentinel.core.config import settings

        user_caldav = await self._resolve_credentials("caldav")
        logger.debug(
            "_get_caldav_config: credential source resolved",
            extra={
                "event": "caldav.config_credential_source",
                "has_user_creds": user_caldav is not None,
            },
        )
        if user_caldav is None:
            if not settings.caldav_url:
                raise ToolError(
                    "Calendar not configured for your account. "
                    "Ask an admin to set up your CalDAV credentials via PUT /api/credentials/caldav"
                )
            logger.debug(
                "_get_caldav_config: using system config fallback",
                extra={"event": "caldav.config_system_fallback"},
            )
            return settings

        return _CredentialOverlay(
            user_caldav,
            settings,
            {
                "caldav_url": "url",
                "caldav_username": "username",
                "caldav_password": "password",
            },
        )

    # -- Dispatchers ---------------------------------------------------------

    @tool_handler(
        "calendar_list_events",
        description=_cal_list_desc,
        args=_cal_list_args,
        group="calendar",
        order=80,
    )
    async def _calendar_list_events(self, args: dict) -> tuple[TaggedData, dict | None]:
        """List calendar events — dispatches to Google or CalDAV based on config."""
        from sentinel.core.config import settings

        logger.debug(
            "calendar_list_events: dispatching",
            extra={
                "event": "calendar.list_dispatch",
                "backend": settings.calendar_backend,
            },
        )
        if settings.calendar_backend == "caldav":
            return await self._caldav_list_events(args)
        return await self._google_calendar_list_events(args)

    @tool_handler(
        "calendar_create_event",
        description=_cal_create_desc,
        args=_cal_create_args,
        group="calendar",
        order=80,
    )
    async def _calendar_create_event(
        self, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """Create calendar event — dispatches to Google or CalDAV based on config."""
        from sentinel.core.config import settings

        logger.debug(
            "calendar_create_event: dispatching",
            extra={
                "event": "calendar.create_dispatch",
                "backend": settings.calendar_backend,
            },
        )
        if settings.calendar_backend == "caldav":
            return await self._caldav_create_event(args)
        return await self._google_calendar_create_event(args)

    @tool_handler(
        "calendar_update_event",
        description=_cal_update_desc,
        args=_cal_update_args,
        group="calendar",
        order=80,
    )
    async def _calendar_update_event(
        self, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """Update calendar event — dispatches to Google or CalDAV based on config."""
        from sentinel.core.config import settings

        logger.debug(
            "calendar_update_event: dispatching",
            extra={
                "event": "calendar.update_dispatch",
                "backend": settings.calendar_backend,
            },
        )
        if settings.calendar_backend == "caldav":
            return await self._caldav_update_event(args)
        return await self._google_calendar_update_event(args)

    @tool_handler(
        "calendar_delete_event",
        description=_cal_delete_desc,
        args=_cal_delete_args,
        group="calendar",
        order=80,
    )
    async def _calendar_delete_event(
        self, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """Delete calendar event — dispatches to Google or CalDAV based on config."""
        from sentinel.core.config import settings

        logger.debug(
            "calendar_delete_event: dispatching",
            extra={
                "event": "calendar.delete_dispatch",
                "backend": settings.calendar_backend,
            },
        )
        if settings.calendar_backend == "caldav":
            return await self._caldav_delete_event(args)
        return await self._google_calendar_delete_event(args)

    # -- Google Calendar handlers (B5) ----------------------------------------

    async def _google_calendar_list_events(
        self, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """List events from Google Calendar."""
        from sentinel.core.config import settings
        from sentinel.integrations.google_calendar import (
            CalendarError,
            format_events,
            list_events,
        )

        if not settings.calendar_enabled:
            raise ToolError("Calendar integration is disabled")
        if self._google_oauth is None:
            raise ToolError("Google OAuth not configured")

        calendar_id = args.get("calendar_id", "primary")
        time_min = args.get("time_min")
        time_max = args.get("time_max")
        try:
            max_results = min(
                int(args.get("max_results", 50)), settings.calendar_max_results
            )
        except (ValueError, TypeError):
            raise ToolError("'max_results' must be a valid integer")

        logger.debug(
            "google_calendar_list_events: querying",
            extra={
                "event": "gcal.list_start",
                "calendar_id": calendar_id,
                "max_results": max_results,
            },
        )

        token = await self._google_oauth.get_access_token()
        try:
            events = await list_events(
                token,
                calendar_id,
                time_min=time_min,
                time_max=time_max,
                max_results=max_results,
                timeout=settings.calendar_api_timeout,
            )
        except CalendarError as e:
            logger.warning(
                "google_calendar_list_events: API error",
                extra={"event": "gcal.list_error", "error": str(e)},
                exc_info=True,
            )
            raise ToolError("Calendar list failed:") from e

        content = format_events(events)
        logger.debug(
            "google_calendar_list_events: complete",
            extra={"event": "gcal.list_complete", "event_count": len(events)},
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_list_events",
        ), None

    async def _google_calendar_create_event(
        self, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """Create a Google Calendar event."""
        from sentinel.core.config import settings
        from sentinel.integrations.google_calendar import (
            CalendarError,
            create_event,
            format_event_detail,
        )

        if not settings.calendar_enabled:
            raise ToolError("Calendar integration is disabled")
        if self._google_oauth is None:
            raise ToolError("Google OAuth not configured")

        summary = args.get("summary", "").strip()
        start = args.get("start", "").strip()
        end = args.get("end", "").strip()
        if not summary:
            raise ToolError("'summary' is required")
        if not start or not end:
            raise ToolError("'start' and 'end' are required")

        logger.debug(
            "google_calendar_create_event: creating",
            extra={"event": "gcal.create_start", "summary_len": len(summary)},
        )

        token = await self._google_oauth.get_access_token()
        try:
            event = await create_event(
                token,
                calendar_id=args.get("calendar_id", "primary"),
                summary=summary,
                start=start,
                end=end,
                location=args.get("location", ""),
                description=args.get("description", ""),
                timeout=settings.calendar_api_timeout,
            )
        except CalendarError as e:
            logger.warning(
                "google_calendar_create_event: API error",
                extra={"event": "gcal.create_error", "error": str(e)},
                exc_info=True,
            )
            raise ToolError("Calendar create failed:") from e

        content = format_event_detail(event)
        logger.info(
            "google_calendar_create_event: complete",
            extra={"event": "gcal.create_complete"},
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_create_event",
        ), None

    async def _google_calendar_update_event(
        self, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """Update an existing Google Calendar event."""
        from sentinel.core.config import settings
        from sentinel.integrations.google_calendar import (
            CalendarError,
            format_event_detail,
            update_event,
        )

        if not settings.calendar_enabled:
            raise ToolError("Calendar integration is disabled")
        if self._google_oauth is None:
            raise ToolError("Google OAuth not configured")

        event_id = args.get("event_id", "").strip()
        if not event_id:
            raise ToolError("'event_id' is required")

        # Collect optional fields to update
        fields = {}
        for key in ("summary", "start", "end", "location", "description"):
            if args.get(key):
                fields[key] = args[key]
        if not fields:
            raise ToolError("At least one field to update is required")

        logger.debug(
            "google_calendar_update_event: updating",
            extra={
                "event": "gcal.update_start",
                "event_id": event_id,
                "field_count": len(fields),
            },
        )

        token = await self._google_oauth.get_access_token()
        try:
            event = await update_event(
                token,
                event_id,
                calendar_id=args.get("calendar_id", "primary"),
                timeout=settings.calendar_api_timeout,
                **fields,
            )
        except CalendarError as e:
            logger.warning(
                "google_calendar_update_event: API error",
                extra={
                    "event": "gcal.update_error",
                    "event_id": event_id,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise ToolError("Calendar update failed:") from e

        content = format_event_detail(event)
        logger.info(
            "google_calendar_update_event: complete",
            extra={"event": "gcal.update_complete", "event_id": event_id},
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_update_event",
        ), None

    async def _google_calendar_delete_event(
        self, args: dict
    ) -> tuple[TaggedData, dict | None]:
        """Delete a Google Calendar event."""
        from sentinel.core.config import settings
        from sentinel.integrations.google_calendar import CalendarError, delete_event

        if not settings.calendar_enabled:
            raise ToolError("Calendar integration is disabled")
        if self._google_oauth is None:
            raise ToolError("Google OAuth not configured")

        event_id = args.get("event_id", "").strip()
        if not event_id:
            raise ToolError("'event_id' is required")

        logger.debug(
            "google_calendar_delete_event: deleting",
            extra={"event": "gcal.delete_start", "event_id": event_id},
        )

        token = await self._google_oauth.get_access_token()
        try:
            await delete_event(
                token,
                event_id,
                calendar_id=args.get("calendar_id", "primary"),
                timeout=settings.calendar_api_timeout,
            )
        except CalendarError as e:
            logger.warning(
                "google_calendar_delete_event: API error",
                extra={
                    "event": "gcal.delete_error",
                    "event_id": event_id,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise ToolError("Calendar delete failed:") from e

        logger.info(
            "google_calendar_delete_event: complete",
            extra={"event": "gcal.delete_complete", "event_id": event_id},
        )
        return await create_tagged_data(
            content=f"Event deleted: {event_id}",
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_delete_event",
        ), None

    # -- CalDAV handlers ------------------------------------------------------

    async def _caldav_list_events(self, args: dict) -> tuple[TaggedData, dict | None]:
        """List events from CalDAV calendar (per-user credentials if available)."""
        from sentinel.core.config import settings
        from sentinel.integrations.caldav_calendar import (
            CalDavError,
            format_events,
            list_events,
        )

        config = await self._get_caldav_config()
        time_min = args.get("time_min")
        time_max = args.get("time_max")
        try:
            max_results = min(
                int(args.get("max_results", 50)), settings.calendar_max_results
            )
        except (ValueError, TypeError):
            raise ToolError("'max_results' must be a valid integer")

        logger.debug(
            "caldav_list_events: querying",
            extra={"event": "caldav.list_start", "max_results": max_results},
        )

        try:
            events = await list_events(
                config,
                time_min=time_min,
                time_max=time_max,
                max_results=max_results,
            )
        except CalDavError as e:
            logger.warning(
                "caldav_list_events: error",
                extra={"event": "caldav.list_error", "error": str(e)},
                exc_info=True,
            )
            raise ToolError("CalDAV list failed:") from e

        content = format_events(events)
        logger.debug(
            "caldav_list_events: complete",
            extra={"event": "caldav.list_complete", "event_count": len(events)},
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_list_events",
        ), None

    async def _caldav_create_event(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Create a CalDAV calendar event (per-user credentials if available)."""
        from sentinel.integrations.caldav_calendar import (
            CalDavError,
            create_event,
            format_event_detail,
        )

        config = await self._get_caldav_config()
        summary = args.get("summary", "").strip()
        start = args.get("start", "").strip()
        end = args.get("end", "").strip()
        if not summary:
            raise ToolError("'summary' is required")
        if not start or not end:
            raise ToolError("'start' and 'end' are required")

        logger.debug(
            "caldav_create_event: creating",
            extra={"event": "caldav.create_start", "summary_len": len(summary)},
        )

        try:
            event = await create_event(
                config,
                summary=summary,
                start=start,
                end=end,
                location=args.get("location", ""),
                description=args.get("description", ""),
            )
        except CalDavError as e:
            logger.warning(
                "caldav_create_event: error",
                extra={"event": "caldav.create_error", "error": str(e)},
                exc_info=True,
            )
            raise ToolError("CalDAV create failed:") from e

        content = format_event_detail(event)
        logger.info(
            "caldav_create_event: complete",
            extra={"event": "caldav.create_complete"},
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_create_event",
        ), None

    async def _caldav_update_event(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Update an existing CalDAV event (per-user credentials if available)."""
        from sentinel.integrations.caldav_calendar import (
            CalDavError,
            format_event_detail,
            update_event,
        )

        config = await self._get_caldav_config()
        event_id = args.get("event_id", "").strip()
        if not event_id:
            raise ToolError("'event_id' is required")

        fields = {}
        for key in ("summary", "start", "end", "location", "description"):
            if args.get(key):
                fields[key] = args[key]
        if not fields:
            raise ToolError("At least one field to update is required")

        logger.debug(
            "caldav_update_event: updating",
            extra={
                "event": "caldav.update_start",
                "event_id": event_id,
                "field_count": len(fields),
            },
        )

        try:
            event = await update_event(config, event_id, **fields)
        except CalDavError as e:
            logger.warning(
                "caldav_update_event: error",
                extra={
                    "event": "caldav.update_error",
                    "event_id": event_id,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise ToolError("CalDAV update failed:") from e

        content = format_event_detail(event)
        logger.info(
            "caldav_update_event: complete",
            extra={"event": "caldav.update_complete", "event_id": event_id},
        )
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_update_event",
        ), None

    async def _caldav_delete_event(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Delete a CalDAV event (per-user credentials if available)."""
        from sentinel.integrations.caldav_calendar import CalDavError, delete_event

        config = await self._get_caldav_config()
        event_id = args.get("event_id", "").strip()
        if not event_id:
            raise ToolError("'event_id' is required")

        logger.debug(
            "caldav_delete_event: deleting",
            extra={"event": "caldav.delete_start", "event_id": event_id},
        )

        try:
            await delete_event(config, event_id)
        except CalDavError as e:
            logger.warning(
                "caldav_delete_event: error",
                extra={
                    "event": "caldav.delete_error",
                    "event_id": event_id,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise ToolError("CalDAV delete failed:") from e

        logger.info(
            "caldav_delete_event: complete",
            extra={"event": "caldav.delete_complete", "event_id": event_id},
        )
        return await create_tagged_data(
            content=f"Event deleted: {event_id}",
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="tool:calendar_delete_event",
        ), None
