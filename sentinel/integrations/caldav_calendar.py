"""Generic CalDAV calendar client — list, create, update, delete events.

Uses the caldav package (lazy import, Apache-2.0 licence) for CalDAV
protocol operations. Supports Nextcloud, Radicale, Fastmail, iCloud,
and any RFC 4791 compliant server.

Results are UNTRUSTED external data — the executor tags them as
DataSource.WEB / TrustLevel.UNTRUSTED before returning to the planner.
"""

import asyncio
import logging
import re
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.audit")

# ATTACH properties are stripped from events for security — they can contain
# URLs and file references that could be used for data exfiltration.
_ATTACH_RE = re.compile(r"^ATTACH[;:].*$", re.MULTILINE)


class CalDavError(Exception):
    """Error from CalDAV operations."""


# ---------------------------------------------------------------------------
# Data classes — compatible with google_calendar.py CalendarEvent
# ---------------------------------------------------------------------------

@dataclass
class CalendarEvent:
    """A single calendar event."""
    event_id: str
    summary: str
    start: str
    end: str
    location: str
    description: str
    status: str
    html_link: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_password(password_file: str) -> str:
    """Read password from a secrets file. Never log the content."""
    try:
        with open(password_file) as f:
            return f.read().strip()
    except OSError as exc:
        raise CalDavError(f"Cannot read password file: {exc}") from exc


def _build_ssl_context(cert_file: str) -> ssl.SSLContext | None:
    """Build SSL context for CalDAV connection with optional custom CA cert."""
    if not cert_file:
        return None
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cert_file)
    return ctx


def _get_caldav_client(config):
    """Create a CalDAV client. Lazy imports caldav package."""
    try:
        import caldav
    except ImportError as exc:
        raise CalDavError(
            "caldav package not installed — required for CalDAV integration"
        ) from exc

    password = _read_password(config.caldav_password_file)

    kwargs = {
        "url": config.caldav_url,
        "username": config.caldav_username,
        "password": password,
        "timeout": config.caldav_timeout,
    }

    ssl_ctx = _build_ssl_context(config.caldav_tls_cert_file)
    if ssl_ctx:
        kwargs["ssl_verify_cert"] = True
        kwargs["ssl_context"] = ssl_ctx

    try:
        client = caldav.DAVClient(**kwargs)
        return client
    except Exception as exc:
        raise CalDavError(f"CalDAV connection failed: {exc}") from exc


def _get_calendar(config):
    """Get the configured calendar from the CalDAV server."""
    client = _get_caldav_client(config)
    try:
        principal = client.principal()
        calendars = principal.calendars()
    except Exception as exc:
        raise CalDavError(f"CalDAV calendar listing failed: {exc}") from exc

    if not calendars:
        raise CalDavError("No calendars found on CalDAV server")

    # Find calendar by name, or use first available
    if config.caldav_calendar_name:
        for cal in calendars:
            if cal.name == config.caldav_calendar_name:
                return cal
        raise CalDavError(
            f"Calendar '{config.caldav_calendar_name}' not found. "
            f"Available: {[c.name for c in calendars]}"
        )

    return calendars[0]


def _ical_safe(value: str) -> str:
    """Strip CRLF sequences to prevent iCalendar property injection."""
    return value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")


def _strip_attach(ical_data: str) -> str:
    """Remove ATTACH properties from iCalendar data for security."""
    return _ATTACH_RE.sub("", ical_data)


def _parse_event_from_vevent(vevent, event_url: str = "") -> CalendarEvent:
    """Parse a vEvent component into a CalendarEvent dataclass."""
    def _get_prop(obj, name, default=""):
        try:
            prop = getattr(obj, name, None)
            if prop is not None:
                val = prop.value
                if isinstance(val, datetime):
                    return val.isoformat()
                return str(val)
        except Exception:
            pass
        return default

    return CalendarEvent(
        event_id=_get_prop(vevent, "uid"),
        summary=_get_prop(vevent, "summary", "(no title)"),
        start=_get_prop(vevent, "dtstart"),
        end=_get_prop(vevent, "dtend"),
        location=_get_prop(vevent, "location"),
        description=_get_prop(vevent, "description"),
        status=_get_prop(vevent, "status", "confirmed"),
        html_link=event_url,
    )


def _parse_caldav_event(cal_event) -> CalendarEvent:
    """Parse a caldav Event object into our CalendarEvent dataclass."""
    try:
        vobj = cal_event.vobject_instance
        vevent = vobj.vevent
    except Exception as exc:
        raise CalDavError(f"Failed to parse CalDAV event: {exc}") from exc

    # Log when ATTACH properties are present — they are stripped from formatted output,
    # not from the parsed event itself (stripping happens in format_events/format_event_detail)
    raw_data = str(cal_event.data) if hasattr(cal_event, "data") else ""
    if "ATTACH" in raw_data:
        logger.info(
            "CalDAV event contains ATTACH properties (stripped during formatting)",
            extra={"event": "caldav_attach_detected"},
        )

    event_url = str(cal_event.url) if hasattr(cal_event, "url") else ""
    return _parse_event_from_vevent(vevent, event_url)


# ---------------------------------------------------------------------------
# Public async API
# ---------------------------------------------------------------------------

# Transient connection errors worth retrying (auth/permission errors are permanent)
_CALDAV_TRANSIENT_ERRORS = (ConnectionError, TimeoutError, OSError)


async def list_events(
    config,
    time_min: str | None = None,
    time_max: str | None = None,
    max_results: int = 50,
) -> list[CalendarEvent]:
    """List events from the CalDAV calendar within a date range."""
    if not config.caldav_url:
        raise CalDavError("CalDAV URL not configured")
    t0 = time.monotonic()

    def _list_sync():
        cal = _get_calendar(config)

        kwargs = {}
        if time_min:
            kwargs["start"] = datetime.fromisoformat(time_min)
        if time_max:
            kwargs["end"] = datetime.fromisoformat(time_max)

        try:
            events = cal.date_search(**kwargs) if kwargs else cal.events()
        except Exception as exc:
            raise CalDavError(f"CalDAV event listing failed: {exc}") from exc

        results = []
        for evt in events[:max_results]:
            try:
                results.append(_parse_caldav_event(evt))
            except CalDavError:
                continue  # Skip unparseable events
        return results

    for attempt in range(2):
        try:
            results = await asyncio.wait_for(asyncio.to_thread(_list_sync), timeout=60)
            logger.info(
                "caldav.list_events",
                extra={"results": len(results), "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return results
        except TimeoutError:
            if attempt < 1:
                logger.warning("CalDAV list timed out, retrying", extra={"event": "caldav_list_retry"})
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV list timed out")
        except CalDavError as exc:
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV list connection error, retrying",
                    extra={"event": "caldav_list_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV list failed: {exc}") from exc
    raise CalDavError("CalDAV list failed after retry")


async def create_event(
    config,
    summary: str,
    start: str,
    end: str,
    description: str = "",
    location: str = "",
) -> CalendarEvent:
    """Create a new CalDAV calendar event."""
    if not config.caldav_url:
        raise CalDavError("CalDAV URL not configured")
    t0 = time.monotonic()

    def _create_sync():
        cal = _get_calendar(config)

        # Sanitise user-supplied fields: strip CRLF to prevent iCalendar property injection
        safe_summary = _ical_safe(summary)
        safe_description = _ical_safe(description)
        safe_location = _ical_safe(location)

        # Build iCalendar VCALENDAR/VEVENT
        vcal = (
            "BEGIN:VCALENDAR\r\n"
            "VERSION:2.0\r\n"
            "PRODID:-//Sentinel//CalDAV//EN\r\n"
            "BEGIN:VEVENT\r\n"
            f"SUMMARY:{safe_summary}\r\n"
            f"DTSTART:{_format_ical_datetime(start)}\r\n"
            f"DTEND:{_format_ical_datetime(end)}\r\n"
        )
        if safe_description:
            vcal += f"DESCRIPTION:{safe_description}\r\n"
        if safe_location:
            vcal += f"LOCATION:{safe_location}\r\n"
        vcal += "END:VEVENT\r\nEND:VCALENDAR\r\n"

        try:
            event = cal.save_event(vcal)
        except Exception as exc:
            raise CalDavError(f"CalDAV event creation failed: {exc}") from exc

        return _parse_caldav_event(event)

    for attempt in range(2):
        try:
            result = await asyncio.wait_for(asyncio.to_thread(_create_sync), timeout=60)
            logger.info(
                "caldav.create_event",
                extra={"summary": summary[:100], "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return result
        except TimeoutError:
            if attempt < 1:
                logger.warning("CalDAV create timed out, retrying", extra={"event": "caldav_create_retry"})
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV create timed out")
        except CalDavError as exc:
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV create connection error, retrying",
                    extra={"event": "caldav_create_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV create failed: {exc}") from exc
    raise CalDavError("CalDAV create failed after retry")


async def update_event(
    config,
    event_id: str,
    summary: str | None = None,
    start: str | None = None,
    end: str | None = None,
    description: str | None = None,
    location: str | None = None,
) -> CalendarEvent:
    """Update an existing CalDAV event by UID."""
    if not config.caldav_url:
        raise CalDavError("CalDAV URL not configured")
    t0 = time.monotonic()

    def _update_sync():
        cal = _get_calendar(config)

        # Find the event by UID
        try:
            event = cal.event_by_uid(event_id)
        except Exception as exc:
            raise CalDavError(f"Event '{event_id}' not found: {exc}") from exc

        # Modify the vobject data
        try:
            vobj = event.vobject_instance
            vevent = vobj.vevent

            # Sanitise user-supplied fields: strip CRLF to prevent iCalendar property injection
            if summary is not None:
                vevent.summary.value = _ical_safe(summary)
            if start is not None:
                vevent.dtstart.value = datetime.fromisoformat(start)
            if end is not None:
                vevent.dtend.value = datetime.fromisoformat(end)
            if description is not None:
                safe_desc = _ical_safe(description)
                if hasattr(vevent, "description"):
                    vevent.description.value = safe_desc
                else:
                    vevent.add("description").value = safe_desc
            if location is not None:
                safe_loc = _ical_safe(location)
                if hasattr(vevent, "location"):
                    vevent.location.value = safe_loc
                else:
                    vevent.add("location").value = safe_loc

            event.save()
        except CalDavError:
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV event update failed: {exc}") from exc

        return _parse_caldav_event(event)

    for attempt in range(2):
        try:
            result = await asyncio.wait_for(asyncio.to_thread(_update_sync), timeout=60)
            logger.info(
                "caldav.update_event",
                extra={"event_id": event_id[:100], "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return result
        except TimeoutError:
            if attempt < 1:
                logger.warning("CalDAV update timed out, retrying", extra={"event": "caldav_update_retry"})
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV update timed out")
        except CalDavError as exc:
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV update connection error, retrying",
                    extra={"event": "caldav_update_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV update failed: {exc}") from exc
    raise CalDavError("CalDAV update failed after retry")


async def delete_event(
    config,
    event_id: str,
) -> None:
    """Delete a CalDAV event by UID."""
    if not config.caldav_url:
        raise CalDavError("CalDAV URL not configured")
    t0 = time.monotonic()

    def _delete_sync():
        cal = _get_calendar(config)

        try:
            event = cal.event_by_uid(event_id)
            event.delete()
        except Exception as exc:
            raise CalDavError(f"CalDAV event deletion failed: {exc}") from exc

    for attempt in range(2):
        try:
            await asyncio.wait_for(asyncio.to_thread(_delete_sync), timeout=60)
            logger.info(
                "caldav.delete_event",
                extra={"event_id": event_id[:100], "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return
        except TimeoutError:
            if attempt < 1:
                logger.warning("CalDAV delete timed out, retrying", extra={"event": "caldav_delete_retry"})
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV delete timed out")
        except CalDavError as exc:
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV delete connection error, retrying",
                    extra={"event": "caldav_delete_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV delete failed: {exc}") from exc
    raise CalDavError("CalDAV delete failed after retry")


# ---------------------------------------------------------------------------
# iCalendar datetime formatting
# ---------------------------------------------------------------------------

def _format_ical_datetime(dt_str: str) -> str:
    """Convert ISO datetime string to iCalendar format."""
    try:
        dt = datetime.fromisoformat(dt_str)
        # If timezone-aware, convert to UTC before formatting with Z suffix
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y%m%dT%H%M%SZ")
        return dt.strftime("%Y%m%dT%H%M%S")
    except ValueError:
        # Already in iCal format or other — pass through
        return dt_str


# ---------------------------------------------------------------------------
# Formatters — produce LLM-friendly text (compatible with google_calendar.py)
# ---------------------------------------------------------------------------

def format_events(events: list[CalendarEvent]) -> str:
    """Format events as numbered text for LLM consumption."""
    if not events:
        return "No events found."

    lines = []
    for i, e in enumerate(events, 1):
        lines.append(f"{i}. {e.summary}")
        lines.append(f"   When: {e.start} → {e.end}")
        if e.location:
            lines.append(f"   Where: {e.location}")
        if e.description:
            # Strip ATTACH from description text too
            desc = _strip_attach(e.description)
            desc_preview = desc[:200]
            if len(desc) > 200:
                desc_preview += "..."
            lines.append(f"   Details: {desc_preview}")
        lines.append(f"   ID: {e.event_id}")
        lines.append("")
    return "\n".join(lines).rstrip()


def format_event_detail(event: CalendarEvent) -> str:
    """Format a single event with full details."""
    desc = _strip_attach(event.description) if event.description else ""
    lines = [
        f"Summary: {event.summary}",
        f"Start: {event.start}",
        f"End: {event.end}",
        f"Location: {event.location}" if event.location else None,
        f"Description: {desc}" if desc else None,
        f"Status: {event.status}",
        f"Event ID: {event.event_id}",
    ]
    return "\n".join(line for line in lines if line is not None)
