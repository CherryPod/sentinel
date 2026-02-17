"""Google Calendar API v3 client — list, create, update, delete events.

All functions take an OAuth2 access token and call the Calendar REST API
directly via httpx. Token is only used in the Authorization header and
never appears in content, logs, or error messages.

Results are UNTRUSTED external data — the executor tags them as
DataSource.WEB / TrustLevel.UNTRUSTED before returning to the planner.
"""

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import quote

import httpx

logger = logging.getLogger("sentinel.audit")

_CALENDAR_BASE = "https://www.googleapis.com/calendar/v3"


class CalendarError(Exception):
    """Error from Google Calendar API operations."""


# ---------------------------------------------------------------------------
# Data classes
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

async def _calendar_request(
    method: str,
    url: str,
    token: str,
    timeout: int = 15,
    json_body: dict | None = None,
) -> httpx.Response:
    """Shared HTTP helper — injects Bearer token, classifies errors.

    Retries once on transient errors (timeout, connect, 5xx).
    Token only enters the Authorization header here — never in content,
    logs, or error messages.
    """
    headers = {"Authorization": f"Bearer {token}"}

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await getattr(client, method.lower())(
                    url,
                    headers=headers,
                    json=json_body,
                )
        except httpx.TimeoutException as exc:
            if attempt < 1:
                logger.warning("Calendar API timeout, retrying", extra={"event": "gcal_retry"})
                await asyncio.sleep(2)
                continue
            raise CalendarError(f"Calendar API request timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            if attempt < 1:
                logger.warning("Calendar API connect error, retrying", extra={"event": "gcal_retry"})
                await asyncio.sleep(2)
                continue
            raise CalendarError(f"Cannot connect to Calendar API: {exc}") from exc

        if resp.status_code == 429:
            raise CalendarError("Calendar API rate limited")
        if resp.status_code == 401:
            raise CalendarError("Calendar API auth failed — token may be expired")
        if resp.status_code >= 500:
            if attempt < 1:
                logger.warning(
                    "Calendar API server error, retrying",
                    extra={"event": "gcal_retry", "status": resp.status_code},
                )
                await asyncio.sleep(2)
                continue
            raise CalendarError(f"Calendar API error {resp.status_code}")
        # Allow 204 (delete success) through
        if resp.status_code >= 400:
            raise CalendarError(f"Calendar API client error {resp.status_code}")

        return resp

    raise CalendarError("Calendar API request failed after retry")


def _parse_event(data: dict) -> CalendarEvent:
    """Parse a Calendar API event response into a CalendarEvent."""
    # Start/end can be dateTime (timed) or date (all-day)
    start_obj = data.get("start", {})
    end_obj = data.get("end", {})
    start = start_obj.get("dateTime") or start_obj.get("date", "")
    end = end_obj.get("dateTime") or end_obj.get("date", "")

    return CalendarEvent(
        event_id=data.get("id", ""),
        summary=data.get("summary", "(no title)"),
        start=start,
        end=end,
        location=data.get("location", ""),
        description=data.get("description", ""),
        status=data.get("status", ""),
        html_link=data.get("htmlLink", ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def list_events(
    token: str,
    calendar_id: str = "primary",
    time_min: str | None = None,
    time_max: str | None = None,
    max_results: int = 50,
    timeout: int = 15,
) -> list[CalendarEvent]:
    """List events from a calendar, ordered by start time."""
    # N-003: URL-encode parameters to prevent injection via special characters
    # in calendar_id or RFC3339 timestamps (which contain : and +).
    params = [
        f"singleEvents=true",
        f"orderBy=startTime",
        f"maxResults={max_results}",
    ]
    if time_min:
        params.append(f"timeMin={quote(time_min, safe='')}")
    if time_max:
        params.append(f"timeMax={quote(time_max, safe='')}")

    url = f"{_CALENDAR_BASE}/calendars/{quote(calendar_id, safe='')}/events?{'&'.join(params)}"
    resp = await _calendar_request("get", url, token, timeout)
    data = resp.json()

    events = []
    for item in data.get("items", []):
        events.append(_parse_event(item))
    return events


async def create_event(
    token: str,
    calendar_id: str = "primary",
    summary: str = "",
    start: str = "",
    end: str = "",
    location: str = "",
    description: str = "",
    timeout: int = 15,
) -> CalendarEvent:
    """Create a new calendar event. Returns the created event."""
    body: dict = {
        "summary": summary,
        "start": {"dateTime": start},
        "end": {"dateTime": end},
    }
    if location:
        body["location"] = location
    if description:
        body["description"] = description

    url = f"{_CALENDAR_BASE}/calendars/{quote(calendar_id, safe='')}/events"
    resp = await _calendar_request("post", url, token, timeout, json_body=body)
    return _parse_event(resp.json())


async def update_event(
    token: str,
    event_id: str,
    calendar_id: str = "primary",
    timeout: int = 15,
    **fields,
) -> CalendarEvent:
    """Update an existing event (PATCH — partial update). Returns updated event."""
    body: dict = {}
    if "summary" in fields:
        body["summary"] = fields["summary"]
    if "start" in fields:
        body["start"] = {"dateTime": fields["start"]}
    if "end" in fields:
        body["end"] = {"dateTime": fields["end"]}
    if "location" in fields:
        body["location"] = fields["location"]
    if "description" in fields:
        body["description"] = fields["description"]

    url = f"{_CALENDAR_BASE}/calendars/{quote(calendar_id, safe='')}/events/{quote(event_id, safe='')}"
    resp = await _calendar_request("patch", url, token, timeout, json_body=body)
    return _parse_event(resp.json())


async def delete_event(
    token: str,
    event_id: str,
    calendar_id: str = "primary",
    timeout: int = 15,
) -> None:
    """Delete a calendar event. Returns None on success (204)."""
    url = f"{_CALENDAR_BASE}/calendars/{quote(calendar_id, safe='')}/events/{quote(event_id, safe='')}"
    await _calendar_request("delete", url, token, timeout)


# ---------------------------------------------------------------------------
# Formatters — produce LLM-friendly text
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
            desc_preview = e.description[:200]
            if len(e.description) > 200:
                desc_preview += "..."
            lines.append(f"   Details: {desc_preview}")
        lines.append(f"   ID: {e.event_id}")
        lines.append("")
    return "\n".join(lines).rstrip()


def format_event_detail(event: CalendarEvent) -> str:
    """Format a single event with full details."""
    lines = [
        f"Summary: {event.summary}",
        f"Start: {event.start}",
        f"End: {event.end}",
        f"Location: {event.location}" if event.location else None,
        f"Description: {event.description}" if event.description else None,
        f"Status: {event.status}",
        f"Event ID: {event.event_id}",
        f"Link: {event.html_link}" if event.html_link else None,
    ]
    return "\n".join(line for line in lines if line is not None)
