"""Generic CalDAV calendar client — list, create, update, delete events.

Uses the caldav package (lazy import, Apache-2.0 licence) for CalDAV
protocol operations. Supports Nextcloud, Radicale, Fastmail, iCloud,
and any RFC 4791 compliant server.

Results are UNTRUSTED external data — the executor tags them as
DataSource.WEB / TrustLevel.UNTRUSTED before returning to the planner.
"""

import asyncio
import ipaddress
import logging
import re
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

# ATTACH properties are stripped from events for security — they can contain
# URLs and file references that could be used for data exfiltration.
_ATTACH_RE = re.compile(r"^ATTACH[;:].*$", re.MULTILINE)

# Maximum length for description preview text in formatted output
_DESC_PREVIEW_MAX_LEN = 200


# Moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import CalDavError
from sentinel.security.ssrf import (
    UrlValidationError,
    _parse_allowlist,
    parse_and_check_syntactic,
    resolve_and_check_private,
)

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


def _validate_caldav_url_ssrf(config) -> str:
    """Q12-F1 use-time SSRF gate: syntactic re-check + DNS + private-IP reject.

    Runs on every CalDAV client construction. Re-runs the syntactic check
    because credentials stored before the PUT validator landed (or via
    direct store write) would otherwise bypass enforcement entirely.
    The DNS+private-IP reject is the hard boundary — it also catches
    public hostnames that resolve into private space (metadata endpoints
    dressed up as public names).

    Returns the canonical URL string with the host normalised to the form
    the transport library will resolve (UTS-46 nontransitional A-label or
    bracketed IPv6 literal). Callers MUST pass the returned string to
    ``caldav.DAVClient`` instead of ``config.caldav_url`` to close the
    validator/transport divergence bypass (C65 trust-boundary closure):
    without substitution, urllib3 would re-resolve the original Unicode
    input under its own UTS-46 profile and could reach a different DNS
    name than the one the validator approved.

    Residual DNS-rebind TOCTOU tracked under Q12-U1 (pin-connect requires
    library-wide transport work, out of hardening-pass scope).
    """
    # Deferred import: avoids settings import cycle at module load.
    from sentinel.core.config import Settings

    settings = Settings()
    allowlist = _parse_allowlist(settings.ssrf_caldav_allowlist)
    private_allowlist = _parse_allowlist(settings.ssrf_caldav_private_host_allowlist)
    try:
        parsed = parse_and_check_syntactic(
            config.caldav_url,
            allow_http=settings.ssrf_allow_http,
            allowlist=allowlist,
        )
        resolve_and_check_private(
            parsed,
            private_host_allowlist=private_allowlist,
        )
    except UrlValidationError as exc:
        logger.info(
            "CalDAV URL rejected by SSRF policy at use-time",
            extra={
                "event": "caldav.ssrf_rejected",
                "reason": exc.category,
                "host": exc.host,
                "resolved_ip": exc.resolved_ip,
            },
        )
        raise CalDavError(f"CalDAV URL rejected by SSRF policy: {exc.reason}") from exc

    # Rebuild the outbound URL using the validator-canonical host so the
    # transport library resolves the same DNS name the validator approved.
    # See C65.design §3 for the netloc reconstruction algorithm rationale —
    # IPv6 re-bracketing, explicit-vs-default port preservation, byte-faithful
    # userinfo preservation are each load-bearing.
    original = urlparse(config.caldav_url)
    canonical_host = parsed.host

    # IPv6 literals: re-bracket. Use ``parsed.literal_ip`` for discrimination
    # (NOT a ``":" in canonical`` heuristic) — relies on the validator's IP
    # classification rather than re-detecting from the canonical string.
    if parsed.literal_ip is not None and isinstance(
        parsed.literal_ip, ipaddress.IPv6Address
    ):
        logger.debug(
            "_validate_caldav_url_ssrf: literal_ip_is_not_None",
            extra={
                "event": "integrations.caldav_calendar._validate_caldav_url_ssrf.match",
                "reason": "literal_ip_is_not_None",
            },
        )  # auto:neg
        canonical_netloc_host = f"[{canonical_host}]"
    else:
        logger.debug(
            "_validate_caldav_url_ssrf: literal_ip_is_not_None",
            extra={
                "event": "integrations.caldav_calendar._validate_caldav_url_ssrf.clean",
                "reason": "literal_ip_is_not_None",
            },
        )  # auto:neg
        canonical_netloc_host = canonical_host

    # Port: emit only if original had an explicit port. Preserves
    # explicit-vs-default distinction (``urlparse('https://h/').port`` is None;
    # ``urlparse('https://h:443/').port`` is 443) — never inject a default port
    # that wasn't present in the operator's input.
    netloc = canonical_netloc_host
    if original.port is not None:
        netloc = f"{netloc}:{original.port}"

    # Userinfo: split on the rightmost ``@`` (byte-faithful preservation;
    # ``urllib.parse.quote`` could double-encode an already-encoded value).
    if "@" in original.netloc:
        logger.debug(
            "_validate_caldav_url_ssrf: @_in_netloc",
            extra={
                "event": "integrations.caldav_calendar._validate_caldav_url_ssrf.match",
                "reason": "@_in_netloc",
            },
        )  # auto:neg
        userinfo = original.netloc.rsplit("@", 1)[0]
        netloc = f"{userinfo}@{netloc}"

    return urlunparse(original._replace(netloc=netloc))


def _disable_caldav_redirects(client) -> None:
    """Wrap ``client.session.request`` to force ``allow_redirects=False``.

    ``caldav.DAVClient`` (1.6.0) delegates to ``requests.Session`` where
    ``allow_redirects`` is a per-call kwarg, not a session attribute.
    Wrapping the bound method catches every DAV verb issued via
    ``session.request(...)``.
    """
    logger.debug(
        "_disable_caldav_redirects called",
        extra={
            "event": "integrations.caldav_calendar._disable_caldav_redirects",
            "client_type": type(client).__name__,
        },
    )  # auto:entry
    session = getattr(client, "session", None)
    if session is None:
        return
    original_request = session.request

    def _request_no_redirect(method, url, **kwargs):
        kwargs["allow_redirects"] = False
        return original_request(method, url, **kwargs)

    session.request = _request_no_redirect


def _get_caldav_client(config):
    """Create a CalDAV client. Lazy imports caldav package."""
    logger.debug(
        "_get_caldav_client called",
        extra={
            "event": "caldav_calendar._get_caldav_client",
            "config_type": type(config).__name__,
        },
    )
    try:
        import caldav
    except ImportError as exc:
        raise CalDavError(
            "caldav package not installed — required for CalDAV integration"
        ) from exc

    # C65: validator returns the canonical URL string — the host is normalised
    # under the same UTS-46 profile the transport library uses, so DAVClient
    # connects to the same DNS name the validator approved. Passing
    # ``config.caldav_url`` here would re-introduce the bypass.
    canonical_url = _validate_caldav_url_ssrf(config)

    password = _read_password(config.caldav_password_file)

    kwargs = {
        "url": canonical_url,
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
    except Exception as exc:
        raise CalDavError(f"CalDAV connection failed: {exc}") from exc

    _disable_caldav_redirects(client)
    return client


def _get_calendar(config):
    """Get the configured calendar from the CalDAV server."""
    logger.debug(
        "_get_calendar called",
        extra={
            "event": "caldav_calendar._get_calendar",
            "config_type": type(config).__name__,
        },
    )
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
    """Strip CRLF sequences to prevent iCalendar property injection.

    Narrow line-break sanitiser — used on the vobject path (which performs
    its own RFC 5545 §3.3.11 TEXT escape on encode via ``TextBehavior``)
    and on DATE-TIME values where TEXT escaping is not spec-correct
    (§3.3.5). For raw VCALENDAR string interpolation of TEXT-typed
    properties (SUMMARY/DESCRIPTION/LOCATION) use ``_ical_escape_text``.
    """
    return value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")


def _ical_escape_text(value: str) -> str:
    """RFC 5545 §3.3.11 TEXT-value escape.

    Escapes the four characters the spec requires for the TEXT value type:
    backslash → ``\\\\``, semicolon → ``\\;``, comma → ``\\,``, and any
    line break (CRLF, bare LF, bare CR) → ``\\n``. Backslash is escaped
    first so the backslashes introduced by the other escape sequences are
    not themselves re-escaped on a subsequent pass.

    Apply at raw VCALENDAR interpolation sites only. The vobject library
    runs the same escape on encode (see ``TextBehavior.encode`` →
    ``backslashEscape``) for SUMMARY/DESCRIPTION/LOCATION/etc., so calling
    this on a value about to be assigned to ``component.value`` would
    double-escape and surface ``\\;`` / ``\\,`` literally in the user's
    calendar.
    """
    logger.debug(
        "_ical_escape_text called",
        extra={
            "event": "integrations.caldav_calendar._ical_escape_text",
            "input_len": len(value),
        },
    )
    # Normalise all line-break shapes to a single LF first so the final
    # replacement turns each logical line break into exactly one "\n".
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return (
        value.replace("\\", "\\\\")
        .replace(";", "\\;")
        .replace(",", "\\,")
        .replace("\n", "\\n")
    )


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
        except Exception:  # catch-all: CalDAV property access (varied formats)
            logger.debug(
                "_get_prop: Exception suppressed",
                extra={"event": "caldav_calendar._get_prop.suppressed"},
                exc_info=True,
            )
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
            extra={"event": "caldav.attach_detected"},
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
        logger.debug("_list_sync called", extra={"event": "caldav_calendar._list_sync"})
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
                logger.debug(
                    "_list_sync: skipping unparseable event",
                    extra={"event": "caldav_calendar._list_sync.skip_event"},
                    exc_info=True,
                )
                continue
        return results

    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            results = await asyncio.wait_for(
                asyncio.to_thread(_list_sync), timeout=config.caldav_timeout
            )
            logger.info(
                "caldav.list_events",
                extra={
                    "event": "caldav.list_events",
                    "results": len(results),
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return results
        except TimeoutError as exc:
            last_exc = exc
            if attempt < 1:
                logger.warning(
                    "CalDAV list timed out, retrying",
                    extra={"event": "caldav.list_retry"},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV list timed out") from exc
        except CalDavError as exc:
            last_exc = exc
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV list connection error, retrying",
                    extra={"event": "caldav.list_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV list failed: {exc}") from exc
    raise CalDavError("CalDAV list failed after retry") from last_exc


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

    # RFC 5545 §3.8.4.7 + §3.8.7.2 — client MUST set UID and DTSTAMP. Generated
    # once outside the retry loop so attempt 2 PUTs to the same library-derived
    # URL (caldav._find_id_path → _generate_url), preventing duplicate-create
    # under to_thread-cancellation-then-retry.
    uid = str(uuid.uuid4()).upper()
    dtstamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    vcal = _build_create_event_vcal(
        summary=summary,
        start=start,
        end=end,
        description=description,
        location=location,
        uid=uid,
        dtstamp=dtstamp,
    )

    def _create_sync():
        logger.debug(
            "_create_sync called", extra={"event": "caldav_calendar._create_sync"}
        )
        cal = _get_calendar(config)
        try:
            event = cal.save_event(vcal)
        except Exception as exc:
            raise CalDavError(f"CalDAV event creation failed: {exc}") from exc

        return _parse_caldav_event(event)

    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_create_sync), timeout=config.caldav_timeout
            )
            logger.info(
                "caldav.create_event",
                extra={
                    "event": "caldav.create_event",
                    "summary": summary[:100],
                    "uid": uid,
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return result
        except TimeoutError as exc:
            last_exc = exc
            if attempt < 1:
                logger.warning(
                    "CalDAV create timed out, retrying",
                    extra={"event": "caldav.create_retry", "uid": uid},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV create timed out") from exc
        except CalDavError as exc:
            last_exc = exc
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV create connection error, retrying",
                    extra={
                        "event": "caldav.create_retry",
                        "uid": uid,
                        "error": str(exc),
                    },
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV create failed: {exc}") from exc
    raise CalDavError("CalDAV create failed after retry") from last_exc


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

    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_update_sync), timeout=config.caldav_timeout
            )
            logger.info(
                "caldav.update_event",
                extra={
                    "event": "caldav.update_event",
                    "event_id": event_id[:100],
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return result
        except TimeoutError as exc:
            last_exc = exc
            if attempt < 1:
                logger.warning(
                    "CalDAV update timed out, retrying",
                    extra={"event": "caldav.update_retry"},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV update timed out") from exc
        except CalDavError as exc:
            last_exc = exc
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV update connection error, retrying",
                    extra={"event": "caldav.update_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV update failed: {exc}") from exc
    raise CalDavError("CalDAV update failed after retry") from last_exc


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

    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            await asyncio.wait_for(
                asyncio.to_thread(_delete_sync), timeout=config.caldav_timeout
            )
            logger.info(
                "caldav.delete_event",
                extra={
                    "event": "caldav.delete_event",
                    "event_id": event_id[:100],
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return
        except TimeoutError as exc:
            last_exc = exc
            if attempt < 1:
                logger.warning(
                    "CalDAV delete timed out, retrying",
                    extra={"event": "caldav.delete_retry"},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise CalDavError("CalDAV delete timed out") from exc
        except CalDavError as exc:
            last_exc = exc
            if attempt < 1 and isinstance(exc.__cause__, _CALDAV_TRANSIENT_ERRORS):
                logger.warning(
                    "CalDAV delete connection error, retrying",
                    extra={"event": "caldav.delete_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise CalDavError(f"CalDAV delete failed: {exc}") from exc
    raise CalDavError("CalDAV delete failed after retry") from last_exc


# ---------------------------------------------------------------------------
# iCalendar datetime formatting
# ---------------------------------------------------------------------------


def _format_ical_datetime(dt_str: str) -> str:
    """Convert ISO datetime string to iCalendar format."""
    try:
        dt = datetime.fromisoformat(dt_str)
        # If timezone-aware, convert to UTC before formatting with Z suffix
        if dt.tzinfo is not None:
            dt = dt.astimezone(UTC)
            return dt.strftime("%Y%m%dT%H%M%SZ")
        return dt.strftime("%Y%m%dT%H%M%S")
    except ValueError:
        # Already in iCal format or other — pass through
        logger.debug("caldav_calendar.format_datetime_passthrough", exc_info=True)
        return dt_str


def _build_create_event_vcal(
    *,
    summary: str,
    start: str,
    end: str,
    description: str,
    location: str,
    uid: str,
    dtstamp: str,
) -> str:
    """Build a UID + DTSTAMP-bearing VCALENDAR/VEVENT string.

    Caller MUST pass a pre-generated stable UID + DTSTAMP — the helper does NOT
    generate them, so the same string can be re-used across retry attempts and
    the caldav library's _find_id_path will derive the same URL each call,
    preventing duplicate-create under to_thread-cancellation-then-retry.
    """
    logger.debug(
        "_build_create_event_vcal called",
        extra={"event": "integrations.caldav_calendar._build_create_event_vcal"},
    )  # auto:entry
    # SUMMARY / DESCRIPTION / LOCATION are TEXT-typed per RFC 5545 §3.3.11.
    # We're interpolating into a raw VCALENDAR string here (not assigning to
    # a vobject component, which would do its own escape on encode), so the
    # full RFC 5545 TEXT escape applies.
    safe_summary = _ical_escape_text(summary)
    safe_description = _ical_escape_text(description)
    safe_location = _ical_escape_text(location)
    # `_format_ical_datetime` returns its input unchanged on parse-failure
    # (it accepts pre-formatted iCal strings). User-supplied CR/LF in
    # `start`/`end` would otherwise inject arbitrary iCalendar properties
    # — wrap with `_ical_safe` to collapse CR/LF to spaces uniformly,
    # matching the discipline applied to summary/description/location.
    safe_start = _ical_safe(_format_ical_datetime(start))
    safe_end = _ical_safe(_format_ical_datetime(end))

    vcal = (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//Sentinel//CalDAV//EN\r\n"
        "BEGIN:VEVENT\r\n"
        f"UID:{uid}\r\n"
        f"DTSTAMP:{dtstamp}\r\n"
        f"SUMMARY:{safe_summary}\r\n"
        f"DTSTART:{safe_start}\r\n"
        f"DTEND:{safe_end}\r\n"
    )
    if safe_description:
        vcal += f"DESCRIPTION:{safe_description}\r\n"
    if safe_location:
        vcal += f"LOCATION:{safe_location}\r\n"
    vcal += "END:VEVENT\r\nEND:VCALENDAR\r\n"
    return vcal


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
            desc_preview = desc[:_DESC_PREVIEW_MAX_LEN]
            if len(desc) > _DESC_PREVIEW_MAX_LEN:
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
