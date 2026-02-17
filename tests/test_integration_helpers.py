"""Unit tests for pure helper functions in integration modules.

Tests internal helpers that don't require network calls or mocking
external services: sanitizers, parsers, formatters, escaping.
"""

import pytest


# ---------------------------------------------------------------------------
# CalDAV helpers
# ---------------------------------------------------------------------------

class TestIcalSafe:
    """caldav_calendar._ical_safe — prevents iCal property injection."""

    def test_strips_crlf(self):
        from sentinel.integrations.caldav_calendar import _ical_safe
        assert _ical_safe("line1\r\nline2") == "line1 line2"

    def test_strips_bare_cr(self):
        from sentinel.integrations.caldav_calendar import _ical_safe
        assert _ical_safe("line1\rline2") == "line1 line2"

    def test_strips_bare_lf(self):
        from sentinel.integrations.caldav_calendar import _ical_safe
        assert _ical_safe("line1\nline2") == "line1 line2"

    def test_no_change_for_safe_string(self):
        from sentinel.integrations.caldav_calendar import _ical_safe
        assert _ical_safe("Meeting at 3pm") == "Meeting at 3pm"

    def test_empty_string(self):
        from sentinel.integrations.caldav_calendar import _ical_safe
        assert _ical_safe("") == ""

    def test_mixed_newlines(self):
        from sentinel.integrations.caldav_calendar import _ical_safe
        assert _ical_safe("a\r\nb\nc\rd") == "a b c d"


class TestStripAttach:
    """caldav_calendar._strip_attach — removes ATTACH properties."""

    def test_strips_attach_line(self):
        from sentinel.integrations.caldav_calendar import _strip_attach
        ical = "SUMMARY:Test\nATTACH;VALUE=URI:https://evil.com/exfil\nEND:VEVENT"
        result = _strip_attach(ical)
        assert "ATTACH" not in result
        assert "SUMMARY:Test" in result

    def test_no_attach_unchanged(self):
        from sentinel.integrations.caldav_calendar import _strip_attach
        ical = "SUMMARY:Test\nDESCRIPTION:Hello\nEND:VEVENT"
        assert _strip_attach(ical) == ical

    def test_strips_multiple_attach(self):
        from sentinel.integrations.caldav_calendar import _strip_attach
        ical = "ATTACH:file1\nSUMMARY:X\nATTACH:file2"
        result = _strip_attach(ical)
        assert "ATTACH" not in result
        assert "SUMMARY:X" in result


class TestFormatIcalDatetime:
    """caldav_calendar._format_ical_datetime — ISO to iCal format."""

    def test_naive_datetime(self):
        from sentinel.integrations.caldav_calendar import _format_ical_datetime
        assert _format_ical_datetime("2026-03-15T14:00:00") == "20260315T140000"

    def test_utc_datetime(self):
        from sentinel.integrations.caldav_calendar import _format_ical_datetime
        assert _format_ical_datetime("2026-03-15T14:00:00+00:00") == "20260315T140000Z"

    def test_offset_datetime_converts_to_utc(self):
        from sentinel.integrations.caldav_calendar import _format_ical_datetime
        # +02:00 → UTC = 12:00
        assert _format_ical_datetime("2026-03-15T14:00:00+02:00") == "20260315T120000Z"

    def test_passthrough_on_invalid(self):
        from sentinel.integrations.caldav_calendar import _format_ical_datetime
        assert _format_ical_datetime("20260315T140000Z") == "20260315T140000Z"


# ---------------------------------------------------------------------------
# Gmail helpers
# ---------------------------------------------------------------------------

class TestGmailParseHeaders:
    """gmail._parse_headers — extracts Subject/From/To/Date."""

    def test_extracts_known_headers(self):
        from sentinel.integrations.gmail import _parse_headers
        headers = [
            {"name": "Subject", "value": "Hello"},
            {"name": "From", "value": "alice@example.com"},
            {"name": "To", "value": "bob@example.com"},
            {"name": "Date", "value": "Mon, 15 Mar 2026"},
            {"name": "X-Custom", "value": "ignored"},
        ]
        result = _parse_headers(headers)
        assert result == {
            "subject": "Hello",
            "from": "alice@example.com",
            "to": "bob@example.com",
            "date": "Mon, 15 Mar 2026",
        }

    def test_empty_list(self):
        from sentinel.integrations.gmail import _parse_headers
        assert _parse_headers([]) == {}

    def test_case_insensitive(self):
        from sentinel.integrations.gmail import _parse_headers
        headers = [{"name": "SUBJECT", "value": "Test"}]
        assert _parse_headers(headers) == {"subject": "Test"}


class TestGmailBase64urlDecode:
    """gmail._base64url_decode — URL-safe base64 without padding."""

    def test_basic_decode(self):
        from sentinel.integrations.gmail import _base64url_decode
        import base64
        encoded = base64.urlsafe_b64encode(b"Hello World").decode().rstrip("=")
        assert _base64url_decode(encoded) == "Hello World"

    def test_empty_string(self):
        from sentinel.integrations.gmail import _base64url_decode
        # Empty base64 decodes to empty string
        assert _base64url_decode("") == ""

    def test_invalid_base64(self):
        from sentinel.integrations.gmail import _base64url_decode
        assert _base64url_decode("!!!not-base64!!!") == ""


class TestGmailSanitizeBody:
    """gmail._sanitize_body — strips HTML tags, decodes entities."""

    def test_strips_tags(self):
        from sentinel.integrations.gmail import _sanitize_body
        assert _sanitize_body("<p>Hello</p>") == "Hello"

    def test_decodes_entities(self):
        from sentinel.integrations.gmail import _sanitize_body
        assert _sanitize_body("a &amp; b") == "a & b"

    def test_collapses_whitespace(self):
        from sentinel.integrations.gmail import _sanitize_body
        result = _sanitize_body("a\n\n\n\nb")
        assert result == "a\n\nb"


class TestGmailTruncateBody:
    """gmail._truncate_body — truncates with indicator."""

    def test_short_body_unchanged(self):
        from sentinel.integrations.gmail import _truncate_body
        assert _truncate_body("short", 100) == "short"

    def test_long_body_truncated(self):
        from sentinel.integrations.gmail import _truncate_body
        result = _truncate_body("a" * 200, 50)
        assert len(result) < 200
        assert "[... truncated]" in result


# ---------------------------------------------------------------------------
# IMAP helpers
# ---------------------------------------------------------------------------

class TestImapEscape:
    """imap_email._build_imap_search — IMAP query sanitization."""

    def test_simple_text_search(self):
        from sentinel.integrations.imap_email import _build_imap_search
        result = _build_imap_search("hello world")
        assert 'TEXT "hello world"' in result

    def test_from_pattern(self):
        from sentinel.integrations.imap_email import _build_imap_search
        result = _build_imap_search("from:alice@example.com")
        assert 'FROM "alice@example.com"' in result

    def test_subject_pattern(self):
        from sentinel.integrations.imap_email import _build_imap_search
        result = _build_imap_search("subject:meeting")
        assert 'SUBJECT "meeting"' in result

    def test_strips_quotes(self):
        from sentinel.integrations.imap_email import _build_imap_search
        result = _build_imap_search('subject:inject"me')
        assert '"' not in result.replace('SUBJECT "', "").replace('"', "x", 1)
        # Should not contain unbalanced quotes — the injected quote is stripped
        assert 'SUBJECT "injectme"' in result

    def test_strips_special_chars(self):
        from sentinel.integrations.imap_email import _build_imap_search
        result = _build_imap_search("subject:test\\injection")
        assert "\\" not in result

    def test_strips_parens(self):
        from sentinel.integrations.imap_email import _build_imap_search
        result = _build_imap_search("subject:test(injection)")
        assert "(" not in result
        assert ")" not in result

    def test_strips_newlines(self):
        from sentinel.integrations.imap_email import _build_imap_search
        result = _build_imap_search("subject:test\r\ninjection")
        assert "\r" not in result
        assert "\n" not in result

    def test_wildcard_returns_all(self):
        from sentinel.integrations.imap_email import _build_imap_search
        assert _build_imap_search("*") == "ALL"

    def test_empty_returns_all(self):
        from sentinel.integrations.imap_email import _build_imap_search
        assert _build_imap_search("") == "ALL"


class TestImapDecodeHeader:
    """imap_email._decode_header_value — RFC 2047 decoding."""

    def test_plain_ascii(self):
        from sentinel.integrations.imap_email import _decode_header_value
        assert _decode_header_value("Hello World") == "Hello World"

    def test_encoded_utf8(self):
        from sentinel.integrations.imap_email import _decode_header_value
        # RFC 2047 encoded "Test"
        assert _decode_header_value("=?utf-8?b?VGVzdA==?=") == "Test"


class TestImapSanitizeHtml:
    """imap_email._sanitize_html — strips HTML for body extraction."""

    def test_strips_tags(self):
        from sentinel.integrations.imap_email import _sanitize_html
        assert _sanitize_html("<b>bold</b>") == "bold"

    def test_empty_string(self):
        from sentinel.integrations.imap_email import _sanitize_html
        assert _sanitize_html("") == ""


class TestImapTruncateBody:
    """imap_email._truncate_body — truncates with indicator."""

    def test_short_body(self):
        from sentinel.integrations.imap_email import _truncate_body
        assert _truncate_body("short", 100) == "short"

    def test_long_body(self):
        from sentinel.integrations.imap_email import _truncate_body
        result = _truncate_body("a" * 200, 50)
        assert "[... truncated]" in result


# ---------------------------------------------------------------------------
# Google Calendar helpers
# ---------------------------------------------------------------------------

class TestGCalParseEvent:
    """google_calendar._parse_event — parses API response dict."""

    def test_timed_event(self):
        from sentinel.integrations.google_calendar import _parse_event
        data = {
            "id": "evt1",
            "summary": "Meeting",
            "start": {"dateTime": "2026-03-15T14:00:00Z"},
            "end": {"dateTime": "2026-03-15T15:00:00Z"},
            "location": "Room A",
            "description": "Weekly sync",
            "status": "confirmed",
            "htmlLink": "https://calendar.google.com/event?eid=abc",
        }
        event = _parse_event(data)
        assert event.event_id == "evt1"
        assert event.summary == "Meeting"
        assert event.start == "2026-03-15T14:00:00Z"
        assert event.location == "Room A"

    def test_all_day_event(self):
        from sentinel.integrations.google_calendar import _parse_event
        data = {
            "id": "evt2",
            "summary": "Holiday",
            "start": {"date": "2026-03-15"},
            "end": {"date": "2026-03-16"},
        }
        event = _parse_event(data)
        assert event.start == "2026-03-15"
        assert event.end == "2026-03-16"

    def test_missing_fields_use_defaults(self):
        from sentinel.integrations.google_calendar import _parse_event
        event = _parse_event({})
        assert event.event_id == ""
        assert event.summary == "(no title)"
        assert event.start == ""
