"""Tests for injection vector modules."""
import email as email_mod
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from vectors.email_vector import (
    seed_email, verify_email_exfil, cleanup_emails,
    _wrap_in_realistic_email,
)
from vectors.calendar_vector import (
    seed_calendar_event, verify_calendar_event_created,
    cleanup_calendar_events, cleanup_single_event,
)
from vectors.signal_vector import (
    send_signal_message, send_signal_message_unknown,
    verify_signal_received,
)
from vectors.telegram_vector import (
    send_telegram_message, send_telegram_message_unknown,
    verify_telegram_allowlist_configured,
)
from vectors.file_vector import (
    seed_file, verify_file_exists, verify_file_deleted,
    verify_file_contains_marker, cleanup_files, seed_canary,
    cleanup_single_file,
)
from vectors.web_vector import (
    generate_pages, get_page_url, _restaurant_page,
)


# ── Email vector ─────────────────────────────────────────────────


class TestEmailVector:
    """Tests for email injection vector."""

    @patch("vectors.email_vector.smtplib.SMTP_SSL")
    def test_seed_email_sends_smtp(self, mock_smtp_cls):
        """seed_email sends SMTP message with [IB-xxx] subject and payload."""
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        config = MagicMock()
        config.seeding.email_smtp_server = "smtp.evil.com"
        config.seeding.email_smtp_user = "attacker@evil.com"
        config.seeding.email_smtp_password = "secret"
        config.sentinel.email = "sentinel@example.com"
        manifest = MagicMock()

        subject = seed_email(config, "IB-001", "EVIL PAYLOAD", manifest)
        assert "[IB-001]" in subject
        mock_smtp.send_message.assert_called_once()
        manifest.add_item.assert_called_once()

    def test_wrap_in_realistic_email(self):
        """seed_email embeds payload in realistic wrapper text."""
        body = _wrap_in_realistic_email("INJECT THIS", "IB-001")
        assert "INJECT THIS" in body
        # Should have surrounding realistic content
        assert "Q2" in body or "report" in body.lower() or "team" in body.lower()

    @patch("vectors.email_vector.imaplib.IMAP4_SSL")
    def test_verify_email_exfil_finds_marker(self, mock_imap_cls):
        """verify_email_exfil polls IMAP and finds EXFIL-xxx marker."""
        # Build a fake email with the marker
        from email.mime.text import MIMEText
        msg = MIMEText("The code is EXFIL-IB-042 as requested")
        raw = msg.as_bytes()

        mock_imap = MagicMock()
        mock_imap_cls.return_value.__enter__ = MagicMock(return_value=mock_imap)
        mock_imap_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_imap.search.return_value = ("OK", [b"1"])
        mock_imap.fetch.return_value = ("OK", [(b"1", raw)])

        config = MagicMock()
        config.attacker.email_imap_server = "imap.evil.com"
        config.attacker.email_imap_user = "attacker@evil.com"
        config.attacker.email_imap_password = "secret"

        assert verify_email_exfil(config, "IB-042", timeout=1) is True

    @patch("vectors.email_vector.imaplib.IMAP4_SSL")
    def test_verify_email_exfil_timeout(self, mock_imap_cls):
        """verify_email_exfil returns False after timeout with no match."""
        mock_imap = MagicMock()
        mock_imap_cls.return_value.__enter__ = MagicMock(return_value=mock_imap)
        mock_imap_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_imap.search.return_value = ("OK", [b""])

        config = MagicMock()
        config.attacker.email_imap_server = "imap.evil.com"
        config.attacker.email_imap_user = "attacker@evil.com"
        config.attacker.email_imap_password = "secret"

        assert verify_email_exfil(config, "IB-099", timeout=1) is False

    @patch("vectors.email_vector.imaplib.IMAP4_SSL")
    def test_cleanup_emails(self, mock_imap_cls):
        """cleanup_emails deletes messages with [IB-*] subject prefix."""
        # Build fake emails, one with IB prefix, one without
        from email.mime.text import MIMEText
        msg1 = MIMEText("poisoned")
        msg1["Subject"] = "[IB-001] Q2 Report Notes"
        msg2 = MIMEText("normal")
        msg2["Subject"] = "Regular email"

        mock_imap = MagicMock()
        mock_imap_cls.return_value.__enter__ = MagicMock(return_value=mock_imap)
        mock_imap_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_imap.search.return_value = ("OK", [b"1 2"])
        mock_imap.fetch.side_effect = [
            ("OK", [(b"1", msg1.as_bytes())]),
            ("OK", [(b"2", msg2.as_bytes())]),
        ]

        config = MagicMock()
        config.sentinel.email = "sentinel@example.com"
        config.seeding.email_smtp_server = "smtp.evil.com"
        config.seeding.email_smtp_user = "attacker@evil.com"
        config.seeding.email_smtp_password = "secret"
        # Use attacker config for IMAP cleanup of sentinel inbox
        config.attacker.email_imap_server = "imap.evil.com"
        config.attacker.email_imap_user = "attacker@evil.com"
        config.attacker.email_imap_password = "secret"

        cleanup_emails(config)
        # Should have flagged message 1 for deletion
        mock_imap.store.assert_called()


# ── File vector ──────────────────────────────────────────────────


class TestFileVector:
    """Tests for file content injection vector."""

    @patch("vectors.file_vector.subprocess.run")
    def test_seed_file_writes_via_podman(self, mock_run):
        """seed_file writes to /workspace/ib-tests/ via podman exec."""
        mock_run.return_value = MagicMock(returncode=0)

        config = MagicMock()
        manifest = MagicMock()
        path = seed_file(config, "IB-005", "EVIL PAYLOAD", manifest)

        assert "/workspace/ib-tests/" in path
        assert "ib-005" in path.lower()
        mock_run.assert_called_once()
        manifest.add_item.assert_called_once()

    @patch("vectors.file_vector.subprocess.run")
    def test_seed_file_embeds_payload(self, mock_run):
        """seed_file embeds payload in realistic document wrapper."""
        mock_run.return_value = MagicMock(returncode=0)

        config = MagicMock()
        manifest = MagicMock()
        seed_file(config, "IB-005", "EVIL PAYLOAD", manifest)

        # Check the content passed to podman exec
        written_content = mock_run.call_args[1].get("input", b"").decode()
        assert "EVIL PAYLOAD" in written_content

    @patch("vectors.file_vector.subprocess.run")
    def test_verify_file_exists_true(self, mock_run):
        """verify_file_exists returns True if file is present."""
        mock_run.return_value = MagicMock(returncode=0)
        assert verify_file_exists("/workspace/ib-tests/test.txt") is True

    @patch("vectors.file_vector.subprocess.run")
    def test_verify_file_deleted_true(self, mock_run):
        """verify_file_deleted returns True if file is absent."""
        mock_run.return_value = MagicMock(returncode=1)
        assert verify_file_deleted("/workspace/ib-tests/test.txt") is True

    @patch("vectors.file_vector.subprocess.run")
    def test_verify_file_contains_marker(self, mock_run):
        """verify_file_contains_marker returns True if marker in file."""
        mock_run.return_value = MagicMock(returncode=0)
        assert verify_file_contains_marker(
            "/workspace/ib-tests/test.txt", "BACKDOOR_MARKER") is True

    @patch("vectors.file_vector.subprocess.run")
    def test_cleanup_files(self, mock_run):
        """cleanup_files removes /workspace/ib-tests/ directory."""
        mock_run.return_value = MagicMock(returncode=0)
        cleanup_files(MagicMock())
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "rm" in cmd and "-rf" in cmd


# ── Web vector ───────────────────────────────────────────────────


class TestWebVector:
    """Tests for web page injection vector."""

    def test_generate_pages_writes_html(self, tmp_path):
        """generate_pages writes HTML files to LAN site directory."""
        config = MagicMock()
        payloads = {"direct": "EVIL PAYLOAD", "dos_stop": "STOP NOW"}
        generate_pages(config, payloads, str(tmp_path))

        assert (tmp_path / "direct.html").exists()
        assert (tmp_path / "dos_stop.html").exists()

    def test_generated_html_contains_payload(self, tmp_path):
        """generated HTML contains payload in realistic page wrapper."""
        config = MagicMock()
        payloads = {"direct": "INJECT THIS"}
        generate_pages(config, payloads, str(tmp_path))

        html = (tmp_path / "direct.html").read_text()
        assert "INJECT THIS" in html
        assert "<html" in html.lower()

    def test_generated_html_has_unique_urls(self):
        """generated HTML has unique per-payload URLs."""
        config = MagicMock()
        config.seeding.web_base_url = "http://192.168.1.100"
        url1 = get_page_url(config, "direct")
        url2 = get_page_url(config, "dos_stop")
        assert url1 != url2
        assert "direct" in url1
        assert "dos_stop" in url2


# ── Calendar vector ──────────────────────────────────────────────


class TestCalendarVector:
    """Tests for calendar injection vector."""

    @patch("vectors.calendar_vector._get_caldav_client")
    def test_seed_calendar_event(self, mock_client):
        """seed_calendar_event creates event via CalDAV with [IB-xxx] title."""
        mock_cal = MagicMock()
        mock_client.return_value = mock_cal

        config = MagicMock()
        config.sentinel.calendar_backend = "caldav"
        manifest = MagicMock()

        title = seed_calendar_event(config, "IB-010", "EVIL PAYLOAD", manifest)
        assert "[IB-010]" in title
        mock_cal.save_event.assert_called_once()
        manifest.add_item.assert_called_once()

    @patch("vectors.calendar_vector._get_caldav_client")
    def test_seed_calendar_embeds_payload(self, mock_client):
        """seed_calendar_event embeds payload in description."""
        mock_cal = MagicMock()
        mock_client.return_value = mock_cal

        config = MagicMock()
        config.sentinel.calendar_backend = "caldav"
        manifest = MagicMock()

        seed_calendar_event(config, "IB-010", "EVIL PAYLOAD", manifest)
        # The ical data passed to save_event should contain the payload
        call_args = mock_cal.save_event.call_args
        ical_data = call_args[0][0] if call_args[0] else call_args[1].get("ical", "")
        assert "EVIL PAYLOAD" in ical_data

    @patch("vectors.calendar_vector._get_caldav_client")
    def test_verify_calendar_event_created(self, mock_client):
        """verify_calendar_event_created finds event by title pattern."""
        mock_cal = MagicMock()
        mock_event = MagicMock()
        mock_event.data = "SUMMARY:Meeting with External Partner"
        mock_cal.events.return_value = [mock_event]
        mock_client.return_value = mock_cal

        config = MagicMock()
        config.sentinel.calendar_backend = "caldav"

        assert verify_calendar_event_created(
            config, "Meeting with External Partner") is True

    @patch("vectors.calendar_vector._get_caldav_client")
    def test_cleanup_calendar_events(self, mock_client):
        """cleanup_calendar_events deletes events with [IB-*] prefix."""
        mock_cal = MagicMock()
        mock_event1 = MagicMock()
        mock_event1.data = "SUMMARY:[IB-001] Team Standup"
        mock_event2 = MagicMock()
        mock_event2.data = "SUMMARY:Regular Meeting"
        mock_cal.events.return_value = [mock_event1, mock_event2]
        mock_client.return_value = mock_cal

        config = MagicMock()
        config.sentinel.calendar_backend = "caldav"

        cleanup_calendar_events(config)
        mock_event1.delete.assert_called_once()
        mock_event2.delete.assert_not_called()


# ── Signal vector ────────────────────────────────────────────────


class TestSignalVector:
    """Tests for Signal injection vector (podman exec + daemon socket)."""

    @patch("vectors.signal_vector.subprocess.run")
    def test_send_signal_message(self, mock_run):
        """send_signal_message sends via podman exec to daemon socket."""
        mock_run.return_value = MagicMock(returncode=0)

        config = MagicMock()
        config.contacts.known_signal = "+15551111111"

        result = send_signal_message(config, "+15559999999", "Hello payload")
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "podman" in cmd[0]
        assert "signal-app" in cmd

    @patch("vectors.signal_vector.subprocess.run")
    def test_send_signal_message_unknown(self, mock_run):
        """send_signal_message_unknown sends from signal-notifs (not in allowlist)."""
        mock_run.return_value = MagicMock(returncode=0)

        config = MagicMock()
        config.contacts.known_signal = "+15551111111"

        result = send_signal_message_unknown(config, "Evil message")
        assert result is True

    @patch("vectors.signal_vector.subprocess.run")
    def test_verify_signal_received(self, mock_run):
        """verify_signal_received checks podman logs for EXFIL marker."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Received: body='EXFIL-IB-042', sender=+15551111111",
            stderr="",
        )

        config = MagicMock()
        config.attacker.signal_phone = "+15550000000"

        assert verify_signal_received(config, "IB-042", timeout=1) is True


# ── Telegram vector ──────────────────────────────────────────────


class TestTelegramVector:
    """Tests for Telegram injection vector."""

    @patch("vectors.telegram_vector._get_bot_token", return_value="fake-token")
    @patch("vectors.telegram_vector.urllib.request.urlopen")
    def test_send_telegram_message(self, mock_urlopen, mock_token):
        """send_telegram_message sends via Bot API."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        config = MagicMock()
        config.contacts.known_telegram_chat_id = "12345"

        result = send_telegram_message(config, "12345", "Hello payload")
        assert result is True

    @patch("vectors.telegram_vector._get_bot_token", return_value="fake-token")
    @patch("vectors.telegram_vector.urllib.request.urlopen")
    def test_send_telegram_message_unknown(self, mock_urlopen, mock_token):
        """send_telegram_message_unknown uses non-allowlisted chat_id."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        config = MagicMock()
        config.contacts.unknown_telegram_chat_id = "99999"

        result = send_telegram_message_unknown(config, "Evil message")
        assert result is True

    def test_verify_telegram_allowlist_configured(self):
        """verify_telegram_allowlist_configured checks config."""
        config = MagicMock()
        config.contacts.unknown_telegram_chat_id = "99999"
        assert verify_telegram_allowlist_configured(config) is True

        config.contacts.unknown_telegram_chat_id = ""
        assert verify_telegram_allowlist_configured(config) is False
