"""Generic IMAP/SMTP email client — search, read, send, draft.

Uses stdlib imaplib (via asyncio.to_thread) for IMAP and aiosmtplib
(lazy import) for SMTP. Supports any IMAP/SMTP provider including
Proton Bridge (self-signed certs), Fastmail, and self-hosted servers.

Results are UNTRUSTED external data — the executor tags them as
DataSource.WEB / TrustLevel.UNTRUSTED before returning to the planner.
"""

import asyncio
import email
import email.header
import html
import imaplib
import logging
import re
import ssl
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

logger = logging.getLogger(__name__)
# Q13-F12: audit channel for credential-discipline events (plaintext auth refusal,
# localhost-allowed plaintext warning). Distinct from `logger` so events route to
# the audit stream rather than just the application log.
audit = logging.getLogger("sentinel.audit")

_HTML_TAG_RE = re.compile(r"<[^>]+>")

# Maximum length for snippet/preview text in search results
_SNIPPET_MAX_LEN = 200


def _mask_email(address: str) -> str:
    """Mask email address for logging — 'a***@example.com'."""
    if "@" in address:
        return address[0] + "***@" + address.split("@")[-1]
    return "***"


def _mask_query(query: str) -> str:
    """Mask email addresses within a search query for logging."""
    return re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+", _mask_email, query)[:100]


# Moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.decorators import no_audit_log
from sentinel.core.exceptions import ImapEmailError
from sentinel.crypto.blind_index import log_hash

# ---------------------------------------------------------------------------
# Data classes — compatible with gmail.py EmailSearchResult / EmailMessage
# ---------------------------------------------------------------------------


@dataclass
class EmailSearchResult:
    """Summary of an email from a search result."""

    message_id: str
    thread_id: str
    subject: str
    sender: str
    date: str
    snippet: str


@dataclass
class EmailMessage:
    """Full email message with decoded body."""

    message_id: str
    thread_id: str
    subject: str
    sender: str
    to: str
    date: str
    body_text: str


# ---------------------------------------------------------------------------
# TLS / SSL context helpers
# ---------------------------------------------------------------------------

# #1 HIGH: hosts where CERT_NONE is acceptable (loopback only)
_LOCALHOST_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _build_ssl_context(
    tls_mode: str,
    cert_file: str,
    host: str = "",
) -> ssl.SSLContext | None:
    """Build an SSL context for IMAP or SMTP connections.

    Supports custom CA certs for self-signed servers (Proton Bridge).
    Falls back to CERT_NONE only for verified localhost connections.
    """
    # Q13-F12: tls_mode="none" disables TLS context construction. For IMAP this
    # means imaplib.IMAP4 (no STARTTLS) — credentials traverse the wire in
    # cleartext via the LOGIN command. For SMTP the aiosmtplib send path still
    # passes start_tls=True, so the credential exposure is IMAP-specific in
    # practice; the gate fail-closes both channels uniformly to prevent
    # operator misconfiguration of remote hosts. Permitted only against
    # loopback (debug/dev).
    #
    # Q13-F12 review fix-now (Cx-2): normalise host casing + trailing dot
    # before the membership check so operator typos like 'Localhost' and
    # 'localhost.' don't false-refuse legitimate loopback configurations.
    # Numeric loopback aliases (e.g. '127.1', '0177.0.0.1') and DNS-based
    # equivalence are out of scope for this pass — fail-closed in the safe
    # direction (operator can switch to '127.0.0.1' / '::1' / 'localhost').
    if tls_mode == "none":
        normalised_host = host.lower().rstrip(".") if host else ""
        if normalised_host and normalised_host not in _LOCALHOST_HOSTS:
            logger.debug(
                "_build_ssl_context: host",
                extra={
                    "event": "integrations.imap_email._build_ssl_context.match",
                    "reason": "host",
                },
            )  # auto:neg
            audit.warning(
                "IMAP/SMTP plaintext auth refused — tls_mode=none requires localhost host",
                extra={"event": "imap.plaintext_auth_refused", "host": host},
            )
            raise ImapEmailError(
                f"IMAP/SMTP tls_mode='none' is only permitted for localhost "
                f"(127.0.0.1/::1/localhost); refusing to send credentials in "
                f"cleartext to remote host {host!r}."
            )
        # Localhost-allowed plaintext — surface to audit stream (not just app log)
        # so operators see it in audit telemetry, plus keep the legacy logger
        # warning for backwards-compatible app-log surfacing.
        audit.warning(
            "IMAP plaintext auth permitted on localhost (tls_mode=none) — "
            "IMAP LOGIN credentials will traverse loopback unencrypted",
            extra={"event": "imap.plaintext_auth", "host": host},
        )
        logger.warning(
            "IMAP/SMTP using plaintext (tls_mode=none) — credentials sent unencrypted",
            extra={"event": "tls.plaintext_warning", "host": host},
        )
        return None

    ctx = ssl.create_default_context()
    if cert_file:
        # Custom CA cert for self-signed servers (e.g. Proton Bridge)
        logger.debug(
            "_build_ssl_context: custom CA cert loaded",
            extra={"event": "tls.custom_ca"},
        )
        ctx.load_verify_locations(cert_file)
    elif host and host not in _LOCALHOST_HOSTS:
        # Remote host with no custom cert — use system CA bundle.
        # ssl.create_default_context() already loads system CAs and
        # verifies hostnames, which is correct for public servers.
        logger.debug(
            "Using system CA bundle for remote host",
            extra={"event": "tls.system_ca", "host": host},
        )
    else:
        # Localhost — disable cert verification (self-signed/dev)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning(
            "IMAP/SMTP TLS: no cert file, using CERT_NONE (localhost only)",
            extra={"event": "tls.cert_none", "host": host},
        )
    return ctx


def _read_password(password_file: str) -> str:
    """Read password from a secrets file. Never log the content."""
    try:
        with open(password_file) as f:
            return f.read().strip()
    except OSError as exc:
        raise ImapEmailError(f"Cannot read password file: {exc}") from exc


# ---------------------------------------------------------------------------
# Header decoding
# ---------------------------------------------------------------------------


def _decode_header_value(raw: str) -> str:
    """Decode RFC 2047 encoded header values."""
    parts = email.header.decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


# ---------------------------------------------------------------------------
# Attachment extraction
# ---------------------------------------------------------------------------


def extract_attachments(
    msg: email.message.Message,
) -> list[tuple[str, str, bytes]]:
    """Extract attachments from a parsed email.Message.

    Returns list of (filename, mime_type, data) tuples for each
    attachment part.  Handles both 'attachment' and 'inline' dispositions
    (with filenames).  Text body parts are skipped.
    """
    attachments: list[tuple[str, str, bytes]] = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()

        # Skip the text body parts (unless explicitly marked as attachment).
        if content_type in ("text/plain", "text/html") and disposition != "attachment":
            continue

        # Only process parts with a filename (attachment or inline with file).
        filename = part.get_filename()
        if not filename:
            continue

        data = part.get_payload(decode=True)
        if data is None:
            continue

        mime_type = content_type or "application/octet-stream"

        logger.debug(
            "email attachment extracted",
            extra={
                "event": "email.attachment_extracted",
                "att_filename": filename,
                "mime_type": mime_type,
                "att_size": len(data),
            },
        )

        attachments.append((filename, mime_type, data))

    return attachments


# ---------------------------------------------------------------------------
# Body extraction
# ---------------------------------------------------------------------------


def _extract_body(msg: email.message.Message, max_length: int) -> str:
    """Extract text body from a MIME message — prefers text/plain."""
    logger.debug(
        "_extract_body called",
        extra={
            "event": "imap_email._extract_body",
            "msg_type": type(msg).__name__,
            "max_length": max_length,
        },
    )
    plain_text = ""
    html_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            # Skip attachments — extracted separately by extract_attachments()
            if part.get_content_disposition() == "attachment":
                continue
            if content_type == "text/plain" and not plain_text:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    plain_text = payload.decode(charset, errors="replace")
            elif content_type == "text/html" and not html_text:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html_text = payload.decode(charset, errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if "html" in msg.get_content_type():
                html_text = text
            else:
                plain_text = text

    body = plain_text or _sanitize_html(html_text)
    return _truncate_body(body, max_length)


def _sanitize_html(html_text: str) -> str:
    """Strip HTML tags, decode entities."""
    logger.debug(
        "_sanitize_html called",
        extra={"event": "imap_email._sanitize_html", "html_len": len(html_text)},
    )
    if not html_text:
        return ""
    text = _HTML_TAG_RE.sub("", html_text)
    text = html.unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" {2,}", " ", text)
    return text.strip()


def _truncate_body(body: str, max_length: int) -> str:
    """Truncate body to max_length with indicator."""
    if len(body) <= max_length:
        return body
    return body[:max_length] + "\n\n[... truncated]"


# ---------------------------------------------------------------------------
# IMAP operations (blocking, wrapped in asyncio.to_thread)
# ---------------------------------------------------------------------------


def _imap_connect(config) -> imaplib.IMAP4_SSL | imaplib.IMAP4:
    """Connect and authenticate to IMAP server. Blocking call."""
    logger.debug(
        "_imap_connect called",
        extra={
            "event": "imap_email._imap_connect",
            "config_type": type(config).__name__,
        },
    )
    password = _read_password(config.imap_password_file)
    ssl_ctx = _build_ssl_context(
        config.imap_tls_mode, config.imap_tls_cert_file, config.imap_host
    )

    try:
        if config.imap_tls_mode == "ssl":
            logger.debug(
                "_imap_connect: SSL mode",
                extra={
                    "event": "imap_email._imap_connect.ssl",
                    "tls_mode": config.imap_tls_mode,
                },
            )
            conn = imaplib.IMAP4_SSL(
                host=config.imap_host,
                port=config.imap_port,
                ssl_context=ssl_ctx,
                timeout=config.imap_timeout,
            )
        elif config.imap_tls_mode == "starttls":
            logger.debug(
                "_imap_connect: STARTTLS mode",
                extra={"event": "imap_email._imap_connect.starttls"},
            )
            conn = imaplib.IMAP4(
                host=config.imap_host,
                port=config.imap_port,
                timeout=config.imap_timeout,
            )
            conn.starttls(ssl_context=ssl_ctx)
        else:
            # "none" — plaintext, testing only
            logger.debug(
                "_imap_connect: plaintext mode",
                extra={"event": "imap_email._imap_connect.plaintext"},
            )
            conn = imaplib.IMAP4(
                host=config.imap_host,
                port=config.imap_port,
                timeout=config.imap_timeout,
            )
    except (ConnectionRefusedError, OSError) as exc:
        raise ImapEmailError(
            f"IMAP connection failed — is the mail server running? ({exc})"
        ) from exc

    # Explicitly set socket timeout for all subsequent IMAP operations
    # (recv/send). Python 3.12 imaplib already does this in _create_socket,
    # but being explicit guards against future imaplib changes.
    try:
        conn.socket().settimeout(config.imap_timeout)
    except (AttributeError, OSError):
        logger.debug(
            "_imap_connect: AttributeError | OSError suppressed",
            extra={"event": "imap_email._imap_connect.suppressed"},
            exc_info=True,
        )

    try:
        conn.login(config.imap_username, password)
    except imaplib.IMAP4.error as exc:
        try:
            conn.logout()
        except Exception:  # catch-all: IMAP logout best-effort
            logger.debug(
                "_imap_connect: Exception suppressed",
                extra={"event": "imap_email._imap_connect.suppressed"},
                exc_info=True,
            )
        raise ImapEmailError(f"IMAP login failed: {exc}") from exc
    except Exception as exc:  # catch-all: connection leak prevention
        # Catch non-IMAP errors (e.g. socket errors) to prevent connection leak
        try:
            conn.logout()
        except Exception:  # catch-all: IMAP logout best-effort
            logger.debug(
                "_imap_connect: Exception suppressed",
                extra={"event": "imap_email._imap_connect.suppressed"},
                exc_info=True,
            )
        raise ImapEmailError(f"IMAP login failed: {exc}") from exc

    return conn


def _imap_search_sync(config, query: str, max_results: int) -> list[EmailSearchResult]:
    """Search IMAP and fetch envelope metadata. Blocking."""
    conn = _imap_connect(config)
    try:
        conn.select("INBOX", readonly=True)

        # IMAP SEARCH: translate simple query to IMAP criteria
        search_criteria = _build_imap_search(query)
        status, data = conn.uid("search", None, search_criteria)
        if status != "OK":
            raise ImapEmailError(f"IMAP SEARCH failed: {status}")

        uids = data[0].split() if data[0] else []
        # Most recent first, limit results
        uids = list(reversed(uids))[:max_results]

        if not uids:
            return []

        results = []
        for uid in uids:
            status, msg_data = conn.uid(
                "fetch",
                uid,
                "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE CONTENT-TRANSFER-ENCODING)] BODY.PEEK[TEXT])",
            )
            if status != "OK" or not msg_data or not msg_data[0]:
                continue

            # Parse the header portion
            raw_header = msg_data[0][1] if isinstance(msg_data[0], tuple) else b""
            if isinstance(raw_header, bytes):
                header_msg = email.message_from_bytes(raw_header)
            else:
                continue

            subject = _decode_header_value(header_msg.get("Subject", "(no subject)"))
            sender = _decode_header_value(header_msg.get("From", ""))
            date_str = header_msg.get("Date", "")

            # Extract snippet from body preview
            snippet = ""
            if len(msg_data) > 1 and isinstance(msg_data[1], tuple):
                body_preview = msg_data[1][1]
                if isinstance(body_preview, bytes):
                    # Decode Content-Transfer-Encoding (base64, quoted-printable)
                    encoding = (
                        header_msg.get("Content-Transfer-Encoding", "").lower().strip()
                    )
                    if "base64" in encoding:
                        import base64

                        try:
                            body_preview = base64.b64decode(body_preview)
                        except Exception:  # catch-all: base64 decode on malformed email
                            logger.debug(
                                "_imap_search_sync: Exception suppressed",
                                extra={
                                    "event": "imap_email._imap_search_sync.suppressed"
                                },
                                exc_info=True,
                            )
                    elif "quoted-printable" in encoding:
                        import quopri

                        try:
                            body_preview = quopri.decodestring(body_preview)
                        except Exception:  # catch-all: QP decode on malformed email
                            logger.debug(
                                "_imap_search_sync: Exception suppressed",
                                extra={
                                    "event": "imap_email._imap_search_sync.suppressed"
                                },
                                exc_info=True,
                            )
                    snippet = body_preview.decode("utf-8", errors="replace")[
                        :_SNIPPET_MAX_LEN
                    ].strip()
                    snippet = re.sub(r"\s+", " ", snippet)

            results.append(
                EmailSearchResult(
                    message_id=uid.decode("ascii")
                    if isinstance(uid, bytes)
                    else str(uid),
                    thread_id="",  # IMAP has no thread concept in basic protocol
                    subject=subject,
                    sender=sender,
                    date=date_str,
                    snippet=snippet,
                )
            )

        return results
    finally:
        try:
            conn.logout()
        except Exception:  # catch-all: IMAP logout best-effort
            logger.debug(
                "_imap_search_sync: Exception suppressed",
                extra={"event": "imap_email._imap_search_sync.suppressed"},
                exc_info=True,
            )


# #3 MED: allowlist-based IMAP escape — only permit safe characters
_IMAP_SAFE_RE = re.compile(r"[^a-zA-Z0-9@._\-+\s]")

# #4 MED: single regex extracts all field:value patterns non-destructively
_QUERY_FIELD_RE = re.compile(r"(from|to|subject):(\S+)", re.IGNORECASE)

_IMAP_FIELD_MAP = {"from": "FROM", "to": "TO", "subject": "SUBJECT"}


def _build_imap_search(query: str) -> str:
    """Translate a simple search query to IMAP SEARCH criteria.

    Supports: from:X, to:X, subject:X, and free text (searches body+subject).
    """

    logger.debug(
        "_build_imap_search called",
        extra={
            "event": "imap_email._build_imap_search",
            "query_len": len(query) if query else 0,
        },
    )

    def _imap_escape(value: str) -> str:
        return _IMAP_SAFE_RE.sub("", value)

    parts = []

    # #4 MED: extract field patterns via regex, collect remaining text
    # by tracking match spans — avoids str.replace() mangling on overlapping patterns
    matched_spans: list[tuple[int, int]] = []
    for match in _QUERY_FIELD_RE.finditer(query):
        field = match.group(1).lower()
        value = match.group(2)
        imap_key = _IMAP_FIELD_MAP.get(field)
        if imap_key:
            parts.append(f'{imap_key} "{_imap_escape(value)}"')
            matched_spans.append(match.span())

    # Build remaining text from unmatched portions
    remaining_parts = []
    prev_end = 0
    for start, end in sorted(matched_spans):
        remaining_parts.append(query[prev_end:start])
        prev_end = end
    remaining_parts.append(query[prev_end:])
    remaining = " ".join(remaining_parts).strip()

    if remaining and remaining != "*":
        parts.append(f'TEXT "{_imap_escape(remaining)}"')

    if not parts:
        parts.append("ALL")

    return " ".join(parts)


def _imap_read_sync(
    config,
    message_id: str,
    max_body_length: int,
) -> tuple[EmailMessage, list[tuple[str, str, bytes]]]:
    """Fetch a full email by UID. Blocking.

    Returns (EmailMessage, raw_attachments) where raw_attachments is a
    list of (filename, mime_type, data) tuples from extract_attachments().
    """
    # #5 MED: validate message_id is numeric — prevents IMAP range injection
    # (e.g. "1:*" would fetch ALL messages, causing resource exhaustion)
    if not message_id or not message_id.strip().isdigit():
        raise ImapEmailError(
            f"Invalid message_id '{message_id}' — must be a numeric IMAP UID"
        )
    conn = _imap_connect(config)
    try:
        conn.select("INBOX", readonly=True)

        status, msg_data = conn.uid("fetch", message_id.strip(), "(RFC822)")
        if status != "OK" or not msg_data or not msg_data[0]:
            raise ImapEmailError(f"Message {message_id} not found")

        raw = msg_data[0][1] if isinstance(msg_data[0], tuple) else b""
        if not raw:
            raise ImapEmailError(f"Empty message data for {message_id}")

        msg = email.message_from_bytes(raw)

        subject = _decode_header_value(msg.get("Subject", "(no subject)"))
        sender = _decode_header_value(msg.get("From", ""))
        to = _decode_header_value(msg.get("To", ""))
        date_str = msg.get("Date", "")
        body = _extract_body(msg, max_body_length)

        raw_attachments = extract_attachments(msg)

        return EmailMessage(
            message_id=message_id,
            thread_id="",
            subject=subject,
            sender=sender,
            to=to,
            date=date_str,
            body_text=body,
        ), raw_attachments
    finally:
        try:
            conn.logout()
        except Exception:  # catch-all: IMAP logout best-effort
            logger.debug(
                "_imap_read_sync: Exception suppressed",
                extra={"event": "imap_email._imap_read_sync.suppressed"},
                exc_info=True,
            )


def _imap_create_draft_sync(config, to: str, subject: str, body: str) -> str:
    """Create a draft via IMAP APPEND to the Drafts folder. Blocking."""
    conn = _imap_connect(config)
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["To"] = to
        msg["Subject"] = subject
        msg["From"] = config.smtp_from_address or config.imap_username
        msg["Date"] = formatdate(localtime=True)

        drafts_folder = config.imap_drafts_folder
        status, _ = conn.append(
            drafts_folder,
            "\\Draft",
            None,
            msg.as_bytes(),
        )
        if status != "OK":
            raise ImapEmailError(f"IMAP APPEND to {drafts_folder} failed: {status}")

        return f"draft-{drafts_folder}"
    finally:
        try:
            conn.logout()
        except Exception:  # catch-all: IMAP logout best-effort
            logger.debug(
                "_imap_create_draft_sync: Exception suppressed",
                extra={"event": "imap_email._imap_create_draft_sync.suppressed"},
                exc_info=True,
            )


# ---------------------------------------------------------------------------
# Public async API
# ---------------------------------------------------------------------------

# Transient connection errors worth retrying (auth failures are permanent — never retry)
_IMAP_TRANSIENT_ERRORS = (ConnectionRefusedError, TimeoutError, OSError)

# #8 LOW: basic email address validation — prevents MIME header injection via newlines
_EMAIL_RE = re.compile(r"^[^@\r\n]+@[^@\r\n]+\.[^@\r\n]+$")

# #7 MED: per-recipient send rate limit (timestamps of recent sends)
_send_timestamps: dict[str, list[float]] = {}
_SEND_RATE_LIMIT = 5  # max sends per window
_SEND_RATE_WINDOW = 3600  # 1 hour window


def _check_send_rate(recipient: str) -> None:
    """Enforce per-recipient rate limit on email sends."""
    logger.debug(
        "_check_send_rate called",
        extra={
            "event": "imap_email._check_send_rate",
            "recipient": _mask_email(recipient),
        },
    )
    now = time.monotonic()
    key = recipient.lower().strip()
    timestamps = _send_timestamps.get(key, [])
    # Prune old entries outside the window
    timestamps = [t for t in timestamps if now - t < _SEND_RATE_WINDOW]
    if len(timestamps) >= _SEND_RATE_LIMIT:
        raise ImapEmailError(
            f"Rate limit exceeded: max {_SEND_RATE_LIMIT} emails per hour to {key}"
        )
    timestamps.append(now)
    _send_timestamps[key] = timestamps


def _validate_email_address(address: str) -> None:
    """Validate email address format — rejects newlines and malformed addresses."""
    if not _EMAIL_RE.match(address):
        raise ImapEmailError(f"Invalid email address format: '{address[:50]}'")


async def search_emails(
    config,
    query: str,
    max_results: int = 20,
) -> list[EmailSearchResult]:
    """Search emails via IMAP SEARCH."""
    if not config.imap_host:
        raise ImapEmailError("IMAP host not configured")
    t0 = time.monotonic()
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            results = await asyncio.to_thread(
                _imap_search_sync, config, query, max_results
            )
            logger.info(
                "imap.search_emails",
                # #10 LOW: mask query in logs — may contain PII (email addresses, names)
                extra={
                    "event": "imap.search_emails",
                    "query": _mask_query(query),
                    "results": len(results),
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return results
        except ImapEmailError as exc:
            last_exc = exc
            # Retry on transient connection errors wrapped in ImapEmailError
            if attempt < 1 and isinstance(exc.__cause__, _IMAP_TRANSIENT_ERRORS):
                logger.warning(
                    "IMAP search connection error, retrying",
                    extra={"event": "imap.search_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise ImapEmailError(f"IMAP search failed: {exc}") from exc
    raise ImapEmailError("IMAP search failed after retry") from last_exc


async def read_email(
    config,
    message_id: str,
    max_body_length: int = 50000,
) -> tuple[EmailMessage, list[tuple[str, str, bytes]]]:
    """Read a full email by message ID (IMAP UID).

    Returns (EmailMessage, raw_attachments) where raw_attachments is a
    list of (filename, mime_type, data) tuples.
    """
    if not config.imap_host:
        raise ImapEmailError("IMAP host not configured")
    t0 = time.monotonic()
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            email_msg, raw_attachments = await asyncio.to_thread(
                _imap_read_sync,
                config,
                message_id,
                max_body_length,
            )
            logger.info(
                "imap.read_email",
                extra={
                    "event": "imap.read_email",
                    "message_id_hash": log_hash(message_id),
                    "message_id_len": len(message_id),
                    "attachment_count": len(raw_attachments),
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return email_msg, raw_attachments
        except ImapEmailError as exc:
            last_exc = exc
            if attempt < 1 and isinstance(exc.__cause__, _IMAP_TRANSIENT_ERRORS):
                logger.warning(
                    "IMAP read connection error, retrying",
                    extra={"event": "imap.read_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise ImapEmailError(f"IMAP read failed: {exc}") from exc
    raise ImapEmailError("IMAP read failed after retry") from last_exc


@no_audit_log
async def send_email(
    config,
    to: str,
    subject: str,
    body: str,
    thread_id: str | None = None,
) -> str:
    """Send an email via SMTP (aiosmtplib)."""
    if not config.smtp_host:
        raise ImapEmailError("SMTP host not configured")
    _validate_email_address(to)
    _check_send_rate(to)
    t0 = time.monotonic()

    password = _read_password(config.smtp_password_file)
    ssl_ctx = _build_ssl_context(
        config.smtp_tls_mode, config.imap_tls_cert_file, config.smtp_host
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["To"] = to
    msg["Subject"] = subject
    msg["From"] = config.smtp_from_address or config.smtp_username
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    try:
        # Lazy import — aiosmtplib may not be installed yet
        import aiosmtplib
    except ImportError as exc:
        raise ImapEmailError(
            "aiosmtplib package not installed — required for SMTP send"
        ) from exc

    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            if config.smtp_tls_mode == "ssl":
                await aiosmtplib.send(
                    msg,
                    hostname=config.smtp_host,
                    port=config.smtp_port,
                    username=config.smtp_username,
                    password=password,
                    use_tls=True,
                    tls_context=ssl_ctx,
                    timeout=config.smtp_timeout,
                )
            else:
                # STARTTLS
                await aiosmtplib.send(
                    msg,
                    hostname=config.smtp_host,
                    port=config.smtp_port,
                    username=config.smtp_username,
                    password=password,
                    start_tls=True,
                    tls_context=ssl_ctx,
                    timeout=config.smtp_timeout,
                )
            # Defence-in-depth: mask recipient address in logs. Server-side
            # logs are on the user's own server, but minimize PII exposure.
            _masked_to = to[0] + "***@" + to.split("@")[-1] if "@" in to else "***"
            logger.info(
                "imap.send_email",
                extra={
                    "event": "imap.send_email",
                    "to": _masked_to,
                    "subject": subject[:100],
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return msg["Message-ID"]
        except _IMAP_TRANSIENT_ERRORS as exc:
            last_exc = exc
            if attempt < 1:
                logger.warning(
                    "SMTP send connection error, retrying",
                    extra={"event": "smtp.send_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise ImapEmailError(f"SMTP send failed after retry: {exc}") from exc
        except Exception as exc:
            raise ImapEmailError(f"SMTP send failed: {exc}") from exc

    raise ImapEmailError("SMTP send failed after retry") from last_exc


async def create_draft(
    config,
    to: str,
    subject: str,
    body: str,
) -> str:
    """Create a draft email via IMAP APPEND to Drafts folder."""
    if not config.imap_host:
        raise ImapEmailError("IMAP host not configured")
    _validate_email_address(to)
    t0 = time.monotonic()
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            result = await asyncio.to_thread(
                _imap_create_draft_sync, config, to, subject, body
            )
            logger.info(
                "imap.create_draft",
                # #9 LOW: mask recipient in draft logs (consistent with send_email)
                extra={
                    "event": "imap.create_draft",
                    "to": _mask_email(to),
                    "subject": subject[:100],
                    "elapsed_s": round(time.monotonic() - t0, 2),
                },
            )
            return result
        except ImapEmailError as exc:
            last_exc = exc
            if attempt < 1 and isinstance(exc.__cause__, _IMAP_TRANSIENT_ERRORS):
                logger.warning(
                    "IMAP draft connection error, retrying",
                    extra={"event": "imap.draft_retry", "error": str(exc)},
                    exc_info=True,
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise ImapEmailError(f"IMAP draft failed: {exc}") from exc
    raise ImapEmailError("IMAP draft failed after retry") from last_exc


# ---------------------------------------------------------------------------
# Formatters — produce LLM-friendly text (compatible with gmail.py format)
# ---------------------------------------------------------------------------


def format_search_results(results: list[EmailSearchResult]) -> str:
    """Format search results as numbered text for LLM consumption."""
    if not results:
        return "No emails found."

    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.subject}")
        lines.append(f"   From: {r.sender}")
        lines.append(f"   Date: {r.date}")
        lines.append(f"   ID: {r.message_id}")
        if r.snippet:
            lines.append(f"   Preview: {r.snippet}")
        lines.append("")
    return "\n".join(lines).rstrip()


def format_email(msg: EmailMessage) -> str:
    """Format a full email as structured text."""
    lines = [
        f"Subject: {msg.subject}",
        f"From: {msg.sender}",
        f"To: {msg.to}",
        f"Date: {msg.date}",
        f"Message ID: {msg.message_id}",
        "",
        msg.body_text,
    ]
    return "\n".join(lines)
