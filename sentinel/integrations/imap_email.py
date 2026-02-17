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

logger = logging.getLogger("sentinel.audit")

_HTML_TAG_RE = re.compile(r"<[^>]+>")


class ImapEmailError(Exception):
    """Error from IMAP/SMTP operations."""


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

def _build_ssl_context(tls_mode: str, cert_file: str) -> ssl.SSLContext | None:
    """Build an SSL context for IMAP or SMTP connections.

    Supports custom CA certs for self-signed servers (Proton Bridge).
    Falls back to CERT_NONE for localhost when no cert file is provided.
    """
    if tls_mode == "none":
        return None

    ctx = ssl.create_default_context()
    if cert_file:
        ctx.load_verify_locations(cert_file)
    else:
        # Self-signed cert without exported CA — only safe for localhost
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning(
            "IMAP/SMTP TLS: no cert file, using CERT_NONE (localhost only)",
            extra={"event": "tls_cert_none"},
        )
    return ctx


def _read_password(password_file: str) -> str:
    """Read password from a secrets file. Never log the content."""
    try:
        with open(password_file) as f:
            return f.read().strip()
    except OSError as exc:
        raise ImapEmailError(
            f"Cannot read password file: {exc}"
        ) from exc


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
# Body extraction
# ---------------------------------------------------------------------------

def _extract_body(msg: email.message.Message, max_length: int) -> str:
    """Extract text body from a MIME message — prefers text/plain."""
    plain_text = ""
    html_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            # Skip attachments (v1: no attachment handling)
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
    password = _read_password(config.imap_password_file)
    ssl_ctx = _build_ssl_context(config.imap_tls_mode, config.imap_tls_cert_file)

    try:
        if config.imap_tls_mode == "ssl":
            conn = imaplib.IMAP4_SSL(
                host=config.imap_host,
                port=config.imap_port,
                ssl_context=ssl_ctx,
                timeout=config.imap_timeout,
            )
        elif config.imap_tls_mode == "starttls":
            conn = imaplib.IMAP4(
                host=config.imap_host,
                port=config.imap_port,
                timeout=config.imap_timeout,
            )
            conn.starttls(ssl_context=ssl_ctx)
        else:
            # "none" — plaintext, testing only
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
        pass  # Socket not yet available (shouldn't happen post-connect)

    try:
        conn.login(config.imap_username, password)
    except imaplib.IMAP4.error as exc:
        try:
            conn.logout()
        except Exception:
            pass
        raise ImapEmailError(f"IMAP login failed: {exc}") from exc
    except Exception as exc:
        # Catch non-IMAP errors (e.g. socket errors) to prevent connection leak
        try:
            conn.logout()
        except Exception:
            pass
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
                "fetch", uid, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)] BODY.PEEK[TEXT])"
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
                    snippet = body_preview.decode("utf-8", errors="replace")[:200].strip()
                    snippet = re.sub(r"\s+", " ", snippet)

            results.append(EmailSearchResult(
                message_id=uid.decode("ascii") if isinstance(uid, bytes) else str(uid),
                thread_id="",  # IMAP has no thread concept in basic protocol
                subject=subject,
                sender=sender,
                date=date_str,
                snippet=snippet,
            ))

        return results
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _build_imap_search(query: str) -> str:
    """Translate a simple search query to IMAP SEARCH criteria.

    Supports: from:X, to:X, subject:X, and free text (searches body+subject).
    """
    # Whitelist approach: keep only safe characters for IMAP SEARCH quoted strings.
    # Strips quotes, backslashes, parens, braces, brackets, control chars, and newlines
    # to prevent IMAP command injection.
    def _imap_escape(value: str) -> str:
        return re.sub(r'["\\\(\)\{\}\[\]\r\n\x00-\x1f]', "", value)

    parts = []
    remaining = query

    # Extract from: patterns
    for match in re.finditer(r"from:(\S+)", query):
        parts.append(f'FROM "{_imap_escape(match.group(1))}"')
        remaining = remaining.replace(match.group(0), "")

    # Extract to: patterns
    for match in re.finditer(r"to:(\S+)", query):
        parts.append(f'TO "{_imap_escape(match.group(1))}"')
        remaining = remaining.replace(match.group(0), "")

    # Extract subject: patterns
    for match in re.finditer(r"subject:(\S+)", query):
        parts.append(f'SUBJECT "{_imap_escape(match.group(1))}"')
        remaining = remaining.replace(match.group(0), "")

    # Remaining text — search in subject and body
    remaining = remaining.strip()
    if remaining and remaining != "*":
        parts.append(f'TEXT "{_imap_escape(remaining)}"')

    if not parts:
        parts.append("ALL")

    return " ".join(parts)


def _imap_read_sync(config, message_id: str, max_body_length: int) -> EmailMessage:
    """Fetch a full email by UID. Blocking."""
    conn = _imap_connect(config)
    try:
        conn.select("INBOX", readonly=True)

        status, msg_data = conn.uid("fetch", message_id, "(RFC822)")
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

        return EmailMessage(
            message_id=message_id,
            thread_id="",
            subject=subject,
            sender=sender,
            to=to,
            date=date_str,
            body_text=body,
        )
    finally:
        try:
            conn.logout()
        except Exception:
            pass


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
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public async API
# ---------------------------------------------------------------------------

# Transient connection errors worth retrying (auth failures are permanent — never retry)
_IMAP_TRANSIENT_ERRORS = (ConnectionRefusedError, TimeoutError, OSError)


async def search_emails(
    config,
    query: str,
    max_results: int = 20,
) -> list[EmailSearchResult]:
    """Search emails via IMAP SEARCH."""
    if not config.imap_host:
        raise ImapEmailError("IMAP host not configured")
    t0 = time.monotonic()
    for attempt in range(2):
        try:
            results = await asyncio.to_thread(_imap_search_sync, config, query, max_results)
            logger.info(
                "imap.search_emails",
                extra={"query": query[:100], "results": len(results), "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return results
        except ImapEmailError as exc:
            # Retry on transient connection errors wrapped in ImapEmailError
            if attempt < 1 and isinstance(exc.__cause__, _IMAP_TRANSIENT_ERRORS):
                logger.warning(
                    "IMAP search connection error, retrying",
                    extra={"event": "imap_search_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise ImapEmailError(f"IMAP search failed: {exc}") from exc
    raise ImapEmailError("IMAP search failed after retry")  # unreachable, keeps type checker happy


async def read_email(
    config,
    message_id: str,
    max_body_length: int = 50000,
) -> EmailMessage:
    """Read a full email by message ID (IMAP UID)."""
    if not config.imap_host:
        raise ImapEmailError("IMAP host not configured")
    t0 = time.monotonic()
    for attempt in range(2):
        try:
            result = await asyncio.to_thread(_imap_read_sync, config, message_id, max_body_length)
            logger.info(
                "imap.read_email",
                extra={"message_id": message_id, "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return result
        except ImapEmailError as exc:
            if attempt < 1 and isinstance(exc.__cause__, _IMAP_TRANSIENT_ERRORS):
                logger.warning(
                    "IMAP read connection error, retrying",
                    extra={"event": "imap_read_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise ImapEmailError(f"IMAP read failed: {exc}") from exc
    raise ImapEmailError("IMAP read failed after retry")


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
    t0 = time.monotonic()

    password = _read_password(config.smtp_password_file)
    ssl_ctx = _build_ssl_context(config.smtp_tls_mode, config.imap_tls_cert_file)

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
                extra={"to": _masked_to, "subject": subject[:100], "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return msg["Message-ID"]
        except _IMAP_TRANSIENT_ERRORS as exc:
            if attempt < 1:
                logger.warning(
                    "SMTP send connection error, retrying",
                    extra={"event": "smtp_send_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise ImapEmailError(f"SMTP send failed after retry: {exc}") from exc
        except Exception as exc:
            raise ImapEmailError(f"SMTP send failed: {exc}") from exc

    raise ImapEmailError("SMTP send failed after retry")


async def create_draft(
    config,
    to: str,
    subject: str,
    body: str,
) -> str:
    """Create a draft email via IMAP APPEND to Drafts folder."""
    if not config.imap_host:
        raise ImapEmailError("IMAP host not configured")
    t0 = time.monotonic()
    for attempt in range(2):
        try:
            result = await asyncio.to_thread(_imap_create_draft_sync, config, to, subject, body)
            logger.info(
                "imap.create_draft",
                extra={"to": to[:100], "subject": subject[:100], "elapsed_s": round(time.monotonic() - t0, 2)},
            )
            return result
        except ImapEmailError as exc:
            if attempt < 1 and isinstance(exc.__cause__, _IMAP_TRANSIENT_ERRORS):
                logger.warning(
                    "IMAP draft connection error, retrying",
                    extra={"event": "imap_draft_retry", "error": str(exc)},
                )
                await asyncio.sleep(2)
                continue
            raise
        except Exception as exc:
            raise ImapEmailError(f"IMAP draft failed: {exc}") from exc
    raise ImapEmailError("IMAP draft failed after retry")


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
